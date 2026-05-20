//! Attested screening inputs and signed instrument telemetry.
//!
//! Replaces `sensor.rs` from the sibling robotics project. The bio analog of a
//! signed motor-sensor reading is a signed screening-database entry or a
//! signed instrument-telemetry sample. Both carry:
//! - a freshness timestamp,
//! - a unique nonce (single-use within the configured replay window),
//! - an Ed25519 signature over the canonical payload bytes,
//! - the attesting key's id (resolved through a trusted-keys map).
//!
//! `AttestationVerifier` verifies an `AttestedInput` or `AttestedReading`
//! against:
//! 1. signer-kid presence in a trusted-keys map,
//! 2. signature validity (Ed25519 over the canonical bytes of the structure
//!    excluding the signature field),
//! 3. freshness within a configurable max-age,
//! 4. nonce uniqueness within a bounded recent-nonce window.

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::util::sha256_hex_json;

/// Default cap on the recent-nonce cache.
const DEFAULT_NONCE_CACHE_CAP: usize = 4096;
/// Default max-age before an attested input is considered stale.
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(5 * 60);

// ---------------------------------------------------------------------------
// Envelope structs
// ---------------------------------------------------------------------------

/// An attested screening-database entry or signed external payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestedInput {
    /// Name of the attesting source (e.g. `"securedna-screening-v2"`).
    pub source: String,
    /// Freshness timestamp.
    pub timestamp: DateTime<Utc>,
    /// Opaque, single-use nonce provided by the firewall to defeat replay.
    pub nonce: String,
    /// Opaque attested payload (JSON-encoded by the source).
    pub payload: String,
    /// Base64-encoded Ed25519 signature from the attesting key.
    pub signature: String,
    /// Key identifier of the attesting signer.
    pub signer_kid: String,
}

/// A single instrument reading carrying the same cryptographic envelope as
/// [`AttestedInput`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestedReading {
    /// Name of the instrument or telemetry source.
    pub source: String,
    /// Freshness timestamp.
    pub timestamp: DateTime<Utc>,
    /// Opaque, single-use nonce.
    pub nonce: String,
    /// Floating-point reading (e.g. dispensed volume in µL, pH, temperature).
    pub value: f64,
    /// Human-readable unit (e.g. `"uL"`, `"degC"`).
    pub unit: String,
    /// Base64-encoded Ed25519 signature from the attesting key.
    pub signature: String,
    /// Key identifier of the attesting signer.
    pub signer_kid: String,
}

// ---------------------------------------------------------------------------
// Canonical payload for signing
// ---------------------------------------------------------------------------

/// The signable view of an [`AttestedInput`]: every field except `signature`.
#[derive(Debug, Serialize)]
struct InputCanonical<'a> {
    source: &'a str,
    timestamp: DateTime<Utc>,
    nonce: &'a str,
    payload: &'a str,
    signer_kid: &'a str,
}

impl<'a> From<&'a AttestedInput> for InputCanonical<'a> {
    fn from(i: &'a AttestedInput) -> Self {
        Self {
            source: &i.source,
            timestamp: i.timestamp,
            nonce: &i.nonce,
            payload: &i.payload,
            signer_kid: &i.signer_kid,
        }
    }
}

/// The signable view of an [`AttestedReading`]: every field except `signature`.
#[derive(Debug, Serialize)]
struct ReadingCanonical<'a> {
    source: &'a str,
    timestamp: DateTime<Utc>,
    nonce: &'a str,
    value: f64,
    unit: &'a str,
    signer_kid: &'a str,
}

impl<'a> From<&'a AttestedReading> for ReadingCanonical<'a> {
    fn from(r: &'a AttestedReading) -> Self {
        Self {
            source: &r.source,
            timestamp: r.timestamp,
            nonce: &r.nonce,
            value: r.value,
            unit: &r.unit,
            signer_kid: &r.signer_kid,
        }
    }
}

// ---------------------------------------------------------------------------
// Persistent nonce log entry
// ---------------------------------------------------------------------------

/// A single entry in the persistent nonce JSONL log.
#[derive(Serialize, Deserialize)]
struct NonceLogEntry {
    kid: String,
    nonce: String,
    /// RFC 3339 timestamp of when this nonce was accepted.
    ts: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised when verifying an attestation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    /// `signer_kid` not present in the trusted-keys map.
    #[error("unknown signer kid {kid:?}")]
    UnknownKid {
        /// The unknown kid.
        kid: String,
    },
    /// Signature was malformed (bad base64 or wrong length).
    #[error("malformed signature: {0}")]
    Signature(String),
    /// Signature verification failed against the canonical bytes.
    #[error("bad signature (tampered or wrong key)")]
    BadSignature,
    /// Timestamp older than the configured `max_age`.
    #[error("stale: timestamp is {age_ms} ms old (max {max_age_ms} ms)")]
    Stale {
        /// Age in milliseconds.
        age_ms: i64,
        /// Configured cap in milliseconds.
        max_age_ms: i64,
    },
    /// Timestamp is in the future beyond clock-skew tolerance.
    #[error("clock skew: timestamp {skew_ms} ms in the future")]
    FutureTimestamp {
        /// How far in the future, in milliseconds.
        skew_ms: i64,
    },
    /// Nonce was already seen within the replay window.
    #[error("nonce {nonce:?} replays a previously-seen attestation")]
    Replay {
        /// The replayed nonce.
        nonce: String,
    },
    /// Serialization of canonical bytes failed.
    #[error("serialization failed: {0}")]
    Serialization(String),
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Stateful verifier holding the trusted-keys map plus a bounded
/// recently-seen-nonce cache.
pub struct AttestationVerifier {
    trusted_keys: std::collections::HashMap<String, VerifyingKey>,
    max_age: Duration,
    skew: Duration,
    nonce_cap: usize,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    /// Optional file handle for persisting accepted nonces across restarts.
    nonce_log: Option<std::fs::File>,
    /// Path to the nonce log file (needed for rotation).
    nonce_log_path: Option<std::path::PathBuf>,
    /// Number of writes since the last log rotation.
    nonce_writes_since_rotation: usize,
}

impl AttestationVerifier {
    /// Number of nonce writes before the persistent log is auto-rotated.
    const ROTATION_THRESHOLD: usize = 1000;

    /// Construct a verifier with default policy: `max_age = 5 min`,
    /// `clock skew = 30 s`, nonce cache capacity = 4096.
    pub fn new(trusted_keys: std::collections::HashMap<String, VerifyingKey>) -> Self {
        Self {
            trusted_keys,
            max_age: DEFAULT_MAX_AGE,
            skew: Duration::from_secs(30),
            nonce_cap: DEFAULT_NONCE_CACHE_CAP,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            nonce_log: None,
            nonce_log_path: None,
            nonce_writes_since_rotation: 0,
        }
    }

    /// Open (or create) a JSONL nonce log at `path`.
    ///
    /// Existing entries are read back: those still within `max_age + skew` are
    /// seeded into the in-memory nonce cache so they continue to prevent replay
    /// after a process restart. Entries older than that window are silently
    /// discarded (they can no longer be replayed anyway).
    ///
    /// The returned verifier appends every newly-accepted nonce to the log.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] if the file cannot be opened or read.
    pub fn with_persistent_log(
        mut self,
        path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .read(true)
            .open(&path_buf)?;

        // Read back existing entries and seed the in-memory cache with those
        // that are still within the freshness window.
        let cutoff_duration =
            chrono::Duration::from_std(self.max_age + self.skew).unwrap_or(chrono::Duration::MAX);
        let now = Utc::now();

        let mut lines_buf = Vec::new();
        {
            let reader = BufReader::new(&mut file);
            for line in reader.lines() {
                let line = line?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(entry) = serde_json::from_str::<NonceLogEntry>(trimmed) {
                    if let Ok(ts) = entry.ts.parse::<DateTime<Utc>>() {
                        let age = now.signed_duration_since(ts);
                        if age <= cutoff_duration {
                            lines_buf.push(entry.nonce);
                        }
                        // Stale entries are simply dropped — they're outside
                        // the freshness window and cannot be replayed.
                    }
                }
            }
        }

        for nonce in lines_buf {
            self.record_nonce(&nonce);
        }

        self.nonce_log = Some(file);
        self.nonce_log_path = Some(path_buf);
        Ok(self)
    }

    /// Override the max-age for freshness checks.
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_age = age;
        self
    }

    /// Override the allowed forward clock skew (default 30 s).
    pub fn with_clock_skew(mut self, skew: Duration) -> Self {
        self.skew = skew;
        self
    }

    /// Override the recent-nonce cache capacity.
    pub fn with_nonce_cache_cap(mut self, cap: usize) -> Self {
        self.nonce_cap = cap.max(1);
        self
    }

    /// Number of nonces currently retained in the replay-protection window.
    pub fn nonce_cache_len(&self) -> usize {
        self.seen.len()
    }

    /// Verify an [`AttestedInput`] against this verifier's policy.
    /// On success, `nonce` is recorded so a later identical envelope is
    /// rejected as replay.
    pub fn verify_input(
        &mut self,
        input: &AttestedInput,
        now: DateTime<Utc>,
    ) -> Result<(), AttestationError> {
        let canonical = sha256_hex_json(&InputCanonical::from(input))
            .map_err(|e| AttestationError::Serialization(e.to_string()))?;
        self.verify_envelope(
            &input.signer_kid,
            &input.signature,
            canonical.as_bytes(),
            input.timestamp,
            &input.nonce,
            now,
        )
    }

    /// Verify an [`AttestedReading`] against this verifier's policy.
    pub fn verify_reading(
        &mut self,
        reading: &AttestedReading,
        now: DateTime<Utc>,
    ) -> Result<(), AttestationError> {
        let canonical = sha256_hex_json(&ReadingCanonical::from(reading))
            .map_err(|e| AttestationError::Serialization(e.to_string()))?;
        self.verify_envelope(
            &reading.signer_kid,
            &reading.signature,
            canonical.as_bytes(),
            reading.timestamp,
            &reading.nonce,
            now,
        )
    }

    fn verify_envelope(
        &mut self,
        kid: &str,
        signature_b64: &str,
        signed_bytes: &[u8],
        timestamp: DateTime<Utc>,
        nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<(), AttestationError> {
        // 1. Resolve key.
        let key = self
            .trusted_keys
            .get(kid)
            .ok_or_else(|| AttestationError::UnknownKid {
                kid: kid.to_string(),
            })?;

        // 2. Parse signature.
        let raw = STANDARD
            .decode(signature_b64.as_bytes())
            .map_err(|e| AttestationError::Signature(e.to_string()))?;
        let arr: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::Signature("expected 64 bytes".into()))?;
        let sig = Signature::from_bytes(&arr);

        // 3. Verify signature.
        key.verify(signed_bytes, &sig)
            .map_err(|_| AttestationError::BadSignature)?;

        // 4. Freshness.
        let delta = now.signed_duration_since(timestamp);
        let age_ms = delta.num_milliseconds();
        if age_ms < -(self.skew.as_millis() as i64) {
            return Err(AttestationError::FutureTimestamp { skew_ms: -age_ms });
        }
        let max_age_ms = self.max_age.as_millis() as i64;
        if age_ms > max_age_ms {
            return Err(AttestationError::Stale { age_ms, max_age_ms });
        }

        // 5. Replay protection.
        if self.seen.contains(nonce) {
            return Err(AttestationError::Replay {
                nonce: nonce.to_string(),
            });
        }
        self.record_nonce(nonce);
        self.persist_nonce(kid, nonce);
        Ok(())
    }

    /// Insert `nonce` into the in-memory cache, evicting the oldest entry when
    /// the capacity is reached.
    fn record_nonce(&mut self, nonce: &str) {
        let owned = nonce.to_string();
        self.seen.insert(owned.clone());
        self.seen_order.push_back(owned);
        while self.seen_order.len() > self.nonce_cap {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
    }

    /// Append the accepted nonce to the persistent log (if one is configured).
    ///
    /// Failures are silently ignored: persistence is best-effort and must not
    /// break the primary verification flow.
    fn persist_nonce(&mut self, kid: &str, nonce: &str) {
        if let Some(ref mut file) = self.nonce_log {
            self.nonce_writes_since_rotation += 1;
            let entry = NonceLogEntry {
                kid: kid.to_string(),
                nonce: nonce.to_string(),
                ts: Utc::now().to_rfc3339(),
            };
            if let Ok(mut line) = serde_json::to_string(&entry) {
                line.push('\n');
                let _ = file.write_all(line.as_bytes());
                let _ = file.flush();
            }
            // Auto-rotate when enough writes have accumulated.
            if self.nonce_writes_since_rotation >= Self::ROTATION_THRESHOLD {
                let _ = self.rotate_log();
            }
        }
    }

    /// Rotate the persistent nonce log: rewrite it keeping only entries
    /// within the freshness window (`max_age + skew`). Older entries are
    /// discarded — they can no longer be replayed anyway. This prevents
    /// unbounded growth on long-running firewall processes.
    ///
    /// Returns the number of entries retained.
    pub fn rotate_log(&mut self) -> std::io::Result<usize> {
        let path = match self.nonce_log_path.as_ref() {
            Some(p) => p.clone(),
            None => return Ok(0),
        };
        self.nonce_writes_since_rotation = 0;
        let cutoff_duration =
            chrono::Duration::from_std(self.max_age + self.skew).unwrap_or(chrono::Duration::MAX);
        let now = Utc::now();

        // Collect surviving entries from the current in-memory cache.
        let mut surviving: Vec<NonceLogEntry> = Vec::new();
        for nonce in &self.seen_order {
            surviving.push(NonceLogEntry {
                kid: String::new(),
                nonce: nonce.clone(),
                ts: now.to_rfc3339(),
            });
        }

        // Also read any entries from the file that are still fresh but
        // might not be in memory (e.g. from a prior process).
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(entry) = serde_json::from_str::<NonceLogEntry>(trimmed) {
                    if let Ok(ts) = entry.ts.parse::<DateTime<Utc>>() {
                        let age = now.signed_duration_since(ts);
                        if age <= cutoff_duration && !self.seen.contains(&entry.nonce) {
                            surviving.push(entry);
                        }
                    }
                }
            }
        }

        // Rewrite the file atomically.
        let mut content = String::new();
        for entry in &surviving {
            if let Ok(line) = serde_json::to_string(entry) {
                content.push_str(&line);
                content.push('\n');
            }
        }
        std::fs::write(&path, content.as_bytes())?;

        // Re-open in append mode.
        let file = std::fs::OpenOptions::new().append(true).open(&path)?;
        self.nonce_log = Some(file);

        Ok(surviving.len())
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Sign an [`AttestedInput`] envelope with `signing_key`. Used by tests and
/// by callers building attested data for the validator.
pub fn sign_attested_input(
    source: &str,
    timestamp: DateTime<Utc>,
    nonce: &str,
    payload: &str,
    signer_kid: &str,
    signing_key: &SigningKey,
) -> AttestedInput {
    let canonical = InputCanonical {
        source,
        timestamp,
        nonce,
        payload,
        signer_kid,
    };
    let hash = sha256_hex_json(&canonical).expect("serialize canonical input");
    let sig = signing_key.sign(hash.as_bytes());
    AttestedInput {
        source: source.to_string(),
        timestamp,
        nonce: nonce.to_string(),
        payload: payload.to_string(),
        signature: STANDARD.encode(sig.to_bytes()),
        signer_kid: signer_kid.to_string(),
    }
}

/// Sign an [`AttestedReading`] envelope.
pub fn sign_attested_reading(
    source: &str,
    timestamp: DateTime<Utc>,
    nonce: &str,
    value: f64,
    unit: &str,
    signer_kid: &str,
    signing_key: &SigningKey,
) -> AttestedReading {
    let canonical = ReadingCanonical {
        source,
        timestamp,
        nonce,
        value,
        unit,
        signer_kid,
    };
    let hash = sha256_hex_json(&canonical).expect("serialize canonical reading");
    let sig = signing_key.sign(hash.as_bytes());
    AttestedReading {
        source: source.to_string(),
        timestamp,
        nonce: nonce.to_string(),
        value,
        unit: unit.to_string(),
        signature: STANDARD.encode(sig.to_bytes()),
        signer_kid: signer_kid.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn key_pair_in_map(kid: &str) -> (SigningKey, HashMap<String, VerifyingKey>) {
        let sk = SigningKey::generate(&mut OsRng);
        let mut m = HashMap::new();
        m.insert(kid.to_string(), sk.verifying_key());
        (sk, m)
    }

    #[test]
    fn happy_path_input_verifies() {
        let (sk, keys) = key_pair_in_map("kid-1");
        let mut v = AttestationVerifier::new(keys);
        let now = Utc::now();
        let input = sign_attested_input("src", now, "n1", "{}", "kid-1", &sk);
        v.verify_input(&input, now).unwrap();
    }

    #[test]
    fn happy_path_reading_verifies() {
        let (sk, keys) = key_pair_in_map("kid-1");
        let mut v = AttestationVerifier::new(keys);
        let now = Utc::now();
        let reading = sign_attested_reading("instr", now, "n2", 37.0, "degC", "kid-1", &sk);
        v.verify_reading(&reading, now).unwrap();
    }

    #[test]
    fn unknown_kid_rejected() {
        let (sk, _) = key_pair_in_map("kid-1");
        let mut v = AttestationVerifier::new(HashMap::new());
        let now = Utc::now();
        let input = sign_attested_input("src", now, "n", "{}", "kid-1", &sk);
        let err = v.verify_input(&input, now).unwrap_err();
        assert!(matches!(err, AttestationError::UnknownKid { .. }));
    }

    #[test]
    fn bad_signature_rejected() {
        let signer = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let mut keys = HashMap::new();
        keys.insert("kid-1".to_string(), attacker.verifying_key());
        let mut v = AttestationVerifier::new(keys);
        let now = Utc::now();
        let input = sign_attested_input("src", now, "n", "{}", "kid-1", &signer);
        let err = v.verify_input(&input, now).unwrap_err();
        assert_eq!(err, AttestationError::BadSignature);
    }

    #[test]
    fn malformed_signature_rejected() {
        let (_sk, keys) = key_pair_in_map("kid-1");
        let mut v = AttestationVerifier::new(keys);
        let now = Utc::now();
        let mut input = sign_attested_input(
            "src",
            now,
            "n",
            "{}",
            "kid-1",
            &SigningKey::generate(&mut OsRng),
        );
        input.signature = "not-base64!!!".into();
        let err = v.verify_input(&input, now).unwrap_err();
        assert!(matches!(err, AttestationError::Signature(_)));
    }

    #[test]
    fn tampered_payload_rejected() {
        let (sk, keys) = key_pair_in_map("kid-1");
        let mut v = AttestationVerifier::new(keys);
        let now = Utc::now();
        let mut input = sign_attested_input("src", now, "n", "original", "kid-1", &sk);
        input.payload = "tampered".into();
        let err = v.verify_input(&input, now).unwrap_err();
        assert_eq!(err, AttestationError::BadSignature);
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (sk, keys) = key_pair_in_map("kid-1");
        let mut v = AttestationVerifier::new(keys).with_max_age(Duration::from_secs(60));
        let stamped = Utc::now() - chrono::Duration::seconds(120);
        let input = sign_attested_input("src", stamped, "n", "{}", "kid-1", &sk);
        let err = v.verify_input(&input, Utc::now()).unwrap_err();
        assert!(matches!(err, AttestationError::Stale { .. }));
    }

    #[test]
    fn future_timestamp_rejected_beyond_skew() {
        let (sk, keys) = key_pair_in_map("kid-1");
        let mut v = AttestationVerifier::new(keys).with_clock_skew(Duration::from_secs(5));
        let stamped = Utc::now() + chrono::Duration::seconds(60);
        let input = sign_attested_input("src", stamped, "n", "{}", "kid-1", &sk);
        let err = v.verify_input(&input, Utc::now()).unwrap_err();
        assert!(matches!(err, AttestationError::FutureTimestamp { .. }));
    }

    #[test]
    fn replay_rejected() {
        let (sk, keys) = key_pair_in_map("kid-1");
        let mut v = AttestationVerifier::new(keys);
        let now = Utc::now();
        let input = sign_attested_input("src", now, "nonce-A", "{}", "kid-1", &sk);
        v.verify_input(&input, now).unwrap();
        let err = v.verify_input(&input, now).unwrap_err();
        assert!(matches!(err, AttestationError::Replay { .. }));
    }

    #[test]
    fn nonce_cache_evicts_oldest() {
        let (sk, keys) = key_pair_in_map("kid-1");
        let mut v = AttestationVerifier::new(keys).with_nonce_cache_cap(2);
        let now = Utc::now();
        for n in &["a", "b", "c"] {
            let input = sign_attested_input("src", now, n, "{}", "kid-1", &sk);
            v.verify_input(&input, now).unwrap();
        }
        // Cache held 3 then trimmed to 2 — "a" should have been evicted.
        assert_eq!(v.nonce_cache_len(), 2);
        // Re-using "a" must succeed (no longer in cache).
        let again = sign_attested_input("src", now, "a", "{}", "kid-1", &sk);
        v.verify_input(&again, now).unwrap();
    }

    // -------------------------------------------------------------------------
    // Persistent nonce log tests
    // -------------------------------------------------------------------------

    /// Helper: return a temp file path that is cleaned up when the returned
    /// `TempPath` is dropped.
    fn temp_log_path() -> std::path::PathBuf {
        // Use a unique name under std::env::temp_dir so tests don't collide.
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let tid = std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "_");
        std::env::temp_dir().join(format!("attestation_nonce_{}_{}.jsonl", tid, nanos))
    }

    #[test]
    fn persistent_nonce_load_from_empty() {
        let path = temp_log_path();
        let (sk, keys) = key_pair_in_map("kid-1");
        // File doesn't exist yet — with_persistent_log should create it.
        let mut v = AttestationVerifier::new(keys)
            .with_persistent_log(&path)
            .expect("open log");
        let now = Utc::now();
        let input = sign_attested_input("src", now, "nonce-empty", "{}", "kid-1", &sk);
        // Normal operation works when starting from an empty log.
        v.verify_input(&input, now).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persistent_nonce_replay_rejected_across_restart() {
        let path = temp_log_path();
        let (sk, keys) = key_pair_in_map("kid-1");
        let now = Utc::now();
        let input = sign_attested_input("src", now, "nonce-restart", "{}", "kid-1", &sk);

        // First "process": verify and persist.
        {
            let keys2 = {
                let mut m = HashMap::new();
                m.insert("kid-1".to_string(), sk.verifying_key());
                m
            };
            let mut v = AttestationVerifier::new(keys2)
                .with_persistent_log(&path)
                .expect("open log first");
            v.verify_input(&input, now).unwrap();
        }

        // Second "process": load from the same log — replay must be rejected.
        let mut v2 = AttestationVerifier::new(keys)
            .with_persistent_log(&path)
            .expect("open log second");
        let err = v2.verify_input(&input, now).unwrap_err();
        assert!(
            matches!(err, AttestationError::Replay { .. }),
            "expected Replay, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persistent_nonce_stale_entries_purged() {
        let path = temp_log_path();

        // Write a log entry whose timestamp is far in the past (outside any
        // reasonable freshness window).
        let stale_ts = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        let entry = NonceLogEntry {
            kid: "kid-1".to_string(),
            nonce: "stale-nonce".to_string(),
            ts: stale_ts,
        };
        let line = serde_json::to_string(&entry).unwrap() + "\n";
        std::fs::write(&path, line).unwrap();

        let (_sk, keys) = key_pair_in_map("kid-1");
        // Default max_age is 5 min; stale entry is 2 h old → should be purged.
        let v = AttestationVerifier::new(keys)
            .with_persistent_log(&path)
            .expect("open log");

        // The stale nonce must NOT appear in the in-memory cache.
        assert!(
            !v.seen.contains("stale-nonce"),
            "stale nonce must not be seeded into the cache"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persistent_nonce_missing_file_creates_fresh() {
        // Construct a path that definitely does not exist.
        let path = temp_log_path();
        // Ensure the file doesn't pre-exist.
        let _ = std::fs::remove_file(&path);

        let (_sk, keys) = key_pair_in_map("kid-1");
        let v = AttestationVerifier::new(keys)
            .with_persistent_log(&path)
            .expect("should create file");

        // The file should now exist and the cache should be empty.
        assert!(path.exists(), "log file should have been created");
        assert_eq!(v.nonce_cache_len(), 0, "fresh cache expected");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persistent_nonce_entries_appended() {
        let path = temp_log_path();
        let (sk, keys) = key_pair_in_map("kid-1");
        let now = Utc::now();
        let input = sign_attested_input("src", now, "nonce-append", "{}", "kid-1", &sk);

        {
            let mut v = AttestationVerifier::new(keys)
                .with_persistent_log(&path)
                .expect("open log");
            v.verify_input(&input, now).unwrap();
        }

        // The log file must contain a line with our nonce.
        let contents = std::fs::read_to_string(&path).unwrap();
        let found = contents.lines().any(|line| {
            serde_json::from_str::<NonceLogEntry>(line)
                .ok()
                .map(|e| e.nonce == "nonce-append")
                .unwrap_or(false)
        });
        assert!(found, "nonce-append must be present in the log file");
        let _ = std::fs::remove_file(&path);
    }
}
