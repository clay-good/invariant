// Append-only signed JSONL audit logger.
//
// Enforces the four audit invariants:
// - L1 Completeness: every command/verdict pair is logged
// - L2 Ordering: SHA-256 hash chain links each entry to its predecessor
// - L3 Authenticity: each entry is Ed25519-signed by the Invariant instance
// - L4 Immutability: append-only writes (O_APPEND when file-backed)

use std::io::Write;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::models::audit::{AuditEntry, SignedAuditEntry};
use crate::models::command::Command;
use crate::models::verdict::SignedVerdict;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("serialization failed: {reason}")]
    Serialization { reason: String },

    #[error("I/O error: {reason}")]
    Io { reason: String },
}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        AuditError::Io {
            reason: e.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Verification error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq)]
pub enum AuditVerifyError {
    #[error("entry {sequence}: hash chain broken (expected previous_hash {expected:?}, got {got:?})")]
    HashChainBroken {
        sequence: u64,
        expected: String,
        got: String,
    },

    #[error("entry {sequence}: entry_hash mismatch (expected {expected:?}, computed {computed:?})")]
    EntryHashMismatch {
        sequence: u64,
        expected: String,
        computed: String,
    },

    #[error("entry {sequence}: signature verification failed")]
    SignatureInvalid { sequence: u64 },

    #[error("entry {sequence}: expected sequence {expected}, got {got}")]
    SequenceGap {
        sequence: u64,
        expected: u64,
        got: u64,
    },

    #[error("entry 0: previous_hash must be empty for the first entry")]
    NonEmptyGenesisPreviousHash,

    #[error("deserialization failed at line {line}: {reason}")]
    Deserialization { line: usize, reason: String },
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/// Append-only audit logger that maintains hash chain state.
///
/// Generic over `W: Write` so it can target a file (with O_APPEND) or an
/// in-memory buffer for testing.
pub struct AuditLogger<W: Write> {
    writer: W,
    signing_key: SigningKey,
    signer_kid: String,
    sequence: u64,
    previous_hash: String,
}

impl<W: Write> AuditLogger<W> {
    /// Create a new audit logger starting at sequence 0 with an empty
    /// previous_hash (genesis).
    pub fn new(writer: W, signing_key: SigningKey, signer_kid: String) -> Self {
        Self {
            writer,
            signing_key,
            signer_kid,
            sequence: 0,
            previous_hash: String::new(),
        }
    }

    /// Resume an audit logger from a known state.
    ///
    /// Use this when replaying an existing log file to continue appending
    /// from the correct sequence number and hash chain position.
    pub fn resume(
        writer: W,
        signing_key: SigningKey,
        signer_kid: String,
        next_sequence: u64,
        last_entry_hash: String,
    ) -> Self {
        Self {
            writer,
            signing_key,
            signer_kid,
            sequence: next_sequence,
            previous_hash: last_entry_hash,
        }
    }

    /// Log a command/verdict pair. Produces a `SignedAuditEntry`, writes it
    /// as a single JSONL line, and advances the hash chain.
    pub fn log(
        &mut self,
        command: &Command,
        signed_verdict: &SignedVerdict,
    ) -> Result<SignedAuditEntry, AuditError> {
        let entry = self.build_entry(command, signed_verdict)?;
        let signed = self.sign_entry(&entry)?;

        // Write as a single JSONL line.
        let json = serde_json::to_string(&signed).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;
        writeln!(self.writer, "{json}")?;

        // Advance hash chain state.
        self.previous_hash = entry.entry_hash.clone();
        self.sequence += 1;

        Ok(signed)
    }

    /// Current sequence number (the next entry will have this sequence).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The hash of the last written entry (empty string if no entries yet).
    pub fn previous_hash(&self) -> &str {
        &self.previous_hash
    }

    fn build_entry(
        &self,
        command: &Command,
        signed_verdict: &SignedVerdict,
    ) -> Result<AuditEntry, AuditError> {
        // Build the entry without the hash first.
        let mut entry = AuditEntry {
            sequence: self.sequence,
            previous_hash: self.previous_hash.clone(),
            command: command.clone(),
            verdict: signed_verdict.clone(),
            entry_hash: String::new(),
        };

        // Compute entry_hash over the canonical JSON of the entry (with
        // empty entry_hash). This makes the hash cover sequence,
        // previous_hash, command, and verdict — the full audit record.
        let entry_json =
            serde_json::to_vec(&entry).map_err(|e| AuditError::Serialization {
                reason: e.to_string(),
            })?;
        entry.entry_hash = sha256_hex(&entry_json);

        Ok(entry)
    }

    fn sign_entry(&self, entry: &AuditEntry) -> Result<SignedAuditEntry, AuditError> {
        let entry_json =
            serde_json::to_vec(entry).map_err(|e| AuditError::Serialization {
                reason: e.to_string(),
            })?;

        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(&entry_json);

        Ok(SignedAuditEntry {
            entry: entry.clone(),
            entry_signature: STANDARD.encode(signature.to_bytes()),
            signer_kid: self.signer_kid.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// File-backed constructor
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "unknown"))]
impl AuditLogger<std::io::BufWriter<std::fs::File>> {
    /// Open a file in append-only mode and create an audit logger for it.
    ///
    /// The file is opened with `O_APPEND | O_CREATE | O_WRONLY` to enforce
    /// immutability (L4). If the file already exists, new entries are
    /// appended.
    pub fn open_file(
        path: &std::path::Path,
        signing_key: SigningKey,
        signer_kid: String,
    ) -> Result<Self, AuditError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self::new(std::io::BufWriter::new(file), signing_key, signer_kid))
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify an audit log's integrity: hash chain continuity (L2), entry hash
/// correctness, signature validity (L3), and sequence monotonicity.
///
/// Returns the number of verified entries on success, or the first error.
pub fn verify_log(
    jsonl: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<u64, AuditVerifyError> {
    let mut previous_hash = String::new();
    let mut expected_sequence: u64 = 0;

    for (line_idx, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let signed: SignedAuditEntry =
            serde_json::from_str(line).map_err(|e| AuditVerifyError::Deserialization {
                line: line_idx + 1,
                reason: e.to_string(),
            })?;

        let entry = &signed.entry;

        // Check sequence monotonicity.
        if entry.sequence != expected_sequence {
            return Err(AuditVerifyError::SequenceGap {
                sequence: entry.sequence,
                expected: expected_sequence,
                got: entry.sequence,
            });
        }

        // Check hash chain linkage (L2).
        if entry.sequence == 0 {
            if !entry.previous_hash.is_empty() {
                return Err(AuditVerifyError::NonEmptyGenesisPreviousHash);
            }
        } else if entry.previous_hash != previous_hash {
            return Err(AuditVerifyError::HashChainBroken {
                sequence: entry.sequence,
                expected: previous_hash,
                got: entry.previous_hash.clone(),
            });
        }

        // Recompute entry_hash and verify.
        let mut recompute_entry = entry.clone();
        recompute_entry.entry_hash = String::new();
        let entry_json = serde_json::to_vec(&recompute_entry).map_err(|e| {
            AuditVerifyError::Deserialization {
                line: line_idx + 1,
                reason: e.to_string(),
            }
        })?;
        let computed_hash = sha256_hex(&entry_json);
        if computed_hash != entry.entry_hash {
            return Err(AuditVerifyError::EntryHashMismatch {
                sequence: entry.sequence,
                expected: entry.entry_hash.clone(),
                computed: computed_hash,
            });
        }

        // Verify Ed25519 signature (L3).
        let signed_json = serde_json::to_vec(entry).map_err(|e| {
            AuditVerifyError::Deserialization {
                line: line_idx + 1,
                reason: e.to_string(),
            }
        })?;
        let sig_bytes = STANDARD
            .decode(&signed.entry_signature)
            .map_err(|_| AuditVerifyError::SignatureInvalid {
                sequence: entry.sequence,
            })?;
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|_| {
            AuditVerifyError::SignatureInvalid {
                sequence: entry.sequence,
            }
        })?;
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(&signed_json, &signature)
            .map_err(|_| AuditVerifyError::SignatureInvalid {
                sequence: entry.sequence,
            })?;

        // Advance state.
        previous_hash = entry.entry_hash.clone();
        expected_sequence += 1;
    }

    Ok(expected_sequence)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::crypto::{generate_keypair, sign_pca};
    use crate::models::authority::{Operation, Pca};
    use crate::models::command::{Command, CommandAuthority, JointState};
    use crate::models::profile::*;
    use crate::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use crate::validator::ValidatorConfig;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use rand::rngs::OsRng;
    use std::collections::{BTreeSet, HashMap};

    fn op(s: &str) -> Operation {
        Operation::new(s).unwrap()
    }

    fn ops(ss: &[&str]) -> BTreeSet<Operation> {
        ss.iter().map(|s| op(s)).collect()
    }

    fn make_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn test_profile() -> RobotProfile {
        RobotProfile {
            name: "test_robot".into(),
            version: "1.0.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -3.15,
                max: 3.15,
                max_velocity: 5.0,
                max_torque: 100.0,
                max_acceleration: 50.0,
            }],
            workspace: WorkspaceBounds::Aabb {
                min: [-2.0, -2.0, 0.0],
                max: [2.0, 2.0, 3.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            max_delta_time: 0.1,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
        }
    }

    fn encode_chain(hops: &[crate::models::authority::SignedPca]) -> String {
        let json = serde_json::to_vec(hops).unwrap();
        STANDARD.encode(&json)
    }

    fn make_command(chain_b64: &str, required_ops: Vec<Operation>) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 1.0,
                effort: 10.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: chain_b64.to_string(),
                required_ops,
            },
            metadata: HashMap::new(),
        }
    }

    fn make_approved_result(
        command: &Command,
    ) -> (SignedVerdict, ValidatorConfig, SigningKey) {
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _sign_vk) = make_keypair();

        let claim = Pca {
            p_0: "alice".into(),
            ops: ops(&["actuate:*"]),
            kid: "key-1".into(),
            exp: None,
            nbf: None,
        };
        let signed_pca = sign_pca(&claim, &pca_sk).unwrap();
        let chain_b64 = encode_chain(&[signed_pca]);

        let mut trusted = HashMap::new();
        trusted.insert("key-1".to_string(), pca_vk);

        let config = ValidatorConfig::new(
            test_profile(),
            trusted,
            sign_sk.clone(),
            "invariant-test".into(),
        )
        .unwrap();

        let mut cmd = command.clone();
        cmd.authority.pca_chain = chain_b64;

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        (result.signed_verdict, config, sign_sk)
    }

    fn make_simple_signed_verdict() -> (SignedVerdict, SigningKey) {
        let (sign_sk, _) = make_keypair();
        let verdict = Verdict {
            approved: true,
            command_hash: "sha256:abc123".into(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks: vec![CheckResult {
                name: "test".into(),
                category: "test".into(),
                passed: true,
                details: "ok".into(),
            }],
            profile_name: "test_robot".into(),
            profile_hash: "sha256:def456".into(),
            authority_summary: AuthoritySummary {
                origin_principal: "alice".into(),
                hop_count: 1,
                operations_granted: vec!["actuate:*".into()],
                operations_required: vec!["actuate:j1".into()],
            },
        };

        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        use ed25519_dalek::Signer;
        let signature = sign_sk.sign(&verdict_json);

        let signed = SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(signature.to_bytes()),
            signer_kid: "invariant-test".into(),
        };

        (signed, sign_sk)
    }

    fn make_simple_command() -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 1.0,
                effort: 10.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![op("actuate:j1")],
            },
            metadata: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Core tests
    // -----------------------------------------------------------------------

    #[test]
    fn single_entry_log_and_verify() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        let entry = logger.log(&cmd, &verdict).unwrap();

        assert_eq!(entry.entry.sequence, 0);
        assert!(entry.entry.previous_hash.is_empty());
        assert!(entry.entry.entry_hash.starts_with("sha256:"));
        assert!(!entry.entry_signature.is_empty());
        assert_eq!(entry.signer_kid, "invariant-001");

        // Logger state advanced.
        assert_eq!(logger.sequence(), 1);
        assert_eq!(logger.previous_hash(), &entry.entry.entry_hash);

        // Verify the JSONL output.
        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn multi_entry_hash_chain() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        let e0 = logger.log(&cmd, &verdict).unwrap();
        let e1 = logger.log(&cmd, &verdict).unwrap();
        let e2 = logger.log(&cmd, &verdict).unwrap();

        // Hash chain links.
        assert!(e0.entry.previous_hash.is_empty());
        assert_eq!(e1.entry.previous_hash, e0.entry.entry_hash);
        assert_eq!(e2.entry.previous_hash, e1.entry.entry_hash);

        // Monotonic sequence.
        assert_eq!(e0.entry.sequence, 0);
        assert_eq!(e1.entry.sequence, 1);
        assert_eq!(e2.entry.sequence, 2);

        // All hashes are distinct.
        assert_ne!(e0.entry.entry_hash, e1.entry.entry_hash);
        assert_ne!(e1.entry.entry_hash, e2.entry.entry_hash);

        // Verify full chain.
        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn tampered_entry_hash_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        // Tamper: modify the entry_hash in the JSONL.
        let jsonl = String::from_utf8(buf).unwrap();
        let tampered = jsonl.replace(
            r#""entry_hash":"sha256:"#,
            r#""entry_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000_REPLACED_"#,
        );

        let result = verify_log(&tampered, &sign_vk);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_signature_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        // Tamper: replace signature with zeros.
        let jsonl = String::from_utf8(buf).unwrap();
        let entry: serde_json::Value = serde_json::from_str(jsonl.trim()).unwrap();
        let mut tampered_entry = entry.clone();
        tampered_entry["entry_signature"] =
            serde_json::Value::String(STANDARD.encode([0u8; 64]));
        let tampered_jsonl = serde_json::to_string(&tampered_entry).unwrap() + "\n";

        let result = verify_log(&tampered_jsonl, &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::SignatureInvalid { sequence } => assert_eq!(sequence, 0),
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let (sign_sk, _) = make_keypair();
        let (_, wrong_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        let jsonl = String::from_utf8(buf).unwrap();
        let result = verify_log(&jsonl, &wrong_vk);
        assert!(result.is_err());
    }

    #[test]
    fn broken_hash_chain_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();
        logger.log(&cmd, &verdict).unwrap();

        // Parse both entries, swap the order so hash chain breaks.
        let jsonl = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);

        // Swapping lines will cause hash chain mismatch at entry 1.
        let swapped = format!("{}\n{}\n", lines[1], lines[0]);
        let result = verify_log(&swapped, &sign_vk);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_gap_detected() {
        let (sign_sk, sign_vk) = make_keypair();

        // Log entry 0.
        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger1.log(&cmd, &verdict).unwrap();

        // Log entry with sequence=2 (skipping 1) via resume.
        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::resume(
            &mut buf2,
            sign_sk,
            "test".into(),
            2, // skip sequence 1
            logger1.previous_hash().to_string(),
        );
        logger2.log(&cmd, &verdict).unwrap();

        let jsonl = format!(
            "{}{}\n",
            String::from_utf8(buf1).unwrap(),
            String::from_utf8(buf2).unwrap().trim()
        );
        let result = verify_log(&jsonl, &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::SequenceGap { expected, got, .. } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("expected SequenceGap, got {other:?}"),
        }
    }

    #[test]
    fn resume_continues_chain() {
        let (sign_sk, sign_vk) = make_keypair();

        // Phase 1: log two entries.
        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger1.log(&cmd, &verdict).unwrap();
        logger1.log(&cmd, &verdict).unwrap();

        let seq = logger1.sequence();
        let prev = logger1.previous_hash().to_string();

        // Phase 2: resume and log one more.
        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::resume(&mut buf2, sign_sk, "test".into(), seq, prev);
        logger2.log(&cmd, &verdict).unwrap();

        // Combine JSONL and verify full chain.
        let jsonl = format!(
            "{}{}",
            String::from_utf8(buf1).unwrap(),
            String::from_utf8(buf2).unwrap(),
        );
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn empty_log_verifies() {
        let (_, sign_vk) = make_keypair();
        let count = verify_log("", &sign_vk).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let (sign_sk, _) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let e1 = logger1.log(&cmd, &verdict).unwrap();

        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::new(&mut buf2, sign_sk, "test".into());
        let e2 = logger2.log(&cmd, &verdict).unwrap();

        assert_eq!(e1.entry.entry_hash, e2.entry.entry_hash);
        assert_eq!(e1.entry_signature, e2.entry_signature);
    }

    #[test]
    fn rejected_verdict_also_logged() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk.clone(), "test".into());

        // Create a rejection verdict.
        let verdict = Verdict {
            approved: false,
            command_hash: "sha256:rejected".into(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks: vec![CheckResult {
                name: "authority".into(),
                category: "authority".into(),
                passed: false,
                details: "chain verification failed".into(),
            }],
            profile_name: "test".into(),
            profile_hash: "sha256:profile".into(),
            authority_summary: AuthoritySummary {
                origin_principal: String::new(),
                hop_count: 0,
                operations_granted: vec![],
                operations_required: vec!["actuate:j1".into()],
            },
        };
        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        use ed25519_dalek::Signer;
        let sig = sign_sk.sign(&verdict_json);
        let signed_verdict = SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(sig.to_bytes()),
            signer_kid: "test".into(),
        };

        let cmd = make_simple_command();
        let entry = logger.log(&cmd, &signed_verdict).unwrap();
        assert!(!entry.entry.verdict.verdict.approved);

        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn verify_detects_malformed_json() {
        let (_, sign_vk) = make_keypair();
        let result = verify_log("this is not json\n", &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::Deserialization { line, .. } => assert_eq!(line, 1),
            other => panic!("expected Deserialization, got {other:?}"),
        }
    }

    #[test]
    fn verify_skips_blank_lines() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        // Add blank lines around the entry.
        let jsonl = String::from_utf8(buf).unwrap();
        let with_blanks = format!("\n\n{jsonl}\n\n");
        let count = verify_log(&with_blanks, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn entry_contains_full_command_and_verdict() {
        let (sign_sk, _) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let entry = logger.log(&cmd, &verdict).unwrap();

        // L1: entry contains the full command and signed verdict.
        assert_eq!(entry.entry.command.source, "test");
        assert_eq!(entry.entry.command.sequence, 1);
        assert_eq!(
            entry.entry.verdict.verdict.command_hash,
            "sha256:abc123"
        );
        assert!(entry.entry.verdict.verdict.approved);
    }
}
