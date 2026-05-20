//! Hazard-database screening interface.
//!
//! This module provides a minimal, file-backed implementation of the
//! [`crate::invariants::HazardDatabase`] trait. The on-disk format is a
//! signed JSON document carrying three lists of hazard signatures (one per
//! substrate). The signature covers the canonical JSON of the body and is
//! verified on load with the existing Ed25519 infrastructure.
//!
//! See `spec.md` Step 4 for the format description and Step 5 for how the
//! validator pipeline consumes the resulting hits.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::invariants::HazardDatabase;
use crate::models::bundle::SynthesisPayload;
use crate::util::sha256_hex_json;

// ---------------------------------------------------------------------------
// On-disk format
// ---------------------------------------------------------------------------

/// One entry in the hazard database.
///
/// `pattern` is interpreted by substrate:
/// - DNA / peptide: a `regex::Regex` matched against the (case-folded)
///   sequence string;
/// - Chemical: a SMARTS-like placeholder that is currently matched as a
///   plain regex against the SMILES string. Real cheminformatics matching
///   lands in Step 8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HazardEntry {
    /// Stable id (e.g. `"hhs-sap-001"`).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Coarse hazard class (e.g. `"select-agent"`, `"cwc-schedule-1"`).
    pub hazard_class: String,
    /// Match pattern — see struct-level docs for substrate semantics.
    pub pattern: String,
}

/// Body of a signed hazard-database file. The signature in the enclosing
/// envelope covers the canonical JSON of this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HazardDatabaseBody {
    /// Format schema version. Must be 1.
    pub schema_version: u32,
    /// Monotonic database version — surfaced via [`HazardDatabase::version`].
    pub db_version: u64,
    /// DNA-substrate hazard signatures.
    #[serde(default)]
    pub dna_signatures: Vec<HazardEntry>,
    /// Peptide-substrate hazard signatures.
    #[serde(default)]
    pub peptide_signatures: Vec<HazardEntry>,
    /// Chemical-substrate hazard signatures.
    #[serde(default)]
    pub chemical_signatures: Vec<HazardEntry>,
}

/// Signed hazard-database file as it lives on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHazardFile {
    /// Key id of the issuer that signed `body`.
    pub issuer_kid: String,
    /// Base64-encoded Ed25519 signature over `sha256_hex_json(&body)`.
    pub signature: String,
    /// Hazard database body.
    pub body: HazardDatabaseBody,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the screening loader and matcher.
#[derive(Debug, Error)]
pub enum ScreeningError {
    /// The file could not be read.
    #[error("could not read hazard-database file: {0}")]
    Io(#[from] std::io::Error),
    /// The file contained invalid JSON.
    #[error("hazard-database JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    /// The schema version was unsupported.
    #[error("unsupported schema_version {found}; expected {expected}")]
    SchemaVersion {
        /// Version found in the file.
        found: u32,
        /// Version this binary supports.
        expected: u32,
    },
    /// The issuer key id was not in the trusted-keys map.
    #[error("issuer kid {kid:?} not in trusted keys")]
    UnknownIssuer {
        /// The unknown kid.
        kid: String,
    },
    /// The signature was malformed (bad base64 or wrong length).
    #[error("signature decode failed: {0}")]
    Signature(String),
    /// The signature did not verify against the canonical body bytes.
    #[error("signature verification failed (tampered or wrong key)")]
    SignatureMismatch,
    /// A hazard entry's pattern failed to compile as a regex.
    #[error("invalid regex pattern in entry {id:?}: {reason}")]
    BadPattern {
        /// Id of the offending entry.
        id: String,
        /// Compilation error.
        reason: String,
    },
    /// Consensus screening configuration error.
    #[error("consensus screening error: {0}")]
    Consensus(String),
}

// ---------------------------------------------------------------------------
// Match results
// ---------------------------------------------------------------------------

/// A single hazard-database hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HazardHit {
    /// The hazard entry that matched.
    pub entry: HazardEntry,
    /// The substring of the input that matched the entry's pattern.
    pub matched_text: String,
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

/// Trait for hazard databases that can also screen a synthesis payload.
///
/// Separated from [`HazardDatabase`] so the latter can stay free of substrate
/// imports. The validator pipeline (Step 5) consumes this trait via
/// `Arc<dyn HazardScreener>` so different concrete implementations
/// (file-backed, network-backed, in-memory test) can be plugged in without
/// recompiling the validator.
pub trait HazardScreener: HazardDatabase {
    /// Return all hazard-database hits for `payload`.
    fn screen_payload(&self, payload: &SynthesisPayload) -> Vec<HazardHit>;
}

/// File-backed implementation of [`HazardDatabase`].
#[derive(Debug)]
pub struct FileBackedHazardDatabase {
    body: HazardDatabaseBody,
    issuer_kid: String,
    loaded_at: Instant,
    freshness_window: Duration,
    dna_re: Vec<(HazardEntry, Regex)>,
    peptide_re: Vec<(HazardEntry, Regex)>,
    chemical_re: Vec<(HazardEntry, Regex)>,
}

const SUPPORTED_SCHEMA_VERSION: u32 = 1;

impl FileBackedHazardDatabase {
    /// Load and verify a signed hazard-database file.
    ///
    /// `trusted_keys` maps issuer kid → verifying key. The file's
    /// `issuer_kid` must be present in the map; the signature must verify
    /// against the canonical SHA-256 of the body's JSON.
    pub fn load(
        path: &Path,
        trusted_keys: &std::collections::HashMap<String, VerifyingKey>,
    ) -> Result<Self, ScreeningError> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes, trusted_keys)
    }

    /// Same as [`Self::load`] but for an already-buffered file.
    pub fn from_bytes(
        bytes: &[u8],
        trusted_keys: &std::collections::HashMap<String, VerifyingKey>,
    ) -> Result<Self, ScreeningError> {
        let file: SignedHazardFile = serde_json::from_slice(bytes)?;

        if file.body.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(ScreeningError::SchemaVersion {
                found: file.body.schema_version,
                expected: SUPPORTED_SCHEMA_VERSION,
            });
        }

        let key =
            trusted_keys
                .get(&file.issuer_kid)
                .ok_or_else(|| ScreeningError::UnknownIssuer {
                    kid: file.issuer_kid.clone(),
                })?;

        let canonical = sha256_hex_json(&file.body)?;
        let sig_bytes = STANDARD
            .decode(file.signature.as_bytes())
            .map_err(|e| ScreeningError::Signature(e.to_string()))?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ScreeningError::Signature("expected 64-byte signature".into()))?;
        let signature = Signature::from_bytes(&sig_array);
        key.verify(canonical.as_bytes(), &signature)
            .map_err(|_| ScreeningError::SignatureMismatch)?;

        let dna_re = compile_entries(&file.body.dna_signatures)?;
        let peptide_re = compile_entries(&file.body.peptide_signatures)?;
        let chemical_re = compile_entries(&file.body.chemical_signatures)?;

        Ok(Self {
            body: file.body,
            issuer_kid: file.issuer_kid,
            loaded_at: Instant::now(),
            freshness_window: Duration::from_secs(30 * 24 * 60 * 60),
            dna_re,
            peptide_re,
            chemical_re,
        })
    }

    /// Override the freshness window (default: 30 days).
    pub fn with_freshness_window(mut self, window: Duration) -> Self {
        self.freshness_window = window;
        self
    }

    /// Issuer key id that signed this database.
    pub fn issuer_kid(&self) -> &str {
        &self.issuer_kid
    }

    /// Screen a synthesis payload and return all hazard hits.
    pub fn screen(&self, payload: &SynthesisPayload) -> Result<Vec<HazardHit>, ScreeningError> {
        match payload {
            SynthesisPayload::Dna { sequence } => {
                Ok(match_entries(&self.dna_re, &sequence.to_ascii_uppercase()))
            }
            SynthesisPayload::Peptide { sequence } => Ok(match_entries(
                &self.peptide_re,
                &sequence.to_ascii_uppercase(),
            )),
            SynthesisPayload::Chemical { smiles } => Ok(match_entries(&self.chemical_re, smiles)),
            SynthesisPayload::Protocol { .. } => Ok(Vec::new()),
        }
    }
}

impl HazardDatabase for FileBackedHazardDatabase {
    fn freshness(&self) -> Duration {
        self.loaded_at.elapsed()
    }
    fn version(&self) -> u64 {
        self.body.db_version
    }
    fn freshness_window(&self) -> Duration {
        self.freshness_window
    }
}

impl HazardScreener for FileBackedHazardDatabase {
    fn screen_payload(&self, payload: &SynthesisPayload) -> Vec<HazardHit> {
        // `screen` itself only returns Err on a future I/O path; for the
        // currently supported substrate set the call is infallible. Surface
        // an empty hit set on the impossible-error branch so the trait
        // signature stays simple.
        self.screen(payload).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Consensus screener
// ---------------------------------------------------------------------------

/// Quorum policy for multi-source consensus screening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumPolicy {
    /// A hit from ANY source triggers a positive screen (fail-safe / union).
    Any,
    /// A hit must appear in ALL sources (intersection). Primarily for
    /// reducing FP in benign-research contexts.
    All,
    /// A hit must appear in at least N sources.
    AtLeast(usize),
}

/// Multi-source consensus screener.
///
/// Aggregates results from N independent [`HazardScreener`] backends and
/// applies a quorum policy. Disagreements between sources are surfaced in
/// the resulting hit metadata.
pub struct ConsensusHazardScreener {
    sources: Vec<Arc<dyn HazardScreener>>,
    policy: QuorumPolicy,
}

impl ConsensusHazardScreener {
    /// Create a new consensus screener.
    ///
    /// # Errors
    /// Returns an error if fewer than 2 sources are provided.
    pub fn new(
        sources: Vec<Arc<dyn HazardScreener>>,
        policy: QuorumPolicy,
    ) -> Result<Self, ScreeningError> {
        if sources.len() < 2 {
            return Err(ScreeningError::Consensus(
                "consensus screening requires at least 2 independent sources".into(),
            ));
        }
        Ok(Self { sources, policy })
    }

    /// Number of sources.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

impl HazardDatabase for ConsensusHazardScreener {
    fn freshness(&self) -> Duration {
        // Return the stalest source's freshness (worst case).
        self.sources
            .iter()
            .map(|s| s.freshness())
            .max()
            .unwrap_or(Duration::ZERO)
    }

    fn version(&self) -> u64 {
        // Return the minimum version (most conservative).
        self.sources
            .iter()
            .map(|s| s.version())
            .min()
            .unwrap_or(0)
    }

    fn freshness_window(&self) -> Duration {
        // Return the shortest window (most restrictive).
        self.sources
            .iter()
            .map(|s| s.freshness_window())
            .min()
            .unwrap_or(Duration::from_secs(30 * 24 * 60 * 60))
    }
}

impl HazardScreener for ConsensusHazardScreener {
    fn screen_payload(&self, payload: &SynthesisPayload) -> Vec<HazardHit> {
        // Collect hits from each source
        let per_source: Vec<Vec<HazardHit>> = self
            .sources
            .iter()
            .map(|s| s.screen_payload(payload))
            .collect();

        // Build a map: hazard_class -> count of sources that reported it
        let mut class_counts: std::collections::HashMap<String, (usize, HazardHit)> =
            std::collections::HashMap::new();
        for hits in &per_source {
            // Track which classes this source reported (dedup per source)
            let mut seen_classes: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for hit in hits {
                let class = hit.entry.hazard_class.to_ascii_lowercase();
                if seen_classes.insert(class.clone()) {
                    let entry = class_counts.entry(class).or_insert((0, hit.clone()));
                    entry.0 += 1;
                }
            }
        }

        let n = self.sources.len();
        let threshold = match self.policy {
            QuorumPolicy::Any => 1,
            QuorumPolicy::All => n,
            QuorumPolicy::AtLeast(k) => k.min(n),
        };

        class_counts
            .into_values()
            .filter(|(count, _)| *count >= threshold)
            .map(|(count, mut hit)| {
                if count < n {
                    // Disagreement: annotate the hit
                    hit.entry.label = format!(
                        "{} [consensus: {}/{} sources agree]",
                        hit.entry.label, count, n
                    );
                }
                hit
            })
            .collect()
    }
}

fn compile_entries(entries: &[HazardEntry]) -> Result<Vec<(HazardEntry, Regex)>, ScreeningError> {
    entries
        .iter()
        .map(|e| {
            Regex::new(&e.pattern)
                .map(|re| (e.clone(), re))
                .map_err(|err| ScreeningError::BadPattern {
                    id: e.id.clone(),
                    reason: err.to_string(),
                })
        })
        .collect()
}

fn match_entries(compiled: &[(HazardEntry, Regex)], haystack: &str) -> Vec<HazardHit> {
    let mut hits = Vec::new();
    for (entry, re) in compiled {
        if let Some(m) = re.find(haystack) {
            hits.push(HazardHit {
                entry: entry.clone(),
                matched_text: m.as_str().to_string(),
            });
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Test helpers (only compiled in tests)
// ---------------------------------------------------------------------------

/// Test/build helper: sign a [`HazardDatabaseBody`] with `signing_key` and
/// produce the on-disk envelope. Intended for fixtures and CLI integration
/// tests; production deployments should use a separate signing pipeline.
pub fn sign_body_for_tests(
    body: &HazardDatabaseBody,
    issuer_kid: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> SignedHazardFile {
    use ed25519_dalek::Signer;
    let canonical = sha256_hex_json(body).expect("hash body");
    let sig = signing_key.sign(canonical.as_bytes());
    SignedHazardFile {
        issuer_kid: issuer_kid.to_string(),
        signature: STANDARD.encode(sig.to_bytes()),
        body: body.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn body_with_one_of_each() -> HazardDatabaseBody {
        HazardDatabaseBody {
            schema_version: 1,
            db_version: 42,
            dna_signatures: vec![HazardEntry {
                id: "dna-1".into(),
                label: "ricin-A-fragment".into(),
                hazard_class: "select-agent".into(),
                pattern: "ATGAAA".into(),
            }],
            peptide_signatures: vec![HazardEntry {
                id: "pep-1".into(),
                label: "melittin".into(),
                hazard_class: "antimicrobial".into(),
                pattern: "GIGAVL".into(),
            }],
            chemical_signatures: vec![HazardEntry {
                id: "chem-1".into(),
                label: "sarin-fragment".into(),
                hazard_class: "cwc-schedule-1".into(),
                pattern: r"P\(=O\)".into(),
            }],
        }
    }

    fn trusted(kid: &str, sk: &SigningKey) -> HashMap<String, VerifyingKey> {
        let mut map = HashMap::new();
        map.insert(kid.to_string(), sk.verifying_key());
        map
    }

    #[test]
    fn loads_and_verifies_valid_signed_file() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap();
        assert_eq!(db.issuer_kid(), "issuer-1");
        assert_eq!(db.version(), 42);
    }

    #[test]
    fn rejects_tampered_body() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        // Mutate the body after signing.
        signed.body.db_version = 999;
        let bytes = serde_json::to_vec(&signed).unwrap();
        let err =
            FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap_err();
        assert!(matches!(err, ScreeningError::SignatureMismatch));
    }

    #[test]
    fn rejects_wrong_key() {
        let signer = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &signer);
        let bytes = serde_json::to_vec(&signed).unwrap();
        // Trusted map has the *attacker's* key under the same kid.
        let err = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &attacker))
            .unwrap_err();
        assert!(matches!(err, ScreeningError::SignatureMismatch));
    }

    #[test]
    fn rejects_unknown_issuer() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let err =
            FileBackedHazardDatabase::from_bytes(&bytes, &trusted("other-kid", &sk)).unwrap_err();
        assert!(matches!(err, ScreeningError::UnknownIssuer { .. }));
    }

    #[test]
    fn rejects_bad_schema_version() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut body = body_with_one_of_each();
        body.schema_version = 99;
        let signed = sign_body_for_tests(&body, "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let err =
            FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap_err();
        assert!(matches!(err, ScreeningError::SchemaVersion { .. }));
    }

    #[test]
    fn rejects_invalid_regex_pattern() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut body = body_with_one_of_each();
        body.dna_signatures[0].pattern = "(unclosed".into();
        let signed = sign_body_for_tests(&body, "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let err =
            FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap_err();
        assert!(matches!(err, ScreeningError::BadPattern { .. }));
    }

    #[test]
    fn screen_dna_hits_match() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap();
        let hits = db
            .screen(&SynthesisPayload::Dna {
                sequence: "GGGATGAAACCC".into(),
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entry.id, "dna-1");
        assert_eq!(hits[0].matched_text, "ATGAAA");
    }

    #[test]
    fn screen_dna_lowercase_normalized() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap();
        let hits = db
            .screen(&SynthesisPayload::Dna {
                sequence: "gggatgaaaccc".into(),
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn screen_peptide_hits_match() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap();
        let hits = db
            .screen(&SynthesisPayload::Peptide {
                sequence: "PREGIGAVLKVLT".into(),
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entry.id, "pep-1");
    }

    #[test]
    fn screen_chemical_hits_match() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap();
        let hits = db
            .screen(&SynthesisPayload::Chemical {
                smiles: "CCP(=O)(OC)F".into(),
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entry.id, "chem-1");
    }

    #[test]
    fn screen_returns_empty_when_no_match() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap();
        let hits = db
            .screen(&SynthesisPayload::Dna {
                sequence: "CCCCCC".into(),
            })
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn screen_protocol_returns_empty() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap();
        let hits = db
            .screen(&SynthesisPayload::Protocol { steps: vec![] })
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn freshness_starts_near_zero_and_window_default_30_days() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap();
        assert!(db.freshness() < Duration::from_secs(5));
        assert_eq!(
            db.freshness_window(),
            Duration::from_secs(30 * 24 * 60 * 60)
        );
        assert!(!db.is_stale());
    }

    #[test]
    fn freshness_window_is_overridable() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk))
            .unwrap()
            .with_freshness_window(Duration::from_secs(60));
        assert_eq!(db.freshness_window(), Duration::from_secs(60));
    }

    #[test]
    fn unknown_substrate_serde_field_rejected() {
        let bad = r#"{"issuer_kid":"x","signature":"","body":{"schema_version":1,"db_version":1,"junk":[]}}"#;
        let err = serde_json::from_str::<SignedHazardFile>(bad).unwrap_err();
        assert!(err.to_string().contains("junk"));
    }

    // -----------------------------------------------------------------------
    // ConsensusHazardScreener tests
    // -----------------------------------------------------------------------

    #[test]
    fn consensus_requires_at_least_two_sources() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db = Arc::new(
            FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap(),
        );
        let result = ConsensusHazardScreener::new(vec![db], QuorumPolicy::Any);
        assert!(result.is_err());
    }

    #[test]
    fn consensus_any_policy_union_of_sources() {
        let sk = SigningKey::generate(&mut OsRng);
        // Source 1: has DNA pattern
        let body1 = HazardDatabaseBody {
            schema_version: 1,
            db_version: 1,
            dna_signatures: vec![HazardEntry {
                id: "dna-1".into(),
                label: "hazard-a".into(),
                hazard_class: "select-agent".into(),
                pattern: "ATGAAA".into(),
            }],
            peptide_signatures: vec![],
            chemical_signatures: vec![],
        };
        // Source 2: different DNA pattern
        let body2 = HazardDatabaseBody {
            schema_version: 1,
            db_version: 2,
            dna_signatures: vec![HazardEntry {
                id: "dna-2".into(),
                label: "hazard-b".into(),
                hazard_class: "pandemic".into(),
                pattern: "CCCGGG".into(),
            }],
            peptide_signatures: vec![],
            chemical_signatures: vec![],
        };
        let signed1 = sign_body_for_tests(&body1, "issuer-1", &sk);
        let signed2 = sign_body_for_tests(&body2, "issuer-1", &sk);
        let db1 = Arc::new(
            FileBackedHazardDatabase::from_bytes(
                &serde_json::to_vec(&signed1).unwrap(),
                &trusted("issuer-1", &sk),
            )
            .unwrap(),
        ) as Arc<dyn HazardScreener>;
        let db2 = Arc::new(
            FileBackedHazardDatabase::from_bytes(
                &serde_json::to_vec(&signed2).unwrap(),
                &trusted("issuer-1", &sk),
            )
            .unwrap(),
        ) as Arc<dyn HazardScreener>;

        let consensus =
            ConsensusHazardScreener::new(vec![db1, db2], QuorumPolicy::Any).unwrap();
        let hits = consensus.screen_payload(&SynthesisPayload::Dna {
            sequence: "ATGAAACCCGGG".into(),
        });
        assert_eq!(hits.len(), 2); // Both sources contribute
    }

    #[test]
    fn consensus_all_policy_requires_agreement() {
        let sk = SigningKey::generate(&mut OsRng);
        let body1 = HazardDatabaseBody {
            schema_version: 1,
            db_version: 1,
            dna_signatures: vec![HazardEntry {
                id: "dna-1".into(),
                label: "hazard-a".into(),
                hazard_class: "select-agent".into(),
                pattern: "ATGAAA".into(),
            }],
            peptide_signatures: vec![],
            chemical_signatures: vec![],
        };
        let body2 = HazardDatabaseBody {
            schema_version: 1,
            db_version: 2,
            dna_signatures: vec![], // no DNA signatures at all
            peptide_signatures: vec![],
            chemical_signatures: vec![],
        };
        let db1 = Arc::new(
            FileBackedHazardDatabase::from_bytes(
                &serde_json::to_vec(&sign_body_for_tests(&body1, "issuer-1", &sk)).unwrap(),
                &trusted("issuer-1", &sk),
            )
            .unwrap(),
        ) as Arc<dyn HazardScreener>;
        let db2 = Arc::new(
            FileBackedHazardDatabase::from_bytes(
                &serde_json::to_vec(&sign_body_for_tests(&body2, "issuer-1", &sk)).unwrap(),
                &trusted("issuer-1", &sk),
            )
            .unwrap(),
        ) as Arc<dyn HazardScreener>;

        let consensus =
            ConsensusHazardScreener::new(vec![db1, db2], QuorumPolicy::All).unwrap();
        let hits = consensus.screen_payload(&SynthesisPayload::Dna {
            sequence: "ATGAAA".into(),
        });
        assert!(hits.is_empty()); // Only one source has the hit
    }

    #[test]
    fn consensus_disagreement_annotated() {
        let sk = SigningKey::generate(&mut OsRng);
        let body1 = HazardDatabaseBody {
            schema_version: 1,
            db_version: 1,
            dna_signatures: vec![HazardEntry {
                id: "dna-1".into(),
                label: "hazard-a".into(),
                hazard_class: "select-agent".into(),
                pattern: "ATGAAA".into(),
            }],
            peptide_signatures: vec![],
            chemical_signatures: vec![],
        };
        let body2 = HazardDatabaseBody {
            schema_version: 1,
            db_version: 2,
            dna_signatures: vec![],
            peptide_signatures: vec![],
            chemical_signatures: vec![],
        };
        let db1 = Arc::new(
            FileBackedHazardDatabase::from_bytes(
                &serde_json::to_vec(&sign_body_for_tests(&body1, "issuer-1", &sk)).unwrap(),
                &trusted("issuer-1", &sk),
            )
            .unwrap(),
        ) as Arc<dyn HazardScreener>;
        let db2 = Arc::new(
            FileBackedHazardDatabase::from_bytes(
                &serde_json::to_vec(&sign_body_for_tests(&body2, "issuer-1", &sk)).unwrap(),
                &trusted("issuer-1", &sk),
            )
            .unwrap(),
        ) as Arc<dyn HazardScreener>;

        let consensus =
            ConsensusHazardScreener::new(vec![db1, db2], QuorumPolicy::Any).unwrap();
        let hits = consensus.screen_payload(&SynthesisPayload::Dna {
            sequence: "ATGAAA".into(),
        });
        assert_eq!(hits.len(), 1);
        assert!(hits[0].entry.label.contains("consensus: 1/2")); // Disagreement annotated
    }

    #[test]
    fn consensus_freshness_takes_worst_case() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = sign_body_for_tests(&body_with_one_of_each(), "issuer-1", &sk);
        let bytes = serde_json::to_vec(&signed).unwrap();
        let db1 = Arc::new(
            FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap(),
        ) as Arc<dyn HazardScreener>;
        let db2 = Arc::new(
            FileBackedHazardDatabase::from_bytes(&bytes, &trusted("issuer-1", &sk)).unwrap(),
        ) as Arc<dyn HazardScreener>;

        let consensus =
            ConsensusHazardScreener::new(vec![db1, db2], QuorumPolicy::Any).unwrap();
        assert_eq!(consensus.source_count(), 2);
        // Freshness should be very small (just loaded)
        assert!(consensus.freshness() < Duration::from_secs(5));
    }
}
