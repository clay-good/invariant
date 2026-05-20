//! Synthesis bundle — the bio analog of a robotics motion command.
//!
//! A `SynthesisBundle` is the payload submitted to the firewall. It carries:
//! * a cryptographic envelope (timestamp, source, monotonic sequence number),
//! * a `BundleAuthority` with a base64-encoded COSE_Sign1 PCA chain,
//! * a typed `SynthesisPayload` describing the requested synthesis.
//!
//! This file replaces the `models/command.rs` from the sibling robotics project. The
//! envelope shape is preserved so the [`crate::audit`] logger and
//! [`crate::authority`] pipeline can stay substrate-agnostic.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::authority::Operation;
use super::error::ValidationError;
use super::profile::BioProfile;

/// Maximum length of the `source` field in bytes.
pub const MAX_BUNDLE_SOURCE_LEN: usize = 256;
/// Maximum length of a single metadata key in bytes.
pub const MAX_METADATA_KEY_LEN: usize = 128;
/// Maximum length of a single metadata value in bytes.
pub const MAX_METADATA_VALUE_LEN: usize = 1024;
/// Maximum number of metadata entries.
pub const MAX_METADATA_ENTRIES: usize = 64;
/// Maximum total size (sum of all key + value byte lengths) of metadata.
pub const MAX_METADATA_TOTAL_BYTES: usize = 10 * 1024; // 10 KiB

/// Default maximum DNA sequence length in base pairs.
pub const DEFAULT_MAX_DNA_LENGTH_BP: u64 = 1_000_000;
/// Default maximum peptide sequence length in amino acids.
pub const DEFAULT_MAX_PEPTIDE_LENGTH_AA: u64 = 100_000;
/// Default maximum SMILES string length in characters.
pub const DEFAULT_MAX_SMILES_LENGTH_CHARS: u64 = 100_000;

/// A signed synthesis request submitted to the firewall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SynthesisBundle {
    /// RFC 3339 / ISO 8601 timestamp.
    pub timestamp: DateTime<Utc>,
    /// Identifier of the cognitive layer or planner that issued this bundle.
    pub source: String,
    /// Monotonic sequence number. Out-of-order or duplicate bundles are rejected.
    pub sequence: u64,
    /// Typed synthesis payload (DNA / peptide / chemical / protocol).
    pub payload: SynthesisPayload,
    /// Time since the previous bundle in seconds.
    #[serde(default)]
    pub delta_time: f64,
    /// Authority evidence: PCA chain + claimed operations.
    pub authority: BundleAuthority,
    /// Flat key-value metadata. String values only to prevent deeply-nested
    /// JSON objects from causing stack-overflow DoS.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// The requested synthesis, tagged by substrate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum SynthesisPayload {
    /// DNA synthesis request (raw nucleotide sequence).
    Dna {
        /// IUPAC DNA sequence (A/C/G/T/N).
        sequence: String,
    },
    /// Peptide synthesis request (amino-acid sequence, one-letter code).
    Peptide {
        /// One-letter amino-acid sequence.
        sequence: String,
    },
    /// Small-molecule synthesis request (SMILES string).
    Chemical {
        /// SMILES representation of the target molecule.
        smiles: String,
    },
    /// Lab protocol (ordered list of steps for an automation platform).
    Protocol {
        /// Ordered protocol steps.
        steps: Vec<String>,
    },
}

/// Authority evidence carried with a bundle: the PCA chain and claimed operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleAuthority {
    /// Base64-encoded COSE_Sign1 PCA chain.
    pub pca_chain: String,
    /// Operations this bundle requires. Validated against the decoded chain's final_ops.
    pub required_ops: Vec<Operation>,
}

impl SynthesisBundle {
    /// Validates the structural shape of the bundle: source length, metadata
    /// bounds, and payload-size caps (profile-driven). Call this before running
    /// authority/screening/invariants.
    pub fn validate_bundle_shape(&self, profile: &BioProfile) -> Result<(), ValidationError> {
        // --- Source ---
        if self.source.is_empty() {
            return Err(ValidationError::BundleFieldInvalid {
                field: "source",
                reason: "source must be non-empty".into(),
            });
        }
        if self.source.len() > MAX_BUNDLE_SOURCE_LEN {
            return Err(ValidationError::BundleFieldInvalid {
                field: "source",
                reason: format!(
                    "source length {} exceeds maximum of {} bytes",
                    self.source.len(),
                    MAX_BUNDLE_SOURCE_LEN
                ),
            });
        }

        // --- Metadata ---
        if self.metadata.len() > MAX_METADATA_ENTRIES {
            return Err(ValidationError::BundleFieldInvalid {
                field: "metadata",
                reason: format!(
                    "metadata has {} entries, exceeding maximum of {}",
                    self.metadata.len(),
                    MAX_METADATA_ENTRIES
                ),
            });
        }
        let mut total_bytes: usize = 0;
        for (k, v) in &self.metadata {
            if k.len() > MAX_METADATA_KEY_LEN {
                return Err(ValidationError::BundleFieldInvalid {
                    field: "metadata",
                    reason: format!(
                        "metadata key length {} exceeds maximum of {} bytes",
                        k.len(),
                        MAX_METADATA_KEY_LEN
                    ),
                });
            }
            if v.len() > MAX_METADATA_VALUE_LEN {
                return Err(ValidationError::BundleFieldInvalid {
                    field: "metadata",
                    reason: format!(
                        "metadata value length {} exceeds maximum of {} bytes",
                        v.len(),
                        MAX_METADATA_VALUE_LEN
                    ),
                });
            }
            total_bytes += k.len() + v.len();
        }
        if total_bytes > MAX_METADATA_TOTAL_BYTES {
            return Err(ValidationError::BundleFieldInvalid {
                field: "metadata",
                reason: format!(
                    "metadata total size {} bytes exceeds maximum of {} bytes",
                    total_bytes, MAX_METADATA_TOTAL_BYTES
                ),
            });
        }

        // --- Payload length caps ---
        match &self.payload {
            SynthesisPayload::Dna { sequence } => {
                let max = profile
                    .max_dna_length_bp
                    .unwrap_or(DEFAULT_MAX_DNA_LENGTH_BP);
                let len = sequence.len() as u64;
                if len > max {
                    return Err(ValidationError::BundleFieldInvalid {
                        field: "payload",
                        reason: format!("DNA sequence length {len} bp exceeds maximum of {max} bp"),
                    });
                }
            }
            SynthesisPayload::Peptide { sequence } => {
                let max = profile
                    .max_peptide_length_aa
                    .unwrap_or(DEFAULT_MAX_PEPTIDE_LENGTH_AA);
                let len = sequence.len() as u64;
                if len > max {
                    return Err(ValidationError::BundleFieldInvalid {
                        field: "payload",
                        reason: format!(
                            "peptide sequence length {len} aa exceeds maximum of {max} aa"
                        ),
                    });
                }
            }
            SynthesisPayload::Chemical { smiles } => {
                let max = profile
                    .max_smiles_length_chars
                    .unwrap_or(DEFAULT_MAX_SMILES_LENGTH_CHARS);
                let len = smiles.len() as u64;
                if len > max {
                    return Err(ValidationError::BundleFieldInvalid {
                        field: "payload",
                        reason: format!("SMILES length {len} chars exceeds maximum of {max} chars"),
                    });
                }
            }
            SynthesisPayload::Protocol { .. } => {
                // Protocol steps are bounded by the vocabulary check, not
                // a length cap.
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn base_profile() -> BioProfile {
        BioProfile {
            name: "test".into(),
            version: "0.1.0".into(),
            bsl_level: 1,
            allowed_substrates: vec!["dna".into()],
            max_synthesis_volume_ml: 5.0,
            export_controlled: false,
            profile_signature: None,
            profile_signer_kid: None,
            codon_usage_organism: None,
            codon_entropy_band: None,
            allowed_protocol_steps: None,
            protein_kmer_k: None,
            protein_kmer_threshold: None,
            allow_stale_screening: false,
            stale_screening_max_days: None,
            max_authority_chain_depth: 5,
            max_dna_length_bp: None,
            max_peptide_length_aa: None,
            max_smiles_length_chars: None,
        }
    }

    fn base_bundle() -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "test-source".into(),
            sequence: 1,
            payload: SynthesisPayload::Dna {
                sequence: "ATGCGT".into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: HashMap::new(),
        }
    }

    // --- V10-1: deny_unknown_fields ---

    #[test]
    fn reject_unknown_fields_bundle() {
        let json = r#"{
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "sequence": 1,
            "payload": {"kind": "dna", "sequence": "ATGC"},
            "authority": {"pca_chain": "", "required_ops": []},
            "exfil_channel": "smuggled-data"
        }"#;
        let err = serde_json::from_str::<SynthesisBundle>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "error: {err}");
    }

    #[test]
    fn reject_unknown_fields_authority() {
        let json = r#"{
            "pca_chain": "",
            "required_ops": [],
            "exfil_channel": "smuggled-data"
        }"#;
        let err = serde_json::from_str::<BundleAuthority>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "error: {err}");
    }

    #[test]
    fn reject_unknown_fields_payload() {
        let json = r#"{"kind": "dna", "sequence": "ATGC", "exfil_channel": "smuggled"}"#;
        let err = serde_json::from_str::<SynthesisPayload>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "error: {err}");
    }

    #[test]
    fn valid_bundle_deserializes() {
        let json = r#"{
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "sequence": 1,
            "payload": {"kind": "dna", "sequence": "ATGC"},
            "authority": {"pca_chain": "", "required_ops": []}
        }"#;
        let bundle: SynthesisBundle = serde_json::from_str(json).unwrap();
        assert_eq!(bundle.source, "test");
    }

    // --- V10-2: source length bounds ---

    #[test]
    fn source_empty_rejected() {
        let b = SynthesisBundle {
            source: String::new(),
            ..base_bundle()
        };
        let err = b.validate_bundle_shape(&base_profile()).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "source",
                ..
            }
        ));
    }

    #[test]
    fn source_at_max_accepted() {
        let b = SynthesisBundle {
            source: "x".repeat(MAX_BUNDLE_SOURCE_LEN),
            ..base_bundle()
        };
        b.validate_bundle_shape(&base_profile()).unwrap();
    }

    #[test]
    fn source_over_max_rejected() {
        let b = SynthesisBundle {
            source: "x".repeat(MAX_BUNDLE_SOURCE_LEN + 1),
            ..base_bundle()
        };
        let err = b.validate_bundle_shape(&base_profile()).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "source",
                ..
            }
        ));
    }

    // --- V10-3: metadata bounds ---

    #[test]
    fn metadata_key_too_long() {
        let mut b = base_bundle();
        b.metadata
            .insert("k".repeat(MAX_METADATA_KEY_LEN + 1), "v".into());
        let err = b.validate_bundle_shape(&base_profile()).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "metadata",
                ..
            }
        ));
    }

    #[test]
    fn metadata_value_too_long() {
        let mut b = base_bundle();
        b.metadata
            .insert("k".into(), "v".repeat(MAX_METADATA_VALUE_LEN + 1));
        let err = b.validate_bundle_shape(&base_profile()).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "metadata",
                ..
            }
        ));
    }

    #[test]
    fn metadata_too_many_entries() {
        let mut b = base_bundle();
        for i in 0..=MAX_METADATA_ENTRIES {
            b.metadata.insert(format!("k{i}"), "v".into());
        }
        let err = b.validate_bundle_shape(&base_profile()).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "metadata",
                ..
            }
        ));
    }

    #[test]
    fn metadata_total_too_large() {
        let mut b = base_bundle();
        // Each entry: key=1 byte, value=1024 bytes -> total = 11 * 1025 = 11_275 > 10240
        for i in 0..11 {
            b.metadata
                .insert(format!("{i}"), "v".repeat(MAX_METADATA_VALUE_LEN));
        }
        let err = b.validate_bundle_shape(&base_profile()).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "metadata",
                ..
            }
        ));
    }

    #[test]
    fn metadata_happy_path() {
        let mut b = base_bundle();
        b.metadata
            .insert("experiment_id".into(), "EXP-2026-001".into());
        b.metadata
            .insert("operator".into(), "alice@example.com".into());
        b.validate_bundle_shape(&base_profile()).unwrap();
    }

    // --- V10-4: payload length caps ---

    #[test]
    fn dna_under_cap_accepted() {
        let p = BioProfile {
            max_dna_length_bp: Some(100),
            ..base_profile()
        };
        let b = SynthesisBundle {
            payload: SynthesisPayload::Dna {
                sequence: "A".repeat(100),
            },
            ..base_bundle()
        };
        b.validate_bundle_shape(&p).unwrap();
    }

    #[test]
    fn dna_over_cap_rejected() {
        let p = BioProfile {
            max_dna_length_bp: Some(100),
            ..base_profile()
        };
        let b = SynthesisBundle {
            payload: SynthesisPayload::Dna {
                sequence: "A".repeat(101),
            },
            ..base_bundle()
        };
        let err = b.validate_bundle_shape(&p).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "payload",
                ..
            }
        ));
    }

    #[test]
    fn peptide_over_cap_rejected() {
        let p = BioProfile {
            max_peptide_length_aa: Some(50),
            ..base_profile()
        };
        let b = SynthesisBundle {
            payload: SynthesisPayload::Peptide {
                sequence: "M".repeat(51),
            },
            ..base_bundle()
        };
        let err = b.validate_bundle_shape(&p).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "payload",
                ..
            }
        ));
    }

    #[test]
    fn smiles_over_cap_rejected() {
        let p = BioProfile {
            max_smiles_length_chars: Some(50),
            ..base_profile()
        };
        let b = SynthesisBundle {
            payload: SynthesisPayload::Chemical {
                smiles: "C".repeat(51),
            },
            ..base_bundle()
        };
        let err = b.validate_bundle_shape(&p).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "payload",
                ..
            }
        ));
    }

    #[test]
    fn profile_cap_1kb_rejects_2kb_sequence() {
        let p = BioProfile {
            max_dna_length_bp: Some(1024),
            ..base_profile()
        };
        let b = SynthesisBundle {
            payload: SynthesisPayload::Dna {
                sequence: "A".repeat(2048),
            },
            ..base_bundle()
        };
        let err = b.validate_bundle_shape(&p).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::BundleFieldInvalid {
                field: "payload",
                ..
            }
        ));
        assert!(err.to_string().contains("2048"));
    }
}

// ── ValidationInput impl (invariant-core integration) ───────────────────────

impl invariant_core::ValidationInput for SynthesisBundle {
    fn domain(&self) -> &'static str {
        "biosynthesis"
    }

    fn operations(&self) -> Vec<invariant_core::models::authority::Operation> {
        self.authority.required_ops.clone()
    }

    fn content_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(self).expect("SynthesisBundle serializes");
        Sha256::digest(&bytes).into()
    }

    fn summary(&self) -> String {
        let kind = match &self.payload {
            SynthesisPayload::Dna { .. } => "dna",
            SynthesisPayload::Peptide { .. } => "peptide",
            SynthesisPayload::Chemical { .. } => "chemical",
            SynthesisPayload::Protocol { .. } => "protocol",
        };
        format!(
            "biosynthesis bundle seq={} source={} kind={}",
            self.sequence, self.source, kind
        )
    }
}
