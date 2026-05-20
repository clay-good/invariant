//! Bio-firewall profile schema.
//!
//! Replaces the robotics sibling profile (which described motor workspaces
//! and zones). The bio profile declares the operational envelope of a synthesis
//! installation — containment level, allowed substrates, synthesis volume
//! caps, and export-control posture. Fields are intentionally minimal at
//! Step 0; more structured limits (chemical hazard classes, organism lists,
//! concentration bounds) are added in Step 4 per spec.md.

use serde::{Deserialize, Serialize};

use super::error::{Validate, ValidationError};

fn default_max_chain_depth() -> usize {
    5
}

/// A synthesis-platform safety profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BioProfile {
    /// Human-readable profile name (e.g. `"university_bsl2_dna"`).
    pub name: String,
    /// Semantic version of this profile document.
    pub version: String,
    /// Biological Safety Level of the installation (1–4).
    pub bsl_level: u8,
    /// List of substrate categories this installation may synthesize
    /// (e.g. `"dna"`, `"peptide"`, `"small_molecule"`).
    pub allowed_substrates: Vec<String>,
    /// Hard upper bound on a single synthesis reaction volume, in millilitres.
    pub max_synthesis_volume_ml: f64,
    /// Whether the installation is export-controlled; stricter screening
    /// applies when `true`.
    pub export_controlled: bool,
    /// Optional Ed25519 signature over the profile canonical bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_signature: Option<String>,
    /// Optional key identifier of the profile signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_signer_kid: Option<String>,
    /// Optional declared host organism for codon-usage entropy screening (D7).
    /// Accepted values: "e_coli", "s_cerevisiae", "h_sapiens", "cho_k1".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codon_usage_organism: Option<String>,
    /// Optional explicit entropy band `(lo, hi)` for D7. When set, takes
    /// precedence over the organism-derived band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codon_entropy_band: Option<(f64, f64)>,
    /// Optional per-profile restriction of the protocol step vocabulary.
    ///
    /// When `Some`, only verbs in this list (which must be a subset of the
    /// built-in vocabulary) are allowed by PR2. Profiles cannot introduce
    /// new verbs outside the built-in list; new verbs require an RFC (see
    /// `docs/rfcs/README.md`) to update the global vocabulary and the
    /// `PROTOCOL_STEP_VOCAB_VERSION` constant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_protocol_steps: Option<Vec<String>>,
    /// Protein k-mer size used by the protein-space rescreen engine.
    /// Default: 5. Must be 3..=8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protein_kmer_k: Option<usize>,
    /// Minimum Jaccard similarity for protein-space k-mer hits.
    /// Default: 0.30. Must be in (0.0, 1.0].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protein_kmer_threshold: Option<f64>,
    /// Whether stale screening databases may be downgraded to advisory
    /// instead of fail-closed. Default: `false`. When `true`, a staleness
    /// window in days must be acceptable for the profile's BSL level.
    ///
    /// This is separate from `allow_unimplemented_invariants` on
    /// `ValidatorConfig`, which only governs stub invariants.
    #[serde(default)]
    pub allow_stale_screening: bool,
    /// Maximum age (in days) of a screening database that is still considered
    /// acceptable when `allow_stale_screening = true`. Required whenever
    /// `allow_stale_screening` is `true`; ignored otherwise.
    ///
    /// Must be ≥ 1. For BSL ≥ 2, must be ≤ 90 (a longer window is treated as
    /// an operational error at these biosafety levels). Values > 365 are
    /// always an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_screening_max_days: Option<u32>,
    /// Maximum permitted depth of the PCA authority chain (number of hops).
    /// Default: 5. Deeply nested delegations are rejected.
    #[serde(default = "default_max_chain_depth")]
    pub max_authority_chain_depth: usize,
    /// Maximum DNA sequence length in base pairs. Default: 1,000,000 bp.
    /// Applied at bundle-shape validation before any invariant runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_dna_length_bp: Option<u64>,
    /// Maximum peptide sequence length in amino acids. Default: 100,000 aa.
    /// Applied at bundle-shape validation before any invariant runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_peptide_length_aa: Option<u64>,
    /// Maximum SMILES string length in characters. Default: 100,000 chars.
    /// Applied at bundle-shape validation before any invariant runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_smiles_length_chars: Option<u64>,
}

impl Validate for BioProfile {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.name.trim().is_empty() {
            return Err(ValidationError::ProfileFieldInvalid {
                field: "name",
                reason: "profile name must be non-empty".into(),
            });
        }
        if !(1..=4).contains(&self.bsl_level) {
            return Err(ValidationError::ProfileFieldInvalid {
                field: "bsl_level",
                reason: format!("BSL level must be 1-4, got {}", self.bsl_level),
            });
        }
        if !self.max_synthesis_volume_ml.is_finite() || self.max_synthesis_volume_ml <= 0.0 {
            return Err(ValidationError::ProfileFieldInvalid {
                field: "max_synthesis_volume_ml",
                reason: format!(
                    "must be a finite positive number, got {}",
                    self.max_synthesis_volume_ml
                ),
            });
        }
        if self.allowed_substrates.is_empty() {
            return Err(ValidationError::ProfileFieldInvalid {
                field: "allowed_substrates",
                reason: "profile must declare at least one allowed substrate".into(),
            });
        }
        if let Some((lo, hi)) = self.codon_entropy_band {
            if !lo.is_finite() || lo <= 0.0 || !hi.is_finite() || hi <= 0.0 || lo >= hi {
                return Err(ValidationError::ProfileFieldInvalid {
                    field: "codon_entropy_band",
                    reason: format!(
                        "must be (lo, hi) with 0 < lo < hi and both finite, got ({}, {})",
                        lo, hi
                    ),
                });
            }
        }
        const KNOWN_ORGANISMS: &[&str] = &["e_coli", "s_cerevisiae", "h_sapiens", "cho_k1"];
        if let Some(ref org) = self.codon_usage_organism {
            if !KNOWN_ORGANISMS.contains(&org.as_str()) {
                return Err(ValidationError::ProfileFieldInvalid {
                    field: "codon_usage_organism",
                    reason: format!(
                        "unknown organism {:?}; accepted values: {}",
                        org,
                        KNOWN_ORGANISMS.join(", ")
                    ),
                });
            }
        }
        if let Some(ref steps) = self.allowed_protocol_steps {
            for step in steps {
                if !crate::invariants::protocol::is_builtin_verb(step) {
                    return Err(ValidationError::ProfileFieldInvalid {
                        field: "allowed_protocol_steps",
                        reason: format!(
                            "verb {:?} is not in the built-in allowed verb list \
                             (PROTOCOL_STEP_VOCAB_VERSION = {}); to add new verbs, \
                             open an RFC — see docs/rfcs/README.md",
                            step,
                            crate::invariants::protocol::PROTOCOL_STEP_VOCAB_VERSION,
                        ),
                    });
                }
            }
        }
        if let Some(k) = self.protein_kmer_k {
            if !(3..=8).contains(&k) {
                return Err(ValidationError::ProfileFieldInvalid {
                    field: "protein_kmer_k",
                    reason: format!("must be 3..=8, got {}", k),
                });
            }
        }
        if let Some(t) = self.protein_kmer_threshold {
            if !t.is_finite() || t <= 0.0 || t > 1.0 {
                return Err(ValidationError::ProfileFieldInvalid {
                    field: "protein_kmer_threshold",
                    reason: format!("must be in (0.0, 1.0], got {}", t),
                });
            }
        }
        if self.allow_stale_screening && self.bsl_level >= 3 {
            return Err(ValidationError::ProfileFieldInvalid {
                field: "allow_stale_screening",
                reason: format!(
                    "stale screening databases cannot be allowed at BSL level {} (>= 3)",
                    self.bsl_level
                ),
            });
        }
        if self.allow_stale_screening && self.stale_screening_max_days.is_none() {
            return Err(ValidationError::ProfileFieldInvalid {
                field: "stale_screening_max_days",
                reason: "must be set when allow_stale_screening is true".into(),
            });
        }
        if let Some(days) = self.stale_screening_max_days {
            if days == 0 {
                return Err(ValidationError::ProfileFieldInvalid {
                    field: "stale_screening_max_days",
                    reason: "stale_screening_max_days must be at least 1".into(),
                });
            }
            if days > 365 {
                return Err(ValidationError::ProfileFieldInvalid {
                    field: "stale_screening_max_days",
                    reason: format!(
                        "stale_screening_max_days > 365 ({days}) is not permitted"
                    ),
                });
            }
            if self.bsl_level >= 2 && days > 90 {
                return Err(ValidationError::ProfileFieldInvalid {
                    field: "stale_screening_max_days",
                    reason: format!(
                        "stale_screening_max_days must be ≤ 90 for BSL ≥ 2, got {days}"
                    ),
                });
            }
        }
        if self.max_authority_chain_depth == 0 || self.max_authority_chain_depth > 16 {
            return Err(ValidationError::ProfileFieldInvalid {
                field: "max_authority_chain_depth",
                reason: format!(
                    "must be 1..=16, got {}",
                    self.max_authority_chain_depth
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // --- GAP-C5 tests ---

    #[test]
    fn stale_screening_true_without_max_days_is_invalid() {
        let p = BioProfile {
            allow_stale_screening: true,
            stale_screening_max_days: None,
            ..base_profile()
        };
        let err = p.validate().unwrap_err();
        assert!(matches!(err, ValidationError::ProfileFieldInvalid { field: "stale_screening_max_days", .. }));
    }

    #[test]
    fn stale_screening_true_with_max_days_30_is_valid() {
        let p = BioProfile {
            allow_stale_screening: true,
            stale_screening_max_days: Some(30),
            ..base_profile()
        };
        p.validate().expect("should be valid for BSL-1");
    }

    #[test]
    fn stale_screening_max_days_zero_is_invalid() {
        let p = BioProfile {
            allow_stale_screening: true,
            stale_screening_max_days: Some(0),
            ..base_profile()
        };
        let err = p.validate().unwrap_err();
        assert!(matches!(err, ValidationError::ProfileFieldInvalid { field: "stale_screening_max_days", .. }));
    }

    #[test]
    fn stale_screening_false_with_no_max_days_is_valid() {
        let p = BioProfile {
            allow_stale_screening: false,
            stale_screening_max_days: None,
            ..base_profile()
        };
        p.validate().expect("field not required when allow_stale_screening is false");
    }

    #[test]
    fn bsl2_stale_screening_max_days_91_is_invalid() {
        let p = BioProfile {
            bsl_level: 2,
            allow_stale_screening: true,
            stale_screening_max_days: Some(91),
            ..base_profile()
        };
        let err = p.validate().unwrap_err();
        assert!(matches!(err, ValidationError::ProfileFieldInvalid { field: "stale_screening_max_days", .. }));
    }

    // --- GAP-N1 tests ---

    #[test]
    fn allowed_protocol_steps_with_valid_verbs_passes() {
        let p = BioProfile {
            allowed_protocol_steps: Some(vec!["aspirate".into(), "dispense".into(), "mix".into()]),
            ..base_profile()
        };
        p.validate().expect("valid built-in verbs accepted");
    }

    #[test]
    fn allowed_protocol_steps_with_unknown_verb_includes_version_in_error() {
        let p = BioProfile {
            allowed_protocol_steps: Some(vec!["aspirate".into(), "teleport".into()]),
            ..base_profile()
        };
        let err = p.validate().unwrap_err();
        match err {
            ValidationError::ProfileFieldInvalid { field, reason } => {
                assert_eq!(field, "allowed_protocol_steps");
                assert!(reason.contains("PROTOCOL_STEP_VOCAB_VERSION"), "reason should include version: {reason}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn protein_kmer_params_5_and_0_30_are_accepted() {
        let p = BioProfile {
            protein_kmer_k: Some(5),
            protein_kmer_threshold: Some(0.30),
            ..base_profile()
        };
        p.validate().expect("k=5, threshold=0.30 should be valid");
    }

    // --- V10-15 boundary tests for bsl_level ---

    #[test]
    fn bsl_level_zero_rejected() {
        let p = BioProfile {
            bsl_level: 0,
            ..base_profile()
        };
        let err = p.validate().unwrap_err();
        match err {
            ValidationError::ProfileFieldInvalid { field, reason } => {
                assert_eq!(field, "bsl_level");
                assert!(reason.contains('0'), "reason should mention rejected value 0: {reason}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn bsl_level_five_rejected() {
        let p = BioProfile {
            bsl_level: 5,
            ..base_profile()
        };
        let err = p.validate().unwrap_err();
        match err {
            ValidationError::ProfileFieldInvalid { field, reason } => {
                assert_eq!(field, "bsl_level");
                assert!(reason.contains('5'), "reason should mention rejected value 5: {reason}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn bsl_level_boundaries_accepted() {
        // BSL-3 and BSL-4 forbid `allow_stale_screening = true` separately; the
        // base profile keeps it `false` so the bsl_level field is the only
        // moving part across this sweep.
        for level in 1u8..=4u8 {
            let p = BioProfile {
                bsl_level: level,
                ..base_profile()
            };
            p.validate()
                .unwrap_or_else(|e| panic!("BSL-{level} must validate: {e}"));
        }
    }
}

// ── DomainProfile impl (invariant-core integration) ─────────────────────────

impl invariant_core::DomainProfile for BioProfile {
    fn id(&self) -> &str {
        &self.name
    }
    fn domain(&self) -> &'static str {
        "biosynthesis"
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
