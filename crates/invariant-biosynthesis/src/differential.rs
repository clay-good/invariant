//! Differential validation: dual-instance verdict comparison.
//!
//! Runs the same synthesis bundle through two independent
//! [`ValidatorConfig`] instances and compares their verdicts. If the two
//! instances disagree on approval status or individual check results, a
//! disagreement is flagged. This is a dual-channel safety pattern (IEC 61508
//! SIL 2+) that catches software bugs, hardware faults affecting one
//! instance, and subtle numerical edge cases near rejection thresholds.
//!
//! Phase 1b: the comparison logic and result types are hoisted to
//! [`invariant_core::differential`]. This module re-exports them and supplies
//! the biosynthesis-specific [`VerdictView`] / [`CheckView`] impls plus the
//! thin [`DifferentialValidator`] wrapper around two [`ValidatorConfig`]s.

use chrono::{DateTime, Utc};

use crate::models::bundle::SynthesisBundle;
use crate::models::verdict::{CheckResult, Verdict};
use crate::validator::{ValidatorConfig, ValidatorError};

pub use invariant_core::differential::{
    compare_verdicts, CheckDisagreement, CheckView, DifferentialResult, VerdictView,
};

// ---------------------------------------------------------------------------
// Trait impls — wire the biosynthesis Verdict / CheckResult into the generic
// `compare_verdicts` function.
// ---------------------------------------------------------------------------

impl CheckView for CheckResult {
    fn name(&self) -> &str {
        &self.name
    }
    fn category(&self) -> &str {
        &self.category
    }
    fn passed(&self) -> bool {
        self.passed
    }
    fn details(&self) -> &str {
        &self.details
    }
}

impl VerdictView for Verdict {
    type Check = CheckResult;
    fn approved(&self) -> bool {
        self.approved
    }
    fn command_hash(&self) -> &str {
        &self.command_hash
    }
    fn command_sequence(&self) -> u64 {
        self.command_sequence
    }
    fn checks(&self) -> &[Self::Check] {
        &self.checks
    }
}

// ---------------------------------------------------------------------------
// Differential validator
// ---------------------------------------------------------------------------

/// A differential validator that runs two independent instances and compares.
pub struct DifferentialValidator<'a> {
    instance_a: &'a ValidatorConfig,
    instance_b: &'a ValidatorConfig,
}

impl<'a> DifferentialValidator<'a> {
    /// Create a new differential validator from two independent instances.
    ///
    /// Both instances should be configured with the same bio profile but MAY
    /// have different signing keys (dual-channel pattern). Different profiles
    /// will produce disagreements on every bundle.
    pub fn new(instance_a: &'a ValidatorConfig, instance_b: &'a ValidatorConfig) -> Self {
        Self {
            instance_a,
            instance_b,
        }
    }

    /// Validate a bundle through both instances and compare their verdicts.
    pub fn validate(
        &self,
        bundle: &SynthesisBundle,
        now: DateTime<Utc>,
    ) -> Result<DifferentialResult, ValidatorError> {
        let result_a = self.instance_a.validate(bundle, now, None)?;
        let result_b = self.instance_b.validate(bundle, now, None)?;

        let verdict_a = &result_a.signed_verdict.verdict;
        let verdict_b = &result_b.signed_verdict.verdict;

        Ok(compare_verdicts(verdict_a, verdict_b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::bundle::{BundleAuthority, SynthesisPayload};
    use crate::models::profile::BioProfile;
    use crate::models::verdict::AuthoritySummary;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn make_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn test_profile() -> BioProfile {
        BioProfile {
            name: "test_profile".into(),
            version: "0.1.0".into(),
            bsl_level: 2,
            allowed_substrates: vec!["dna".into()],
            max_synthesis_volume_ml: 5.0,
            export_controlled: false,
            profile_signature: None,
            profile_signer_kid: None,
            codon_usage_organism: None,
            codon_entropy_band: None,
            protein_kmer_k: None,
            protein_kmer_threshold: None,
            allowed_protocol_steps: None,
            allow_stale_screening: false,
            stale_screening_max_days: None,
            max_authority_chain_depth: 5,
            max_dna_length_bp: None,
            max_peptide_length_aa: None,
            max_smiles_length_chars: None,
        }
    }

    fn make_bundle() -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            payload: SynthesisPayload::Dna {
                sequence: "ATGCGT".into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: Default::default(),
        }
    }

    fn make_config(sk: SigningKey, kid: &str) -> ValidatorConfig {
        ValidatorConfig::new(test_profile(), HashMap::new(), sk, kid.into()).unwrap()
    }

    // -- DifferentialValidator integration tests --

    #[test]
    fn identical_instances_agree_on_rejected_bundle() {
        // Bundle with empty PCA chain is rejected by both.
        let config_a = make_config(make_keypair(), "instance-a");
        let config_b = make_config(make_keypair(), "instance-b");

        let diff = DifferentialValidator::new(&config_a, &config_b);
        let result = diff.validate(&make_bundle(), Utc::now()).unwrap();

        assert!(result.approval_agrees);
        assert!(!result.instance_a_approved);
        assert!(!result.instance_b_approved);
    }

    #[test]
    fn identical_instances_have_same_command_hash() {
        let config_a = make_config(make_keypair(), "instance-a");
        let config_b = make_config(make_keypair(), "instance-b");

        let diff = DifferentialValidator::new(&config_a, &config_b);
        let bundle = make_bundle();
        let result = diff.validate(&bundle, Utc::now()).unwrap();

        assert!(result.command_hash.starts_with("sha256:"));
        assert_eq!(result.command_sequence, 1);
    }

    // -- compare_verdicts pure-function tests --

    fn auth_summary() -> AuthoritySummary {
        AuthoritySummary {
            origin_principal: "alice".into(),
            hop_count: 1,
            operations_granted: vec!["synthesize:dna:*".into()],
            operations_required: vec!["synthesize:dna:fragment".into()],
        }
    }

    #[test]
    fn compare_verdicts_with_matching_checks() {
        let checks = vec![
            CheckResult::new("authority", "authority", true, "ok"),
            CheckResult::new("d1_select_agent_screen", "invariant.dna", true, "ok"),
        ];

        let verdict_a = Verdict {
            approved: true,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks: checks.clone(),
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: auth_summary(),
            threat_analysis: None,
        };
        let verdict_b = verdict_a.clone();

        let result = compare_verdicts(&verdict_a, &verdict_b);
        assert!(result.fully_agrees());
        assert_eq!(result.total_checks, 2);
        assert_eq!(result.agreeing_checks, 2);
    }

    #[test]
    fn compare_verdicts_with_one_check_disagreement() {
        let now = Utc::now();
        let verdict_a = Verdict {
            approved: true,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: now,
            checks: vec![
                CheckResult::new("authority", "authority", true, "ok"),
                CheckResult::new("d1_select_agent_screen", "invariant.dna", true, "no hit"),
            ],
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: auth_summary(),
            threat_analysis: None,
        };

        let verdict_b = Verdict {
            approved: false,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: now,
            checks: vec![
                CheckResult::new("authority", "authority", true, "ok"),
                CheckResult::new(
                    "d1_select_agent_screen",
                    "invariant.dna",
                    false,
                    "matched select agent X",
                ),
            ],
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: auth_summary(),
            threat_analysis: None,
        };

        let result = compare_verdicts(&verdict_a, &verdict_b);
        assert!(!result.fully_agrees());
        assert!(!result.approval_agrees);
        assert_eq!(result.check_disagreements.len(), 1);
        assert_eq!(
            result.check_disagreements[0].check_name,
            "d1_select_agent_screen"
        );
        assert!(result.check_disagreements[0].instance_a_passed);
        assert!(!result.check_disagreements[0].instance_b_passed);
        assert_eq!(result.agreeing_checks, 1);
    }

    #[test]
    fn compare_verdicts_missing_check_in_one_instance() {
        let now = Utc::now();
        let verdict_a = Verdict {
            approved: false,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: now,
            checks: vec![
                CheckResult::new("authority", "authority", false, "failed"),
                CheckResult::new("extra_check", "invariant.dna", true, "ok"),
            ],
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: auth_summary(),
            threat_analysis: None,
        };

        let verdict_b = Verdict {
            approved: false,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: now,
            checks: vec![CheckResult::new("authority", "authority", false, "failed")],
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: auth_summary(),
            threat_analysis: None,
        };

        let result = compare_verdicts(&verdict_a, &verdict_b);
        assert!(result.approval_agrees);
        assert!(!result.fully_agrees());
        assert_eq!(result.check_disagreements.len(), 1);
        assert_eq!(result.check_disagreements[0].check_name, "extra_check");
        assert!(result.check_disagreements[0]
            .instance_b_details
            .contains("not present"));
    }

    #[test]
    fn fully_agrees_requires_both_approval_and_checks() {
        let result = DifferentialResult {
            approval_agrees: true,
            instance_a_approved: true,
            instance_b_approved: true,
            check_disagreements: vec![CheckDisagreement {
                check_name: "test".into(),
                category: "invariant.dna".into(),
                instance_a_passed: true,
                instance_b_passed: false,
                instance_a_details: "a".into(),
                instance_b_details: "b".into(),
            }],
            total_checks: 1,
            agreeing_checks: 0,
            command_hash: "sha256:test".into(),
            command_sequence: 1,
        };

        assert!(!result.fully_agrees());
    }

    #[test]
    fn same_signing_key_on_both_instances_agrees_on_rejected_bundle() {
        let sk = make_keypair();
        let sk_clone = SigningKey::from_bytes(&sk.to_bytes());

        let config_a = make_config(sk, "instance-shared");
        let config_b = make_config(sk_clone, "instance-shared");

        let diff = DifferentialValidator::new(&config_a, &config_b);
        let result = diff.validate(&make_bundle(), Utc::now()).unwrap();
        assert!(result.approval_agrees);
    }
}
