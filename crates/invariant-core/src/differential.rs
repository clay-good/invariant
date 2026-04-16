// Differential validation: dual-instance verdict comparison.
//
// Runs the same command through two independent ValidatorConfig instances
// and compares their verdicts. If the two instances disagree on approval
// status or individual check results, a disagreement is flagged.
//
// This is a dual-channel safety pattern from IEC 61508 (SIL 2+). It catches:
// - Software bugs where one instance has corrupted state
// - Hardware faults that affect one instance but not the other
// - Subtle numerical edge cases near rejection thresholds
//
// Design: the two instances MAY have different signing keys (simulating
// physically separate processes or hardware channels). The comparison
// ignores signature values and signer_kid — only the semantic content
// of the verdict (approval, check names, check pass/fail, check details)
// is compared.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::command::JointState;
use crate::models::verdict::{CheckResult, Verdict};
use crate::validator::{ValidatorConfig, ValidatorError};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single check-level disagreement between the two validator instances.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::differential::CheckDisagreement;
///
/// let d = CheckDisagreement {
///     check_name: "joint_limits".to_string(),
///     category: "physics".to_string(),
///     instance_a_passed: true,
///     instance_b_passed: false,
///     instance_a_details: "within bounds".to_string(),
///     instance_b_details: "j1 exceeds max".to_string(),
/// };
///
/// assert_eq!(d.check_name, "joint_limits");
/// assert!(d.instance_a_passed);
/// assert!(!d.instance_b_passed);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckDisagreement {
    /// Name of the check that disagreed.
    pub check_name: String,
    /// Category of the check (e.g. "authority", "physics").
    pub category: String,
    /// Whether instance A passed this check.
    pub instance_a_passed: bool,
    /// Whether instance B passed this check.
    pub instance_b_passed: bool,
    /// Details from instance A.
    pub instance_a_details: String,
    /// Details from instance B.
    pub instance_b_details: String,
}

/// The result of a differential validation run.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::differential::DifferentialResult;
///
/// // A result where both instances fully agree.
/// let result = DifferentialResult {
///     approval_agrees: true,
///     instance_a_approved: true,
///     instance_b_approved: true,
///     check_disagreements: vec![],
///     total_checks: 10,
///     agreeing_checks: 10,
///     command_hash: "sha256:abc".to_string(),
///     command_sequence: 1,
/// };
///
/// assert!(result.fully_agrees());
/// assert_eq!(result.total_checks, 10);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialResult {
    /// Whether the two instances agree on the approval decision.
    pub approval_agrees: bool,
    /// Instance A's approval decision.
    pub instance_a_approved: bool,
    /// Instance B's approval decision.
    pub instance_b_approved: bool,
    /// Check-level disagreements (empty if all checks agree).
    pub check_disagreements: Vec<CheckDisagreement>,
    /// Number of checks that both instances evaluated.
    pub total_checks: usize,
    /// Number of checks where both instances agree.
    pub agreeing_checks: usize,
    /// The command hash from instance A (should match instance B).
    pub command_hash: String,
    /// The command sequence number.
    pub command_sequence: u64,
}

impl DifferentialResult {
    /// Returns true if both instances fully agree (approval + all checks).
    pub fn fully_agrees(&self) -> bool {
        self.approval_agrees && self.check_disagreements.is_empty()
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
    /// Both instances should be configured with the same robot profile but
    /// MAY have different signing keys (dual-channel pattern). Different
    /// profiles will produce disagreements on every command.
    pub fn new(instance_a: &'a ValidatorConfig, instance_b: &'a ValidatorConfig) -> Self {
        Self {
            instance_a,
            instance_b,
        }
    }

    /// Validate a command through both instances and compare their verdicts.
    ///
    /// Returns `Err` only if one of the instances encounters a fatal error
    /// (serialization failure). Disagreements are captured in the result, not
    /// as errors.
    pub fn validate(
        &self,
        command: &crate::models::command::Command,
        now: DateTime<Utc>,
        previous_joints: Option<&[JointState]>,
    ) -> Result<DifferentialResult, ValidatorError> {
        let result_a = self.instance_a.validate(command, now, previous_joints)?;
        let result_b = self.instance_b.validate(command, now, previous_joints)?;

        let verdict_a = &result_a.signed_verdict.verdict;
        let verdict_b = &result_b.signed_verdict.verdict;

        Ok(compare_verdicts(verdict_a, verdict_b))
    }
}

// ---------------------------------------------------------------------------
// Comparison logic
// ---------------------------------------------------------------------------

/// Compare two verdicts and produce a DifferentialResult.
///
/// This is a pure function — no I/O, no signing keys, no side effects.
/// Exposed publicly so it can be used independently of the validator.
pub fn compare_verdicts(a: &Verdict, b: &Verdict) -> DifferentialResult {
    let approval_agrees = a.approved == b.approved;

    // Compare check results by name. Both validators should produce the
    // same set of checks in the same order, but we match by name to be
    // robust against ordering differences.
    let mut disagreements = Vec::new();
    let mut agreeing = 0usize;

    for check_a in &a.checks {
        if let Some(check_b) = b.checks.iter().find(|c| c.name == check_a.name) {
            if checks_disagree(check_a, check_b) {
                disagreements.push(CheckDisagreement {
                    check_name: check_a.name.clone(),
                    category: check_a.category.clone(),
                    instance_a_passed: check_a.passed,
                    instance_b_passed: check_b.passed,
                    instance_a_details: check_a.details.clone(),
                    instance_b_details: check_b.details.clone(),
                });
            } else {
                agreeing += 1;
            }
        } else {
            // Instance A has a check that B does not — this is a structural
            // disagreement (different check sets).
            disagreements.push(CheckDisagreement {
                check_name: check_a.name.clone(),
                category: check_a.category.clone(),
                instance_a_passed: check_a.passed,
                instance_b_passed: false,
                instance_a_details: check_a.details.clone(),
                instance_b_details: "check not present in instance B".into(),
            });
        }
    }

    // Also flag checks present in B but not in A.
    for check_b in &b.checks {
        if !a.checks.iter().any(|c| c.name == check_b.name) {
            disagreements.push(CheckDisagreement {
                check_name: check_b.name.clone(),
                category: check_b.category.clone(),
                instance_a_passed: false,
                instance_a_details: "check not present in instance A".into(),
                instance_b_passed: check_b.passed,
                instance_b_details: check_b.details.clone(),
            });
        }
    }

    let total_checks = a.checks.len().max(b.checks.len());

    DifferentialResult {
        approval_agrees,
        instance_a_approved: a.approved,
        instance_b_approved: b.approved,
        check_disagreements: disagreements,
        total_checks,
        agreeing_checks: agreeing,
        command_hash: a.command_hash.clone(),
        command_sequence: a.command_sequence,
    }
}

/// Two checks disagree if their pass/fail status differs.
fn checks_disagree(a: &CheckResult, b: &CheckResult) -> bool {
    a.passed != b.passed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::crypto::{generate_keypair, sign_pca};
    use crate::models::authority::{Operation, Pca};
    use crate::models::command::{Command, CommandAuthority, EndEffectorPosition, JointState};
    use crate::models::profile::*;
    use crate::models::verdict::AuthoritySummary;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::Utc;
    use rand::rngs::OsRng;
    use std::collections::{BTreeSet, HashMap};

    fn op(s: &str) -> Operation {
        Operation::new(s).unwrap()
    }

    fn ops(ss: &[&str]) -> BTreeSet<Operation> {
        ss.iter().map(|s| op(s)).collect()
    }

    fn make_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
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
            locomotion: None,
            max_delta_time: 0.1,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None,
            end_effectors: vec![],
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
            end_effector_positions: vec![EndEffectorPosition {
                name: "end_effector".into(),
                position: [0.0, 0.0, 1.0],
            }],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: chain_b64.to_string(),
                required_ops,
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        }
    }

    fn make_config(
        trusted: HashMap<String, ed25519_dalek::VerifyingKey>,
        sign_sk: ed25519_dalek::SigningKey,
        kid: &str,
    ) -> ValidatorConfig {
        ValidatorConfig::new(test_profile(), trusted, sign_sk, kid.into()).unwrap()
    }

    // -- Helper to build a valid PCA chain + trusted keys ----------------------

    fn setup_authority() -> (String, HashMap<String, ed25519_dalek::VerifyingKey>) {
        let (pca_sk, pca_vk) = make_keypair();
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
        (chain_b64, trusted)
    }

    // -----------------------------------------------------------------------
    // Test: two identical instances fully agree on approved command
    // -----------------------------------------------------------------------

    #[test]
    fn identical_instances_agree_on_approved_command() {
        let (chain_b64, trusted) = setup_authority();
        let (sk_a, _) = make_keypair();
        let (sk_b, _) = make_keypair();

        let config_a = make_config(trusted.clone(), sk_a, "instance-a");
        let config_b = make_config(trusted, sk_b, "instance-b");

        let diff = DifferentialValidator::new(&config_a, &config_b);
        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        let now = Utc::now();

        let result = diff.validate(&cmd, now, None).unwrap();

        assert!(result.fully_agrees());
        assert!(result.approval_agrees);
        assert!(result.instance_a_approved);
        assert!(result.instance_b_approved);
        assert!(result.check_disagreements.is_empty());
        assert!(result.agreeing_checks > 0);
    }

    // -----------------------------------------------------------------------
    // Test: two identical instances fully agree on rejected command
    // -----------------------------------------------------------------------

    #[test]
    fn identical_instances_agree_on_rejected_command() {
        let (chain_b64, trusted) = setup_authority();
        let (sk_a, _) = make_keypair();
        let (sk_b, _) = make_keypair();

        let config_a = make_config(trusted.clone(), sk_a, "instance-a");
        let config_b = make_config(trusted, sk_b, "instance-b");

        let diff = DifferentialValidator::new(&config_a, &config_b);

        // Command with position outside joint limits -> rejection.
        let mut cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        cmd.joint_states[0].position = 999.0;
        let now = Utc::now();

        let result = diff.validate(&cmd, now, None).unwrap();

        assert!(result.fully_agrees());
        assert!(result.approval_agrees);
        assert!(!result.instance_a_approved);
        assert!(!result.instance_b_approved);
    }

    // -----------------------------------------------------------------------
    // Test: one instance has different trusted keys -> authority disagreement
    // -----------------------------------------------------------------------

    #[test]
    fn different_trusted_keys_causes_authority_disagreement() {
        let (chain_b64, trusted) = setup_authority();
        let (sk_a, _) = make_keypair();
        let (sk_b, _) = make_keypair();

        // Instance A trusts the PCA key; instance B has empty trusted keys.
        let config_a = make_config(trusted, sk_a, "instance-a");
        let config_b = make_config(HashMap::new(), sk_b, "instance-b");

        let diff = DifferentialValidator::new(&config_a, &config_b);
        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        let now = Utc::now();

        let result = diff.validate(&cmd, now, None).unwrap();

        assert!(!result.fully_agrees());
        assert!(!result.approval_agrees);
        assert!(result.instance_a_approved);
        assert!(!result.instance_b_approved);

        // There should be at least an authority check disagreement.
        let auth_disagreement = result
            .check_disagreements
            .iter()
            .find(|d| d.check_name == "authority");
        assert!(auth_disagreement.is_some());
        let auth = auth_disagreement.unwrap();
        assert!(auth.instance_a_passed);
        assert!(!auth.instance_b_passed);
    }

    // -----------------------------------------------------------------------
    // Test: compare_verdicts pure function works independently
    // -----------------------------------------------------------------------

    #[test]
    fn compare_verdicts_with_matching_checks() {
        let checks = vec![
            CheckResult {
                name: "authority".into(),
                category: "authority".into(),
                passed: true,
                details: "ok".into(),
                derating: None,
            },
            CheckResult {
                name: "joint_limits".into(),
                category: "physics".into(),
                passed: true,
                details: "ok".into(),
                derating: None,
            },
        ];

        let verdict_a = Verdict {
            approved: true,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks: checks.clone(),
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: AuthoritySummary {
                origin_principal: "alice".into(),
                hop_count: 1,
                operations_granted: vec!["actuate:*".into()],
                operations_required: vec!["actuate:j1".into()],
            },
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
        let base_summary = AuthoritySummary {
            origin_principal: "alice".into(),
            hop_count: 1,
            operations_granted: vec!["actuate:*".into()],
            operations_required: vec!["actuate:j1".into()],
        };

        let verdict_a = Verdict {
            approved: true,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: now,
            checks: vec![
                CheckResult {
                    name: "authority".into(),
                    category: "authority".into(),
                    passed: true,
                    details: "ok".into(),
                    derating: None,
                },
                CheckResult {
                    name: "joint_limits".into(),
                    category: "physics".into(),
                    passed: true,
                    details: "within bounds".into(),
                    derating: None,
                },
            ],
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: base_summary.clone(),
            threat_analysis: None,
        };

        // Instance B says joint_limits failed.
        let verdict_b = Verdict {
            approved: false,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: now,
            checks: vec![
                CheckResult {
                    name: "authority".into(),
                    category: "authority".into(),
                    passed: true,
                    details: "ok".into(),
                    derating: None,
                },
                CheckResult {
                    name: "joint_limits".into(),
                    category: "physics".into(),
                    passed: false,
                    details: "j1 position 5.0 exceeds max 3.15".into(),
                    derating: None,
                },
            ],
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: base_summary,
            threat_analysis: None,
        };

        let result = compare_verdicts(&verdict_a, &verdict_b);
        assert!(!result.fully_agrees());
        assert!(!result.approval_agrees);
        assert_eq!(result.check_disagreements.len(), 1);
        assert_eq!(result.check_disagreements[0].check_name, "joint_limits");
        assert!(result.check_disagreements[0].instance_a_passed);
        assert!(!result.check_disagreements[0].instance_b_passed);
        assert_eq!(result.agreeing_checks, 1); // authority agrees
    }

    #[test]
    fn compare_verdicts_missing_check_in_one_instance() {
        let now = Utc::now();
        let base_summary = AuthoritySummary {
            origin_principal: String::new(),
            hop_count: 0,
            operations_granted: vec![],
            operations_required: vec!["actuate:j1".into()],
        };

        let verdict_a = Verdict {
            approved: false,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: now,
            checks: vec![
                CheckResult {
                    name: "authority".into(),
                    category: "authority".into(),
                    passed: false,
                    details: "failed".into(),
                    derating: None,
                },
                CheckResult {
                    name: "extra_check".into(),
                    category: "physics".into(),
                    passed: true,
                    details: "ok".into(),
                    derating: None,
                },
            ],
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: base_summary.clone(),
            threat_analysis: None,
        };

        let verdict_b = Verdict {
            approved: false,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: now,
            checks: vec![CheckResult {
                name: "authority".into(),
                category: "authority".into(),
                passed: false,
                details: "failed".into(),
                derating: None,
            }],
            profile_name: "test".into(),
            profile_hash: "sha256:xyz".into(),
            authority_summary: base_summary,
            threat_analysis: None,
        };

        let result = compare_verdicts(&verdict_a, &verdict_b);
        // Approval agrees (both false), but check sets differ.
        assert!(result.approval_agrees);
        assert!(!result.fully_agrees());
        assert_eq!(result.check_disagreements.len(), 1);
        assert_eq!(result.check_disagreements[0].check_name, "extra_check");
        assert!(result.check_disagreements[0]
            .instance_b_details
            .contains("not present"));
    }

    // -----------------------------------------------------------------------
    // Test: DifferentialResult::fully_agrees
    // -----------------------------------------------------------------------

    #[test]
    fn fully_agrees_requires_both_approval_and_checks() {
        let result = DifferentialResult {
            approval_agrees: true,
            instance_a_approved: true,
            instance_b_approved: true,
            check_disagreements: vec![CheckDisagreement {
                check_name: "test".into(),
                category: "physics".into(),
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

        // Approval agrees but checks disagree -> not fully agrees.
        assert!(!result.fully_agrees());
    }

    // -----------------------------------------------------------------------
    // Test: same signing key on both instances still agrees
    // -----------------------------------------------------------------------

    #[test]
    fn same_signing_key_on_both_instances_agrees() {
        let (chain_b64, trusted) = setup_authority();
        let (sk, _) = make_keypair();
        let sk_clone = ed25519_dalek::SigningKey::from_bytes(&sk.to_bytes());

        let config_a = make_config(trusted.clone(), sk, "instance-shared");
        let config_b = make_config(trusted, sk_clone, "instance-shared");

        let diff = DifferentialValidator::new(&config_a, &config_b);
        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        let now = Utc::now();

        let result = diff.validate(&cmd, now, None).unwrap();
        assert!(result.fully_agrees());
    }

    // -----------------------------------------------------------------------
    // Test: acceleration disagreement via different previous_joints
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_with_previous_joints() {
        let (chain_b64, trusted) = setup_authority();
        let (sk_a, _) = make_keypair();
        let (sk_b, _) = make_keypair();

        let config_a = make_config(trusted.clone(), sk_a, "instance-a");
        let config_b = make_config(trusted, sk_b, "instance-b");

        let diff = DifferentialValidator::new(&config_a, &config_b);
        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        let prev = vec![JointState {
            name: "j1".into(),
            position: 0.0,
            velocity: 0.0,
            effort: 0.0,
        }];
        let now = Utc::now();

        let result = diff.validate(&cmd, now, Some(&prev)).unwrap();
        assert!(result.fully_agrees());
    }
}
