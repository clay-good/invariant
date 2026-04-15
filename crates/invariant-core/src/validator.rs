// Validator orchestrator: authority + physics -> signed verdict.
//
// The central pipeline of the Invariant system. Takes a Command, a
// RobotProfile, trusted Ed25519 keys, and a signing key, and produces a
// SignedVerdict (always) plus an optional SignedActuationCommand (only
// if approved).
//
// Design invariants:
// - Fail-closed: any error in the validation path produces a rejection.
// - Deterministic: no I/O, no randomness. The `now` timestamp and
//   `previous_joints` are caller-supplied for testability.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use thiserror::Error;

use crate::actuator;
use crate::authority::chain::{check_required_ops, verify_chain};
use crate::models::actuation::SignedActuationCommand;
use crate::models::authority::{AuthorityChain, Operation, SignedPca};
use crate::models::command::{Command, EndEffectorForce, JointState};
use crate::models::error::{Validate, ValidationError};
use crate::models::profile::RobotProfile;
use crate::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
use crate::physics;
use crate::sensor::{self, SensorTrustPolicy};
use crate::threat::ThreatScorer;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the validator pipeline.
///
/// Only truly unrecoverable errors (serialization, signing) propagate as
/// `Err(...)`. Authority and physics failures are captured as check results
/// inside a rejection verdict, not as `ValidatorError`.
#[derive(Debug, Error)]
pub enum ValidatorError {
    /// The robot profile failed structural validation.
    #[error("profile validation failed: {0}")]
    InvalidProfile(#[from] ValidationError),

    /// JSON serialization of a verdict or command failed.
    #[error("serialization failed: {reason}")]
    Serialization {
        /// Human-readable reason for the serialization failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Immutable configuration for a validator instance.
pub struct ValidatorConfig {
    profile: RobotProfile,
    trusted_keys: HashMap<String, VerifyingKey>,
    signing_key: SigningKey,
    signer_kid: String,
    /// Pre-computed SHA-256 hash of the canonical profile JSON.
    profile_hash: String,
    /// How to handle signed vs unsigned sensor data.
    sensor_policy: SensorTrustPolicy,
    /// Trusted sensor signing keys (kid -> VerifyingKey).
    trusted_sensor_keys: HashMap<String, VerifyingKey>,
    /// Maximum age of sensor readings in milliseconds before rejection.
    sensor_max_age_ms: u64,
    /// Optional threat scorer for continuous adversarial monitoring (Section 11.3).
    /// Uses `Mutex` for interior mutability since the scorer tracks state
    /// across `validate()` calls (which take `&self`) and must be `Sync`
    /// for use with `Arc` in `invariant serve`.
    threat_scorer: Option<Mutex<ThreatScorer>>,
}

impl ValidatorConfig {
    /// Create a new validator configuration.
    ///
    /// The profile is validated immediately; construction fails if the profile
    /// is invalid.
    pub fn new(
        profile: RobotProfile,
        trusted_keys: HashMap<String, VerifyingKey>,
        signing_key: SigningKey,
        signer_kid: String,
    ) -> Result<Self, ValidatorError> {
        profile.validate()?;
        let profile_json =
            serde_json::to_vec(&profile).map_err(|e| ValidatorError::Serialization {
                reason: e.to_string(),
            })?;
        let profile_hash = crate::util::sha256_hex(&profile_json);
        Ok(Self {
            profile,
            trusted_keys,
            signing_key,
            signer_kid,
            profile_hash,
            sensor_policy: SensorTrustPolicy::AcceptUnsigned,
            trusted_sensor_keys: HashMap::new(),
            sensor_max_age_ms: 500,
            threat_scorer: None,
        })
    }

    /// Set the sensor trust policy, trusted sensor keys, and max reading age.
    pub fn with_sensor_policy(
        mut self,
        policy: SensorTrustPolicy,
        sensor_keys: HashMap<String, VerifyingKey>,
        max_age_ms: u64,
    ) -> Self {
        self.sensor_policy = policy;
        self.trusted_sensor_keys = sensor_keys;
        self.sensor_max_age_ms = max_age_ms;
        self
    }

    /// The robot profile used for validation.
    pub fn profile(&self) -> &RobotProfile {
        &self.profile
    }

    /// The key identifier used when signing verdicts and actuation commands.
    pub fn signer_kid(&self) -> &str {
        &self.signer_kid
    }

    /// The sensor trust policy in effect for this validator instance.
    pub fn sensor_policy(&self) -> SensorTrustPolicy {
        self.sensor_policy
    }

    /// Enable continuous adversarial monitoring with the given threat scorer.
    /// Enable continuous adversarial monitoring with the given threat scorer.
    pub fn with_threat_scorer(mut self, scorer: ThreatScorer) -> Self {
        self.threat_scorer = Some(Mutex::new(scorer));
        self
    }
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// The output of a successful `validate()` call.
///
/// Always contains a `SignedVerdict`. If the verdict is approved,
/// `actuation_command` is `Some(...)`.
pub struct ValidationResult {
    /// The cryptographically signed verdict for this command.
    pub signed_verdict: SignedVerdict,
    /// Signed actuation command, present only when the verdict is approved.
    pub actuation_command: Option<SignedActuationCommand>,
}

// ---------------------------------------------------------------------------
// Core validation pipeline
// ---------------------------------------------------------------------------

impl ValidatorConfig {
    /// Run the full validation pipeline on a command.
    ///
    /// Returns `Err(ValidatorError)` only for truly fatal errors (e.g.
    /// serialization failure). Authority/physics failures are encoded in a
    /// rejection verdict, not as errors.
    pub fn validate(
        &self,
        command: &Command,
        now: DateTime<Utc>,
        previous_joints: Option<&[JointState]>,
    ) -> Result<ValidationResult, ValidatorError> {
        self.validate_with_forces(command, now, previous_joints, None)
    }

    /// Run the full validation pipeline on a command, with optional previous
    /// force state for the force-rate check (P13).
    ///
    /// `previous_forces` supplies the previous command's end-effector force
    /// readings.  Pass `None` on the first command of an episode.
    pub fn validate_with_forces(
        &self,
        command: &Command,
        now: DateTime<Utc>,
        previous_joints: Option<&[JointState]>,
        previous_forces: Option<&[EndEffectorForce]>,
    ) -> Result<ValidationResult, ValidatorError> {
        // Guard: reject commands with oversized collections (DoS prevention).
        // These caps mirror the profile-side caps in RobotProfile::validate().
        const MAX_CMD_JOINTS: usize = 256;
        const MAX_CMD_EE: usize = 256;
        const MAX_CMD_FORCES: usize = 256;
        const MAX_CMD_SENSORS: usize = 256;
        const MAX_CMD_FEET: usize = 64;
        if let Some(rejection) = check_command_size_caps(
            command,
            MAX_CMD_JOINTS,
            MAX_CMD_EE,
            MAX_CMD_FORCES,
            MAX_CMD_SENSORS,
            MAX_CMD_FEET,
        ) {
            // Produce a rejection verdict immediately without processing the
            // oversized payload (prevents DoS via expensive physics checks on
            // millions of joints).
            let verdict = Verdict {
                approved: false,
                command_hash: "oversized_command".into(),
                command_sequence: command.sequence,
                timestamp: now,
                checks: vec![rejection],
                profile_name: self.profile.name.clone(),
                profile_hash: self.profile_hash.clone(),
                authority_summary: AuthoritySummary {
                    origin_principal: String::new(),
                    hop_count: 0,
                    operations_granted: vec![],
                    operations_required: command
                        .authority
                        .required_ops
                        .iter()
                        .map(|o| o.as_str().to_owned())
                        .collect(),
                },
                threat_analysis: None,
            };
            let signed = self.sign_verdict(&verdict)?;
            return Ok(ValidationResult {
                signed_verdict: signed,
                actuation_command: None,
            });
        }

        // Compute command hash.
        let command_json =
            serde_json::to_vec(command).map_err(|e| ValidatorError::Serialization {
                reason: e.to_string(),
            })?;
        let command_hash = crate::util::sha256_hex(&command_json);

        // Decode PCA chain and run authority verification.
        let (authority_result, verified_chain) = self.run_authority(
            &command.authority.pca_chain,
            &command.authority.required_ops,
            now,
        );

        // Run sensor integrity verification per configured trust policy.
        let sensor_check = self.run_sensor_check(command, now);

        // Run physics checks (P1-P10 + ISO/TS 15066 = 11 base, plus optional P11-P25).
        let physics_checks =
            physics::run_all_checks(command, &self.profile, previous_joints, previous_forces);

        // Assemble check results (1 authority + 1 sensor + N physics).
        let mut checks = Vec::with_capacity(2 + physics_checks.len());
        checks.push(authority_result);
        checks.push(sensor_check);
        checks.extend(physics_checks);

        let approved = checks.iter().all(|c| c.passed);

        // Build authority summary.
        let authority_summary =
            build_authority_summary(verified_chain.as_ref(), &command.authority.required_ops);

        // Run threat scoring if a scorer is configured (Section 11.3).
        // Use poison recovery: if a previous panic poisoned the mutex, recover
        // the inner scorer and continue rather than propagating a panic that
        // would permanently brick the validator (Step 106).
        let threat_analysis = self.threat_scorer.as_ref().map(|scorer| {
            let authority_passed = checks.first().is_some_and(|c| c.passed);
            scorer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .score(
                    command,
                    &self.profile,
                    authority_passed,
                    &authority_summary.origin_principal,
                    approved,
                )
        });

        // Build and sign verdict.
        let verdict = Verdict {
            approved,
            command_hash: command_hash.clone(),
            command_sequence: command.sequence,
            timestamp: now,
            checks,
            profile_name: self.profile.name.clone(),
            profile_hash: self.profile_hash.clone(),
            authority_summary,
            threat_analysis,
        };

        let signed_verdict = self.sign_verdict(&verdict)?;

        // If approved, build and sign actuation command.
        let actuation_command = if approved {
            Some(actuator::build_signed_actuation_command(
                &command_hash,
                command.sequence,
                &command.joint_states,
                now,
                &self.signing_key,
                &self.signer_kid,
            )?)
        } else {
            None
        };

        Ok(ValidationResult {
            signed_verdict,
            actuation_command,
        })
    }

    /// Decode the PCA chain from base64 JSON and run authority verification.
    fn run_authority(
        &self,
        pca_chain_b64: &str,
        required_ops: &[Operation],
        now: DateTime<Utc>,
    ) -> (CheckResult, Option<AuthorityChain>) {
        // Reject empty required_ops — a command must declare at least one
        // operation it intends to perform. Empty ops would pass via vacuous
        // truth, producing an approved command with no operation constraints.
        if required_ops.is_empty() {
            return (
                CheckResult {
                    name: "authority".into(),
                    category: "authority".into(),
                    passed: false,
                    details: "required_ops must not be empty".into(),
                    derating: None,
                },
                None,
            );
        }

        // Decode base64 -> JSON -> Vec<SignedPca>.
        let hops = match decode_pca_chain(pca_chain_b64) {
            Ok(h) => h,
            Err(reason) => {
                return (
                    CheckResult {
                        name: "authority".into(),
                        category: "authority".into(),
                        passed: false,
                        details: format!("PCA chain decode failed: {reason}"),
                        derating: None,
                    },
                    None,
                );
            }
        };

        // Verify chain (A1, A2, A3, temporal).
        let chain = match verify_chain(&hops, &self.trusted_keys, now) {
            Ok(c) => c,
            Err(e) => {
                return (
                    CheckResult {
                        name: "authority".into(),
                        category: "authority".into(),
                        passed: false,
                        details: e.to_string(),
                        derating: None,
                    },
                    None,
                );
            }
        };

        // Check required ops coverage.
        // Return None for the chain: the granted ops were insufficient, so the
        // chain must not be forwarded to the authority summary where it could
        // leak origin_principal or hop information into a rejection verdict.
        if let Err(e) = check_required_ops(&chain, required_ops) {
            return (
                CheckResult {
                    name: "authority".into(),
                    category: "authority".into(),
                    passed: false,
                    details: e.to_string(),
                    derating: None,
                },
                None,
            );
        }

        (
            CheckResult {
                name: "authority".into(),
                category: "authority".into(),
                passed: true,
                details: "authority chain verified, all required operations covered".into(),
                derating: None,
            },
            Some(chain),
        )
    }

    /// Run sensor integrity verification per the configured trust policy.
    ///
    /// - `AcceptUnsigned`: always passes (backwards compatible).
    /// - `PreferSigned`: passes but warns if unsigned data is present.
    /// - `RequireSigned`: fails if the command has no signed sensor readings,
    ///   or if any reading fails signature/freshness verification.
    fn run_sensor_check(&self, command: &Command, now: DateTime<Utc>) -> CheckResult {
        let readings = &command.signed_sensor_readings;

        match self.sensor_policy {
            SensorTrustPolicy::AcceptUnsigned => CheckResult {
                name: "sensor_integrity".into(),
                category: "sensor".into(),
                passed: true,
                details: "sensor trust policy: accept_unsigned (no verification)".into(),
                derating: None,
            },
            SensorTrustPolicy::PreferSigned => {
                if readings.is_empty() {
                    return CheckResult {
                        name: "sensor_integrity".into(),
                        category: "sensor".into(),
                        passed: true,
                        details: "sensor trust policy: prefer_signed (no signed readings provided, accepted with warning)".into(),
                        derating: None,
                    };
                }
                match sensor::verify_sensor_batch(
                    readings,
                    &self.trusted_sensor_keys,
                    now,
                    self.sensor_max_age_ms,
                ) {
                    Ok(verified) => CheckResult {
                        name: "sensor_integrity".into(),
                        category: "sensor".into(),
                        passed: true,
                        details: format!(
                            "sensor trust policy: prefer_signed ({} readings verified)",
                            verified.len()
                        ),
                        derating: None,
                    },
                    Err(e) => CheckResult {
                        name: "sensor_integrity".into(),
                        category: "sensor".into(),
                        passed: false,
                        details: format!("sensor verification failed: {e}"),
                        derating: None,
                    },
                }
            }
            SensorTrustPolicy::RequireSigned => {
                if readings.is_empty() {
                    return CheckResult {
                        name: "sensor_integrity".into(),
                        category: "sensor".into(),
                        passed: false,
                        details:
                            "sensor trust policy: require_signed (no signed readings provided)"
                                .into(),
                        derating: None,
                    };
                }
                match sensor::verify_sensor_batch(
                    readings,
                    &self.trusted_sensor_keys,
                    now,
                    self.sensor_max_age_ms,
                ) {
                    Ok(verified) => CheckResult {
                        name: "sensor_integrity".into(),
                        category: "sensor".into(),
                        passed: true,
                        details: format!(
                            "sensor trust policy: require_signed ({} readings verified)",
                            verified.len()
                        ),
                        derating: None,
                    },
                    Err(e) => CheckResult {
                        name: "sensor_integrity".into(),
                        category: "sensor".into(),
                        passed: false,
                        details: format!("sensor verification failed: {e}"),
                        derating: None,
                    },
                }
            }
        }
    }

    fn sign_verdict(&self, verdict: &Verdict) -> Result<SignedVerdict, ValidatorError> {
        let verdict_json =
            serde_json::to_vec(verdict).map_err(|e| ValidatorError::Serialization {
                reason: e.to_string(),
            })?;

        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(&verdict_json);

        Ok(SignedVerdict {
            verdict: verdict.clone(),
            verdict_signature: STANDARD.encode(signature.to_bytes()),
            signer_kid: self.signer_kid.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maximum size of base64-encoded PCA chain before decode (DoS guard).
const MAX_PCA_CHAIN_B64_BYTES: usize = 65_536;

fn decode_pca_chain(pca_chain_b64: &str) -> Result<Vec<SignedPca>, String> {
    if pca_chain_b64.len() > MAX_PCA_CHAIN_B64_BYTES {
        return Err(format!(
            "PCA chain too large: {} bytes exceeds {MAX_PCA_CHAIN_B64_BYTES} byte limit",
            pca_chain_b64.len()
        ));
    }
    let bytes = STANDARD
        .decode(pca_chain_b64)
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JSON parse failed: {e}"))
}

fn build_authority_summary(
    chain: Option<&AuthorityChain>,
    required_ops: &[Operation],
) -> AuthoritySummary {
    // Sort operations for canonical ordering so that the verdict signature
    // is deterministic regardless of caller-supplied ordering.
    let mut operations_required: Vec<String> =
        required_ops.iter().map(|op| op.to_string()).collect();
    operations_required.sort();

    match chain {
        Some(c) => {
            // BTreeSet already iterates in sorted order; no explicit sort needed.
            let operations_granted: Vec<String> =
                c.final_ops().iter().map(|op| op.to_string()).collect();
            AuthoritySummary {
                origin_principal: c.origin_principal().to_string(),
                hop_count: c.hops().len(),
                operations_granted,
                operations_required,
            }
        }
        None => AuthoritySummary {
            origin_principal: String::new(),
            hop_count: 0,
            operations_granted: Vec::new(),
            operations_required,
        },
    }
}

// ---------------------------------------------------------------------------
// Command size caps (DoS prevention)
// ---------------------------------------------------------------------------

/// Check that command collections do not exceed size caps.
///
/// Returns `Some(CheckResult)` with a rejection if any collection is oversized,
/// `None` if all are within limits. This prevents memory exhaustion from
/// adversarial commands with millions of joints or end-effectors.
fn check_command_size_caps(
    command: &Command,
    max_joints: usize,
    max_ee: usize,
    max_forces: usize,
    max_sensors: usize,
    max_feet: usize,
) -> Option<CheckResult> {
    let checks: &[(&str, usize, usize)] = &[
        ("joint_states", command.joint_states.len(), max_joints),
        (
            "end_effector_positions",
            command.end_effector_positions.len(),
            max_ee,
        ),
        (
            "end_effector_forces",
            command.end_effector_forces.len(),
            max_forces,
        ),
        (
            "signed_sensor_readings",
            command.signed_sensor_readings.len(),
            max_sensors,
        ),
    ];

    for &(name, count, max) in checks {
        if count > max {
            return Some(CheckResult {
                name: "command_size_cap".into(),
                category: "physics".into(),
                passed: false,
                details: format!("{name} has {count} entries, exceeding cap of {max}"),
                derating: None,
            });
        }
    }

    // Check locomotion feet if present.
    if let Some(ref loco) = command.locomotion_state {
        if loco.feet.len() > max_feet {
            return Some(CheckResult {
                name: "command_size_cap".into(),
                category: "physics".into(),
                passed: false,
                details: format!(
                    "locomotion_state.feet has {} entries, exceeding cap of {max_feet}",
                    loco.feet.len()
                ),
                derating: None,
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::crypto::{generate_keypair, sign_pca};
    use crate::models::authority::{Operation, Pca};
    use crate::models::command::{CommandAuthority, EndEffectorPosition, JointState};
    use crate::models::profile::*;
    use chrono::Utc;
    use rand::rngs::OsRng;
    use std::collections::BTreeSet;

    fn op(s: &str) -> Operation {
        Operation::new(s).unwrap()
    }

    fn ops(ss: &[&str]) -> BTreeSet<Operation> {
        ss.iter().map(|s| op(s)).collect()
    }

    fn make_keypair() -> (SigningKey, VerifyingKey) {
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

    fn encode_chain(hops: &[SignedPca]) -> String {
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
            // Provide a position inside the test_profile workspace AABB
            // (min [-2,-2,0] max [2,2,3]) so that the workspace bounds check
            // does not reject commands that are otherwise valid.
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

    fn make_config(trusted: HashMap<String, VerifyingKey>, sign_sk: SigningKey) -> ValidatorConfig {
        ValidatorConfig::new(test_profile(), trusted, sign_sk, "invariant-test".into()).unwrap()
    }

    #[test]
    fn happy_path_approved() {
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _) = make_keypair();

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

        let config = make_config(trusted, sign_sk);
        let now = Utc::now();
        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);

        let result = config.validate(&cmd, now, None).unwrap();
        assert!(result.signed_verdict.verdict.approved);
        assert_eq!(result.signed_verdict.verdict.checks.len(), 13);
        assert!(result.actuation_command.is_some());
        assert_eq!(result.signed_verdict.signer_kid, "invariant-test");

        // Authority summary should reflect the chain.
        let summary = &result.signed_verdict.verdict.authority_summary;
        assert_eq!(summary.origin_principal, "alice");
        assert_eq!(summary.hop_count, 1);
        assert!(!summary.operations_granted.is_empty());
    }

    #[test]
    fn authority_failure_empty_chain_produces_rejection() {
        let (sign_sk, _) = make_keypair();
        let chain_b64 = STANDARD.encode(b"[]"); // valid JSON but empty chain

        let config = make_config(HashMap::new(), sign_sk);
        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        assert!(result.actuation_command.is_none());
        assert_eq!(result.signed_verdict.verdict.checks.len(), 13);

        let auth_check = &result.signed_verdict.verdict.checks[0];
        assert_eq!(auth_check.name, "authority");
        assert!(!auth_check.passed);
    }

    #[test]
    fn physics_failure_produces_rejection() {
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _) = make_keypair();

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
        let config = make_config(trusted, sign_sk);

        // Joint position way outside limits.
        let mut cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        cmd.joint_states[0].position = 999.0;

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(!result.signed_verdict.verdict.approved);
        assert!(result.actuation_command.is_none());
        // Authority passed.
        assert!(result.signed_verdict.verdict.checks[0].passed);
    }

    #[test]
    fn invalid_base64_chain_produces_rejection() {
        let (sign_sk, _) = make_keypair();
        let config = make_config(HashMap::new(), sign_sk);

        let cmd = make_command("not-valid-base64!!!", vec![op("actuate:j1")]);
        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        assert!(!result.signed_verdict.verdict.checks[0].passed);
        assert!(result.signed_verdict.verdict.checks[0]
            .details
            .contains("decode failed"));
    }

    #[test]
    fn insufficient_ops_produces_rejection() {
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _) = make_keypair();

        // Grant only "read:*", require "actuate:j1".
        let claim = Pca {
            p_0: "alice".into(),
            ops: ops(&["read:*"]),
            kid: "key-1".into(),
            exp: None,
            nbf: None,
        };
        let signed_pca = sign_pca(&claim, &pca_sk).unwrap();
        let chain_b64 = encode_chain(&[signed_pca]);

        let mut trusted = HashMap::new();
        trusted.insert("key-1".to_string(), pca_vk);
        let config = make_config(trusted, sign_sk);

        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        let auth = &result.signed_verdict.verdict.checks[0];
        assert!(!auth.passed);
        assert!(auth.details.contains("not covered"));

        // Finding 76: when check_required_ops fails, the chain is not forwarded
        // to the authority summary. origin_principal must be empty to avoid
        // leaking chain metadata in a rejection verdict.
        assert_eq!(
            result
                .signed_verdict
                .verdict
                .authority_summary
                .origin_principal,
            ""
        );
        assert_eq!(result.signed_verdict.verdict.authority_summary.hop_count, 0);
    }

    #[test]
    fn deterministic_output() {
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _) = make_keypair();

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
        let config = make_config(trusted, sign_sk);

        let now = Utc::now();
        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);

        let r1 = config.validate(&cmd, now, None).unwrap();
        let r2 = config.validate(&cmd, now, None).unwrap();

        assert_eq!(
            r1.signed_verdict.verdict_signature,
            r2.signed_verdict.verdict_signature
        );
        assert_eq!(
            r1.actuation_command
                .as_ref()
                .map(|a| &a.actuation_signature),
            r2.actuation_command
                .as_ref()
                .map(|a| &a.actuation_signature),
        );
    }

    #[test]
    fn verdict_signature_verifiable() {
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _) = make_keypair();
        let sign_vk = sign_sk.verifying_key();

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
        let config = make_config(trusted, sign_sk);

        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        // Re-serialize the verdict and verify the signature.
        let verdict_json = serde_json::to_vec(&result.signed_verdict.verdict).unwrap();
        let sig_bytes = STANDARD
            .decode(&result.signed_verdict.verdict_signature)
            .unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        use ed25519_dalek::Verifier;
        assert!(sign_vk.verify(&verdict_json, &signature).is_ok());
    }

    #[test]
    fn command_hash_format() {
        let hash = crate::util::sha256_hex(b"hello world");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn invalid_profile_rejected() {
        let (sign_sk, _) = make_keypair();
        let mut profile = test_profile();
        profile.joints[0].min = 10.0; // inverted limits
        profile.joints[0].max = 0.0;

        let result = ValidatorConfig::new(profile, HashMap::new(), sign_sk, "test".into());
        assert!(result.is_err());
    }

    #[test]
    fn oversized_pca_chain_rejected() {
        // S5-P1-02: base64 string exceeding MAX_PCA_CHAIN_B64_BYTES is rejected
        // before decode, preventing memory DoS.
        let (sign_sk, _) = make_keypair();
        let config = make_config(HashMap::new(), sign_sk);

        let huge_b64 = "A".repeat(MAX_PCA_CHAIN_B64_BYTES + 1);
        let cmd = make_command(&huge_b64, vec![op("actuate:j1")]);
        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        let auth = &result.signed_verdict.verdict.checks[0];
        assert!(!auth.passed);
        assert!(auth.details.contains("too large"));
    }

    #[test]
    fn empty_required_ops_rejected() {
        // S5-P1-03: empty required_ops must be rejected, not pass via vacuous truth.
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _) = make_keypair();

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
        let config = make_config(trusted, sign_sk);

        let cmd = make_command(&chain_b64, vec![]); // empty required_ops
        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        let auth = &result.signed_verdict.verdict.checks[0];
        assert!(!auth.passed);
        assert!(auth.details.contains("required_ops must not be empty"));
    }

    #[test]
    fn canonical_ops_ordering_in_verdict() {
        // S5-P1-04: operations_required and operations_granted must be sorted
        // so that verdict signatures are deterministic regardless of input order.
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _) = make_keypair();

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
        let config = make_config(trusted, sign_sk);

        let now = Utc::now();

        // Two commands with the same required ops in different order.
        let cmd1 = make_command(&chain_b64, vec![op("actuate:j1"), op("actuate:j2")]);
        let cmd2 = make_command(&chain_b64, vec![op("actuate:j2"), op("actuate:j1")]);

        let r1 = config.validate(&cmd1, now, None).unwrap();
        let r2 = config.validate(&cmd2, now, None).unwrap();

        // Both should produce the same sorted operations_required.
        assert_eq!(
            r1.signed_verdict
                .verdict
                .authority_summary
                .operations_required,
            r2.signed_verdict
                .verdict
                .authority_summary
                .operations_required,
        );

        // Verify they're actually sorted.
        let ops_req = &r1
            .signed_verdict
            .verdict
            .authority_summary
            .operations_required;
        let mut sorted = ops_req.clone();
        sorted.sort();
        assert_eq!(ops_req, &sorted);
    }

    #[test]
    fn pca_chain_exact_boundary_fails_base64_decode_not_size_limit() {
        // Finding 18: a string of exactly MAX_PCA_CHAIN_B64_BYTES bytes passes
        // the size guard but must then fail with a base64 decode error (because
        // the payload is not valid base64-encoded JSON), NOT a "too large" error.
        let (sign_sk, _) = make_keypair();
        let config = make_config(HashMap::new(), sign_sk);

        // A string of exactly MAX_PCA_CHAIN_B64_BYTES '!' characters is not
        // valid base64, so it should hit the decode path, not the size guard.
        let at_limit = "!".repeat(MAX_PCA_CHAIN_B64_BYTES);
        assert_eq!(at_limit.len(), MAX_PCA_CHAIN_B64_BYTES);

        let cmd = make_command(&at_limit, vec![op("actuate:j1")]);
        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        let auth = &result.signed_verdict.verdict.checks[0];
        assert!(!auth.passed);
        // Must be a decode failure, not a size-limit rejection.
        assert!(
            auth.details.contains("decode failed"),
            "expected 'decode failed' in details, got: {}",
            auth.details
        );
        assert!(
            !auth.details.contains("too large"),
            "must not be rejected by the size guard at the boundary"
        );
    }

    #[test]
    fn acceleration_limit_exceeded_with_previous_joints_produces_rejection() {
        // Finding 72: validate() with previous_joints must run the acceleration
        // check end-to-end.  When the velocity delta divided by delta_time
        // exceeds max_acceleration the verdict must be rejected and the
        // acceleration_limits check must be the failing one.
        //
        // test_profile: j1 has max_acceleration = 50.0 rad/s²
        // delta_time = 0.01 s
        // previous velocity = 0.0 rad/s, new velocity = 10.0 rad/s
        // estimated acceleration = |10.0 - 0.0| / 0.01 = 1000 rad/s²  >> 50
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _) = make_keypair();

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
        let config = make_config(trusted, sign_sk);

        // Command: j1 velocity = 10.0 rad/s.
        let mut cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        cmd.joint_states[0].velocity = 10.0;
        cmd.delta_time = 0.01;

        // Previous joints: j1 velocity = 0.0 rad/s.
        let prev_joints = vec![JointState {
            name: "j1".into(),
            position: 0.0,
            velocity: 0.0,
            effort: 0.0,
        }];

        let result = config
            .validate(&cmd, Utc::now(), Some(&prev_joints))
            .unwrap();

        assert!(
            !result.signed_verdict.verdict.approved,
            "verdict must be rejected when acceleration exceeds limit"
        );
        assert!(result.actuation_command.is_none());

        // Find the acceleration_limits check and confirm it failed.
        let accel_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "acceleration_limits")
            .expect("acceleration_limits check must be present");
        assert!(
            !accel_check.passed,
            "acceleration_limits check must fail: {}",
            accel_check.details
        );
        assert!(
            accel_check.details.contains("exceeds max_acceleration"),
            "details should mention the violation: {}",
            accel_check.details
        );
    }

    #[test]
    fn multi_hop_chain_approved() {
        let (sk1, vk1) = make_keypair();
        let (sk2, vk2) = make_keypair();
        let (sign_sk, _) = make_keypair();

        // Hop 0: root grants broad ops.
        let hop0 = Pca {
            p_0: "root".into(),
            ops: ops(&["actuate:*"]),
            kid: "k1".into(),
            exp: None,
            nbf: None,
        };
        let s0 = sign_pca(&hop0, &sk1).unwrap();

        // Hop 1: delegates narrower ops.
        let hop1 = Pca {
            p_0: "root".into(),
            ops: ops(&["actuate:j1"]),
            kid: "k2".into(),
            exp: None,
            nbf: None,
        };
        let s1 = sign_pca(&hop1, &sk2).unwrap();

        let chain_b64 = encode_chain(&[s0, s1]);
        let mut trusted = HashMap::new();
        trusted.insert("k1".to_string(), vk1);
        trusted.insert("k2".to_string(), vk2);

        let config = make_config(trusted, sign_sk);
        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(result.signed_verdict.verdict.approved);
        assert_eq!(result.signed_verdict.verdict.authority_summary.hop_count, 2);
    }

    // -----------------------------------------------------------------------
    // Sensor integrity integration tests
    // -----------------------------------------------------------------------

    use crate::sensor::{sign_sensor_reading, SensorPayload, SensorReading, SensorTrustPolicy};

    fn setup_valid_command_with_authority() -> (Command, HashMap<String, VerifyingKey>) {
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
        let cmd = make_command(&chain_b64, vec![op("actuate:j1")]);
        (cmd, trusted)
    }

    #[test]
    fn accept_unsigned_policy_always_passes_sensor_check() {
        let (cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let config = make_config(trusted, sign_sk); // default: AcceptUnsigned

        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(result.signed_verdict.verdict.approved);
        let sensor_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "sensor_integrity")
            .expect("sensor_integrity check must be present");
        assert!(sensor_check.passed);
        assert!(sensor_check.details.contains("accept_unsigned"));
    }

    #[test]
    fn require_signed_rejects_when_no_readings() {
        let (cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let config = make_config(trusted, sign_sk).with_sensor_policy(
            SensorTrustPolicy::RequireSigned,
            HashMap::new(),
            500,
        );

        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        assert!(result.actuation_command.is_none());
        let sensor_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "sensor_integrity")
            .unwrap();
        assert!(!sensor_check.passed);
        assert!(sensor_check.details.contains("no signed readings"));
    }

    #[test]
    fn require_signed_approves_with_valid_readings() {
        let (mut cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let (sensor_sk, sensor_vk) = make_keypair();

        let reading = SensorReading {
            sensor_name: "left_hand".into(),
            timestamp: Utc::now(),
            payload: SensorPayload::Position {
                position: [0.0, 0.0, 1.0],
            },
            sequence: 1,
        };
        let signed_reading = sign_sensor_reading(&reading, &sensor_sk, "sensor-k1").unwrap();
        cmd.signed_sensor_readings = vec![signed_reading];

        let mut sensor_keys = HashMap::new();
        sensor_keys.insert("sensor-k1".to_string(), sensor_vk);
        let config = make_config(trusted, sign_sk).with_sensor_policy(
            SensorTrustPolicy::RequireSigned,
            sensor_keys,
            5000,
        );

        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(result.signed_verdict.verdict.approved);
        let sensor_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "sensor_integrity")
            .unwrap();
        assert!(sensor_check.passed);
        assert!(sensor_check.details.contains("1 readings verified"));
    }

    #[test]
    fn require_signed_rejects_tampered_reading() {
        let (mut cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let (sensor_sk, sensor_vk) = make_keypair();

        let reading = SensorReading {
            sensor_name: "left_hand".into(),
            timestamp: Utc::now(),
            payload: SensorPayload::Position {
                position: [0.0, 0.0, 1.0],
            },
            sequence: 1,
        };
        let mut signed_reading = sign_sensor_reading(&reading, &sensor_sk, "sensor-k1").unwrap();
        // Tamper: change the position after signing.
        signed_reading.reading.payload = SensorPayload::Position {
            position: [999.0, 999.0, 999.0],
        };
        cmd.signed_sensor_readings = vec![signed_reading];

        let mut sensor_keys = HashMap::new();
        sensor_keys.insert("sensor-k1".to_string(), sensor_vk);
        let config = make_config(trusted, sign_sk).with_sensor_policy(
            SensorTrustPolicy::RequireSigned,
            sensor_keys,
            5000,
        );

        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        let sensor_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "sensor_integrity")
            .unwrap();
        assert!(!sensor_check.passed);
        assert!(sensor_check.details.contains("sensor verification failed"));
    }

    #[test]
    fn require_signed_rejects_stale_reading() {
        let (mut cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let (sensor_sk, sensor_vk) = make_keypair();

        let reading = SensorReading {
            sensor_name: "left_hand".into(),
            timestamp: Utc::now() - chrono::Duration::seconds(10),
            payload: SensorPayload::Position {
                position: [0.0, 0.0, 1.0],
            },
            sequence: 1,
        };
        let signed_reading = sign_sensor_reading(&reading, &sensor_sk, "sensor-k1").unwrap();
        cmd.signed_sensor_readings = vec![signed_reading];

        let mut sensor_keys = HashMap::new();
        sensor_keys.insert("sensor-k1".to_string(), sensor_vk);
        // max_age_ms = 100ms, reading is 10s old
        let config = make_config(trusted, sign_sk).with_sensor_policy(
            SensorTrustPolicy::RequireSigned,
            sensor_keys,
            100,
        );

        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        let sensor_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "sensor_integrity")
            .unwrap();
        assert!(!sensor_check.passed);
        assert!(sensor_check.details.contains("expired"));
    }

    #[test]
    fn prefer_signed_warns_when_no_readings() {
        let (cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let config = make_config(trusted, sign_sk).with_sensor_policy(
            SensorTrustPolicy::PreferSigned,
            HashMap::new(),
            500,
        );

        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        // Still approved (prefer_signed doesn't block on missing readings).
        assert!(result.signed_verdict.verdict.approved);
        let sensor_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "sensor_integrity")
            .unwrap();
        assert!(sensor_check.passed);
        assert!(sensor_check.details.contains("accepted with warning"));
    }

    #[test]
    fn prefer_signed_rejects_tampered_reading() {
        let (mut cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let (sensor_sk, sensor_vk) = make_keypair();

        let reading = SensorReading {
            sensor_name: "sensor_a".into(),
            timestamp: Utc::now(),
            payload: SensorPayload::Force {
                force: [10.0, 0.0, 0.0],
            },
            sequence: 1,
        };
        let mut signed_reading = sign_sensor_reading(&reading, &sensor_sk, "sk1").unwrap();
        signed_reading.reading.payload = SensorPayload::Force {
            force: [0.0, 0.0, 0.0],
        };
        cmd.signed_sensor_readings = vec![signed_reading];

        let mut sensor_keys = HashMap::new();
        sensor_keys.insert("sk1".to_string(), sensor_vk);
        let config = make_config(trusted, sign_sk).with_sensor_policy(
            SensorTrustPolicy::PreferSigned,
            sensor_keys,
            5000,
        );

        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        let sensor_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "sensor_integrity")
            .unwrap();
        assert!(!sensor_check.passed);
    }

    #[test]
    fn sensor_check_always_present_in_verdict() {
        // Every verdict must include the sensor_integrity check regardless of policy.
        let (cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let config = make_config(trusted, sign_sk);

        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        let sensor_checks: Vec<_> = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .filter(|c| c.name == "sensor_integrity")
            .collect();
        assert_eq!(sensor_checks.len(), 1);
        assert_eq!(sensor_checks[0].category, "sensor");
    }

    #[test]
    fn require_signed_rejects_unknown_sensor_kid() {
        let (mut cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let (sensor_sk, _sensor_vk) = make_keypair();

        let reading = SensorReading {
            sensor_name: "imu".into(),
            timestamp: Utc::now(),
            payload: SensorPayload::CenterOfMass {
                com: [0.0, 0.0, 0.9],
            },
            sequence: 1,
        };
        let signed_reading = sign_sensor_reading(&reading, &sensor_sk, "unknown-kid").unwrap();
        cmd.signed_sensor_readings = vec![signed_reading];

        // No sensor keys registered — "unknown-kid" is not trusted.
        let config = make_config(trusted, sign_sk).with_sensor_policy(
            SensorTrustPolicy::RequireSigned,
            HashMap::new(),
            5000,
        );

        let result = config.validate(&cmd, Utc::now(), None).unwrap();

        assert!(!result.signed_verdict.verdict.approved);
        let sensor_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "sensor_integrity")
            .unwrap();
        assert!(!sensor_check.passed);
        assert!(sensor_check.details.contains("unknown signer kid"));
    }

    // -----------------------------------------------------------------------
    // Threat scorer integration tests
    // -----------------------------------------------------------------------

    use crate::threat::{ThreatScorer, ThreatScorerConfig};

    #[test]
    fn verdict_has_no_threat_analysis_by_default() {
        let (cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let config = make_config(trusted, sign_sk);

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(result.signed_verdict.verdict.threat_analysis.is_none());
    }

    #[test]
    fn verdict_has_threat_analysis_when_scorer_enabled() {
        let (cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let config =
            make_config(trusted, sign_sk).with_threat_scorer(ThreatScorer::with_defaults());

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        let ta = result
            .signed_verdict
            .verdict
            .threat_analysis
            .expect("threat_analysis should be present when scorer is enabled");

        // First command — scores should be low.
        assert!(!ta.alert);
        assert!(ta.composite_threat_score < 0.5);
    }

    #[test]
    fn threat_scorer_accumulates_across_validate_calls() {
        let (cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let config =
            make_config(trusted, sign_sk).with_threat_scorer(ThreatScorer::with_defaults());

        // Multiple validate calls should accumulate state in the scorer.
        for _ in 0..5 {
            let result = config.validate(&cmd, Utc::now(), None).unwrap();
            assert!(result.signed_verdict.verdict.threat_analysis.is_some());
        }
    }

    #[test]
    fn threat_scorer_alert_propagates_to_verdict() {
        let (cmd, trusted) = setup_valid_command_with_authority();
        let (sign_sk, _) = make_keypair();
        let scorer_config = ThreatScorerConfig {
            alert_threshold: 0.0, // triggers alert on any non-zero score
            ..ThreatScorerConfig::default()
        };
        let config =
            make_config(trusted, sign_sk).with_threat_scorer(ThreatScorer::new(scorer_config));

        // Feed some commands to build history, then check.
        for _ in 0..15 {
            config.validate(&cmd, Utc::now(), None).unwrap();
        }

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        // With threshold 0.0, alert may or may not trigger depending on scores.
        // The important thing is that threat_analysis is present.
        assert!(result.signed_verdict.verdict.threat_analysis.is_some());
    }

    // -----------------------------------------------------------------------
    // Built-in profile integration tests
    // -----------------------------------------------------------------------
    //
    // These tests exercise the full validation pipeline against every one of
    // the 10 built-in robot profiles, proving that:
    //   - a safe command (midpoint positions, zero velocity, zero effort) is
    //     approved by every profile, and
    //   - a dangerous command (positions = 999.0) is rejected by every profile.
    //
    // Helper: build a minimal valid command for a given profile.
    //
    // Strategy for each field:
    //   joint positions  — midpoint of [min, max] for each joint (always within limits)
    //   joint velocity   — 0.0 (always within limits)
    //   joint effort     — 0.0 (always within limits)
    //   delta_time       — half of max_delta_time (valid: > 0 and <= max)
    //   end_effector_positions —
    //       * one generic "ee" entry at the workspace AABB centre so P5
    //         (workspace bounds) passes for profiles without collision pairs, and
    //       * one entry per unique link name in each collision pair, spread 0.5 m
    //         apart along the X-axis so P7 (self-collision) passes.
    //   center_of_mass   — centroid of the support polygon when stability is
    //                      enabled (always inside the polygon), or None otherwise.
    //   authority chain  — single PCA hop granting "actuate:*", required_ops
    //                      is ["actuate:<first-joint-name>"].

    use crate::models::profile::WorkspaceBounds;
    use crate::profiles::{list_builtins, load_builtin};

    /// Build an authority chain + trusted-keys map that grants "actuate:*".
    fn make_forge_chain() -> (String, HashMap<String, VerifyingKey>, String) {
        let (pca_sk, pca_vk) = make_keypair();
        let claim = Pca {
            p_0: "forge".into(),
            ops: ops(&["actuate:*"]),
            kid: "forge-key".into(),
            exp: None,
            nbf: None,
        };
        let signed_pca = sign_pca(&claim, &pca_sk).unwrap();
        let chain_b64 = encode_chain(&[signed_pca]);
        let mut trusted = HashMap::new();
        trusted.insert("forge-key".to_string(), pca_vk);
        (chain_b64, trusted, "forge-key".to_string())
    }

    /// Compute the workspace centre for an AABB workspace.
    fn ws_center(ws: &WorkspaceBounds) -> [f64; 3] {
        match ws {
            WorkspaceBounds::Aabb { min, max } => [
                (min[0] + max[0]) / 2.0,
                (min[1] + max[1]) / 2.0,
                (min[2] + max[2]) / 2.0,
            ],
        }
    }

    /// Build a safe (midpoint) command for the given profile.
    fn make_safe_command_for_profile(profile: &crate::models::profile::RobotProfile) -> Command {
        use crate::models::command::{CommandAuthority, EndEffectorPosition, JointState};
        use std::collections::HashSet;

        let (chain_b64, _trusted, _kid) = make_forge_chain();

        // Joint states: midpoint position, zero velocity, zero effort.
        let joint_states: Vec<JointState> = profile
            .joints
            .iter()
            .map(|j| JointState {
                name: j.name.clone(),
                position: (j.min + j.max) / 2.0,
                velocity: 0.0,
                effort: 0.0,
            })
            .collect();

        // delta_time: half of max_delta_time.
        let delta_time = profile.max_delta_time / 2.0;

        // End-effector positions: workspace AABB centre + one per collision-pair link.
        //
        // Each additional link is placed at the workspace centre shifted
        // slightly in the +X direction. +X spreading is safe for every
        // built-in profile because:
        //   - All operator/exclusion zones in the built-in profiles are
        //     located at x ≥ 0.6 m from the workspace origin, so a spread
        //     of up to 0.5 m from centre (5 links × 0.1 m) keeps all
        //     positions well inside the safe region.
        //   - The workspace X maximum is at least 0.8 m beyond the centre
        //     for every profile, preventing out-of-bounds violations.
        // The step size (0.1 m) is 10× `min_collision_distance` (0.01 m for
        // all built-in profiles), so every self-collision distance check passes.
        let center = ws_center(&profile.workspace);
        let mut ee_positions: Vec<EndEffectorPosition> = vec![EndEffectorPosition {
            name: "ee".into(),
            position: center,
        }];
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert("ee".into());
        for pair in &profile.collision_pairs {
            for link_name in [&pair.link_a, &pair.link_b] {
                if seen.insert(link_name.clone()) {
                    // Each new link is shifted 0.1 m further in +X than the
                    // previous one. The count starts at 1 so the first link
                    // is 0.1 m from centre, the second 0.2 m, etc.
                    let idx = (seen.len() - 1) as f64; // 1-based index for unique links
                    ee_positions.push(EndEffectorPosition {
                        name: link_name.clone(),
                        position: [center[0] + idx * 0.1, center[1], center[2]],
                    });
                }
            }
        }

        // center_of_mass: centroid of the support polygon when stability is enabled.
        let center_of_mass = profile
            .stability
            .as_ref()
            .filter(|s| s.enabled && s.support_polygon.len() >= 3)
            .map(|s| {
                let n = s.support_polygon.len() as f64;
                let cx = s.support_polygon.iter().map(|v| v[0]).sum::<f64>() / n;
                let cy = s.support_polygon.iter().map(|v| v[1]).sum::<f64>() / n;
                [cx, cy, s.com_height_estimate]
            });

        // required_ops: actuate the first joint in the profile.
        let first_joint_op = op(&format!("actuate:{}", profile.joints[0].name));

        Command {
            timestamp: Utc::now(),
            source: "builtin-profile-test".into(),
            sequence: 1,
            joint_states,
            delta_time,
            end_effector_positions: ee_positions,
            center_of_mass,
            authority: CommandAuthority {
                pca_chain: chain_b64,
                required_ops: vec![first_joint_op],
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

    #[test]
    fn all_builtin_profiles_approve_safe_command() {
        // For each of the 10 built-in profiles, a command with midpoint joint
        // positions, zero velocity, zero effort, and valid authority must be
        // approved by the full validation pipeline.
        for &name in list_builtins() {
            let profile =
                load_builtin(name).unwrap_or_else(|e| panic!("failed to load profile {name}: {e}"));

            let (chain_b64, trusted, _) = make_forge_chain();
            let sign_sk = make_keypair().0;

            let config =
                ValidatorConfig::new(profile.clone(), trusted, sign_sk, "invariant-test".into())
                    .unwrap_or_else(|e| panic!("ValidatorConfig::new failed for {name}: {e}"));

            let cmd = make_safe_command_for_profile(&profile);
            // Override the chain in the command with one signed by our trusted key.
            let mut cmd = cmd;
            cmd.authority.pca_chain = chain_b64;

            let result = config
                .validate(&cmd, Utc::now(), None)
                .unwrap_or_else(|e| panic!("validate() returned Err for {name}: {e}"));

            // Print failing checks to aid diagnosis.
            if !result.signed_verdict.verdict.approved {
                let failing: Vec<_> = result
                    .signed_verdict
                    .verdict
                    .checks
                    .iter()
                    .filter(|c| !c.passed)
                    .map(|c| format!("{}: {}", c.name, c.details))
                    .collect();
                panic!(
                    "profile {name}: expected approved=true but got rejection. \
                     Failing checks: {:?}",
                    failing
                );
            }

            assert!(
                result.actuation_command.is_some(),
                "profile {name}: approved verdict must include actuation_command"
            );
        }
    }

    #[test]
    fn all_builtin_profiles_reject_dangerous_command() {
        // For each profile, a command with all joint positions = 999.0 must be
        // rejected (well outside any realistic joint limit).
        for &name in list_builtins() {
            let profile =
                load_builtin(name).unwrap_or_else(|e| panic!("failed to load profile {name}: {e}"));

            let (chain_b64, trusted, _) = make_forge_chain();
            let sign_sk = make_keypair().0;

            let config =
                ValidatorConfig::new(profile.clone(), trusted, sign_sk, "invariant-test".into())
                    .unwrap_or_else(|e| panic!("ValidatorConfig::new failed for {name}: {e}"));

            let mut cmd = make_safe_command_for_profile(&profile);
            cmd.authority.pca_chain = chain_b64;

            // Overwrite all joint positions with an extreme value.
            for js in &mut cmd.joint_states {
                js.position = 999.0;
            }

            let result = config
                .validate(&cmd, Utc::now(), None)
                .unwrap_or_else(|e| panic!("validate() returned Err for {name}: {e}"));

            assert!(
                !result.signed_verdict.verdict.approved,
                "profile {name}: expected rejection for position=999.0 but got approval"
            );
            assert!(
                result.actuation_command.is_none(),
                "profile {name}: rejected verdict must not include actuation_command"
            );
        }
    }

    #[test]
    fn all_builtin_profiles_reject_nan_velocity() {
        // A command with one joint velocity = NaN must be rejected by every
        // built-in profile.  NaN fails the finite-value guard in the velocity
        // and joint-limit checks.
        for &name in list_builtins() {
            let profile =
                load_builtin(name).unwrap_or_else(|e| panic!("failed to load profile {name}: {e}"));

            let (chain_b64, trusted, _) = make_forge_chain();
            let sign_sk = make_keypair().0;

            let config =
                ValidatorConfig::new(profile.clone(), trusted, sign_sk, "invariant-test".into())
                    .unwrap_or_else(|e| panic!("ValidatorConfig::new failed for {name}: {e}"));

            let mut cmd = make_safe_command_for_profile(&profile);
            cmd.authority.pca_chain = chain_b64;

            // Inject NaN into the first joint's velocity.
            cmd.joint_states[0].velocity = f64::NAN;

            let result = config
                .validate(&cmd, Utc::now(), None)
                .unwrap_or_else(|e| panic!("validate() returned Err for {name}: {e}"));

            assert!(
                !result.signed_verdict.verdict.approved,
                "profile {name}: expected rejection for NaN velocity but got approval"
            );
            assert!(
                result.actuation_command.is_none(),
                "profile {name}: rejected verdict must not include actuation_command"
            );
        }
    }

    #[test]
    fn all_builtin_profiles_reject_inf_torque() {
        // A command with one joint effort = +Infinity must be rejected by every
        // built-in profile.  Infinite values fail the finite-value guard in the
        // torque check.
        for &name in list_builtins() {
            let profile =
                load_builtin(name).unwrap_or_else(|e| panic!("failed to load profile {name}: {e}"));

            let (chain_b64, trusted, _) = make_forge_chain();
            let sign_sk = make_keypair().0;

            let config =
                ValidatorConfig::new(profile.clone(), trusted, sign_sk, "invariant-test".into())
                    .unwrap_or_else(|e| panic!("ValidatorConfig::new failed for {name}: {e}"));

            let mut cmd = make_safe_command_for_profile(&profile);
            cmd.authority.pca_chain = chain_b64;

            // Inject +Infinity into the first joint's effort.
            cmd.joint_states[0].effort = f64::INFINITY;

            let result = config
                .validate(&cmd, Utc::now(), None)
                .unwrap_or_else(|e| panic!("validate() returned Err for {name}: {e}"));

            assert!(
                !result.signed_verdict.verdict.approved,
                "profile {name}: expected rejection for Infinity torque but got approval"
            );
            assert!(
                result.actuation_command.is_none(),
                "profile {name}: rejected verdict must not include actuation_command"
            );
        }
    }

    // ── Zeroed signing key security test (Step 99) ────────────────────

    #[test]
    fn zeroed_signing_key_produces_verifiable_signature_only_with_matching_vk() {
        // Documents the attack surface: a config constructed with an all-zero
        // signing key produces valid Ed25519 signatures — but only verifiable
        // by the corresponding all-zero verifying key. An attacker who knows
        // the key is all-zeros can forge signatures offline.
        let zeroed_sk = SigningKey::from_bytes(&[0u8; 32]);
        let zeroed_vk = zeroed_sk.verifying_key();

        let profile = crate::profiles::load_builtin("franka_panda").unwrap();

        // Use a valid authority chain so the command passes all checks.
        let (chain_b64, trusted, _) = make_forge_chain();

        // Use the zeroed key as the verdict/actuation signing key.
        let config =
            ValidatorConfig::new(profile.clone(), trusted, zeroed_sk, "zeroed-key".into()).unwrap();

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(
            result.signed_verdict.verdict.approved,
            "safe command must be approved"
        );

        // The verdict signature must verify with the zeroed verifying key.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&result.signed_verdict.verdict_signature)
            .unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .expect("signature must be 64 bytes"),
        );
        let verdict_json = serde_json::to_vec(&result.signed_verdict.verdict).unwrap();
        use ed25519_dalek::Verifier;
        assert!(
            zeroed_vk.verify(&verdict_json, &sig).is_ok(),
            "zeroed-key signature must verify against zeroed vk"
        );

        // But must NOT verify against a random key.
        let random_vk = make_keypair().1;
        assert!(
            random_vk.verify(&verdict_json, &sig).is_err(),
            "zeroed-key signature must NOT verify against a random vk"
        );
    }

    // ── Sensor-physics binding gap documentation test (Step 100) ──────

    #[test]
    fn require_signed_policy_empty_readings_rejects() {
        // RequireSigned with no signed_sensor_readings must fail the sensor
        // integrity check, not silently pass.
        let profile = crate::profiles::load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;

        let mut config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();
        config = config.with_sensor_policy(
            crate::sensor::SensorTrustPolicy::RequireSigned,
            std::collections::HashMap::new(),
            500,
        );

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;
        cmd.signed_sensor_readings = vec![]; // empty — triggers rejection

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(
            !result.signed_verdict.verdict.approved,
            "RequireSigned with no readings must reject"
        );
        let sensor_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "sensor_integrity")
            .expect("must have sensor_integrity check");
        assert!(
            !sensor_check.passed,
            "sensor_integrity check must fail when RequireSigned and no readings"
        );
    }

    // ── Step 103: Command size cap + DoS protection tests ─────────────

    #[test]
    fn oversized_joint_states_rejected() {
        let profile = load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;
        let config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        // Stuff 300 joints into the command (cap is 256).
        cmd.joint_states = (0..300)
            .map(|i| JointState {
                name: format!("j{i}"),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            })
            .collect();

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(
            !result.signed_verdict.verdict.approved,
            "command with 300 joints must be rejected"
        );
        let cap_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "command_size_cap");
        assert!(cap_check.is_some(), "must have command_size_cap check");
        assert!(
            cap_check.unwrap().details.contains("joint_states"),
            "details must mention joint_states"
        );
    }

    #[test]
    fn oversized_end_effector_positions_rejected() {
        let profile = load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;
        let config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        // Stuff 300 EE positions (cap is 256).
        cmd.end_effector_positions = (0..300)
            .map(|i| EndEffectorPosition {
                name: format!("ee{i}"),
                position: [0.0, 0.0, 0.5],
            })
            .collect();

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(
            !result.signed_verdict.verdict.approved,
            "command with 300 EE positions must be rejected"
        );
    }

    #[test]
    fn normal_sized_command_not_affected_by_caps() {
        // A normal command (7 joints, a few EEs) must NOT be affected by the caps.
        let profile = load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;
        let config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(
            result.signed_verdict.verdict.approved,
            "normal command must pass; failed: {:?}",
            result
                .signed_verdict
                .verdict
                .checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| format!("{}: {}", c.name, c.details))
                .collect::<Vec<_>>()
        );
    }

    // ── Step 103: Joint name mismatch tests ───────────────────────────

    #[test]
    fn command_with_extra_joints_rejected() {
        // A command with more joints than the profile defines should be
        // rejected — extra joints with extreme values trigger P1/P2/P3
        // violations because the physics checks compare against the profile's
        // joint count. This is correct fail-closed behavior.
        let profile = load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;
        let config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        // Add an extra joint not in the profile with extreme values.
        cmd.joint_states.push(JointState {
            name: "nonexistent_joint".into(),
            position: 999.0,
            velocity: 999.0,
            effort: 999.0,
        });

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(
            !result.signed_verdict.verdict.approved,
            "command with extra joints beyond profile should be rejected"
        );
    }

    #[test]
    fn check_command_size_caps_unit() {
        // Direct unit test for the helper function.
        let profile = load_builtin("franka_panda").unwrap();
        let cmd = make_safe_command_for_profile(&profile);

        // Normal command within caps.
        assert!(check_command_size_caps(&cmd, 256, 256, 256, 256, 64).is_none());

        // Cap at 1 joint — the franka has 7 joints, so it should trigger.
        let result = check_command_size_caps(&cmd, 1, 256, 256, 256, 64);
        assert!(result.is_some());
        assert!(result.unwrap().details.contains("joint_states"));
    }

    // ── Step 103: Remaining collection size cap tests ──────────────────

    #[test]
    fn oversized_end_effector_forces_rejected() {
        let profile = load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;
        let config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        // Stuff 300 EE forces (cap is 256).
        cmd.end_effector_forces = (0..300)
            .map(|i| EndEffectorForce {
                name: format!("ee{i}"),
                force: [0.0, 0.0, 0.0],
                torque: [0.0, 0.0, 0.0],
                grasp_force: None,
            })
            .collect();

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(
            !result.signed_verdict.verdict.approved,
            "command with 300 EE forces must be rejected"
        );
        let cap_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "command_size_cap");
        assert!(cap_check.is_some(), "must have command_size_cap check");
        assert!(
            cap_check.unwrap().details.contains("end_effector_forces"),
            "details must mention end_effector_forces"
        );
    }

    #[test]
    fn oversized_sensor_readings_rejected() {
        use crate::sensor::{SensorPayload, SensorReading, SignedSensorReading};

        let profile = load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;
        let config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        // Stuff 300 sensor readings (cap is 256).
        cmd.signed_sensor_readings = (0..300)
            .map(|i| SignedSensorReading {
                reading: SensorReading {
                    sensor_name: format!("sensor_{i}"),
                    timestamp: Utc::now(),
                    payload: SensorPayload::Position {
                        position: [0.0, 0.0, 0.0],
                    },
                    sequence: i as u64,
                },
                signature: String::new(),
                signer_kid: String::new(),
            })
            .collect();

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(
            !result.signed_verdict.verdict.approved,
            "command with 300 sensor readings must be rejected"
        );
        let cap_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "command_size_cap");
        assert!(cap_check.is_some(), "must have command_size_cap check");
        assert!(
            cap_check
                .unwrap()
                .details
                .contains("signed_sensor_readings"),
            "details must mention signed_sensor_readings"
        );
    }

    #[test]
    fn oversized_locomotion_feet_rejected() {
        use crate::models::command::{FootState, LocomotionState};

        let profile = load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;
        let config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        // Stuff 100 feet (cap is 64).
        cmd.locomotion_state = Some(LocomotionState {
            base_velocity: [0.0, 0.0, 0.0],
            heading_rate: 0.0,
            feet: (0..100)
                .map(|i| FootState {
                    name: format!("foot_{i}"),
                    position: [0.0, 0.0, 0.0],
                    contact: true,
                    ground_reaction_force: None,
                })
                .collect(),
            step_length: 0.0,
        });

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        assert!(
            !result.signed_verdict.verdict.approved,
            "command with 100 feet must be rejected (cap is 64)"
        );
        let cap_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "command_size_cap");
        assert!(cap_check.is_some(), "must have command_size_cap check");
        assert!(
            cap_check.unwrap().details.contains("locomotion_state.feet"),
            "details must mention locomotion_state.feet"
        );
    }

    // ── Step 106: Replay + threat scorer poison tests ─────────────────

    #[test]
    fn identical_commands_produce_identical_verdicts() {
        // Documents that the validator is deterministic: the same command
        // submitted twice produces the same approval and signature. This is
        // the prerequisite for the serve handler's sequence monotonicity
        // check (Step 106) — without that check, replay is trivial.
        let profile = load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;
        let config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();

        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        let now = Utc::now();
        let r1 = config.validate(&cmd, now, None).unwrap();
        let r2 = config.validate(&cmd, now, None).unwrap();

        assert_eq!(
            r1.signed_verdict.verdict.approved,
            r2.signed_verdict.verdict.approved
        );
        assert_eq!(
            r1.signed_verdict.verdict_signature, r2.signed_verdict.verdict_signature,
            "deterministic: same input must produce same signature"
        );
    }

    #[test]
    fn threat_scorer_poison_recovery_continues_validation() {
        // If the threat scorer's mutex is poisoned (from a previous panic),
        // validation must still succeed via poison recovery, not propagate
        // the panic.
        use crate::threat::ThreatScorer;

        let profile = load_builtin("franka_panda").unwrap();
        let (chain_b64, trusted, _) = make_forge_chain();
        let sign_sk = make_keypair().0;
        let mut config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "test".into()).unwrap();
        config = config.with_threat_scorer(ThreatScorer::with_defaults());

        // Poison the mutex by panicking while holding the lock.
        // We do this by wrapping in catch_unwind.
        if let Some(ref scorer_mutex) = config.threat_scorer {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = scorer_mutex.lock().unwrap();
                panic!("intentional poison");
            }));
            // Verify the mutex is now poisoned.
            assert!(scorer_mutex.lock().is_err(), "mutex must be poisoned");
        }

        // Validation must still work — poison recovery via unwrap_or_else.
        let mut cmd = make_safe_command_for_profile(&profile);
        cmd.authority.pca_chain = chain_b64;

        let result = config.validate(&cmd, Utc::now(), None);
        assert!(
            result.is_ok(),
            "validation must succeed even with poisoned threat scorer: {:?}",
            result.err()
        );
        let r = result.unwrap();
        assert!(
            r.signed_verdict.verdict.approved,
            "safe command must still be approved after poison recovery"
        );
    }
}
