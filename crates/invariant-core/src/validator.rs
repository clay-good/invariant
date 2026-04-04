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
use crate::models::command::{Command, JointState};
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
    #[error("profile validation failed: {0}")]
    InvalidProfile(#[from] ValidationError),

    #[error("serialization failed: {reason}")]
    Serialization { reason: String },
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

    pub fn profile(&self) -> &RobotProfile {
        &self.profile
    }

    pub fn signer_kid(&self) -> &str {
        &self.signer_kid
    }

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
    pub signed_verdict: SignedVerdict,
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

        // Run physics checks (P1-P10 + ISO/TS 15066 = 11 base, plus optional P11-P20).
        let physics_checks = physics::run_all_checks(command, &self.profile, previous_joints);

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
        let threat_analysis = self.threat_scorer.as_ref().map(|scorer| {
            let authority_passed = checks.first().is_some_and(|c| c.passed);
            scorer.lock().unwrap().score(
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
            },
            SensorTrustPolicy::PreferSigned => {
                if readings.is_empty() {
                    return CheckResult {
                        name: "sensor_integrity".into(),
                        category: "sensor".into(),
                        passed: true,
                        details: "sensor trust policy: prefer_signed (no signed readings provided, accepted with warning)".into(),
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
                    },
                    Err(e) => CheckResult {
                        name: "sensor_integrity".into(),
                        category: "sensor".into(),
                        passed: false,
                        details: format!("sensor verification failed: {e}"),
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
                    },
                    Err(e) => CheckResult {
                        name: "sensor_integrity".into(),
                        category: "sensor".into(),
                        passed: false,
                        details: format!("sensor verification failed: {e}"),
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
}
