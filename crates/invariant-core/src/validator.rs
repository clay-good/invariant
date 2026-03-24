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

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
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
        let profile_json = serde_json::to_vec(&profile).map_err(|e| {
            ValidatorError::Serialization {
                reason: e.to_string(),
            }
        })?;
        let profile_hash = sha256_hex(&profile_json);
        Ok(Self {
            profile,
            trusted_keys,
            signing_key,
            signer_kid,
            profile_hash,
        })
    }

    pub fn profile(&self) -> &RobotProfile {
        &self.profile
    }

    pub fn signer_kid(&self) -> &str {
        &self.signer_kid
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
        let command_json = serde_json::to_vec(command).map_err(|e| {
            ValidatorError::Serialization {
                reason: e.to_string(),
            }
        })?;
        let command_hash = sha256_hex(&command_json);

        // Decode PCA chain and run authority verification.
        let (authority_result, verified_chain) = self.run_authority(
            &command.authority.pca_chain,
            &command.authority.required_ops,
            now,
        );

        // Run 10 physics checks.
        let physics_checks = physics::run_all_checks(command, &self.profile, previous_joints);

        // Assemble all 11 check results and determine approval.
        let mut checks = Vec::with_capacity(11);
        checks.push(authority_result);
        checks.extend(physics_checks);

        let approved = checks.iter().all(|c| c.passed);

        // Build authority summary.
        let authority_summary =
            build_authority_summary(verified_chain.as_ref(), &command.authority.required_ops);

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
        if let Err(e) = check_required_ops(&chain, required_ops) {
            return (
                CheckResult {
                    name: "authority".into(),
                    category: "authority".into(),
                    passed: false,
                    details: e.to_string(),
                },
                Some(chain),
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

    fn sign_verdict(&self, verdict: &Verdict) -> Result<SignedVerdict, ValidatorError> {
        let verdict_json = serde_json::to_vec(verdict).map_err(|e| {
            ValidatorError::Serialization {
                reason: e.to_string(),
            }
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

fn decode_pca_chain(pca_chain_b64: &str) -> Result<Vec<SignedPca>, String> {
    let bytes = STANDARD
        .decode(pca_chain_b64)
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JSON parse failed: {e}"))
}

fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

fn build_authority_summary(
    chain: Option<&AuthorityChain>,
    required_ops: &[Operation],
) -> AuthoritySummary {
    let operations_required: Vec<String> = required_ops.iter().map(|op| op.to_string()).collect();

    match chain {
        Some(c) => AuthoritySummary {
            origin_principal: c.origin_principal().to_string(),
            hop_count: c.hops().len(),
            operations_granted: c.final_ops().iter().map(|op| op.to_string()).collect(),
            operations_required,
        },
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
    use crate::models::command::{CommandAuthority, JointState};
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
                min: -3.14,
                max: 3.14,
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
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: chain_b64.to_string(),
                required_ops,
            },
            metadata: HashMap::new(),
        }
    }

    fn make_config(
        trusted: HashMap<String, VerifyingKey>,
        sign_sk: SigningKey,
    ) -> ValidatorConfig {
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
        assert_eq!(result.signed_verdict.verdict.checks.len(), 11);
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
        assert_eq!(result.signed_verdict.verdict.checks.len(), 11);

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

        // Even though authority ops were insufficient, the chain was verified,
        // so the summary should have the origin principal.
        assert_eq!(
            result.signed_verdict.verdict.authority_summary.origin_principal,
            "alice"
        );
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
            r1.actuation_command.as_ref().map(|a| &a.actuation_signature),
            r2.actuation_command.as_ref().map(|a| &a.actuation_signature),
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
        let hash = sha256_hex(b"hello world");
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
        assert_eq!(
            result.signed_verdict.verdict.authority_summary.hop_count,
            2
        );
    }
}
