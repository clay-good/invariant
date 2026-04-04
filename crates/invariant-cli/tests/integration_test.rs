//! End-to-end integration tests for the Invariant validation pipeline.
//!
//! These tests exercise the full pipeline: load profile → build command →
//! forge authority → validate → check verdict → write audit → verify audit.
//! They use the public APIs of invariant-core and invariant-sim together.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tempfile::TempDir;

use invariant_core::authority::crypto::{generate_keypair, sign_pca};
use invariant_core::models::authority::{Operation, Pca};
use invariant_core::models::command::{Command, CommandAuthority, EndEffectorPosition, JointState};
use invariant_core::models::profile::RobotProfile;
use invariant_core::profiles;
use invariant_core::validator::ValidatorConfig;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_humanoid() -> RobotProfile {
    profiles::load_builtin("humanoid_28dof").unwrap()
}

fn make_signing_keys() -> (SigningKey, ed25519_dalek::VerifyingKey, String) {
    let sk = generate_keypair(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk, "integration-test-key".to_string())
}

fn forge_chain(sk: &SigningKey, kid: &str, ops: &[Operation]) -> String {
    let pca = Pca {
        p_0: "integration-test-operator".to_string(),
        ops: ops.iter().cloned().collect(),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed = sign_pca(&pca, sk).unwrap();
    let chain_json = serde_json::to_vec(&[signed]).unwrap();
    STANDARD.encode(&chain_json)
}

fn safe_command(profile: &RobotProfile, chain_b64: &str, ops: Vec<Operation>) -> Command {
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

    // Provide positions for all links referenced by collision pairs, spread
    // apart so the self-collision check (P7) passes.
    let mut ee_positions: Vec<EndEffectorPosition> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for pair in &profile.collision_pairs {
        if seen.insert(pair.link_a.clone()) {
            ee_positions.push(EndEffectorPosition {
                name: pair.link_a.clone(),
                position: [0.2 * ee_positions.len() as f64, 0.0, 1.0],
            });
        }
        if seen.insert(pair.link_b.clone()) {
            ee_positions.push(EndEffectorPosition {
                name: pair.link_b.clone(),
                position: [0.2 * ee_positions.len() as f64, 0.0, 1.0],
            });
        }
    }
    ee_positions.push(EndEffectorPosition {
        name: "end_effector".to_string(),
        position: [0.0, 0.0, 1.0],
    });

    Command {
        timestamp: Utc::now(),
        source: "integration-test".to_string(),
        sequence: 1,
        joint_states,
        delta_time: profile.max_delta_time * 0.5,
        end_effector_positions: ee_positions,
        center_of_mass: None,
        authority: CommandAuthority {
            pca_chain: chain_b64.to_string(),
            required_ops: ops,
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

// ---------------------------------------------------------------------------
// Test: full pipeline — safe command approved with signed actuation
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_safe_command_approved() {
    let profile = load_humanoid();
    let (pca_sk, pca_vk, kid) = make_signing_keys();
    let (sign_sk, _sign_vk) = (generate_keypair(&mut OsRng), ());

    let op = Operation::new("actuate:*").unwrap();
    let chain_b64 = forge_chain(&pca_sk, &kid, &[op.clone()]);

    let mut trusted = HashMap::new();
    trusted.insert(kid.clone(), pca_vk);

    let config =
        ValidatorConfig::new(profile.clone(), trusted, sign_sk, "signer-001".to_string()).unwrap();

    let cmd = safe_command(&profile, &chain_b64, vec![op]);
    let result = config.validate(&cmd, Utc::now(), None).unwrap();

    assert!(
        result.signed_verdict.verdict.approved,
        "safe command must be approved; failed checks: {:?}",
        result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .filter(|c| !c.passed)
            .collect::<Vec<_>>()
    );
    assert!(
        result.actuation_command.is_some(),
        "approved command must produce a signed actuation command"
    );
    assert_eq!(result.signed_verdict.signer_kid, "signer-001");
}

// ---------------------------------------------------------------------------
// Test: full pipeline — dangerous command rejected, no actuation
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_dangerous_command_rejected() {
    let profile = load_humanoid();
    let (pca_sk, pca_vk, kid) = make_signing_keys();
    let sign_sk = generate_keypair(&mut OsRng);

    let op = Operation::new("actuate:*").unwrap();
    let chain_b64 = forge_chain(&pca_sk, &kid, &[op.clone()]);

    let mut trusted = HashMap::new();
    trusted.insert(kid, pca_vk);

    let config =
        ValidatorConfig::new(profile.clone(), trusted, sign_sk, "signer-001".to_string()).unwrap();

    // Dangerous: position way outside joint limits.
    let mut cmd = safe_command(&profile, &chain_b64, vec![op]);
    for js in &mut cmd.joint_states {
        js.position = 999.0;
        js.velocity = 999.0;
        js.effort = 99999.0;
    }

    let result = config.validate(&cmd, Utc::now(), None).unwrap();

    assert!(
        !result.signed_verdict.verdict.approved,
        "dangerous command must be rejected"
    );
    assert!(
        result.actuation_command.is_none(),
        "rejected command must NOT produce actuation"
    );

    // Specific physics checks must have failed.
    let failed: Vec<&str> = result
        .signed_verdict
        .verdict
        .checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.name.as_str())
        .collect();
    assert!(failed.contains(&"joint_limits"), "P1 must fail");
    assert!(failed.contains(&"velocity_limits"), "P2 must fail");
    assert!(failed.contains(&"torque_limits"), "P3 must fail");
}

// ---------------------------------------------------------------------------
// Test: full pipeline — authority failure, no actuation
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_authority_failure() {
    let profile = load_humanoid();
    let sign_sk = generate_keypair(&mut OsRng);

    // Empty trusted keys = no key can verify the chain.
    let config = ValidatorConfig::new(
        profile.clone(),
        HashMap::new(),
        sign_sk,
        "signer".to_string(),
    )
    .unwrap();

    let op = Operation::new("actuate:*").unwrap();
    // Forge a chain with an unknown key.
    let rogue_sk = generate_keypair(&mut OsRng);
    let chain_b64 = forge_chain(&rogue_sk, "rogue-key", &[op.clone()]);

    let cmd = safe_command(&profile, &chain_b64, vec![op]);
    let result = config.validate(&cmd, Utc::now(), None).unwrap();

    assert!(!result.signed_verdict.verdict.approved);
    assert!(result.actuation_command.is_none());

    let auth_check = result
        .signed_verdict
        .verdict
        .checks
        .iter()
        .find(|c| c.name == "authority")
        .unwrap();
    assert!(
        !auth_check.passed,
        "authority check must fail with unknown key"
    );
}

// ---------------------------------------------------------------------------
// Test: validate → audit → verify round-trip
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_audit_round_trip() {
    let dir = TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    let profile = load_humanoid();
    let (pca_sk, pca_vk, kid) = make_signing_keys();
    let sign_sk = generate_keypair(&mut OsRng);
    let audit_sk = generate_keypair(&mut OsRng);

    let op = Operation::new("actuate:*").unwrap();
    let chain_b64 = forge_chain(&pca_sk, &kid, &[op.clone()]);

    let mut trusted = HashMap::new();
    trusted.insert(kid, pca_vk);

    let config =
        ValidatorConfig::new(profile.clone(), trusted, sign_sk, "signer".to_string()).unwrap();

    // Open audit logger.
    let mut logger = invariant_core::audit::AuditLogger::open_file(
        &audit_path,
        audit_sk,
        "audit-signer".to_string(),
    )
    .unwrap();

    // Validate 3 commands and log them.
    for seq in 1..=3u64 {
        let mut cmd = safe_command(&profile, &chain_b64, vec![op.clone()]);
        cmd.sequence = seq;
        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        logger.log(&cmd, &result.signed_verdict).unwrap();
    }
    drop(logger);

    // Verify the audit log exists and has 3 lines.
    let log_content = std::fs::read_to_string(&audit_path).unwrap();
    let lines: Vec<&str> = log_content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3, "audit log must contain 3 entries");

    // Each line must be valid JSON.
    for (i, line) in lines.iter().enumerate() {
        let parsed: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("audit line {i} is not valid JSON: {e}"));
        // Must have sequence, entry_hash, entry_signature fields.
        assert!(
            parsed.get("sequence").is_some(),
            "line {i} missing sequence"
        );
        assert!(
            parsed.get("entry_hash").is_some(),
            "line {i} missing entry_hash"
        );
        assert!(
            parsed.get("entry_signature").is_some(),
            "line {i} missing entry_signature"
        );
    }

    // Hash chain: entry[i].previous_hash == entry[i-1].entry_hash
    let entries: Vec<serde_json::Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    for i in 1..entries.len() {
        let prev_hash = entries[i - 1]["entry_hash"].as_str().unwrap();
        let curr_prev = entries[i]["previous_hash"].as_str().unwrap();
        assert_eq!(
            curr_prev,
            prev_hash,
            "hash chain broken at entry {i}: previous_hash != entry[{prev}].entry_hash",
            prev = i - 1
        );
    }
}

// ---------------------------------------------------------------------------
// Test: all 4 built-in profiles load and validate successfully
// ---------------------------------------------------------------------------

#[test]
fn all_builtin_profiles_load_and_validate() {
    let names = profiles::list_builtins();
    assert!(names.len() >= 4, "expected at least 4 built-in profiles");

    for name in names {
        let profile = profiles::load_builtin(name)
            .unwrap_or_else(|e| panic!("failed to load profile '{name}': {e}"));

        use invariant_core::models::error::Validate;
        profile
            .validate()
            .unwrap_or_else(|e| panic!("profile '{name}' validation failed: {e}"));

        assert!(!profile.joints.is_empty(), "profile '{name}' has no joints");
    }
}

// ---------------------------------------------------------------------------
// Test: verdict signature is verifiable with the signer's public key
// ---------------------------------------------------------------------------

#[test]
fn verdict_signature_independently_verifiable() {
    let profile = load_humanoid();
    let (pca_sk, pca_vk, kid) = make_signing_keys();
    let sign_sk = generate_keypair(&mut OsRng);
    let sign_vk = sign_sk.verifying_key();

    let op = Operation::new("actuate:*").unwrap();
    let chain_b64 = forge_chain(&pca_sk, &kid, &[op.clone()]);

    let mut trusted = HashMap::new();
    trusted.insert(kid, pca_vk);

    let config =
        ValidatorConfig::new(profile.clone(), trusted, sign_sk, "signer".to_string()).unwrap();

    let cmd = safe_command(&profile, &chain_b64, vec![op]);
    let result = config.validate(&cmd, Utc::now(), None).unwrap();

    // Re-serialize verdict and verify the Ed25519 signature.
    let verdict_json = serde_json::to_vec(&result.signed_verdict.verdict).unwrap();
    let sig_bytes = STANDARD
        .decode(&result.signed_verdict.verdict_signature)
        .unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();

    use ed25519_dalek::Verifier;
    sign_vk
        .verify(&verdict_json, &signature)
        .expect("verdict signature must verify with signer's public key");
}
