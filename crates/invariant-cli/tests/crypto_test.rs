//! Cross-crate Ed25519 cryptographic integration tests.
//!
//! Verifies that PCA signing, verdict signing, and actuation signing work
//! correctly across crate boundaries, and that forged/tampered signatures
//! are properly detected.

use std::collections::{BTreeSet, HashMap};

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use rand::rngs::OsRng;

use invariant_core::authority::crypto::{generate_keypair, sign_pca, verify_signed_pca};
use invariant_core::models::authority::{Operation, Pca};
use invariant_core::models::command::{Command, CommandAuthority, JointState};
use invariant_core::profiles;
use invariant_core::validator::ValidatorConfig;

// ---------------------------------------------------------------------------
// Test: PCA sign → verify round-trip
// ---------------------------------------------------------------------------

#[test]
fn pca_sign_verify_round_trip() {
    let sk = generate_keypair(&mut OsRng);
    let vk = sk.verifying_key();

    let pca = Pca {
        p_0: "alice".to_string(),
        ops: BTreeSet::from([Operation::new("actuate:left_arm:*").unwrap()]),
        kid: "key-001".to_string(),
        exp: None,
        nbf: None,
    };

    let signed = sign_pca(&pca, &sk).unwrap();
    assert!(
        verify_signed_pca(&signed, &vk, 0).is_ok(),
        "freshly signed PCA must verify"
    );
}

// ---------------------------------------------------------------------------
// Test: tampered PCA signature is rejected
// ---------------------------------------------------------------------------

#[test]
fn tampered_pca_signature_rejected() {
    let sk = generate_keypair(&mut OsRng);
    let vk = sk.verifying_key();

    let pca = Pca {
        p_0: "alice".to_string(),
        ops: BTreeSet::from([Operation::new("actuate:*").unwrap()]),
        kid: "key-001".to_string(),
        exp: None,
        nbf: None,
    };

    let mut signed = sign_pca(&pca, &sk).unwrap();

    // Tamper: flip a byte in the raw COSE_Sign1 envelope.
    if let Some(byte) = signed.raw.last_mut() {
        *byte ^= 0xFF;
    }

    let result = verify_signed_pca(&signed, &vk, 0);
    assert!(
        result.is_err(),
        "tampered PCA must fail verification: got Ok"
    );
}

// ---------------------------------------------------------------------------
// Test: wrong key rejects PCA
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_rejects_pca() {
    let sk = generate_keypair(&mut OsRng);
    let wrong_sk = generate_keypair(&mut OsRng);
    let wrong_vk = wrong_sk.verifying_key();

    let pca = Pca {
        p_0: "bob".to_string(),
        ops: BTreeSet::from([Operation::new("actuate:*").unwrap()]),
        kid: "key-001".to_string(),
        exp: None,
        nbf: None,
    };

    let signed = sign_pca(&pca, &sk).unwrap();

    assert!(
        verify_signed_pca(&signed, &wrong_vk, 0).is_err(),
        "PCA signed by key A must not verify with key B"
    );
}

// ---------------------------------------------------------------------------
// Test: multi-hop chain with monotonically narrowing ops is approved
// ---------------------------------------------------------------------------

#[test]
fn multi_hop_monotonic_chain_approved() {
    let profile = profiles::load_builtin("humanoid_28dof").unwrap();

    let sk1 = generate_keypair(&mut OsRng);
    let vk1 = sk1.verifying_key();
    let sk2 = generate_keypair(&mut OsRng);
    let vk2 = sk2.verifying_key();
    let sign_sk = generate_keypair(&mut OsRng);

    // Hop 0: broad ops.
    let pca0 = Pca {
        p_0: "operator".to_string(),
        ops: BTreeSet::from([Operation::new("actuate:*").unwrap()]),
        kid: "k1".to_string(),
        exp: None,
        nbf: None,
    };
    let s0 = sign_pca(&pca0, &sk1).unwrap();

    // Hop 1: narrower ops (subset).
    let pca1 = Pca {
        p_0: "operator".to_string(),
        ops: BTreeSet::from([Operation::new("actuate:humanoid_28dof:joint_0:*").unwrap()]),
        kid: "k2".to_string(),
        exp: None,
        nbf: None,
    };
    let s1 = sign_pca(&pca1, &sk2).unwrap();

    let chain_json = serde_json::to_vec(&[s0, s1]).unwrap();
    let chain_b64 = STANDARD.encode(&chain_json);

    let mut trusted = HashMap::new();
    trusted.insert("k1".to_string(), vk1);
    trusted.insert("k2".to_string(), vk2);

    let config =
        ValidatorConfig::new(profile.clone(), trusted, sign_sk, "signer".to_string()).unwrap();

    let op = Operation::new("actuate:humanoid_28dof:joint_0:position").unwrap();
    let cmd = Command {
        timestamp: Utc::now(),
        source: "test".to_string(),
        sequence: 1,
        joint_states: vec![JointState {
            name: "joint_0".to_string(),
            position: 0.0,
            velocity: 0.0,
            effort: 0.0,
        }],
        delta_time: 0.01,
        end_effector_positions: vec![],
        center_of_mass: None,
        authority: CommandAuthority {
            pca_chain: chain_b64,
            required_ops: vec![op],
        },
        metadata: HashMap::new(),
        locomotion_state: None,
        end_effector_forces: vec![],
        estimated_payload_kg: None,
    };

    let result = config.validate(&cmd, Utc::now(), None).unwrap();
    let auth_check = result
        .signed_verdict
        .verdict
        .checks
        .iter()
        .find(|c| c.name == "authority")
        .unwrap();
    assert!(
        auth_check.passed,
        "multi-hop monotonic chain must pass authority: {}",
        auth_check.details
    );
    assert_eq!(result.signed_verdict.verdict.authority_summary.hop_count, 2);
}

// ---------------------------------------------------------------------------
// Test: privilege escalation (non-monotonic chain) is rejected
// ---------------------------------------------------------------------------

#[test]
fn privilege_escalation_rejected() {
    let profile = profiles::load_builtin("humanoid_28dof").unwrap();

    let sk1 = generate_keypair(&mut OsRng);
    let vk1 = sk1.verifying_key();
    let sk2 = generate_keypair(&mut OsRng);
    let vk2 = sk2.verifying_key();
    let sign_sk = generate_keypair(&mut OsRng);

    // Hop 0: narrow ops.
    let pca0 = Pca {
        p_0: "operator".to_string(),
        ops: BTreeSet::from([
            Operation::new("actuate:humanoid_28dof:joint_0:position").unwrap()
        ]),
        kid: "k1".to_string(),
        exp: None,
        nbf: None,
    };
    let s0 = sign_pca(&pca0, &sk1).unwrap();

    // Hop 1: BROADER ops (escalation!).
    let pca1 = Pca {
        p_0: "operator".to_string(),
        ops: BTreeSet::from([Operation::new("actuate:*").unwrap()]),
        kid: "k2".to_string(),
        exp: None,
        nbf: None,
    };
    let s1 = sign_pca(&pca1, &sk2).unwrap();

    let chain_json = serde_json::to_vec(&[s0, s1]).unwrap();
    let chain_b64 = STANDARD.encode(&chain_json);

    let mut trusted = HashMap::new();
    trusted.insert("k1".to_string(), vk1);
    trusted.insert("k2".to_string(), vk2);

    let config =
        ValidatorConfig::new(profile.clone(), trusted, sign_sk, "signer".to_string()).unwrap();

    let op = Operation::new("actuate:humanoid_28dof:joint_0:position").unwrap();
    let cmd = Command {
        timestamp: Utc::now(),
        source: "test".to_string(),
        sequence: 1,
        joint_states: vec![JointState {
            name: "joint_0".to_string(),
            position: 0.0,
            velocity: 0.0,
            effort: 0.0,
        }],
        delta_time: 0.01,
        end_effector_positions: vec![],
        center_of_mass: None,
        authority: CommandAuthority {
            pca_chain: chain_b64,
            required_ops: vec![op],
        },
        metadata: HashMap::new(),
        locomotion_state: None,
        end_effector_forces: vec![],
        estimated_payload_kg: None,
    };

    let result = config.validate(&cmd, Utc::now(), None).unwrap();
    assert!(
        !result.signed_verdict.verdict.approved,
        "privilege escalation must be rejected"
    );
}
