/// Shared helper for generating a self-signed PCA chain.
///
/// Both the `validate` (forge mode) and `serve` (trust-plane mode) commands
/// need to auto-issue a PCA chain that grants `required_ops`.  This module
/// keeps the logic in one place and exposes it via [`forge_authority`].
///
/// The `p_0` parameter allows callers to brand the origin principal
/// differently:
/// - `"forge"` — used by the CLI `validate --mode forge` command
/// - `"trust-plane"` — used by the `serve --trust-plane` server
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;

use invariant_core::authority::crypto::sign_pca;
use invariant_core::models::authority::Pca;
use invariant_core::models::command::Command;

/// Attach a freshly-signed PCA chain to `cmd.authority.pca_chain`.
///
/// The chain contains a single PCA whose `p_0` field is set to `p_0`, whose
/// `ops` list mirrors `cmd.authority.required_ops`, and whose `kid` matches
/// the supplied signing key identifier.
///
/// Expiry (`exp`) and not-before (`nbf`) are left unset so that the chain is
/// valid for the life of the process; callers that need a bounded validity
/// window should extend this function or add expiry fields to the PCA before
/// signing.
pub fn forge_authority(
    cmd: &mut Command,
    signing_key: &SigningKey,
    kid: &str,
    p_0: &str,
) -> Result<(), String> {
    let ops = cmd.authority.required_ops.iter().cloned().collect();

    let pca = Pca {
        p_0: p_0.to_string(),
        ops,
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };

    let signed = sign_pca(&pca, signing_key).map_err(|e| e.to_string())?;

    // Encode the chain as a base64-wrapped JSON array of SignedPca.
    let chain = vec![signed];
    let chain_json = serde_json::to_vec(&chain).map_err(|e| e.to_string())?;
    cmd.authority.pca_chain = STANDARD.encode(&chain_json);

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{engine::general_purpose::STANDARD, Engine};
    use invariant_core::authority::crypto::generate_keypair;
    use invariant_core::models::authority::{Operation, SignedPca};
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn make_cmd(ops: Vec<Operation>) -> Command {
        Command {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".to_string(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
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

    /// Happy path: produced chain is non-empty and decodes to exactly one
    /// `SignedPca` entry (which wraps a COSE_Sign1 raw bytes blob).
    #[test]
    fn forge_authority_happy_path_produces_valid_chain() {
        let sk = generate_keypair(&mut OsRng);
        let op = Operation::new("actuate:j1").unwrap();
        let mut cmd = make_cmd(vec![op]);

        forge_authority(&mut cmd, &sk, "test-kid", "forge").unwrap();

        assert!(
            !cmd.authority.pca_chain.is_empty(),
            "pca_chain must be non-empty after forge"
        );

        // Decode and parse the chain — must be valid base64 JSON wrapping one entry.
        let chain_bytes = STANDARD.decode(&cmd.authority.pca_chain).unwrap();
        let chain: Vec<SignedPca> = serde_json::from_slice(&chain_bytes).unwrap();
        assert_eq!(chain.len(), 1, "chain must contain exactly one PCA");
        assert!(
            !chain[0].raw.is_empty(),
            "SignedPca raw bytes must not be empty"
        );
    }

    /// The chain produced with p_0 = "forge" should pass the validator when the
    /// matching verifying key is registered as trusted.
    #[test]
    fn forge_authority_chain_validates_with_matching_key() {
        use invariant_core::validator::ValidatorConfig;
        use std::collections::HashMap;

        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        let kid = "test-kid".to_string();

        let profile_name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(profile_name).unwrap();

        let mut trusted = HashMap::new();
        trusted.insert(kid.clone(), vk);

        // Use a separate signing key copy for the config (config consumes it).
        let sk_for_config = invariant_core::authority::crypto::generate_keypair(&mut OsRng);
        let vk_for_config = sk_for_config.verifying_key();
        trusted.insert("config-kid".to_string(), vk_for_config);

        let config =
            ValidatorConfig::new(profile, trusted, sk_for_config, "config-kid".to_string())
                .unwrap();

        let op = Operation::new("actuate:humanoid_28dof:joint_0:position").unwrap();
        let mut cmd = make_cmd(vec![op]);
        forge_authority(&mut cmd, &sk, &kid, "forge").unwrap();

        let now = chrono::Utc::now();
        let result = config.validate(&cmd, now, None).unwrap();
        // The authority check must pass; physics may or may not depending on profile.
        let authority_check = result
            .signed_verdict
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "authority")
            .expect("authority check must be present");
        assert!(authority_check.passed, "authority check must pass");
    }

    /// p_0 label used in trust-plane mode must also produce a parseable chain.
    #[test]
    fn forge_authority_trust_plane_p0_produces_valid_chain() {
        let sk = generate_keypair(&mut OsRng);
        let mut cmd = make_cmd(vec![Operation::new("actuate:j1").unwrap()]);

        forge_authority(&mut cmd, &sk, "kid", "trust-plane").unwrap();

        let chain_bytes = STANDARD.decode(&cmd.authority.pca_chain).unwrap();
        let chain: Vec<SignedPca> = serde_json::from_slice(&chain_bytes).unwrap();
        assert_eq!(chain.len(), 1);
        assert!(!chain[0].raw.is_empty());
    }

    /// Calling `forge_authority` twice with the same cmd overwrites the first chain;
    /// both chains decode correctly.
    #[test]
    fn forge_authority_overwrites_previous_chain() {
        let sk = generate_keypair(&mut OsRng);
        let mut cmd = make_cmd(vec![Operation::new("actuate:j1").unwrap()]);

        forge_authority(&mut cmd, &sk, "kid", "forge").unwrap();
        let first_chain = cmd.authority.pca_chain.clone();

        forge_authority(&mut cmd, &sk, "kid", "forge").unwrap();
        let second_chain = cmd.authority.pca_chain.clone();

        // Both should decode correctly.
        for chain_b64 in &[first_chain, second_chain] {
            let bytes = STANDARD.decode(chain_b64).unwrap();
            let chain: Vec<SignedPca> = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(chain.len(), 1);
        }
    }

    /// Empty required_ops produces a chain with an empty ops set.
    #[test]
    fn forge_authority_empty_ops() {
        let sk = generate_keypair(&mut OsRng);
        let mut cmd = make_cmd(vec![]);

        forge_authority(&mut cmd, &sk, "kid", "forge").unwrap();

        assert!(!cmd.authority.pca_chain.is_empty());
        let chain_bytes = STANDARD.decode(&cmd.authority.pca_chain).unwrap();
        let chain: Vec<SignedPca> = serde_json::from_slice(&chain_bytes).unwrap();
        assert_eq!(chain.len(), 1);
    }
}
