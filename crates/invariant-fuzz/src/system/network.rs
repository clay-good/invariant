//! SA7, SA13: Network-level system attacks.
//!
//! - SA7: Man-in-the-middle / command injection (verify signed commands reject modification)
//! - SA13: Cognitive layer impersonation (commands without valid PCA chain are rejected)

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use invariant_core::authority::crypto::generate_keypair;
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::validator::ValidatorConfig;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn setup_validator() -> ValidatorConfig {
        let name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(name).unwrap();
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        let kid = "sa-kid".to_string();
        let mut trusted = HashMap::new();
        trusted.insert(kid.clone(), vk);
        ValidatorConfig::new(profile, trusted, sk, kid).unwrap()
    }

    fn minimal_command(_profile_name: &str) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "impersonator".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
        }
    }

    /// SA13: A command from a "rogue" process with no PCA chain is rejected.
    #[test]
    fn sa13_no_pca_chain_rejected() {
        let config = setup_validator();
        let cmd = minimal_command("test");
        let result = config.validate(&cmd, Utc::now(), None);
        match result {
            Ok(r) => assert!(
                !r.signed_verdict.verdict.approved,
                "SA13: command without PCA chain must be rejected"
            ),
            Err(_) => {} // Validator error = also a rejection, which is correct
        }
    }

    /// SA13: A command with garbage PCA chain is rejected.
    #[test]
    fn sa13_garbage_pca_chain_rejected() {
        let config = setup_validator();
        let mut cmd = minimal_command("test");
        cmd.authority.pca_chain = "AAAA_this_is_garbage_base64_that_decodes_to_nonsense".into();

        let result = config.validate(&cmd, Utc::now(), None);
        match result {
            Ok(r) => assert!(
                !r.signed_verdict.verdict.approved,
                "SA13: garbage PCA chain must be rejected"
            ),
            Err(_) => {} // Also correct — validator error
        }
    }

    /// SA7: A signed actuation command that has been bit-flipped in transit
    /// would fail Ed25519 verification on the motor controller side.
    /// We test that verification detects the tampering.
    #[test]
    fn sa7_bit_flipped_signature_rejected() {
        use ed25519_dalek::{Signature, Signer, Verifier};

        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        // Sign a payload.
        let payload = b"signed actuation command payload";
        let signature = sk.sign(payload);

        // Verify original — should pass.
        assert!(
            vk.verify(payload, &signature).is_ok(),
            "original signature must verify"
        );

        // Bit-flip the payload (simulating MITM tampering).
        let mut tampered_payload = payload.to_vec();
        tampered_payload[5] ^= 0x01;

        let result = vk.verify(&tampered_payload, &signature);
        assert!(
            result.is_err(),
            "SA7: bit-flipped payload must fail Ed25519 verification"
        );

        // Bit-flip the signature instead.
        let mut sig_bytes = signature.to_bytes();
        sig_bytes[10] ^= 0xFF;
        let tampered_sig = Signature::from_bytes(&sig_bytes);

        let result = vk.verify(payload, &tampered_sig);
        assert!(
            result.is_err(),
            "SA7: bit-flipped signature must fail Ed25519 verification"
        );
    }

    /// SA7 (container-only): Full network interception test requires spawning
    /// the `invariant serve` process and a Unix socket MITM proxy.
    #[test]
    #[ignore = "SA7-full: requires containerized environment with Unix socket MITM proxy"]
    fn sa7_full_network_interception() {
        // Would: spawn invariant serve, connect via Unix socket,
        // intercept and modify commands in transit, verify motor rejects.
    }
}
