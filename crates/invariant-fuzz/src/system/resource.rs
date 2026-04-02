//! SA8: Resource exhaustion resilience.
//!
//! Verifies that sending a large number of commands in a tight loop does not
//! cause panics, OOM, or unbounded memory growth in the validation pipeline.

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use invariant_core::authority::crypto::generate_keypair;
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::validator::ValidatorConfig;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn setup_validator() -> (ValidatorConfig, Command) {
        let name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(name).unwrap();

        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        let kid = "sa8-kid".to_string();
        let mut trusted = HashMap::new();
        trusted.insert(kid.clone(), vk);

        let config = ValidatorConfig::new(profile.clone(), trusted, sk, kid).unwrap();

        let cmd = Command {
            timestamp: Utc::now(),
            source: "sa8-flood".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: profile.joints[0].name.clone(),
                position: (profile.joints[0].min + profile.joints[0].max) / 2.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: profile.max_delta_time * 0.5,
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
        };

        (config, cmd)
    }

    /// SA8: Send 10,000 commands in a tight loop — no panic, no hang.
    #[test]
    fn sa8_flood_10k_commands_no_panic() {
        let (config, cmd) = setup_validator();
        let now = Utc::now();

        for _ in 0..10_000 {
            // We expect rejection (no valid PCA chain), but the point is
            // that the validator doesn't panic, OOM, or hang.
            let _ = config.validate(&cmd, now, None);
        }
    }

    /// SA8: Send commands with maximally large metadata — no crash.
    #[test]
    fn sa8_large_metadata_no_crash() {
        let (config, mut cmd) = setup_validator();
        let now = Utc::now();

        // Fill metadata with many entries.
        for i in 0..100 {
            cmd.metadata.insert(format!("key_{i}"), "x".repeat(1000));
        }

        let _ = config.validate(&cmd, now, None);
    }

    /// SA8: Send commands with many joints — no crash.
    #[test]
    fn sa8_many_joints_no_crash() {
        let (config, mut cmd) = setup_validator();
        let now = Utc::now();

        // Add 200 extra joints (profile only defines a few).
        for i in 0..200 {
            cmd.joint_states.push(JointState {
                name: format!("flood_joint_{i}"),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            });
        }

        let _ = config.validate(&cmd, now, None);
    }
}
