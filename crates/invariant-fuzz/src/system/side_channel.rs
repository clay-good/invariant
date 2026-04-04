//! SA15: Side-channel timing analysis.
//!
//! Verifies that the accept and reject paths have similar execution times,
//! preventing an attacker from inferring rejection reasons via timing analysis.

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use invariant_core::authority::crypto::generate_keypair;
    use invariant_core::models::command::{
        Command, CommandAuthority, EndEffectorPosition, JointState,
    };
    use invariant_core::validator::ValidatorConfig;
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use std::time::Instant;

    fn setup() -> (
        ValidatorConfig,
        invariant_core::models::profile::RobotProfile,
    ) {
        let name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(name).unwrap();
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        let kid = "sa15-kid".to_string();
        let mut trusted = HashMap::new();
        trusted.insert(kid.clone(), vk);
        let config = ValidatorConfig::new(profile.clone(), trusted, sk, kid).unwrap();
        (config, profile)
    }

    fn make_command(
        profile: &invariant_core::models::profile::RobotProfile,
        valid: bool,
    ) -> Command {
        let position = if valid {
            (profile.joints[0].min + profile.joints[0].max) / 2.0
        } else {
            profile.joints[0].max * 100.0 // way outside limits
        };

        Command {
            timestamp: Utc::now(),
            source: "sa15".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: profile.joints[0].name.clone(),
                position,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: profile.max_delta_time * 0.5,
            end_effector_positions: vec![EndEffectorPosition {
                name: "ee".into(),
                position: [0.0, 0.0, 1.0],
            }],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
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

    /// SA15: The ratio of reject-path time to accept-path time should be
    /// bounded. A large ratio would leak information about which checks failed.
    ///
    /// Note: Both paths will be "rejected" here because there's no valid PCA
    /// chain, but the physics checks execute in full regardless.  We measure
    /// the physics path difference between valid-physics and invalid-physics
    /// commands.
    #[test]
    fn sa15_timing_ratio_bounded() {
        let (config, profile) = setup();
        let now = Utc::now();

        let valid_cmd = make_command(&profile, true);
        let invalid_cmd = make_command(&profile, false);

        // Warm up.
        for _ in 0..100 {
            let _ = config.validate(&valid_cmd, now, None);
            let _ = config.validate(&invalid_cmd, now, None);
        }

        let iterations = 5000;

        // Measure valid-physics path.
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = config.validate(&valid_cmd, now, None);
        }
        let valid_elapsed = start.elapsed();

        // Measure invalid-physics path.
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = config.validate(&invalid_cmd, now, None);
        }
        let invalid_elapsed = start.elapsed();

        let ratio = valid_elapsed.as_nanos() as f64 / invalid_elapsed.as_nanos().max(1) as f64;

        // The ratio should be within 5x.  A perfectly constant-time
        // implementation would give ratio ≈ 1.0.  Real-world variance
        // means we allow a generous bound.
        assert!(
            ratio > 0.2 && ratio < 5.0,
            "SA15: timing ratio {ratio:.2} is outside acceptable range [0.2, 5.0]; \
             valid={valid_elapsed:?}, invalid={invalid_elapsed:?}"
        );
    }
}
