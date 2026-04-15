//! Random valid command generator.
//!
//! `CommandGenerator` produces `Command` values whose joint positions and
//! velocities are uniformly distributed within the limits defined by the
//! supplied `RobotProfile`.  The commands have no PCA chain; callers must
//! attach one before running through the full validator.

use std::collections::HashMap;

use rand::Rng;

use invariant_core::models::command::{Command, CommandAuthority, JointState};
use invariant_core::models::profile::RobotProfile;

/// Generates random valid commands for a robot profile.
///
/// # Examples
///
/// ```
/// use invariant_robotics_fuzz::generators::command_gen::CommandGenerator;
/// use invariant_core::models::profile::{RobotProfile, JointDefinition, JointType,
///                                        WorkspaceBounds, SafeStopProfile};
/// use rand::SeedableRng;
/// use rand::rngs::StdRng;
///
/// // Build a minimal two-joint profile.
/// let profile = RobotProfile {
///     name: "test-arm".into(),
///     version: "1.0.0".into(),
///     joints: vec![
///         JointDefinition { name: "shoulder".into(), joint_type: JointType::Revolute,
///                           min: -1.57, max: 1.57, max_velocity: 1.0,
///                           max_torque: 50.0, max_acceleration: 5.0 },
///         JointDefinition { name: "elbow".into(), joint_type: JointType::Revolute,
///                           min: -2.0, max: 2.0, max_velocity: 1.5,
///                           max_torque: 30.0, max_acceleration: 8.0 },
///     ],
///     workspace: WorkspaceBounds::Aabb { min: [-2.0,-2.0,0.0], max: [2.0,2.0,3.0] },
///     exclusion_zones: vec![], proximity_zones: vec![], collision_pairs: vec![],
///     stability: None, locomotion: None, max_delta_time: 0.1,
///     min_collision_distance: 0.01, global_velocity_scale: 1.0,
///     watchdog_timeout_ms: 50, safe_stop_profile: SafeStopProfile::default(),
///     profile_signature: None, profile_signer_kid: None, config_sequence: None,
///     real_world_margins: None, task_envelope: None, environment: None,
///     end_effectors: vec![],
/// };
///
/// let mut rng = StdRng::seed_from_u64(42);
///
/// // Generate ten random commands and verify they stay within joint limits.
/// for _ in 0..10 {
///     let cmd = CommandGenerator::generate(&profile, &mut rng);
///     assert_eq!(cmd.joint_states.len(), 2);
///     assert_eq!(cmd.source, "command-gen");
///
///     for (js, jd) in cmd.joint_states.iter().zip(profile.joints.iter()) {
///         assert!(js.position >= jd.min && js.position <= jd.max,
///             "position {} out of [{}, {}] for {}", js.position, jd.min, jd.max, js.name);
///         assert!(js.velocity >= 0.0 && js.velocity <= jd.max_velocity,
///             "velocity {} out of [0, {}] for {}", js.velocity, jd.max_velocity, js.name);
///     }
/// }
/// ```
pub struct CommandGenerator;

impl CommandGenerator {
    /// Create a new `CommandGenerator`.
    pub fn new() -> Self {
        Self
    }

    /// Generate a single random valid command for `profile`.
    ///
    /// Joint positions are sampled uniformly from `[min, max]`.
    /// Joint velocities are sampled uniformly from `[0, max_velocity]`.
    /// Efforts are set to zero.
    /// `delta_time` is fixed at `0.01` s.
    ///
    /// The returned command has an empty `pca_chain`; callers must attach a
    /// valid chain before validating.
    pub fn generate<R: Rng>(profile: &RobotProfile, rng: &mut R) -> Command {
        let joint_states: Vec<JointState> = profile
            .joints
            .iter()
            .map(|j| {
                let position = rng.gen_range(j.min..=j.max);
                let velocity = rng.gen_range(0.0..=j.max_velocity);
                JointState {
                    name: j.name.clone(),
                    position,
                    velocity,
                    effort: 0.0,
                }
            })
            .collect();

        Command {
            timestamp: chrono::Utc::now(),
            source: "command-gen".to_string(),
            sequence: rng.gen_range(1..=u64::MAX),
            joint_states,
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        }
    }
}

impl Default for CommandGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use invariant_core::models::profile::{
        JointDefinition, JointType, RobotProfile, SafeStopProfile, WorkspaceBounds,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_profile() -> RobotProfile {
        RobotProfile {
            name: "gen_test".into(),
            version: "1.0.0".into(),
            joints: vec![
                JointDefinition {
                    name: "j1".into(),
                    joint_type: JointType::Revolute,
                    min: -1.0,
                    max: 1.0,
                    max_velocity: 2.0,
                    max_torque: 50.0,
                    max_acceleration: 10.0,
                },
                JointDefinition {
                    name: "j2".into(),
                    joint_type: JointType::Revolute,
                    min: -0.5,
                    max: 0.5,
                    max_velocity: 1.0,
                    max_torque: 20.0,
                    max_acceleration: 5.0,
                },
            ],
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

    #[test]
    fn generate_has_correct_joint_count() {
        let profile = test_profile();
        let mut rng = StdRng::seed_from_u64(42);
        let cmd = CommandGenerator::generate(&profile, &mut rng);
        assert_eq!(cmd.joint_states.len(), 2);
    }

    #[test]
    fn generate_positions_within_limits() {
        let profile = test_profile();
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..100 {
            let cmd = CommandGenerator::generate(&profile, &mut rng);
            for (js, jd) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.position >= jd.min && js.position <= jd.max,
                    "position {} out of [{}, {}] for {}",
                    js.position,
                    jd.min,
                    jd.max,
                    js.name
                );
            }
        }
    }

    #[test]
    fn generate_velocities_within_limits() {
        let profile = test_profile();
        let mut rng = StdRng::seed_from_u64(999);
        for _ in 0..100 {
            let cmd = CommandGenerator::generate(&profile, &mut rng);
            for (js, jd) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.velocity >= 0.0 && js.velocity <= jd.max_velocity,
                    "velocity {} out of [0, {}] for {}",
                    js.velocity,
                    jd.max_velocity,
                    js.name
                );
            }
        }
    }

    #[test]
    fn generate_delta_time_is_fixed() {
        let profile = test_profile();
        let mut rng = StdRng::seed_from_u64(7);
        let cmd = CommandGenerator::generate(&profile, &mut rng);
        assert!((cmd.delta_time - 0.01).abs() < 1e-10);
    }

    #[test]
    fn generate_source_is_command_gen() {
        let profile = test_profile();
        let mut rng = StdRng::seed_from_u64(1);
        let cmd = CommandGenerator::generate(&profile, &mut rng);
        assert_eq!(cmd.source, "command-gen");
    }

    #[test]
    fn generate_joint_names_match_profile() {
        let profile = test_profile();
        let mut rng = StdRng::seed_from_u64(55);
        let cmd = CommandGenerator::generate(&profile, &mut rng);
        for (js, jd) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            assert_eq!(js.name, jd.name);
        }
    }

    #[test]
    fn default_constructor_works() {
        let _gen = CommandGenerator::default();
    }

    #[test]
    fn two_calls_with_different_seeds_differ() {
        let profile = test_profile();
        let mut rng1 = StdRng::seed_from_u64(1);
        let mut rng2 = StdRng::seed_from_u64(2);
        let cmd1 = CommandGenerator::generate(&profile, &mut rng1);
        let cmd2 = CommandGenerator::generate(&profile, &mut rng2);
        // Extremely unlikely that two independent seeds produce the same positions.
        let same = cmd1
            .joint_states
            .iter()
            .zip(cmd2.joint_states.iter())
            .all(|(a, b)| (a.position - b.position).abs() < 1e-12);
        assert!(!same, "different seeds should produce different positions");
    }
}
