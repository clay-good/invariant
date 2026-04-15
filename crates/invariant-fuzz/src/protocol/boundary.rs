//! PA1–PA2: Boundary probing and epsilon escalation.
//!
//! `BoundaryProber` generates commands that sit exactly at joint limits (PA1)
//! and just beyond them by a small epsilon (PA2).  Each generated command is
//! paired with a boolean indicating whether the validator *should* accept it
//! (`true`) or reject it (`false`).

use std::collections::HashMap;

use invariant_core::models::command::{Command, CommandAuthority, EndEffectorPosition, JointState};
use invariant_core::models::profile::{RobotProfile, WorkspaceBounds};

/// A small positive offset used to probe values just outside the joint limits.
const EPSILON: f64 = 1e-9;

/// Generates boundary-probing commands for a robot profile.
///
/// For each joint, `probe_all_joints` produces four commands:
/// - `min` and `max` (PA1 — expected to pass the joint-limits check)
/// - `min - epsilon` and `max + epsilon` (PA2 — expected to be rejected)
///
/// # Examples
///
/// ```
/// use invariant_robotics_fuzz::protocol::boundary::BoundaryProber;
/// use invariant_core::models::profile::{RobotProfile, JointDefinition, JointType,
///                                        WorkspaceBounds, SafeStopProfile};
///
/// let profile = RobotProfile {
///     name: "cobot".into(),
///     version: "1.0.0".into(),
///     joints: vec![
///         JointDefinition { name: "wrist".into(), joint_type: JointType::Revolute,
///                           min: -3.14, max: 3.14, max_velocity: 2.0,
///                           max_torque: 10.0, max_acceleration: 20.0 },
///     ],
///     workspace: WorkspaceBounds::Aabb { min: [-1.0,-1.0,0.0], max: [1.0,1.0,2.0] },
///     exclusion_zones: vec![], proximity_zones: vec![], collision_pairs: vec![],
///     stability: None, locomotion: None, max_delta_time: 0.1,
///     min_collision_distance: 0.01, global_velocity_scale: 1.0,
///     watchdog_timeout_ms: 50, safe_stop_profile: SafeStopProfile::default(),
///     profile_signature: None, profile_signer_kid: None, config_sequence: None,
///     real_world_margins: None, task_envelope: None, environment: None,
///     end_effectors: vec![],
/// };
///
/// // One joint => 4 probes (min, max, min-eps, max+eps).
/// let probes = BoundaryProber::probe_all_joints(&profile);
/// assert_eq!(probes.len(), 4);
///
/// // The first two are at the exact limits and should pass.
/// assert!(probes[0].1, "min boundary probe should be expected-pass");
/// assert!(probes[1].1, "max boundary probe should be expected-pass");
///
/// // The last two exceed limits and should be rejected.
/// assert!(!probes[2].1, "min-epsilon probe should be expected-reject");
/// assert!(!probes[3].1, "max+epsilon probe should be expected-reject");
///
/// // All commands have the correct source tag.
/// for (cmd, _) in &probes {
///     assert_eq!(cmd.source, "boundary-prober");
/// }
/// ```
pub struct BoundaryProber;

impl BoundaryProber {
    /// Create a new `BoundaryProber`.
    pub fn new() -> Self {
        Self
    }

    /// Generate boundary-probing commands for all joints in `profile`.
    ///
    /// For each joint the following positions are probed:
    ///
    /// | Position          | Class | Expected |
    /// |-------------------|-------|----------|
    /// | `min`             | PA1   | accept   |
    /// | `max`             | PA1   | accept   |
    /// | `min - epsilon`   | PA2   | reject   |
    /// | `max + epsilon`   | PA2   | reject   |
    ///
    /// Returns a `Vec` of `(Command, expected_pass)` pairs.  The commands have
    /// an empty PCA chain; callers must attach a valid chain before running
    /// them through the full validator.  The `expected_pass` value reflects only
    /// the joint-limits check — if the chain is invalid the command will be
    /// rejected regardless.
    pub fn probe_all_joints(profile: &RobotProfile) -> Vec<(Command, bool)> {
        let mut results = Vec::new();

        for joint in &profile.joints {
            // PA1 – exactly at limits: should pass the joint-limits check.
            results.push((make_command(profile, &joint.name, joint.min), true));
            results.push((make_command(profile, &joint.name, joint.max), true));

            // PA2 – just outside limits: should be rejected.
            results.push((
                make_command(profile, &joint.name, joint.min - EPSILON),
                false,
            ));
            results.push((
                make_command(profile, &joint.name, joint.max + EPSILON),
                false,
            ));
        }

        results
    }
}

impl Default for BoundaryProber {
    fn default() -> Self {
        Self::new()
    }
}

/// Build end-effector positions that satisfy workspace and self-collision checks.
///
/// Includes one position named "ee" at the workspace center, plus positions
/// for each unique link name in the profile's collision pairs (all at the
/// center with slight offsets so they are far apart from each other).
fn build_ee_positions(profile: &RobotProfile) -> Vec<EndEffectorPosition> {
    let center = workspace_center(&profile.workspace);
    let mut positions = vec![EndEffectorPosition {
        name: "ee".into(),
        position: center,
    }];

    let mut seen = std::collections::HashSet::new();
    for pair in &profile.collision_pairs {
        for name in [&pair.link_a, &pair.link_b] {
            if seen.insert(name.clone()) {
                let offset = seen.len() as f64 * 0.1;
                positions.push(EndEffectorPosition {
                    name: name.clone(),
                    position: [center[0] + offset, center[1], center[2]],
                });
            }
        }
    }

    positions
}

/// Return the center point of the workspace bounding volume.
fn workspace_center(ws: &WorkspaceBounds) -> [f64; 3] {
    match ws {
        WorkspaceBounds::Aabb { min, max } => [
            (min[0] + max[0]) / 2.0,
            (min[1] + max[1]) / 2.0,
            (min[2] + max[2]) / 2.0,
        ],
    }
}

/// Build a minimal command with a single joint set to `position`.
///
/// All other joints in the profile are set to their midpoints so that they
/// do not trigger independent limit violations while the target joint is
/// being probed.
fn make_command(profile: &RobotProfile, target_joint: &str, position: f64) -> Command {
    let joint_states: Vec<JointState> = profile
        .joints
        .iter()
        .map(|j| {
            let pos = if j.name == target_joint {
                position
            } else {
                // Midpoint — inside limits; won't trigger a joint-limits rejection.
                (j.min + j.max) / 2.0
            };
            JointState {
                name: j.name.clone(),
                position: pos,
                velocity: 0.0,
                effort: 0.0,
            }
        })
        .collect();

    // P9 requires center_of_mass when stability config is present and enabled
    // (fail-closed). Supply the polygon centroid so boundary probes pass P9.
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

    Command {
        timestamp: chrono::Utc::now(),
        source: "boundary-prober".to_string(),
        sequence: 1,
        joint_states,
        delta_time: profile.max_delta_time * 0.5,
        end_effector_positions: build_ee_positions(profile),
        center_of_mass,
        authority: CommandAuthority {
            // Callers must attach a valid chain.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_profile() -> RobotProfile {
        use invariant_core::models::profile::{
            JointDefinition, JointType, RobotProfile, SafeStopProfile, WorkspaceBounds,
        };

        RobotProfile {
            name: "test".into(),
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
                    joint_type: JointType::Prismatic,
                    min: 0.0,
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
    fn probe_all_joints_count() {
        let profile = minimal_profile();
        // 2 joints * 4 probes each = 8
        let probes = BoundaryProber::probe_all_joints(&profile);
        assert_eq!(probes.len(), 8);
    }

    #[test]
    fn probe_at_limits_expected_pass() {
        let profile = minimal_profile();
        let probes = BoundaryProber::probe_all_joints(&profile);

        // Probes 0 and 1 are min and max for j1 (expected pass).
        assert!(probes[0].1, "min should be expected-pass");
        assert!(probes[1].1, "max should be expected-pass");
    }

    #[test]
    fn probe_outside_limits_expected_fail() {
        let profile = minimal_profile();
        let probes = BoundaryProber::probe_all_joints(&profile);

        // Probes 2 and 3 are min-eps and max+eps for j1 (expected reject).
        assert!(!probes[2].1, "min-epsilon should be expected-reject");
        assert!(!probes[3].1, "max+epsilon should be expected-reject");
    }

    #[test]
    fn probe_positions_are_correct() {
        let profile = minimal_profile();
        let probes = BoundaryProber::probe_all_joints(&profile);

        // j1: min=-1.0, max=1.0
        let j1_min_pos = probes[0]
            .0
            .joint_states
            .iter()
            .find(|s| s.name == "j1")
            .unwrap()
            .position;
        let j1_max_pos = probes[1]
            .0
            .joint_states
            .iter()
            .find(|s| s.name == "j1")
            .unwrap()
            .position;
        let j1_below_min_pos = probes[2]
            .0
            .joint_states
            .iter()
            .find(|s| s.name == "j1")
            .unwrap()
            .position;
        let j1_above_max_pos = probes[3]
            .0
            .joint_states
            .iter()
            .find(|s| s.name == "j1")
            .unwrap()
            .position;

        assert_eq!(j1_min_pos, -1.0);
        assert_eq!(j1_max_pos, 1.0);
        assert!(j1_below_min_pos < -1.0);
        assert!(j1_above_max_pos > 1.0);
    }

    #[test]
    fn non_target_joints_are_at_midpoint() {
        let profile = minimal_profile();
        let probes = BoundaryProber::probe_all_joints(&profile);

        // When probing j1, j2 should be at its midpoint (0.25).
        let j2_pos = probes[0]
            .0
            .joint_states
            .iter()
            .find(|s| s.name == "j2")
            .unwrap()
            .position;
        assert!(
            (j2_pos - 0.25).abs() < 1e-10,
            "j2 should be at midpoint 0.25, got {j2_pos}"
        );
    }

    #[test]
    fn commands_have_correct_source() {
        let profile = minimal_profile();
        let probes = BoundaryProber::probe_all_joints(&profile);
        for (cmd, _) in &probes {
            assert_eq!(cmd.source, "boundary-prober");
        }
    }

    #[test]
    fn default_constructor_works() {
        let _prober = BoundaryProber::default();
    }
}
