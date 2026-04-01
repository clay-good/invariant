pub mod acceleration;
pub mod delta_time;
pub mod ee_force;
pub mod exclusion_zones;
pub mod foot_clearance;
pub mod force_rate;
pub mod friction_cone;
pub mod grasp_force;
pub mod ground_reaction;
pub mod heading_rate;
pub mod joint_limits;
pub mod locomotion_velocity;
pub mod payload;
pub mod proximity;
pub mod self_collision;
pub mod stability;
pub mod step_length;
pub mod torque;
pub mod velocity;
pub mod workspace;

#[cfg(test)]
mod tests;

use crate::models::command::{Command, EndEffectorForce, JointState};
use crate::models::profile::RobotProfile;
use crate::models::verdict::CheckResult;

/// Run all 10 physics checks (P1–P10) against a command and robot profile.
///
/// `previous_joints` supplies the previous command's joint states for the
/// acceleration check (P4). Pass `None` on the first command.
///
/// Returns a `Vec` of at least 10 `CheckResult`s, one per invariant, in order.
/// Locomotion checks (P15–P20) are appended when both the command carries
/// `locomotion_state` and the profile defines a `locomotion` config.
pub fn run_all_checks(
    command: &Command,
    profile: &RobotProfile,
    previous_joints: Option<&[JointState]>,
) -> Vec<CheckResult> {
    // Reject commands with empty joint_states — a command without any joint
    // data would vacuously pass all joint-based checks (P1-P4, P10), allowing
    // an empty command to bypass the entire safety envelope.
    if command.joint_states.is_empty() && !profile.joints.is_empty() {
        let fail = CheckResult {
            name: "empty_joint_states".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "command contains no joint states but profile defines joints".to_string(),
        };
        return vec![fail; 10];
    }

    let mut results = vec![
        // P1: Joint position limits
        joint_limits::check_joint_limits(&command.joint_states, &profile.joints),
        // P2: Joint velocity limits
        velocity::check_velocity_limits(
            &command.joint_states,
            &profile.joints,
            profile.global_velocity_scale,
        ),
        // P3: Joint torque limits
        torque::check_torque_limits(&command.joint_states, &profile.joints),
        // P4: Joint acceleration limits
        acceleration::check_acceleration_limits(
            &command.joint_states,
            previous_joints,
            &profile.joints,
            command.delta_time,
        ),
        // P5: Workspace bounds
        workspace::check_workspace_bounds(&command.end_effector_positions, &profile.workspace),
        // P6: Exclusion zones
        exclusion_zones::check_exclusion_zones(
            &command.end_effector_positions,
            &profile.exclusion_zones,
        ),
        // P7: Self-collision
        self_collision::check_self_collision(
            &command.end_effector_positions,
            &profile.collision_pairs,
            profile.min_collision_distance,
        ),
        // P8: Delta time
        delta_time::check_delta_time(command.delta_time, profile.max_delta_time),
        // P9: Stability (ZMP)
        stability::check_stability(command.center_of_mass.as_ref(), profile.stability.as_ref()),
        // P10: Proximity velocity scaling
        proximity::check_proximity_velocity(
            &command.joint_states,
            &profile.joints,
            &command.end_effector_positions,
            &profile.proximity_zones,
            profile.global_velocity_scale,
        ),
    ];

    // P15–P20: Locomotion checks — only when both sides are present.
    let mut loco_results = run_locomotion_checks(command, profile);
    results.append(&mut loco_results);

    // P11–P14: Manipulation checks — only when the profile defines end-effectors.
    let mut manip_results = run_manipulation_checks(command, profile, None);
    results.append(&mut manip_results);

    results
}

/// Run manipulation safety checks (P11–P14) against a command and robot profile.
///
/// Returns an empty `Vec` when the profile defines no `end_effectors`. Otherwise
/// returns up to 4 `CheckResult`s, one per manipulation invariant.
///
/// `previous_forces` supplies the previous command's end-effector force readings
/// for the force-rate check (P13). Pass `None` on the first command.
pub fn run_manipulation_checks(
    command: &Command,
    profile: &RobotProfile,
    previous_forces: Option<&[EndEffectorForce]>,
) -> Vec<CheckResult> {
    if profile.end_effectors.is_empty() {
        return vec![];
    }

    vec![
        // P11: End-effector force limit
        ee_force::check_ee_force_limits(&command.end_effector_forces, &profile.end_effectors),
        // P12: Grasp force limits
        grasp_force::check_grasp_force_limits(&command.end_effector_forces, &profile.end_effectors),
        // P13: Contact force rate limit
        force_rate::check_force_rate_limits(
            &command.end_effector_forces,
            previous_forces,
            &profile.end_effectors,
            command.delta_time,
        ),
        // P14: Payload weight check
        payload::check_payload_limits(
            &command.end_effector_forces,
            command.estimated_payload_kg,
            &profile.end_effectors,
        ),
    ]
}

/// Run locomotion safety checks (P15–P20) against a command and robot profile.
///
/// Returns an empty `Vec` when either the command has no `locomotion_state` or
/// the profile has no `locomotion` config. Otherwise returns up to 6
/// `CheckResult`s (one per locomotion invariant).
pub fn run_locomotion_checks(command: &Command, profile: &RobotProfile) -> Vec<CheckResult> {
    let (loco, config) = match (&command.locomotion_state, &profile.locomotion) {
        (Some(l), Some(c)) => (l, c),
        _ => return vec![],
    };

    vec![
        // P15: Locomotion velocity limit
        locomotion_velocity::check_locomotion_velocity(loco, config),
        // P16: Foot clearance minimum
        foot_clearance::check_foot_clearance(loco, config),
        // P17: Ground reaction force limit
        ground_reaction::check_ground_reaction(loco, config),
        // P18: Friction cone constraint
        friction_cone::check_friction_cone(loco, config),
        // P19: Step length limit
        step_length::check_step_length(loco, config),
        // P20: Heading rate limit
        heading_rate::check_heading_rate(loco, config),
    ]
}
