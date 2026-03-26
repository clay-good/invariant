pub mod acceleration;
pub mod delta_time;
pub mod exclusion_zones;
pub mod joint_limits;
pub mod proximity;
pub mod self_collision;
pub mod stability;
pub mod torque;
pub mod velocity;
pub mod workspace;

#[cfg(test)]
mod tests;

use crate::models::command::{Command, JointState};
use crate::models::profile::RobotProfile;
use crate::models::verdict::CheckResult;

/// Run all 10 physics checks (P1–P10) against a command and robot profile.
///
/// `previous_joints` supplies the previous command's joint states for the
/// acceleration check (P4). Pass `None` on the first command.
///
/// Returns a `Vec` of exactly 10 `CheckResult`s, one per invariant, in order.
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

    vec![
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
    ]
}
