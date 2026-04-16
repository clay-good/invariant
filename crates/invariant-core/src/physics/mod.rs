/// P4: Joint acceleration limit check.
pub mod acceleration;
/// P8: Control-loop delta-time limit check.
pub mod delta_time;
/// P11: End-effector force limit check.
pub mod ee_force;
/// P21–P25: Environmental awareness checks (terrain, temperature, battery, latency, e-stop).
pub mod environment;
/// P6: Exclusion zone enforcement.
pub mod exclusion_zones;
/// P16: Foot clearance minimum check for legged robots.
pub mod foot_clearance;
/// P13: Contact force rate-of-change limit check.
pub mod force_rate;
/// P18: Friction cone constraint check for legged robots.
pub mod friction_cone;
pub(crate) mod geometry;
/// P12: Grasp force limit check.
pub mod grasp_force;
/// P17: Ground reaction force limit check for legged robots.
pub mod ground_reaction;
/// P20: Heading (yaw) rate limit check for legged robots.
pub mod heading_rate;
/// ISO/TS 15066: Proximity-triggered force limiting for collaborative robots.
pub mod iso15066;
/// P1: Joint position limit check.
pub mod joint_limits;
/// P15: Locomotion velocity limit check for legged robots.
pub mod locomotion_velocity;
/// P14: Payload weight limit check.
pub mod payload;
/// P10: Proximity zone velocity scaling check.
pub mod proximity;
/// P7: Self-collision avoidance check.
pub mod self_collision;
/// P9: Zero-moment point (ZMP) stability check.
pub mod stability;
/// P19: Step length limit check for legged robots.
pub mod step_length;
/// P3: Joint torque limit check.
pub mod torque;
/// P2: Joint velocity limit check.
pub mod velocity;
/// P5: Workspace bounds check.
pub mod workspace;

#[cfg(test)]
mod tests;

use crate::models::command::{Command, EndEffectorForce, JointState};
use crate::models::profile::{ExclusionZone, RobotProfile, WorkspaceBounds};
use crate::models::verdict::CheckResult;

/// Run all 10 physics checks (P1–P10) against a command and robot profile.
///
/// `previous_joints` supplies the previous command's joint states for the
/// acceleration check (P4). Pass `None` on the first command.
///
/// `previous_forces` supplies the previous command's end-effector force
/// readings for the force-rate check (P13). Pass `None` on the first command.
///
/// Returns a `Vec` of at least 10 `CheckResult`s, one per invariant, in order.
/// Locomotion checks (P15–P20) are appended when both the command carries
/// `locomotion_state` and the profile defines a `locomotion` config.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::physics::run_all_checks;
/// use invariant_robotics_core::profiles::load_builtin;
/// use invariant_robotics_core::models::command::{
///     Command, CommandAuthority, EndEffectorPosition, JointState,
/// };
/// use chrono::Utc;
/// use std::collections::HashMap;
///
/// let profile = load_builtin("ur10").unwrap();
///
/// // Build a command with all 6 UR10 joints at zero and an end-effector
/// // inside the workspace bounds. delta_time must be ≤ max_delta_time (0.008 s).
/// let command = Command {
///     timestamp: Utc::now(),
///     source: "test".to_string(),
///     sequence: 0,
///     joint_states: vec![
///         JointState { name: "shoulder_pan_joint".into(),  position: 0.0, velocity: 0.0, effort: 0.0 },
///         JointState { name: "shoulder_lift_joint".into(), position: 0.0, velocity: 0.0, effort: 0.0 },
///         JointState { name: "elbow_joint".into(),         position: 0.0, velocity: 0.0, effort: 0.0 },
///         JointState { name: "wrist_1_joint".into(),       position: 0.0, velocity: 0.0, effort: 0.0 },
///         JointState { name: "wrist_2_joint".into(),       position: 0.0, velocity: 0.0, effort: 0.0 },
///         JointState { name: "wrist_3_joint".into(),       position: 0.0, velocity: 0.0, effort: 0.0 },
///     ],
///     delta_time: 0.004,
///     end_effector_positions: vec![
///         EndEffectorPosition { name: "tool0".into(), position: [0.5, 0.0, 1.0] },
///     ],
///     center_of_mass: None,
///     authority: CommandAuthority { pca_chain: String::new(), required_ops: vec![] },
///     metadata: HashMap::new(),
///     locomotion_state: None,
///     end_effector_forces: vec![],
///     estimated_payload_kg: None,
///     signed_sensor_readings: vec![],
///     zone_overrides: HashMap::new(),
///     environment_state: None,
/// };
///
/// let results = run_all_checks(&command, &profile, None, None);
///
/// // At least 10 checks returned (P1–P10 + ISO 15066).
/// assert!(results.len() >= 10);
///
/// // The first four checks (joint limits, velocity, torque, acceleration) all pass.
/// assert!(results[0].passed, "joint_limits: {}", results[0].details);
/// assert!(results[1].passed, "velocity: {}", results[1].details);
/// assert!(results[2].passed, "torque: {}", results[2].details);
/// assert!(results[3].passed, "acceleration: {}", results[3].details);
/// ```
pub fn run_all_checks(
    command: &Command,
    profile: &RobotProfile,
    previous_joints: Option<&[JointState]>,
    previous_forces: Option<&[EndEffectorForce]>,
) -> Vec<CheckResult> {
    // Reject commands with empty joint_states — a command without any joint
    // data would vacuously pass all joint-based checks (P1-P4, P10), allowing
    // an empty command to bypass the entire safety envelope.
    if command.joint_states.is_empty() && !profile.joints.is_empty() {
        let reason = "command contains no joint states but profile defines joints";
        let names = [
            "joint_limits",
            "velocity_limits",
            "torque_limits",
            "acceleration_limits",
            "workspace_bounds",
            "exclusion_zones",
            "self_collision",
            "delta_time",
            "stability",
            "proximity_velocity",
        ];
        return names
            .iter()
            .map(|name| CheckResult {
                name: name.to_string(),
                category: "physics".to_string(),
                passed: false,
                details: reason.to_string(),
                derating: None,
            })
            .collect();
    }

    let margins = profile.real_world_margins.as_ref();
    let envelope = profile.task_envelope.as_ref();

    // Task envelope overrides (Section 17): tighten-only semantics.
    let effective_velocity_scale = match envelope.and_then(|e| e.global_velocity_scale) {
        Some(env_scale) => env_scale.min(profile.global_velocity_scale),
        None => profile.global_velocity_scale,
    };

    // Effective workspace: use envelope workspace if present (must be subset of profile).
    let effective_workspace: &WorkspaceBounds = match envelope.and_then(|e| e.workspace.as_ref()) {
        Some(ws) => ws,
        None => &profile.workspace,
    };

    // Effective exclusion zones: profile zones + envelope additional zones.
    let mut effective_zones: Vec<ExclusionZone> = profile.exclusion_zones.clone();
    if let Some(env) = envelope {
        effective_zones.extend(env.additional_exclusion_zones.iter().cloned());
    }

    let mut results = vec![
        // P1: Joint position limits (tightened by position_margin in Guardian mode)
        joint_limits::check_joint_limits(&command.joint_states, &profile.joints, margins),
        // P2: Joint velocity limits (tightened by velocity_margin + envelope velocity scale)
        velocity::check_velocity_limits(
            &command.joint_states,
            &profile.joints,
            effective_velocity_scale,
            margins,
        ),
        // P3: Joint torque limits (tightened by torque_margin in Guardian mode)
        torque::check_torque_limits(&command.joint_states, &profile.joints, margins),
        // P4: Joint acceleration limits (tightened by acceleration_margin in Guardian mode)
        acceleration::check_acceleration_limits(
            &command.joint_states,
            previous_joints,
            &profile.joints,
            command.delta_time,
            margins,
        ),
        // P5: Workspace bounds (envelope may tighten workspace)
        workspace::check_workspace_bounds(&command.end_effector_positions, effective_workspace),
        // P6: Exclusion zones (profile zones + envelope additional zones)
        exclusion_zones::check_exclusion_zones(
            &command.end_effector_positions,
            &effective_zones,
            &command.zone_overrides,
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
        // P10: Proximity velocity scaling (uses envelope velocity scale if tighter)
        proximity::check_proximity_velocity(
            &command.joint_states,
            &profile.joints,
            &command.end_effector_positions,
            &profile.proximity_zones,
            effective_velocity_scale,
        ),
    ];

    // P15–P20: Locomotion checks — only when both sides are present.
    let mut loco_results = run_locomotion_checks(command, profile);
    results.append(&mut loco_results);

    // P11–P14 + ISO/TS 15066: Manipulation checks — only when the profile defines end-effectors.
    let mut manip_results = run_manipulation_checks(command, profile, previous_forces);
    results.append(&mut manip_results);

    // ISO/TS 15066: Proximity-triggered force limiting.
    // Active when both proximity zones and force data are present.
    results.push(iso15066::check_iso15066_force_limits(
        &command.end_effector_positions,
        &command.end_effector_forces,
        &profile.proximity_zones,
        None, // body region override from task envelope (future)
    ));

    // P21–P25: Environmental awareness checks — only when command carries environment_state.
    let mut env_results = run_environment_checks(command, profile);
    results.append(&mut env_results);

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

/// Run environmental awareness checks (P21–P25) against a command and robot profile.
///
/// Returns an empty `Vec` when the command has no `environment_state`.
/// P21–P24 also require `profile.environment` config for thresholds.
/// P25 (emergency stop) is always active when e-stop data is present,
/// regardless of profile config.
pub fn run_environment_checks(command: &Command, profile: &RobotProfile) -> Vec<CheckResult> {
    let Some(env) = &command.environment_state else {
        return vec![];
    };

    let mut results = Vec::new();

    // Sensor range plausibility — reject physically impossible values before
    // P21-P25 threshold checks. Always active, no config needed.
    results.push(environment::check_sensor_range(env));

    // P25: Emergency stop — always active, no config needed.
    results.push(environment::check_emergency_stop(env));

    // P21–P24 require profile environment config for thresholds.
    if let Some(config) = &profile.environment {
        // P21: Terrain incline
        results.push(environment::check_terrain_incline(env, config));
        // P22: Actuator temperature
        results.push(environment::check_actuator_temperature(env, config));
        // P23: Battery state
        results.push(environment::check_battery_state(env, config));
        // P24: Communication latency
        results.push(environment::check_communication_latency(env, config));
    }

    results
}
