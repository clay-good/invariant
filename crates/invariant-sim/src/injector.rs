// Fault injector: mutates a valid `Command` to introduce specific failure modes.
//
// Each `InjectionType` corresponds to one class of safety-relevant misbehaviour
// that the Invariant firewall must detect and reject.

use invariant_core::models::command::{Command, EndEffectorPosition};
use invariant_core::models::profile::RobotProfile;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// InjectionType
// ---------------------------------------------------------------------------

/// The twenty-seven fault-injection modes.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::injector::InjectionType;
///
/// // Variants are comparable and copyable.
/// assert_eq!(InjectionType::VelocityOvershoot, InjectionType::VelocityOvershoot);
/// assert_ne!(InjectionType::VelocityOvershoot, InjectionType::PositionViolation);
///
/// // The full list of injection types is accessible via list_injections().
/// use invariant_robotics_sim::injector::list_injections;
/// let all = list_injections();
/// assert!(!all.is_empty());
/// assert!(all.contains(&InjectionType::VelocityOvershoot));
/// assert!(all.contains(&InjectionType::AuthorityStrip));
/// assert!(all.contains(&InjectionType::NanInjection));
/// assert!(all.contains(&InjectionType::LocomotionOverspeed));
/// assert!(all.contains(&InjectionType::EStopEngage));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionType {
    /// Scale every joint velocity past its profile maximum.
    VelocityOvershoot,
    /// Move joint positions outside their configured limits.
    PositionViolation,
    /// Set joint effort above the configured max torque.
    TorqueSpike,
    /// Place end-effectors outside the workspace AABB.
    WorkspaceEscape,
    /// Set `delta_time` above the profile maximum.
    DeltaTimeViolation,
    /// Place all end-effectors at the same position (self-collision).
    SelfCollision,
    /// Move the centre-of-mass outside the support polygon.
    StabilityViolation,
    /// Clear the PCA chain, removing all authority.
    AuthorityStrip,
    /// Duplicate sequence numbers (replay attack simulation).
    ReplayAttack,
    /// Replace numeric fields with `NaN` / `Infinity`.
    NanInjection,
    // -- Locomotion adversarial injections --
    /// Set base velocity to 3× max locomotion velocity (P15 runaway).
    LocomotionOverspeed,
    /// Violate friction cone constraint: tangential >> normal (P18 slip).
    SlipViolation,
    /// Set swing foot height to 0 or below ground (P16 trip).
    FootClearanceViolation,
    /// Set swing foot height to 3× max_step_height (P16 stomp).
    StompViolation,
    /// Set step length to 3× max (P19 overextension).
    StepOverextension,
    /// Set heading rate to 5× max (P20 spinout).
    HeadingSpinout,
    /// Set ground reaction force to 5× max (P17 stomp).
    GroundReactionSpike,
    // -- Environmental adversarial injections --
    /// Set IMU pitch to 2× max safe pitch (P21 terrain incline).
    TerrainIncline,
    /// Set actuator temperature to 1.5× max operating temperature (P22 overheat).
    TemperatureSpike,
    /// Set battery percentage to 0% (P23 critical battery).
    BatteryDrain,
    /// Set communication latency to 5× max (P24 latency spike).
    LatencySpike,
    /// Engage the hardware emergency stop (P25 e-stop).
    EStopEngage,
    /// Place EE inside a proximity zone and set velocity above the scaled limit (P10 proximity).
    ProximityOverspeed,
    /// Set end-effector force magnitude above max_force_n (P11 force overload).
    ForceOverload,
    /// Set grasp force above max_grasp_force_n (P12 grasp force violation).
    GraspForceViolation,
    /// Set estimated payload mass above max_payload_kg (P14 payload overload).
    PayloadOverload,
    /// Set end-effector force to trigger force-rate limit violation (P13 force rate spike).
    ForceRateSpike,
}

/// All injection types in a fixed order, for iteration.
const ALL_INJECTIONS: &[InjectionType] = &[
    InjectionType::VelocityOvershoot,
    InjectionType::PositionViolation,
    InjectionType::TorqueSpike,
    InjectionType::WorkspaceEscape,
    InjectionType::DeltaTimeViolation,
    InjectionType::SelfCollision,
    InjectionType::StabilityViolation,
    InjectionType::AuthorityStrip,
    InjectionType::ReplayAttack,
    InjectionType::NanInjection,
    InjectionType::LocomotionOverspeed,
    InjectionType::SlipViolation,
    InjectionType::FootClearanceViolation,
    InjectionType::StompViolation,
    InjectionType::StepOverextension,
    InjectionType::HeadingSpinout,
    InjectionType::GroundReactionSpike,
    InjectionType::TerrainIncline,
    InjectionType::TemperatureSpike,
    InjectionType::BatteryDrain,
    InjectionType::LatencySpike,
    InjectionType::EStopEngage,
    InjectionType::ProximityOverspeed,
    InjectionType::ForceOverload,
    InjectionType::GraspForceViolation,
    InjectionType::PayloadOverload,
    InjectionType::ForceRateSpike,
];

/// Returns a slice of every known `InjectionType`.
pub fn list_injections() -> &'static [InjectionType] {
    ALL_INJECTIONS
}

// ---------------------------------------------------------------------------
// inject
// ---------------------------------------------------------------------------

/// Mutate `cmd` in-place to introduce the failure mode described by `injection`.
///
/// The `profile` is consulted to derive limit values used when constructing
/// out-of-bounds values (e.g., `max_velocity * 3.0`).
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use chrono::Utc;
/// use invariant_robotics_sim::injector::{inject, InjectionType};
/// use invariant_core::models::command::{Command, CommandAuthority, JointState};
///
/// let profile = invariant_core::profiles::load_builtin("franka_panda")
///     .expect("franka_panda profile must be available");
///
/// // Start with a command whose joint velocities are within limits.
/// let original_velocity = 0.1_f64;
/// let mut cmd = Command {
///     timestamp: Utc::now(),
///     source: "test".to_string(),
///     sequence: 0,
///     joint_states: vec![JointState {
///         name: "panda_joint1".to_string(),
///         position: 0.0,
///         velocity: original_velocity,
///         effort: 5.0,
///     }],
///     delta_time: 0.01,
///     end_effector_positions: vec![],
///     center_of_mass: None,
///     authority: CommandAuthority {
///         pca_chain: "valid-chain".to_string(),
///         required_ops: vec![],
///     },
///     metadata: HashMap::new(),
///     locomotion_state: None,
///     end_effector_forces: vec![],
///     estimated_payload_kg: None,
///     signed_sensor_readings: vec![],
///     zone_overrides: HashMap::new(),
///     environment_state: None,
/// };
///
/// // After VelocityOvershoot injection the joint velocity must exceed the original.
/// inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
/// assert!(cmd.joint_states[0].velocity > original_velocity);
/// ```
pub fn inject(cmd: &mut Command, injection: InjectionType, profile: &RobotProfile) {
    match injection {
        InjectionType::VelocityOvershoot => inject_velocity_overshoot(cmd, profile),
        InjectionType::PositionViolation => inject_position_violation(cmd, profile),
        InjectionType::TorqueSpike => inject_torque_spike(cmd, profile),
        InjectionType::WorkspaceEscape => inject_workspace_escape(cmd, profile),
        InjectionType::DeltaTimeViolation => inject_delta_time_violation(cmd, profile),
        InjectionType::SelfCollision => inject_self_collision(cmd),
        InjectionType::StabilityViolation => inject_stability_violation(cmd, profile),
        InjectionType::AuthorityStrip => inject_authority_strip(cmd),
        InjectionType::ReplayAttack => inject_replay_attack(cmd),
        InjectionType::NanInjection => inject_nan(cmd),
        InjectionType::LocomotionOverspeed => inject_locomotion_overspeed(cmd, profile),
        InjectionType::SlipViolation => inject_slip_violation(cmd, profile),
        InjectionType::FootClearanceViolation => inject_foot_clearance_violation(cmd),
        InjectionType::StompViolation => inject_stomp_violation(cmd, profile),
        InjectionType::StepOverextension => inject_step_overextension(cmd, profile),
        InjectionType::HeadingSpinout => inject_heading_spinout(cmd, profile),
        InjectionType::GroundReactionSpike => inject_ground_reaction_spike(cmd, profile),
        InjectionType::TerrainIncline => inject_terrain_incline(cmd, profile),
        InjectionType::TemperatureSpike => inject_temperature_spike(cmd, profile),
        InjectionType::BatteryDrain => inject_battery_drain(cmd),
        InjectionType::LatencySpike => inject_latency_spike(cmd, profile),
        InjectionType::EStopEngage => inject_estop_engage(cmd),
        InjectionType::ProximityOverspeed => inject_proximity_overspeed(cmd, profile),
        InjectionType::ForceOverload => inject_force_overload(cmd, profile),
        InjectionType::GraspForceViolation => inject_grasp_force_violation(cmd, profile),
        InjectionType::PayloadOverload => inject_payload_overload(cmd, profile),
        InjectionType::ForceRateSpike => inject_force_rate_spike(cmd, profile),
    }
}

// ---------------------------------------------------------------------------
// Individual injection implementations
// ---------------------------------------------------------------------------

/// Set every joint velocity to 3× its profile maximum (well above any scale).
fn inject_velocity_overshoot(cmd: &mut Command, profile: &RobotProfile) {
    for (js, jdef) in cmd.joint_states.iter_mut().zip(profile.joints.iter()) {
        js.velocity = jdef.max_velocity * profile.global_velocity_scale * 3.0;
    }
}

/// Push every joint position 20 % beyond its limit (alternating sign).
fn inject_position_violation(cmd: &mut Command, profile: &RobotProfile) {
    for (i, (js, jdef)) in cmd
        .joint_states
        .iter_mut()
        .zip(profile.joints.iter())
        .enumerate()
    {
        if i % 2 == 0 {
            // Exceed the upper limit
            let range = jdef.max - jdef.min;
            js.position = jdef.max + range * 0.2;
        } else {
            // Exceed the lower limit
            let range = jdef.max - jdef.min;
            js.position = jdef.min - range * 0.2;
        }
    }
}

/// Set every joint effort to 5× its configured max torque.
fn inject_torque_spike(cmd: &mut Command, profile: &RobotProfile) {
    for (js, jdef) in cmd.joint_states.iter_mut().zip(profile.joints.iter()) {
        js.effort = jdef.max_torque * 5.0;
    }
}

/// Place every end-effector 2 m beyond the maximum corner of the workspace.
fn inject_workspace_escape(cmd: &mut Command, profile: &RobotProfile) {
    use invariant_core::models::profile::WorkspaceBounds;

    let oob = match &profile.workspace {
        WorkspaceBounds::Aabb { max, .. } => [max[0] + 2.0, max[1] + 2.0, max[2] + 2.0],
    };

    if cmd.end_effector_positions.is_empty() {
        // Insert a fabricated end-effector if the command has none.
        cmd.end_effector_positions.push(EndEffectorPosition {
            name: "injected_ee".to_owned(),
            position: oob,
        });
    } else {
        for ee in cmd.end_effector_positions.iter_mut() {
            ee.position = oob;
        }
    }
}

/// Set `delta_time` to twice the profile maximum.
fn inject_delta_time_violation(cmd: &mut Command, profile: &RobotProfile) {
    cmd.delta_time = profile.max_delta_time * 2.0;
}

/// Collapse all end-effectors to the origin — a guaranteed self-collision.
fn inject_self_collision(cmd: &mut Command) {
    let collision_point = [0.0_f64, 0.0, 0.0];
    if cmd.end_effector_positions.len() < 2 {
        // Ensure at least two end-effectors exist so the firewall can detect
        // the co-location.
        let n = cmd.end_effector_positions.len();
        for k in n..2 {
            cmd.end_effector_positions.push(EndEffectorPosition {
                name: format!("injected_ee_{k}"),
                position: collision_point,
            });
        }
    }
    for ee in cmd.end_effector_positions.iter_mut() {
        ee.position = collision_point;
    }
}

/// Place the centre-of-mass far outside any reasonable support polygon.
///
/// If the command already has a `center_of_mass`, it is overwritten; otherwise
/// one is inserted.
fn inject_stability_violation(cmd: &mut Command, profile: &RobotProfile) {
    // Pick a point that is far outside the support polygon.  If the profile
    // has a stability config, jump to 10× the first polygon vertex; otherwise
    // use an arbitrary large offset.
    //
    // If the first vertex is at or near the origin, 10× of it is still near
    // zero and would remain inside the polygon.  In that case fall back to a
    // fixed large offset (100 m) to guarantee the point is well outside any
    // realistic support polygon.
    const NEAR_ZERO_THRESHOLD: f64 = 1e-6;
    const FALLBACK_OFFSET: f64 = 100.0;

    let far_x = profile
        .stability
        .as_ref()
        .and_then(|s| s.support_polygon.first())
        .map(|v| {
            let scaled = v[0] * 10.0;
            if scaled.abs() < NEAR_ZERO_THRESHOLD {
                FALLBACK_OFFSET
            } else {
                scaled
            }
        })
        .unwrap_or(FALLBACK_OFFSET);

    let far_y = profile
        .stability
        .as_ref()
        .and_then(|s| s.support_polygon.first())
        .map(|v| {
            let scaled = v[1] * 10.0;
            if scaled.abs() < NEAR_ZERO_THRESHOLD {
                FALLBACK_OFFSET
            } else {
                scaled
            }
        })
        .unwrap_or(FALLBACK_OFFSET);

    cmd.center_of_mass = Some([far_x, far_y, 2.0]);
}

/// Clear the PCA chain entirely.
fn inject_authority_strip(cmd: &mut Command) {
    cmd.authority.pca_chain.clear();
}

/// Set the sequence number back to 0, simulating a replayed / stale command.
fn inject_replay_attack(cmd: &mut Command) {
    cmd.sequence = 0;
}

/// Replace all floating-point fields with `f64::NAN` or `f64::INFINITY`.
fn inject_nan(cmd: &mut Command) {
    // Alternate NaN and Inf across joints for variety.
    for (i, js) in cmd.joint_states.iter_mut().enumerate() {
        if i % 2 == 0 {
            js.position = f64::NAN;
            js.velocity = f64::NAN;
            js.effort = f64::NAN;
        } else {
            js.position = f64::INFINITY;
            js.velocity = f64::NEG_INFINITY;
            js.effort = f64::INFINITY;
        }
    }
    for ee in cmd.end_effector_positions.iter_mut() {
        ee.position = [f64::NAN, f64::NAN, f64::NAN];
    }
    cmd.delta_time = f64::NAN;
}

// ---------------------------------------------------------------------------
// Locomotion injection implementations
// ---------------------------------------------------------------------------

use invariant_core::models::command::{FootState, LocomotionState};

/// Ensure the command has a locomotion_state; create a default one if absent.
fn ensure_locomotion_state<'a>(
    cmd: &'a mut Command,
    profile: &RobotProfile,
) -> &'a mut LocomotionState {
    if cmd.locomotion_state.is_none() {
        let max_vel = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_locomotion_velocity)
            .unwrap_or(1.5);
        cmd.locomotion_state = Some(LocomotionState {
            base_velocity: [max_vel * 0.5, 0.0, 0.0],
            heading_rate: 0.0,
            feet: vec![
                FootState {
                    name: "left_foot".into(),
                    position: [-0.15, 0.1, 0.0],
                    contact: true,
                    ground_reaction_force: Some([0.0, 0.0, 400.0]),
                },
                FootState {
                    name: "right_foot".into(),
                    position: [0.15, -0.1, 0.05],
                    contact: false,
                    ground_reaction_force: None,
                },
            ],
            step_length: 0.3,
        });
    }
    cmd.locomotion_state
        .as_mut()
        .expect("locomotion_state was just set above")
}

/// P15 attack: set base velocity to 3× the max locomotion velocity (runaway).
fn inject_locomotion_overspeed(cmd: &mut Command, profile: &RobotProfile) {
    let loco = ensure_locomotion_state(cmd, profile);
    let max_vel = profile
        .locomotion
        .as_ref()
        .map(|l| l.max_locomotion_velocity)
        .unwrap_or(1.5);
    loco.base_velocity = [max_vel * 3.0, 0.0, 0.0];
}

/// P18 attack: set tangential GRF much larger than normal GRF to violate
/// the friction cone constraint (slip).
fn inject_slip_violation(cmd: &mut Command, profile: &RobotProfile) {
    let loco = ensure_locomotion_state(cmd, profile);
    let friction = profile
        .locomotion
        .as_ref()
        .map(|l| l.friction_coefficient)
        .unwrap_or(0.6);
    // Create a foot with tangential force >> friction_coefficient * normal_force.
    // Normal = 400 N, tangential = friction * 400 * 3 = well above the cone.
    let tangential = friction * 400.0 * 3.0;
    for foot in &mut loco.feet {
        foot.contact = true;
        foot.ground_reaction_force = Some([tangential, 0.0, 400.0]);
    }
}

/// P16 attack: set swing foot height to 0 (on the ground) or negative,
/// violating the minimum foot clearance (trip).
fn inject_foot_clearance_violation(cmd: &mut Command) {
    if cmd.locomotion_state.is_none() {
        cmd.locomotion_state = Some(LocomotionState {
            base_velocity: [0.5, 0.0, 0.0],
            heading_rate: 0.0,
            feet: vec![
                FootState {
                    name: "left_foot".into(),
                    position: [-0.15, 0.1, 0.0],
                    contact: true,
                    ground_reaction_force: Some([0.0, 0.0, 400.0]),
                },
                FootState {
                    name: "right_foot".into(),
                    position: [0.15, -0.1, -0.01], // below ground!
                    contact: false,
                    ground_reaction_force: None,
                },
            ],
            step_length: 0.3,
        });
    } else if let Some(loco) = cmd.locomotion_state.as_mut() {
        // Set all non-contact feet to zero clearance.
        for foot in &mut loco.feet {
            if !foot.contact {
                foot.position[2] = -0.01; // below ground
            }
        }
        // Ensure at least one foot is in swing phase.
        if loco.feet.iter().all(|f| f.contact) {
            if let Some(foot) = loco.feet.last_mut() {
                foot.contact = false;
                foot.position[2] = -0.01;
            }
        }
    }
}

/// P16 stomp attack: set swing foot height to 3× max_step_height.
///
/// A foot raised excessively high will slam down with dangerous force. This
/// exercises the upper-bound check.
fn inject_stomp_violation(cmd: &mut Command, profile: &RobotProfile) {
    let max_height = profile
        .locomotion
        .as_ref()
        .map(|l| l.max_step_height)
        .unwrap_or(0.5);
    let stomp_height = max_height * 3.0;

    if cmd.locomotion_state.is_none() {
        cmd.locomotion_state = Some(LocomotionState {
            base_velocity: [0.5, 0.0, 0.0],
            heading_rate: 0.0,
            feet: vec![
                FootState {
                    name: "left_foot".into(),
                    position: [-0.15, 0.1, 0.0],
                    contact: true,
                    ground_reaction_force: Some([0.0, 0.0, 400.0]),
                },
                FootState {
                    name: "right_foot".into(),
                    position: [0.15, -0.1, stomp_height],
                    contact: false,
                    ground_reaction_force: None,
                },
            ],
            step_length: 0.3,
        });
    } else if let Some(loco) = cmd.locomotion_state.as_mut() {
        // Set all non-contact feet to excessive height.
        for foot in &mut loco.feet {
            if !foot.contact {
                foot.position[2] = stomp_height;
            }
        }
        // Ensure at least one foot is in swing phase.
        if loco.feet.iter().all(|f| f.contact) {
            if let Some(foot) = loco.feet.last_mut() {
                foot.contact = false;
                foot.position[2] = stomp_height;
            }
        }
    }
}

/// P19 attack: set step length to 3× the max (overextension leading to fall).
fn inject_step_overextension(cmd: &mut Command, profile: &RobotProfile) {
    let loco = ensure_locomotion_state(cmd, profile);
    let max_step = profile
        .locomotion
        .as_ref()
        .map(|l| l.max_step_length)
        .unwrap_or(0.6);
    loco.step_length = max_step * 3.0;
}

/// P20 attack: set heading rate to 5× max (spinning out of control).
fn inject_heading_spinout(cmd: &mut Command, profile: &RobotProfile) {
    let loco = ensure_locomotion_state(cmd, profile);
    let max_heading = profile
        .locomotion
        .as_ref()
        .map(|l| l.max_heading_rate)
        .unwrap_or(1.0);
    loco.heading_rate = max_heading * 5.0;
}

/// P17 attack: set ground reaction force to 5× max (stomping).
fn inject_ground_reaction_spike(cmd: &mut Command, profile: &RobotProfile) {
    let loco = ensure_locomotion_state(cmd, profile);
    let max_grf = profile
        .locomotion
        .as_ref()
        .map(|l| l.max_ground_reaction_force)
        .unwrap_or(800.0);
    for foot in &mut loco.feet {
        foot.contact = true;
        foot.ground_reaction_force = Some([0.0, 0.0, max_grf * 5.0]);
    }
}

// ---------------------------------------------------------------------------
// Environmental injection helpers
// ---------------------------------------------------------------------------

use invariant_core::models::command::{ActuatorTemperature, EnvironmentState};

/// Ensure the command has an `EnvironmentState`, creating an empty one if absent.
fn ensure_environment_state(cmd: &mut Command) -> &mut EnvironmentState {
    if cmd.environment_state.is_none() {
        cmd.environment_state = Some(EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        });
    }
    cmd.environment_state
        .as_mut()
        .expect("environment_state was just set above")
}

/// P21 attack: set IMU pitch to 2× the max safe pitch (terrain incline).
fn inject_terrain_incline(cmd: &mut Command, profile: &RobotProfile) {
    let env = ensure_environment_state(cmd);
    let max_pitch = profile
        .environment
        .as_ref()
        .map(|e| e.max_safe_pitch_rad)
        .unwrap_or(0.2618);
    env.imu_pitch_rad = Some(max_pitch * 2.0);
}

/// P22 attack: set all actuator temperatures to 1.5× max operating temperature.
fn inject_temperature_spike(cmd: &mut Command, profile: &RobotProfile) {
    let max_temp = profile
        .environment
        .as_ref()
        .map(|e| e.max_operating_temperature_c)
        .unwrap_or(80.0);
    let temps: Vec<ActuatorTemperature> = profile
        .joints
        .iter()
        .map(|j| ActuatorTemperature {
            joint_name: j.name.clone(),
            temperature_celsius: max_temp * 1.5,
        })
        .collect();
    let env = ensure_environment_state(cmd);
    env.actuator_temperatures = temps;
}

/// P23 attack: set battery percentage to 0% (well below any critical threshold).
fn inject_battery_drain(cmd: &mut Command) {
    let env = ensure_environment_state(cmd);
    env.battery_percentage = Some(0.0);
}

/// P24 attack: set communication latency to 5× max acceptable latency.
fn inject_latency_spike(cmd: &mut Command, profile: &RobotProfile) {
    let env = ensure_environment_state(cmd);
    let max_lat = profile
        .environment
        .as_ref()
        .map(|e| e.max_latency_ms)
        .unwrap_or(100.0);
    env.communication_latency_ms = Some(max_lat * 5.0);
}

/// P25 attack: engage the hardware emergency stop.
fn inject_estop_engage(cmd: &mut Command) {
    let env = ensure_environment_state(cmd);
    env.e_stop_engaged = Some(true);
}

// ---------------------------------------------------------------------------
// Manipulation adversarial injections (P10–P14)
// ---------------------------------------------------------------------------

use invariant_core::models::profile::ProximityZone;

/// P10 attack: place end-effector inside the tightest proximity zone and
/// set joint velocities to 3× the proximity-scaled limit.
fn inject_proximity_overspeed(cmd: &mut Command, profile: &RobotProfile) {
    // Find the proximity zone with the smallest velocity_scale (most restrictive).
    let zone = profile.proximity_zones.iter().min_by(|a, b| {
        let scale_a = match a {
            ProximityZone::Sphere { velocity_scale, .. } => *velocity_scale,
            _ => 1.0,
        };
        let scale_b = match b {
            ProximityZone::Sphere { velocity_scale, .. } => *velocity_scale,
            _ => 1.0,
        };
        scale_a
            .partial_cmp(&scale_b)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let Some(zone) = zone else { return };

    let (center, velocity_scale) = match zone {
        ProximityZone::Sphere {
            center,
            velocity_scale,
            ..
        } => (*center, *velocity_scale),
        _ => return,
    };

    // Place an EE at the zone center to trigger proximity detection.
    if cmd.end_effector_positions.is_empty() {
        cmd.end_effector_positions
            .push(invariant_core::models::command::EndEffectorPosition {
                name: "proximity_ee".to_owned(),
                position: center,
            });
    } else {
        cmd.end_effector_positions[0].position = center;
    }

    // Set all joint velocities to 3× the proximity-scaled limit.
    for (js, jdef) in cmd.joint_states.iter_mut().zip(profile.joints.iter()) {
        let scaled_limit = jdef.max_velocity * velocity_scale * profile.global_velocity_scale;
        js.velocity = scaled_limit * 3.0;
    }
}

/// P11 attack: set end-effector force to 3× max_force_n.
fn inject_force_overload(cmd: &mut Command, profile: &RobotProfile) {
    use invariant_core::models::command::EndEffectorForce;
    let max_force = profile
        .end_effectors
        .first()
        .map(|e| e.max_force_n)
        .unwrap_or(100.0);
    let force_val = max_force * 3.0;
    let ee_name = profile
        .end_effectors
        .first()
        .map(|e| e.name.clone())
        .unwrap_or_else(|| "gripper".to_owned());
    // Replace or insert end-effector force data.
    cmd.end_effector_forces = vec![EndEffectorForce {
        name: ee_name,
        force: [force_val, 0.0, 0.0],
        torque: [0.0, 0.0, 0.0],
        grasp_force: None,
    }];
}

/// P12 attack: set grasp force to 3× max_grasp_force_n.
fn inject_grasp_force_violation(cmd: &mut Command, profile: &RobotProfile) {
    use invariant_core::models::command::EndEffectorForce;
    let max_grasp = profile
        .end_effectors
        .first()
        .map(|e| e.max_grasp_force_n)
        .unwrap_or(100.0);
    let ee_name = profile
        .end_effectors
        .first()
        .map(|e| e.name.clone())
        .unwrap_or_else(|| "gripper".to_owned());
    cmd.end_effector_forces = vec![EndEffectorForce {
        name: ee_name,
        force: [0.0, 0.0, 0.0],
        torque: [0.0, 0.0, 0.0],
        grasp_force: Some(max_grasp * 3.0),
    }];
}

/// P14 attack: set payload to 3× max_payload_kg.
fn inject_payload_overload(cmd: &mut Command, profile: &RobotProfile) {
    use invariant_core::models::command::EndEffectorForce;
    let max_payload = profile
        .end_effectors
        .first()
        .map(|e| e.max_payload_kg)
        .unwrap_or(10.0);
    let ee_name = profile
        .end_effectors
        .first()
        .map(|e| e.name.clone())
        .unwrap_or_else(|| "gripper".to_owned());
    cmd.estimated_payload_kg = Some(max_payload * 3.0);
    // Also need end_effector_forces for the check to find a matching config.
    if cmd.end_effector_forces.is_empty() {
        cmd.end_effector_forces = vec![EndEffectorForce {
            name: ee_name,
            force: [0.0, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }];
    }
}

/// P13 attack: set a large end-effector force that, when compared to a
/// previous command with zero force, will produce a force rate exceeding
/// `max_force_rate_n_per_s`.  This injection must be used on 2+ commands
/// in sequence — the first command establishes a zero-force baseline and
/// the second triggers the rate violation.
///
/// To ensure alternating forces across consecutive commands (so the validator
/// sees a large delta on every other step), odd-sequence commands receive zero
/// force and even-sequence commands receive the large spike force.  The
/// stored `previous_forces` from an odd command is then zero, and the
/// subsequent even command carries the spike — guaranteeing a rate violation
/// from command index 1 onwards in the episode.
fn inject_force_rate_spike(cmd: &mut Command, profile: &RobotProfile) {
    use invariant_core::models::command::EndEffectorForce;
    // Use the profile's max_force_rate_n_per_s to compute a force that,
    // applied over one delta_time step from zero, exceeds the rate limit.
    let max_rate = profile
        .end_effectors
        .first()
        .map(|e| e.max_force_rate_n_per_s)
        .unwrap_or(500.0);
    let ee_name = profile
        .end_effectors
        .first()
        .map(|e| e.name.clone())
        .unwrap_or_else(|| "gripper".to_owned());

    // Alternate: even-sequence → large spike; odd-sequence → zero force.
    // This guarantees a large rate-of-change on every even-indexed command
    // relative to the zero force stored from the previous odd command.
    let force_val = if cmd.sequence.is_multiple_of(2) {
        // Force magnitude = max_rate * delta_time * 3.0 (3× the limit for one step)
        max_rate * cmd.delta_time * 3.0
    } else {
        0.0
    };

    cmd.end_effector_forces = vec![EndEffectorForce {
        name: ee_name,
        force: [force_val, 0.0, 0.0],
        torque: [0.0, 0.0, 0.0],
        grasp_force: None,
    }];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use invariant_core::models::command::{CommandAuthority, JointState};
    use invariant_core::models::profile::WorkspaceBounds;
    use invariant_core::profiles::load_builtin;
    use std::collections::HashMap;

    fn panda() -> RobotProfile {
        load_builtin("franka_panda").expect("franka_panda profile must load")
    }

    /// Build a minimal valid command from the given profile.
    fn make_cmd(profile: &RobotProfile) -> Command {
        use chrono::Utc;

        let joint_states = profile
            .joints
            .iter()
            .map(|j| JointState {
                name: j.name.clone(),
                position: (j.min + j.max) / 2.0,
                velocity: 0.0,
                effort: 0.0,
            })
            .collect();

        let ee_pos = match &profile.workspace {
            WorkspaceBounds::Aabb { min, max } => EndEffectorPosition {
                name: "end_effector".to_owned(),
                position: [
                    (min[0] + max[0]) / 2.0,
                    (min[1] + max[1]) / 2.0,
                    (min[2] + max[2]) / 2.0,
                ],
            },
        };

        Command {
            timestamp: Utc::now(),
            source: "test_agent".to_owned(),
            sequence: 42,
            joint_states,
            delta_time: profile.max_delta_time * 0.5,
            end_effector_positions: vec![ee_pos],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: "dGVzdA==".to_owned(),
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

    // --- list_injections ---

    #[test]
    fn list_injections_contains_all_twenty_seven() {
        let injections = list_injections();
        assert_eq!(injections.len(), 27);
    }

    #[test]
    fn list_injections_contains_velocity_overshoot() {
        assert!(list_injections().contains(&InjectionType::VelocityOvershoot));
    }

    // --- VelocityOvershoot ---

    #[test]
    fn velocity_overshoot_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            let limit = jdef.max_velocity * profile.global_velocity_scale;
            assert!(
                js.velocity > limit,
                "VelocityOvershoot: velocity {:.4} should exceed limit {:.4} for {}",
                js.velocity,
                limit,
                jdef.name
            );
        }
    }

    // --- PositionViolation ---

    #[test]
    fn position_violation_exits_limits() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::PositionViolation, &profile);
        let any_violation = cmd
            .joint_states
            .iter()
            .zip(profile.joints.iter())
            .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max);
        assert!(
            any_violation,
            "PositionViolation must produce out-of-limit positions"
        );
    }

    // --- TorqueSpike ---

    #[test]
    fn torque_spike_exceeds_max_torque() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TorqueSpike, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            assert!(
                js.effort > jdef.max_torque,
                "TorqueSpike: effort {:.2} should exceed max_torque {:.2} for {}",
                js.effort,
                jdef.max_torque,
                jdef.name
            );
        }
    }

    // --- WorkspaceEscape ---

    #[test]
    fn workspace_escape_places_ee_outside_bounds() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        let oob = cmd
            .end_effector_positions
            .iter()
            .any(|ee| match &profile.workspace {
                WorkspaceBounds::Aabb { min, max } => {
                    ee.position[0] > max[0]
                        || ee.position[1] > max[1]
                        || ee.position[2] > max[2]
                        || ee.position[0] < min[0]
                        || ee.position[1] < min[1]
                        || ee.position[2] < min[2]
                }
            });
        assert!(
            oob,
            "WorkspaceEscape must place end-effector outside workspace"
        );
    }

    #[test]
    fn workspace_escape_inserts_ee_when_none_present() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        cmd.end_effector_positions.clear();
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        assert!(!cmd.end_effector_positions.is_empty());
    }

    // --- DeltaTimeViolation ---

    #[test]
    fn delta_time_violation_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::DeltaTimeViolation, &profile);
        assert!(
            cmd.delta_time > profile.max_delta_time,
            "DeltaTimeViolation: delta_time {:.6} should exceed max {:.6}",
            cmd.delta_time,
            profile.max_delta_time
        );
    }

    // --- SelfCollision ---

    #[test]
    fn self_collision_puts_all_ee_at_same_position() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::SelfCollision, &profile);
        assert!(
            cmd.end_effector_positions.len() >= 2,
            "SelfCollision must produce at least 2 end-effectors"
        );
        let first = cmd.end_effector_positions[0].position;
        for ee in &cmd.end_effector_positions {
            assert_eq!(
                ee.position, first,
                "SelfCollision: all end-effectors must share the same position"
            );
        }
    }

    // --- StabilityViolation ---

    #[test]
    fn stability_violation_sets_center_of_mass() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        assert!(cmd.center_of_mass.is_none());
        inject(&mut cmd, InjectionType::StabilityViolation, &profile);
        assert!(
            cmd.center_of_mass.is_some(),
            "StabilityViolation must set center_of_mass"
        );
    }

    // --- AuthorityStrip ---

    #[test]
    fn authority_strip_clears_pca_chain() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        assert!(!cmd.authority.pca_chain.is_empty());
        inject(&mut cmd, InjectionType::AuthorityStrip, &profile);
        assert!(
            cmd.authority.pca_chain.is_empty(),
            "AuthorityStrip must clear pca_chain"
        );
    }

    // --- ReplayAttack ---

    #[test]
    fn replay_attack_resets_sequence_to_zero() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        cmd.sequence = 9999;
        inject(&mut cmd, InjectionType::ReplayAttack, &profile);
        assert_eq!(cmd.sequence, 0, "ReplayAttack must set sequence to 0");
    }

    // --- NanInjection ---

    #[test]
    fn nan_injection_produces_non_finite_values() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::NanInjection, &profile);

        let has_non_finite = cmd.joint_states.iter().any(|js| {
            !js.position.is_finite() || !js.velocity.is_finite() || !js.effort.is_finite()
        });
        assert!(
            has_non_finite,
            "NanInjection must produce non-finite joint values"
        );

        assert!(
            !cmd.delta_time.is_finite(),
            "NanInjection must produce non-finite delta_time"
        );
    }

    #[test]
    fn nan_injection_produces_non_finite_ee_positions() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::NanInjection, &profile);
        let has_non_finite_ee = cmd
            .end_effector_positions
            .iter()
            .any(|ee| ee.position.iter().any(|v| !v.is_finite()));
        assert!(
            has_non_finite_ee,
            "NanInjection must produce non-finite EE positions"
        );
    }

    // --- Serde round-trip for InjectionType ---

    #[test]
    fn injection_type_serde_round_trip() {
        for &inj in list_injections() {
            let json = serde_json::to_string(&inj).unwrap();
            let back: InjectionType = serde_json::from_str(&json).unwrap();
            assert_eq!(inj, back, "serde round-trip failed for {inj:?}");
        }
    }

    // --- inject does not panic on empty joint/ee lists ---

    #[test]
    fn inject_empty_joints_no_panic() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        cmd.joint_states.clear();
        cmd.end_effector_positions.clear();
        // None of these should panic when the command has no joints or EEs.
        for &inj in list_injections() {
            inject(&mut cmd, inj, &profile);
        }
    }

    // --- Locomotion injections ---

    #[test]
    fn locomotion_overspeed_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::LocomotionOverspeed, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let [vx, vy, vz] = loco.base_velocity;
        let speed = (vx * vx + vy * vy + vz * vz).sqrt();
        // Default max is 1.5, injected 3x = 4.5
        assert!(
            speed > 1.5,
            "LocomotionOverspeed: speed {speed:.2} should exceed default max"
        );
    }

    #[test]
    fn slip_violation_produces_friction_cone_violation() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::SlipViolation, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        for foot in &loco.feet {
            if let Some(grf) = &foot.ground_reaction_force {
                let tangential = (grf[0] * grf[0] + grf[1] * grf[1]).sqrt();
                let normal = grf[2];
                if normal > 0.0 {
                    // friction_coefficient default = 0.6
                    // tangential / normal should exceed 0.6
                    assert!(
                        tangential / normal > 0.6,
                        "SlipViolation: tangential/normal ratio {:.2} should exceed friction coefficient",
                        tangential / normal
                    );
                }
            }
        }
    }

    #[test]
    fn foot_clearance_violation_below_ground() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::FootClearanceViolation, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let any_below = loco.feet.iter().any(|f| !f.contact && f.position[2] < 0.0);
        assert!(
            any_below,
            "FootClearanceViolation: at least one swing foot must be below ground"
        );
    }

    // --- StompViolation ---

    #[test]
    fn stomp_violation_above_max_step_height() {
        let profile = panda();
        let max_height = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_height)
            .unwrap_or(0.5);
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::StompViolation, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let any_above = loco
            .feet
            .iter()
            .any(|f| !f.contact && f.position[2] > max_height);
        assert!(
            any_above,
            "StompViolation: at least one swing foot must exceed max_step_height {max_height}"
        );
    }

    #[test]
    fn step_overextension_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::StepOverextension, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        // Default max_step_length = 0.6, injected 3x = 1.8
        assert!(
            loco.step_length > 0.6,
            "StepOverextension: step_length {:.2} should exceed default max",
            loco.step_length
        );
    }

    #[test]
    fn heading_spinout_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::HeadingSpinout, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        // Default max_heading_rate = 1.0, injected 5x = 5.0
        assert!(
            loco.heading_rate.abs() > 1.0,
            "HeadingSpinout: heading_rate {:.2} should exceed default max",
            loco.heading_rate
        );
    }

    #[test]
    fn ground_reaction_spike_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::GroundReactionSpike, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let any_spike = loco.feet.iter().any(|f| {
            if let Some(grf) = &f.ground_reaction_force {
                let norm = (grf[0] * grf[0] + grf[1] * grf[1] + grf[2] * grf[2]).sqrt();
                norm > 800.0 // default max_ground_reaction_force
            } else {
                false
            }
        });
        assert!(
            any_spike,
            "GroundReactionSpike: at least one foot must have GRF > max"
        );
    }

    // --- Environmental injections ---

    #[test]
    fn terrain_incline_exceeds_max_pitch() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TerrainIncline, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        // Default max_safe_pitch_rad = 0.2618, injected 2x = 0.5236
        assert!(
            env.imu_pitch_rad.unwrap() > 0.2618,
            "TerrainIncline: pitch should exceed default max"
        );
    }

    #[test]
    fn temperature_spike_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TemperatureSpike, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        // Default max_operating_temperature_c = 80.0, injected 1.5x = 120.0
        assert!(
            !env.actuator_temperatures.is_empty(),
            "TemperatureSpike: must populate actuator temperatures"
        );
        for temp in &env.actuator_temperatures {
            assert!(
                temp.temperature_celsius > 80.0,
                "TemperatureSpike: temp {:.1} should exceed default max 80°C",
                temp.temperature_celsius
            );
        }
    }

    #[test]
    fn battery_drain_sets_zero() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::BatteryDrain, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        assert_eq!(
            env.battery_percentage,
            Some(0.0),
            "BatteryDrain: battery must be 0%"
        );
    }

    #[test]
    fn latency_spike_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::LatencySpike, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        // Default max_latency_ms = 100.0, injected 5x = 500.0
        assert!(
            env.communication_latency_ms.unwrap() > 100.0,
            "LatencySpike: latency should exceed default max"
        );
    }

    #[test]
    fn estop_engage_sets_true() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::EStopEngage, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        assert_eq!(
            env.e_stop_engaged,
            Some(true),
            "EStopEngage: e_stop must be engaged"
        );
    }

    // -----------------------------------------------------------------------
    // Profile helpers for multi-profile tests
    // -----------------------------------------------------------------------

    fn ur10() -> RobotProfile {
        load_builtin("ur10").expect("ur10 profile must load")
    }

    fn quadruped() -> RobotProfile {
        load_builtin("quadruped_12dof").expect("quadruped_12dof profile must load")
    }

    fn humanoid() -> RobotProfile {
        load_builtin("humanoid_28dof").expect("humanoid_28dof profile must load")
    }

    fn haas_cell() -> RobotProfile {
        load_builtin("ur10e_cnc_tending").expect("ur10e_cnc_tending profile must load")
    }

    // -----------------------------------------------------------------------
    // UR10 injection tests
    // -----------------------------------------------------------------------

    #[test]
    fn ur10_velocity_overshoot_exceeds_max() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            let limit = jdef.max_velocity * profile.global_velocity_scale;
            assert!(
                js.velocity > limit,
                "ur10 VelocityOvershoot: velocity {:.4} should exceed limit {:.4} for {}",
                js.velocity,
                limit,
                jdef.name
            );
        }
    }

    #[test]
    fn ur10_position_violation_exits_limits() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::PositionViolation, &profile);
        let any_violation = cmd
            .joint_states
            .iter()
            .zip(profile.joints.iter())
            .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max);
        assert!(
            any_violation,
            "ur10 PositionViolation must produce out-of-limit positions"
        );
    }

    #[test]
    fn ur10_torque_spike_exceeds_max() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TorqueSpike, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            assert!(
                js.effort > jdef.max_torque,
                "ur10 TorqueSpike: effort {:.2} should exceed max_torque {:.2} for {}",
                js.effort,
                jdef.max_torque,
                jdef.name
            );
        }
    }

    #[test]
    fn ur10_workspace_escape_outside_bounds() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        let oob = cmd
            .end_effector_positions
            .iter()
            .any(|ee| match &profile.workspace {
                WorkspaceBounds::Aabb { min, max } => {
                    ee.position[0] > max[0]
                        || ee.position[1] > max[1]
                        || ee.position[2] > max[2]
                        || ee.position[0] < min[0]
                        || ee.position[1] < min[1]
                        || ee.position[2] < min[2]
                }
            });
        assert!(oob, "ur10 WorkspaceEscape must place EE outside workspace");
    }

    #[test]
    fn ur10_delta_time_violation_exceeds_max() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::DeltaTimeViolation, &profile);
        assert!(
            cmd.delta_time > profile.max_delta_time,
            "ur10 DeltaTimeViolation: delta_time {:.6} should exceed max {:.6}",
            cmd.delta_time,
            profile.max_delta_time
        );
    }

    #[test]
    fn ur10_self_collision_same_position() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::SelfCollision, &profile);
        assert!(
            cmd.end_effector_positions.len() >= 2,
            "ur10 SelfCollision must produce at least 2 end-effectors"
        );
        let first = cmd.end_effector_positions[0].position;
        for ee in &cmd.end_effector_positions {
            assert_eq!(
                ee.position, first,
                "ur10 SelfCollision: all EEs must share the same position"
            );
        }
    }

    #[test]
    fn ur10_authority_strip_clears_chain() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        assert!(!cmd.authority.pca_chain.is_empty());
        inject(&mut cmd, InjectionType::AuthorityStrip, &profile);
        assert!(
            cmd.authority.pca_chain.is_empty(),
            "ur10 AuthorityStrip must clear pca_chain"
        );
    }

    #[test]
    fn ur10_replay_attack_resets_sequence() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        cmd.sequence = 9999;
        inject(&mut cmd, InjectionType::ReplayAttack, &profile);
        assert_eq!(cmd.sequence, 0, "ur10 ReplayAttack must set sequence to 0");
    }

    #[test]
    fn ur10_nan_injection_non_finite() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::NanInjection, &profile);
        let has_non_finite = cmd.joint_states.iter().any(|js| {
            !js.position.is_finite() || !js.velocity.is_finite() || !js.effort.is_finite()
        });
        assert!(
            has_non_finite,
            "ur10 NanInjection must produce non-finite joint values"
        );
        assert!(
            !cmd.delta_time.is_finite(),
            "ur10 NanInjection must produce non-finite delta_time"
        );
    }

    #[test]
    fn ur10_stability_violation_sets_com() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        assert!(cmd.center_of_mass.is_none());
        inject(&mut cmd, InjectionType::StabilityViolation, &profile);
        assert!(
            cmd.center_of_mass.is_some(),
            "ur10 StabilityViolation must set center_of_mass"
        );
    }

    #[test]
    fn ur10_all_injections_no_panic() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        for &inj in list_injections() {
            inject(&mut cmd, inj, &profile);
        }
    }

    #[test]
    fn ur10_workspace_escape_inserts_ee_when_empty() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        cmd.end_effector_positions.clear();
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        assert!(
            !cmd.end_effector_positions.is_empty(),
            "ur10 WorkspaceEscape must insert an EE when none present"
        );
    }

    #[test]
    fn ur10_locomotion_overspeed() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::LocomotionOverspeed, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let [vx, vy, vz] = loco.base_velocity;
        let speed = (vx * vx + vy * vy + vz * vz).sqrt();
        // No locomotion config on ur10; default max_vel = 1.5, injected 3× = 4.5
        assert!(
            speed > 1.5,
            "ur10 LocomotionOverspeed: speed {speed:.2} should exceed default max 1.5"
        );
    }

    #[test]
    fn ur10_terrain_incline() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TerrainIncline, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        // No environment config on ur10; default max_pitch = 0.2618, injected 2× = 0.5236
        assert!(
            env.imu_pitch_rad.unwrap() > 0.2618,
            "ur10 TerrainIncline: pitch should exceed default max 0.2618"
        );
    }

    #[test]
    fn ur10_battery_drain() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::BatteryDrain, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        assert_eq!(
            env.battery_percentage,
            Some(0.0),
            "ur10 BatteryDrain: battery must be 0%"
        );
    }

    // -----------------------------------------------------------------------
    // Quadruped injection tests
    // -----------------------------------------------------------------------

    #[test]
    fn quadruped_velocity_overshoot_exceeds_max() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            let limit = jdef.max_velocity * profile.global_velocity_scale;
            assert!(
                js.velocity > limit,
                "quadruped VelocityOvershoot: velocity {:.4} should exceed limit {:.4} for {}",
                js.velocity,
                limit,
                jdef.name
            );
        }
    }

    #[test]
    fn quadruped_position_violation_exits_limits() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::PositionViolation, &profile);
        let any_violation = cmd
            .joint_states
            .iter()
            .zip(profile.joints.iter())
            .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max);
        assert!(
            any_violation,
            "quadruped PositionViolation must produce out-of-limit positions"
        );
    }

    #[test]
    fn quadruped_torque_spike_exceeds_max() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TorqueSpike, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            assert!(
                js.effort > jdef.max_torque,
                "quadruped TorqueSpike: effort {:.2} should exceed max_torque {:.2} for {}",
                js.effort,
                jdef.max_torque,
                jdef.name
            );
        }
    }

    #[test]
    fn quadruped_workspace_escape_outside_bounds() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        let oob = cmd
            .end_effector_positions
            .iter()
            .any(|ee| match &profile.workspace {
                WorkspaceBounds::Aabb { min, max } => {
                    ee.position[0] > max[0]
                        || ee.position[1] > max[1]
                        || ee.position[2] > max[2]
                        || ee.position[0] < min[0]
                        || ee.position[1] < min[1]
                        || ee.position[2] < min[2]
                }
            });
        assert!(
            oob,
            "quadruped WorkspaceEscape must place EE outside workspace"
        );
    }

    #[test]
    fn quadruped_delta_time_violation_exceeds_max() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::DeltaTimeViolation, &profile);
        assert!(
            cmd.delta_time > profile.max_delta_time,
            "quadruped DeltaTimeViolation: delta_time {:.6} should exceed max {:.6}",
            cmd.delta_time,
            profile.max_delta_time
        );
    }

    #[test]
    fn quadruped_authority_strip_clears_chain() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        assert!(!cmd.authority.pca_chain.is_empty());
        inject(&mut cmd, InjectionType::AuthorityStrip, &profile);
        assert!(
            cmd.authority.pca_chain.is_empty(),
            "quadruped AuthorityStrip must clear pca_chain"
        );
    }

    #[test]
    fn quadruped_replay_attack_resets_sequence() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        cmd.sequence = 9999;
        inject(&mut cmd, InjectionType::ReplayAttack, &profile);
        assert_eq!(
            cmd.sequence, 0,
            "quadruped ReplayAttack must set sequence to 0"
        );
    }

    #[test]
    fn quadruped_nan_injection_non_finite() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::NanInjection, &profile);
        let has_non_finite = cmd.joint_states.iter().any(|js| {
            !js.position.is_finite() || !js.velocity.is_finite() || !js.effort.is_finite()
        });
        assert!(
            has_non_finite,
            "quadruped NanInjection must produce non-finite joint values"
        );
        assert!(
            !cmd.delta_time.is_finite(),
            "quadruped NanInjection must produce non-finite delta_time"
        );
    }

    #[test]
    fn quadruped_all_injections_no_panic() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        for &inj in list_injections() {
            inject(&mut cmd, inj, &profile);
        }
    }

    #[test]
    fn quadruped_locomotion_overspeed_exceeds_max() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::LocomotionOverspeed, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let [vx, vy, vz] = loco.base_velocity;
        let speed = (vx * vx + vy * vy + vz * vz).sqrt();
        // quadruped has no locomotion config; default max_vel = 1.5, injected 3× = 4.5
        let max_vel = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_locomotion_velocity)
            .unwrap_or(1.5);
        assert!(
            speed > max_vel,
            "quadruped LocomotionOverspeed: speed {speed:.2} should exceed max {max_vel:.2}"
        );
    }

    #[test]
    fn quadruped_slip_violation_friction_cone() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::SlipViolation, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let friction = profile
            .locomotion
            .as_ref()
            .map(|l| l.friction_coefficient)
            .unwrap_or(0.6);
        for foot in &loco.feet {
            if let Some(grf) = &foot.ground_reaction_force {
                let tangential = (grf[0] * grf[0] + grf[1] * grf[1]).sqrt();
                let normal = grf[2];
                if normal > 0.0 {
                    assert!(
                        tangential / normal > friction,
                        "quadruped SlipViolation: tangential/normal {:.2} should exceed friction {:.2}",
                        tangential / normal,
                        friction
                    );
                }
            }
        }
    }

    #[test]
    fn quadruped_foot_clearance_below_ground() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::FootClearanceViolation, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let any_below = loco.feet.iter().any(|f| !f.contact && f.position[2] < 0.0);
        assert!(
            any_below,
            "quadruped FootClearanceViolation: at least one swing foot must be below ground"
        );
    }

    #[test]
    fn quadruped_stomp_violation_above_max_step_height() {
        let profile = quadruped();
        let max_height = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_height)
            .unwrap_or(0.5);
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::StompViolation, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let any_above = loco
            .feet
            .iter()
            .any(|f| !f.contact && f.position[2] > max_height);
        assert!(
            any_above,
            "quadruped StompViolation: at least one swing foot must exceed max_step_height {max_height}"
        );
    }

    #[test]
    fn quadruped_step_overextension_exceeds_max() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::StepOverextension, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let max_step = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_length)
            .unwrap_or(0.6);
        assert!(
            loco.step_length > max_step,
            "quadruped StepOverextension: step_length {:.2} should exceed max {:.2}",
            loco.step_length,
            max_step
        );
    }

    #[test]
    fn quadruped_heading_spinout_exceeds_max() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::HeadingSpinout, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let max_heading = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_heading_rate)
            .unwrap_or(1.0);
        assert!(
            loco.heading_rate.abs() > max_heading,
            "quadruped HeadingSpinout: heading_rate {:.2} should exceed max {:.2}",
            loco.heading_rate,
            max_heading
        );
    }

    #[test]
    fn quadruped_ground_reaction_spike() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::GroundReactionSpike, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let max_grf = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_ground_reaction_force)
            .unwrap_or(800.0);
        let any_spike = loco.feet.iter().any(|f| {
            if let Some(grf) = &f.ground_reaction_force {
                let norm = (grf[0] * grf[0] + grf[1] * grf[1] + grf[2] * grf[2]).sqrt();
                norm > max_grf
            } else {
                false
            }
        });
        assert!(
            any_spike,
            "quadruped GroundReactionSpike: at least one foot must have GRF > max {max_grf:.1}"
        );
    }

    #[test]
    fn quadruped_terrain_incline() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TerrainIncline, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        let max_pitch = profile
            .environment
            .as_ref()
            .map(|e| e.max_safe_pitch_rad)
            .unwrap_or(0.2618);
        assert!(
            env.imu_pitch_rad.unwrap() > max_pitch,
            "quadruped TerrainIncline: pitch should exceed max {max_pitch:.4}"
        );
    }

    #[test]
    fn quadruped_temperature_spike() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TemperatureSpike, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        let max_temp = profile
            .environment
            .as_ref()
            .map(|e| e.max_operating_temperature_c)
            .unwrap_or(80.0);
        assert!(
            !env.actuator_temperatures.is_empty(),
            "quadruped TemperatureSpike: must populate actuator temperatures"
        );
        for temp in &env.actuator_temperatures {
            assert!(
                temp.temperature_celsius > max_temp,
                "quadruped TemperatureSpike: temp {:.1} should exceed max {max_temp:.1}",
                temp.temperature_celsius
            );
        }
    }

    #[test]
    fn quadruped_battery_drain() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::BatteryDrain, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        assert_eq!(
            env.battery_percentage,
            Some(0.0),
            "quadruped BatteryDrain: battery must be 0%"
        );
    }

    #[test]
    fn quadruped_latency_spike() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::LatencySpike, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        let max_lat = profile
            .environment
            .as_ref()
            .map(|e| e.max_latency_ms)
            .unwrap_or(100.0);
        assert!(
            env.communication_latency_ms.unwrap() > max_lat,
            "quadruped LatencySpike: latency should exceed max {max_lat:.1}"
        );
    }

    #[test]
    fn quadruped_estop_engage() {
        let profile = quadruped();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::EStopEngage, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        assert_eq!(
            env.e_stop_engaged,
            Some(true),
            "quadruped EStopEngage: e_stop must be engaged"
        );
    }

    // -----------------------------------------------------------------------
    // Humanoid injection tests
    // -----------------------------------------------------------------------

    #[test]
    fn humanoid_velocity_overshoot_exceeds_max() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            let limit = jdef.max_velocity * profile.global_velocity_scale;
            assert!(
                js.velocity > limit,
                "humanoid VelocityOvershoot: velocity {:.4} should exceed limit {:.4} for {}",
                js.velocity,
                limit,
                jdef.name
            );
        }
    }

    #[test]
    fn humanoid_position_violation_exits_limits() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::PositionViolation, &profile);
        let any_violation = cmd
            .joint_states
            .iter()
            .zip(profile.joints.iter())
            .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max);
        assert!(
            any_violation,
            "humanoid PositionViolation must produce out-of-limit positions"
        );
    }

    #[test]
    fn humanoid_torque_spike_exceeds_max() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TorqueSpike, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            assert!(
                js.effort > jdef.max_torque,
                "humanoid TorqueSpike: effort {:.2} should exceed max_torque {:.2} for {}",
                js.effort,
                jdef.max_torque,
                jdef.name
            );
        }
    }

    #[test]
    fn humanoid_workspace_escape_outside_bounds() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        let oob = cmd
            .end_effector_positions
            .iter()
            .any(|ee| match &profile.workspace {
                WorkspaceBounds::Aabb { min, max } => {
                    ee.position[0] > max[0]
                        || ee.position[1] > max[1]
                        || ee.position[2] > max[2]
                        || ee.position[0] < min[0]
                        || ee.position[1] < min[1]
                        || ee.position[2] < min[2]
                }
            });
        assert!(
            oob,
            "humanoid WorkspaceEscape must place EE outside workspace"
        );
    }

    #[test]
    fn humanoid_delta_time_violation_exceeds_max() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::DeltaTimeViolation, &profile);
        assert!(
            cmd.delta_time > profile.max_delta_time,
            "humanoid DeltaTimeViolation: delta_time {:.6} should exceed max {:.6}",
            cmd.delta_time,
            profile.max_delta_time
        );
    }

    #[test]
    fn humanoid_self_collision_same_position() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::SelfCollision, &profile);
        assert!(
            cmd.end_effector_positions.len() >= 2,
            "humanoid SelfCollision must produce at least 2 end-effectors"
        );
        let first = cmd.end_effector_positions[0].position;
        for ee in &cmd.end_effector_positions {
            assert_eq!(
                ee.position, first,
                "humanoid SelfCollision: all EEs must share the same position"
            );
        }
    }

    #[test]
    fn humanoid_stability_violation_sets_com() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        assert!(cmd.center_of_mass.is_none());
        inject(&mut cmd, InjectionType::StabilityViolation, &profile);
        assert!(
            cmd.center_of_mass.is_some(),
            "humanoid StabilityViolation must set center_of_mass"
        );
    }

    #[test]
    fn humanoid_authority_strip_clears_chain() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        assert!(!cmd.authority.pca_chain.is_empty());
        inject(&mut cmd, InjectionType::AuthorityStrip, &profile);
        assert!(
            cmd.authority.pca_chain.is_empty(),
            "humanoid AuthorityStrip must clear pca_chain"
        );
    }

    #[test]
    fn humanoid_replay_attack_resets_sequence() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        cmd.sequence = 9999;
        inject(&mut cmd, InjectionType::ReplayAttack, &profile);
        assert_eq!(
            cmd.sequence, 0,
            "humanoid ReplayAttack must set sequence to 0"
        );
    }

    #[test]
    fn humanoid_nan_injection_non_finite() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::NanInjection, &profile);
        let has_non_finite = cmd.joint_states.iter().any(|js| {
            !js.position.is_finite() || !js.velocity.is_finite() || !js.effort.is_finite()
        });
        assert!(
            has_non_finite,
            "humanoid NanInjection must produce non-finite joint values"
        );
        assert!(
            !cmd.delta_time.is_finite(),
            "humanoid NanInjection must produce non-finite delta_time"
        );
    }

    #[test]
    fn humanoid_all_injections_no_panic() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        for &inj in list_injections() {
            inject(&mut cmd, inj, &profile);
        }
    }

    #[test]
    fn humanoid_locomotion_overspeed_exceeds_max() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::LocomotionOverspeed, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let [vx, vy, vz] = loco.base_velocity;
        let speed = (vx * vx + vy * vy + vz * vz).sqrt();
        let max_vel = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_locomotion_velocity)
            .unwrap_or(1.5);
        assert!(
            speed > max_vel,
            "humanoid LocomotionOverspeed: speed {speed:.2} should exceed max {max_vel:.2}"
        );
    }

    #[test]
    fn humanoid_slip_violation_friction_cone() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::SlipViolation, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let friction = profile
            .locomotion
            .as_ref()
            .map(|l| l.friction_coefficient)
            .unwrap_or(0.6);
        for foot in &loco.feet {
            if let Some(grf) = &foot.ground_reaction_force {
                let tangential = (grf[0] * grf[0] + grf[1] * grf[1]).sqrt();
                let normal = grf[2];
                if normal > 0.0 {
                    assert!(
                        tangential / normal > friction,
                        "humanoid SlipViolation: tangential/normal {:.2} should exceed friction {:.2}",
                        tangential / normal,
                        friction
                    );
                }
            }
        }
    }

    #[test]
    fn humanoid_foot_clearance_below_ground() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::FootClearanceViolation, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let any_below = loco.feet.iter().any(|f| !f.contact && f.position[2] < 0.0);
        assert!(
            any_below,
            "humanoid FootClearanceViolation: at least one swing foot must be below ground"
        );
    }

    #[test]
    fn humanoid_stomp_violation_above_max_step_height() {
        let profile = humanoid();
        let max_height = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_height)
            .unwrap_or(0.5);
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::StompViolation, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let any_above = loco
            .feet
            .iter()
            .any(|f| !f.contact && f.position[2] > max_height);
        assert!(
            any_above,
            "humanoid StompViolation: at least one swing foot must exceed max_step_height {max_height}"
        );
    }

    #[test]
    fn humanoid_step_overextension_exceeds_max() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::StepOverextension, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let max_step = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_step_length)
            .unwrap_or(0.6);
        assert!(
            loco.step_length > max_step,
            "humanoid StepOverextension: step_length {:.2} should exceed max {:.2}",
            loco.step_length,
            max_step
        );
    }

    #[test]
    fn humanoid_heading_spinout_exceeds_max() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::HeadingSpinout, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let max_heading = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_heading_rate)
            .unwrap_or(1.0);
        assert!(
            loco.heading_rate.abs() > max_heading,
            "humanoid HeadingSpinout: heading_rate {:.2} should exceed max {:.2}",
            loco.heading_rate,
            max_heading
        );
    }

    #[test]
    fn humanoid_ground_reaction_spike() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::GroundReactionSpike, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let max_grf = profile
            .locomotion
            .as_ref()
            .map(|l| l.max_ground_reaction_force)
            .unwrap_or(800.0);
        let any_spike = loco.feet.iter().any(|f| {
            if let Some(grf) = &f.ground_reaction_force {
                let norm = (grf[0] * grf[0] + grf[1] * grf[1] + grf[2] * grf[2]).sqrt();
                norm > max_grf
            } else {
                false
            }
        });
        assert!(
            any_spike,
            "humanoid GroundReactionSpike: at least one foot must have GRF > max {max_grf:.1}"
        );
    }

    #[test]
    fn humanoid_terrain_incline() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TerrainIncline, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        let max_pitch = profile
            .environment
            .as_ref()
            .map(|e| e.max_safe_pitch_rad)
            .unwrap_or(0.2618);
        assert!(
            env.imu_pitch_rad.unwrap() > max_pitch,
            "humanoid TerrainIncline: pitch should exceed max {max_pitch:.4}"
        );
    }

    #[test]
    fn humanoid_temperature_spike() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TemperatureSpike, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        let max_temp = profile
            .environment
            .as_ref()
            .map(|e| e.max_operating_temperature_c)
            .unwrap_or(80.0);
        assert!(
            !env.actuator_temperatures.is_empty(),
            "humanoid TemperatureSpike: must populate actuator temperatures"
        );
        for temp in &env.actuator_temperatures {
            assert!(
                temp.temperature_celsius > max_temp,
                "humanoid TemperatureSpike: temp {:.1} should exceed max {max_temp:.1}",
                temp.temperature_celsius
            );
        }
    }

    #[test]
    fn humanoid_latency_spike() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::LatencySpike, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        let max_lat = profile
            .environment
            .as_ref()
            .map(|e| e.max_latency_ms)
            .unwrap_or(100.0);
        assert!(
            env.communication_latency_ms.unwrap() > max_lat,
            "humanoid LatencySpike: latency should exceed max {max_lat:.1}"
        );
    }

    // -----------------------------------------------------------------------
    // UR10e CNC Tending (haas_cell) injection tests
    // -----------------------------------------------------------------------

    #[test]
    fn haas_cell_velocity_overshoot_exceeds_max() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            let limit = jdef.max_velocity * profile.global_velocity_scale;
            assert!(
                js.velocity > limit,
                "haas_cell VelocityOvershoot: velocity {:.4} should exceed limit {:.4} for {}",
                js.velocity,
                limit,
                jdef.name
            );
        }
    }

    #[test]
    fn haas_cell_position_violation_exits_limits() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::PositionViolation, &profile);
        let any_violation = cmd
            .joint_states
            .iter()
            .zip(profile.joints.iter())
            .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max);
        assert!(
            any_violation,
            "haas_cell PositionViolation must produce out-of-limit positions"
        );
    }

    #[test]
    fn haas_cell_torque_spike_exceeds_max() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TorqueSpike, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            assert!(
                js.effort > jdef.max_torque,
                "haas_cell TorqueSpike: effort {:.2} should exceed max_torque {:.2} for {}",
                js.effort,
                jdef.max_torque,
                jdef.name
            );
        }
    }

    #[test]
    fn haas_cell_workspace_escape_outside_bounds() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        let oob = cmd
            .end_effector_positions
            .iter()
            .any(|ee| match &profile.workspace {
                WorkspaceBounds::Aabb { min, max } => {
                    ee.position[0] > max[0]
                        || ee.position[1] > max[1]
                        || ee.position[2] > max[2]
                        || ee.position[0] < min[0]
                        || ee.position[1] < min[1]
                        || ee.position[2] < min[2]
                }
            });
        assert!(
            oob,
            "haas_cell WorkspaceEscape must place EE outside workspace"
        );
    }

    #[test]
    fn haas_cell_delta_time_violation_exceeds_max() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::DeltaTimeViolation, &profile);
        assert!(
            cmd.delta_time > profile.max_delta_time,
            "haas_cell DeltaTimeViolation: delta_time {:.6} should exceed max {:.6}",
            cmd.delta_time,
            profile.max_delta_time
        );
    }

    #[test]
    fn haas_cell_authority_strip_clears_chain() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        assert!(!cmd.authority.pca_chain.is_empty());
        inject(&mut cmd, InjectionType::AuthorityStrip, &profile);
        assert!(
            cmd.authority.pca_chain.is_empty(),
            "haas_cell AuthorityStrip must clear pca_chain"
        );
    }

    #[test]
    fn haas_cell_nan_injection_non_finite() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::NanInjection, &profile);
        let has_non_finite = cmd.joint_states.iter().any(|js| {
            !js.position.is_finite() || !js.velocity.is_finite() || !js.effort.is_finite()
        });
        assert!(
            has_non_finite,
            "haas_cell NanInjection must produce non-finite joint values"
        );
        assert!(
            !cmd.delta_time.is_finite(),
            "haas_cell NanInjection must produce non-finite delta_time"
        );
    }

    #[test]
    fn haas_cell_all_injections_no_panic() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        for &inj in list_injections() {
            inject(&mut cmd, inj, &profile);
        }
    }

    #[test]
    fn haas_cell_terrain_incline() {
        // ur10e_cnc_tending has environment config with max_safe_pitch_rad = 0.0873
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TerrainIncline, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        let max_pitch = profile
            .environment
            .as_ref()
            .map(|e| e.max_safe_pitch_rad)
            .unwrap_or(0.2618);
        assert!(
            (max_pitch - 0.0873).abs() < 1e-6,
            "haas_cell environment must have max_safe_pitch_rad = 0.0873, got {max_pitch:.4}"
        );
        assert!(
            env.imu_pitch_rad.unwrap() > max_pitch,
            "haas_cell TerrainIncline: pitch {:.4} should exceed max {max_pitch:.4}",
            env.imu_pitch_rad.unwrap()
        );
    }

    #[test]
    fn haas_cell_temperature_spike() {
        // ur10e_cnc_tending has max_operating_temperature_c = 75.0
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TemperatureSpike, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        let max_temp = profile
            .environment
            .as_ref()
            .map(|e| e.max_operating_temperature_c)
            .unwrap_or(80.0);
        assert!(
            (max_temp - 75.0).abs() < 1e-6,
            "haas_cell environment must have max_operating_temperature_c = 75.0, got {max_temp:.1}"
        );
        assert!(
            !env.actuator_temperatures.is_empty(),
            "haas_cell TemperatureSpike: must populate actuator temperatures"
        );
        for temp in &env.actuator_temperatures {
            assert!(
                temp.temperature_celsius > max_temp,
                "haas_cell TemperatureSpike: temp {:.1} should exceed max {max_temp:.1}",
                temp.temperature_celsius
            );
        }
    }

    #[test]
    fn haas_cell_latency_spike() {
        // ur10e_cnc_tending has max_latency_ms = 50.0
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::LatencySpike, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        let max_lat = profile
            .environment
            .as_ref()
            .map(|e| e.max_latency_ms)
            .unwrap_or(100.0);
        assert!(
            (max_lat - 50.0).abs() < 1e-6,
            "haas_cell environment must have max_latency_ms = 50.0, got {max_lat:.1}"
        );
        assert!(
            env.communication_latency_ms.unwrap() > max_lat,
            "haas_cell LatencySpike: latency {:.1} should exceed max {max_lat:.1}",
            env.communication_latency_ms.unwrap()
        );
    }

    #[test]
    fn haas_cell_estop_engage() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::EStopEngage, &profile);
        let env = cmd.environment_state.as_ref().unwrap();
        assert_eq!(
            env.e_stop_engaged,
            Some(true),
            "haas_cell EStopEngage: e_stop must be engaged"
        );
    }

    // -----------------------------------------------------------------------
    // Cross-profile comprehensive tests
    // -----------------------------------------------------------------------

    fn all_profiles() -> Vec<RobotProfile> {
        vec![panda(), ur10(), quadruped(), humanoid(), haas_cell()]
    }

    #[test]
    fn all_profiles_velocity_overshoot_exceeds_max() {
        for profile in all_profiles() {
            let mut cmd = make_cmd(&profile);
            inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                let limit = jdef.max_velocity * profile.global_velocity_scale;
                assert!(
                    js.velocity > limit,
                    "[{}] VelocityOvershoot: velocity {:.4} should exceed limit {:.4} for {}",
                    profile.name,
                    js.velocity,
                    limit,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn all_profiles_position_violation_exits_limits() {
        for profile in all_profiles() {
            let mut cmd = make_cmd(&profile);
            inject(&mut cmd, InjectionType::PositionViolation, &profile);
            let any_violation = cmd
                .joint_states
                .iter()
                .zip(profile.joints.iter())
                .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max);
            assert!(
                any_violation,
                "[{}] PositionViolation must produce out-of-limit positions",
                profile.name
            );
        }
    }

    #[test]
    fn all_profiles_torque_spike_exceeds_max() {
        for profile in all_profiles() {
            let mut cmd = make_cmd(&profile);
            inject(&mut cmd, InjectionType::TorqueSpike, &profile);
            for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
                assert!(
                    js.effort > jdef.max_torque,
                    "[{}] TorqueSpike: effort {:.2} should exceed max_torque {:.2} for {}",
                    profile.name,
                    js.effort,
                    jdef.max_torque,
                    jdef.name
                );
            }
        }
    }

    #[test]
    fn all_profiles_workspace_escape_outside_bounds() {
        for profile in all_profiles() {
            let mut cmd = make_cmd(&profile);
            inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
            let oob = cmd
                .end_effector_positions
                .iter()
                .any(|ee| match &profile.workspace {
                    WorkspaceBounds::Aabb { min, max } => {
                        ee.position[0] > max[0]
                            || ee.position[1] > max[1]
                            || ee.position[2] > max[2]
                            || ee.position[0] < min[0]
                            || ee.position[1] < min[1]
                            || ee.position[2] < min[2]
                    }
                });
            assert!(
                oob,
                "[{}] WorkspaceEscape must place EE outside workspace",
                profile.name
            );
        }
    }

    #[test]
    fn all_profiles_delta_time_violation_exceeds_max() {
        for profile in all_profiles() {
            let mut cmd = make_cmd(&profile);
            inject(&mut cmd, InjectionType::DeltaTimeViolation, &profile);
            assert!(
                cmd.delta_time > profile.max_delta_time,
                "[{}] DeltaTimeViolation: delta_time {:.6} should exceed max {:.6}",
                profile.name,
                cmd.delta_time,
                profile.max_delta_time
            );
        }
    }

    #[test]
    fn all_profiles_authority_strip_clears_chain() {
        for profile in all_profiles() {
            let mut cmd = make_cmd(&profile);
            inject(&mut cmd, InjectionType::AuthorityStrip, &profile);
            assert!(
                cmd.authority.pca_chain.is_empty(),
                "[{}] AuthorityStrip must clear pca_chain",
                profile.name
            );
        }
    }

    #[test]
    fn all_profiles_nan_injection_non_finite() {
        for profile in all_profiles() {
            let mut cmd = make_cmd(&profile);
            inject(&mut cmd, InjectionType::NanInjection, &profile);
            let has_non_finite = cmd.joint_states.iter().any(|js| {
                !js.position.is_finite() || !js.velocity.is_finite() || !js.effort.is_finite()
            });
            assert!(
                has_non_finite,
                "[{}] NanInjection must produce non-finite joint values",
                profile.name
            );
            assert!(
                !cmd.delta_time.is_finite(),
                "[{}] NanInjection must produce non-finite delta_time",
                profile.name
            );
        }
    }

    #[test]
    fn all_profiles_all_injections_no_panic() {
        for profile in all_profiles() {
            let mut cmd = make_cmd(&profile);
            for &inj in list_injections() {
                inject(&mut cmd, inj, &profile);
            }
        }
    }

    // =========================================================================
    // Stability injection precision: COM must be outside support polygon
    // =========================================================================

    #[test]
    fn stability_violation_on_humanoid_com_outside_polygon() {
        // humanoid_28dof has stability config: support_polygon ±0.15×±0.10
        let profile = humanoid();
        assert!(
            profile.stability.is_some(),
            "humanoid must have stability config"
        );
        let stability = profile.stability.as_ref().unwrap();
        assert!(stability.enabled, "humanoid stability must be enabled");

        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::StabilityViolation, &profile);
        let com = cmd.center_of_mass.expect("StabilityViolation must set COM");
        // COM must be outside the support polygon.
        // The polygon is ±0.15 x ±0.10. Projected COM is (com[0], com[1]).
        let inside = com[0].abs() <= 0.15 && com[1].abs() <= 0.10;
        assert!(
            !inside,
            "StabilityViolation COM ({:.3}, {:.3}) must be outside humanoid polygon (±0.15×±0.10)",
            com[0], com[1]
        );
    }

    #[test]
    fn stability_violation_on_quadruped_com_outside_polygon() {
        // quadruped_12dof has stability config: support_polygon ±0.20×±0.12
        let profile = quadruped();
        assert!(
            profile.stability.is_some(),
            "quadruped must have stability config"
        );
        let stability = profile.stability.as_ref().unwrap();
        assert!(stability.enabled, "quadruped stability must be enabled");

        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::StabilityViolation, &profile);
        let com = cmd.center_of_mass.expect("StabilityViolation must set COM");
        let inside = com[0].abs() <= 0.20 && com[1].abs() <= 0.12;
        assert!(
            !inside,
            "StabilityViolation COM ({:.3}, {:.3}) must be outside quadruped polygon (±0.20×±0.12)",
            com[0], com[1]
        );
    }

    // =========================================================================
    // Compound injection: multiple faults applied to same command
    // =========================================================================

    #[test]
    fn compound_velocity_and_authority_both_effective() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        // Apply VelocityOvershoot first
        inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
        // Then apply AuthorityStrip
        inject(&mut cmd, InjectionType::AuthorityStrip, &profile);
        // Both effects should be present
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            let limit = jdef.max_velocity * profile.global_velocity_scale;
            assert!(
                js.velocity > limit,
                "VelocityOvershoot effect must persist after AuthorityStrip"
            );
        }
        assert!(
            cmd.authority.pca_chain.is_empty(),
            "AuthorityStrip effect must be present"
        );
    }

    #[test]
    fn compound_position_and_workspace_both_effective() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::PositionViolation, &profile);
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        // Position violation
        let any_pos_violation = cmd
            .joint_states
            .iter()
            .zip(profile.joints.iter())
            .any(|(js, jdef)| js.position < jdef.min || js.position > jdef.max);
        assert!(any_pos_violation, "PositionViolation must persist");
        // Workspace escape
        let oob = cmd
            .end_effector_positions
            .iter()
            .any(|ee| match &profile.workspace {
                WorkspaceBounds::Aabb { min, max } => {
                    ee.position[0] > max[0]
                        || ee.position[1] > max[1]
                        || ee.position[2] > max[2]
                        || ee.position[0] < min[0]
                        || ee.position[1] < min[1]
                        || ee.position[2] < min[2]
                }
            });
        assert!(oob, "WorkspaceEscape must persist");
    }

    #[test]
    fn compound_nan_and_estop_both_effective() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::NanInjection, &profile);
        inject(&mut cmd, InjectionType::EStopEngage, &profile);
        assert!(!cmd.delta_time.is_finite(), "NaN must persist");
        let env = cmd.environment_state.as_ref().unwrap();
        assert_eq!(env.e_stop_engaged, Some(true), "E-stop must persist");
    }

    // =========================================================================
    // Gap-filling tests
    // =========================================================================

    #[test]
    fn velocity_overshoot_multiplier_is_at_least_3x() {
        // VelocityOvershoot uses 3× max. Verify injected velocity is at least 2.5× limit.
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            let limit = jdef.max_velocity * profile.global_velocity_scale;
            assert!(
                js.velocity >= 2.5 * limit,
                "VelocityOvershoot: velocity {:.4} must be at least 2.5× limit {:.4} for {}",
                js.velocity,
                limit,
                jdef.name
            );
        }
    }

    #[test]
    fn position_violation_alternates_direction() {
        // Panda has 7 joints. Even joints exceed max, odd joints go below min.
        // Verify at least one joint exceeds max and at least one is below min.
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::PositionViolation, &profile);
        let any_above_max = cmd
            .joint_states
            .iter()
            .zip(profile.joints.iter())
            .any(|(js, jdef)| js.position > jdef.max);
        let any_below_min = cmd
            .joint_states
            .iter()
            .zip(profile.joints.iter())
            .any(|(js, jdef)| js.position < jdef.min);
        assert!(
            any_above_max,
            "PositionViolation must push at least one joint above its max"
        );
        assert!(
            any_below_min,
            "PositionViolation must push at least one joint below its min"
        );
    }

    #[test]
    fn torque_spike_multiplier_is_at_least_5x() {
        // TorqueSpike uses 5× max torque. Verify effort is at least 4× max.
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::TorqueSpike, &profile);
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            assert!(
                js.effort >= 4.0 * jdef.max_torque,
                "TorqueSpike: effort {:.2} must be at least 4× max_torque {:.2} for {}",
                js.effort,
                jdef.max_torque,
                jdef.name
            );
        }
    }

    #[test]
    fn workspace_escape_displacement_is_large() {
        // WorkspaceEscape adds 2.0 beyond max. Verify EE exceeds max by at least 1.0.
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        let any_large_displacement =
            cmd.end_effector_positions
                .iter()
                .any(|ee| match &profile.workspace {
                    WorkspaceBounds::Aabb { max, .. } => {
                        ee.position[0] > max[0] + 1.0
                            || ee.position[1] > max[1] + 1.0
                            || ee.position[2] > max[2] + 1.0
                    }
                });
        assert!(
            any_large_displacement,
            "WorkspaceEscape must displace EE by at least 1.0 beyond workspace max"
        );
    }

    #[test]
    fn delta_time_violation_multiplier_is_at_least_2x() {
        // DeltaTimeViolation uses 2× max. Verify delta_time is at least 1.5× max.
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::DeltaTimeViolation, &profile);
        assert!(
            cmd.delta_time >= 1.5 * profile.max_delta_time,
            "DeltaTimeViolation: delta_time {:.6} must be at least 1.5× max {:.6}",
            cmd.delta_time,
            profile.max_delta_time
        );
    }

    #[test]
    fn self_collision_creates_collision_pair_named_ees() {
        use crate::scenario::{ScenarioGenerator, ScenarioType};
        // Use the scenario generator to build a baseline command which includes
        // EEs named after collision-pair links, then apply SelfCollision.
        let profile = panda();
        let authority = invariant_core::models::command::CommandAuthority {
            pca_chain: "dGVzdA==".to_owned(),
            required_ops: vec![],
        };
        let ops = vec![];
        let gen = ScenarioGenerator::new(&profile, ScenarioType::Baseline);
        let mut cmds = gen.generate_commands(1, &authority.pca_chain, &ops);
        let mut cmd = cmds.remove(0);

        // The baseline command includes EEs named after collision-pair links.
        let link_names_in_cmd: std::collections::HashSet<&str> = cmd
            .end_effector_positions
            .iter()
            .map(|ee| ee.name.as_str())
            .collect();
        let any_link_present = profile.collision_pairs.iter().any(|pair| {
            link_names_in_cmd.contains(pair.link_a.as_str())
                || link_names_in_cmd.contains(pair.link_b.as_str())
        });
        assert!(
            any_link_present,
            "Baseline command must include EEs named after collision-pair links before injection"
        );

        inject(&mut cmd, InjectionType::SelfCollision, &profile);

        // After injection all EEs are at origin. Verify link-named EEs are still present.
        let link_names_after: std::collections::HashSet<&str> = cmd
            .end_effector_positions
            .iter()
            .map(|ee| ee.name.as_str())
            .collect();
        let any_link_after = profile.collision_pairs.iter().any(|pair| {
            link_names_after.contains(pair.link_a.as_str())
                || link_names_after.contains(pair.link_b.as_str())
        });
        assert!(
            any_link_after,
            "SelfCollision must preserve EEs named after collision-pair links"
        );
        // And all those EEs must now be at origin.
        for ee in &cmd.end_effector_positions {
            assert_eq!(
                ee.position,
                [0.0, 0.0, 0.0],
                "SelfCollision: EE '{}' must be at origin",
                ee.name
            );
        }
    }

    #[test]
    fn nan_injection_produces_specific_nan_and_inf() {
        // inject_nan sets even-index joints to NaN, odd-index to Inf.
        // Panda has 7 joints so joint 0 has position.is_nan() and joint 1 has
        // velocity.is_infinite().
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::NanInjection, &profile);
        let any_nan_position = cmd.joint_states.iter().any(|js| js.position.is_nan());
        let any_inf_velocity = cmd.joint_states.iter().any(|js| js.velocity.is_infinite());
        assert!(
            any_nan_position,
            "NanInjection must produce at least one joint with NaN position"
        );
        assert!(
            any_inf_velocity,
            "NanInjection must produce at least one joint with infinite velocity"
        );
    }

    #[test]
    fn replay_attack_preserves_other_fields() {
        // ReplayAttack only sets sequence=0. Joint positions/velocities must be unchanged.
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        let original_positions: Vec<f64> = cmd.joint_states.iter().map(|js| js.position).collect();
        let original_velocities: Vec<f64> = cmd.joint_states.iter().map(|js| js.velocity).collect();
        cmd.sequence = 9999;
        inject(&mut cmd, InjectionType::ReplayAttack, &profile);
        assert_eq!(cmd.sequence, 0, "ReplayAttack must set sequence to 0");
        let after_positions: Vec<f64> = cmd.joint_states.iter().map(|js| js.position).collect();
        let after_velocities: Vec<f64> = cmd.joint_states.iter().map(|js| js.velocity).collect();
        assert_eq!(
            original_positions, after_positions,
            "ReplayAttack must not alter joint positions"
        );
        assert_eq!(
            original_velocities, after_velocities,
            "ReplayAttack must not alter joint velocities"
        );
    }

    #[test]
    fn estop_engage_does_not_modify_joint_states() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        let original: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        inject(&mut cmd, InjectionType::EStopEngage, &profile);
        let after: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        assert_eq!(original, after, "EStopEngage must not modify joint_states");
    }

    #[test]
    fn battery_drain_does_not_modify_joint_states() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        let original: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        inject(&mut cmd, InjectionType::BatteryDrain, &profile);
        let after: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        assert_eq!(original, after, "BatteryDrain must not modify joint_states");
    }

    #[test]
    fn terrain_incline_does_not_modify_joint_states() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        let original: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        inject(&mut cmd, InjectionType::TerrainIncline, &profile);
        let after: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        assert_eq!(
            original, after,
            "TerrainIncline must not modify joint_states"
        );
    }

    #[test]
    fn locomotion_overspeed_does_not_modify_joint_states() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        let original: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        inject(&mut cmd, InjectionType::LocomotionOverspeed, &profile);
        let after: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        assert_eq!(
            original, after,
            "LocomotionOverspeed must not modify joint_states"
        );
    }

    // =========================================================================
    // Injection field isolation: verify non-targeted fields are preserved
    // =========================================================================

    #[test]
    fn velocity_overshoot_preserves_positions() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        let original_positions: Vec<f64> = cmd.joint_states.iter().map(|js| js.position).collect();
        inject(&mut cmd, InjectionType::VelocityOvershoot, &profile);
        let after_positions: Vec<f64> = cmd.joint_states.iter().map(|js| js.position).collect();
        assert_eq!(
            original_positions, after_positions,
            "VelocityOvershoot must not change joint positions"
        );
    }

    #[test]
    fn position_violation_preserves_velocities() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        let original_velocities: Vec<f64> = cmd.joint_states.iter().map(|js| js.velocity).collect();
        inject(&mut cmd, InjectionType::PositionViolation, &profile);
        let after_velocities: Vec<f64> = cmd.joint_states.iter().map(|js| js.velocity).collect();
        assert_eq!(
            original_velocities, after_velocities,
            "PositionViolation must not change joint velocities"
        );
    }

    #[test]
    fn torque_spike_preserves_positions_and_velocities() {
        let profile = ur10();
        let mut cmd = make_cmd(&profile);
        let original_pos: Vec<f64> = cmd.joint_states.iter().map(|js| js.position).collect();
        let original_vel: Vec<f64> = cmd.joint_states.iter().map(|js| js.velocity).collect();
        inject(&mut cmd, InjectionType::TorqueSpike, &profile);
        let after_pos: Vec<f64> = cmd.joint_states.iter().map(|js| js.position).collect();
        let after_vel: Vec<f64> = cmd.joint_states.iter().map(|js| js.velocity).collect();
        assert_eq!(
            original_pos, after_pos,
            "TorqueSpike must not change positions"
        );
        assert_eq!(
            original_vel, after_vel,
            "TorqueSpike must not change velocities"
        );
    }

    #[test]
    fn authority_strip_preserves_joint_states() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        let original_joints: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        inject(&mut cmd, InjectionType::AuthorityStrip, &profile);
        let after_joints: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        assert_eq!(
            original_joints, after_joints,
            "AuthorityStrip must not change any joint states"
        );
    }

    #[test]
    fn workspace_escape_preserves_joint_states() {
        let profile = humanoid();
        let mut cmd = make_cmd(&profile);
        let original_joints: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        let after_joints: Vec<(f64, f64, f64)> = cmd
            .joint_states
            .iter()
            .map(|js| (js.position, js.velocity, js.effort))
            .collect();
        assert_eq!(
            original_joints, after_joints,
            "WorkspaceEscape must not change any joint states"
        );
    }

    // =========================================================================
    // E-stop injection on all 6 profiles (including ur10e_cnc_tending)
    // =========================================================================

    #[test]
    fn estop_engage_on_all_six_profiles() {
        let profiles = [
            panda(),
            ur10(),
            quadruped(),
            humanoid(),
            haas_cell(),
            load_builtin("ur10e_haas_cell").unwrap(),
        ];
        for profile in &profiles {
            let mut cmd = make_cmd(profile);
            inject(&mut cmd, InjectionType::EStopEngage, profile);
            let env = cmd.environment_state.as_ref().unwrap();
            assert_eq!(
                env.e_stop_engaged,
                Some(true),
                "[{}] E-stop must be engaged after EStopEngage injection",
                profile.name
            );
        }
    }

    // =========================================================================
    // Injection on fresh command: all 21 types produce a mutation
    // =========================================================================

    #[test]
    fn all_injections_mutate_at_least_one_field() {
        let profile = panda();
        for &inj in list_injections() {
            let original = make_cmd(&profile);
            let mut mutated = make_cmd(&profile);
            inject(&mut mutated, inj, &profile);
            // At least one field must differ between original and mutated.
            // We check the most common mutation targets.
            let joints_differ = original
                .joint_states
                .iter()
                .zip(mutated.joint_states.iter())
                .any(|(a, b)| {
                    a.position != b.position
                        || a.velocity != b.velocity
                        || a.effort != b.effort
                        || (a.position.is_finite() != b.position.is_finite())
                });
            let ee_differ = original.end_effector_positions.len()
                != mutated.end_effector_positions.len()
                || original
                    .end_effector_positions
                    .iter()
                    .zip(mutated.end_effector_positions.iter())
                    .any(|(a, b)| a.position != b.position);
            let dt_differ = original.delta_time != mutated.delta_time
                || (original.delta_time.is_finite() != mutated.delta_time.is_finite());
            let auth_differ = original.authority.pca_chain != mutated.authority.pca_chain;
            let seq_differ = original.sequence != mutated.sequence;
            let com_differ = original.center_of_mass != mutated.center_of_mass;
            let loco_differ = original.locomotion_state.is_some()
                != mutated.locomotion_state.is_some()
                || (original.locomotion_state.is_some() && mutated.locomotion_state.is_some());
            let env_differ =
                original.environment_state.is_some() != mutated.environment_state.is_some();
            let ee_forces_differ = original.end_effector_forces.len()
                != mutated.end_effector_forces.len()
                || original
                    .end_effector_forces
                    .iter()
                    .zip(mutated.end_effector_forces.iter())
                    .any(|(a, b)| a.force != b.force || a.grasp_force != b.grasp_force);
            let payload_differ = original.estimated_payload_kg != mutated.estimated_payload_kg;

            let any_diff = joints_differ
                || ee_differ
                || dt_differ
                || auth_differ
                || seq_differ
                || com_differ
                || loco_differ
                || env_differ
                || ee_forces_differ
                || payload_differ;
            assert!(
                any_diff,
                "Injection {inj:?} must mutate at least one command field"
            );
        }
    }

    // -----------------------------------------------------------------------
    // New manipulation injection tests (P10–P14)
    // -----------------------------------------------------------------------

    #[test]
    fn proximity_overspeed_places_ee_in_zone_and_exceeds_limit() {
        // franka_panda has proximity zone human_warning with velocity_scale=0.5
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::ProximityOverspeed, &profile);

        // The profile must have at least one proximity zone for this to do anything.
        assert!(
            !profile.proximity_zones.is_empty(),
            "franka_panda must have at least one proximity zone"
        );

        // EE must be inside the tightest zone (at its center).
        assert!(
            !cmd.end_effector_positions.is_empty(),
            "ProximityOverspeed must set at least one end-effector position"
        );

        // Velocity of every joint must exceed the proximity-scaled limit.
        // human_warning has velocity_scale=0.5, so scaled_limit = max_vel * 0.5 * global_scale.
        // Injected velocity = scaled_limit * 3.0 > scaled_limit.
        for (js, jdef) in cmd.joint_states.iter().zip(profile.joints.iter()) {
            // Use the minimum velocity_scale across all zones (most restrictive).
            let min_scale = profile
                .proximity_zones
                .iter()
                .map(|z| match z {
                    invariant_core::models::profile::ProximityZone::Sphere {
                        velocity_scale,
                        ..
                    } => *velocity_scale,
                    _ => 1.0,
                })
                .fold(f64::INFINITY, f64::min);
            let scaled_limit = jdef.max_velocity * min_scale * profile.global_velocity_scale;
            assert!(
                js.velocity > scaled_limit,
                "ProximityOverspeed: velocity {:.4} should exceed proximity-scaled limit {:.4} for {}",
                js.velocity,
                scaled_limit,
                jdef.name
            );
        }
    }

    #[test]
    fn force_overload_exceeds_max_force() {
        // haas_cell (ur10e_cnc_tending) has end_effector gripper with max_force_n=140
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::ForceOverload, &profile);

        assert!(
            !cmd.end_effector_forces.is_empty(),
            "ForceOverload must populate end_effector_forces"
        );
        let ee = &cmd.end_effector_forces[0];
        let max_force = profile
            .end_effectors
            .first()
            .map(|e| e.max_force_n)
            .unwrap_or(100.0);
        let force_mag =
            (ee.force[0] * ee.force[0] + ee.force[1] * ee.force[1] + ee.force[2] * ee.force[2])
                .sqrt();
        assert!(
            force_mag > max_force,
            "ForceOverload: force magnitude {:.2} should exceed max_force_n {:.2}",
            force_mag,
            max_force
        );
    }

    #[test]
    fn grasp_force_violation_exceeds_max_grasp() {
        // haas_cell has max_grasp_force_n=100
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::GraspForceViolation, &profile);

        assert!(
            !cmd.end_effector_forces.is_empty(),
            "GraspForceViolation must populate end_effector_forces"
        );
        let ee = &cmd.end_effector_forces[0];
        let max_grasp = profile
            .end_effectors
            .first()
            .map(|e| e.max_grasp_force_n)
            .unwrap_or(100.0);
        let grasp = ee
            .grasp_force
            .expect("GraspForceViolation must set grasp_force");
        assert!(
            grasp > max_grasp,
            "GraspForceViolation: grasp_force {:.2} should exceed max_grasp_force_n {:.2}",
            grasp,
            max_grasp
        );
    }

    #[test]
    fn payload_overload_exceeds_max_payload() {
        // haas_cell has max_payload_kg=10
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::PayloadOverload, &profile);

        let max_payload = profile
            .end_effectors
            .first()
            .map(|e| e.max_payload_kg)
            .unwrap_or(10.0);
        let payload = cmd
            .estimated_payload_kg
            .expect("PayloadOverload must set estimated_payload_kg");
        assert!(
            payload > max_payload,
            "PayloadOverload: estimated_payload_kg {:.2} should exceed max_payload_kg {:.2}",
            payload,
            max_payload
        );
        // end_effector_forces must be non-empty so the validator can find a matching config.
        assert!(
            !cmd.end_effector_forces.is_empty(),
            "PayloadOverload must populate end_effector_forces"
        );
    }

    #[test]
    fn all_new_injections_no_panic() {
        let new_types = [
            InjectionType::ProximityOverspeed,
            InjectionType::ForceOverload,
            InjectionType::GraspForceViolation,
            InjectionType::PayloadOverload,
        ];
        for profile in all_profiles() {
            for &inj in &new_types {
                let mut cmd = make_cmd(&profile);
                inject(&mut cmd, inj, &profile);
            }
        }
    }

    #[test]
    fn force_rate_spike_sets_large_force() {
        let profile = haas_cell();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::ForceRateSpike, &profile);
        assert!(
            !cmd.end_effector_forces.is_empty(),
            "ForceRateSpike must populate end_effector_forces"
        );
        let force_mag = {
            let f = &cmd.end_effector_forces[0].force;
            (f[0] * f[0] + f[1] * f[1] + f[2] * f[2]).sqrt()
        };
        // Force must be large enough that rate from zero exceeds max_force_rate
        let max_rate = profile.end_effectors[0].max_force_rate_n_per_s;
        let expected_min = max_rate * cmd.delta_time * 2.0; // at least 2× the threshold
        assert!(force_mag >= expected_min,
            "ForceRateSpike force {force_mag:.1} N must be >= {expected_min:.1} N to exceed rate limit");
    }
}
