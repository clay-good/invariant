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

/// The sixteen fault-injection modes.
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
    // -- Locomotion adversarial injections (Step 52) --
    /// Set base velocity to 3× max locomotion velocity (P15 runaway).
    LocomotionOverspeed,
    /// Violate friction cone constraint: tangential >> normal (P18 slip).
    SlipViolation,
    /// Set swing foot height to 0 or below ground (P16 trip).
    FootClearanceViolation,
    /// Set step length to 3× max (P19 overextension).
    StepOverextension,
    /// Set heading rate to 5× max (P20 spinout).
    HeadingSpinout,
    /// Set ground reaction force to 5× max (P17 stomp).
    GroundReactionSpike,
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
    InjectionType::StepOverextension,
    InjectionType::HeadingSpinout,
    InjectionType::GroundReactionSpike,
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
        InjectionType::StepOverextension => inject_step_overextension(cmd, profile),
        InjectionType::HeadingSpinout => inject_heading_spinout(cmd, profile),
        InjectionType::GroundReactionSpike => inject_ground_reaction_spike(cmd, profile),
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
// Locomotion injection implementations (Step 52)
// ---------------------------------------------------------------------------

use invariant_core::models::command::{FootState, LocomotionState};

/// Ensure the command has a locomotion_state; create a default one if absent.
fn ensure_locomotion_state<'a>(cmd: &'a mut Command, profile: &RobotProfile) -> &'a mut LocomotionState {
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
    cmd.locomotion_state.as_mut().unwrap()
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
        }
    }

    // --- list_injections ---

    #[test]
    fn list_injections_contains_all_sixteen() {
        let injections = list_injections();
        assert_eq!(injections.len(), 16);
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

    // --- Locomotion injections (Step 52) ---

    #[test]
    fn locomotion_overspeed_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::LocomotionOverspeed, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        let [vx, vy, vz] = loco.base_velocity;
        let speed = (vx * vx + vy * vy + vz * vz).sqrt();
        // Default max is 1.5, injected 3x = 4.5
        assert!(speed > 1.5, "LocomotionOverspeed: speed {speed:.2} should exceed default max");
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
        assert!(any_below, "FootClearanceViolation: at least one swing foot must be below ground");
    }

    #[test]
    fn step_overextension_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::StepOverextension, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        // Default max_step_length = 0.6, injected 3x = 1.8
        assert!(loco.step_length > 0.6, "StepOverextension: step_length {:.2} should exceed default max", loco.step_length);
    }

    #[test]
    fn heading_spinout_exceeds_max() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::HeadingSpinout, &profile);
        let loco = cmd.locomotion_state.as_ref().unwrap();
        // Default max_heading_rate = 1.0, injected 5x = 5.0
        assert!(loco.heading_rate.abs() > 1.0, "HeadingSpinout: heading_rate {:.2} should exceed default max", loco.heading_rate);
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
        assert!(any_spike, "GroundReactionSpike: at least one foot must have GRF > max");
    }
}
