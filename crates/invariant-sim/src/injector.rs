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

/// The ten fault-injection modes.
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
    let far_x = profile
        .stability
        .as_ref()
        .and_then(|s| s.support_polygon.first())
        .map(|v| v[0] * 10.0)
        .unwrap_or(100.0);

    let far_y = profile
        .stability
        .as_ref()
        .and_then(|s| s.support_polygon.first())
        .map(|v| v[1] * 10.0)
        .unwrap_or(100.0);

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
        }
    }

    // --- list_injections ---

    #[test]
    fn list_injections_contains_all_ten() {
        let injections = list_injections();
        assert_eq!(injections.len(), 10);
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
                js.velocity, limit, jdef.name
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
        assert!(any_violation, "PositionViolation must produce out-of-limit positions");
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
                js.effort, jdef.max_torque, jdef.name
            );
        }
    }

    // --- WorkspaceEscape ---

    #[test]
    fn workspace_escape_places_ee_outside_bounds() {
        let profile = panda();
        let mut cmd = make_cmd(&profile);
        inject(&mut cmd, InjectionType::WorkspaceEscape, &profile);
        let oob = cmd.end_effector_positions.iter().any(|ee| match &profile.workspace {
            WorkspaceBounds::Aabb { min, max } => {
                ee.position[0] > max[0]
                    || ee.position[1] > max[1]
                    || ee.position[2] > max[2]
                    || ee.position[0] < min[0]
                    || ee.position[1] < min[1]
                    || ee.position[2] < min[2]
            }
        });
        assert!(oob, "WorkspaceEscape must place end-effector outside workspace");
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
            cmd.delta_time, profile.max_delta_time
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
        assert!(has_non_finite, "NanInjection must produce non-finite joint values");

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
        assert!(has_non_finite_ee, "NanInjection must produce non-finite EE positions");
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
}
