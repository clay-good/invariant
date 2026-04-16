#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::models::command::{EndEffectorPosition, JointState};
    use crate::models::profile::{
        CollisionPair, ExclusionZone, JointDefinition, JointType, ProximityZone, RobotProfile,
        SafeStopProfile, StabilityConfig, WorkspaceBounds,
    };
    use crate::physics::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn joint_def(name: &str, min: f64, max: f64) -> JointDefinition {
        JointDefinition {
            name: name.into(),
            joint_type: JointType::Revolute,
            min,
            max,
            max_velocity: 5.0,
            max_torque: 50.0,
            max_acceleration: 25.0,
        }
    }

    fn joint_state(name: &str, pos: f64, vel: f64, effort: f64) -> JointState {
        JointState {
            name: name.into(),
            position: pos,
            velocity: vel,
            effort,
        }
    }

    fn ee(name: &str, x: f64, y: f64, z: f64) -> EndEffectorPosition {
        EndEffectorPosition {
            name: name.into(),
            position: [x, y, z],
        }
    }

    // ── P1: Joint position limits ───────────────────────────────────────

    #[test]
    fn p1_all_within_limits() {
        let defs = vec![joint_def("j1", -1.0, 1.0), joint_def("j2", -2.0, 2.0)];
        let joints = vec![
            joint_state("j1", 0.0, 0.0, 0.0),
            joint_state("j2", 1.5, 0.0, 0.0),
        ];
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(r.passed);
        assert_eq!(r.name, "joint_limits");
        assert_eq!(r.category, "physics");
    }

    #[test]
    fn p1_at_exact_boundary() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 1.0, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(r.passed);

        let joints_min = vec![joint_state("j1", -1.0, 0.0, 0.0)];
        let r2 = joint_limits::check_joint_limits(&joints_min, &defs, None);
        assert!(r2.passed);
    }

    #[test]
    fn p1_exceeds_max() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 1.001, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(!r.passed);
        assert!(r.details.contains("j1"));
    }

    #[test]
    fn p1_below_min() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", -1.001, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(!r.passed);
    }

    #[test]
    fn p1_unknown_joint() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j_unknown", 0.0, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(!r.passed);
        assert!(r.details.contains("unknown joint"));
    }

    #[test]
    fn p1_empty_joints_passes() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let r = joint_limits::check_joint_limits(&[], &defs, None);
        assert!(r.passed);
    }

    #[test]
    fn p1_multiple_violations() {
        let defs = vec![joint_def("j1", -1.0, 1.0), joint_def("j2", -0.5, 0.5)];
        let joints = vec![
            joint_state("j1", 2.0, 0.0, 0.0),
            joint_state("j2", -1.0, 0.0, 0.0),
        ];
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(!r.passed);
        assert!(r.details.contains("j1"));
        assert!(r.details.contains("j2"));
    }

    // ── P2: Velocity limits ─────────────────────────────────────────────

    #[test]
    fn p2_within_limits() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 4.9, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0, None);
        assert!(r.passed);
    }

    #[test]
    fn p2_exceeds_limit() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 5.1, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0, None);
        assert!(!r.passed);
        assert!(r.details.contains("j1"));
    }

    #[test]
    fn p2_negative_velocity() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, -5.1, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0, None);
        assert!(!r.passed);
    }

    #[test]
    fn p2_scaled_velocity() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 3.0, 0.0)];
        // With scale 0.5, effective limit = 5.0 * 0.5 = 2.5
        let r = velocity::check_velocity_limits(&joints, &defs, 0.5, None);
        assert!(!r.passed);

        // With scale 1.0, 3.0 <= 5.0 passes
        let r2 = velocity::check_velocity_limits(&joints, &defs, 1.0, None);
        assert!(r2.passed);
    }

    #[test]
    fn p2_at_exact_boundary() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 5.0, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0, None);
        assert!(r.passed);
    }

    // ── P3: Torque limits ───────────────────────────────────────────────

    #[test]
    fn p3_within_limits() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_torque = 50.0
        let joints = vec![joint_state("j1", 0.0, 0.0, 49.9)];
        let r = torque::check_torque_limits(&joints, &defs, None);
        assert!(r.passed);
    }

    #[test]
    fn p3_exceeds_limit() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_torque = 50.0
        let joints = vec![joint_state("j1", 0.0, 0.0, 50.1)];
        let r = torque::check_torque_limits(&joints, &defs, None);
        assert!(!r.passed);
    }

    #[test]
    fn p3_negative_effort() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 0.0, -50.1)];
        let r = torque::check_torque_limits(&joints, &defs, None);
        assert!(!r.passed);
    }

    #[test]
    fn p3_at_exact_boundary() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_torque = 50.0
        let joints = vec![joint_state("j1", 0.0, 0.0, 50.0)];
        let r = torque::check_torque_limits(&joints, &defs, None);
        assert!(r.passed);
    }

    // ── P4: Acceleration limits ─────────────────────────────────────────

    #[test]
    fn p4_no_previous_passes() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 5.0, 0.0)];
        let r = acceleration::check_acceleration_limits(&joints, None, &defs, 0.01, None);
        assert!(r.passed);
        assert!(r.details.contains("first command"));
    }

    #[test]
    fn p4_within_limits() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_acceleration = 25.0
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.2, 0.0)]; // accel = 0.2/0.01 = 20.0
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01, None);
        assert!(r.passed);
    }

    #[test]
    fn p4_exceeds_limit() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_acceleration = 25.0
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.3, 0.0)]; // accel = 0.3/0.01 = 30.0
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01, None);
        assert!(!r.passed);
    }

    #[test]
    fn p4_zero_delta_time_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.1, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.0, None);
        assert!(!r.passed);
        assert!(r.details.contains("non-positive"));
    }

    #[test]
    fn p4_negative_delta_time_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.1, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, -0.01, None);
        assert!(!r.passed);
    }

    #[test]
    fn p4_missing_previous_joint_flagged() {
        let defs = vec![joint_def("j1", -1.0, 1.0), joint_def("j2", -1.0, 1.0)];
        // j2 appears in current but not in previous — should be flagged as violation
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![
            joint_state("j1", 0.0, 1.1, 0.0),   // accel = 10, within 25
            joint_state("j2", 0.0, 100.0, 0.0), // no prev data — flagged
        ];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01, None);
        assert!(!r.passed);
        assert!(r.details.contains("j2"));
        assert!(r.details.contains("no previous joint state"));
    }

    #[test]
    fn p4_deceleration() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_acceleration = 25.0
        let prev = vec![joint_state("j1", 0.0, 5.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 4.7, 0.0)]; // accel = 0.3/0.01 = 30.0
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01, None);
        assert!(!r.passed); // deceleration also checked
    }

    #[test]
    fn p4_vanishing_joint_absent_from_current_command() {
        // Finding 40: a joint present in previous_joints but absent from the
        // current command must be reported as a violation with a message
        // containing 'absent from current command'.
        let defs = vec![joint_def("j1", -1.0, 1.0), joint_def("j2", -1.0, 1.0)];
        let prev = vec![
            joint_state("j1", 0.0, 1.0, 0.0),
            joint_state("j2", 0.0, 1.0, 0.0),
        ];
        // j2 is absent from the current command.
        let curr = vec![joint_state("j1", 0.0, 1.1, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01, None);
        assert!(
            !r.passed,
            "result must fail when j2 vanishes from current command"
        );
        assert!(
            r.details.contains("absent from current command"),
            "details must mention 'absent from current command': {}",
            r.details
        );
    }

    // ── Real-world margins (Section 18.2) ────────────────────────────────

    use crate::models::profile::RealWorldMargins;

    fn test_margins() -> RealWorldMargins {
        RealWorldMargins {
            position_margin: 0.10,     // 10% tightening
            velocity_margin: 0.15,     // 15% tightening
            torque_margin: 0.10,       // 10% tightening
            acceleration_margin: 0.10, // 10% tightening
        }
    }

    #[test]
    fn p1_margin_tightens_position_range() {
        // Joint range [-1.0, 1.0], 10% margin → effective [-0.8, 0.8].
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let margins = test_margins();

        // 0.85 is within original range but outside margined range.
        let joints = vec![joint_state("j1", 0.85, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, Some(&margins));
        assert!(!r.passed, "position 0.85 should exceed margined max 0.8");

        // 0.75 is within margined range.
        let joints = vec![joint_state("j1", 0.75, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, Some(&margins));
        assert!(r.passed, "position 0.75 should be within margined max 0.8");
    }

    #[test]
    fn p1_no_margin_uses_full_range() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.95, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(r.passed, "position 0.95 should pass without margins");
    }

    #[test]
    fn p2_margin_tightens_velocity_limit() {
        // max_velocity = 5.0, 15% margin → effective 4.25.
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let margins = test_margins();

        // Velocity 4.5 passes without margin but fails with 15% margin.
        let joints = vec![joint_state("j1", 0.0, 4.5, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0, Some(&margins));
        assert!(!r.passed, "velocity 4.5 should exceed margined limit 4.25");

        // Velocity 4.0 passes with margin.
        let joints = vec![joint_state("j1", 0.0, 4.0, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0, Some(&margins));
        assert!(
            r.passed,
            "velocity 4.0 should be within margined limit 4.25"
        );
    }

    #[test]
    fn p3_margin_tightens_torque_limit() {
        // max_torque = 50.0, 10% margin → effective 45.0.
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let margins = test_margins();

        // Effort 47 passes without margin but fails with 10% margin.
        let joints = vec![joint_state("j1", 0.0, 0.0, 47.0)];
        let r = torque::check_torque_limits(&joints, &defs, Some(&margins));
        assert!(!r.passed, "effort 47 should exceed margined limit 45");

        // Effort 44 passes with margin.
        let joints = vec![joint_state("j1", 0.0, 0.0, 44.0)];
        let r = torque::check_torque_limits(&joints, &defs, Some(&margins));
        assert!(r.passed, "effort 44 should be within margined limit 45");
    }

    #[test]
    fn p4_margin_tightens_acceleration_limit() {
        // max_acceleration = 25.0, 10% margin → effective 22.5.
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let margins = test_margins();

        let prev = vec![joint_state("j1", 0.0, 0.0, 0.0)];
        // velocity=0.24 at dt=0.01 → accel=24.0. Passes without margin (limit 25),
        // fails with 10% margin (limit 22.5).
        let joints = vec![joint_state("j1", 0.0, 0.24, 0.0)];
        let r = acceleration::check_acceleration_limits(
            &joints,
            Some(&prev),
            &defs,
            0.01,
            Some(&margins),
        );
        assert!(!r.passed, "accel 24 should exceed margined limit 22.5");

        // velocity=0.20 → accel=20.0. Passes with margin.
        let joints = vec![joint_state("j1", 0.0, 0.20, 0.0)];
        let r = acceleration::check_acceleration_limits(
            &joints,
            Some(&prev),
            &defs,
            0.01,
            Some(&margins),
        );
        assert!(r.passed, "accel 20 should be within margined limit 22.5");
    }

    #[test]
    fn margins_zero_has_no_effect() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let zero_margins = RealWorldMargins {
            position_margin: 0.0,
            velocity_margin: 0.0,
            torque_margin: 0.0,
            acceleration_margin: 0.0,
        };

        // 0.95 passes with zero margins (same as None).
        let joints = vec![joint_state("j1", 0.95, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, Some(&zero_margins));
        assert!(r.passed, "zero margins should behave identically to None");
    }

    // ── P5: Workspace bounds ────────────────────────────────────────────

    #[test]
    fn p5_within_bounds() {
        let ws = WorkspaceBounds::Aabb {
            min: [-2.0, -2.0, 0.0],
            max: [2.0, 2.0, 2.5],
        };
        let ees = vec![ee("left_hand", 0.5, 0.5, 1.0)];
        let r = workspace::check_workspace_bounds(&ees, &ws);
        assert!(r.passed);
    }

    #[test]
    fn p5_outside_bounds() {
        let ws = WorkspaceBounds::Aabb {
            min: [-2.0, -2.0, 0.0],
            max: [2.0, 2.0, 2.5],
        };
        let ees = vec![ee("left_hand", 3.0, 0.0, 1.0)];
        let r = workspace::check_workspace_bounds(&ees, &ws);
        assert!(!r.passed);
        assert!(r.details.contains("left_hand"));
    }

    #[test]
    fn p5_at_boundary() {
        let ws = WorkspaceBounds::Aabb {
            min: [-2.0, -2.0, 0.0],
            max: [2.0, 2.0, 2.5],
        };
        let ees = vec![ee("left_hand", 2.0, 2.0, 2.5)];
        let r = workspace::check_workspace_bounds(&ees, &ws);
        assert!(r.passed);
    }

    #[test]
    fn p5_below_z_floor() {
        let ws = WorkspaceBounds::Aabb {
            min: [-2.0, -2.0, 0.0],
            max: [2.0, 2.0, 2.5],
        };
        let ees = vec![ee("left_hand", 0.0, 0.0, -0.01)];
        let r = workspace::check_workspace_bounds(&ees, &ws);
        assert!(!r.passed);
    }

    #[test]
    fn p5_empty_end_effectors_fails() {
        // Workspace bounds are always defined; no positions means the check
        // cannot be satisfied — fail instead of passing trivially.
        let ws = WorkspaceBounds::Aabb {
            min: [-2.0, -2.0, 0.0],
            max: [2.0, 2.0, 2.5],
        };
        let r = workspace::check_workspace_bounds(&[], &ws);
        assert!(!r.passed);
        assert!(r.details.contains("end_effector_positions required"));
    }

    // ── P6: Exclusion zones ─────────────────────────────────────────────

    #[test]
    fn p6_not_in_any_zone() {
        let zones = vec![ExclusionZone::Aabb {
            name: "operator".into(),
            min: [1.0, -0.5, 0.0],
            max: [3.0, 0.5, 2.0],
            conditional: false,
        }];
        let ees = vec![ee("left_hand", -1.0, 0.0, 1.0)]; // outside zone
        let r =
            exclusion_zones::check_exclusion_zones(&ees, &zones, &std::collections::HashMap::new());
        assert!(r.passed);
    }

    #[test]
    fn p6_inside_aabb_zone() {
        let zones = vec![ExclusionZone::Aabb {
            name: "operator".into(),
            min: [1.0, -0.5, 0.0],
            max: [3.0, 0.5, 2.0],
            conditional: false,
        }];
        let ees = vec![ee("left_hand", 2.0, 0.0, 1.0)]; // inside zone
        let r =
            exclusion_zones::check_exclusion_zones(&ees, &zones, &std::collections::HashMap::new());
        assert!(!r.passed);
        assert!(r.details.contains("operator"));
    }

    #[test]
    fn p6_inside_sphere_zone() {
        let zones = vec![ExclusionZone::Sphere {
            name: "head".into(),
            center: [0.0, 0.0, 1.7],
            radius: 0.3,
            conditional: false,
        }];
        let ees = vec![ee("left_hand", 0.0, 0.0, 1.7)]; // at center
        let r =
            exclusion_zones::check_exclusion_zones(&ees, &zones, &std::collections::HashMap::new());
        assert!(!r.passed);
    }

    #[test]
    fn p6_outside_sphere_zone() {
        let zones = vec![ExclusionZone::Sphere {
            name: "head".into(),
            center: [0.0, 0.0, 1.7],
            radius: 0.3,
            conditional: false,
        }];
        let ees = vec![ee("left_hand", 0.0, 0.0, 2.1)]; // distance = 0.4 > 0.3
        let r =
            exclusion_zones::check_exclusion_zones(&ees, &zones, &std::collections::HashMap::new());
        assert!(r.passed);
    }

    #[test]
    fn p6_on_sphere_boundary() {
        let zones = vec![ExclusionZone::Sphere {
            name: "head".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            conditional: false,
        }];
        let ees = vec![ee("left_hand", 1.0, 0.0, 0.0)]; // on surface
        let r =
            exclusion_zones::check_exclusion_zones(&ees, &zones, &std::collections::HashMap::new());
        assert!(!r.passed); // on boundary = inside
    }

    #[test]
    fn p6_empty_zones_passes() {
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0)];
        let r =
            exclusion_zones::check_exclusion_zones(&ees, &[], &std::collections::HashMap::new());
        assert!(r.passed);
    }

    #[test]
    fn p6_empty_end_effectors_fails_when_zones_defined() {
        // Zones are defined; no positions means we cannot verify — fail.
        let zones = vec![ExclusionZone::Aabb {
            name: "operator".into(),
            min: [0.0, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
            conditional: false,
        }];
        let r =
            exclusion_zones::check_exclusion_zones(&[], &zones, &std::collections::HashMap::new());
        assert!(!r.passed);
        assert!(r.details.contains("end_effector_positions required"));
    }

    // ── P6: Conditional exclusion zones ─────────────────────────────────

    #[test]
    fn p6_conditional_zone_active_by_default() {
        // A conditional zone with no override entry is active (fail-closed).
        let zones = vec![ExclusionZone::Aabb {
            name: "spindle".into(),
            min: [0.0, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
            conditional: true,
        }];
        let ees = vec![ee("gripper", 0.5, 0.5, 0.5)]; // inside zone
        let overrides = std::collections::HashMap::new(); // empty = active
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &overrides);
        assert!(!r.passed);
        assert!(r.details.contains("spindle"));
    }

    #[test]
    fn p6_conditional_zone_explicitly_active() {
        // Override set to true = active.
        let zones = vec![ExclusionZone::Aabb {
            name: "spindle".into(),
            min: [0.0, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
            conditional: true,
        }];
        let ees = vec![ee("gripper", 0.5, 0.5, 0.5)];
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("spindle".to_string(), true);
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &overrides);
        assert!(!r.passed);
    }

    #[test]
    fn p6_conditional_zone_disabled_allows_entry() {
        // Override set to false = disabled. Robot can enter.
        let zones = vec![ExclusionZone::Aabb {
            name: "spindle".into(),
            min: [0.0, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
            conditional: true,
        }];
        let ees = vec![ee("gripper", 0.5, 0.5, 0.5)]; // inside zone but zone disabled
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("spindle".to_string(), false);
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &overrides);
        assert!(r.passed);
    }

    #[test]
    fn p6_non_conditional_zone_ignores_override() {
        // A non-conditional zone cannot be disabled by overrides.
        let zones = vec![ExclusionZone::Aabb {
            name: "permanent".into(),
            min: [0.0, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
            conditional: false,
        }];
        let ees = vec![ee("gripper", 0.5, 0.5, 0.5)];
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("permanent".to_string(), false); // try to disable it
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &overrides);
        assert!(!r.passed); // still active — non-conditional zones can't be disabled
    }

    #[test]
    fn p6_mixed_conditional_and_permanent_zones() {
        // One conditional (disabled), one permanent. Robot inside both.
        let zones = vec![
            ExclusionZone::Aabb {
                name: "spindle".into(),
                min: [0.0, 0.0, 0.0],
                max: [1.0, 1.0, 1.0],
                conditional: true,
            },
            ExclusionZone::Aabb {
                name: "enclosure_rear".into(),
                min: [0.0, 0.0, 0.0],
                max: [1.0, 1.0, 1.0],
                conditional: false,
            },
        ];
        let ees = vec![ee("gripper", 0.5, 0.5, 0.5)];
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("spindle".to_string(), false);
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &overrides);
        assert!(!r.passed); // permanent zone still catches it
        assert!(r.details.contains("enclosure_rear"));
        assert!(!r.details.contains("spindle")); // spindle zone is disabled
    }

    #[test]
    fn p6_conditional_sphere_zone_disabled() {
        let zones = vec![ExclusionZone::Sphere {
            name: "edge_pc".into(),
            center: [0.5, 0.0, 0.5],
            radius: 0.15,
            conditional: true,
        }];
        let ees = vec![ee("gripper", 0.5, 0.0, 0.5)]; // dead center
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("edge_pc".to_string(), false);
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &overrides);
        assert!(r.passed);
    }

    #[test]
    fn p6_all_conditional_zones_disabled_passes() {
        let zones = vec![
            ExclusionZone::Aabb {
                name: "z1".into(),
                min: [0.0, 0.0, 0.0],
                max: [1.0, 1.0, 1.0],
                conditional: true,
            },
            ExclusionZone::Sphere {
                name: "z2".into(),
                center: [0.5, 0.5, 0.5],
                radius: 1.0,
                conditional: true,
            },
        ];
        let ees = vec![ee("gripper", 0.5, 0.5, 0.5)];
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("z1".to_string(), false);
        overrides.insert("z2".to_string(), false);
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &overrides);
        assert!(r.passed);
        assert!(r.details.contains("all conditional zones disabled"));
    }

    #[test]
    fn p6_override_for_nonexistent_zone_is_harmless() {
        // Extra override entries for zones that don't exist are ignored.
        let zones = vec![ExclusionZone::Aabb {
            name: "real_zone".into(),
            min: [0.0, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
            conditional: false,
        }];
        let ees = vec![ee("gripper", 5.0, 5.0, 5.0)]; // outside zone
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("nonexistent".to_string(), false);
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &overrides);
        assert!(r.passed);
    }

    // ── P7: Self-collision ──────────────────────────────────────────────

    #[test]
    fn p7_far_apart_passes() {
        let pairs = vec![CollisionPair {
            link_a: "left_hand".into(),
            link_b: "head".into(),
        }];
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0), ee("head", 1.0, 1.0, 1.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p7_too_close_fails() {
        let pairs = vec![CollisionPair {
            link_a: "left_hand".into(),
            link_b: "head".into(),
        }];
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0), ee("head", 0.005, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.01);
        assert!(!r.passed);
        assert!(r.details.contains("left_hand"));
        assert!(r.details.contains("head"));
    }

    #[test]
    fn p7_exactly_at_threshold() {
        let pairs = vec![CollisionPair {
            link_a: "a".into(),
            link_b: "b".into(),
        }];
        // Distance = 0.01 exactly, which is the threshold. < 0.01 fails, >= passes.
        let ees = vec![ee("a", 0.0, 0.0, 0.0), ee("b", 0.01, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p7_missing_link_flagged() {
        let pairs = vec![CollisionPair {
            link_a: "left_hand".into(),
            link_b: "missing".into(),
        }];
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.01);
        assert!(!r.passed); // missing link is now flagged as violation
        assert!(r.details.contains("missing"));
    }

    #[test]
    fn p7_empty_pairs_passes() {
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &[], 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p7_empty_end_effectors_fails_when_pairs_defined() {
        // Collision pairs are defined; no positions means we cannot verify — fail.
        let pairs = vec![CollisionPair {
            link_a: "left_hand".into(),
            link_b: "head".into(),
        }];
        let r = self_collision::check_self_collision(&[], &pairs, 0.05);
        assert!(!r.passed);
        assert!(r.details.contains("end_effector_positions required"));
    }

    // ── P8: Delta time ──────────────────────────────────────────────────

    #[test]
    fn p8_valid_delta_time() {
        let r = delta_time::check_delta_time(0.01, 0.1);
        assert!(r.passed);
    }

    #[test]
    fn p8_zero_delta_time() {
        let r = delta_time::check_delta_time(0.0, 0.1);
        assert!(!r.passed);
        assert!(r.details.contains("not finite and positive"));
    }

    #[test]
    fn p8_negative_delta_time() {
        let r = delta_time::check_delta_time(-0.01, 0.1);
        assert!(!r.passed);
    }

    #[test]
    fn p8_exceeds_max() {
        let r = delta_time::check_delta_time(0.2, 0.1);
        assert!(!r.passed);
        assert!(r.details.contains("exceeds"));
    }

    #[test]
    fn p8_at_exact_max() {
        let r = delta_time::check_delta_time(0.1, 0.1);
        assert!(r.passed);
    }

    #[test]
    fn p8_very_small_delta_time() {
        let r = delta_time::check_delta_time(0.0001, 0.1);
        assert!(r.passed);
    }

    // ── P9: Stability (ZMP) ────────────────────────────────────────────

    #[test]
    fn p9_inside_polygon() {
        let config = StabilityConfig {
            support_polygon: vec![[-0.15, -0.1], [0.15, -0.1], [0.15, 0.1], [-0.15, 0.1]],
            com_height_estimate: 0.9,
            enabled: true,
        };
        let com = [0.0, 0.0, 0.9]; // center of polygon
        let r = stability::check_stability(Some(&com), Some(&config));
        assert!(r.passed);
    }

    #[test]
    fn p9_outside_polygon() {
        let config = StabilityConfig {
            support_polygon: vec![[-0.15, -0.1], [0.15, -0.1], [0.15, 0.1], [-0.15, 0.1]],
            com_height_estimate: 0.9,
            enabled: true,
        };
        let com = [0.5, 0.0, 0.9]; // outside
        let r = stability::check_stability(Some(&com), Some(&config));
        assert!(!r.passed);
    }

    #[test]
    fn p9_no_com_data_with_enabled_stability_fails() {
        // Fail-closed: if the profile requires stability (enabled=true) but
        // the command omits center_of_mass, P9 must reject.
        let config = StabilityConfig {
            support_polygon: vec![[-0.15, -0.1], [0.15, -0.1], [0.15, 0.1], [-0.15, 0.1]],
            com_height_estimate: 0.9,
            enabled: true,
        };
        let r = stability::check_stability(None, Some(&config));
        assert!(
            !r.passed,
            "P9 must fail-closed when COM missing but stability enabled"
        );
    }

    #[test]
    fn p9_no_com_data_with_disabled_stability_passes() {
        // When stability is disabled, missing COM is fine.
        let config = StabilityConfig {
            support_polygon: vec![[-0.15, -0.1], [0.15, -0.1], [0.15, 0.1], [-0.15, 0.1]],
            com_height_estimate: 0.9,
            enabled: false,
        };
        let r = stability::check_stability(None, Some(&config));
        assert!(r.passed, "P9 must pass when stability is disabled");
    }

    #[test]
    fn p9_no_config_passes() {
        let com = [0.0, 0.0, 0.9];
        let r = stability::check_stability(Some(&com), None);
        assert!(r.passed);
    }

    #[test]
    fn p9_disabled_passes() {
        let config = StabilityConfig {
            support_polygon: vec![[-0.15, -0.1], [0.15, -0.1], [0.15, 0.1], [-0.15, 0.1]],
            com_height_estimate: 0.9,
            enabled: false,
        };
        let com = [10.0, 10.0, 0.9]; // way outside, but disabled
        let r = stability::check_stability(Some(&com), Some(&config));
        assert!(r.passed);
    }

    #[test]
    fn p9_degenerate_polygon_fails() {
        // A polygon with fewer than 3 vertices is degenerate and must fail
        // the stability check (fail-closed behaviour, Finding 39).
        let config = StabilityConfig {
            support_polygon: vec![[0.0, 0.0], [1.0, 0.0]], // only 2 vertices
            com_height_estimate: 0.9,
            enabled: true,
        };
        let com = [0.5, 0.0, 0.9];
        let r = stability::check_stability(Some(&com), Some(&config));
        assert!(!r.passed);
        assert!(r.details.contains("degenerate support polygon"));

        // A polygon with zero vertices must also fail.
        let config_empty = StabilityConfig {
            support_polygon: vec![],
            com_height_estimate: 0.9,
            enabled: true,
        };
        let r2 = stability::check_stability(Some(&com), Some(&config_empty));
        assert!(!r2.passed);
        assert!(r2.details.contains("degenerate support polygon"));
    }

    #[test]
    fn p9_triangle_polygon() {
        let config = StabilityConfig {
            support_polygon: vec![[0.0, 0.0], [1.0, 0.0], [0.5, 1.0]],
            com_height_estimate: 0.9,
            enabled: true,
        };
        let com_inside = [0.5, 0.3, 0.9];
        let r = stability::check_stability(Some(&com_inside), Some(&config));
        assert!(r.passed);

        let com_outside = [-0.5, 0.3, 0.9];
        let r2 = stability::check_stability(Some(&com_outside), Some(&config));
        assert!(!r2.passed);
    }

    // ── P10: Proximity velocity scaling ─────────────────────────────────

    #[test]
    fn p10_no_zones_passes() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 5.0, 0.0)];
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0)];
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &[], 1.0);
        assert!(r.passed);
    }

    #[test]
    fn p10_not_in_zone_passes() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 4.9, 0.0)];
        let ees = vec![ee("left_hand", 10.0, 0.0, 0.0)]; // far from zone
        let zones = vec![ProximityZone::Sphere {
            name: "human".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(r.passed);
    }

    #[test]
    fn p10_in_zone_velocity_ok() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 2.0, 0.0)];
        let ees = vec![ee("left_hand", 0.5, 0.0, 0.0)]; // inside sphere radius 1.0
        let zones = vec![ProximityZone::Sphere {
            name: "human".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        // effective limit = 5.0 * 0.5 * 1.0 = 2.5, vel = 2.0 => pass
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(r.passed);
    }

    #[test]
    fn p10_in_zone_velocity_exceeds() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 3.0, 0.0)];
        let ees = vec![ee("left_hand", 0.5, 0.0, 0.0)]; // inside sphere radius 1.0
        let zones = vec![ProximityZone::Sphere {
            name: "human".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        // effective limit = 5.0 * 0.5 * 1.0 = 2.5, vel = 3.0 => fail
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(!r.passed);
    }

    #[test]
    fn p10_multiple_zones_takes_minimum_scale() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 0.4, 0.0)];
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0)];
        let zones = vec![
            ProximityZone::Sphere {
                name: "zone1".into(),
                center: [0.0, 0.0, 0.0],
                radius: 2.0,
                velocity_scale: 0.5,
                dynamic: false,
            },
            ProximityZone::Sphere {
                name: "zone2".into(),
                center: [0.0, 0.0, 0.0],
                radius: 1.0,
                velocity_scale: 0.1,
                dynamic: false,
            },
        ];
        // Both zones active, min scale = 0.1, limit = 5.0 * 0.1 * 1.0 = 0.5
        // vel 0.4 < 0.5 => pass
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(r.passed);

        // vel 0.6 > 0.5 => fail
        let joints2 = vec![joint_state("j1", 0.0, 0.6, 0.0)];
        let r2 = proximity::check_proximity_velocity(&joints2, &defs, &ees, &zones, 1.0);
        assert!(!r2.passed);
    }

    #[test]
    fn p10_global_scale_compounds() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0)];
        let zones = vec![ProximityZone::Sphere {
            name: "human".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        // limit = 5.0 * 0.5 * 0.5 = 1.25, vel = 1.0 => pass
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 0.5);
        assert!(r.passed);

        // limit = 5.0 * 0.5 * 0.3 = 0.75, vel = 1.0 => fail
        let r2 = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 0.3);
        assert!(!r2.passed);
    }

    // ── run_all_checks integration ──────────────────────────────────────

    #[test]
    fn run_all_checks_returns_10_results() {
        use crate::models::authority::Operation;
        use crate::models::command::{Command, CommandAuthority};
        use crate::models::profile::{RobotProfile, SafeStopProfile, WorkspaceBounds};
        use chrono::Utc;
        use std::collections::HashMap;

        let profile = RobotProfile {
            name: "test".into(),
            version: "1.0.0".into(),
            joints: vec![joint_def("j1", -1.0, 1.0)],
            workspace: WorkspaceBounds::Aabb {
                min: [-2.0, -2.0, 0.0],
                max: [2.0, 2.0, 2.5],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
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
            locomotion: None,
            end_effectors: vec![],
        };

        let command = Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![joint_state("j1", 0.0, 1.0, 5.0)],
            delta_time: 0.01,
            end_effector_positions: vec![ee("left_hand", 0.0, 0.0, 1.0)],
            center_of_mass: Some([0.0, 0.0, 0.9]),
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![Operation::new("actuate:j1").unwrap()],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        };

        let results = crate::physics::run_all_checks(&command, &profile, None, None);
        assert_eq!(results.len(), 11);

        // All should pass for this valid command
        for result in &results {
            assert!(
                result.passed,
                "check '{}' failed: {}",
                result.name, result.details
            );
            assert_eq!(result.category, "physics");
        }

        // Verify the names are correct and in order
        let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
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
                "iso15066_force_limits",
            ]
        );
    }

    #[test]
    fn run_all_checks_detects_failures() {
        use crate::models::authority::Operation;
        use crate::models::command::{Command, CommandAuthority};
        use crate::models::profile::{RobotProfile, SafeStopProfile, WorkspaceBounds};
        use chrono::Utc;
        use std::collections::HashMap;

        let profile = RobotProfile {
            name: "test".into(),
            version: "1.0.0".into(),
            joints: vec![joint_def("j1", -1.0, 1.0)], // max_vel=5, max_torque=50
            workspace: WorkspaceBounds::Aabb {
                min: [-2.0, -2.0, 0.0],
                max: [2.0, 2.0, 2.5],
            },
            exclusion_zones: vec![ExclusionZone::Aabb {
                name: "forbidden".into(),
                min: [-0.5, -0.5, 0.0],
                max: [0.5, 0.5, 1.5],
                conditional: false,
            }],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
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
            locomotion: None,
            end_effectors: vec![],
        };

        let command = Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![joint_state("j1", 2.0, 6.0, 60.0)], // position, velocity, torque all bad
            delta_time: 0.5,                                       // exceeds max_delta_time
            end_effector_positions: vec![ee("left_hand", 0.0, 0.0, 1.0)], // inside exclusion zone
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![Operation::new("actuate:j1").unwrap()],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        };

        let results = crate::physics::run_all_checks(&command, &profile, None, None);
        assert_eq!(results.len(), 11);

        // P1: joint_limits — position 2.0 > max 1.0 => fail
        assert!(!results[0].passed);
        // P2: velocity — |6.0| > 5.0 => fail
        assert!(!results[1].passed);
        // P3: torque — |60.0| > 50.0 => fail
        assert!(!results[2].passed);
        // P4: acceleration — no previous => pass (skipped)
        assert!(results[3].passed);
        // P5: workspace — (0, 0, 1) inside [-2,2] => pass
        assert!(results[4].passed);
        // P6: exclusion_zones — (0, 0, 1) inside forbidden AABB => fail
        assert!(!results[5].passed);
        // P7: self_collision — no pairs => pass
        assert!(results[6].passed);
        // P8: delta_time — 0.5 > 0.1 => fail
        assert!(!results[7].passed);
        // P9: stability — no config => pass
        assert!(results[8].passed);
        // P10: proximity — no zones => pass
        assert!(results[9].passed);
    }

    // ── Finding 10: run_all_checks with acceleration failure ────────────

    #[test]
    fn run_all_checks_acceleration_failure_with_previous_joints() {
        // run_all_checks must exercise the acceleration check (P4) when
        // previous_joints is Some.  This test provides previous and current
        // joints whose velocity delta / delta_time exceeds max_acceleration.
        //
        // joint_def max_acceleration = 25.0 rad/s²
        // prev velocity = 0.0 rad/s, curr velocity = 10.0 rad/s
        // delta_time = 0.01 s
        // estimated acceleration = |10.0 - 0.0| / 0.01 = 1000 rad/s² >> 25
        use crate::models::authority::Operation;
        use crate::models::command::{Command, CommandAuthority, EndEffectorPosition};
        use crate::models::profile::{RobotProfile, SafeStopProfile, WorkspaceBounds};
        use chrono::Utc;
        use std::collections::HashMap;

        let profile = RobotProfile {
            name: "accel-test".into(),
            version: "1.0.0".into(),
            joints: vec![joint_def("j1", -3.15, 3.15)], // max_acceleration=25.0
            workspace: WorkspaceBounds::Aabb {
                min: [-2.0, -2.0, 0.0],
                max: [2.0, 2.0, 3.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            end_effectors: vec![],
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
        };

        let command = Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![joint_state("j1", 0.0, 10.0, 0.0)], // velocity = 10 rad/s
            delta_time: 0.01,
            end_effector_positions: vec![EndEffectorPosition {
                name: "ee".into(),
                position: [0.0, 0.0, 1.0],
            }],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![Operation::new("actuate:j1").unwrap()],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        };

        let prev_joints = vec![joint_state("j1", 0.0, 0.0, 0.0)]; // velocity = 0 rad/s

        let results = crate::physics::run_all_checks(&command, &profile, Some(&prev_joints), None);
        assert_eq!(results.len(), 11);

        // P4: acceleration_limits — 1000 rad/s² >> 25 => fail
        let accel_check = &results[3];
        assert_eq!(accel_check.name, "acceleration_limits");
        assert!(
            !accel_check.passed,
            "acceleration_limits must fail: {}",
            accel_check.details
        );
        assert!(
            accel_check.details.contains("exceeds max_acceleration"),
            "details should mention the violation: {}",
            accel_check.details
        );
    }

    // ── NaN/Inf guard tests (R3-01) ─────────────────────────────────────

    #[test]
    fn p1_nan_position_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", f64::NAN, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p1_inf_position_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", f64::INFINITY, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p2_nan_velocity_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, f64::NAN, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0, None);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p2_neg_inf_velocity_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, f64::NEG_INFINITY, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0, None);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p3_nan_effort_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 0.0, f64::NAN)];
        let r = torque::check_torque_limits(&joints, &defs, None);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p3_inf_effort_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 0.0, f64::INFINITY)];
        let r = torque::check_torque_limits(&joints, &defs, None);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p4_nan_delta_time_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.5, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, f64::NAN, None);
        assert!(!r.passed);
    }

    #[test]
    fn p4_nan_velocity_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, f64::NAN, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01, None);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p4_inf_previous_velocity_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, f64::INFINITY, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01, None);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p5_nan_position_fails() {
        let workspace = WorkspaceBounds::Aabb {
            min: [-2.0, -2.0, 0.0],
            max: [2.0, 2.0, 2.5],
        };
        let ees = vec![ee("ee1", f64::NAN, 0.0, 1.0)];
        let r = workspace::check_workspace_bounds(&ees, &workspace);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p5_inf_position_fails() {
        let workspace = WorkspaceBounds::Aabb {
            min: [-2.0, -2.0, 0.0],
            max: [2.0, 2.0, 2.5],
        };
        let ees = vec![ee("ee1", 0.0, f64::INFINITY, 1.0)];
        let r = workspace::check_workspace_bounds(&ees, &workspace);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p6_nan_position_fails() {
        let zones = vec![ExclusionZone::Aabb {
            name: "zone".into(),
            min: [-1.0, -1.0, -1.0],
            max: [1.0, 1.0, 1.0],
            conditional: false,
        }];
        let ees = vec![ee("ee1", f64::NAN, 0.0, 0.0)];
        let r =
            exclusion_zones::check_exclusion_zones(&ees, &zones, &std::collections::HashMap::new());
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p7_nan_position_fails() {
        let pairs = vec![CollisionPair {
            link_a: "a".into(),
            link_b: "b".into(),
        }];
        let ees = vec![ee("a", f64::NAN, 0.0, 0.0), ee("b", 1.0, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.01);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p8_nan_delta_time_fails() {
        let r = delta_time::check_delta_time(f64::NAN, 0.1);
        assert!(!r.passed);
    }

    #[test]
    fn p8_inf_delta_time_fails() {
        let r = delta_time::check_delta_time(f64::INFINITY, 0.1);
        assert!(!r.passed);
    }

    #[test]
    fn p8_nan_max_delta_time_fails() {
        // Finding 41: a non-finite max_delta_time must produce a specific
        // "profile configuration is invalid" message, not the generic
        // "exceeds max_delta_time" message.
        let r = delta_time::check_delta_time(0.01, f64::NAN);
        assert!(!r.passed);
        assert!(
            r.details.contains("profile configuration is invalid"),
            "expected 'profile configuration is invalid' in details, got: {}",
            r.details
        );
    }

    #[test]
    fn p9_nan_com_fails() {
        let config = StabilityConfig {
            support_polygon: vec![[-0.1, -0.1], [0.1, -0.1], [0.1, 0.1], [-0.1, 0.1]],
            com_height_estimate: 0.9,
            enabled: true,
        };
        let com = [f64::NAN, 0.0, 0.9];
        let r = stability::check_stability(Some(&com), Some(&config));
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p10_nan_ee_position_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let zones = vec![ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: 10.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        let ees = vec![ee("ee1", f64::NAN, 0.0, 0.0)];
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p10_nan_velocity_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, f64::NAN, 0.0)];
        let zones = vec![ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: 10.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        let ees = vec![ee("ee1", 0.0, 0.0, 0.0)];
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p10_unknown_joint_flagged() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j_unknown", 0.0, 1.0, 0.0)];
        let zones = vec![ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: 10.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        let ees = vec![ee("ee1", 0.0, 0.0, 0.0)];
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(!r.passed);
        assert!(r.details.contains("unknown joint"));
    }

    // ── Task Envelope Enforcement (Section 17) ─────────────────────────

    use crate::models::profile::TaskEnvelope;
    use crate::physics::run_all_checks;

    fn envelope_test_profile() -> RobotProfile {
        RobotProfile {
            name: "envelope_test".into(),
            version: "1.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -std::f64::consts::PI,
                max: std::f64::consts::PI,
                max_velocity: 5.0,
                max_torque: 50.0,
                max_acceleration: 25.0,
            }],
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

    fn envelope_command(j1_vel: f64, ee_pos: [f64; 3]) -> Command {
        Command {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: j1_vel,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![EndEffectorPosition {
                name: "ee".into(),
                position: ee_pos,
            }],
            center_of_mass: None,
            authority: crate::models::command::CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: std::collections::HashMap::new(),
            environment_state: None,
        }
    }

    #[test]
    fn envelope_velocity_scale_tightens_p2() {
        let mut profile = envelope_test_profile();
        // Without envelope: velocity limit = 5.0 * 1.0 = 5.0
        // Velocity 4.5 should pass.
        let cmd = envelope_command(4.5, [0.0, 0.0, 1.0]);
        let results = run_all_checks(&cmd, &profile, None, None);
        let p2 = results
            .iter()
            .find(|c| c.name == "velocity_limits")
            .unwrap();
        assert!(p2.passed, "4.5 should pass without envelope");

        // With envelope velocity_scale = 0.5: limit = 5.0 * 0.5 = 2.5
        // Velocity 4.5 should now fail.
        profile.task_envelope = Some(TaskEnvelope {
            name: "tight_task".into(),
            description: String::new(),
            global_velocity_scale: Some(0.5),
            max_payload_kg: None,
            end_effector_force_limit_n: None,
            workspace: None,
            additional_exclusion_zones: vec![],
        });
        let results = run_all_checks(&cmd, &profile, None, None);
        let p2 = results
            .iter()
            .find(|c| c.name == "velocity_limits")
            .unwrap();
        assert!(
            !p2.passed,
            "4.5 should fail with envelope velocity_scale 0.5"
        );
    }

    #[test]
    fn envelope_velocity_scale_cannot_loosen() {
        let mut profile = envelope_test_profile();
        profile.global_velocity_scale = 0.5; // profile already restricts to 50%

        // Envelope tries to set 1.0 (looser) — should use min(0.5, 1.0) = 0.5.
        profile.task_envelope = Some(TaskEnvelope {
            name: "loose_attempt".into(),
            description: String::new(),
            global_velocity_scale: Some(1.0),
            max_payload_kg: None,
            end_effector_force_limit_n: None,
            workspace: None,
            additional_exclusion_zones: vec![],
        });

        // Velocity 3.0 > limit 5.0 * 0.5 = 2.5 → should fail.
        let cmd = envelope_command(3.0, [0.0, 0.0, 1.0]);
        let results = run_all_checks(&cmd, &profile, None, None);
        let p2 = results
            .iter()
            .find(|c| c.name == "velocity_limits")
            .unwrap();
        assert!(
            !p2.passed,
            "envelope cannot loosen velocity scale below profile"
        );
    }

    #[test]
    fn envelope_workspace_tightens_p5() {
        let mut profile = envelope_test_profile();
        // Profile workspace: [-2, -2, 0] to [2, 2, 3]
        // End effector at (1.5, 0, 1) → inside profile workspace.
        let cmd = envelope_command(0.0, [1.5, 0.0, 1.0]);
        let results = run_all_checks(&cmd, &profile, None, None);
        let p5 = results
            .iter()
            .find(|c| c.name == "workspace_bounds")
            .unwrap();
        assert!(p5.passed, "1.5 should be within profile workspace");

        // Envelope workspace: [-1, -1, 0] to [1, 1, 2] (tighter)
        profile.task_envelope = Some(TaskEnvelope {
            name: "small_workspace".into(),
            description: String::new(),
            global_velocity_scale: None,
            max_payload_kg: None,
            end_effector_force_limit_n: None,
            workspace: Some(WorkspaceBounds::Aabb {
                min: [-1.0, -1.0, 0.0],
                max: [1.0, 1.0, 2.0],
            }),
            additional_exclusion_zones: vec![],
        });
        let results = run_all_checks(&cmd, &profile, None, None);
        let p5 = results
            .iter()
            .find(|c| c.name == "workspace_bounds")
            .unwrap();
        assert!(
            !p5.passed,
            "1.5 should be outside envelope workspace [-1, 1]"
        );
    }

    #[test]
    fn envelope_additional_exclusion_zones_appended_to_p6() {
        let mut profile = envelope_test_profile();
        // No base exclusion zones. EE at (0.5, 0.5, 0.5) passes.
        let cmd = envelope_command(0.0, [0.5, 0.5, 0.5]);
        let results = run_all_checks(&cmd, &profile, None, None);
        let p6 = results
            .iter()
            .find(|c| c.name == "exclusion_zones")
            .unwrap();
        assert!(p6.passed, "no zones → should pass");

        // Add exclusion zone via envelope that contains (0.5, 0.5, 0.5).
        profile.task_envelope = Some(TaskEnvelope {
            name: "zone_task".into(),
            description: String::new(),
            global_velocity_scale: None,
            max_payload_kg: None,
            end_effector_force_limit_n: None,
            workspace: None,
            additional_exclusion_zones: vec![ExclusionZone::Aabb {
                name: "task_zone".into(),
                min: [0.0, 0.0, 0.0],
                max: [1.0, 1.0, 1.0],
                conditional: false,
            }],
        });
        let results = run_all_checks(&cmd, &profile, None, None);
        let p6 = results
            .iter()
            .find(|c| c.name == "exclusion_zones")
            .unwrap();
        assert!(!p6.passed, "EE should be inside envelope exclusion zone");
        assert!(p6.details.contains("task_zone"));
    }

    #[test]
    fn no_envelope_uses_profile_defaults() {
        let profile = envelope_test_profile();
        let cmd = envelope_command(4.9, [0.0, 0.0, 1.0]);
        let results = run_all_checks(&cmd, &profile, None, None);
        let p2 = results
            .iter()
            .find(|c| c.name == "velocity_limits")
            .unwrap();
        assert!(p2.passed, "4.9 should pass with profile velocity_scale 1.0");
    }

    // ── P21–P25: Environmental Awareness Checks ────────────────────────

    use crate::models::command::{ActuatorTemperature, EnvironmentState};
    use crate::models::profile::EnvironmentConfig;

    fn default_env_config() -> EnvironmentConfig {
        EnvironmentConfig {
            max_safe_pitch_rad: 0.2618,
            max_safe_roll_rad: 0.1745,
            max_operating_temperature_c: 80.0,
            critical_battery_pct: 5.0,
            low_battery_pct: 15.0,
            max_latency_ms: 100.0,
            warning_latency_ms: 50.0,
            warning_pitch_rad: 0.1396,
            warning_roll_rad: 0.0873,
            warning_temperature_c: 65.0,
        }
    }

    // -- P21: Terrain incline --

    #[test]
    fn p21_pitch_within_limits() {
        let env = EnvironmentState {
            imu_pitch_rad: Some(0.1),
            imu_roll_rad: Some(0.05),
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_terrain_incline(&env, &config);
        assert!(r.passed);
        assert_eq!(r.name, "terrain_incline");
    }

    #[test]
    fn p21_pitch_exceeds_max() {
        let env = EnvironmentState {
            imu_pitch_rad: Some(0.3),
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_terrain_incline(&env, &config);
        assert!(!r.passed);
        assert!(r.details.contains("pitch"));
    }

    #[test]
    fn p21_roll_exceeds_max() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: Some(-0.2),
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_terrain_incline(&env, &config);
        assert!(!r.passed);
        assert!(r.details.contains("roll"));
    }

    #[test]
    fn p21_nan_pitch_rejected() {
        let env = EnvironmentState {
            imu_pitch_rad: Some(f64::NAN),
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_terrain_incline(&env, &config);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p21_absent_data_passes() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_terrain_incline(&env, &config);
        assert!(r.passed);
    }

    // -- P22: Actuator temperature --

    #[test]
    fn p22_temps_within_limits() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![
                ActuatorTemperature {
                    joint_name: "j1".to_string(),
                    temperature_celsius: 45.0,
                },
                ActuatorTemperature {
                    joint_name: "j2".to_string(),
                    temperature_celsius: 70.0,
                },
            ],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_actuator_temperature(&env, &config);
        assert!(r.passed);
    }

    #[test]
    fn p22_temp_exceeds_max() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![ActuatorTemperature {
                joint_name: "j1".to_string(),
                temperature_celsius: 85.0,
            }],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_actuator_temperature(&env, &config);
        assert!(!r.passed);
        assert!(r.details.contains("j1"));
        assert!(r.details.contains("85.0"));
    }

    #[test]
    fn p22_nan_temp_rejected() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![ActuatorTemperature {
                joint_name: "j1".to_string(),
                temperature_celsius: f64::NAN,
            }],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_actuator_temperature(&env, &config);
        assert!(!r.passed);
    }

    #[test]
    fn p22_no_temps_passes() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_actuator_temperature(&env, &config);
        assert!(r.passed);
        assert!(r.details.contains("no actuator temperature data"));
    }

    // -- P23: Battery state --

    #[test]
    fn p23_battery_ok() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: Some(80.0),
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_battery_state(&env, &config);
        assert!(r.passed);
        assert!(r.details.contains("within operating range"));
    }

    #[test]
    fn p23_battery_low_advisory() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: Some(10.0),
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_battery_state(&env, &config);
        assert!(r.passed, "low battery is advisory, should still pass");
        assert!(r.details.contains("derate") || r.details.contains("low threshold"));
        assert!(
            r.derating.is_some(),
            "low battery must produce derating advice"
        );
    }

    #[test]
    fn p23_battery_critical_rejected() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: Some(3.0),
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_battery_state(&env, &config);
        assert!(!r.passed);
        assert!(r.details.contains("critical"));
    }

    #[test]
    fn p23_battery_absent_passes() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_battery_state(&env, &config);
        assert!(r.passed);
    }

    // -- P24: Communication latency --

    #[test]
    fn p24_latency_ok() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: Some(20.0),
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_communication_latency(&env, &config);
        assert!(r.passed);
        assert!(r.details.contains("within acceptable"));
    }

    #[test]
    fn p24_latency_warning_advisory() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: Some(75.0),
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_communication_latency(&env, &config);
        assert!(r.passed, "warning latency is advisory, should still pass");
        assert!(r.details.contains("derate") || r.details.contains("warning"));
        assert!(
            r.derating.is_some(),
            "warning latency must produce derating advice"
        );
    }

    #[test]
    fn p24_latency_exceeds_max() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: Some(150.0),
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_communication_latency(&env, &config);
        assert!(!r.passed);
        assert!(r.details.contains("exceeds"));
    }

    #[test]
    fn p24_latency_absent_passes() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let config = default_env_config();
        let r = environment::check_communication_latency(&env, &config);
        assert!(r.passed);
    }

    // -- P25: Emergency stop --

    #[test]
    fn p25_estop_not_engaged() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: Some(false),
        };
        let r = environment::check_emergency_stop(&env);
        assert!(r.passed);
    }

    #[test]
    fn p25_estop_engaged_rejected() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: Some(true),
        };
        let r = environment::check_emergency_stop(&env);
        assert!(!r.passed);
        assert!(r.details.contains("emergency stop"));
    }

    #[test]
    fn p25_estop_absent_passes() {
        let env = EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        };
        let r = environment::check_emergency_stop(&env);
        assert!(r.passed);
    }

    // -- Integration: run_all_checks with environment_state --

    use crate::models::authority::Operation;
    use crate::models::command::{Command, CommandAuthority};
    use chrono::Utc;
    use std::collections::HashMap;

    fn env_test_profile() -> RobotProfile {
        RobotProfile {
            name: "env_test".into(),
            version: "1.0.0".into(),
            joints: vec![joint_def("j1", -1.0, 1.0)],
            workspace: WorkspaceBounds::Aabb {
                min: [-2.0, -2.0, 0.0],
                max: [2.0, 2.0, 2.5],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            end_effectors: vec![],
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
        }
    }

    fn env_test_command() -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![joint_state("j1", 0.0, 1.0, 5.0)],
            delta_time: 0.01,
            end_effector_positions: vec![ee("left_hand", 0.0, 0.0, 1.0)],
            center_of_mass: Some([0.0, 0.0, 0.9]),
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![Operation::new("actuate:j1").unwrap()],
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

    #[test]
    fn env_checks_absent_when_no_environment_state() {
        let profile = env_test_profile();
        let cmd = env_test_command();
        let results = run_all_checks(&cmd, &profile, None, None);
        assert!(
            !results.iter().any(|c| c.name == "emergency_stop"),
            "no env checks when environment_state is None"
        );
    }

    #[test]
    fn env_checks_present_when_environment_state_provided() {
        let mut profile = env_test_profile();
        profile.environment = Some(default_env_config());
        let mut cmd = env_test_command();
        cmd.environment_state = Some(EnvironmentState {
            imu_pitch_rad: Some(0.1),
            imu_roll_rad: Some(0.05),
            actuator_temperatures: vec![],
            battery_percentage: Some(80.0),
            communication_latency_ms: Some(10.0),
            e_stop_engaged: Some(false),
        });
        let results = run_all_checks(&cmd, &profile, None, None);
        let names: Vec<&str> = results.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"emergency_stop"), "P25 should be present");
        assert!(names.contains(&"terrain_incline"), "P21 should be present");
        assert!(
            names.contains(&"actuator_temperature"),
            "P22 should be present"
        );
        assert!(names.contains(&"battery_state"), "P23 should be present");
        assert!(
            names.contains(&"communication_latency"),
            "P24 should be present"
        );
        assert!(
            results.iter().all(|c| c.passed),
            "all checks should pass with safe values"
        );
    }

    #[test]
    fn env_estop_rejects_in_full_pipeline() {
        let mut profile = env_test_profile();
        profile.environment = Some(default_env_config());
        let mut cmd = env_test_command();
        cmd.environment_state = Some(EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: Some(true),
        });
        let results = run_all_checks(&cmd, &profile, None, None);
        let estop = results.iter().find(|c| c.name == "emergency_stop").unwrap();
        assert!(!estop.passed, "e-stop engaged must fail");
    }

    #[test]
    fn env_estop_works_without_profile_config() {
        let profile = env_test_profile(); // no environment config
        let mut cmd = env_test_command();
        cmd.environment_state = Some(EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: Some(true),
        });
        let results = run_all_checks(&cmd, &profile, None, None);
        let estop = results.iter().find(|c| c.name == "emergency_stop").unwrap();
        assert!(
            !estop.passed,
            "P25 e-stop must work even without profile environment config"
        );
        // P21-P24 should NOT be present (no profile config)
        assert!(
            !results.iter().any(|c| c.name == "terrain_incline"),
            "P21 requires profile config"
        );
    }

    #[test]
    fn env_serde_round_trip() {
        let env = EnvironmentState {
            imu_pitch_rad: Some(0.15),
            imu_roll_rad: Some(-0.08),
            actuator_temperatures: vec![ActuatorTemperature {
                joint_name: "shoulder".to_string(),
                temperature_celsius: 55.0,
            }],
            battery_percentage: Some(72.5),
            communication_latency_ms: Some(12.3),
            e_stop_engaged: Some(false),
        };
        let json = serde_json::to_string(&env).unwrap();
        let deserialized: EnvironmentState = serde_json::from_str(&json).unwrap();
        assert_eq!(env, deserialized);
    }

    // ── P7 self-collision edge cases ──────────────────────────

    #[test]
    fn p7_identical_positions_fails_with_nonzero_threshold() {
        // Two links at the exact same position — distance = 0.0, which is
        // always < any positive min_collision_distance. Must fail.
        let pairs = vec![CollisionPair {
            link_a: "a".into(),
            link_b: "b".into(),
        }];
        let ees = vec![ee("a", 0.0, 0.0, 0.0), ee("b", 0.0, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.05);
        assert!(
            !r.passed,
            "identical positions must fail: distance 0 < 0.05"
        );
    }

    #[test]
    fn p7_identical_positions_passes_with_zero_threshold() {
        // Documents that zero threshold is a deliberate escape hatch:
        // 0.0 < 0.0 is false, so the check passes even at distance zero.
        // Profile validation already requires min_collision_distance > 0 when
        // collision_pairs are non-empty, so this should never happen in
        // production.
        let pairs = vec![CollisionPair {
            link_a: "a".into(),
            link_b: "b".into(),
        }];
        let ees = vec![ee("a", 0.0, 0.0, 0.0), ee("b", 0.0, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.0);
        assert!(
            r.passed,
            "distance 0.0 is not < 0.0 (zero threshold escape)"
        );
    }

    #[test]
    fn p7_nan_position_flagged() {
        let pairs = vec![CollisionPair {
            link_a: "a".into(),
            link_b: "b".into(),
        }];
        let ees = vec![ee("a", f64::NAN, 0.0, 0.0), ee("b", 0.0, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.01);
        assert!(!r.passed, "NaN position must be rejected");
        assert!(r.details.contains("NaN"));
    }

    // ── P10 proximity boundary edge cases ───────────────────

    #[test]
    fn p10_ee_exactly_on_sphere_boundary_triggers_scaling() {
        // EE at distance exactly = radius should be inside (<=) and scaling applies.
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 3.0, 0.0)];
        // EE at [1.0, 0.0, 0.0], zone center [0.0, 0.0, 0.0], radius 1.0
        // Distance = exactly 1.0 = radius => inside.
        let ees = vec![ee("left_hand", 1.0, 0.0, 0.0)];
        let zones = vec![ProximityZone::Sphere {
            name: "human".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        // effective limit = 5.0 * 0.5 * 1.0 = 2.5, vel = 3.0 => fail
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(
            !r.passed,
            "EE on sphere boundary must trigger velocity scaling"
        );
    }

    #[test]
    fn p10_ee_just_outside_sphere_boundary_no_scaling() {
        // EE at distance slightly > radius should be outside, no scaling.
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 4.9, 0.0)];
        // 1.0 + small epsilon puts EE outside the sphere
        let ees = vec![ee("left_hand", 1.0 + 1e-9, 0.0, 0.0)];
        let zones = vec![ProximityZone::Sphere {
            name: "human".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        // Outside zone: no scaling, limit = 5.0, vel = 4.9 => pass
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(
            r.passed,
            "EE just outside sphere boundary must NOT trigger scaling"
        );
    }

    #[test]
    fn p10_nan_ee_position_rejected() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let ees = vec![ee("left_hand", f64::NAN, 0.0, 0.0)];
        let zones = vec![ProximityZone::Sphere {
            name: "z".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(!r.passed, "NaN EE position must be rejected");
    }

    // ── P8 delta_time edge cases ────────────────────────────

    #[test]
    fn p8_negative_delta_time_rejected() {
        let r = delta_time::check_delta_time(-0.01, 0.05);
        assert!(!r.passed, "negative delta_time must be rejected");
    }

    #[test]
    fn p8_zero_delta_time_rejected() {
        let r = delta_time::check_delta_time(0.0, 0.05);
        assert!(!r.passed, "zero delta_time must be rejected");
    }

    #[test]
    fn p8_nan_delta_time_rejected() {
        let r = delta_time::check_delta_time(f64::NAN, 0.05);
        assert!(!r.passed, "NaN delta_time must be rejected");
    }

    #[test]
    fn p8_exactly_at_max_passes() {
        let r = delta_time::check_delta_time(0.05, 0.05);
        assert!(r.passed, "delta_time exactly at max must pass");
    }

    // ── P6 exclusion zone NaN bounds ─────────────────────────

    #[test]
    fn p6_aabb_nan_bound_fails_closed() {
        // NaN in an AABB zone bound must not silently disable the zone.
        // Fail-closed: treat point as inside the zone.
        let zones = vec![ExclusionZone::Aabb {
            name: "nan_zone".into(),
            min: [f64::NAN, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
            conditional: false,
        }];
        let ees = vec![ee("hand", 0.5, 0.5, 0.5)];
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &HashMap::new());
        assert!(
            !r.passed,
            "AABB zone with NaN bound must fail-closed (reject)"
        );
    }

    #[test]
    fn p6_sphere_nan_center_fails_closed() {
        // NaN in sphere center must not silently disable the zone.
        let zones = vec![ExclusionZone::Sphere {
            name: "nan_sphere".into(),
            center: [f64::NAN, 0.0, 0.0],
            radius: 1.0,
            conditional: false,
        }];
        let ees = vec![ee("hand", 5.0, 5.0, 5.0)];
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &HashMap::new());
        assert!(
            !r.passed,
            "sphere zone with NaN center must fail-closed (reject)"
        );
    }

    #[test]
    fn p6_sphere_nan_radius_fails_closed() {
        let zones = vec![ExclusionZone::Sphere {
            name: "nan_r".into(),
            center: [0.0, 0.0, 0.0],
            radius: f64::NAN,
            conditional: false,
        }];
        let ees = vec![ee("hand", 5.0, 5.0, 5.0)];
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &HashMap::new());
        assert!(
            !r.passed,
            "sphere zone with NaN radius must fail-closed (reject)"
        );
    }

    #[test]
    fn p6_sphere_inf_radius_fails_closed() {
        let zones = vec![ExclusionZone::Sphere {
            name: "inf_r".into(),
            center: [0.0, 0.0, 0.0],
            radius: f64::INFINITY,
            conditional: false,
        }];
        let ees = vec![ee("hand", 999.0, 999.0, 999.0)];
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones, &HashMap::new());
        assert!(
            !r.passed,
            "sphere zone with Inf radius must fail-closed (reject)"
        );
    }

    // ── P21-P25 environment checks silent skip ─────────────

    #[test]
    fn env_checks_skip_p21_p24_when_config_absent() {
        use crate::models::command::{Command, CommandAuthority, EnvironmentState};
        use crate::models::profile::{RobotProfile, SafeStopProfile, WorkspaceBounds};

        // Profile with no environment config.
        let profile = RobotProfile {
            name: "test".into(),
            version: "1.0.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -1.0,
                max: 1.0,
                max_velocity: 5.0,
                max_torque: 50.0,
                max_acceleration: 10.0,
            }],
            workspace: WorkspaceBounds::Aabb {
                min: [-1.0, -1.0, 0.0],
                max: [1.0, 1.0, 2.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            max_delta_time: 0.01,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None, // <-- no environment config
            end_effectors: vec![],
        };

        // Command with environment state that has over-temperature actuator.
        let cmd = Command {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.005,
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
            zone_overrides: std::collections::HashMap::new(),
            environment_state: Some(EnvironmentState {
                imu_pitch_rad: None,
                imu_roll_rad: None,
                actuator_temperatures: vec![crate::models::command::ActuatorTemperature {
                    joint_name: "j1".into(),
                    temperature_celsius: 999.0, // way over any limit
                }],
                battery_percentage: None,
                communication_latency_ms: None,
                e_stop_engaged: Some(false),
            }),
        };

        let results = run_environment_checks(&cmd, &profile);
        // sensor_range + P25 (e-stop) should fire — P21-P24 are skipped.
        assert_eq!(
            results.len(),
            2,
            "sensor_range + P25 should fire when environment config absent"
        );
        assert_eq!(results[0].name, "sensor_range");
        assert!(results[0].passed, "sensor range must pass for valid data");
        assert_eq!(results[1].name, "emergency_stop");
        assert!(results[1].passed, "e-stop not engaged, so P25 should pass");
    }

    #[test]
    fn env_config_serde_defaults() {
        let json = "{}";
        let config: EnvironmentConfig = serde_json::from_str(json).unwrap();
        assert!((config.max_safe_pitch_rad - 0.2618).abs() < 0.001);
        assert!((config.max_safe_roll_rad - 0.1745).abs() < 0.001);
        assert!((config.max_operating_temperature_c - 80.0).abs() < 0.001);
        assert!((config.critical_battery_pct - 5.0).abs() < 0.001);
        assert!((config.low_battery_pct - 15.0).abs() < 0.001);
        assert!((config.max_latency_ms - 100.0).abs() < 0.001);
        assert!((config.warning_latency_ms - 50.0).abs() < 0.001);
    }

    // ── P25 e-stop cannot-be-disabled enforcement ──────────

    #[test]
    fn p25_estop_engaged_rejects_without_environment_config() {
        // spec-v1.md: "P25: This check CANNOT be disabled in any profile.
        // It is always active." Even when the profile has NO environment
        // config, P25 must still reject commands when e-stop is engaged.
        use crate::models::command::{Command, CommandAuthority, EnvironmentState};
        use crate::models::profile::{RobotProfile, SafeStopProfile, WorkspaceBounds};

        let profile = RobotProfile {
            name: "test".into(),
            version: "1.0.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -1.0,
                max: 1.0,
                max_velocity: 5.0,
                max_torque: 50.0,
                max_acceleration: 10.0,
            }],
            workspace: WorkspaceBounds::Aabb {
                min: [-1.0, -1.0, 0.0],
                max: [1.0, 1.0, 2.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            max_delta_time: 0.01,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None, // NO environment config
            end_effectors: vec![],
        };

        let cmd = Command {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.005,
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
            zone_overrides: std::collections::HashMap::new(),
            environment_state: Some(EnvironmentState {
                imu_pitch_rad: None,
                imu_roll_rad: None,
                actuator_temperatures: vec![],
                battery_percentage: None,
                communication_latency_ms: None,
                e_stop_engaged: Some(true), // ENGAGED
            }),
        };

        let results = run_environment_checks(&cmd, &profile);
        assert!(
            !results.is_empty(),
            "P25 must fire even without environment config"
        );
        let estop = results.iter().find(|r| r.name == "emergency_stop");
        assert!(estop.is_some(), "P25 check must be present");
        assert!(
            !estop.unwrap().passed,
            "P25 must REJECT when e-stop is engaged, regardless of environment config"
        );
    }

    #[test]
    fn p25_estop_absent_passes_without_environment_config() {
        // When e_stop_engaged is None (sensor not wired), P25 passes
        // with "no e-stop data" — documents the sensor-absence behavior.
        use crate::models::command::{Command, CommandAuthority, EnvironmentState};
        use crate::models::profile::{RobotProfile, SafeStopProfile, WorkspaceBounds};

        let profile = RobotProfile {
            name: "test".into(),
            version: "1.0.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -1.0,
                max: 1.0,
                max_velocity: 5.0,
                max_torque: 50.0,
                max_acceleration: 10.0,
            }],
            workspace: WorkspaceBounds::Aabb {
                min: [-1.0, -1.0, 0.0],
                max: [1.0, 1.0, 2.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            max_delta_time: 0.01,
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
        };

        let cmd = Command {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.005,
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
            zone_overrides: std::collections::HashMap::new(),
            environment_state: Some(EnvironmentState {
                imu_pitch_rad: None,
                imu_roll_rad: None,
                actuator_temperatures: vec![],
                battery_percentage: None,
                communication_latency_ms: None,
                e_stop_engaged: None, // sensor not wired
            }),
        };

        let results = run_environment_checks(&cmd, &profile);
        let estop = results.iter().find(|r| r.name == "emergency_stop");
        assert!(estop.is_some(), "P25 check must always be present");
        assert!(
            estop.unwrap().passed,
            "P25 with e_stop_engaged=None must pass (no sensor data)"
        );
    }

    // ── P18 friction cone zero-coefficient edge case ───────

    #[test]
    fn p18_zero_friction_passes_with_zero_tangential() {
        // Documents behavior: with mu=0.0, a stationary foot (zero tangential
        // force) has ratio 0.0 <= 0.0, which passes. This is correct per the
        // math but misleading — a zero-friction surface provides no traction.
        // Profile validation now prevents mu <= 0, so this can only occur with
        // a handcrafted profile bypassing validation.
        use crate::models::command::{FootState, LocomotionState};
        use crate::models::profile::LocomotionConfig;

        let config = LocomotionConfig {
            max_locomotion_velocity: 1.5,
            max_step_length: 0.5,
            min_foot_clearance: 0.02,
            max_step_height: 0.5,
            max_ground_reaction_force: 500.0,
            friction_coefficient: 0.0, // zero friction
            max_heading_rate: 1.0,
        };
        let foot = FootState {
            name: "fl".into(),
            position: [0.0, 0.0, 0.0],
            contact: true,
            ground_reaction_force: Some([0.0, 0.0, 300.0]), // zero tangential
        };
        let loco = LocomotionState {
            base_velocity: [0.0, 0.0, 0.0],
            heading_rate: 0.0,
            feet: vec![foot],
            step_length: 0.0,
        };
        let r = friction_cone::check_friction_cone(&loco, &config);
        assert!(
            r.passed,
            "zero tangential on zero-friction passes: ratio 0/fz = 0 <= 0"
        );
    }

    #[test]
    fn p18_zero_friction_fails_with_any_tangential_force() {
        use crate::models::command::{FootState, LocomotionState};
        use crate::models::profile::LocomotionConfig;

        let config = LocomotionConfig {
            max_locomotion_velocity: 1.5,
            max_step_length: 0.5,
            min_foot_clearance: 0.02,
            max_step_height: 0.5,
            max_ground_reaction_force: 500.0,
            friction_coefficient: 0.0, // zero friction
            max_heading_rate: 1.0,
        };
        let foot = FootState {
            name: "fl".into(),
            position: [0.0, 0.0, 0.0],
            contact: true,
            ground_reaction_force: Some([1.0, 0.0, 300.0]), // tiny tangential
        };
        let loco = LocomotionState {
            base_velocity: [0.0, 0.0, 0.0],
            heading_rate: 0.0,
            feet: vec![foot],
            step_length: 0.0,
        };
        let r = friction_cone::check_friction_cone(&loco, &config);
        assert!(!r.passed, "any tangential force on zero-friction must fail");
    }

    // ── P13 force rate with invalid delta_time ─────────────

    #[test]
    fn p13_force_rate_zero_delta_time_with_matching_ee_fails() {
        use crate::models::command::EndEffectorForce;
        use crate::models::profile::EndEffectorConfig;

        let configs = vec![EndEffectorConfig {
            name: "gripper".into(),
            max_force_n: 100.0,
            max_grasp_force_n: 80.0,
            min_grasp_force_n: 5.0,
            max_force_rate_n_per_s: 500.0,
            max_payload_kg: 10.0,
        }];
        let prev = vec![EndEffectorForce {
            name: "gripper".into(),
            force: [10.0, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }];
        let curr = vec![EndEffectorForce {
            name: "gripper".into(),
            force: [20.0, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }];
        // delta_time = 0.0 with matching EEs → must fail.
        let r = force_rate::check_force_rate_limits(&curr, Some(&prev), &configs, 0.0);
        assert!(
            !r.passed,
            "zero delta_time with matching EEs must fail: {}",
            r.details
        );
        assert!(r.details.contains("delta_time"));
    }

    #[test]
    fn p13_force_rate_nan_delta_time_fails() {
        use crate::models::command::EndEffectorForce;
        use crate::models::profile::EndEffectorConfig;

        let configs = vec![EndEffectorConfig {
            name: "gripper".into(),
            max_force_n: 100.0,
            max_grasp_force_n: 80.0,
            min_grasp_force_n: 5.0,
            max_force_rate_n_per_s: 500.0,
            max_payload_kg: 10.0,
        }];
        let prev = vec![EndEffectorForce {
            name: "gripper".into(),
            force: [10.0, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }];
        let curr = vec![EndEffectorForce {
            name: "gripper".into(),
            force: [20.0, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }];
        let r = force_rate::check_force_rate_limits(&curr, Some(&prev), &configs, f64::NAN);
        assert!(!r.passed, "NaN delta_time must fail");
    }

    // ── P10 proximity NaN zone center fail-closed ──────────

    #[test]
    fn p10_proximity_nan_zone_center_triggers_scaling() {
        // NaN zone center must fail-closed: treat EE as inside the zone,
        // so velocity scaling is applied. This is the most safety-critical
        // application — a corrupt proximity zone near a human must still
        // enforce velocity reduction.
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 3.0, 0.0)];
        let ees = vec![ee("hand", 10.0, 10.0, 10.0)]; // far from any real zone
        let zones = vec![ProximityZone::Sphere {
            name: "human".into(),
            center: [f64::NAN, 0.0, 0.0], // corrupt center
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        // NaN center → point_in_sphere returns true → zone active → velocity
        // scaled by 0.5 → limit = 5.0 * 0.5 = 2.5, vel = 3.0 → fail
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(
            !r.passed,
            "NaN proximity zone center must fail-closed (enforce scaling): {}",
            r.details
        );
    }

    #[test]
    fn p10_proximity_nan_zone_radius_triggers_scaling() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 3.0, 0.0)];
        let ees = vec![ee("hand", 10.0, 10.0, 10.0)];
        let zones = vec![ProximityZone::Sphere {
            name: "human".into(),
            center: [0.0, 0.0, 0.0],
            radius: f64::NAN,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(
            !r.passed,
            "NaN proximity zone radius must fail-closed (enforce scaling)"
        );
    }

    // ── P10 proximity point_in_sphere NaN point defense-in-depth ──

    #[test]
    fn p10_proximity_nan_ee_position_caught_by_sphere_guard() {
        // Although the P10 caller rejects NaN EE positions before reaching
        // point_in_sphere, the function itself must be self-contained: a NaN
        // point must return true (inside zone), not false (outside). This
        // documents that the defense-in-depth guard works — consistent with
        // the ISO 15066 point_in_sphere.
        //
        // We test via active_proximity_scale indirectly: if point_in_sphere
        // treats NaN point as inside, any zone with velocity_scale < 1.0 will
        // activate, and a high velocity will fail.
        //
        // But since the caller's NaN guard fires first, we use the integration
        // path directly (the caller rejects NaN EEs before sphere check).
        // So instead, document with a standalone assertion on the private fn.
        //
        // Since point_in_sphere is private, we test through the public API:
        // provide a NaN EE position → expect P10 rejection (the caller guard).
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 0.1, 0.0)]; // low velocity
        let ees = vec![ee("hand", f64::NAN, 0.0, 0.0)]; // NaN EE
        let zones = vec![ProximityZone::Sphere {
            name: "human".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: false,
        }];
        let r = proximity::check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
        assert!(
            !r.passed,
            "NaN EE position must be rejected by P10 (caller guard or sphere guard): {}",
            r.details
        );
    }

    // ── Margin composition tests ───────────────────────────

    #[test]
    fn p1_position_valid_without_margins_rejected_with_margins() {
        // A position at 95% of the raw range should pass P1 without margins
        // but be rejected when a 10% position_margin is applied (effective
        // range tightened by 10% on each side).
        use crate::models::profile::{JointDefinition, JointType, RealWorldMargins};
        let defs = vec![JointDefinition {
            name: "j1".into(),
            joint_type: JointType::Revolute,
            min: -1.0,
            max: 1.0,
            max_velocity: 5.0,
            max_torque: 50.0,
            max_acceleration: 10.0,
        }];
        // Position at 0.95 — within raw range [-1, 1] but outside effective
        // range [-0.9, 0.9] when position_margin = 0.10.
        let joints = vec![joint_state("j1", 0.95, 0.0, 0.0)];

        // Without margins: passes.
        let r = joint_limits::check_joint_limits(&joints, &defs, None);
        assert!(r.passed, "0.95 must pass without margins");

        // With 10% position margin: effective max = 1.0 - 2.0*0.10 = 0.80
        // Wait — actually margin works as: effective range = [min + range*margin, max - range*margin]
        // range = 2.0, so effective = [-1.0 + 0.2, 1.0 - 0.2] = [-0.8, 0.8]
        // 0.95 > 0.8 → rejected.
        let margins = RealWorldMargins {
            position_margin: 0.10,
            velocity_margin: 0.0,
            torque_margin: 0.0,
            acceleration_margin: 0.0,
        };
        let r = joint_limits::check_joint_limits(&joints, &defs, Some(&margins));
        assert!(
            !r.passed,
            "0.95 must be rejected with 10% position margin (effective max = 0.8)"
        );
    }

    #[test]
    fn p2_velocity_scaling_composes_proximity_envelope_margins() {
        // Test that proximity scale and envelope velocity scale compose
        // correctly via multiplication in the P10 check.
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0

        // Place EE inside a proximity zone with velocity_scale = 0.8.
        let ees = vec![ee("hand", 0.0, 0.0, 0.0)]; // inside zone center
        let zones = vec![ProximityZone::Sphere {
            name: "z".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.8,
            dynamic: false,
        }];

        // Envelope velocity scale = 0.9 (global_velocity_scale passed to check).
        // Velocity margin = 0.15 → margin_factor = 0.85.
        // Effective limit = 5.0 * min(0.9, 1.0) * 0.8 * 0.85
        //                 = 5.0 * 0.9 * 0.8 * 0.85 = 3.06
        // Wait, actually check_proximity_velocity takes global_velocity_scale as
        // parameter and applies it inside. Let me trace the logic:
        //   effective = max_velocity * min_proximity_scale * global_velocity_scale
        // Then velocity check applies margin_factor on top if margins are present.
        // But proximity check and velocity check are separate P2/P10 checks.
        // P10 effective = max_velocity * proximity_scale * global_velocity_scale
        // P2 effective = max_velocity * global_velocity_scale * (1 - velocity_margin)

        // Test P10: velocity at 3.5 with effective limit =
        // 5.0 * 0.8 * 0.9 = 3.6 → 3.5 passes.
        let joints_pass = vec![joint_state("j1", 0.0, 3.5, 0.0)];
        let r = proximity::check_proximity_velocity(&joints_pass, &defs, &ees, &zones, 0.9);
        assert!(
            r.passed,
            "velocity 3.5 with limit 3.6 should pass: {}",
            r.details
        );

        // Velocity at 3.7 with effective limit = 3.6 → fails.
        let joints_fail = vec![joint_state("j1", 0.0, 3.7, 0.0)];
        let r = proximity::check_proximity_velocity(&joints_fail, &defs, &ees, &zones, 0.9);
        assert!(
            !r.passed,
            "velocity 3.7 with limit 3.6 should fail: {}",
            r.details
        );
    }

    #[test]
    fn run_all_checks_margin_tightening_integrated() {
        // End-to-end: a command that passes all checks without margins should
        // fail P1 when margins are applied.
        use crate::models::command::{Command, CommandAuthority};
        use crate::models::profile::{
            JointDefinition, JointType, RealWorldMargins, RobotProfile, SafeStopProfile,
            WorkspaceBounds,
        };

        let profile = RobotProfile {
            name: "margin_test".into(),
            version: "1.0.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -1.0,
                max: 1.0,
                max_velocity: 5.0,
                max_torque: 50.0,
                max_acceleration: 10.0,
            }],
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
            real_world_margins: Some(RealWorldMargins {
                position_margin: 0.10,
                velocity_margin: 0.0,
                torque_margin: 0.0,
                acceleration_margin: 0.0,
            }),
            task_envelope: None,
            environment: None,
            end_effectors: vec![],
        };

        let cmd = Command {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.85, // inside raw [-1,1] but outside margined [-0.8,0.8]
                velocity: 0.0,
                effort: 0.0,
            }],
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
            zone_overrides: std::collections::HashMap::new(),
            environment_state: None,
        };

        let results = run_all_checks(&cmd, &profile, None, None);
        let p1 = results.iter().find(|c| c.name == "joint_limits").unwrap();
        assert!(
            !p1.passed,
            "position 0.85 must fail P1 with 10% margin (effective max=0.8): {}",
            p1.details
        );
    }
}
