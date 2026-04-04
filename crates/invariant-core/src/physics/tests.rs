#[cfg(test)]
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
            effort: effort,
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
    fn p9_no_com_data_passes() {
        let config = StabilityConfig {
            support_polygon: vec![[-0.15, -0.1], [0.15, -0.1], [0.15, 0.1], [-0.15, 0.1]],
            com_height_estimate: 0.9,
            enabled: true,
        };
        let r = stability::check_stability(None, Some(&config));
        assert!(r.passed);
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

        let results = crate::physics::run_all_checks(&command, &profile, None);
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

        let results = crate::physics::run_all_checks(&command, &profile, None);
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

        let results = crate::physics::run_all_checks(&command, &profile, Some(&prev_joints));
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
                min: -3.14,
                max: 3.14,
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
        assert!(r.details.contains("advisory"));
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
        assert!(r.details.contains("advisory"));
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
        let results = run_all_checks(&cmd, &profile, None);
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
}
