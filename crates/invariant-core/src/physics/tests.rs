#[cfg(test)]
mod tests {
    use crate::models::command::{EndEffectorPosition, JointState};
    use crate::models::profile::{
        CollisionPair, ExclusionZone, JointDefinition, JointType, ProximityZone,
        StabilityConfig, WorkspaceBounds,
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
        let joints = vec![joint_state("j1", 0.0, 0.0, 0.0), joint_state("j2", 1.5, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs);
        assert!(r.passed);
        assert_eq!(r.name, "joint_limits");
        assert_eq!(r.category, "physics");
    }

    #[test]
    fn p1_at_exact_boundary() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 1.0, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs);
        assert!(r.passed);

        let joints_min = vec![joint_state("j1", -1.0, 0.0, 0.0)];
        let r2 = joint_limits::check_joint_limits(&joints_min, &defs);
        assert!(r2.passed);
    }

    #[test]
    fn p1_exceeds_max() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 1.001, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs);
        assert!(!r.passed);
        assert!(r.details.contains("j1"));
    }

    #[test]
    fn p1_below_min() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", -1.001, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs);
        assert!(!r.passed);
    }

    #[test]
    fn p1_unknown_joint() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j_unknown", 0.0, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs);
        assert!(!r.passed);
        assert!(r.details.contains("unknown joint"));
    }

    #[test]
    fn p1_empty_joints_passes() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let r = joint_limits::check_joint_limits(&[], &defs);
        assert!(r.passed);
    }

    #[test]
    fn p1_multiple_violations() {
        let defs = vec![joint_def("j1", -1.0, 1.0), joint_def("j2", -0.5, 0.5)];
        let joints = vec![joint_state("j1", 2.0, 0.0, 0.0), joint_state("j2", -1.0, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs);
        assert!(!r.passed);
        assert!(r.details.contains("j1"));
        assert!(r.details.contains("j2"));
    }

    // ── P2: Velocity limits ─────────────────────────────────────────────

    #[test]
    fn p2_within_limits() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 4.9, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0);
        assert!(r.passed);
    }

    #[test]
    fn p2_exceeds_limit() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 5.1, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0);
        assert!(!r.passed);
        assert!(r.details.contains("j1"));
    }

    #[test]
    fn p2_negative_velocity() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, -5.1, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0);
        assert!(!r.passed);
    }

    #[test]
    fn p2_scaled_velocity() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 3.0, 0.0)];
        // With scale 0.5, effective limit = 5.0 * 0.5 = 2.5
        let r = velocity::check_velocity_limits(&joints, &defs, 0.5);
        assert!(!r.passed);

        // With scale 1.0, 3.0 <= 5.0 passes
        let r2 = velocity::check_velocity_limits(&joints, &defs, 1.0);
        assert!(r2.passed);
    }

    #[test]
    fn p2_at_exact_boundary() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_velocity = 5.0
        let joints = vec![joint_state("j1", 0.0, 5.0, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0);
        assert!(r.passed);
    }

    // ── P3: Torque limits ───────────────────────────────────────────────

    #[test]
    fn p3_within_limits() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_torque = 50.0
        let joints = vec![joint_state("j1", 0.0, 0.0, 49.9)];
        let r = torque::check_torque_limits(&joints, &defs);
        assert!(r.passed);
    }

    #[test]
    fn p3_exceeds_limit() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_torque = 50.0
        let joints = vec![joint_state("j1", 0.0, 0.0, 50.1)];
        let r = torque::check_torque_limits(&joints, &defs);
        assert!(!r.passed);
    }

    #[test]
    fn p3_negative_effort() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 0.0, -50.1)];
        let r = torque::check_torque_limits(&joints, &defs);
        assert!(!r.passed);
    }

    #[test]
    fn p3_at_exact_boundary() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_torque = 50.0
        let joints = vec![joint_state("j1", 0.0, 0.0, 50.0)];
        let r = torque::check_torque_limits(&joints, &defs);
        assert!(r.passed);
    }

    // ── P4: Acceleration limits ─────────────────────────────────────────

    #[test]
    fn p4_no_previous_passes() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 5.0, 0.0)];
        let r = acceleration::check_acceleration_limits(&joints, None, &defs, 0.01);
        assert!(r.passed);
        assert!(r.details.contains("first command"));
    }

    #[test]
    fn p4_within_limits() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_acceleration = 25.0
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.2, 0.0)]; // accel = 0.2/0.01 = 20.0
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p4_exceeds_limit() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_acceleration = 25.0
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.3, 0.0)]; // accel = 0.3/0.01 = 30.0
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01);
        assert!(!r.passed);
    }

    #[test]
    fn p4_zero_delta_time_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.1, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.0);
        assert!(!r.passed);
        assert!(r.details.contains("non-positive"));
    }

    #[test]
    fn p4_negative_delta_time_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.1, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, -0.01);
        assert!(!r.passed);
    }

    #[test]
    fn p4_missing_previous_joint_flagged() {
        let defs = vec![joint_def("j1", -1.0, 1.0), joint_def("j2", -1.0, 1.0)];
        // j2 appears in current but not in previous — should be flagged as violation
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![
            joint_state("j1", 0.0, 1.1, 0.0), // accel = 10, within 25
            joint_state("j2", 0.0, 100.0, 0.0), // no prev data — flagged
        ];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01);
        assert!(!r.passed);
        assert!(r.details.contains("j2"));
        assert!(r.details.contains("no previous joint state"));
    }

    #[test]
    fn p4_deceleration() {
        let defs = vec![joint_def("j1", -1.0, 1.0)]; // max_acceleration = 25.0
        let prev = vec![joint_state("j1", 0.0, 5.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 4.7, 0.0)]; // accel = 0.3/0.01 = 30.0
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01);
        assert!(!r.passed); // deceleration also checked
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
    fn p5_empty_end_effectors_passes() {
        let ws = WorkspaceBounds::Aabb {
            min: [-2.0, -2.0, 0.0],
            max: [2.0, 2.0, 2.5],
        };
        let r = workspace::check_workspace_bounds(&[], &ws);
        assert!(r.passed);
    }

    // ── P6: Exclusion zones ─────────────────────────────────────────────

    #[test]
    fn p6_not_in_any_zone() {
        let zones = vec![ExclusionZone::Aabb {
            name: "operator".into(),
            min: [1.0, -0.5, 0.0],
            max: [3.0, 0.5, 2.0],
        }];
        let ees = vec![ee("left_hand", -1.0, 0.0, 1.0)]; // outside zone
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones);
        assert!(r.passed);
    }

    #[test]
    fn p6_inside_aabb_zone() {
        let zones = vec![ExclusionZone::Aabb {
            name: "operator".into(),
            min: [1.0, -0.5, 0.0],
            max: [3.0, 0.5, 2.0],
        }];
        let ees = vec![ee("left_hand", 2.0, 0.0, 1.0)]; // inside zone
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones);
        assert!(!r.passed);
        assert!(r.details.contains("operator"));
    }

    #[test]
    fn p6_inside_sphere_zone() {
        let zones = vec![ExclusionZone::Sphere {
            name: "head".into(),
            center: [0.0, 0.0, 1.7],
            radius: 0.3,
        }];
        let ees = vec![ee("left_hand", 0.0, 0.0, 1.7)]; // at center
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones);
        assert!(!r.passed);
    }

    #[test]
    fn p6_outside_sphere_zone() {
        let zones = vec![ExclusionZone::Sphere {
            name: "head".into(),
            center: [0.0, 0.0, 1.7],
            radius: 0.3,
        }];
        let ees = vec![ee("left_hand", 0.0, 0.0, 2.1)]; // distance = 0.4 > 0.3
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones);
        assert!(r.passed);
    }

    #[test]
    fn p6_on_sphere_boundary() {
        let zones = vec![ExclusionZone::Sphere {
            name: "head".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
        }];
        let ees = vec![ee("left_hand", 1.0, 0.0, 0.0)]; // on surface
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones);
        assert!(!r.passed); // on boundary = inside
    }

    #[test]
    fn p6_empty_zones_passes() {
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0)];
        let r = exclusion_zones::check_exclusion_zones(&ees, &[]);
        assert!(r.passed);
    }

    #[test]
    fn p6_empty_end_effectors_passes() {
        let zones = vec![ExclusionZone::Aabb {
            name: "operator".into(),
            min: [0.0, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
        }];
        let r = exclusion_zones::check_exclusion_zones(&[], &zones);
        assert!(r.passed);
    }

    // ── P7: Self-collision ──────────────────────────────────────────────

    #[test]
    fn p7_far_apart_passes() {
        let pairs = vec![CollisionPair { link_a: "left_hand".into(), link_b: "head".into() }];
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0), ee("head", 1.0, 1.0, 1.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p7_too_close_fails() {
        let pairs = vec![CollisionPair { link_a: "left_hand".into(), link_b: "head".into() }];
        let ees = vec![ee("left_hand", 0.0, 0.0, 0.0), ee("head", 0.005, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.01);
        assert!(!r.passed);
        assert!(r.details.contains("left_hand"));
        assert!(r.details.contains("head"));
    }

    #[test]
    fn p7_exactly_at_threshold() {
        let pairs = vec![CollisionPair { link_a: "a".into(), link_b: "b".into() }];
        // Distance = 0.01 exactly, which is the threshold. < 0.01 fails, >= passes.
        let ees = vec![ee("a", 0.0, 0.0, 0.0), ee("b", 0.01, 0.0, 0.0)];
        let r = self_collision::check_self_collision(&ees, &pairs, 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p7_missing_link_flagged() {
        let pairs = vec![CollisionPair { link_a: "left_hand".into(), link_b: "missing".into() }];
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
            support_polygon: vec![
                [-0.15, -0.1], [0.15, -0.1], [0.15, 0.1], [-0.15, 0.1],
            ],
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
            support_polygon: vec![
                [-0.15, -0.1], [0.15, -0.1], [0.15, 0.1], [-0.15, 0.1],
            ],
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
    fn p9_degenerate_polygon_passes() {
        let config = StabilityConfig {
            support_polygon: vec![[0.0, 0.0], [1.0, 0.0]], // only 2 vertices
            com_height_estimate: 0.9,
            enabled: true,
        };
        let com = [0.5, 0.0, 0.9];
        let r = stability::check_stability(Some(&com), Some(&config));
        assert!(r.passed);
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
        use chrono::Utc;
        use std::collections::HashMap;
        use crate::models::command::{Command, CommandAuthority};
        use crate::models::profile::{RobotProfile, SafeStopProfile, WorkspaceBounds};
        use crate::models::authority::Operation;

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
        };

        let results = crate::physics::run_all_checks(&command, &profile, None);
        assert_eq!(results.len(), 10);

        // All should pass for this valid command
        for result in &results {
            assert!(result.passed, "check '{}' failed: {}", result.name, result.details);
            assert_eq!(result.category, "physics");
        }

        // Verify the names are correct and in order
        let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec![
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
        ]);
    }

    #[test]
    fn run_all_checks_detects_failures() {
        use chrono::Utc;
        use std::collections::HashMap;
        use crate::models::command::{Command, CommandAuthority};
        use crate::models::profile::{RobotProfile, SafeStopProfile, WorkspaceBounds};
        use crate::models::authority::Operation;

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
            }],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            max_delta_time: 0.1,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
        };

        let command = Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![joint_state("j1", 2.0, 6.0, 60.0)], // position, velocity, torque all bad
            delta_time: 0.5, // exceeds max_delta_time
            end_effector_positions: vec![ee("left_hand", 0.0, 0.0, 1.0)], // inside exclusion zone
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![Operation::new("actuate:j1").unwrap()],
            },
            metadata: HashMap::new(),
        };

        let results = crate::physics::run_all_checks(&command, &profile, None);
        assert_eq!(results.len(), 10);

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

    // ── NaN/Inf guard tests (R3-01) ─────────────────────────────────────

    #[test]
    fn p1_nan_position_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", f64::NAN, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p1_inf_position_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", f64::INFINITY, 0.0, 0.0)];
        let r = joint_limits::check_joint_limits(&joints, &defs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p2_nan_velocity_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, f64::NAN, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p2_neg_inf_velocity_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, f64::NEG_INFINITY, 0.0)];
        let r = velocity::check_velocity_limits(&joints, &defs, 1.0);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p3_nan_effort_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 0.0, f64::NAN)];
        let r = torque::check_torque_limits(&joints, &defs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p3_inf_effort_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let joints = vec![joint_state("j1", 0.0, 0.0, f64::INFINITY)];
        let r = torque::check_torque_limits(&joints, &defs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p4_nan_delta_time_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.5, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, f64::NAN);
        assert!(!r.passed);
    }

    #[test]
    fn p4_nan_velocity_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let curr = vec![joint_state("j1", 0.0, f64::NAN, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p4_inf_previous_velocity_fails() {
        let defs = vec![joint_def("j1", -1.0, 1.0)];
        let prev = vec![joint_state("j1", 0.0, f64::INFINITY, 0.0)];
        let curr = vec![joint_state("j1", 0.0, 1.0, 0.0)];
        let r = acceleration::check_acceleration_limits(&curr, Some(&prev), &defs, 0.01);
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
        }];
        let ees = vec![ee("ee1", f64::NAN, 0.0, 0.0)];
        let r = exclusion_zones::check_exclusion_zones(&ees, &zones);
        assert!(!r.passed);
        assert!(r.details.contains("NaN"));
    }

    #[test]
    fn p7_nan_position_fails() {
        let pairs = vec![CollisionPair { link_a: "a".into(), link_b: "b".into() }];
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
        let r = delta_time::check_delta_time(0.01, f64::NAN);
        assert!(!r.passed);
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
}
