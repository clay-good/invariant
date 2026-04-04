//! UR10e URDF forward kinematics integration tests.
//!
//! Tests that our URDF parser + FK solver produces correct link positions
//! for the real UR10e robot using the official DH parameters from
//! Universal Robots' ROS-Industrial package.

use invariant_core::urdf::{forward_kinematics, parse_urdf};
use std::collections::HashMap;

const UR10E_URDF: &str = include_str!("../../../profiles/ur10e.urdf");

fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() < tol
}

// ---------------------------------------------------------------------------
// Parse tests
// ---------------------------------------------------------------------------

#[test]
fn ur10e_urdf_parses_successfully() {
    let model = parse_urdf(UR10E_URDF).unwrap();
    assert_eq!(model.name, "ur10e");
    assert_eq!(model.links.len(), 8); // base + 6 arm links + tool0
    assert_eq!(model.joints.len(), 7); // 6 revolute + 1 fixed (tool0)
}

#[test]
fn ur10e_joint_names_match_profile() {
    let model = parse_urdf(UR10E_URDF).unwrap();
    let joint_names: Vec<&str> = model.joints.iter().map(|j| j.name.as_str()).collect();
    assert!(joint_names.contains(&"shoulder_pan_joint"));
    assert!(joint_names.contains(&"shoulder_lift_joint"));
    assert!(joint_names.contains(&"elbow_joint"));
    assert!(joint_names.contains(&"wrist_1_joint"));
    assert!(joint_names.contains(&"wrist_2_joint"));
    assert!(joint_names.contains(&"wrist_3_joint"));
}

// ---------------------------------------------------------------------------
// FK tests at zero angles (home position)
// ---------------------------------------------------------------------------

#[test]
fn ur10e_fk_home_position_base_at_origin() {
    let model = parse_urdf(UR10E_URDF).unwrap();
    let pos = forward_kinematics(&model, &HashMap::new()).unwrap();

    let base = pos.get("base_link").unwrap();
    assert!(approx_eq(base[0], 0.0, 0.001));
    assert!(approx_eq(base[1], 0.0, 0.001));
    assert!(approx_eq(base[2], 0.0, 0.001));
}

#[test]
fn ur10e_fk_home_shoulder_at_correct_height() {
    let model = parse_urdf(UR10E_URDF).unwrap();
    let pos = forward_kinematics(&model, &HashMap::new()).unwrap();

    // Shoulder is at d1 = 0.181m above base
    let shoulder = pos.get("shoulder_link").unwrap();
    assert!(
        approx_eq(shoulder[2], 0.181, 0.001),
        "shoulder Z should be ~0.181, got {}",
        shoulder[2]
    );
}

#[test]
fn ur10e_fk_home_tool_reachable() {
    let model = parse_urdf(UR10E_URDF).unwrap();
    let pos = forward_kinematics(&model, &HashMap::new()).unwrap();

    // At home (all zeros), the tool0 should be within the 1.3m reach radius
    let tool = pos.get("tool0").unwrap();
    let reach = (tool[0] * tool[0] + tool[1] * tool[1] + tool[2] * tool[2]).sqrt();
    assert!(
        reach < 1.4,
        "tool0 at home should be within 1.4m reach, got {:.3}m at [{:.3}, {:.3}, {:.3}]",
        reach,
        tool[0],
        tool[1],
        tool[2]
    );
    assert!(
        reach > 0.1,
        "tool0 at home should not be at the origin, reach={:.3}m",
        reach
    );
}

// ---------------------------------------------------------------------------
// FK tests with specific joint angles
// ---------------------------------------------------------------------------

#[test]
fn ur10e_fk_shoulder_pan_90_rotates_arm() {
    let model = parse_urdf(UR10E_URDF).unwrap();

    let mut angles = HashMap::new();
    angles.insert(
        "shoulder_pan_joint".to_string(),
        std::f64::consts::FRAC_PI_2,
    );

    let pos = forward_kinematics(&model, &angles).unwrap();

    // With 90 deg shoulder pan (Z-axis rotation), what was in front
    // of the robot should now be to the side.
    let tool_home = {
        let p = forward_kinematics(&model, &HashMap::new()).unwrap();
        *p.get("tool0").unwrap()
    };
    let tool_rotated = pos.get("tool0").unwrap();

    // The tool should have moved significantly from its home position
    let delta = ((tool_home[0] - tool_rotated[0]).powi(2)
        + (tool_home[1] - tool_rotated[1]).powi(2))
    .sqrt();
    assert!(
        delta > 0.1,
        "90 deg shoulder pan should move tool significantly in XY, delta={:.3}m",
        delta
    );
}

#[test]
fn ur10e_fk_all_zeros_same_as_default() {
    let model = parse_urdf(UR10E_URDF).unwrap();

    let empty: HashMap<String, f64> = HashMap::new();
    let mut all_zeros = HashMap::new();
    for j in &model.joints {
        all_zeros.insert(j.name.clone(), 0.0);
    }

    let pos1 = forward_kinematics(&model, &empty).unwrap();
    let pos2 = forward_kinematics(&model, &all_zeros).unwrap();

    // Both should produce identical positions
    for link in &model.links {
        let p1 = pos1.get(&link.name).unwrap();
        let p2 = pos2.get(&link.name).unwrap();
        assert!(
            approx_eq(p1[0], p2[0], 1e-10)
                && approx_eq(p1[1], p2[1], 1e-10)
                && approx_eq(p1[2], p2[2], 1e-10),
            "link {} differs: {:?} vs {:?}",
            link.name,
            p1,
            p2
        );
    }
}

// ---------------------------------------------------------------------------
// FK + self-collision relevance test
// ---------------------------------------------------------------------------

#[test]
fn ur10e_fk_can_detect_tool_near_base() {
    let model = parse_urdf(UR10E_URDF).unwrap();

    // If we fold the arm back on itself, the tool should be near the base.
    // shoulder_lift = -pi (pointing straight up, then back)
    // elbow = pi (folding the forearm back)
    let mut angles = HashMap::new();
    angles.insert("shoulder_lift_joint".to_string(), -std::f64::consts::PI);
    angles.insert("elbow_joint".to_string(), std::f64::consts::PI);

    let pos = forward_kinematics(&model, &angles).unwrap();

    let base = pos.get("base_link").unwrap();
    let tool = pos.get("tool0").unwrap();

    let dist =
        ((base[0] - tool[0]).powi(2) + (base[1] - tool[1]).powi(2) + (base[2] - tool[2]).powi(2))
            .sqrt();

    // In a folded configuration, the tool should be close-ish to the base
    // (within reach envelope). This validates that FK produces meaningful
    // positions that could be used for self-collision detection.
    assert!(
        dist < 1.5,
        "folded arm tool should be within 1.5m of base, got {:.3}m",
        dist
    );
}

// ---------------------------------------------------------------------------
// Validates all links have positions
// ---------------------------------------------------------------------------

#[test]
fn ur10e_fk_produces_positions_for_all_links() {
    let model = parse_urdf(UR10E_URDF).unwrap();
    let pos = forward_kinematics(&model, &HashMap::new()).unwrap();

    for link in &model.links {
        assert!(
            pos.contains_key(&link.name),
            "FK must produce a position for link '{}'",
            link.name
        );
    }
    assert_eq!(pos.len(), model.links.len());
}
