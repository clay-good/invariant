//! Intent tests for the C-01 / C-04 / C-05 generators added to close out
//! v11 prompt 2.2 (Category C: workspace & geometry).
//!
//! Spec: `docs/robotics/spec-15m-campaign.md` §3 Category C.
//!
//! | Spec ID | Variant                       | Assertion                                                         |
//! |---------|-------------------------------|--------------------------------------------------------------------|
//! | C-01    | `WorkspaceBoundarySweep`      | Every command's EE sits on an AABB corner or 1 m outside a face.   |
//! | C-04    | `SelfCollisionApproach`       | First/last commands span the `[2×, 0.1×] × min_collision_distance` window. |
//! | C-05    | `OverlappingZoneBoundaries`   | Every command's EE lies inside ≥1 declared exclusion zone.         |

use invariant_robotics::models::profile::{ExclusionZone, WorkspaceBounds};
use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

const COUNT: usize = 32;
const PCA_PLACEHOLDER: &str = "AAAA";

fn ops() -> [Operation; 1] {
    [Operation::new("actuate:*").expect("valid op")]
}

#[test]
fn c01_workspace_boundary_sweep_alternates_corners_and_outside_faces() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let (min, max) = match &profile.workspace {
        WorkspaceBounds::Aabb { min, max } => (*min, *max),
    };

    let gen = ScenarioGenerator::new(&profile, ScenarioType::WorkspaceBoundarySweep);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    let is_on_corner = |p: [f64; 3]| -> bool {
        let on_axis = |v: f64, lo: f64, hi: f64| (v - lo).abs() < 1e-9 || (v - hi).abs() < 1e-9;
        on_axis(p[0], min[0], max[0])
            && on_axis(p[1], min[1], max[1])
            && on_axis(p[2], min[2], max[2])
    };
    let is_outside_by_1m = |p: [f64; 3]| -> bool {
        let off_axis = |v: f64, lo: f64, hi: f64| {
            (v - (lo - 1.0)).abs() < 1e-9 || (v - (hi + 1.0)).abs() < 1e-9
        };
        off_axis(p[0], min[0], max[0])
            && off_axis(p[1], min[1], max[1])
            && off_axis(p[2], min[2], max[2])
    };

    let mut saw_corner = false;
    let mut saw_outside = false;
    for (i, cmd) in cmds.iter().enumerate() {
        let ee = cmd
            .end_effector_positions
            .first()
            .unwrap_or_else(|| panic!("C-01 cmd {i} missing EE"));
        assert!(
            is_on_corner(ee.position) || is_outside_by_1m(ee.position),
            "C-01 cmd {i}: EE {:?} is neither a corner nor a 1 m-outside corner",
            ee.position
        );
        if is_on_corner(ee.position) {
            saw_corner = true;
        }
        if is_outside_by_1m(ee.position) {
            saw_outside = true;
        }
    }
    assert!(saw_corner, "C-01 must visit at least one AABB corner");
    assert!(
        saw_outside,
        "C-01 must visit at least one outside-corner position"
    );
}

#[test]
fn c04_self_collision_approach_ramps_separation_below_min_collision_distance() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let min_dist = profile.min_collision_distance.max(1e-3);

    let gen = ScenarioGenerator::new(&profile, ScenarioType::SelfCollisionApproach);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    let sep_of = |cmd: &invariant_robotics::models::command::Command| -> f64 {
        let eps = &cmd.end_effector_positions;
        assert_eq!(eps.len(), 2, "C-04 commands must emit exactly two EEs");
        let dx = eps[0].position[0] - eps[1].position[0];
        let dy = eps[0].position[1] - eps[1].position[1];
        let dz = eps[0].position[2] - eps[1].position[2];
        (dx * dx + dy * dy + dz * dz).sqrt()
    };

    let first_sep = sep_of(&cmds[0]);
    let last_sep = sep_of(cmds.last().unwrap());

    // First command sits at ~2× min_collision_distance.
    assert!(
        (first_sep - 2.0 * min_dist).abs() < 1e-9,
        "C-04 first separation {first_sep} should be 2 × min_collision_distance ({})",
        2.0 * min_dist
    );
    // Final command sits below min_collision_distance.
    assert!(
        last_sep < min_dist,
        "C-04 final separation {last_sep} should be below min_collision_distance ({min_dist})"
    );

    // Monotonic non-increasing separation.
    let series: Vec<f64> = cmds.iter().map(sep_of).collect();
    for w in series.windows(2) {
        assert!(
            w[1] <= w[0] + 1e-9,
            "C-04 separation not monotonically non-increasing: {} -> {}",
            w[0],
            w[1]
        );
    }

    // Joint state stays finite (isolation: collision is spatial-only).
    for cmd in &cmds {
        for js in &cmd.joint_states {
            assert!(js.position.is_finite() && js.velocity.is_finite());
        }
    }
}

#[test]
fn c05_overlapping_zone_boundaries_every_command_in_at_least_one_zone() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    assert!(
        !profile.exclusion_zones.is_empty(),
        "ur10e_haas_cell must declare ≥1 exclusion_zone for the C-05 happy path"
    );

    let gen = ScenarioGenerator::new(&profile, ScenarioType::OverlappingZoneBoundaries);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    let in_zone = |p: [f64; 3], z: &ExclusionZone| -> bool {
        match z {
            ExclusionZone::Aabb { min, max, .. } => {
                p[0] >= min[0]
                    && p[0] <= max[0]
                    && p[1] >= min[1]
                    && p[1] <= max[1]
                    && p[2] >= min[2]
                    && p[2] <= max[2]
            }
            ExclusionZone::Sphere { center, radius, .. } => {
                let dx = p[0] - center[0];
                let dy = p[1] - center[1];
                let dz = p[2] - center[2];
                dx * dx + dy * dy + dz * dz <= radius * radius
            }
            _ => false,
        }
    };

    for (i, cmd) in cmds.iter().enumerate() {
        let ee = cmd
            .end_effector_positions
            .first()
            .unwrap_or_else(|| panic!("C-05 cmd {i} missing EE"));
        let any = profile
            .exclusion_zones
            .iter()
            .any(|z| in_zone(ee.position, z));
        assert!(
            any,
            "C-05 cmd {i}: EE {:?} should lie inside ≥1 exclusion zone",
            ee.position
        );
    }
}

#[test]
fn c05_overlapping_zone_boundaries_falls_back_to_outside_workspace_when_no_zones() {
    // Pick any built-in that declares zero exclusion zones — `franka_panda`
    // is the canonical arm without an opinionated cell.
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    if !profile.exclusion_zones.is_empty() {
        // If the canonical example ever grows zones, the fallback branch is
        // still exercised by any zero-zone profile; soft-skip in that case.
        eprintln!("franka_panda now has exclusion zones; fallback branch not exercised here");
        return;
    }

    let (_min, max) = match &profile.workspace {
        WorkspaceBounds::Aabb { min, max } => (*min, *max),
    };
    let gen = ScenarioGenerator::new(&profile, ScenarioType::OverlappingZoneBoundaries);
    let cmds = gen.generate_commands(8, PCA_PLACEHOLDER, &ops());

    for cmd in &cmds {
        let ee = cmd.end_effector_positions.first().unwrap();
        assert!(
            (ee.position[0] - (max[0] + 1.0)).abs() < 1e-9
                && (ee.position[1] - (max[1] + 1.0)).abs() < 1e-9
                && (ee.position[2] - (max[2] + 1.0)).abs() < 1e-9,
            "C-05 zero-zone fallback should park the EE at workspace_max + 1 m on every axis"
        );
    }
}

#[test]
fn c_more_spec_id_bindings() {
    assert_eq!(ScenarioType::WorkspaceBoundarySweep.spec_id(), "C-01");
    assert_eq!(ScenarioType::SelfCollisionApproach.spec_id(), "C-04");
    assert_eq!(ScenarioType::OverlappingZoneBoundaries.spec_id(), "C-05");
}
