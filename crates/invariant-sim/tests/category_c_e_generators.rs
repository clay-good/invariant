//! Intent tests for the new C-06 + E-04 generators added 2026-05-17
//! (v11 prompts 2.2 + 2.4 — partial).
//!
//! Spec: `docs/robotics/spec-15m-campaign.md` §3 Categories C & E.
//!
//! | Spec ID | Variant                  | Assertion                                       |
//! |---------|--------------------------|--------------------------------------------------|
//! | C-06    | `CorruptSpatialData`     | Every command's EE position carries ≥1 non-finite. |
//! | E-04    | `PayloadOverload`        | `estimated_payload_kg` ramps 0 → 3×max monotonically. |

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

const COUNT: usize = 30;
const PCA_PLACEHOLDER: &str = "AAAA";

fn ops() -> [Operation; 1] {
    [Operation::new("actuate:*").expect("valid op")]
}

#[test]
fn c06_corrupt_spatial_data_every_command_has_a_non_finite_ee_position() {
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::CorruptSpatialData);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    let mut saw_nan = false;
    let mut saw_pos_inf = false;
    let mut saw_neg_inf = false;

    for (i, cmd) in cmds.iter().enumerate() {
        let ee = cmd
            .end_effector_positions
            .first()
            .unwrap_or_else(|| panic!("C-06 cmd {i} missing EE position"));
        let any_bad = ee.position.iter().any(|c| !c.is_finite());
        assert!(
            any_bad,
            "C-06 cmd {i}: EE position {:?} should have ≥1 non-finite coord",
            ee.position
        );
        for &c in &ee.position {
            if c.is_nan() {
                saw_nan = true;
            } else if c == f64::INFINITY {
                saw_pos_inf = true;
            } else if c == f64::NEG_INFINITY {
                saw_neg_inf = true;
            }
        }
    }
    assert!(saw_nan, "C-06 must emit NaN somewhere across the sequence");
    assert!(saw_pos_inf, "C-06 must emit +Inf somewhere");
    assert!(saw_neg_inf, "C-06 must emit -Inf somewhere");

    // Joint state must remain baseline-safe so the only failure mode is
    // the spatial corruption.
    for cmd in &cmds {
        for js in &cmd.joint_states {
            assert!(
                js.position.is_finite() && js.velocity.is_finite(),
                "C-06: joint state must remain finite (corruption is spatial only)"
            );
        }
    }
}

#[test]
fn e04_payload_overload_ramps_monotonically_and_exceeds_2x_max() {
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    let max_payload = profile
        .end_effectors
        .first()
        .map(|ee| ee.max_payload_kg)
        .expect("franka_panda must declare an end_effector with max_payload_kg");

    let gen = ScenarioGenerator::new(&profile, ScenarioType::PayloadOverload);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    let series: Vec<f64> = cmds
        .iter()
        .map(|c| c.estimated_payload_kg.expect("payload field must be set"))
        .collect();

    // First command is at the ramp origin (0 kg).
    assert!(
        series[0] < 1.0e-9,
        "E-04 first command payload should be ~0, got {}",
        series[0]
    );

    // Monotonic non-decreasing across the ramp.
    for w in series.windows(2) {
        assert!(
            w[1] >= w[0] - 1e-9,
            "E-04 ramp not monotonic: {} -> {}",
            w[0],
            w[1]
        );
    }

    // Final step must exceed 2× the profile's max_payload_kg (ramp goes
    // to 3× near the end).
    let last = *series.last().unwrap();
    assert!(
        last > max_payload * 2.0,
        "E-04 final payload {last} should exceed 2 × max_payload_kg = {}",
        max_payload * 2.0
    );
}
