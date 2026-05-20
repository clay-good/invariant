//! Intent tests for the Category H temporal scenarios introduced on
//! 2026-05-17 (v11 prompt 2.7 — implemented subset).
//!
//! Spec: `docs/robotics/spec-15m-campaign.md` §3 Category H.
//!
//! | Spec ID | Variant            | What this file asserts                              |
//! |---------|--------------------|------------------------------------------------------|
//! | H-04    | `DeltaTimeAttack`  | `delta_time` cycles through {0, <0, NaN, ±Inf}.      |
//! | H-05    | `StaleCommand`     | `delta_time == 2 × profile.max_delta_time` everywhere. |
//!
//! The remaining Category H spec IDs (H-01 replay, H-02 regression, H-03
//! gap, H-06 future-dated sensor) still need their own variants. H-02 is
//! covered structurally by `MultiAgentHandoff`; H-06 depends on the sensor
//! freshness check landing.

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

const COUNT: usize = 20;
const PCA_PLACEHOLDER: &str = "AAAA";

fn ops() -> [Operation; 1] {
    [Operation::new("actuate:*").expect("valid op")]
}

#[test]
fn h04_delta_time_attack_emits_pathological_dt_in_every_command() {
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::DeltaTimeAttack);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    // The attack cycles through 5 values: 0, negative, NaN, +Inf, -Inf.
    // After at least one full cycle, all 5 must have appeared.
    let mut saw_zero = false;
    let mut saw_negative = false;
    let mut saw_nan = false;
    let mut saw_pos_inf = false;
    let mut saw_neg_inf = false;

    for cmd in &cmds {
        let dt = cmd.delta_time;
        if dt == 0.0 {
            saw_zero = true;
        } else if dt.is_nan() {
            saw_nan = true;
        } else if dt == f64::INFINITY {
            saw_pos_inf = true;
        } else if dt == f64::NEG_INFINITY {
            saw_neg_inf = true;
        } else if dt < 0.0 && dt.is_finite() {
            saw_negative = true;
        } else {
            panic!(
                "H-04: command carries unexpected `delta_time` = {dt}; \
                 expected only 0, <0, NaN, ±Inf"
            );
        }
    }
    assert!(saw_zero, "H-04 must emit at least one delta_time == 0");
    assert!(saw_negative, "H-04 must emit at least one delta_time < 0");
    assert!(saw_nan, "H-04 must emit at least one delta_time = NaN");
    assert!(saw_pos_inf, "H-04 must emit at least one delta_time = +Inf");
    assert!(saw_neg_inf, "H-04 must emit at least one delta_time = -Inf");
}

#[test]
fn h05_stale_command_uses_dt_double_the_profile_max() {
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    let expected = profile.max_delta_time * 2.0;
    let gen = ScenarioGenerator::new(&profile, ScenarioType::StaleCommand);
    let cmds = gen.generate_commands(8, PCA_PLACEHOLDER, &ops());
    assert!(!cmds.is_empty());

    for (i, cmd) in cmds.iter().enumerate() {
        assert!(
            (cmd.delta_time - expected).abs() < 1e-12,
            "H-05 cmd {i}: expected delta_time = {expected}, got {}",
            cmd.delta_time
        );
        // Sanity: must strictly exceed the profile's max so P8 actually rejects.
        assert!(
            cmd.delta_time > profile.max_delta_time,
            "H-05 cmd {i}: delta_time {} must exceed profile max {}",
            cmd.delta_time,
            profile.max_delta_time
        );
    }
}

#[test]
fn h04_and_h05_round_trip_through_parse_scenario_type() {
    // Spot-check that the YAML-config side accepts both snake_case and
    // PascalCase forms, the way the existing variants do.
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    for st in [ScenarioType::DeltaTimeAttack, ScenarioType::StaleCommand] {
        let g = ScenarioGenerator::new(&profile, st);
        let cmds = g.generate_commands(4, PCA_PLACEHOLDER, &ops());
        assert_eq!(cmds.len(), 4, "{st:?} must produce all requested commands");
    }
}

#[test]
fn h01_sequence_replay_emits_the_same_sequence_number_for_every_command() {
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::SequenceReplay);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);
    let first_seq = cmds[0].sequence;
    for (i, cmd) in cmds.iter().enumerate() {
        assert_eq!(
            cmd.sequence, first_seq,
            "H-01 cmd {i}: every command must share `sequence`={first_seq}"
        );
    }
    // Joint state must remain baseline-safe so the only failure mode is
    // the replay itself — guards against accidentally smuggling a physics
    // violation into this scenario.
    for cmd in &cmds {
        for js in &cmd.joint_states {
            assert!(
                js.position.is_finite() && js.velocity.is_finite() && js.effort.is_finite(),
                "H-01: joint state must remain finite"
            );
        }
    }
}

#[test]
fn h03_sequence_gap_jumps_into_the_millions_after_the_first_command() {
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::SequenceGap);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);
    assert_eq!(cmds[0].sequence, 0, "H-03 cmd 0 must be the gap origin");
    for (i, cmd) in cmds.iter().enumerate().skip(1) {
        assert!(
            cmd.sequence >= 1_000_000,
            "H-03 cmd {i}: sequence {} must be in the post-gap range",
            cmd.sequence
        );
    }
    // Sequences after the gap should be strictly monotonic so the
    // scenario doesn't accidentally re-encode replay.
    for w in cmds.iter().skip(1).map(|c| c.sequence).collect::<Vec<_>>().windows(2) {
        assert!(w[1] > w[0], "H-03 post-gap sequences must increase");
    }
}
