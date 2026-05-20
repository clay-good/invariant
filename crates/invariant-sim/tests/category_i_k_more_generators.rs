//! Intent tests for K-02 (watchdog recovery) and the Category I openers
//! (I-02 distraction flooding, I-05 error mining).
//!
//! Spec: `docs/robotics/spec-15m-campaign.md` §3 Categories I & K.

use invariant_robotics::models::profile::WorkspaceBounds;
use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

const PCA_PLACEHOLDER: &str = "AAAA";

fn ops() -> [Operation; 1] {
    [Operation::new("actuate:*").expect("valid op")]
}

#[test]
fn k02_watchdog_recovery_cycle_three_phases() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let normal_dt = profile.max_delta_time * 0.5;
    let missed_dt = profile.max_delta_time * 5.0;

    let count = 30;
    let gen = ScenarioGenerator::new(&profile, ScenarioType::WatchdogRecoveryCycle);
    let cmds = gen.generate_commands(count, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), count);

    let third = count / 3;
    let two_thirds = third * 2;
    for (i, cmd) in cmds.iter().enumerate() {
        let expected = if i >= third && i < two_thirds {
            missed_dt
        } else {
            normal_dt
        };
        assert!(
            (cmd.delta_time - expected).abs() < 1e-12,
            "K-02 cmd {i}: delta_time {} should be {expected}",
            cmd.delta_time
        );
    }

    // Both states must appear at the expected counts.
    let missed = cmds.iter().filter(|c| c.delta_time > profile.max_delta_time).count();
    assert_eq!(missed, two_thirds - third, "K-02 missed-heartbeat span");
}

#[test]
fn i02_distraction_flooding_one_in_ten_violations() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let first_max = profile
        .joints
        .first()
        .map(|j| j.max)
        .expect("≥1 joint required");

    let count = 30;
    let gen = ScenarioGenerator::new(&profile, ScenarioType::DistractionFlooding);
    let cmds = gen.generate_commands(count, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), count);

    let mut violations = 0;
    for (i, cmd) in cmds.iter().enumerate() {
        let pos = cmd.joint_states[0].position;
        if i % 10 == 9 {
            assert!(
                (pos - first_max * 2.0).abs() < 1e-9,
                "I-02 cmd {i}: should be 2 × max, got {pos}"
            );
            violations += 1;
        } else {
            assert!(
                pos < first_max,
                "I-02 cmd {i}: distraction command should be mid-range, got {pos}"
            );
        }
    }
    // 30 / 10 = 3 violations expected.
    assert_eq!(violations, 3, "I-02 should produce 1 violation per 10 commands");
}

#[test]
fn i05_error_mining_cycles_through_four_check_modes() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let first_joint = profile.joints.first().expect("≥1 joint");
    let max_pos = first_joint.max;
    let max_vel = first_joint.max_velocity;
    let max_torque = first_joint.max_torque;
    let (_min, ws_max) = match &profile.workspace {
        WorkspaceBounds::Aabb { min, max } => (*min, *max),
    };
    let outside = [ws_max[0] + 1.0, ws_max[1] + 1.0, ws_max[2] + 1.0];

    let count = 16;
    let gen = ScenarioGenerator::new(&profile, ScenarioType::ErrorMining);
    let cmds = gen.generate_commands(count, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), count);

    let mut saw = [false; 4];
    for (i, cmd) in cmds.iter().enumerate() {
        match i % 4 {
            0 => {
                assert!((cmd.joint_states[0].position - max_pos * 2.0).abs() < 1e-9);
                saw[0] = true;
            }
            1 => {
                assert!((cmd.joint_states[0].velocity - max_vel * 2.0).abs() < 1e-9);
                saw[1] = true;
            }
            2 => {
                assert!((cmd.joint_states[0].effort - max_torque * 2.0).abs() < 1e-9);
                saw[2] = true;
            }
            _ => {
                let ee = cmd.end_effector_positions.first().expect("EE present");
                assert!((ee.position[0] - outside[0]).abs() < 1e-9);
                assert!((ee.position[1] - outside[1]).abs() < 1e-9);
                assert!((ee.position[2] - outside[2]).abs() < 1e-9);
                saw[3] = true;
            }
        }
    }
    assert!(saw.iter().all(|s| *s), "I-05 must exercise all four modes");
}

#[test]
fn i_k_more_spec_id_bindings() {
    assert_eq!(ScenarioType::WatchdogRecoveryCycle.spec_id(), "K-02");
    assert_eq!(ScenarioType::DistractionFlooding.spec_id(), "I-02");
    assert_eq!(ScenarioType::ErrorMining.spec_id(), "I-05");
}
