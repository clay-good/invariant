//! Intent tests for Category J additions (J-03 / J-06 / J-08) under
//! v11 prompt 2.9 closure.
//!
//! Spec: `docs/robotics/spec-15m-campaign.md` §3 Category J.
//!
//! | Spec ID | Variant                  | Assertion                                                |
//! |---------|--------------------------|-----------------------------------------------------------|
//! | J-03    | `NanAuthorityBypass`     | First joint NaN AND `pca_chain` empty.                    |
//! | J-06    | `ProfileProbingTargeted` | First half sweeps 0.5×→0.99×max; second half `max + ε`.   |
//! | J-08    | `MultiRobotDistraction`  | Sources alternate `robot_a` (valid) / `robot_b` (invalid).|

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

const COUNT: usize = 20;
const PCA_PLACEHOLDER: &str = "AAAA";

fn ops() -> [Operation; 1] {
    [Operation::new("actuate:*").expect("valid op")]
}

#[test]
fn j03_nan_authority_bypass_emits_nan_joint_and_empty_chain() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::NanAuthorityBypass);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    for (i, cmd) in cmds.iter().enumerate() {
        let first = cmd
            .joint_states
            .first()
            .unwrap_or_else(|| panic!("J-03 cmd {i} missing joint state"));
        assert!(
            first.position.is_nan(),
            "J-03 cmd {i}: first joint position should be NaN, got {}",
            first.position
        );
        assert_eq!(
            cmd.authority.pca_chain, "",
            "J-03 cmd {i}: pca_chain should be empty (authority bypass half), got {:?}",
            cmd.authority.pca_chain
        );
    }
}

#[test]
fn j06_profile_probing_targeted_splits_probe_then_attack() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::ProfileProbingTargeted);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    let half = COUNT / 2;
    for (i, cmd) in cmds.iter().enumerate() {
        // Test the first profile joint's position.
        let j0 = profile.joints.first().expect("≥1 joint");
        let range = j0.max - j0.min;
        let eps = (range * 1e-6).max(1e-9);
        let pos = cmd.joint_states[0].position;
        if i < half {
            // Probe phase: 0.5 × max ≤ position ≤ 0.99 × max (with tiny tolerance).
            assert!(
                pos >= j0.max * 0.5 - 1e-9 && pos <= j0.max * 0.99 + 1e-9,
                "J-06 probe cmd {i}: pos {pos} outside [{}, {}]",
                j0.max * 0.5,
                j0.max * 0.99
            );
        } else {
            // Targeted attack: exactly max + ε.
            assert!(
                (pos - (j0.max + eps)).abs() < 1e-9 * range.max(1.0),
                "J-06 attack cmd {i}: pos {pos} should be max + ε ({})",
                j0.max + eps
            );
        }
    }
}

#[test]
fn j08_multi_robot_distraction_alternates_sources_and_validity() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let first_joint_max = profile
        .joints
        .first()
        .map(|j| j.max)
        .expect("ur10e_haas_cell must declare ≥1 joint");

    let gen = ScenarioGenerator::new(&profile, ScenarioType::MultiRobotDistraction);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    let mut saw_a_pass = false;
    let mut saw_b_reject = false;
    for (i, cmd) in cmds.iter().enumerate() {
        if i % 2 == 0 {
            assert_eq!(cmd.source, "robot_a", "J-08 cmd {i}: even-index source");
            // Baseline-safe.
            let pos = cmd.joint_states[0].position;
            assert!(
                pos < first_joint_max,
                "J-08 robot_a cmd {i}: first joint should be mid-range, got {pos}"
            );
            saw_a_pass = true;
        } else {
            assert_eq!(cmd.source, "robot_b", "J-08 cmd {i}: odd-index source");
            let pos = cmd.joint_states[0].position;
            assert!(
                (pos - first_joint_max * 2.0).abs() < 1e-9,
                "J-08 robot_b cmd {i}: first joint should be 2 × max, got {pos}"
            );
            saw_b_reject = true;
        }
    }
    assert!(saw_a_pass, "J-08 must include ≥1 valid robot_a command");
    assert!(
        saw_b_reject,
        "J-08 must include ≥1 invalid robot_b command"
    );

    // Per-source sequence monotonicity.
    let seqs_a: Vec<u64> = cmds
        .iter()
        .filter(|c| c.source == "robot_a")
        .map(|c| c.sequence)
        .collect();
    let seqs_b: Vec<u64> = cmds
        .iter()
        .filter(|c| c.source == "robot_b")
        .map(|c| c.sequence)
        .collect();
    for w in seqs_a.windows(2) {
        assert!(w[1] > w[0], "robot_a per-source sequence must be monotonic");
    }
    for w in seqs_b.windows(2) {
        assert!(w[1] > w[0], "robot_b per-source sequence must be monotonic");
    }
}

#[test]
fn j_more_spec_id_bindings() {
    assert_eq!(ScenarioType::NanAuthorityBypass.spec_id(), "J-03");
    assert_eq!(ScenarioType::ProfileProbingTargeted.spec_id(), "J-06");
    assert_eq!(ScenarioType::MultiRobotDistraction.spec_id(), "J-08");
}
