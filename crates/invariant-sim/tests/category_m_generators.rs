//! Intent tests for the Category M variants added under v11 prompt 2.10.
//!
//! Spec: `docs/robotics/spec-15m-campaign.md` §3 Category M.
//!
//! | Spec ID | Variant                     | Assertion                                                |
//! |---------|-----------------------------|-----------------------------------------------------------|
//! | M-02    | `ValidInvalidAlternating`   | Even index baseline, odd index first-joint at 2 × max.    |
//! | M-04    | `MaximumPayloadCommand`     | 256 joints / 256 EEs / 256 forces, all uniquely named.    |
//! | M-05    | `MinimumValidCommand`       | 1 joint state, 0 EEs, 0 forces, no environment state.     |

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

const COUNT: usize = 24;
const PCA_PLACEHOLDER: &str = "AAAA";

fn ops() -> [Operation; 1] {
    [Operation::new("actuate:*").expect("valid op")]
}

#[test]
fn m02_alternating_50_50_invalid_on_odd_indices() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let first_joint_max = profile
        .joints
        .first()
        .map(|j| j.max)
        .expect("ur10e_haas_cell must declare ≥1 joint");

    let gen = ScenarioGenerator::new(&profile, ScenarioType::ValidInvalidAlternating);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    for (i, cmd) in cmds.iter().enumerate() {
        let pos = cmd.joint_states[0].position;
        if i % 2 == 0 {
            // Baseline-safe: mid-range, well below max.
            assert!(
                pos < first_joint_max,
                "M-02 even cmd {i}: first joint should be mid-range, got {pos}"
            );
        } else {
            assert!(
                (pos - first_joint_max * 2.0).abs() < 1e-9,
                "M-02 odd cmd {i}: first joint should be 2 × max ({}) got {pos}",
                first_joint_max * 2.0
            );
        }
    }
}

#[test]
fn m04_maximum_payload_command_carries_256_synthetic_entries_each() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::MaximumPayloadCommand);
    let cmds = gen.generate_commands(4, PCA_PLACEHOLDER, &ops());

    for (i, cmd) in cmds.iter().enumerate() {
        assert_eq!(cmd.joint_states.len(), 256, "M-04 cmd {i}: 256 joints");
        assert_eq!(
            cmd.end_effector_positions.len(),
            256,
            "M-04 cmd {i}: 256 EE positions"
        );
        assert_eq!(
            cmd.end_effector_forces.len(),
            256,
            "M-04 cmd {i}: 256 EE forces"
        );

        // Uniqueness of synthesised names within each vector.
        let mut joint_names: Vec<&str> = cmd.joint_states.iter().map(|j| j.name.as_str()).collect();
        joint_names.sort();
        joint_names.dedup();
        assert_eq!(joint_names.len(), 256, "M-04 joint names must be unique");

        // Spot-check the naming scheme.
        assert!(cmd.joint_states[0].name.starts_with("synth_joint_"));
        assert!(cmd.end_effector_positions[0].name.starts_with("synth_ee_"));
        assert!(cmd.end_effector_forces[0].name.starts_with("synth_force_"));
    }
}

#[test]
fn m05_minimum_valid_command_has_single_joint_and_no_optional_state() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let first_joint = profile
        .joints
        .first()
        .expect("ur10e_haas_cell must declare ≥1 joint");

    let gen = ScenarioGenerator::new(&profile, ScenarioType::MinimumValidCommand);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    for (i, cmd) in cmds.iter().enumerate() {
        assert_eq!(
            cmd.joint_states.len(),
            1,
            "M-05 cmd {i}: must carry exactly one joint state"
        );
        let js = &cmd.joint_states[0];
        assert_eq!(js.name, first_joint.name);
        let mid = (first_joint.min + first_joint.max) / 2.0;
        assert!(
            (js.position - mid).abs() < 1e-9,
            "M-05 cmd {i}: position should be joint midpoint"
        );
        assert!(cmd.end_effector_positions.is_empty(), "M-05 zero EEs");
        assert!(cmd.end_effector_forces.is_empty(), "M-05 zero forces");
        assert!(
            cmd.signed_sensor_readings.is_empty(),
            "M-05 zero sensor readings"
        );
        assert!(cmd.environment_state.is_none(), "M-05 no environment state");
        assert!(cmd.locomotion_state.is_none(), "M-05 no locomotion state");
    }
}

#[test]
fn m_spec_id_bindings() {
    assert_eq!(ScenarioType::ValidInvalidAlternating.spec_id(), "M-02");
    assert_eq!(ScenarioType::MaximumPayloadCommand.spec_id(), "M-04");
    assert_eq!(ScenarioType::MinimumValidCommand.spec_id(), "M-05");
}
