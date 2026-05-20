//! Intent tests for the additional Category I (Cognitive Escape) variants
//! landed alongside the I-02 / I-05 batch.
//!
//! Each test asserts the deterministic shape its generator must produce; it
//! does not exercise the validator. Validator behaviour for these failure
//! modes is covered by the per-check unit tests under
//! `crates/invariant-robotics`.
//!
//! v11 prompt 2.8 (Category I) — see `docs/robotics/spec-v11.md` row 2.8
//! and `docs/robotics/spec-15m-campaign.md` §3 rows I-01 / I-03.

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

fn ops() -> Vec<Operation> {
    vec![Operation::new("actuate:*").unwrap()]
}

fn load_ur10() -> invariant_robotics::models::profile::RobotProfile {
    load_builtin("ur10").expect("ur10 profile must be available")
}

#[test]
fn i_01_gradual_drift_escape_first_command_in_band_last_out_of_band() {
    let profile = load_ur10();
    let first = profile
        .joints
        .first()
        .expect("ur10 profile has joints")
        .clone();
    let mid = 0.5 * (first.min + first.max);
    let count = 200_000; // enough steps × 0.0001 rad to walk past max
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::GradualDriftEscape)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    // The very first command sits at the joint midpoint (within bounds).
    let p0 = cmds[0].joint_states[0].position;
    assert!(
        (p0 - mid).abs() < 1e-12,
        "first command must start at midpoint {mid}, got {p0}",
    );
    assert!(
        p0 >= first.min && p0 <= first.max,
        "first command must be in-band",
    );

    // Drift is monotonically non-decreasing on joint 0.
    for w in cmds.windows(2) {
        let a = w[0].joint_states[0].position;
        let b = w[1].joint_states[0].position;
        assert!(
            b >= a - 1e-12,
            "joint 0 drift must be non-decreasing: {a} -> {b}",
        );
    }

    // Step delta is exactly 0.0001 rad.
    let step = cmds[1].joint_states[0].position - cmds[0].joint_states[0].position;
    assert!(
        (step - 0.0001).abs() < 1e-12,
        "step must be 0.0001 rad, got {step}",
    );

    // The final command has drifted past `max`.
    let last = cmds[count - 1].joint_states[0].position;
    assert!(
        last > first.max,
        "final position {last} must exceed joint max {} after {count} steps",
        first.max,
    );

    // Source tag is stable.
    for c in &cmds {
        assert_eq!(c.source, "gradual_drift_escape");
    }
}

#[test]
fn i_03_semantic_confusion_rotates_names_against_positions() {
    // franka_panda has asymmetric joints 4 and 6 (non-zero midpoints) so a
    // joint-name rotation is observable in the per-slot position values.
    // The ur10 profile is symmetric (every joint midpoint is 0) and would
    // make the swap a no-op at the position level.
    let profile = load_builtin("franka_panda").expect("franka_panda available");
    let n = profile.joints.len();
    assert!(n > 1, "ur10 must have at least two joints for I-03");
    let count = n.max(8);

    let cmds = ScenarioGenerator::new(&profile, ScenarioType::SemanticConfusion).generate_commands(
        count,
        "",
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    // Every command reports a joint state per profile joint, and every
    // state's `name` is one of the profile joints' names.
    let known: std::collections::HashSet<&str> =
        profile.joints.iter().map(|j| j.name.as_str()).collect();
    for c in &cmds {
        assert_eq!(c.joint_states.len(), n);
        for js in &c.joint_states {
            assert!(
                known.contains(js.name.as_str()),
                "joint name {:?} must remain a known profile joint name",
                js.name
            );
        }
    }

    // Names are always reported in profile-declaration order so the
    // mismatch is in name↔position, not name↔name.
    for c in &cmds {
        for (j, js) in c.joint_states.iter().enumerate() {
            assert_eq!(js.name, profile.joints[j].name);
        }
    }

    // Every command (including the first, given n > 1) has at least one
    // slot whose position is not the midpoint of the *named* joint —
    // i.e. names truly don't match positions.
    for (i, c) in cmds.iter().enumerate() {
        let mismatched = c.joint_states.iter().enumerate().any(|(j, js)| {
            let expected_mid = 0.5 * (profile.joints[j].min + profile.joints[j].max);
            (js.position - expected_mid).abs() > 1e-9
        });
        assert!(
            mismatched,
            "command {i}: every slot still matches its declared joint's midpoint — \
             the swap is a no-op",
        );
    }

    for c in &cmds {
        assert_eq!(c.source, "semantic_confusion");
    }
}
