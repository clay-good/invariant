//! Intent tests for the K-03 / L-02 / L-03 generators added under
//! v11 prompt 2.9 (Category J/K/L grouping).
//!
//! Spec: `docs/robotics/spec-15m-campaign.md` §3 Categories K & L.
//!
//! | Spec ID | Variant                | Assertion                                                  |
//! |---------|------------------------|-------------------------------------------------------------|
//! | K-03    | `EstopRecoveryCycle`   | First half `e_stop_engaged=true`, second half `=false`.     |
//! | L-02    | `MillionEntryAudit`    | All baseline-safe; carries `audit_stress="true"` metadata.  |
//! | L-03    | `CounterSaturation`    | Sequence ends at `u64::MAX`; strictly monotonic; finite.    |

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

const COUNT: usize = 20;
const PCA_PLACEHOLDER: &str = "AAAA";

fn ops() -> [Operation; 1] {
    [Operation::new("actuate:*").expect("valid op")]
}

#[test]
fn k03_estop_recovery_cycle_first_half_engaged_second_half_released() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::EstopRecoveryCycle);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    let half = COUNT / 2;
    for (i, cmd) in cmds.iter().enumerate() {
        let engaged = cmd
            .environment_state
            .as_ref()
            .and_then(|e| e.e_stop_engaged)
            .unwrap_or_else(|| panic!("K-03 cmd {i} must set e_stop_engaged"));
        let expected = i < half;
        assert_eq!(
            engaged, expected,
            "K-03 cmd {i}: e_stop_engaged={engaged}, expected {expected} (half={half})"
        );
    }

    // Both states must appear.
    let states: Vec<bool> = cmds
        .iter()
        .map(|c| {
            c.environment_state
                .as_ref()
                .unwrap()
                .e_stop_engaged
                .unwrap()
        })
        .collect();
    assert!(states.contains(&true), "K-03 must include engaged commands");
    assert!(
        states.contains(&false),
        "K-03 must include released commands"
    );
}

#[test]
fn l02_million_entry_audit_carries_stress_marker_and_finite_state() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::MillionEntryAudit);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    for (i, cmd) in cmds.iter().enumerate() {
        let stress = cmd.metadata.get("audit_stress").map(String::as_str);
        assert_eq!(
            stress,
            Some("true"),
            "L-02 cmd {i} must carry audit_stress=true metadata, got {stress:?}"
        );
        for js in &cmd.joint_states {
            assert!(
                js.position.is_finite() && js.velocity.is_finite(),
                "L-02 cmd {i}: joint state must be finite (baseline-safe long sequence)"
            );
        }
    }

    // Sequence is strictly monotonic from 1.
    for w in cmds.windows(2) {
        assert!(
            w[1].sequence == w[0].sequence + 1,
            "L-02 sequence must be strictly +1 monotonic"
        );
    }
}

#[test]
fn l03_counter_saturation_ends_at_u64_max_and_is_strictly_monotonic() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::CounterSaturation);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    let last = cmds.last().unwrap().sequence;
    assert_eq!(
        last,
        u64::MAX,
        "L-03 final command should sit at u64::MAX, got {last}"
    );
    let first = cmds[0].sequence;
    assert_eq!(
        first,
        u64::MAX - (COUNT as u64) + 1,
        "L-03 first command should be u64::MAX - count + 1"
    );

    for w in cmds.windows(2) {
        assert!(
            w[1].sequence == w[0].sequence + 1,
            "L-03 sequence must be strictly +1 monotonic across the saturation window"
        );
    }

    // Joint state stays baseline-safe.
    for cmd in &cmds {
        for js in &cmd.joint_states {
            assert!(js.position.is_finite());
        }
    }
}

#[test]
fn k_l_spec_id_bindings() {
    assert_eq!(ScenarioType::EstopRecoveryCycle.spec_id(), "K-03");
    assert_eq!(ScenarioType::MillionEntryAudit.spec_id(), "L-02");
    assert_eq!(ScenarioType::CounterSaturation.spec_id(), "L-03");
}
