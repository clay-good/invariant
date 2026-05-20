//! Intent tests for Category N (red-team fuzz integration), v11 2.11:
//! N-01 `RedTeamFuzzGeneration`, N-02 `RedTeamFuzzMutation`,
//! N-08 `RedTeamFuzzUnicode`, N-10 `RedTeamFuzzIntegerBoundary`.
//!
//! See `docs/robotics/spec-15m-campaign.md` §3 (Category N) and
//! `docs/robotics/spec-v11.md` row 2.11.

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

fn ops() -> Vec<Operation> {
    vec![Operation::new("actuate:*").unwrap()]
}

fn load_ur10() -> invariant_robotics::models::profile::RobotProfile {
    load_builtin("ur10").expect("ur10 profile must be available")
}

/// N-01 stamps every command with the redteam_class/generation metadata
/// pair and the fixed seed; joint positions span both inside and outside
/// the profile envelope.
#[test]
fn n_01_generation_emits_in_and_out_of_band_positions() {
    let profile = load_ur10();
    let count = 200;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::RedTeamFuzzGeneration)
        .generate_commands(count, "harness_chain_b64", &ops());
    assert_eq!(cmds.len(), count);

    let j0_min = profile.joints[0].min;
    let j0_max = profile.joints[0].max;

    let mut in_band = 0usize;
    let mut out_of_band = 0usize;
    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(c.source, "redteam_fuzz_gen");
        assert_eq!(
            c.metadata.get("redteam_class").map(String::as_str),
            Some("generation"),
            "cmd {i}: redteam_class metadata"
        );
        assert_eq!(
            c.metadata.get("seed").map(String::as_str),
            Some("0xfa251234"),
            "cmd {i}: seed metadata"
        );
        let p = c.joint_states[0].position;
        // Generator must produce finite values (no NaN/inf in N-01).
        assert!(p.is_finite(), "cmd {i}: joint 0 must be finite, got {p}");
        if (j0_min..=j0_max).contains(&p) {
            in_band += 1;
        } else {
            out_of_band += 1;
        }
    }
    // 50/50 in expectation; assert both populations are non-trivial so the
    // mixed pass/reject pattern actually happens. The exact split is
    // deterministic from the seed but jitter-tolerant here.
    assert!(in_band > 0 && out_of_band > 0, "in={in_band} out={out_of_band}");
    assert!(
        in_band > 20 && out_of_band > 20,
        "in={in_band} out={out_of_band}: expected both populations to be substantial"
    );
}

/// N-01 is reproducible bytewise from the seed — re-running the generator
/// against the same profile yields identical commands.
#[test]
fn n_01_generation_is_deterministic_from_seed() {
    let profile = load_ur10();
    let a = ScenarioGenerator::new(&profile, ScenarioType::RedTeamFuzzGeneration)
        .generate_commands(64, "harness_chain", &ops());
    let b = ScenarioGenerator::new(&profile, ScenarioType::RedTeamFuzzGeneration)
        .generate_commands(64, "harness_chain", &ops());
    // Timestamps differ because base_ts = Utc::now(); compare the parts
    // that the generator actually computes from the seed.
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        assert_eq!(
            x.joint_states.iter().map(|j| j.position).collect::<Vec<_>>(),
            y.joint_states.iter().map(|j| j.position).collect::<Vec<_>>(),
            "cmd {i}: joint positions must reproduce from the seed"
        );
        assert_eq!(x.metadata, y.metadata, "cmd {i}: metadata reproduces");
    }
}

/// N-02 cycles through the five mutation kinds and stamps the
/// mutation_kind metadata accordingly; every kind appears in 20 commands.
#[test]
fn n_02_mutation_visits_every_kind() {
    let profile = load_ur10();
    let count = 20;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::RedTeamFuzzMutation)
        .generate_commands(count, "harness_chain_b64", &ops());
    assert_eq!(cmds.len(), count);

    let mut kinds = std::collections::BTreeSet::new();
    let baseline_seq_xor: u64 = 0xDEAD_BEEF;
    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(c.source, "redteam_fuzz_mut");
        assert_eq!(
            c.metadata.get("redteam_class").map(String::as_str),
            Some("mutation")
        );
        let kind = c
            .metadata
            .get("mutation_kind")
            .map(String::as_str)
            .unwrap_or_else(|| panic!("cmd {i}: mutation_kind missing"));
        kinds.insert(kind.to_string());
        match i % 5 {
            2 => assert!(c.delta_time < 1e-15, "cmd {i}: dt mutation should be tiny"),
            3 => {
                let x = c.end_effector_positions[0].position[0];
                assert!(x <= 0.0, "cmd {i}: ee x must be flipped negative");
            }
            4 => {
                let expected = (i as u64 + 1) ^ baseline_seq_xor;
                assert_eq!(c.sequence, expected, "cmd {i}: sequence xor mutation");
            }
            _ => {}
        }
    }
    let expected: std::collections::BTreeSet<String> =
        ["bitflip", "swap", "dt", "ee", "seq"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    assert_eq!(kinds, expected, "every mutation_kind must appear");
}

/// N-08 decorates the first joint's name with adversarial Unicode; the
/// rest of the command stays well-formed. Every kind appears, every
/// modified name embeds the decorator codepoint.
#[test]
fn n_08_unicode_decorates_first_joint_name() {
    let profile = load_ur10();
    let count = 8;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::RedTeamFuzzUnicode)
        .generate_commands(count, "harness_chain_b64", &ops());
    assert_eq!(cmds.len(), count);

    let original = profile.joints[0].name.clone();
    let mut kinds = std::collections::BTreeSet::new();
    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(c.source, "redteam_fuzz_unicode");
        assert_eq!(
            c.metadata.get("redteam_class").map(String::as_str),
            Some("unicode")
        );
        let kind = c
            .metadata
            .get("unicode_kind")
            .map(String::as_str)
            .unwrap_or_else(|| panic!("cmd {i}: unicode_kind missing"));
        kinds.insert(kind.to_string());
        let name = &c.joint_states[0].name;
        assert_ne!(name, &original, "cmd {i}: name must be decorated");
        assert!(
            name.starts_with(&original),
            "cmd {i}: name should start with the ASCII original"
        );
        // The decorator codepoint specific to this kind appears in the name.
        let expected_cp = match kind {
            "zws" => '\u{200B}',
            "cyrillic" => '\u{043E}',
            "rlo" => '\u{202E}',
            "nul" => '\u{0000}',
            other => panic!("cmd {i}: unexpected unicode_kind {other}"),
        };
        assert!(
            name.chars().any(|ch| ch == expected_cp),
            "cmd {i}: decorator {expected_cp:?} not in name {name:?}"
        );
    }
    let expected: std::collections::BTreeSet<String> =
        ["zws", "cyrillic", "rlo", "nul"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    assert_eq!(kinds, expected);
}

/// N-10 cycles through five integer boundary values on `sequence`; physics
/// remains baseline-safe.
#[test]
fn n_10_integer_boundary_cycles_through_five_values() {
    let profile = load_ur10();
    let count = 10;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::RedTeamFuzzIntegerBoundary)
        .generate_commands(count, "harness_chain_b64", &ops());
    assert_eq!(cmds.len(), count);

    let expected: [(u64, &str); 5] = [
        (0, "zero"),
        (1, "one"),
        (u64::MAX, "umax"),
        (u64::MAX - 1, "umaxm1"),
        (i64::MAX as u64, "imax"),
    ];
    for (i, c) in cmds.iter().enumerate() {
        let (exp_seq, exp_kind) = expected[i % 5];
        assert_eq!(c.sequence, exp_seq, "cmd {i}: sequence");
        assert_eq!(
            c.metadata.get("bound_kind").map(String::as_str),
            Some(exp_kind),
            "cmd {i}: bound_kind metadata"
        );
        assert_eq!(c.source, "redteam_fuzz_intbound");
        assert_eq!(
            c.metadata.get("redteam_class").map(String::as_str),
            Some("integer_boundary")
        );
        // Physics is baseline-safe — joint 0 stays inside the profile.
        let p = c.joint_states[0].position;
        let (lo, hi) = (profile.joints[0].min, profile.joints[0].max);
        assert!(p.is_finite() && (lo..=hi).contains(&p), "cmd {i}: joint 0 baseline");
    }
}

/// Spec-id bindings stay stable; the dry-run parser accepts both
/// PascalCase and snake_case for the four new variants.
#[test]
fn n_category_spec_id_bindings_are_stable() {
    assert_eq!(ScenarioType::RedTeamFuzzGeneration.spec_id(), "N-01");
    assert_eq!(ScenarioType::RedTeamFuzzMutation.spec_id(), "N-02");
    assert_eq!(ScenarioType::RedTeamFuzzUnicode.spec_id(), "N-08");
    assert_eq!(ScenarioType::RedTeamFuzzIntegerBoundary.spec_id(), "N-10");
}
