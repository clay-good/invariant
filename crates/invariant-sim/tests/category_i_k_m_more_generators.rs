//! Intent tests for the fifth batch of scenario generators:
//! I-07 `ProfileProbingBinarySearch`, I-10 `RollbackReplay`, K-05
//! `ProfileReloadDuringOperation`, M-03 `PureFuzz`.
//!
//! Each test asserts the deterministic shape its generator must produce;
//! validator behaviour for these failure modes is covered by the per-check
//! unit tests under `crates/invariant-robotics`.
//!
//! v11 prompts 2.8 / 2.9 / 2.10 — see `docs/robotics/spec-v11.md` and
//! `docs/robotics/spec-15m-campaign.md` §3.

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
fn i_07_profile_probing_binary_search_converges_to_max() {
    let profile = load_ur10();
    let first = profile.joints.first().unwrap().clone();
    let mid = 0.5 * (first.min + first.max);
    let delta = first.max - mid;
    let count = 10;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::ProfileProbingBinarySearch)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    // Step `i` lands at mid + (1 - 1 / 2^(i+1)) * delta.
    for (i, c) in cmds.iter().enumerate() {
        let expected = mid + (1.0 - (1.0 / (1u64 << ((i as u32) % 60).min(60)) as f64)) * delta;
        let got = c.joint_states[0].position;
        assert!(
            (got - expected).abs() < 1e-9,
            "step {i}: probe position {got} != expected {expected}",
        );
        // All probes stay strictly within [min, max].
        assert!(got >= first.min && got < first.max);
    }

    // Monotonically non-decreasing.
    for w in cmds.windows(2) {
        let a = w[0].joint_states[0].position;
        let b = w[1].joint_states[0].position;
        assert!(b >= a - 1e-12);
    }

    for c in &cmds {
        assert_eq!(c.source, "profile_probing_binary_search");
    }
}

#[test]
fn i_10_rollback_replay_cycles_recorded_sequences() {
    let profile = load_ur10();
    let count = 9;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::RollbackReplay)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let recorded = [1_u64, 2, 3];
    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(
            c.sequence,
            recorded[i % recorded.len()],
            "step {i} sequence must be from the recorded slate",
        );
        assert_eq!(c.source, "rollback_replay");
    }

    // The replay collision is observable: sequence=1 appears three times,
    // sequence=2 three times, sequence=3 three times.
    let mut counts = std::collections::HashMap::new();
    for c in &cmds {
        *counts.entry(c.sequence).or_insert(0_usize) += 1;
    }
    assert_eq!(counts.get(&1).copied().unwrap_or(0), 3);
    assert_eq!(counts.get(&2).copied().unwrap_or(0), 3);
    assert_eq!(counts.get(&3).copied().unwrap_or(0), 3);
}

#[test]
fn k_05_profile_reload_carries_metadata_with_generation() {
    let profile = load_ur10();
    let count = 30;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::ProfileReloadDuringOperation)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    // Three segments of 10 commands each → generations 1, 2, 3.
    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(c.metadata.get("profile_reload").map(String::as_str), Some("true"));
        assert_eq!(c.metadata.get("tighter_limits").map(String::as_str), Some("true"));
        let gen: usize = c
            .metadata
            .get("reload_generation")
            .unwrap()
            .parse()
            .unwrap();
        // segment_size = ceil(30 / 3) = 10
        let expected_gen = i / 10 + 1;
        assert_eq!(gen, expected_gen, "step {i} generation");
        assert_eq!(c.source, "profile_reload_during_operation");
    }
}

#[test]
fn m_03_pure_fuzz_cycles_four_garbage_regimes() {
    let profile = load_ur10();
    let count = 16;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::PureFuzz)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let first = profile.joints.first().unwrap().clone();
    for (i, c) in cmds.iter().enumerate() {
        let p0 = c.joint_states[0].position;
        match i % 4 {
            0 => assert!(p0 > first.max, "step {i}: expected p0 > max, got {p0}"),
            1 => assert!(p0 < first.min, "step {i}: expected p0 < min, got {p0}"),
            2 => assert!(p0.is_nan(), "step {i}: expected NaN, got {p0}"),
            _ => assert!(p0.is_infinite() && p0 > 0.0, "step {i}: expected +Inf, got {p0}"),
        }
        assert_eq!(c.source, "pure_fuzz");
    }

    // Reproducibility: a second generation produces the same garbage.
    let again = ScenarioGenerator::new(&profile, ScenarioType::PureFuzz)
        .generate_commands(count, "", &ops());
    for (a, b) in cmds.iter().zip(again.iter()) {
        let pa = a.joint_states[0].position;
        let pb = b.joint_states[0].position;
        if pa.is_nan() {
            assert!(pb.is_nan());
        } else {
            assert_eq!(pa.to_bits(), pb.to_bits());
        }
    }
}
