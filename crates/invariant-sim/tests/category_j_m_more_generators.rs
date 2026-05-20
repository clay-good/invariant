//! Intent tests for the second round of Category I / J / M generators
//! (I-09 `TimingExploitation`, J-04 `WatchdogTimeoutReplay`, M-01
//! `RateStressSustained`).
//!
//! Each test asserts the deterministic shape its generator must produce; it
//! does not exercise the validator. Validator behaviour for these failure
//! modes is covered by the per-check unit tests under
//! `crates/invariant-robotics`.
//!
//! v11 prompts 2.8 / 2.9 / 2.10 (I, J, M) — see `docs/robotics/spec-v11.md`
//! and `docs/robotics/spec-15m-campaign.md` §3.

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
fn j_04_watchdog_timeout_replay_two_phases() {
    let profile = load_ur10();
    let count = 30;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::WatchdogTimeoutReplay)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let phase_boundary = count / 3; // 10
    let normal_dt = profile.max_delta_time * 0.5;
    let missed_dt = profile.max_delta_time * 5.0;

    // Phase 1: missed heartbeats (delta_time = 5× max). Sequences are
    // distinct and monotonic so isolation of the P8 failure mode is clean.
    let mut last_seq: Option<u64> = None;
    for (i, c) in cmds.iter().take(phase_boundary).enumerate() {
        assert!(
            (c.delta_time - missed_dt).abs() < 1e-12,
            "phase-1 step {i} delta_time {} != missed {}",
            c.delta_time,
            missed_dt,
        );
        if let Some(prev) = last_seq {
            assert!(c.sequence > prev, "phase-1 sequence must be monotonic");
        }
        last_seq = Some(c.sequence);
    }

    // Phase 2: every command replays sequence = 1.
    for (i, c) in cmds.iter().skip(phase_boundary).enumerate() {
        assert!(
            (c.delta_time - normal_dt).abs() < 1e-12,
            "phase-2 step {i} delta_time {} != normal {}",
            c.delta_time,
            normal_dt,
        );
        assert_eq!(c.sequence, 1, "phase-2 step {i} must replay sequence=1");
    }

    // Source tag is stable across phases so a per-source monotonicity
    // tracker observes the replay collision rather than treating the two
    // phases as distinct streams.
    for c in &cmds {
        assert_eq!(c.source, "watchdog_timeout_replay");
    }
}

#[test]
fn i_09_timing_exploitation_alternates_at_tight_delta_time() {
    let profile = load_ur10();
    let first = profile.joints.first().unwrap().clone();
    let mid = 0.5 * (first.min + first.max);
    let count = 20;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::TimingExploitation)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let expected_dt = profile.max_delta_time.clamp(1e-4, 0.001);
    for c in &cmds {
        assert!(
            (c.delta_time - expected_dt).abs() < 1e-12,
            "delta_time must clamp to ~1ms, got {}",
            c.delta_time
        );
    }

    // Even-index commands sit at the baseline midpoint (PASS).
    // Odd-index commands push the first joint to 2× max (REJECT P1).
    for (i, c) in cmds.iter().enumerate() {
        let p0 = c.joint_states[0].position;
        if i.is_multiple_of(2) {
            assert!(
                (p0 - mid).abs() < 1e-9,
                "even-index step {i} must be at midpoint {mid}, got {p0}",
            );
        } else {
            assert!(
                (p0 - first.max * 2.0).abs() < 1e-9,
                "odd-index step {i} must be at 2× max, got {p0}",
            );
        }
    }

    for c in &cmds {
        assert_eq!(c.source, "timing_exploitation");
    }
}

#[test]
fn m_01_rate_stress_sustained_baseline_safe_at_1khz() {
    let profile = load_ur10();
    let first = profile.joints.first().unwrap().clone();
    let mid = 0.5 * (first.min + first.max);
    let count = 60_000; // 60 s × 1 kHz, per spec row M-01
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::RateStressSustained)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let expected_dt = profile.max_delta_time.clamp(1e-4, 0.001);
    for c in &cmds {
        assert!(
            (c.delta_time - expected_dt).abs() < 1e-12,
            "delta_time must clamp to ~1 ms"
        );
        assert!(
            (c.joint_states[0].position - mid).abs() < 1e-9,
            "first joint must stay at midpoint"
        );
        assert_eq!(
            c.metadata.get("rate_stress").map(String::as_str),
            Some("true"),
            "rate_stress metadata must be set"
        );
        assert_eq!(c.source, "rate_stress_sustained");
    }

    // Sequences are strictly monotonic across the whole run.
    for w in cmds.windows(2) {
        assert!(
            w[1].sequence > w[0].sequence,
            "sequence must be monotonic at sustained throughput",
        );
    }
}
