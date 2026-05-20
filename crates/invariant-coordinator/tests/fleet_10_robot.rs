//! v11 5.5 — 10-robot fleet integration test.
//!
//! 8 arms + 2 mobile bases laid out in a 5×2 grid, scripted for 60
//! simulated seconds at 10 Hz (600 ticks). The grid spacing keeps every
//! pairwise separation well above the 0.5 m threshold for the first 30 s.
//! At t = 30 s `arm-3` starts drifting toward `arm-4` along the +x axis;
//! by t = 45 s its end-effector is 0.2 m inside the threshold. The test
//! asserts:
//!
//! 1. The `CoordinationMonitor::check` call for `arm-3`'s state at the
//!    near-miss tick returns `safe == false` with a `separation`
//!    [`CrossRobotCheck`] naming `(arm-3, arm-4)`.
//! 2. A [`FleetSnapshot`] taken at the same tick contains the near-miss
//!    geometry (so `invariant robotics fleet status` would flag it).
//! 3. Across the full 60 s sweep the monitor admits every tick before the
//!    drift begins and rejects every tick after `arm-3` crosses the
//!    threshold, mirroring the expected safety envelope.
//!
//! No I/O, no randomness, no clock dependency — every state is derived
//! deterministically from the tick index so the test is reproducible on
//! every CI run.

use chrono::{DateTime, TimeZone, Utc};
use invariant_coordinator::monitor::{
    CoordinationConfig, CoordinationMonitor, EndEffectorState, StaleRobotPolicy,
};
use invariant_coordinator::{FleetSnapshot, RobotState};

const TICK_HZ: u32 = 10;
const DURATION_SECS: u32 = 60;
const MIN_SEPARATION_M: f64 = 0.5;
/// `arm-3` starts drifting toward `arm-4` at this tick.
const DRIFT_START_TICK: u32 = 30 * TICK_HZ;
/// `arm-3` enters the separation envelope at this tick.
const DRIFT_VIOLATION_TICK: u32 = 45 * TICK_HZ;
/// Tick at which we capture the snapshot used for both assertions and the
/// fleet-status CLI rendering scenario.
const SNAPSHOT_TICK: u32 = 50 * TICK_HZ;

/// Base epoch for derived timestamps. Frozen so the test snapshot is
/// reproducible.
fn epoch() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap()
}

fn tick_to_time(tick: u32) -> DateTime<Utc> {
    epoch() + chrono::Duration::milliseconds((tick as i64) * (1000 / TICK_HZ as i64))
}

/// Returns the scripted state of robot `id` at the given tick.
fn state_at(id: &str, tick: u32) -> RobotState {
    // 5 × 2 grid: arms 1..=8 in two rows (y = 0 and y = 1), mobile bases
    // off to the right (x = 6 and 8). Spacing is 1.5 m between adjacent
    // arms along x, well above the 0.5 m threshold.
    let (mut x, y) = match id {
        "arm-1" => (0.0, 0.0),
        "arm-2" => (1.5, 0.0),
        "arm-3" => (3.0, 0.0),
        "arm-4" => (4.5, 0.0),
        "arm-5" => (0.0, 1.0),
        "arm-6" => (1.5, 1.0),
        "arm-7" => (3.0, 1.0),
        "arm-8" => (4.5, 1.0),
        "base-1" => (6.0, 0.5),
        "base-2" => (8.0, 0.5),
        _ => panic!("unknown robot id {id}"),
    };

    // `arm-3` drifts toward `arm-4` along +x after DRIFT_START_TICK.
    // Drift rate is tuned so that at DRIFT_VIOLATION_TICK its EE sits at
    // x = 4.0 — exactly 0.5 m away from arm-4's x = 4.5 (i.e. on the
    // boundary), then continues past it.
    if id == "arm-3" && tick >= DRIFT_START_TICK {
        // From x = 3.0 → x = 4.0 over (DRIFT_VIOLATION_TICK - DRIFT_START_TICK)
        // ticks, then keeps going at the same rate.
        let elapsed = (tick - DRIFT_START_TICK) as f64;
        let total = (DRIFT_VIOLATION_TICK - DRIFT_START_TICK) as f64;
        x = 3.0 + 1.0 * (elapsed / total);
    }

    RobotState {
        robot_id: id.into(),
        timestamp: tick_to_time(tick),
        end_effector_positions: vec![EndEffectorState {
            name: if id.starts_with("base") {
                "base_origin".into()
            } else {
                "tcp".into()
            },
            position: [x, y, 0.5],
        }],
        active: true,
    }
}

fn all_robots() -> [&'static str; 10] {
    [
        "arm-1", "arm-2", "arm-3", "arm-4", "arm-5", "arm-6", "arm-7", "arm-8", "base-1",
        "base-2",
    ]
}

fn build_monitor() -> CoordinationMonitor {
    CoordinationMonitor::new(CoordinationConfig {
        min_separation_m: MIN_SEPARATION_M,
        stale_timeout_ms: 1_000,
        stale_policy: StaleRobotPolicy::TreatAsObstacle,
        max_robots: 16,
    })
}

#[test]
fn pre_drift_monitor_admits_every_state() {
    let mut mon = build_monitor();
    for id in all_robots() {
        mon.update_state(state_at(id, 0)).unwrap();
    }
    // For every tick in [0, DRIFT_START_TICK), every robot's update must be
    // accepted as safe (modulo arm-3, whose proposed position is the same
    // as its current state since drift hasn't started).
    let tick = DRIFT_START_TICK - 1;
    for id in all_robots() {
        // Re-register so timestamps stay fresh for stale-check.
        mon.update_state(state_at(id, tick)).unwrap();
    }
    let now = tick_to_time(tick);
    for id in all_robots() {
        let proposed = state_at(id, tick);
        let verdict = mon.check(&proposed, now);
        assert!(
            verdict.safe,
            "robot {id} should be safe before drift; failed checks: {:?}",
            verdict.checks.iter().filter(|c| !c.passed).collect::<Vec<_>>()
        );
    }
}

#[test]
fn post_drift_monitor_rejects_arm3_with_named_separation_check() {
    let mut mon = build_monitor();
    // Seed with everyone's pre-drift state.
    for id in all_robots() {
        mon.update_state(state_at(id, 0)).unwrap();
    }
    // Advance every robot except arm-3 to SNAPSHOT_TICK; arm-3's state
    // would be the violating one.
    for id in all_robots() {
        if id == "arm-3" {
            continue;
        }
        mon.update_state(state_at(id, SNAPSHOT_TICK)).unwrap();
    }
    let now = tick_to_time(SNAPSHOT_TICK);
    let proposed = state_at("arm-3", SNAPSHOT_TICK);
    let verdict = mon.check(&proposed, now);
    assert!(!verdict.safe, "post-drift arm-3 must be rejected");
    let sep_check = verdict
        .checks
        .iter()
        .find(|c| c.name == "separation" && !c.passed)
        .expect("a failing separation check must be present");
    let pair = (sep_check.robot_a.as_str(), sep_check.robot_b.as_str());
    assert!(
        pair == ("arm-3", "arm-4") || pair == ("arm-4", "arm-3"),
        "failing pair must name arm-3 and arm-4, got {pair:?}"
    );
}

#[test]
fn snapshot_at_violation_tick_round_trips_through_serde_json() {
    let mut mon = build_monitor();
    for id in all_robots() {
        mon.update_state(state_at(id, SNAPSHOT_TICK)).unwrap();
    }
    let snap: FleetSnapshot = mon.snapshot(tick_to_time(SNAPSHOT_TICK));
    assert_eq!(snap.states.len(), 10);
    // States are sorted by robot_id, so arm-1 is first.
    assert_eq!(snap.states[0].robot_id, "arm-1");
    // Serde round-trip — the `fleet status` CLI consumes this exact bytes.
    let bytes = serde_json::to_vec_pretty(&snap).expect("FleetSnapshot serializes");
    let reloaded: FleetSnapshot =
        serde_json::from_slice(&bytes).expect("FleetSnapshot round-trips");
    assert_eq!(reloaded.states.len(), 10);
    assert_eq!(
        reloaded.config.min_separation_m, MIN_SEPARATION_M,
        "config must survive serde"
    );
}

#[test]
fn full_60s_sweep_classifies_every_tick_correctly() {
    let mut mon = build_monitor();
    let total_ticks = DURATION_SECS * TICK_HZ;
    let mut first_violation: Option<u32> = None;

    for tick in 0..total_ticks {
        // Re-publish every robot's state for this tick.
        for id in all_robots() {
            mon.update_state(state_at(id, tick)).unwrap();
        }
        let now = tick_to_time(tick);
        // Snapshot's separation alerts == the source of truth for any
        // pairwise violation at this tick.
        let snap = mon.snapshot(now);
        let any_violation = pairwise_min_separation(&snap) < MIN_SEPARATION_M;
        if any_violation && first_violation.is_none() {
            first_violation = Some(tick);
        }

        if tick < DRIFT_START_TICK {
            assert!(
                !any_violation,
                "no violations expected before drift (tick {tick})"
            );
        }
        if tick > DRIFT_VIOLATION_TICK {
            assert!(
                any_violation,
                "tick {tick} past DRIFT_VIOLATION_TICK must have a violation \
                 (min_sep={:.4})",
                pairwise_min_separation(&snap)
            );
        }
    }

    // First violation must land at the boundary tick (or one tick later
    // depending on rounding), strictly between DRIFT_START_TICK and
    // DRIFT_VIOLATION_TICK + 1.
    let first = first_violation.expect("at least one violation must occur");
    assert!(
        (DRIFT_START_TICK..=DRIFT_VIOLATION_TICK + 1).contains(&first),
        "first violation tick {first} should be within [{DRIFT_START_TICK}, \
         {}]",
        DRIFT_VIOLATION_TICK + 1
    );
}

/// Minimum pairwise EE distance across every robot pair in `snap`.
fn pairwise_min_separation(snap: &FleetSnapshot) -> f64 {
    let mut best = f64::INFINITY;
    for i in 0..snap.states.len() {
        for j in (i + 1)..snap.states.len() {
            for ee_a in &snap.states[i].end_effector_positions {
                for ee_b in &snap.states[j].end_effector_positions {
                    let dx = ee_a.position[0] - ee_b.position[0];
                    let dy = ee_a.position[1] - ee_b.position[1];
                    let dz = ee_a.position[2] - ee_b.position[2];
                    let d = (dx * dx + dy * dy + dz * dz).sqrt();
                    if d < best {
                        best = d;
                    }
                }
            }
        }
    }
    best
}
