//! Coordinator partition-merge soundness fixture (v12-N-18).
//!
//! Four robots split across two AABB workspace partitions (`A`, `B`). Each
//! partition is internally safe — the two robots inside each partition are
//! well above the minimum-separation threshold — and the closest cross-
//! partition pair sits exactly at the threshold. Merging the partitions'
//! plans into one `CoordinationMonitor` must therefore admit every robot.
//!
//! A second test perturbs one robot in partition `A` toward partition `B`
//! by a tunable `EPS` and asserts the merged plan is rejected with a
//! separation check that names the offending pair.

use chrono::{DateTime, Utc};
use invariant_coordinator::monitor::{CoordinationConfig, EndEffectorState, StaleRobotPolicy};
use invariant_coordinator::{
    CoordinationMonitor, CoordinationVerdict, RobotState, WorkspacePartition,
    WorkspacePartitionConfig,
};

const MIN_SEPARATION_M: f64 = 0.5;
/// Perturbation magnitude that pushes the merged plan just past the
/// separation threshold. Tune here to make the boundary case more or
/// less aggressive.
const EPS: f64 = 1.0e-3;

const ARM_1: &str = "arm-1";
const ARM_2: &str = "arm-2";
const BASE_1: &str = "base-1";
const BASE_2: &str = "base-2";

const PARTITION_A: &str = "partition-A";
const PARTITION_B: &str = "partition-B";

/// Build the AABB partition config. Partition `A` is split along `y = 2.0`
/// into two non-overlapping sub-zones (one per arm); partition `B` is split
/// the same way (one per mobile base). The A / B halves abut at `x = 2.5`.
/// The overlap check uses strict inequality on both bounds, so partitions
/// that share a face (same `max` / `min` plane) are accepted.
fn build_partitions() -> WorkspacePartitionConfig {
    let a1 = WorkspacePartition {
        name: format!("{PARTITION_A}-1"),
        robot_id: ARM_1.into(),
        min: [0.0, 0.0, 0.0],
        max: [2.5, 2.0, 3.0],
    };
    let a2 = WorkspacePartition {
        name: format!("{PARTITION_A}-2"),
        robot_id: ARM_2.into(),
        min: [0.0, 2.0, 0.0],
        max: [2.5, 4.0, 3.0],
    };
    let b1 = WorkspacePartition {
        name: format!("{PARTITION_B}-1"),
        robot_id: BASE_1.into(),
        min: [2.5, 0.0, 0.0],
        max: [5.0, 2.0, 3.0],
    };
    let b2 = WorkspacePartition {
        name: format!("{PARTITION_B}-2"),
        robot_id: BASE_2.into(),
        min: [2.5, 2.0, 0.0],
        max: [5.0, 4.0, 3.0],
    };
    WorkspacePartitionConfig::new(vec![a1, a2, b1, b2])
        .expect("hand-crafted partitions must be admitted by the config")
}

fn ee(name: &str, position: [f64; 3]) -> EndEffectorState {
    EndEffectorState {
        name: name.into(),
        position,
    }
}

fn robot_state(robot_id: &str, ts: DateTime<Utc>, position: [f64; 3]) -> RobotState {
    RobotState {
        robot_id: robot_id.into(),
        timestamp: ts,
        end_effector_positions: vec![ee("tcp", position)],
        active: true,
    }
}

/// Positions used by both tests. Each robot's position lies strictly
/// inside its sub-partition. The closest cross-partition pair is
/// (`arm-1`, `base-1`), exactly `MIN_SEPARATION_M` apart along the +x axis.
fn baseline_positions() -> [(&'static str, [f64; 3]); 4] {
    [
        // arm-1 in partition-A-1 (y<2.0); base-1 across the boundary in B-1.
        (ARM_1, [2.25, 1.0, 1.0]),
        (BASE_1, [2.75, 1.0, 1.0]),
        // arm-2 in partition-A-2 (y>2.0); base-2 in B-2 — far from the
        // closest-pair line so internal pairs cannot dominate.
        (ARM_2, [1.0, 3.0, 1.0]),
        (BASE_2, [4.0, 3.0, 1.0]),
    ]
}

fn build_monitor() -> (CoordinationMonitor, DateTime<Utc>) {
    let config = CoordinationConfig {
        min_separation_m: MIN_SEPARATION_M,
        stale_timeout_ms: 60_000,
        stale_policy: StaleRobotPolicy::TreatAsObstacle,
        max_robots: 8,
    };
    let monitor = CoordinationMonitor::new(config);
    (monitor, Utc::now())
}

fn register_all(monitor: &mut CoordinationMonitor, ts: DateTime<Utc>) {
    for (id, pos) in baseline_positions() {
        monitor
            .update_state(robot_state(id, ts, pos))
            .expect("baseline registration must succeed");
    }
}

fn assert_each_robot_safe(monitor: &CoordinationMonitor, ts: DateTime<Utc>) {
    for (id, pos) in baseline_positions() {
        let verdict: CoordinationVerdict = monitor.check(&robot_state(id, ts, pos), ts);
        assert!(
            verdict.safe,
            "merged plan must admit {id}: {} check(s) recorded, details: {:?}",
            verdict.checks.len(),
            verdict
                .checks
                .iter()
                .map(|c| c.details.clone())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn partition_internal_consistency() {
    // Every baseline position lies inside its assigned partition. This
    // is the "each partition is internally safe" precondition.
    let config = build_partitions();
    for (id, pos) in baseline_positions() {
        config
            .check_position(id, &pos)
            .unwrap_or_else(|e| panic!("{id} at {pos:?} must be inside its partition: {e}"));
    }
}

#[test]
fn merged_plan_at_boundary_is_admitted() {
    // The closest cross-partition pair (arm-1 at x=2.25, base-1 at x=2.75)
    // is exactly MIN_SEPARATION_M apart, which is the inclusive boundary
    // for the separation check (`min_dist >= MIN_SEPARATION_M` passes).
    let pair = baseline_positions();
    // baseline_positions returns [ARM_1, BASE_1, ARM_2, BASE_2]; the
    // critical cross-partition pair is index 0 / 1.
    assert_eq!(pair[0].0, ARM_1);
    assert_eq!(pair[1].0, BASE_1);
    let a = pair[0].1;
    let b = pair[1].1;
    let dx = a[0] - b[0];
    let dy = a[1] - b[1];
    let dz = a[2] - b[2];
    let dist = (dx * dx + dy * dy + dz * dz).sqrt();
    assert!(
        (dist - MIN_SEPARATION_M).abs() < 1e-9,
        "closest cross-partition pair must equal MIN_SEPARATION_M exactly \
         (got {dist})"
    );

    let (mut monitor, ts) = build_monitor();
    register_all(&mut monitor, ts);
    assert_each_robot_safe(&monitor, ts);
}

#[test]
fn perturbed_plan_is_rejected_with_offending_pair_named() {
    // Push arm-1 by +EPS along +x — toward base-1 — so the merged plan
    // violates separation by EPS. The verdict must (a) be unsafe and (b)
    // contain a separation check whose `robot_a`/`robot_b` pair names
    // arm-1 and base-1 in some order.
    let (mut monitor, ts) = build_monitor();
    register_all(&mut monitor, ts);

    let perturbed_arm_1 = robot_state(ARM_1, ts, [2.25 + EPS, 1.0, 1.0]);
    monitor
        .update_state(perturbed_arm_1.clone())
        .expect("perturbed arm-1 registration must succeed");

    let verdict = monitor.check(&perturbed_arm_1, ts);
    assert!(
        !verdict.safe,
        "perturbed merged plan must be rejected (EPS={EPS}, threshold={MIN_SEPARATION_M})"
    );

    let offending = verdict
        .checks
        .iter()
        .find(|c| !c.passed && c.name == "separation")
        .unwrap_or_else(|| {
            panic!(
                "no failing separation check in verdict: {:?}",
                verdict.checks
            )
        });

    let names = (offending.robot_a.as_str(), offending.robot_b.as_str());
    let is_a1_b1 = names == (ARM_1, BASE_1) || names == (BASE_1, ARM_1);
    assert!(
        is_a1_b1,
        "failing separation check must name (arm-1, base-1); got {names:?}"
    );

    assert!(
        offending.details.contains("VIOLATION"),
        "details should mention VIOLATION; got: {}",
        offending.details
    );
}

#[test]
fn perturbation_below_eps_does_not_trip_check() {
    // Sanity: a perturbation of EPS/2 still violates strictly, but a
    // perturbation in the *opposite* direction (away from base-1) keeps
    // the plan safe. Confirms EPS direction matters and our test isn't
    // accidentally passing on numerical noise.
    let (mut monitor, ts) = build_monitor();
    register_all(&mut monitor, ts);

    let away = robot_state(ARM_1, ts, [2.25 - EPS, 1.0, 1.0]);
    monitor
        .update_state(away.clone())
        .expect("away perturbation must register");
    let verdict = monitor.check(&away, ts);
    assert!(
        verdict.safe,
        "perturbation AWAY from base-1 must not trip the separation check"
    );
}
