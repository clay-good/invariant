//! Intent tests for Category E (Manipulation Safety) and the H-06 row
//! that landed alongside the E-01..E-03 generators.
//!
//! Each test asserts the deterministic structure each generator must
//! produce — it does NOT exercise the validator. Validator behaviour is
//! covered by the per-check unit tests under `crates/invariant-robotics`.
//!
//! v11 prompt 2.4 (Category E) + v11 prompt 2.7 (Category H tail) —
//! see `docs/robotics/spec-v12.md` and `docs/robotics/spec-v11.md`.

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

fn ops() -> Vec<Operation> {
    vec![Operation::new("actuate:*").unwrap()]
}

fn load_ur10e() -> invariant_robotics::models::profile::RobotProfile {
    load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell profile must be available")
}

#[test]
fn e_01_force_limit_sweep_ramps_zero_to_three_times_max() {
    let profile = load_ur10e();
    let max_force = profile
        .end_effectors
        .first()
        .map(|e| e.max_force_n)
        .expect("ur10e_haas_cell has an end_effectors entry");
    let count = 30;
    let cmds =
        ScenarioGenerator::new(&profile, ScenarioType::ForceLimitSweep).generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    // First command sits at force = 0.
    let f0 = &cmds[0].end_effector_forces;
    assert_eq!(f0.len(), 1);
    assert!((f0[0].force[0] - 0.0).abs() < 1e-12);

    // The magnitude is monotonically non-decreasing along +x.
    for w in cmds.windows(2) {
        let a = w[0].end_effector_forces[0].force[0];
        let b = w[1].end_effector_forces[0].force[0];
        assert!(b >= a - 1e-12, "force ramp must be non-decreasing: {a} -> {b}");
    }

    // Final command exceeds 2× max_force_n (3× ramp - last step gap).
    let last = cmds[count - 1].end_effector_forces[0].force[0];
    assert!(
        last > 2.0 * max_force,
        "final force {last} must exceed 2× max_force_n {max_force}"
    );

    // Every reported end-effector name matches the profile's first ee.
    let ee_name = &profile.end_effectors[0].name;
    for c in &cmds {
        assert_eq!(&c.end_effector_forces[0].name, ee_name);
        assert!(c.end_effector_forces[0].grasp_force.is_none());
    }
}

#[test]
fn e_02_grasp_force_envelope_covers_all_five_regimes() {
    let profile = load_ur10e();
    let (min_g, max_g) = profile
        .end_effectors
        .first()
        .map(|e| (e.min_grasp_force_n, e.max_grasp_force_n))
        .unwrap();
    let count = 25; // exactly 5 cycles of 5 regimes
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::GraspForceEnvelope)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let mid = 0.5 * (min_g + max_g);
    let expected = [0.5 * min_g, min_g, mid, max_g, 1.5 * max_g];
    for (i, c) in cmds.iter().enumerate() {
        let g = c.end_effector_forces[0]
            .grasp_force
            .expect("grasp_force must be set for E-02");
        assert!(
            (g - expected[i % expected.len()]).abs() < 1e-9,
            "step {i} grasp_force {g} != expected {}",
            expected[i % expected.len()]
        );
    }

    // Each of the five regimes appeared at least once in the sequence.
    for want in expected {
        assert!(
            cmds.iter().any(|c| {
                let g = c.end_effector_forces[0].grasp_force.unwrap();
                (g - want).abs() < 1e-9
            }),
            "regime {want} grasp force never appeared"
        );
    }
}

#[test]
fn e_03_force_rate_spike_alternates_zero_and_over_rate() {
    let profile = load_ur10e();
    let max_rate = profile
        .end_effectors
        .first()
        .map(|e| e.max_force_rate_n_per_s)
        .unwrap();
    let count = 20;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::ForceRateSpike)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let dt = cmds[0].delta_time;
    let rate_limit = max_rate * dt; // expected per-step delta budget under P13

    for c in &cmds {
        let fx = c.end_effector_forces[0].force[0];
        if c.sequence.is_multiple_of(2) {
            // Even-sequence: large spike (> 2× rate budget).
            assert!(
                fx > 2.0 * rate_limit,
                "even-sequence step seq={} fx={fx} must exceed 2× rate_limit {rate_limit}",
                c.sequence
            );
        } else {
            // Odd-sequence: explicit zero force so the validator's
            // previous_forces snapshot is the rate's lower bound.
            assert_eq!(fx, 0.0, "odd-sequence step seq={} must be zero", c.sequence);
        }
    }
}

#[test]
fn h_06_future_dated_sensor_has_timestamp_ahead_of_command() {
    let profile = load_ur10e();
    let count = 12;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::FutureDatedSensor)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    for c in &cmds {
        assert_eq!(
            c.signed_sensor_readings.len(),
            1,
            "H-06 must attach exactly one signed sensor reading per command"
        );
        let r = &c.signed_sensor_readings[0];
        let delta = r.reading.timestamp - c.timestamp;
        // 10s ahead, tolerance for sub-millisecond rounding.
        assert!(
            delta.num_milliseconds() >= 9_999 && delta.num_milliseconds() <= 10_001,
            "sensor timestamp must be ~10s ahead of command (got {} ms)",
            delta.num_milliseconds()
        );
        assert_eq!(r.signer_kid, "h06-future-stub");
        assert!(!r.signature.is_empty());
    }
}
