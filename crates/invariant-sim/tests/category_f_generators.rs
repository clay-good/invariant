//! Intent tests for Category F (Environmental Hazards) single-phase
//! splits F-01..F-04 that complement the pre-existing combined F-08
//! generator (`EnvironmentFault`).
//!
//! Each test asserts the deterministic structure each generator must
//! produce. Validator behaviour is covered by the per-check unit tests
//! under `crates/invariant-robotics/src/physics/`.
//!
//! v11 prompt 2.5 — see `docs/robotics/spec-v12.md`.

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

fn ops() -> Vec<Operation> {
    vec![Operation::new("actuate:*").unwrap()]
}

fn load_profile() -> invariant_robotics::models::profile::RobotProfile {
    load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell profile must be available")
}

#[test]
fn f_01_temperature_ramp_crosses_warning_and_max() {
    let profile = load_profile();
    let env = profile.environment.as_ref().expect("env config present");
    let max_temp = env.max_operating_temperature_c;
    let warning = env.warning_temperature_c;
    let count = 50;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::TemperatureRamp).generate_commands(
        count,
        "",
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    // Per-step temperatures: all joints share the same value at each step.
    let mut temps = Vec::with_capacity(count);
    for c in &cmds {
        let es = c.environment_state.as_ref().unwrap();
        let ts: Vec<f64> = es
            .actuator_temperatures
            .iter()
            .map(|t| t.temperature_celsius)
            .collect();
        assert_eq!(
            ts.len(),
            profile.joints.len(),
            "every joint must get a temperature"
        );
        assert!(ts.windows(2).all(|w| (w[0] - w[1]).abs() < 1e-12));
        temps.push(ts[0]);
    }

    // First step at ambient (20 °C), monotonically non-decreasing,
    // final > 2× max.
    assert!((temps[0] - 20.0).abs() < 1e-9);
    for w in temps.windows(2) {
        assert!(w[1] >= w[0] - 1e-12);
    }
    assert!(
        temps[count - 1] > 1.9 * max_temp,
        "final temperature must exceed ~2× max ({})",
        max_temp
    );

    // The sweep crosses both the warning band and the hard limit.
    assert!(temps.iter().any(|t| *t > warning));
    assert!(temps.iter().any(|t| *t > max_temp));
    // And starts below warning so derate-only commands exist.
    assert!(temps.iter().any(|t| *t < warning));
}

#[test]
fn f_02_battery_drain_crosses_low_and_critical() {
    let profile = load_profile();
    let env = profile.environment.as_ref().unwrap();
    let critical = env.critical_battery_pct;
    let low = env.low_battery_pct;
    let count = 40;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::BatteryDrain).generate_commands(
        count,
        "",
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    let pcts: Vec<f64> = cmds
        .iter()
        .map(|c| {
            c.environment_state
                .as_ref()
                .unwrap()
                .battery_percentage
                .unwrap()
        })
        .collect();
    // Starts at 100, monotonically non-increasing, final close to 0.
    assert!((pcts[0] - 100.0).abs() < 1e-9);
    for w in pcts.windows(2) {
        assert!(w[1] <= w[0] + 1e-12);
    }
    assert!(pcts[count - 1] < 5.0);
    // Sweep crosses both thresholds.
    assert!(pcts.iter().any(|p| *p > low));
    assert!(pcts.iter().any(|p| *p < low && *p > critical));
    assert!(pcts.iter().any(|p| *p < critical));
}

#[test]
fn f_03_latency_spike_crosses_warning_and_max() {
    let profile = load_profile();
    let env = profile.environment.as_ref().unwrap();
    let warning = env.warning_latency_ms;
    let max_l = env.max_latency_ms;
    let count = 40;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::LatencySpike).generate_commands(
        count,
        "",
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    let lats: Vec<f64> = cmds
        .iter()
        .map(|c| {
            c.environment_state
                .as_ref()
                .unwrap()
                .communication_latency_ms
                .unwrap()
        })
        .collect();
    assert!((lats[0] - 0.0).abs() < 1e-9);
    for w in lats.windows(2) {
        assert!(w[1] >= w[0] - 1e-12);
    }
    assert!(lats[count - 1] > 4.0 * max_l);
    assert!(lats.iter().any(|l| *l > warning && *l <= max_l));
    assert!(lats.iter().any(|l| *l > max_l));
    assert!(lats.iter().any(|l| *l < warning));
}

#[test]
fn f_04_estop_alternates_engaged_and_released() {
    let profile = load_profile();
    let count = 10;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::EStopEngageRelease)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    for (i, c) in cmds.iter().enumerate() {
        let engaged = c
            .environment_state
            .as_ref()
            .unwrap()
            .e_stop_engaged
            .expect("e_stop_engaged must be set");
        let expected = !i.is_multiple_of(2);
        assert_eq!(
            engaged, expected,
            "step {i}: expected engaged={expected}, got {engaged}"
        );
    }
    // Both states actually appear.
    let engaged_count = cmds
        .iter()
        .filter(|c| c.environment_state.as_ref().unwrap().e_stop_engaged == Some(true))
        .count();
    assert_eq!(engaged_count, count / 2);
}
