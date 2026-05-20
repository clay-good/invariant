//! Intent tests for Category F sensor-range / fusion variants (F-05,
//! F-06, F-07) — the second half of v11 prompt 2.5 / v12 row 2.5.
//!
//! Each test asserts the deterministic structure each generator must
//! produce. Validator behaviour for SR1/SR2 lives in
//! `crates/invariant-robotics/src/physics/environment.rs`; the fusion
//! detector lives in `crates/invariant-robotics/src/sensor.rs`.

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_robotics::sensor::SensorPayload;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

fn ops() -> Vec<Operation> {
    vec![Operation::new("actuate:*").unwrap()]
}

fn load_profile() -> invariant_robotics::models::profile::RobotProfile {
    load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell profile must be available")
}

#[test]
fn f_05_cycles_through_all_three_sr1_violation_modes() {
    let profile = load_profile();
    let count = 30;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::SensorRangeImplausible)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let mut imu_count = 0;
    let mut temp_count = 0;
    let mut batt_count = 0;
    for (i, c) in cmds.iter().enumerate() {
        let env = c
            .environment_state
            .as_ref()
            .expect("F-05 always emits an environment_state");
        match i % 3 {
            0 => {
                let pitch = env.imu_pitch_rad.expect("mode A sets imu_pitch_rad");
                assert!(
                    pitch.is_finite() && pitch.abs() > std::f64::consts::PI,
                    "mode A imu_pitch_rad {pitch} must exceed ±π plausible bound"
                );
                imu_count += 1;
            }
            1 => {
                assert!(
                    !env.actuator_temperatures.is_empty(),
                    "mode B must populate actuator_temperatures"
                );
                for t in &env.actuator_temperatures {
                    assert!(
                        t.temperature_celsius < -273.15,
                        "mode B temp {} must be below absolute zero",
                        t.temperature_celsius
                    );
                }
                temp_count += 1;
            }
            _ => {
                let pct = env
                    .battery_percentage
                    .expect("mode C sets battery_percentage");
                assert!(
                    pct > 100.0,
                    "mode C battery_percentage {pct} must be outside [0,100]"
                );
                batt_count += 1;
            }
        }
        // Joint state stays baseline-safe so SR1 is the only failure mode.
        for js in &c.joint_states {
            assert!(js.position.is_finite());
            assert!(js.velocity.is_finite());
        }
    }
    assert!(imu_count > 0 && temp_count > 0 && batt_count > 0);
    assert_eq!(imu_count + temp_count + batt_count, count);
}

#[test]
fn f_06_cycles_through_all_three_sr2_violation_modes() {
    let profile = load_profile();
    let count = 30;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::SensorPayloadRange)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    const FOUR_PI: f64 = 4.0 * std::f64::consts::PI;
    const SR2_MAX_EE_M: f64 = 1000.0;
    const SR2_MAX_EE_FORCE_N: f64 = 100_000.0;

    let mut joint_count = 0;
    let mut ee_count = 0;
    let mut force_count = 0;
    for (i, c) in cmds.iter().enumerate() {
        match i % 3 {
            0 => {
                let js = c.joint_states.first().expect("at least one joint");
                assert!(
                    js.position.is_finite() && js.position.abs() > FOUR_PI,
                    "mode A joint position {} must exceed 4π SR2 max",
                    js.position
                );
                // Other modes' fields stay clean.
                assert!(c.end_effector_forces.is_empty());
                joint_count += 1;
            }
            1 => {
                let ee = c
                    .end_effector_positions
                    .first()
                    .expect("at least one EE position");
                let max_axis = ee.position.iter().map(|v| v.abs()).fold(0.0_f64, f64::max);
                assert!(
                    max_axis > SR2_MAX_EE_M,
                    "mode B EE max-axis {max_axis} must exceed 1000 m SR2 max"
                );
                assert!(c.end_effector_forces.is_empty());
                ee_count += 1;
            }
            _ => {
                let f = c
                    .end_effector_forces
                    .first()
                    .expect("mode C emits one EE force vector");
                let mag = (f.force[0].powi(2) + f.force[1].powi(2) + f.force[2].powi(2)).sqrt();
                assert!(
                    mag > SR2_MAX_EE_FORCE_N,
                    "mode C EE force magnitude {mag} must exceed 100 kN SR2 max"
                );
                force_count += 1;
            }
        }
    }
    assert!(joint_count > 0 && ee_count > 0 && force_count > 0);
    assert_eq!(joint_count + ee_count + force_count, count);
}

#[test]
fn f_07_emits_two_diverging_readings_with_shared_sensor_name() {
    let profile = load_profile();
    let count = 12;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::SensorFusionInconsistency)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    for c in &cmds {
        assert_eq!(
            c.signed_sensor_readings.len(),
            2,
            "F-07 must emit exactly two signed sensor readings"
        );
        let a = &c.signed_sensor_readings[0].reading;
        let b = &c.signed_sensor_readings[1].reading;
        assert_eq!(
            a.sensor_name, b.sensor_name,
            "fusion divergence requires a shared sensor_name"
        );
        let (pa, pb) = match (&a.payload, &b.payload) {
            (
                SensorPayload::Position { position: pa },
                SensorPayload::Position { position: pb },
            ) => (*pa, *pb),
            _ => panic!("F-07 must emit Position payloads on both readings"),
        };
        let dist =
            ((pa[0] - pb[0]).powi(2) + (pa[1] - pb[1]).powi(2) + (pa[2] - pb[2]).powi(2)).sqrt();
        assert!(
            dist >= 9.99,
            "F-07 divergence {dist} m must be at least ~10 m for fusion to flag it"
        );
        assert_eq!(
            c.signed_sensor_readings[0].signer_kid, "f07-fusion-stub",
            "F-07 should mark readings with the documented stub signer kid"
        );
        // Joint state baseline-safe so the failure mode is unambiguous.
        for js in &c.joint_states {
            assert!(js.position.is_finite() && js.velocity.is_finite());
        }
    }
}

#[test]
fn f_05_06_07_spec_id_bindings() {
    assert_eq!(ScenarioType::SensorRangeImplausible.spec_id(), "F-05");
    assert_eq!(ScenarioType::SensorPayloadRange.spec_id(), "F-06");
    assert_eq!(ScenarioType::SensorFusionInconsistency.spec_id(), "F-07");
}
