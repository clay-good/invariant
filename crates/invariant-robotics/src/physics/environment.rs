//! Environmental awareness checks P21–P25.
//!
//! These checks validate environmental sensor data against profile-configured
//! thresholds. All sensor fields are optional; checks for absent data are
//! gracefully skipped (fail-open), except P25 (e-stop) which is always active
//! when present.

use crate::models::command::{Command, EnvironmentState};
use crate::models::profile::EnvironmentConfig;
use crate::models::verdict::{CheckResult, DeratingAdvice};

/// `CheckResult.name` used by SR1 (environment-side sensor range).
pub const SR1_CHECK_NAME: &str = "SR1.sensor-range-env";

/// `CheckResult.name` used by SR2 (payload-side sensor range).
pub const SR2_CHECK_NAME: &str = "SR2.sensor-range-payload";

/// SR2 plausibility bounds — values larger than these cannot come from real
/// hardware and indicate a corrupted driver or spoofed payload (spec-v2 §3.2).
pub const SR2_MAX_JOINT_POSITION_RAD: f64 = 4.0 * std::f64::consts::PI;
pub const SR2_MAX_JOINT_VELOCITY_RAD_S: f64 = 1000.0;
pub const SR2_MAX_EE_POSITION_M: f64 = 1000.0;
pub const SR2_MAX_EE_FORCE_N: f64 = 100_000.0;

/// Compute a linear derating factor in [min_factor, 1.0] based on where
/// `value` falls between `warning_threshold` and `max_threshold`.
///
/// At warning_threshold: returns 1.0 (no derating).
/// At max_threshold: returns min_factor (maximum derating).
/// Between: linear interpolation.
fn linear_derating(value: f64, warning_threshold: f64, max_threshold: f64, min_factor: f64) -> f64 {
    if max_threshold <= warning_threshold {
        return min_factor; // degenerate config
    }
    let t = (value - warning_threshold) / (max_threshold - warning_threshold);
    (1.0 - t * (1.0 - min_factor)).clamp(min_factor, 1.0)
}

/// P21: Incline / terrain safety.
///
/// Rejects commands when IMU reports pitch or roll angles exceeding safe limits.
/// When angles are between warning and max thresholds, passes with velocity
/// derating advice. Skipped when IMU data is absent.
pub fn check_terrain_incline(env: &EnvironmentState, config: &EnvironmentConfig) -> CheckResult {
    let mut violations: Vec<String> = Vec::new();
    let mut worst_derating = 1.0f64;

    if let Some(pitch) = env.imu_pitch_rad {
        if !pitch.is_finite() {
            violations.push("imu_pitch_rad is NaN or infinite".to_string());
        } else if pitch.abs() > config.max_safe_pitch_rad {
            violations.push(format!(
                "pitch {:.4} rad exceeds max_safe_pitch_rad {:.4} rad",
                pitch.abs(),
                config.max_safe_pitch_rad
            ));
        } else if pitch.abs() > config.warning_pitch_rad {
            let factor = linear_derating(
                pitch.abs(),
                config.warning_pitch_rad,
                config.max_safe_pitch_rad,
                0.3,
            );
            worst_derating = worst_derating.min(factor);
        }
    }

    if let Some(roll) = env.imu_roll_rad {
        if !roll.is_finite() {
            violations.push("imu_roll_rad is NaN or infinite".to_string());
        } else if roll.abs() > config.max_safe_roll_rad {
            violations.push(format!(
                "roll {:.4} rad exceeds max_safe_roll_rad {:.4} rad",
                roll.abs(),
                config.max_safe_roll_rad
            ));
        } else if roll.abs() > config.warning_roll_rad {
            let factor = linear_derating(
                roll.abs(),
                config.warning_roll_rad,
                config.max_safe_roll_rad,
                0.3,
            );
            worst_derating = worst_derating.min(factor);
        }
    }

    if !violations.is_empty() {
        return CheckResult {
            name: "terrain_incline".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        };
    }

    let derating = if worst_derating < 1.0 {
        Some(DeratingAdvice {
            velocity_scale: worst_derating,
            torque_scale: 1.0,
            reason: format!(
                "terrain incline in warning zone — reduce velocity to {:.0}%",
                worst_derating * 100.0
            ),
        })
    } else {
        None
    };

    CheckResult {
        name: "terrain_incline".to_string(),
        category: "physics".to_string(),
        passed: true,
        details: if derating.is_some() {
            format!(
                "terrain angles in warning zone (velocity derate to {:.0}%)",
                worst_derating * 100.0
            )
        } else {
            "terrain angles within safe limits".to_string()
        },
        derating,
    }
}

/// P22: Operating temperature bounds.
///
/// Rejects commands when any actuator reports a temperature exceeding the
/// maximum operating temperature. When temperatures are between warning and
/// max, passes with torque derating advice. Skipped when no temperature data.
pub fn check_actuator_temperature(
    env: &EnvironmentState,
    config: &EnvironmentConfig,
) -> CheckResult {
    if env.actuator_temperatures.is_empty() {
        return CheckResult {
            name: "actuator_temperature".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no actuator temperature data to check".to_string(),
            derating: None,
        };
    }

    let mut violations: Vec<String> = Vec::new();
    let mut worst_derating = 1.0f64;

    for reading in &env.actuator_temperatures {
        if !reading.temperature_celsius.is_finite() {
            violations.push(format!(
                "'{}': temperature is NaN or infinite",
                reading.joint_name
            ));
        } else if reading.temperature_celsius > config.max_operating_temperature_c {
            violations.push(format!(
                "'{}': temperature {:.1}°C exceeds max {:.1}°C",
                reading.joint_name, reading.temperature_celsius, config.max_operating_temperature_c
            ));
        } else if reading.temperature_celsius > config.warning_temperature_c {
            let factor = linear_derating(
                reading.temperature_celsius,
                config.warning_temperature_c,
                config.max_operating_temperature_c,
                0.5,
            );
            worst_derating = worst_derating.min(factor);
        }
    }

    if !violations.is_empty() {
        return CheckResult {
            name: "actuator_temperature".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        };
    }

    let derating = if worst_derating < 1.0 {
        Some(DeratingAdvice {
            velocity_scale: 1.0,
            torque_scale: worst_derating,
            reason: format!(
                "actuator temperature in warning zone — reduce torque to {:.0}%",
                worst_derating * 100.0
            ),
        })
    } else {
        None
    };

    CheckResult {
        name: "actuator_temperature".to_string(),
        category: "physics".to_string(),
        passed: true,
        details: if derating.is_some() {
            format!(
                "actuator temperatures in warning zone (torque derate to {:.0}%)",
                worst_derating * 100.0
            )
        } else {
            "all actuator temperatures within operating limits".to_string()
        },
        derating,
    }
}

/// P23: Battery / power state validation.
///
/// Rejects commands when battery percentage is below the critical threshold.
/// Issues a passing result with advisory details when below the low threshold.
/// Skipped when battery data is absent.
pub fn check_battery_state(env: &EnvironmentState, config: &EnvironmentConfig) -> CheckResult {
    let Some(pct) = env.battery_percentage else {
        return CheckResult {
            name: "battery_state".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no battery data to check".to_string(),
            derating: None,
        };
    };

    if !pct.is_finite() {
        return CheckResult {
            name: "battery_state".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "battery_percentage is NaN or infinite".to_string(),
            derating: None,
        };
    }

    if pct < config.critical_battery_pct {
        CheckResult {
            name: "battery_state".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "battery {:.1}% is below critical threshold {:.1}%",
                pct, config.critical_battery_pct
            ),
            derating: None,
        }
    } else if pct < config.low_battery_pct {
        // Linear derating: at low_battery_pct factor=1.0, at critical factor=0.3.
        let factor = linear_derating(
            config.low_battery_pct - pct, // invert: higher deficit = more derating
            0.0,
            config.low_battery_pct - config.critical_battery_pct,
            0.3,
        );
        CheckResult {
            name: "battery_state".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "battery {:.1}% is below low threshold {:.1}% — derate to {:.0}%",
                pct,
                config.low_battery_pct,
                factor * 100.0
            ),
            derating: Some(DeratingAdvice {
                velocity_scale: factor,
                torque_scale: factor,
                reason: format!(
                    "low battery {:.1}% — reduce velocity and torque to {:.0}%",
                    pct,
                    factor * 100.0
                ),
            }),
        }
    } else {
        CheckResult {
            name: "battery_state".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!("battery {:.1}% is within operating range", pct),
            derating: None,
        }
    }
}

/// P24: Communication latency bounds.
///
/// Rejects commands when round-trip communication latency exceeds the maximum
/// acceptable threshold. Skipped when latency data is absent.
pub fn check_communication_latency(
    env: &EnvironmentState,
    config: &EnvironmentConfig,
) -> CheckResult {
    let Some(latency) = env.communication_latency_ms else {
        return CheckResult {
            name: "communication_latency".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no latency data to check".to_string(),
            derating: None,
        };
    };

    if !latency.is_finite() {
        return CheckResult {
            name: "communication_latency".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "communication_latency_ms is NaN or infinite".to_string(),
            derating: None,
        };
    }

    if latency > config.max_latency_ms {
        CheckResult {
            name: "communication_latency".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "latency {:.1} ms exceeds max_latency_ms {:.1} ms",
                latency, config.max_latency_ms
            ),
            derating: None,
        }
    } else if latency > config.warning_latency_ms {
        let factor = linear_derating(
            latency,
            config.warning_latency_ms,
            config.max_latency_ms,
            0.3,
        );
        CheckResult {
            name: "communication_latency".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "latency {:.1} ms in warning zone — derate velocity to {:.0}%",
                latency,
                factor * 100.0
            ),
            derating: Some(DeratingAdvice {
                velocity_scale: factor,
                torque_scale: 1.0,
                reason: format!(
                    "high latency {:.1} ms — reduce velocity to {:.0}%",
                    latency,
                    factor * 100.0
                ),
            }),
        }
    } else {
        CheckResult {
            name: "communication_latency".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!("latency {:.1} ms is within acceptable bounds", latency),
            derating: None,
        }
    }
}

/// SR1 — environment-side sensor range validation.
///
/// Reject physically impossible values in `EnvironmentState` before they
/// reach the P21-P25 threshold checks. This catches corrupted sensor
/// drivers or spoofed data that reports values outside the laws of physics:
/// - IMU angles > π rad (physically impossible for a rigid body)
/// - Temperature below absolute zero (-273.15°C) or above 1000°C
/// - Battery percentage outside [0, 100]
/// - Communication latency negative
///
/// These are NOT threshold checks (P21-P25 handle that). These are
/// plausibility bounds — values that no real sensor can produce.
///
/// Split from the unified `check_sensor_range` in v11 5.1; the payload-side
/// counterpart is [`check_sensor_range_payload`].
pub fn check_sensor_range_env(env: &EnvironmentState) -> CheckResult {
    let mut violations: Vec<String> = Vec::new();

    // IMU: angles beyond ±π rad are physically impossible for a rigid body.
    if let Some(pitch) = env.imu_pitch_rad {
        if pitch.is_finite() && pitch.abs() > std::f64::consts::PI {
            violations.push(format!(
                "imu_pitch_rad {:.4} exceeds physical limit ±π rad",
                pitch
            ));
        }
    }
    if let Some(roll) = env.imu_roll_rad {
        if roll.is_finite() && roll.abs() > std::f64::consts::PI {
            violations.push(format!(
                "imu_roll_rad {:.4} exceeds physical limit ±π rad",
                roll
            ));
        }
    }

    // Temperature: below absolute zero or above 1000°C (no actuator operates here).
    for at in &env.actuator_temperatures {
        if at.temperature_celsius.is_finite() {
            if at.temperature_celsius < -273.15 {
                violations.push(format!(
                    "'{}': temperature {:.1}°C is below absolute zero",
                    at.joint_name, at.temperature_celsius
                ));
            } else if at.temperature_celsius > 1000.0 {
                violations.push(format!(
                    "'{}': temperature {:.1}°C exceeds 1000°C physical plausibility limit",
                    at.joint_name, at.temperature_celsius
                ));
            }
        }
    }

    // Battery: percentage must be in [0, 100].
    if let Some(batt) = env.battery_percentage {
        if batt.is_finite() && !(0.0..=100.0).contains(&batt) {
            violations.push(format!(
                "battery_percentage {:.1} is outside [0, 100] range",
                batt
            ));
        }
    }

    // Latency: cannot be negative.
    if let Some(lat) = env.communication_latency_ms {
        if lat.is_finite() && lat < 0.0 {
            violations.push(format!("communication_latency_ms {:.1} is negative", lat));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: SR1_CHECK_NAME.to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all environment sensor values within physical plausibility bounds"
                .to_string(),
            derating: None,
        }
    } else {
        CheckResult {
            name: SR1_CHECK_NAME.to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        }
    }
}

/// SR2 — payload-side sensor range validation (v11 5.1).
///
/// Plausibility bounds on the *payload-side* sensors (joint encoders, joint
/// tachometers, end-effector position trackers, force/torque cells). Values
/// outside these envelopes indicate a corrupt driver, a wrap-around in an
/// encoder, or a spoofed payload — none of them can come from real
/// hardware (spec-v2 §3.2 row SR2):
/// - Joint position magnitude > 4π rad (encoder past plausible wrap)
/// - Joint velocity magnitude > 1000 rad/s
/// - End-effector position magnitude > 1000 m
/// - End-effector force magnitude > 100 kN
///
/// NaN/∞ on these fields is left to the per-field downstream checks (P1–P4
/// already reject them); SR2 only flags finite values that breach the
/// plausibility envelope.
pub fn check_sensor_range_payload(command: &Command) -> CheckResult {
    let mut violations: Vec<String> = Vec::new();

    for js in &command.joint_states {
        if js.position.is_finite() && js.position.abs() > SR2_MAX_JOINT_POSITION_RAD {
            violations.push(format!(
                "'{}': joint position {:.4} rad exceeds ±{:.4} rad plausibility limit",
                js.name, js.position, SR2_MAX_JOINT_POSITION_RAD
            ));
        }
        if js.velocity.is_finite() && js.velocity.abs() > SR2_MAX_JOINT_VELOCITY_RAD_S {
            violations.push(format!(
                "'{}': joint velocity {:.4} rad/s exceeds ±{:.1} rad/s plausibility limit",
                js.name, js.velocity, SR2_MAX_JOINT_VELOCITY_RAD_S
            ));
        }
    }

    for ee in &command.end_effector_positions {
        // Use ∞-norm so any single axis at >1000 m triggers; same intent as
        // the spec's "Position > 1000m".
        let max_axis = ee.position.iter().copied().fold(0.0f64, |acc, v| {
            if v.is_finite() {
                acc.max(v.abs())
            } else {
                acc
            }
        });
        if max_axis > SR2_MAX_EE_POSITION_M {
            violations.push(format!(
                "'{}': end-effector position max-axis {:.2} m exceeds {:.0} m plausibility limit",
                ee.name, max_axis, SR2_MAX_EE_POSITION_M
            ));
        }
    }

    for ef in &command.end_effector_forces {
        let mag_sq = ef
            .force
            .iter()
            .filter(|v| v.is_finite())
            .map(|v| v * v)
            .sum::<f64>();
        if mag_sq.is_finite() && mag_sq.sqrt() > SR2_MAX_EE_FORCE_N {
            violations.push(format!(
                "'{}': end-effector force magnitude {:.1} N exceeds {:.0} N plausibility limit",
                ef.name,
                mag_sq.sqrt(),
                SR2_MAX_EE_FORCE_N
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: SR2_CHECK_NAME.to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all payload sensor values within physical plausibility bounds".to_string(),
            derating: None,
        }
    } else {
        CheckResult {
            name: SR2_CHECK_NAME.to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        }
    }
}

/// P25: Emergency stop state.
///
/// Rejects ALL commands when the hardware emergency stop is engaged.
/// This check CANNOT be disabled by any profile configuration.
/// Skipped only when e-stop data is absent (sensor not wired).
pub fn check_emergency_stop(env: &EnvironmentState) -> CheckResult {
    let Some(engaged) = env.e_stop_engaged else {
        return CheckResult {
            name: "emergency_stop".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no e-stop data to check".to_string(),
            derating: None,
        };
    };

    if engaged {
        CheckResult {
            name: "emergency_stop".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "hardware emergency stop is engaged — all commands rejected".to_string(),
            derating: None,
        }
    } else {
        CheckResult {
            name: "emergency_stop".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "emergency stop is not engaged".to_string(),
            derating: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::command::ActuatorTemperature;

    fn empty_env() -> EnvironmentState {
        EnvironmentState {
            imu_pitch_rad: None,
            imu_roll_rad: None,
            actuator_temperatures: vec![],
            battery_percentage: None,
            communication_latency_ms: None,
            e_stop_engaged: None,
        }
    }

    // ── Sensor range: all-empty passes ────────────────────────────────

    #[test]
    fn sensor_range_empty_env_passes() {
        let r = check_sensor_range_env(&empty_env());
        assert!(r.passed, "empty env state must pass range check");
        assert_eq!(r.name, SR1_CHECK_NAME);
    }

    // ── Sensor range: IMU angles ──────────────────────────────────────

    #[test]
    fn sensor_range_valid_imu_passes() {
        let mut env = empty_env();
        env.imu_pitch_rad = Some(0.2);
        env.imu_roll_rad = Some(-0.1);
        let r = check_sensor_range_env(&env);
        assert!(r.passed, "valid IMU angles must pass");
    }

    #[test]
    fn sensor_range_pitch_beyond_pi_rejected() {
        let mut env = empty_env();
        env.imu_pitch_rad = Some(4.0); // > π
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "pitch > π must be rejected");
        assert!(r.details.contains("imu_pitch_rad"));
    }

    #[test]
    fn sensor_range_roll_beyond_neg_pi_rejected() {
        let mut env = empty_env();
        env.imu_roll_rad = Some(-4.0); // < -π
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "roll < -π must be rejected");
        assert!(r.details.contains("imu_roll_rad"));
    }

    #[test]
    fn sensor_range_imu_at_pi_passes() {
        let mut env = empty_env();
        env.imu_pitch_rad = Some(std::f64::consts::PI);
        env.imu_roll_rad = Some(-std::f64::consts::PI);
        let r = check_sensor_range_env(&env);
        assert!(r.passed, "angles at exactly ±π must pass");
    }

    #[test]
    fn sensor_range_nan_imu_skipped() {
        // NaN is handled by the P21 check's own NaN guard, not the range check.
        let mut env = empty_env();
        env.imu_pitch_rad = Some(f64::NAN);
        let r = check_sensor_range_env(&env);
        assert!(
            r.passed,
            "NaN IMU should be skipped by range check (handled by P21)"
        );
    }

    // ── Sensor range: temperature ─────────────────────────────────────

    #[test]
    fn sensor_range_valid_temperature_passes() {
        let mut env = empty_env();
        env.actuator_temperatures = vec![ActuatorTemperature {
            joint_name: "j1".into(),
            temperature_celsius: 42.0,
        }];
        let r = check_sensor_range_env(&env);
        assert!(r.passed);
    }

    #[test]
    fn sensor_range_below_absolute_zero_rejected() {
        let mut env = empty_env();
        env.actuator_temperatures = vec![ActuatorTemperature {
            joint_name: "j1".into(),
            temperature_celsius: -300.0,
        }];
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "-300°C must be rejected (below absolute zero)");
        assert!(r.details.contains("absolute zero"));
    }

    #[test]
    fn sensor_range_above_1000c_rejected() {
        let mut env = empty_env();
        env.actuator_temperatures = vec![ActuatorTemperature {
            joint_name: "j1".into(),
            temperature_celsius: 1500.0,
        }];
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "1500°C must be rejected");
        assert!(r.details.contains("1000"));
    }

    #[test]
    fn sensor_range_negative_273_passes() {
        // Exactly -273.15°C is absolute zero — physically possible (barely).
        let mut env = empty_env();
        env.actuator_temperatures = vec![ActuatorTemperature {
            joint_name: "j1".into(),
            temperature_celsius: -273.15,
        }];
        let r = check_sensor_range_env(&env);
        assert!(r.passed, "-273.15°C (absolute zero) must pass");
    }

    // ── Sensor range: battery ─────────────────────────────────────────

    #[test]
    fn sensor_range_valid_battery_passes() {
        let mut env = empty_env();
        env.battery_percentage = Some(72.0);
        let r = check_sensor_range_env(&env);
        assert!(r.passed);
    }

    #[test]
    fn sensor_range_battery_above_100_rejected() {
        let mut env = empty_env();
        env.battery_percentage = Some(105.0);
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "battery > 100% must be rejected");
        assert!(r.details.contains("battery_percentage"));
    }

    #[test]
    fn sensor_range_battery_negative_rejected() {
        let mut env = empty_env();
        env.battery_percentage = Some(-5.0);
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "negative battery must be rejected");
    }

    #[test]
    fn sensor_range_battery_at_boundaries_passes() {
        for val in [0.0, 100.0] {
            let mut env = empty_env();
            env.battery_percentage = Some(val);
            let r = check_sensor_range_env(&env);
            assert!(r.passed, "battery {val}% must pass");
        }
    }

    // ── Sensor range: latency ─────────────────────────────────────────

    #[test]
    fn sensor_range_valid_latency_passes() {
        let mut env = empty_env();
        env.communication_latency_ms = Some(25.0);
        let r = check_sensor_range_env(&env);
        assert!(r.passed);
    }

    #[test]
    fn sensor_range_negative_latency_rejected() {
        let mut env = empty_env();
        env.communication_latency_ms = Some(-10.0);
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "negative latency must be rejected");
        assert!(r.details.contains("latency"));
    }

    #[test]
    fn sensor_range_zero_latency_passes() {
        let mut env = empty_env();
        env.communication_latency_ms = Some(0.0);
        let r = check_sensor_range_env(&env);
        assert!(r.passed, "zero latency must pass");
    }

    // ── Sensor range: multiple violations ─────────────────────────────

    #[test]
    fn sensor_range_multiple_violations_all_reported() {
        let mut env = empty_env();
        env.imu_pitch_rad = Some(5.0);
        env.battery_percentage = Some(200.0);
        env.communication_latency_ms = Some(-1.0);
        let r = check_sensor_range_env(&env);
        assert!(!r.passed);
        assert!(r.details.contains("imu_pitch_rad"));
        assert!(r.details.contains("battery_percentage"));
        assert!(r.details.contains("latency"));
    }

    // ── SR2 (payload sensor-range) ─────────────────────────────────────────

    use crate::models::command::{
        CommandAuthority, EndEffectorForce, EndEffectorPosition, JointState,
    };
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_payload_command() -> Command {
        Command {
            timestamp: Utc::now(),
            source: "sr2-test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.5,
                velocity: 1.0,
                effort: 10.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![EndEffectorPosition {
                name: "tcp".into(),
                position: [0.5, -0.2, 0.8],
            }],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![EndEffectorForce {
                name: "tcp".into(),
                force: [1.0, 2.0, 3.0],
                torque: [0.0, 0.0, 0.0],
                grasp_force: None,
            }],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        }
    }

    #[test]
    fn sr2_in_range_command_passes() {
        let r = check_sensor_range_payload(&make_payload_command());
        assert!(r.passed, "in-range payload must pass: {}", r.details);
        assert_eq!(r.name, SR2_CHECK_NAME);
    }

    #[test]
    fn sr2_joint_position_beyond_4pi_rejected() {
        let mut cmd = make_payload_command();
        cmd.joint_states[0].position = 4.5 * std::f64::consts::PI;
        let r = check_sensor_range_payload(&cmd);
        assert!(!r.passed, "joint position > 4π must be rejected");
        assert!(r.details.contains("joint position"));
        assert_eq!(r.name, SR2_CHECK_NAME);
    }

    #[test]
    fn sr2_joint_velocity_above_1000_rejected() {
        let mut cmd = make_payload_command();
        cmd.joint_states[0].velocity = 1500.0;
        let r = check_sensor_range_payload(&cmd);
        assert!(!r.passed, "velocity > 1000 rad/s must be rejected");
        assert!(r.details.contains("joint velocity"));
    }

    #[test]
    fn sr2_ee_position_above_1000m_rejected() {
        let mut cmd = make_payload_command();
        cmd.end_effector_positions[0].position = [5000.0, 0.0, 0.0];
        let r = check_sensor_range_payload(&cmd);
        assert!(!r.passed, "EE position > 1000 m must be rejected");
        assert!(r.details.contains("end-effector position"));
    }

    #[test]
    fn sr2_ee_force_above_100kn_rejected() {
        let mut cmd = make_payload_command();
        cmd.end_effector_forces[0].force = [60_000.0, 80_000.0, 0.0]; // |F| = 100 kN exactly
        cmd.end_effector_forces[0].force[0] = 70_000.0; // |F| ≈ 106 kN
        let r = check_sensor_range_payload(&cmd);
        assert!(!r.passed, "EE force > 100 kN must be rejected");
        assert!(r.details.contains("end-effector force"));
    }

    #[test]
    fn sr2_nan_payload_is_left_to_downstream_checks() {
        // NaN/∞ payload values are caught by P1–P4; SR2 must not double-report
        // them so that the verdict's first failed check still names the
        // canonical P-check.
        let mut cmd = make_payload_command();
        cmd.joint_states[0].position = f64::NAN;
        cmd.joint_states[0].velocity = f64::INFINITY;
        let r = check_sensor_range_payload(&cmd);
        assert!(
            r.passed,
            "SR2 must skip NaN/∞ payload (handled by P-checks): {}",
            r.details
        );
    }

    #[test]
    fn sr2_at_4pi_boundary_passes() {
        let mut cmd = make_payload_command();
        cmd.joint_states[0].position = SR2_MAX_JOINT_POSITION_RAD;
        let r = check_sensor_range_payload(&cmd);
        assert!(r.passed, "joint position exactly at 4π must pass");
    }

    #[test]
    fn sr2_and_sr1_have_distinct_names() {
        // The whole point of the v11-5.1 split: coverage tables key off
        // CheckResult.name, so the two checks must never collide.
        assert_ne!(SR1_CHECK_NAME, SR2_CHECK_NAME);
        let env_r = check_sensor_range_env(&empty_env());
        let pay_r = check_sensor_range_payload(&make_payload_command());
        assert_eq!(env_r.name, SR1_CHECK_NAME);
        assert_eq!(pay_r.name, SR2_CHECK_NAME);
    }
}
