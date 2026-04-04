//! Environmental awareness checks P21–P25.
//!
//! These checks validate environmental sensor data against profile-configured
//! thresholds. All sensor fields are optional; checks for absent data are
//! gracefully skipped (fail-open), except P25 (e-stop) which is always active
//! when present.

use crate::models::command::EnvironmentState;
use crate::models::profile::EnvironmentConfig;
use crate::models::verdict::CheckResult;

/// P21: Incline / terrain safety.
///
/// Rejects commands when IMU reports pitch or roll angles exceeding safe limits.
/// Skipped when IMU data is absent.
pub fn check_terrain_incline(env: &EnvironmentState, config: &EnvironmentConfig) -> CheckResult {
    let mut violations: Vec<String> = Vec::new();

    if let Some(pitch) = env.imu_pitch_rad {
        if !pitch.is_finite() {
            violations.push("imu_pitch_rad is NaN or infinite".to_string());
        } else if pitch.abs() > config.max_safe_pitch_rad {
            violations.push(format!(
                "pitch {:.4} rad exceeds max_safe_pitch_rad {:.4} rad",
                pitch.abs(),
                config.max_safe_pitch_rad
            ));
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
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "terrain_incline".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "terrain angles within safe limits".to_string(),
        }
    } else {
        CheckResult {
            name: "terrain_incline".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
    }
}

/// P22: Operating temperature bounds.
///
/// Rejects commands when any actuator reports a temperature exceeding the
/// maximum operating temperature. Skipped when no temperature data is present.
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
        };
    }

    let mut violations: Vec<String> = Vec::new();

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
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "actuator_temperature".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all actuator temperatures within operating limits".to_string(),
        }
    } else {
        CheckResult {
            name: "actuator_temperature".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
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
        };
    };

    if !pct.is_finite() {
        return CheckResult {
            name: "battery_state".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "battery_percentage is NaN or infinite".to_string(),
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
        }
    } else if pct < config.low_battery_pct {
        CheckResult {
            name: "battery_state".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "battery {:.1}% is below low threshold {:.1}% (advisory)",
                pct, config.low_battery_pct
            ),
        }
    } else {
        CheckResult {
            name: "battery_state".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!("battery {:.1}% is within operating range", pct),
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
        };
    };

    if !latency.is_finite() {
        return CheckResult {
            name: "communication_latency".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "communication_latency_ms is NaN or infinite".to_string(),
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
        }
    } else if latency > config.warning_latency_ms {
        CheckResult {
            name: "communication_latency".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "latency {:.1} ms exceeds warning threshold {:.1} ms (advisory)",
                latency, config.warning_latency_ms
            ),
        }
    } else {
        CheckResult {
            name: "communication_latency".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!("latency {:.1} ms is within acceptable bounds", latency),
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
        };
    };

    if engaged {
        CheckResult {
            name: "emergency_stop".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "hardware emergency stop is engaged — all commands rejected".to_string(),
        }
    } else {
        CheckResult {
            name: "emergency_stop".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "emergency stop is not engaged".to_string(),
        }
    }
}
