// P15: Locomotion velocity limit

use crate::models::command::LocomotionState;
use crate::models::profile::LocomotionConfig;
use crate::models::verdict::CheckResult;

/// Check that the magnitude of the robot base linear velocity does not exceed
/// `max_locomotion_velocity`.
///
/// The check computes the Euclidean norm of `base_velocity` and compares it
/// against the configured limit. Non-finite velocity components are treated as
/// violations to prevent NaN/Inf values from vacuously passing the comparison.
pub fn check_locomotion_velocity(loco: &LocomotionState, config: &LocomotionConfig) -> CheckResult {
    let [vx, vy, vz] = loco.base_velocity;

    if !vx.is_finite() || !vy.is_finite() || !vz.is_finite() {
        return CheckResult {
            name: "locomotion_velocity".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "base_velocity contains NaN or infinite value".to_string(),
            derating: None,
        };
    }

    let speed = (vx * vx + vy * vy + vz * vz).sqrt();

    if speed <= config.max_locomotion_velocity {
        CheckResult {
            name: "locomotion_velocity".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "base speed {:.6} m/s is within limit {:.6} m/s",
                speed, config.max_locomotion_velocity
            ),
            derating: None,
        }
    } else {
        CheckResult {
            name: "locomotion_velocity".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "base speed {:.6} m/s exceeds max_locomotion_velocity {:.6} m/s",
                speed, config.max_locomotion_velocity
            ),
            derating: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::command::LocomotionState;
    use crate::models::profile::LocomotionConfig;

    fn config(max_vel: f64) -> LocomotionConfig {
        LocomotionConfig {
            max_locomotion_velocity: max_vel,
            max_step_length: 0.5,
            min_foot_clearance: 0.02,
            max_step_height: 0.5,
            max_ground_reaction_force: 500.0,
            friction_coefficient: 0.7,
            max_heading_rate: 1.0,
        }
    }

    fn loco(vx: f64, vy: f64, vz: f64) -> LocomotionState {
        LocomotionState {
            base_velocity: [vx, vy, vz],
            heading_rate: 0.0,
            feet: vec![],
            step_length: 0.0,
        }
    }

    #[test]
    fn p15_velocity_within_limit_passes() {
        let result = check_locomotion_velocity(&loco(0.5, 0.0, 0.0), &config(1.0));
        assert!(result.passed);
        assert_eq!(result.name, "locomotion_velocity");
        assert_eq!(result.category, "physics");
    }

    #[test]
    fn p15_velocity_at_exact_limit_passes() {
        // norm([1.0, 0.0, 0.0]) == 1.0 == max
        let result = check_locomotion_velocity(&loco(1.0, 0.0, 0.0), &config(1.0));
        assert!(
            result.passed,
            "speed at exact limit should pass: {}",
            result.details
        );
    }

    #[test]
    fn p15_velocity_exceeds_limit_fails() {
        let result = check_locomotion_velocity(&loco(0.8, 0.8, 0.0), &config(1.0));
        // norm([0.8, 0.8, 0.0]) ≈ 1.131
        assert!(!result.passed);
        assert!(result.details.contains("exceeds max_locomotion_velocity"));
    }

    #[test]
    fn p15_diagonal_velocity_within_limit_passes() {
        // norm([0.6, 0.6, 0.6]) ≈ 1.039; limit 1.1
        let result = check_locomotion_velocity(&loco(0.6, 0.6, 0.6), &config(1.1));
        assert!(result.passed);
    }

    #[test]
    fn p15_nan_velocity_fails() {
        let result = check_locomotion_velocity(&loco(f64::NAN, 0.0, 0.0), &config(1.0));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }

    #[test]
    fn p15_infinite_velocity_fails() {
        let result = check_locomotion_velocity(&loco(f64::INFINITY, 0.0, 0.0), &config(1.0));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }

    #[test]
    fn p15_zero_velocity_passes() {
        let result = check_locomotion_velocity(&loco(0.0, 0.0, 0.0), &config(1.0));
        assert!(result.passed);
    }
}
