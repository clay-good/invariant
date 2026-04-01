// P19: Step length limit check

use crate::models::command::LocomotionState;
use crate::models::profile::LocomotionConfig;
use crate::models::verdict::CheckResult;

/// Check that the commanded step length does not exceed `max_step_length`.
///
/// A non-finite step length is treated as a violation to prevent NaN/Inf from
/// vacuously passing the comparison.
pub fn check_step_length(loco: &LocomotionState, config: &LocomotionConfig) -> CheckResult {
    if !loco.step_length.is_finite() {
        return CheckResult {
            name: "step_length".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "step_length is NaN or infinite".to_string(),
        };
    }

    if loco.step_length <= config.max_step_length {
        CheckResult {
            name: "step_length".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "step_length {:.6} m is within max_step_length {:.6} m",
                loco.step_length, config.max_step_length
            ),
        }
    } else {
        CheckResult {
            name: "step_length".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "step_length {:.6} m exceeds max_step_length {:.6} m",
                loco.step_length, config.max_step_length
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::command::LocomotionState;
    use crate::models::profile::LocomotionConfig;

    fn config(max_step: f64) -> LocomotionConfig {
        LocomotionConfig {
            max_locomotion_velocity: 1.5,
            max_step_length: max_step,
            min_foot_clearance: 0.02,
            max_ground_reaction_force: 500.0,
            friction_coefficient: 0.7,
            max_heading_rate: 1.0,
        }
    }

    fn loco(step_length: f64) -> LocomotionState {
        LocomotionState {
            base_velocity: [0.0, 0.0, 0.0],
            heading_rate: 0.0,
            feet: vec![],
            step_length,
        }
    }

    #[test]
    fn p19_step_length_within_limit_passes() {
        let result = check_step_length(&loco(0.3), &config(0.5));
        assert!(result.passed);
        assert_eq!(result.name, "step_length");
        assert_eq!(result.category, "physics");
    }

    #[test]
    fn p19_step_length_at_exact_limit_passes() {
        let result = check_step_length(&loco(0.5), &config(0.5));
        assert!(
            result.passed,
            "step at exact limit should pass: {}",
            result.details
        );
    }

    #[test]
    fn p19_step_length_exceeds_limit_fails() {
        let result = check_step_length(&loco(0.6), &config(0.5));
        assert!(!result.passed);
        assert!(result.details.contains("exceeds max_step_length"));
    }

    #[test]
    fn p19_zero_step_length_passes() {
        let result = check_step_length(&loco(0.0), &config(0.5));
        assert!(result.passed);
    }

    #[test]
    fn p19_nan_step_length_fails() {
        let result = check_step_length(&loco(f64::NAN), &config(0.5));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }

    #[test]
    fn p19_infinite_step_length_fails() {
        let result = check_step_length(&loco(f64::INFINITY), &config(0.5));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }

    #[test]
    fn p19_negative_step_length_passes() {
        // Negative step length is unusual but not physically forbidden as a
        // magnitude check; the spec only requires <= max_step_length.
        let result = check_step_length(&loco(-0.1), &config(0.5));
        assert!(result.passed);
    }
}
