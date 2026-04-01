// P20: Heading rate limit check

use crate::models::command::LocomotionState;
use crate::models::profile::LocomotionConfig;
use crate::models::verdict::CheckResult;

/// Check that the absolute heading (yaw) rate does not exceed `max_heading_rate`.
///
/// A non-finite heading rate is treated as a violation to prevent NaN/Inf from
/// vacuously passing the comparison.
pub fn check_heading_rate(loco: &LocomotionState, config: &LocomotionConfig) -> CheckResult {
    if !loco.heading_rate.is_finite() {
        return CheckResult {
            name: "heading_rate".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "heading_rate is NaN or infinite".to_string(),
        };
    }

    let abs_rate = loco.heading_rate.abs();

    if abs_rate <= config.max_heading_rate {
        CheckResult {
            name: "heading_rate".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "|heading_rate| {:.6} rad/s is within max_heading_rate {:.6} rad/s",
                abs_rate, config.max_heading_rate
            ),
        }
    } else {
        CheckResult {
            name: "heading_rate".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "|heading_rate| {:.6} rad/s exceeds max_heading_rate {:.6} rad/s",
                abs_rate, config.max_heading_rate
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::command::LocomotionState;
    use crate::models::profile::LocomotionConfig;

    fn config(max_rate: f64) -> LocomotionConfig {
        LocomotionConfig {
            max_locomotion_velocity: 1.5,
            max_step_length: 0.5,
            min_foot_clearance: 0.02,
            max_ground_reaction_force: 500.0,
            friction_coefficient: 0.7,
            max_heading_rate: max_rate,
        }
    }

    fn loco(heading_rate: f64) -> LocomotionState {
        LocomotionState {
            base_velocity: [0.0, 0.0, 0.0],
            heading_rate,
            feet: vec![],
            step_length: 0.0,
        }
    }

    #[test]
    fn p20_heading_rate_within_limit_passes() {
        let result = check_heading_rate(&loco(0.5), &config(1.0));
        assert!(result.passed);
        assert_eq!(result.name, "heading_rate");
        assert_eq!(result.category, "physics");
    }

    #[test]
    fn p20_heading_rate_at_exact_positive_limit_passes() {
        let result = check_heading_rate(&loco(1.0), &config(1.0));
        assert!(
            result.passed,
            "rate at exact limit should pass: {}",
            result.details
        );
    }

    #[test]
    fn p20_heading_rate_at_exact_negative_limit_passes() {
        let result = check_heading_rate(&loco(-1.0), &config(1.0));
        assert!(
            result.passed,
            "negative rate at exact limit should pass: {}",
            result.details
        );
    }

    #[test]
    fn p20_heading_rate_positive_exceeds_limit_fails() {
        let result = check_heading_rate(&loco(1.5), &config(1.0));
        assert!(!result.passed);
        assert!(result.details.contains("exceeds max_heading_rate"));
    }

    #[test]
    fn p20_heading_rate_negative_exceeds_limit_fails() {
        let result = check_heading_rate(&loco(-1.5), &config(1.0));
        assert!(!result.passed);
        assert!(result.details.contains("exceeds max_heading_rate"));
    }

    #[test]
    fn p20_zero_heading_rate_passes() {
        let result = check_heading_rate(&loco(0.0), &config(1.0));
        assert!(result.passed);
    }

    #[test]
    fn p20_nan_heading_rate_fails() {
        let result = check_heading_rate(&loco(f64::NAN), &config(1.0));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }

    #[test]
    fn p20_infinite_heading_rate_fails() {
        let result = check_heading_rate(&loco(f64::INFINITY), &config(1.0));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }

    #[test]
    fn p20_negative_infinite_heading_rate_fails() {
        let result = check_heading_rate(&loco(f64::NEG_INFINITY), &config(1.0));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }
}
