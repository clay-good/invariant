// P16: Foot clearance minimum check

use crate::models::command::LocomotionState;
use crate::models::profile::LocomotionConfig;
use crate::models::verdict::CheckResult;

/// Check that every swing foot (not in contact) has a z-position at or above
/// `min_foot_clearance`.
///
/// Feet that are in contact with the ground are not required to meet the
/// clearance threshold — they are expected to be at or near ground level.
/// Non-finite z-values in swing feet are treated as violations.
pub fn check_foot_clearance(loco: &LocomotionState, config: &LocomotionConfig) -> CheckResult {
    let mut violations: Vec<String> = Vec::new();

    for foot in &loco.feet {
        // Only swing feet (not in contact) must clear the ground.
        if foot.contact {
            continue;
        }

        let z = foot.position[2];

        if !z.is_finite() {
            violations.push(format!(
                "'{}': foot z-position is NaN or infinite",
                foot.name
            ));
        } else if z < config.min_foot_clearance {
            violations.push(format!(
                "'{}': foot z-position {:.6} m is below min_foot_clearance {:.6} m",
                foot.name, z, config.min_foot_clearance
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "foot_clearance".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all swing feet meet minimum clearance".to_string(),
        }
    } else {
        CheckResult {
            name: "foot_clearance".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::command::{FootState, LocomotionState};
    use crate::models::profile::LocomotionConfig;

    fn config(min_clearance: f64) -> LocomotionConfig {
        LocomotionConfig {
            max_locomotion_velocity: 1.5,
            max_step_length: 0.5,
            min_foot_clearance: min_clearance,
            max_ground_reaction_force: 500.0,
            friction_coefficient: 0.7,
            max_heading_rate: 1.0,
        }
    }

    fn swing_foot(name: &str, z: f64) -> FootState {
        FootState {
            name: name.to_string(),
            position: [0.0, 0.0, z],
            contact: false,
            ground_reaction_force: None,
        }
    }

    fn contact_foot(name: &str, z: f64) -> FootState {
        FootState {
            name: name.to_string(),
            position: [0.0, 0.0, z],
            contact: true,
            ground_reaction_force: None,
        }
    }

    fn loco(feet: Vec<FootState>) -> LocomotionState {
        LocomotionState {
            base_velocity: [0.0, 0.0, 0.0],
            heading_rate: 0.0,
            feet,
            step_length: 0.0,
        }
    }

    #[test]
    fn p16_swing_foot_above_clearance_passes() {
        let state = loco(vec![swing_foot("fl", 0.05)]);
        let result = check_foot_clearance(&state, &config(0.02));
        assert!(result.passed);
        assert_eq!(result.name, "foot_clearance");
        assert_eq!(result.category, "physics");
    }

    #[test]
    fn p16_swing_foot_at_exact_clearance_passes() {
        let state = loco(vec![swing_foot("fl", 0.02)]);
        let result = check_foot_clearance(&state, &config(0.02));
        assert!(
            result.passed,
            "foot at exact clearance should pass: {}",
            result.details
        );
    }

    #[test]
    fn p16_swing_foot_below_clearance_fails() {
        let state = loco(vec![swing_foot("fl", 0.01)]);
        let result = check_foot_clearance(&state, &config(0.02));
        assert!(!result.passed);
        assert!(result.details.contains("fl"));
        assert!(result.details.contains("below min_foot_clearance"));
    }

    #[test]
    fn p16_contact_foot_below_clearance_passes() {
        // Contact feet can be at ground level — no clearance requirement.
        let state = loco(vec![contact_foot("fl", 0.0)]);
        let result = check_foot_clearance(&state, &config(0.02));
        assert!(
            result.passed,
            "contact foot at ground should pass: {}",
            result.details
        );
    }

    #[test]
    fn p16_mixed_feet_one_violation_fails() {
        let state = loco(vec![
            swing_foot("fl", 0.05),  // OK
            contact_foot("fr", 0.0), // contact — skip
            swing_foot("rl", 0.005), // violation
            swing_foot("rr", 0.03),  // OK
        ]);
        let result = check_foot_clearance(&state, &config(0.02));
        assert!(!result.passed);
        assert!(result.details.contains("rl"));
        assert!(!result.details.contains("fl"));
        assert!(!result.details.contains("fr"));
    }

    #[test]
    fn p16_no_feet_passes() {
        let state = loco(vec![]);
        let result = check_foot_clearance(&state, &config(0.02));
        assert!(result.passed);
    }

    #[test]
    fn p16_nan_z_on_swing_foot_fails() {
        let state = loco(vec![swing_foot("fl", f64::NAN)]);
        let result = check_foot_clearance(&state, &config(0.02));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }
}
