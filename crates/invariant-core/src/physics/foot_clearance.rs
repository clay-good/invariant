// P16: Foot clearance validation (min and max bounds)

use crate::models::command::LocomotionState;
use crate::models::profile::LocomotionConfig;
use crate::models::verdict::CheckResult;

/// Check that every swing foot (not in contact) has a z-position within
/// `[min_foot_clearance, max_step_height]`.
///
/// The lower bound prevents dragging/tripping (foot too low).
/// The upper bound prevents stomping (foot raised excessively high, which
/// slams down with dangerous force).
///
/// Feet that are in contact with the ground are not required to meet either
/// threshold — they are expected to be at or near ground level.
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
        } else if z > config.max_step_height {
            violations.push(format!(
                "'{}': foot z-position {:.6} m exceeds max_step_height {:.6} m",
                foot.name, z, config.max_step_height
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "foot_clearance".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all swing feet within clearance bounds".to_string(),
            derating: None,
        }
    } else {
        CheckResult {
            name: "foot_clearance".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
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
            max_step_height: 0.3,
            max_ground_reaction_force: 500.0,
            friction_coefficient: 0.7,
            max_heading_rate: 1.0,
        }
    }

    fn config_with_max_height(min_clearance: f64, max_height: f64) -> LocomotionConfig {
        LocomotionConfig {
            max_locomotion_velocity: 1.5,
            max_step_length: 0.5,
            min_foot_clearance: min_clearance,
            max_step_height: max_height,
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

    // ── P16 max_step_height upper-bound tests ───────────────

    #[test]
    fn p16_swing_foot_below_max_step_height_passes() {
        let state = loco(vec![swing_foot("fl", 0.20)]);
        let result = check_foot_clearance(&state, &config_with_max_height(0.02, 0.30));
        assert!(
            result.passed,
            "foot below max should pass: {}",
            result.details
        );
    }

    #[test]
    fn p16_swing_foot_at_exact_max_step_height_passes() {
        let state = loco(vec![swing_foot("fl", 0.30)]);
        let result = check_foot_clearance(&state, &config_with_max_height(0.02, 0.30));
        assert!(
            result.passed,
            "foot at exact max should pass: {}",
            result.details
        );
    }

    #[test]
    fn p16_swing_foot_above_max_step_height_fails() {
        let state = loco(vec![swing_foot("fl", 0.35)]);
        let result = check_foot_clearance(&state, &config_with_max_height(0.02, 0.30));
        assert!(!result.passed);
        assert!(result.details.contains("fl"));
        assert!(result.details.contains("exceeds max_step_height"));
    }

    #[test]
    fn p16_contact_foot_above_max_step_height_passes() {
        // Contact feet are exempt from both bounds.
        let state = loco(vec![contact_foot("fl", 0.50)]);
        let result = check_foot_clearance(&state, &config_with_max_height(0.02, 0.30));
        assert!(
            result.passed,
            "contact foot should be exempt: {}",
            result.details
        );
    }

    #[test]
    fn p16_mixed_feet_one_stomp_violation_fails() {
        let state = loco(vec![
            swing_foot("fl", 0.05),  // OK (within bounds)
            swing_foot("fr", 0.50),  // violation (exceeds max 0.30)
            contact_foot("rl", 0.0), // contact — skip
            swing_foot("rr", 0.10),  // OK
        ]);
        let result = check_foot_clearance(&state, &config_with_max_height(0.02, 0.30));
        assert!(!result.passed);
        assert!(result.details.contains("fr"));
        assert!(result.details.contains("exceeds max_step_height"));
        assert!(!result.details.contains("fl"));
        assert!(!result.details.contains("rr"));
    }

    #[test]
    fn p16_both_bounds_violated_reports_both() {
        let state = loco(vec![
            swing_foot("fl", 0.001), // below min (0.02)
            swing_foot("fr", 0.50),  // above max (0.30)
        ]);
        let result = check_foot_clearance(&state, &config_with_max_height(0.02, 0.30));
        assert!(!result.passed);
        assert!(result.details.contains("fl"));
        assert!(result.details.contains("below min_foot_clearance"));
        assert!(result.details.contains("fr"));
        assert!(result.details.contains("exceeds max_step_height"));
    }

    #[test]
    fn p16_infinity_z_on_swing_foot_fails() {
        let state = loco(vec![swing_foot("fl", f64::INFINITY)]);
        let result = check_foot_clearance(&state, &config_with_max_height(0.02, 0.30));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }
}
