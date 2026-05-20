// P17: Ground reaction force limit check

use crate::models::command::LocomotionState;
use crate::models::profile::LocomotionConfig;
use crate::models::verdict::CheckResult;

/// Check that the magnitude of the ground reaction force (GRF) at each
/// contact foot does not exceed `max_ground_reaction_force`.
///
/// Only feet that are both in contact AND have GRF data are checked. Feet
/// without GRF data or feet not in contact are skipped. Non-finite GRF
/// components are treated as violations.
pub fn check_ground_reaction(loco: &LocomotionState, config: &LocomotionConfig) -> CheckResult {
    let mut violations: Vec<String> = Vec::new();

    for foot in &loco.feet {
        // Only check feet that are in contact and have GRF data.
        if !foot.contact {
            continue;
        }
        let grf = match foot.ground_reaction_force {
            Some(g) => g,
            None => continue,
        };

        let [fx, fy, fz] = grf;
        if !fx.is_finite() || !fy.is_finite() || !fz.is_finite() {
            violations.push(format!(
                "'{}': ground reaction force contains NaN or infinite value",
                foot.name
            ));
            continue;
        }

        let magnitude = (fx * fx + fy * fy + fz * fz).sqrt();
        if magnitude > config.max_ground_reaction_force {
            violations.push(format!(
                "'{}': GRF magnitude {:.6} N exceeds max_ground_reaction_force {:.6} N",
                foot.name, magnitude, config.max_ground_reaction_force
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "ground_reaction_force".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all feet within ground reaction force limit".to_string(),
            derating: None,
        }
    } else {
        CheckResult {
            name: "ground_reaction_force".to_string(),
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

    fn config(max_grf: f64) -> LocomotionConfig {
        LocomotionConfig {
            max_locomotion_velocity: 1.5,
            max_step_length: 0.5,
            min_foot_clearance: 0.02,
            max_step_height: 0.5,
            max_ground_reaction_force: max_grf,
            friction_coefficient: 0.7,
            max_heading_rate: 1.0,
        }
    }

    fn contact_foot_with_grf(name: &str, fx: f64, fy: f64, fz: f64) -> FootState {
        FootState {
            name: name.to_string(),
            position: [0.0, 0.0, 0.0],
            contact: true,
            ground_reaction_force: Some([fx, fy, fz]),
        }
    }

    fn swing_foot_no_grf(name: &str) -> FootState {
        FootState {
            name: name.to_string(),
            position: [0.0, 0.0, 0.1],
            contact: false,
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
    fn p17_grf_within_limit_passes() {
        let state = loco(vec![contact_foot_with_grf("fl", 0.0, 0.0, 300.0)]);
        let result = check_ground_reaction(&state, &config(500.0));
        assert!(result.passed);
        assert_eq!(result.name, "ground_reaction_force");
        assert_eq!(result.category, "physics");
    }

    #[test]
    fn p17_grf_at_exact_limit_passes() {
        // norm([0, 0, 500]) == 500 == max
        let state = loco(vec![contact_foot_with_grf("fl", 0.0, 0.0, 500.0)]);
        let result = check_ground_reaction(&state, &config(500.0));
        assert!(
            result.passed,
            "GRF at exact limit should pass: {}",
            result.details
        );
    }

    #[test]
    fn p17_grf_exceeds_limit_fails() {
        let state = loco(vec![contact_foot_with_grf("fl", 0.0, 0.0, 600.0)]);
        let result = check_ground_reaction(&state, &config(500.0));
        assert!(!result.passed);
        assert!(result.details.contains("fl"));
        assert!(result.details.contains("exceeds max_ground_reaction_force"));
    }

    #[test]
    fn p17_swing_foot_no_grf_skipped_passes() {
        // Swing foot without GRF data should not be checked.
        let state = loco(vec![swing_foot_no_grf("fl")]);
        let result = check_ground_reaction(&state, &config(500.0));
        assert!(result.passed);
    }

    #[test]
    fn p17_contact_foot_without_grf_data_skipped() {
        // Contact foot without GRF data — no sensing available, skip gracefully.
        let foot = FootState {
            name: "fl".to_string(),
            position: [0.0, 0.0, 0.0],
            contact: true,
            ground_reaction_force: None,
        };
        let state = loco(vec![foot]);
        let result = check_ground_reaction(&state, &config(500.0));
        assert!(result.passed);
    }

    #[test]
    fn p17_nan_grf_fails() {
        let state = loco(vec![contact_foot_with_grf("fl", f64::NAN, 0.0, 0.0)]);
        let result = check_ground_reaction(&state, &config(500.0));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }

    #[test]
    fn p17_multiple_feet_one_violation_fails() {
        let state = loco(vec![
            contact_foot_with_grf("fl", 0.0, 0.0, 300.0), // OK
            contact_foot_with_grf("fr", 0.0, 0.0, 600.0), // violation
            swing_foot_no_grf("rl"),                      // skipped
        ]);
        let result = check_ground_reaction(&state, &config(500.0));
        assert!(!result.passed);
        assert!(result.details.contains("fr"));
        assert!(!result.details.contains("fl"));
    }
}
