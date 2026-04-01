// P18: Friction cone constraint check

use crate::models::command::LocomotionState;
use crate::models::profile::LocomotionConfig;
use crate::models::verdict::CheckResult;

/// Check that the ground reaction force at each contact foot satisfies the
/// Coulomb friction cone constraint: `sqrt(fx^2 + fy^2) / fz <= mu`.
///
/// Only feet that are in contact AND have GRF data are checked. Feet where
/// `fz <= 0` are considered to be in the process of lifting off — the normal
/// force is absent so the friction constraint does not apply in the conventional
/// sense; these are skipped rather than flagged as violations.
///
/// Non-finite GRF components on contact feet are treated as violations.
pub fn check_friction_cone(loco: &LocomotionState, config: &LocomotionConfig) -> CheckResult {
    let mut violations: Vec<String> = Vec::new();
    let mu = config.friction_coefficient;

    for foot in &loco.feet {
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

        // If normal force is non-positive the foot is lifting off — skip.
        if fz <= 0.0 {
            continue;
        }

        let tangential = (fx * fx + fy * fy).sqrt();
        let ratio = tangential / fz;

        if ratio > mu {
            violations.push(format!(
                "'{}': friction ratio {:.6} (tangential {:.6} N / normal {:.6} N) exceeds friction_coefficient {:.6}",
                foot.name, ratio, tangential, fz, mu
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "friction_cone".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all feet satisfy friction cone constraint".to_string(),
        }
    } else {
        CheckResult {
            name: "friction_cone".to_string(),
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

    fn config(mu: f64) -> LocomotionConfig {
        LocomotionConfig {
            max_locomotion_velocity: 1.5,
            max_step_length: 0.5,
            min_foot_clearance: 0.02,
            max_ground_reaction_force: 500.0,
            friction_coefficient: mu,
            max_heading_rate: 1.0,
        }
    }

    fn contact_foot(name: &str, fx: f64, fy: f64, fz: f64) -> FootState {
        FootState {
            name: name.to_string(),
            position: [0.0, 0.0, 0.0],
            contact: true,
            ground_reaction_force: Some([fx, fy, fz]),
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
    fn p18_within_friction_cone_passes() {
        // tangential = 0, ratio = 0 <= 0.7
        let state = loco(vec![contact_foot("fl", 0.0, 0.0, 300.0)]);
        let result = check_friction_cone(&state, &config(0.7));
        assert!(result.passed);
        assert_eq!(result.name, "friction_cone");
        assert_eq!(result.category, "physics");
    }

    #[test]
    fn p18_at_exact_friction_limit_passes() {
        // tangential = 70, normal = 100, ratio = 0.7 == mu
        let state = loco(vec![contact_foot("fl", 70.0, 0.0, 100.0)]);
        let result = check_friction_cone(&state, &config(0.7));
        assert!(
            result.passed,
            "ratio at exact limit should pass: {}",
            result.details
        );
    }

    #[test]
    fn p18_exceeds_friction_cone_fails() {
        // tangential = 100, normal = 100, ratio = 1.0 > 0.7
        let state = loco(vec![contact_foot("fl", 100.0, 0.0, 100.0)]);
        let result = check_friction_cone(&state, &config(0.7));
        assert!(!result.passed);
        assert!(result.details.contains("fl"));
        assert!(result.details.contains("friction_coefficient"));
    }

    #[test]
    fn p18_liftoff_fz_zero_skipped() {
        // fz <= 0 means foot is lifting off — skip rather than flag.
        let state = loco(vec![contact_foot("fl", 100.0, 100.0, 0.0)]);
        let result = check_friction_cone(&state, &config(0.7));
        assert!(
            result.passed,
            "liftoff foot (fz=0) should be skipped: {}",
            result.details
        );
    }

    #[test]
    fn p18_negative_fz_skipped() {
        let state = loco(vec![contact_foot("fl", 0.0, 0.0, -10.0)]);
        let result = check_friction_cone(&state, &config(0.7));
        assert!(result.passed, "foot with negative fz should be skipped");
    }

    #[test]
    fn p18_swing_foot_skipped() {
        let foot = FootState {
            name: "fl".to_string(),
            position: [0.0, 0.0, 0.1],
            contact: false,
            ground_reaction_force: Some([100.0, 100.0, 50.0]),
        };
        let state = loco(vec![foot]);
        let result = check_friction_cone(&state, &config(0.7));
        assert!(result.passed, "swing foot should be skipped");
    }

    #[test]
    fn p18_nan_grf_fails() {
        let state = loco(vec![contact_foot("fl", f64::NAN, 0.0, 100.0)]);
        let result = check_friction_cone(&state, &config(0.7));
        assert!(!result.passed);
        assert!(result.details.contains("NaN or infinite"));
    }

    #[test]
    fn p18_diagonal_tangential_force_correctly_checked() {
        // fx=fy=50, fz=100 => tangential=sqrt(5000)≈70.71, ratio≈0.707 > 0.7
        let state = loco(vec![contact_foot("fl", 50.0, 50.0, 100.0)]);
        let result = check_friction_cone(&state, &config(0.7));
        assert!(
            !result.passed,
            "diagonal tangential force exceeding mu should fail"
        );
    }
}
