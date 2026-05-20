// P12: Grasp force limits check

use std::collections::HashMap;

use crate::models::command::EndEffectorForce;
use crate::models::profile::EndEffectorConfig;
use crate::models::verdict::CheckResult;

/// Check that the grasp (closing) force at each end-effector satisfies
/// `min_grasp_force_n <= grasp_force <= max_grasp_force_n` (P12).
///
/// This check only fires when `grasp_force` is `Some(...)` in the command.
/// End-effectors without grasp force sensing are skipped. Entries without a
/// matching profile config are also skipped.
///
/// A non-finite grasp force is treated as a violation.
pub fn check_grasp_force_limits(
    forces: &[EndEffectorForce],
    configs: &[EndEffectorConfig],
) -> CheckResult {
    if configs.is_empty() || forces.is_empty() {
        return CheckResult {
            name: "grasp_force_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no end-effector force data or profile configs to check".to_string(),
            derating: None,
        };
    }

    let config_map: HashMap<&str, &EndEffectorConfig> =
        configs.iter().map(|c| (c.name.as_str(), c)).collect();

    let mut violations: Vec<String> = Vec::new();
    let mut any_checked = false;

    for entry in forces {
        let Some(grasp) = entry.grasp_force else {
            // No grasp force reading for this end-effector; skip.
            continue;
        };

        let Some(cfg) = config_map.get(entry.name.as_str()) else {
            // No profile config for this end-effector; skip without violation.
            continue;
        };

        any_checked = true;

        if !grasp.is_finite() {
            violations.push(format!("'{}': grasp_force is NaN or infinite", entry.name));
            continue;
        }

        if grasp < cfg.min_grasp_force_n {
            violations.push(format!(
                "'{}': grasp_force {:.6} N is below min_grasp_force_n {:.6} N",
                entry.name, grasp, cfg.min_grasp_force_n
            ));
        } else if grasp > cfg.max_grasp_force_n {
            violations.push(format!(
                "'{}': grasp_force {:.6} N exceeds max_grasp_force_n {:.6} N",
                entry.name, grasp, cfg.max_grasp_force_n
            ));
        }
    }

    let details = if violations.is_empty() {
        if any_checked {
            "all grasp forces within limits".to_string()
        } else {
            "no grasp force data present; check skipped".to_string()
        }
    } else {
        violations.join("; ")
    };

    CheckResult {
        name: "grasp_force_limits".to_string(),
        category: "physics".to_string(),
        passed: violations.is_empty(),
        details,
        derating: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, min_grasp: f64, max_grasp: f64) -> EndEffectorConfig {
        EndEffectorConfig {
            name: name.into(),
            max_force_n: 200.0,
            max_grasp_force_n: max_grasp,
            min_grasp_force_n: min_grasp,
            max_force_rate_n_per_s: 500.0,
            max_payload_kg: 5.0,
        }
    }

    fn force_with_grasp(name: &str, grasp: f64) -> EndEffectorForce {
        EndEffectorForce {
            name: name.into(),
            force: [0.0, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: Some(grasp),
        }
    }

    fn force_no_grasp(name: &str) -> EndEffectorForce {
        EndEffectorForce {
            name: name.into(),
            force: [0.0, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }
    }

    // ── Pass cases ───────────────────────────────────────────────────────────

    #[test]
    fn p12_no_configs_passes_trivially() {
        let forces = vec![force_with_grasp("gripper", 50.0)];
        let r = check_grasp_force_limits(&forces, &[]);
        assert!(r.passed);
        assert_eq!(r.name, "grasp_force_limits");
        assert_eq!(r.category, "physics");
    }

    #[test]
    fn p12_no_forces_passes_trivially() {
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let r = check_grasp_force_limits(&[], &configs);
        assert!(r.passed);
    }

    #[test]
    fn p12_grasp_within_range_passes() {
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let forces = vec![force_with_grasp("gripper", 50.0)];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(r.passed);
        assert!(r.details.contains("within limits"));
    }

    #[test]
    fn p12_grasp_at_minimum_boundary_passes() {
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let forces = vec![force_with_grasp("gripper", 5.0)];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(r.passed);
    }

    #[test]
    fn p12_grasp_at_maximum_boundary_passes() {
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let forces = vec![force_with_grasp("gripper", 100.0)];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(r.passed);
    }

    #[test]
    fn p12_no_grasp_force_field_skipped() {
        // grasp_force is None — the check must be skipped (passes).
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let forces = vec![force_no_grasp("gripper")];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(r.passed);
        assert!(r.details.contains("skipped"));
    }

    #[test]
    fn p12_unmatched_ee_is_skipped() {
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let forces = vec![force_with_grasp("unknown_ee", 9999.0)];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(r.passed);
    }

    // ── Fail cases ───────────────────────────────────────────────────────────

    #[test]
    fn p12_grasp_below_minimum_fails() {
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let forces = vec![force_with_grasp("gripper", 2.0)];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(!r.passed);
        assert!(r.details.contains("below min_grasp_force_n"));
        assert!(r.details.contains("gripper"));
    }

    #[test]
    fn p12_grasp_above_maximum_fails() {
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let forces = vec![force_with_grasp("gripper", 150.0)];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(!r.passed);
        assert!(r.details.contains("exceeds max_grasp_force_n"));
        assert!(r.details.contains("gripper"));
    }

    #[test]
    fn p12_nan_grasp_force_fails() {
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let forces = vec![force_with_grasp("gripper", f64::NAN)];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p12_infinite_grasp_force_fails() {
        let configs = vec![cfg("gripper", 5.0, 100.0)];
        let forces = vec![force_with_grasp("gripper", f64::INFINITY)];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p12_multiple_ees_both_violations() {
        let configs = vec![cfg("left", 5.0, 100.0), cfg("right", 5.0, 100.0)];
        let forces = vec![
            force_with_grasp("left", 1.0),    // below min
            force_with_grasp("right", 200.0), // above max
        ];
        let r = check_grasp_force_limits(&forces, &configs);
        assert!(!r.passed);
        assert!(r.details.contains("left"));
        assert!(r.details.contains("right"));
    }
}
