// P14: Payload weight check

use std::collections::HashMap;

use crate::models::command::EndEffectorForce;
use crate::models::profile::EndEffectorConfig;
use crate::models::verdict::CheckResult;

/// Check that the estimated payload mass does not exceed `max_payload_kg` for
/// the end-effector that is currently grasping it (P14).
///
/// The check requires both:
/// - `estimated_payload_kg` to be `Some(...)` in the command, and
/// - at least one `EndEffectorForce` entry with a matching profile config.
///
/// When multiple end-effectors are present, the payload limit of the *first*
/// matching end-effector config is used as the binding constraint. In practice,
/// at most one end-effector at a time carries a grasped payload.
///
/// If `estimated_payload_kg` is absent, the check passes trivially — the robot
/// may not be performing a manipulation task, or payload sensing may not be
/// available.
pub fn check_payload_limits(
    forces: &[EndEffectorForce],
    estimated_payload_kg: Option<f64>,
    configs: &[EndEffectorConfig],
) -> CheckResult {
    let Some(payload_kg) = estimated_payload_kg else {
        return CheckResult {
            name: "payload_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no payload estimate present; check skipped".to_string(),
        };
    };

    if configs.is_empty() {
        return CheckResult {
            name: "payload_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no end-effector configs in profile; check skipped".to_string(),
        };
    }

    // Reject non-finite payload mass before any comparison.
    if !payload_kg.is_finite() {
        return CheckResult {
            name: "payload_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!("estimated_payload_kg {payload_kg} is NaN or infinite"),
        };
    }

    if payload_kg < 0.0 {
        return CheckResult {
            name: "payload_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!("estimated_payload_kg {payload_kg:.6} is negative"),
        };
    }

    let config_map: HashMap<&str, &EndEffectorConfig> =
        configs.iter().map(|c| (c.name.as_str(), c)).collect();

    // Find end-effectors in the command that have a profile config.
    let mut violations: Vec<String> = Vec::new();
    let mut any_checked = false;

    for entry in forces {
        let Some(cfg) = config_map.get(entry.name.as_str()) else {
            continue;
        };

        any_checked = true;

        if payload_kg > cfg.max_payload_kg {
            violations.push(format!(
                "'{}': estimated_payload_kg {:.6} kg exceeds max_payload_kg {:.6} kg",
                entry.name, payload_kg, cfg.max_payload_kg
            ));
        }
    }

    let details = if violations.is_empty() {
        if any_checked {
            format!("payload {payload_kg:.6} kg is within all end-effector limits")
        } else {
            // No matching end-effectors; no check fired.
            "no matching end-effector configs for payload check; skipped".to_string()
        }
    } else {
        violations.join("; ")
    };

    CheckResult {
        name: "payload_limits".to_string(),
        category: "physics".to_string(),
        passed: violations.is_empty(),
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, max_payload: f64) -> EndEffectorConfig {
        EndEffectorConfig {
            name: name.into(),
            max_force_n: 200.0,
            max_grasp_force_n: 100.0,
            min_grasp_force_n: 1.0,
            max_force_rate_n_per_s: 500.0,
            max_payload_kg: max_payload,
        }
    }

    fn force_entry(name: &str) -> EndEffectorForce {
        EndEffectorForce {
            name: name.into(),
            force: [0.0, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }
    }

    // ── Pass cases ───────────────────────────────────────────────────────────

    #[test]
    fn p14_no_payload_estimate_passes_trivially() {
        let configs = vec![cfg("gripper", 5.0)];
        let forces = vec![force_entry("gripper")];
        let r = check_payload_limits(&forces, None, &configs);
        assert!(r.passed);
        assert_eq!(r.name, "payload_limits");
        assert_eq!(r.category, "physics");
        assert!(r.details.contains("skipped"));
    }

    #[test]
    fn p14_no_configs_passes_trivially() {
        let forces = vec![force_entry("gripper")];
        let r = check_payload_limits(&forces, Some(3.0), &[]);
        assert!(r.passed);
        assert!(r.details.contains("skipped"));
    }

    #[test]
    fn p14_payload_within_limit_passes() {
        let configs = vec![cfg("gripper", 5.0)];
        let forces = vec![force_entry("gripper")];
        let r = check_payload_limits(&forces, Some(3.0), &configs);
        assert!(r.passed);
        assert!(r.details.contains("within"));
    }

    #[test]
    fn p14_payload_at_exact_limit_passes() {
        let configs = vec![cfg("gripper", 5.0)];
        let forces = vec![force_entry("gripper")];
        let r = check_payload_limits(&forces, Some(5.0), &configs);
        assert!(r.passed);
    }

    #[test]
    fn p14_zero_payload_passes() {
        let configs = vec![cfg("gripper", 5.0)];
        let forces = vec![force_entry("gripper")];
        let r = check_payload_limits(&forces, Some(0.0), &configs);
        assert!(r.passed);
    }

    #[test]
    fn p14_unmatched_ee_is_skipped() {
        let configs = vec![cfg("gripper", 5.0)];
        let forces = vec![force_entry("unknown_ee")];
        let r = check_payload_limits(&forces, Some(9999.0), &configs);
        assert!(r.passed);
        assert!(r.details.contains("skipped"));
    }

    #[test]
    fn p14_no_forces_passes() {
        let configs = vec![cfg("gripper", 5.0)];
        let r = check_payload_limits(&[], Some(3.0), &configs);
        assert!(r.passed);
    }

    // ── Fail cases ───────────────────────────────────────────────────────────

    #[test]
    fn p14_payload_exceeds_limit_fails() {
        let configs = vec![cfg("gripper", 5.0)];
        let forces = vec![force_entry("gripper")];
        let r = check_payload_limits(&forces, Some(6.0), &configs);
        assert!(!r.passed);
        assert!(r.details.contains("gripper"));
        assert!(r.details.contains("max_payload_kg"));
    }

    #[test]
    fn p14_nan_payload_fails() {
        let configs = vec![cfg("gripper", 5.0)];
        let forces = vec![force_entry("gripper")];
        let r = check_payload_limits(&forces, Some(f64::NAN), &configs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p14_infinite_payload_fails() {
        let configs = vec![cfg("gripper", 5.0)];
        let forces = vec![force_entry("gripper")];
        let r = check_payload_limits(&forces, Some(f64::INFINITY), &configs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p14_negative_payload_fails() {
        let configs = vec![cfg("gripper", 5.0)];
        let forces = vec![force_entry("gripper")];
        let r = check_payload_limits(&forces, Some(-1.0), &configs);
        assert!(!r.passed);
        assert!(r.details.contains("negative"));
    }

    #[test]
    fn p14_multiple_ees_one_violation() {
        // Both end-effectors present; payload exceeds limit for "fragile_ee" (max 2 kg).
        let configs = vec![cfg("robust_ee", 10.0), cfg("fragile_ee", 2.0)];
        let forces = vec![force_entry("robust_ee"), force_entry("fragile_ee")];
        let r = check_payload_limits(&forces, Some(3.0), &configs);
        assert!(!r.passed);
        assert!(r.details.contains("fragile_ee"));
        assert!(!r.details.contains("robust_ee"));
    }
}
