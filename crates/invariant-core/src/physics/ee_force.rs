// P11: End-effector force limit check

use std::collections::HashMap;

use crate::models::command::EndEffectorForce;
use crate::models::profile::EndEffectorConfig;
use crate::models::verdict::CheckResult;

/// Check that the Cartesian force magnitude at each end-effector does not
/// exceed the configured `max_force_n` limit (P11).
///
/// Each [`EndEffectorForce`] entry is matched to an [`EndEffectorConfig`] by name.
/// Entries with no matching profile config are skipped (no check without a limit).
/// If `forces` is empty, or no entry matches a profile config, the check passes
/// trivially — the profile may not define end-effectors for this robot class.
///
/// Non-finite force components are treated as a violation because they would
/// vacuously pass any finite comparison.
pub fn check_ee_force_limits(
    forces: &[EndEffectorForce],
    configs: &[EndEffectorConfig],
) -> CheckResult {
    if configs.is_empty() || forces.is_empty() {
        return CheckResult {
            name: "ee_force_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no end-effector force data or profile configs to check".to_string(),
            derating: None,
        };
    }

    let config_map: HashMap<&str, &EndEffectorConfig> =
        configs.iter().map(|c| (c.name.as_str(), c)).collect();

    let mut violations: Vec<String> = Vec::new();

    for entry in forces {
        let Some(cfg) = config_map.get(entry.name.as_str()) else {
            // No profile config for this end-effector; skip without violation.
            continue;
        };

        // Reject non-finite force components before computing the norm.
        if entry.force.iter().any(|f| !f.is_finite()) {
            violations.push(format!(
                "'{}': force vector contains NaN or infinite component",
                entry.name
            ));
            continue;
        }

        let norm = vector_norm(&entry.force);
        if norm > cfg.max_force_n {
            violations.push(format!(
                "'{}': force magnitude {:.6} N exceeds max_force_n {:.6} N",
                entry.name, norm, cfg.max_force_n
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "ee_force_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all end-effector forces within limits".to_string(),
            derating: None,
        }
    } else {
        CheckResult {
            name: "ee_force_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        }
    }
}

/// Compute the Euclidean norm of a 3-vector.
#[inline]
fn vector_norm(v: &[f64; 3]) -> f64 {
    (v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str, max_force: f64) -> EndEffectorConfig {
        EndEffectorConfig {
            name: name.into(),
            max_force_n: max_force,
            max_grasp_force_n: 100.0,
            min_grasp_force_n: 1.0,
            max_force_rate_n_per_s: 500.0,
            max_payload_kg: 5.0,
        }
    }

    fn force_entry(name: &str, fx: f64, fy: f64, fz: f64) -> EndEffectorForce {
        EndEffectorForce {
            name: name.into(),
            force: [fx, fy, fz],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }
    }

    // ── Pass cases ───────────────────────────────────────────────────────────

    #[test]
    fn p11_no_configs_passes_trivially() {
        let forces = vec![force_entry("gripper", 50.0, 0.0, 0.0)];
        let r = check_ee_force_limits(&forces, &[]);
        assert!(r.passed);
        assert_eq!(r.name, "ee_force_limits");
        assert_eq!(r.category, "physics");
    }

    #[test]
    fn p11_no_forces_passes_trivially() {
        let configs = vec![cfg("gripper", 100.0)];
        let r = check_ee_force_limits(&[], &configs);
        assert!(r.passed);
    }

    #[test]
    fn p11_force_within_limit_passes() {
        let configs = vec![cfg("gripper", 100.0)];
        // norm([60, 0, 0]) = 60 <= 100
        let forces = vec![force_entry("gripper", 60.0, 0.0, 0.0)];
        let r = check_ee_force_limits(&forces, &configs);
        assert!(r.passed);
    }

    #[test]
    fn p11_force_at_exact_limit_passes() {
        let configs = vec![cfg("gripper", 100.0)];
        // norm([100, 0, 0]) = 100 == 100 → should pass (<=, not <)
        let forces = vec![force_entry("gripper", 100.0, 0.0, 0.0)];
        let r = check_ee_force_limits(&forces, &configs);
        assert!(r.passed);
    }

    #[test]
    fn p11_diagonal_force_within_limit_passes() {
        // norm([3, 4, 0]) = 5 <= 10
        let configs = vec![cfg("ee", 10.0)];
        let forces = vec![force_entry("ee", 3.0, 4.0, 0.0)];
        let r = check_ee_force_limits(&forces, &configs);
        assert!(r.passed);
    }

    #[test]
    fn p11_unmatched_ee_is_skipped() {
        // Force for "unknown_ee" has no config entry — must pass, not violate.
        let configs = vec![cfg("gripper", 10.0)];
        let forces = vec![force_entry("unknown_ee", 9999.0, 0.0, 0.0)];
        let r = check_ee_force_limits(&forces, &configs);
        assert!(r.passed);
    }

    // ── Fail cases ───────────────────────────────────────────────────────────

    #[test]
    fn p11_force_exceeds_limit_fails() {
        let configs = vec![cfg("gripper", 100.0)];
        // norm([101, 0, 0]) = 101 > 100
        let forces = vec![force_entry("gripper", 101.0, 0.0, 0.0)];
        let r = check_ee_force_limits(&forces, &configs);
        assert!(!r.passed);
        assert!(r.details.contains("gripper"));
        assert!(r.details.contains("max_force_n"));
    }

    #[test]
    fn p11_multiple_ees_one_violation() {
        let configs = vec![cfg("left", 50.0), cfg("right", 50.0)];
        let forces = vec![
            force_entry("left", 30.0, 0.0, 0.0),  // ok: 30 <= 50
            force_entry("right", 60.0, 0.0, 0.0), // fail: 60 > 50
        ];
        let r = check_ee_force_limits(&forces, &configs);
        assert!(!r.passed);
        assert!(r.details.contains("right"));
        assert!(!r.details.contains("left"));
    }

    #[test]
    fn p11_multiple_ees_both_violations() {
        let configs = vec![cfg("left", 50.0), cfg("right", 50.0)];
        let forces = vec![
            force_entry("left", 60.0, 0.0, 0.0),
            force_entry("right", 70.0, 0.0, 0.0),
        ];
        let r = check_ee_force_limits(&forces, &configs);
        assert!(!r.passed);
        assert!(r.details.contains("left"));
        assert!(r.details.contains("right"));
    }

    #[test]
    fn p11_nan_force_component_fails() {
        let configs = vec![cfg("gripper", 100.0)];
        let mut entry = force_entry("gripper", 0.0, 0.0, 0.0);
        entry.force[0] = f64::NAN;
        let r = check_ee_force_limits(&[entry], &configs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p11_infinite_force_component_fails() {
        let configs = vec![cfg("gripper", 100.0)];
        let mut entry = force_entry("gripper", 0.0, 0.0, 0.0);
        entry.force[2] = f64::INFINITY;
        let r = check_ee_force_limits(&[entry], &configs);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }
}
