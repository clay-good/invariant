// P13: Contact force rate limit check

use std::collections::HashMap;

use crate::models::command::EndEffectorForce;
use crate::models::profile::EndEffectorConfig;
use crate::models::verdict::CheckResult;

/// Check that the rate of change of end-effector force magnitude does not
/// exceed `max_force_rate_n_per_s` (P13).
///
/// The rate is estimated as `|norm(force_new) - norm(force_prev)| / delta_time`.
///
/// When `previous_forces` is `None` (first command), the check passes trivially —
/// there is no prior force to difference against. Entries with no matching profile
/// config, or with no corresponding previous force reading, are skipped.
///
/// Non-positive or non-finite `delta_time` is a violation for any end-effector
/// that would otherwise be evaluated.
pub fn check_force_rate_limits(
    forces: &[EndEffectorForce],
    previous_forces: Option<&[EndEffectorForce]>,
    configs: &[EndEffectorConfig],
    delta_time: f64,
) -> CheckResult {
    // First command — no previous forces to diff against; pass trivially.
    let Some(prev) = previous_forces else {
        return CheckResult {
            name: "force_rate_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "skipped on first command (no previous end-effector forces)".to_string(),
        };
    };

    if configs.is_empty() || forces.is_empty() {
        return CheckResult {
            name: "force_rate_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no end-effector force data or profile configs to check".to_string(),
        };
    }

    let config_map: HashMap<&str, &EndEffectorConfig> =
        configs.iter().map(|c| (c.name.as_str(), c)).collect();
    let prev_map: HashMap<&str, &EndEffectorForce> =
        prev.iter().map(|f| (f.name.as_str(), f)).collect();

    // Non-finite or non-positive delta_time makes rate estimation undefined.
    if !delta_time.is_finite() || delta_time <= 0.0 {
        // Collect the names of end-effectors that would be evaluated.
        let affected: Vec<String> = forces
            .iter()
            .filter(|e| {
                config_map.contains_key(e.name.as_str()) && prev_map.contains_key(e.name.as_str())
            })
            .map(|e| format!("'{}'", e.name))
            .collect();

        if affected.is_empty() {
            // Nothing would have been evaluated anyway; pass.
            return CheckResult {
                name: "force_rate_limits".to_string(),
                category: "physics".to_string(),
                passed: true,
                details: "no end-effector force data or profile configs to check".to_string(),
            };
        }

        return CheckResult {
            name: "force_rate_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "delta_time {:.6} is non-positive; force rate is undefined for: {}",
                delta_time,
                affected.join(", ")
            ),
        };
    }

    let mut violations: Vec<String> = Vec::new();

    for entry in forces {
        let Some(cfg) = config_map.get(entry.name.as_str()) else {
            continue;
        };

        let Some(prev_entry) = prev_map.get(entry.name.as_str()) else {
            // No previous reading for this end-effector; skip.
            continue;
        };

        // Reject non-finite force components.
        if entry.force.iter().any(|f| !f.is_finite()) {
            violations.push(format!(
                "'{}': current force vector contains NaN or infinite component",
                entry.name
            ));
            continue;
        }
        if prev_entry.force.iter().any(|f| !f.is_finite()) {
            violations.push(format!(
                "'{}': previous force vector contains NaN or infinite component",
                entry.name
            ));
            continue;
        }

        let norm_new = vector_norm(&entry.force);
        let norm_prev = vector_norm(&prev_entry.force);
        let rate = (norm_new - norm_prev).abs() / delta_time;

        if rate > cfg.max_force_rate_n_per_s {
            violations.push(format!(
                "'{}': force rate {:.6} N/s exceeds max_force_rate_n_per_s {:.6} N/s",
                entry.name, rate, cfg.max_force_rate_n_per_s
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "force_rate_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all end-effector force rates within limits".to_string(),
        }
    } else {
        CheckResult {
            name: "force_rate_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
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

    fn cfg(name: &str, max_rate: f64) -> EndEffectorConfig {
        EndEffectorConfig {
            name: name.into(),
            max_force_n: 200.0,
            max_grasp_force_n: 100.0,
            min_grasp_force_n: 1.0,
            max_force_rate_n_per_s: max_rate,
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

    // ── First-command pass ───────────────────────────────────────────────────

    #[test]
    fn p13_no_previous_forces_passes_trivially() {
        let configs = vec![cfg("gripper", 500.0)];
        let forces = vec![force_entry("gripper", 100.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&forces, None, &configs, 0.01);
        assert!(r.passed);
        assert_eq!(r.name, "force_rate_limits");
        assert_eq!(r.category, "physics");
        assert!(r.details.contains("first command"));
    }

    // ── Pass cases ───────────────────────────────────────────────────────────

    #[test]
    fn p13_no_configs_passes_trivially() {
        let forces = vec![force_entry("gripper", 100.0, 0.0, 0.0)];
        let prev = vec![force_entry("gripper", 90.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&forces, Some(&prev), &[], 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p13_force_rate_within_limit_passes() {
        // norm(new) = 100, norm(prev) = 90, delta = 0.01 s → rate = 1000 N/s
        let configs = vec![cfg("gripper", 2000.0)];
        let forces = vec![force_entry("gripper", 100.0, 0.0, 0.0)];
        let prev = vec![force_entry("gripper", 90.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&forces, Some(&prev), &configs, 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p13_force_rate_at_exact_limit_passes() {
        // norm(new) = 100, norm(prev) = 90, delta = 0.01 → rate = 1000 N/s == limit
        let configs = vec![cfg("gripper", 1000.0)];
        let forces = vec![force_entry("gripper", 100.0, 0.0, 0.0)];
        let prev = vec![force_entry("gripper", 90.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&forces, Some(&prev), &configs, 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p13_unmatched_ee_is_skipped() {
        let configs = vec![cfg("gripper", 500.0)];
        let forces = vec![force_entry("unknown_ee", 9999.0, 0.0, 0.0)];
        let prev = vec![force_entry("unknown_ee", 0.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&forces, Some(&prev), &configs, 0.01);
        assert!(r.passed);
    }

    #[test]
    fn p13_no_previous_entry_for_ee_is_skipped() {
        // Previous forces do not include "gripper" — skip that end-effector.
        let configs = vec![cfg("gripper", 500.0)];
        let forces = vec![force_entry("gripper", 100.0, 0.0, 0.0)];
        let prev = vec![force_entry("other_ee", 0.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&forces, Some(&prev), &configs, 0.01);
        assert!(r.passed);
    }

    // ── Fail cases ───────────────────────────────────────────────────────────

    #[test]
    fn p13_force_rate_exceeds_limit_fails() {
        // norm(new) = 100, norm(prev) = 0, delta = 0.01 s → rate = 10000 N/s > 500
        let configs = vec![cfg("gripper", 500.0)];
        let forces = vec![force_entry("gripper", 100.0, 0.0, 0.0)];
        let prev = vec![force_entry("gripper", 0.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&forces, Some(&prev), &configs, 0.01);
        assert!(!r.passed);
        assert!(r.details.contains("gripper"));
        assert!(r.details.contains("max_force_rate_n_per_s"));
    }

    #[test]
    fn p13_non_positive_delta_time_fails() {
        let configs = vec![cfg("gripper", 500.0)];
        let forces = vec![force_entry("gripper", 100.0, 0.0, 0.0)];
        let prev = vec![force_entry("gripper", 90.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&forces, Some(&prev), &configs, 0.0);
        assert!(!r.passed);
        assert!(r.details.contains("non-positive"));
    }

    #[test]
    fn p13_negative_delta_time_fails() {
        let configs = vec![cfg("gripper", 500.0)];
        let forces = vec![force_entry("gripper", 100.0, 0.0, 0.0)];
        let prev = vec![force_entry("gripper", 90.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&forces, Some(&prev), &configs, -0.01);
        assert!(!r.passed);
    }

    #[test]
    fn p13_nan_current_force_fails() {
        let configs = vec![cfg("gripper", 500.0)];
        let mut entry = force_entry("gripper", 0.0, 0.0, 0.0);
        entry.force[0] = f64::NAN;
        let prev = vec![force_entry("gripper", 90.0, 0.0, 0.0)];
        let r = check_force_rate_limits(&[entry], Some(&prev), &configs, 0.01);
        assert!(!r.passed);
        assert!(r.details.contains("NaN or infinite"));
    }

    #[test]
    fn p13_multiple_ees_one_violation() {
        // left: rate = |50 - 45| / 0.01 = 500 == limit → pass
        // right: rate = |100 - 0| / 0.01 = 10000 > 500 → fail
        let configs = vec![cfg("left", 500.0), cfg("right", 500.0)];
        let forces = vec![
            force_entry("left", 50.0, 0.0, 0.0),
            force_entry("right", 100.0, 0.0, 0.0),
        ];
        let prev = vec![
            force_entry("left", 45.0, 0.0, 0.0),
            force_entry("right", 0.0, 0.0, 0.0),
        ];
        let r = check_force_rate_limits(&forces, Some(&prev), &configs, 0.01);
        assert!(!r.passed);
        assert!(r.details.contains("right"));
        assert!(!r.details.contains("left"));
    }
}
