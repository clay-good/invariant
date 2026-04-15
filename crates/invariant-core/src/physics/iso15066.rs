// ISO/TS 15066 proximity-triggered force limiting (Step 45).
//
// When an end-effector is inside a proximity zone tagged as human-critical,
// the maximum allowable force is clamped to ISO/TS 15066 body-region limits.
//
// The standard defines maximum quasi-static and transient contact forces for
// different body regions. When the specific body region is unknown (no task
// envelope override), the most conservative limit (65 N — face contact) is
// applied.
//
// This check is additive — it does NOT replace P11 (ee_force_limits). It
// provides an additional, tighter limit when humans are detected nearby.

use crate::models::command::{EndEffectorForce, EndEffectorPosition};
use crate::models::profile::ProximityZone;
use crate::models::verdict::CheckResult;
use crate::physics::geometry::point_in_sphere;

// ---------------------------------------------------------------------------
// ISO/TS 15066 body-region force table
// ---------------------------------------------------------------------------

/// A body region with its ISO/TS 15066 force limits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BodyRegionLimit {
    /// Name of the body region (e.g., `"face"`, `"chest"`).
    pub region: &'static str,
    /// Maximum quasi-static contact force (N).
    pub max_quasi_static_n: f64,
    /// Maximum transient contact force (N).
    pub max_transient_n: f64,
}

/// ISO/TS 15066 Table A.2 — Maximum permissible force values.
///
/// These are the standard body-region limits for collaborative robot contact.
pub const BODY_REGION_LIMITS: &[BodyRegionLimit] = &[
    BodyRegionLimit {
        region: "skull_forehead",
        max_quasi_static_n: 130.0,
        max_transient_n: 130.0,
    },
    BodyRegionLimit {
        region: "face",
        max_quasi_static_n: 65.0,
        max_transient_n: 65.0,
    },
    BodyRegionLimit {
        region: "neck_side",
        max_quasi_static_n: 150.0,
        max_transient_n: 150.0,
    },
    BodyRegionLimit {
        region: "chest",
        max_quasi_static_n: 140.0,
        max_transient_n: 140.0,
    },
    BodyRegionLimit {
        region: "abdomen",
        max_quasi_static_n: 110.0,
        max_transient_n: 110.0,
    },
    BodyRegionLimit {
        region: "hand_finger",
        max_quasi_static_n: 140.0,
        max_transient_n: 180.0,
    },
    BodyRegionLimit {
        region: "upper_arm",
        max_quasi_static_n: 150.0,
        max_transient_n: 190.0,
    },
    BodyRegionLimit {
        region: "lower_leg",
        max_quasi_static_n: 130.0,
        max_transient_n: 160.0,
    },
];

/// The most conservative force limit across all body regions.
/// Used when the specific body region is unknown. This is the face limit (65 N).
pub const MOST_CONSERVATIVE_FORCE_N: f64 = 65.0;

/// Look up the force limit for a named body region.
/// Returns `None` if the region name is not recognized.
pub fn limit_for_region(region: &str) -> Option<&'static BodyRegionLimit> {
    BODY_REGION_LIMITS.iter().find(|l| l.region == region)
}

// ---------------------------------------------------------------------------
// Proximity-triggered force check
// ---------------------------------------------------------------------------

/// Determine if a proximity zone is tagged as human-critical.
///
/// A zone is considered human-critical if its name contains "human_critical"
/// (case-insensitive match). This follows the naming convention from the spec
/// Section 3.1 (`human_critical` proximity zone).
fn is_human_critical(zone: &ProximityZone) -> bool {
    match zone {
        ProximityZone::Sphere { name, .. } => name.to_ascii_lowercase().contains("human_critical"),
    }
}

/// Check if a point is inside a proximity zone.
fn point_in_proximity_zone(zone: &ProximityZone, point: &[f64; 3]) -> bool {
    match zone {
        ProximityZone::Sphere {
            center, radius, ..
        } => point_in_sphere(point, center, *radius),
    }
}

/// Check that end-effector forces comply with ISO/TS 15066 limits when the
/// end-effector is inside a human-critical proximity zone.
///
/// # Algorithm
///
/// 1. Identify all human-critical proximity zones (name contains "human_critical").
/// 2. For each end-effector position, check if it is inside any human-critical zone.
/// 3. If yes, apply the ISO/TS 15066 force limit (default: 65 N most conservative).
/// 4. If an `override_body_region` is specified, use that region's limits instead.
///
/// Returns a passing `CheckResult` when:
/// - No human-critical zones exist
/// - No end-effectors are inside human-critical zones
/// - All forces inside human-critical zones are within ISO/TS 15066 limits
pub fn check_iso15066_force_limits(
    ee_positions: &[EndEffectorPosition],
    ee_forces: &[EndEffectorForce],
    proximity_zones: &[ProximityZone],
    override_body_region: Option<&str>,
) -> CheckResult {
    // Collect human-critical zones.
    let critical_zones: Vec<&ProximityZone> = proximity_zones
        .iter()
        .filter(|z| is_human_critical(z))
        .collect();

    if critical_zones.is_empty() || ee_positions.is_empty() {
        return CheckResult {
            name: "iso15066_force_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no human-critical proximity zones active or no end-effector positions"
                .to_string(),
            derating: None,
        };
    }

    // Fail-closed: if any EE is inside a human-critical zone but no force data
    // is provided, reject. Missing force data in a human zone is not safe.
    if ee_forces.is_empty() {
        // Check if any EE is actually inside a critical zone before rejecting.
        let ee_in_zone = ee_positions.iter().any(|ee| {
            critical_zones
                .iter()
                .any(|z| point_in_proximity_zone(z, &ee.position))
        });
        if ee_in_zone {
            return CheckResult {
                name: "iso15066_force_limits".to_string(),
                category: "physics".to_string(),
                passed: false,
                details: "end-effector is inside human-critical zone but no force data provided"
                    .to_string(),
                derating: None,
            };
        }
        return CheckResult {
            name: "iso15066_force_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no end-effectors inside human-critical zones".to_string(),
            derating: None,
        };
    }

    // Determine the applicable force limit.
    let force_limit = match override_body_region {
        Some(region) => match limit_for_region(region) {
            Some(limit) => limit.max_quasi_static_n,
            None => MOST_CONSERVATIVE_FORCE_N,
        },
        None => MOST_CONSERVATIVE_FORCE_N,
    };

    // Find end-effectors inside human-critical zones.
    let mut violations: Vec<String> = Vec::new();

    for ee_pos in ee_positions {
        // Check non-finite positions.
        if !ee_pos.position[0].is_finite()
            || !ee_pos.position[1].is_finite()
            || !ee_pos.position[2].is_finite()
        {
            continue; // P10 catches this; don't double-report.
        }

        let inside_critical = critical_zones.iter().any(|zone| match zone {
            ProximityZone::Sphere { center, radius, .. } => {
                point_in_sphere(&ee_pos.position, center, *radius)
            }
        });

        if !inside_critical {
            continue;
        }

        // This end-effector is inside a human-critical zone.
        // Check if there's a matching force reading.
        if let Some(force_entry) = ee_forces.iter().find(|f| f.name == ee_pos.name) {
            if force_entry.force.iter().any(|f| !f.is_finite()) {
                violations.push(format!(
                    "'{}': force contains NaN/Inf inside human-critical zone",
                    ee_pos.name
                ));
                continue;
            }

            let norm = vector_norm(&force_entry.force);
            if norm > force_limit {
                let region_label = override_body_region.unwrap_or("face (default)");
                violations.push(format!(
                    "'{}': force {norm:.1} N exceeds ISO/TS 15066 limit {force_limit:.1} N \
                     for body region '{region_label}' inside human-critical zone",
                    ee_pos.name
                ));
            }
        }
    }

    if violations.is_empty() {
        let region_label = override_body_region.unwrap_or("face (default)");
        CheckResult {
            name: "iso15066_force_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "all forces within ISO/TS 15066 limits ({force_limit:.1} N, region: {region_label})"
            ),
            derating: None,
        }
    } else {
        CheckResult {
            name: "iso15066_force_limits".to_string(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::command::{EndEffectorForce, EndEffectorPosition};
    use crate::models::profile::ProximityZone;

    fn human_critical_zone(center: [f64; 3], radius: f64) -> ProximityZone {
        ProximityZone::Sphere {
            name: "human_critical".into(),
            center,
            radius,
            velocity_scale: 0.1,
            dynamic: true,
        }
    }

    fn human_warning_zone(center: [f64; 3], radius: f64) -> ProximityZone {
        ProximityZone::Sphere {
            name: "human_warning".into(),
            center,
            radius,
            velocity_scale: 0.5,
            dynamic: true,
        }
    }

    fn ee_pos(name: &str, pos: [f64; 3]) -> EndEffectorPosition {
        EndEffectorPosition {
            name: name.into(),
            position: pos,
        }
    }

    fn ee_force(name: &str, fx: f64, fy: f64, fz: f64) -> EndEffectorForce {
        EndEffectorForce {
            name: name.into(),
            force: [fx, fy, fz],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }
    }

    // -- Table data tests --

    #[test]
    fn body_region_table_has_8_entries() {
        assert_eq!(BODY_REGION_LIMITS.len(), 8);
    }

    #[test]
    fn most_conservative_is_face() {
        // The most conservative limit should be face at 65 N.
        let min = BODY_REGION_LIMITS
            .iter()
            .map(|l| l.max_quasi_static_n)
            .fold(f64::MAX, f64::min);
        assert_eq!(min, 65.0);
        assert_eq!(MOST_CONSERVATIVE_FORCE_N, 65.0);
    }

    #[test]
    fn limit_for_region_known() {
        let chest = limit_for_region("chest").unwrap();
        assert_eq!(chest.max_quasi_static_n, 140.0);
        assert_eq!(chest.max_transient_n, 140.0);

        let hand = limit_for_region("hand_finger").unwrap();
        assert_eq!(hand.max_quasi_static_n, 140.0);
        assert_eq!(hand.max_transient_n, 180.0);
    }

    #[test]
    fn limit_for_region_unknown_returns_none() {
        assert!(limit_for_region("ankle").is_none());
    }

    // -- No human-critical zones: trivially passes --

    #[test]
    fn no_critical_zones_passes() {
        let zones = vec![human_warning_zone([1.0, 0.0, 1.0], 1.0)];
        let positions = vec![ee_pos("gripper", [1.0, 0.0, 1.0])];
        let forces = vec![ee_force("gripper", 200.0, 0.0, 0.0)];

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(result.passed);
    }

    // -- End-effector outside critical zone: passes --

    #[test]
    fn ee_outside_critical_zone_passes() {
        let zones = vec![human_critical_zone([5.0, 0.0, 1.0], 0.5)];
        let positions = vec![ee_pos("gripper", [0.0, 0.0, 1.0])]; // far away
        let forces = vec![ee_force("gripper", 200.0, 0.0, 0.0)]; // would fail if inside

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(result.passed);
    }

    // -- End-effector inside critical zone with safe force: passes --

    #[test]
    fn ee_inside_critical_zone_force_within_limit_passes() {
        let zones = vec![human_critical_zone([1.0, 0.0, 1.0], 1.0)];
        let positions = vec![ee_pos("gripper", [1.0, 0.0, 1.0])]; // inside
        let forces = vec![ee_force("gripper", 30.0, 0.0, 0.0)]; // 30 N < 65 N

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(result.passed);
        assert!(result.details.contains("65.0 N"));
    }

    // -- End-effector inside critical zone with excessive force: fails --

    #[test]
    fn ee_inside_critical_zone_force_exceeds_limit_fails() {
        let zones = vec![human_critical_zone([1.0, 0.0, 1.0], 1.0)];
        let positions = vec![ee_pos("gripper", [1.0, 0.0, 1.0])]; // inside
        let forces = vec![ee_force("gripper", 100.0, 0.0, 0.0)]; // 100 N > 65 N

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(!result.passed);
        assert!(result.details.contains("ISO/TS 15066"));
        assert!(result.details.contains("100.0 N"));
        assert!(result.details.contains("65.0 N"));
        assert!(result.details.contains("face (default)"));
    }

    // -- Body region override: uses the specified region's limit --

    #[test]
    fn body_region_override_uses_specified_limit() {
        let zones = vec![human_critical_zone([1.0, 0.0, 1.0], 1.0)];
        let positions = vec![ee_pos("gripper", [1.0, 0.0, 1.0])];
        // 100 N would fail the default face limit (65 N) but passes chest limit (140 N).
        let forces = vec![ee_force("gripper", 100.0, 0.0, 0.0)];

        let result = check_iso15066_force_limits(&positions, &forces, &zones, Some("chest"));
        assert!(result.passed);
        assert!(result.details.contains("140.0 N"));
        assert!(result.details.contains("chest"));
    }

    #[test]
    fn body_region_override_unknown_falls_back_to_conservative() {
        let zones = vec![human_critical_zone([1.0, 0.0, 1.0], 1.0)];
        let positions = vec![ee_pos("gripper", [1.0, 0.0, 1.0])];
        let forces = vec![ee_force("gripper", 100.0, 0.0, 0.0)];

        let result = check_iso15066_force_limits(&positions, &forces, &zones, Some("ankle"));
        assert!(!result.passed); // 100 > 65 (fallback)
    }

    // -- At exact limit: passes --

    #[test]
    fn force_at_exact_iso_limit_passes() {
        let zones = vec![human_critical_zone([0.0, 0.0, 0.0], 2.0)];
        let positions = vec![ee_pos("gripper", [0.0, 0.0, 0.0])];
        let forces = vec![ee_force("gripper", 65.0, 0.0, 0.0)]; // exactly 65 N

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(result.passed);
    }

    // -- Multiple end-effectors: one inside, one outside --

    #[test]
    fn multiple_ees_only_inside_one_checked() {
        let zones = vec![human_critical_zone([0.0, 0.0, 0.0], 1.0)];
        let positions = vec![
            ee_pos("left_hand", [0.0, 0.0, 0.0]),  // inside
            ee_pos("right_hand", [5.0, 0.0, 0.0]), // outside
        ];
        let forces = vec![
            ee_force("left_hand", 30.0, 0.0, 0.0),   // safe
            ee_force("right_hand", 200.0, 0.0, 0.0), // would fail if inside
        ];

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(result.passed); // right_hand is outside, not checked
    }

    // -- No matching force data for an end-effector inside zone: passes --

    #[test]
    fn ee_inside_zone_but_no_force_data_rejected() {
        // Fail-closed: an EE inside a human-critical zone without force data
        // must be rejected — missing data is not safe.
        let zones = vec![human_critical_zone([0.0, 0.0, 0.0], 1.0)];
        let positions = vec![ee_pos("gripper", [0.0, 0.0, 0.0])];
        let forces: Vec<EndEffectorForce> = vec![]; // no force data

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(!result.passed, "missing force data in human zone must be rejected");
    }

    #[test]
    fn ee_outside_zone_no_force_data_passes() {
        // EE is far from the human-critical zone — no force data needed.
        let zones = vec![human_critical_zone([0.0, 0.0, 0.0], 1.0)];
        let positions = vec![ee_pos("gripper", [5.0, 5.0, 5.0])]; // far away
        let forces: Vec<EndEffectorForce> = vec![];

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(result.passed, "EE outside zone should pass without force data");
    }

    // -- NaN force inside critical zone: violation --

    #[test]
    fn nan_force_inside_critical_zone_fails() {
        let zones = vec![human_critical_zone([0.0, 0.0, 0.0], 1.0)];
        let positions = vec![ee_pos("gripper", [0.0, 0.0, 0.0])];
        let forces = vec![EndEffectorForce {
            name: "gripper".into(),
            force: [f64::NAN, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }];

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(!result.passed);
        assert!(result.details.contains("NaN"));
    }

    // -- Diagonal force vector --

    #[test]
    fn diagonal_force_checked_correctly() {
        let zones = vec![human_critical_zone([0.0, 0.0, 0.0], 2.0)];
        let positions = vec![ee_pos("gripper", [0.0, 0.0, 0.0])];
        // norm([40, 40, 40]) = 69.28.. > 65 N
        let forces = vec![ee_force("gripper", 40.0, 40.0, 40.0)];

        let result = check_iso15066_force_limits(&positions, &forces, &zones, None);
        assert!(!result.passed);
    }

    // -- is_human_critical naming convention --

    #[test]
    fn human_critical_zone_name_detection() {
        assert!(is_human_critical(&ProximityZone::Sphere {
            name: "human_critical".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.1,
            dynamic: true,
        }));
        assert!(is_human_critical(&ProximityZone::Sphere {
            name: "Human_Critical_Zone_1".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.1,
            dynamic: true,
        }));
        assert!(!is_human_critical(&ProximityZone::Sphere {
            name: "human_warning".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.5,
            dynamic: true,
        }));
    }

    // ── Step 104: ISO 15066 NaN zone center fail-closed tests ─────────

    #[test]
    fn point_in_sphere_nan_center_returns_true() {
        // Fail-closed: NaN center must treat point as inside.
        assert!(point_in_sphere(
            &[5.0, 5.0, 5.0],
            &[f64::NAN, 0.0, 0.0],
            1.0
        ));
    }

    #[test]
    fn point_in_sphere_nan_radius_returns_true() {
        assert!(point_in_sphere(
            &[5.0, 5.0, 5.0],
            &[0.0, 0.0, 0.0],
            f64::NAN
        ));
    }

    #[test]
    fn point_in_sphere_inf_center_returns_true() {
        assert!(point_in_sphere(
            &[0.0, 0.0, 0.0],
            &[f64::INFINITY, 0.0, 0.0],
            1.0
        ));
    }

    #[test]
    fn point_in_sphere_nan_point_returns_true() {
        // Fail-closed: NaN in the EE position must treat the point as inside
        // the zone. Before this fix, NaN point produced NaN distance which
        // compared as false (<=), silently bypassing the zone — fail-open.
        assert!(point_in_sphere(
            &[f64::NAN, 0.0, 0.0],
            &[0.0, 0.0, 0.0],
            1.0
        ));
    }

    #[test]
    fn point_in_sphere_inf_point_returns_true() {
        assert!(point_in_sphere(
            &[f64::INFINITY, 0.0, 0.0],
            &[0.0, 0.0, 0.0],
            1.0
        ));
    }

    #[test]
    fn iso15066_nan_zone_center_fails_closed_for_force_check() {
        // A proximity zone with NaN center should be treated as containing
        // any EE (fail-closed), so force limits should be enforced.
        let ee_pos = vec![EndEffectorPosition {
            name: "gripper".into(),
            position: [5.0, 5.0, 5.0], // far from any real zone
        }];
        let forces = vec![EndEffectorForce {
            name: "gripper".into(),
            force: [200.0, 0.0, 0.0], // large force
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }];
        let zones = vec![ProximityZone::Sphere {
            name: "human_critical".into(),
            center: [f64::NAN, 0.0, 0.0], // corrupt center
            radius: 0.5,
            velocity_scale: 0.1, // critical zone
            dynamic: true,
        }];

        let result = check_iso15066_force_limits(&ee_pos, &forces, &zones, None);
        // With NaN center → point_in_sphere returns true → zone is active →
        // ISO 15066 limits enforced → large force should be flagged.
        assert!(
            !result.passed,
            "NaN zone center must fail-closed: {}",
            result.details
        );
    }
}
