// P6: Exclusion zone check (AABB + sphere) with conditional zone support.

use std::collections::HashMap;

use crate::models::command::EndEffectorPosition;
use crate::models::profile::ExclusionZone;
use crate::models::verdict::CheckResult;

/// Check that no end-effector position falls inside any active exclusion zone.
///
/// For AABB zones, a point is inside when `min[i] <= pos[i] <= max[i]` for all i.
/// For Sphere zones, a point is inside when the Euclidean distance to the center
/// is `<= radius`.
///
/// **Conditional zones:** Zones with `conditional: true` can be disabled at runtime
/// via `zone_overrides`. A conditional zone is ACTIVE by default (fail-closed) —
/// it must be explicitly disabled by setting its name to `false` in the overrides
/// map. Non-conditional zones ignore overrides entirely.
///
/// If `zones` is empty the check passes trivially — there is nothing to violate.
/// If `zones` is non-empty but `end_effectors` is empty the check fails — positions
/// are required to verify that no zone is entered.
pub fn check_exclusion_zones(
    end_effectors: &[EndEffectorPosition],
    zones: &[ExclusionZone],
    zone_overrides: &HashMap<String, bool>,
) -> CheckResult {
    // No zones defined: nothing to violate.
    if zones.is_empty() {
        return CheckResult {
            name: "exclusion_zones".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no exclusion zone violations".to_string(),
        };
    }

    // Filter out conditional zones that are explicitly disabled.
    let active_zones: Vec<&ExclusionZone> = zones
        .iter()
        .filter(|zone| is_zone_active(zone, zone_overrides))
        .collect();

    // All zones disabled: nothing to violate.
    if active_zones.is_empty() {
        return CheckResult {
            name: "exclusion_zones".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no exclusion zone violations (all conditional zones disabled)".to_string(),
        };
    }

    // Active zones exist but no positions provided: cannot verify — fail.
    if end_effectors.is_empty() {
        return CheckResult {
            name: "exclusion_zones".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "end_effector_positions required for exclusion zone check".to_string(),
        };
    }

    let mut violations: Vec<String> = Vec::new();

    for ee in end_effectors {
        if !ee.position[0].is_finite() || !ee.position[1].is_finite() || !ee.position[2].is_finite()
        {
            violations.push(format!(
                "'{}': position contains NaN or infinite value",
                ee.name
            ));
            continue;
        }
        for zone in &active_zones {
            match zone {
                ExclusionZone::Aabb { name, min, max, .. } => {
                    if point_in_aabb(&ee.position, min, max) {
                        violations.push(format!("'{}' inside AABB zone '{}'", ee.name, name));
                    }
                }
                ExclusionZone::Sphere {
                    name,
                    center,
                    radius,
                    ..
                } => {
                    if point_in_sphere(&ee.position, center, *radius) {
                        violations.push(format!("'{}' inside sphere zone '{}'", ee.name, name));
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "exclusion_zones".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no exclusion zone violations".to_string(),
        }
    } else {
        CheckResult {
            name: "exclusion_zones".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
    }
}

/// Determine if a zone is currently active given the overrides map.
///
/// - Non-conditional zones are always active (overrides are ignored).
/// - Conditional zones default to active (fail-closed). They are only
///   disabled when the override map explicitly sets their name to `false`.
fn is_zone_active(zone: &ExclusionZone, overrides: &HashMap<String, bool>) -> bool {
    let (name, conditional) = match zone {
        ExclusionZone::Aabb {
            name, conditional, ..
        } => (name, *conditional),
        ExclusionZone::Sphere {
            name, conditional, ..
        } => (name, *conditional),
    };

    if !conditional {
        return true; // non-conditional zones are always active
    }

    // Conditional zone: active unless explicitly set to false.
    // Missing entry = active (fail-closed).
    overrides.get(name).copied().unwrap_or(true)
}

/// Returns `true` if `point` is inside or on the surface of the AABB defined by
/// `[min, max]`.
#[inline]
fn point_in_aabb(point: &[f64; 3], min: &[f64; 3], max: &[f64; 3]) -> bool {
    point[0] >= min[0]
        && point[0] <= max[0]
        && point[1] >= min[1]
        && point[1] <= max[1]
        && point[2] >= min[2]
        && point[2] <= max[2]
}

/// Returns `true` if `point` is inside or on the surface of the sphere defined by
/// `center` and `radius`.
#[inline]
fn point_in_sphere(point: &[f64; 3], center: &[f64; 3], radius: f64) -> bool {
    let dx = point[0] - center[0];
    let dy = point[1] - center[1];
    let dz = point[2] - center[2];
    // Compare squared distances to avoid a sqrt.
    dx * dx + dy * dy + dz * dz <= radius * radius
}
