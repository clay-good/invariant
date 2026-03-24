// P6: Exclusion zone check (AABB + sphere)

use crate::models::command::EndEffectorPosition;
use crate::models::profile::ExclusionZone;
use crate::models::verdict::CheckResult;

/// Check that no end-effector position falls inside any exclusion zone.
///
/// For AABB zones, a point is inside when `min[i] <= pos[i] <= max[i]` for all i.
/// For Sphere zones, a point is inside when the Euclidean distance to the center
/// is `<= radius`.
///
/// If `end_effectors` or `zones` is empty the check passes trivially — there is
/// nothing to violate.
pub fn check_exclusion_zones(
    end_effectors: &[EndEffectorPosition],
    zones: &[ExclusionZone],
) -> CheckResult {
    if end_effectors.is_empty() || zones.is_empty() {
        return CheckResult {
            name: "exclusion_zones".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no exclusion zone violations".to_string(),
        };
    }

    let mut violations: Vec<String> = Vec::new();

    for ee in end_effectors {
        if !ee.position[0].is_finite() || !ee.position[1].is_finite() || !ee.position[2].is_finite() {
            violations.push(format!(
                "'{}': position contains NaN or infinite value",
                ee.name
            ));
            continue;
        }
        for zone in zones {
            match zone {
                ExclusionZone::Aabb { name, min, max } => {
                    if point_in_aabb(&ee.position, min, max) {
                        violations.push(format!(
                            "'{}' inside AABB zone '{}'",
                            ee.name, name
                        ));
                    }
                }
                ExclusionZone::Sphere { name, center, radius } => {
                    if point_in_sphere(&ee.position, center, *radius) {
                        violations.push(format!(
                            "'{}' inside sphere zone '{}'",
                            ee.name, name
                        ));
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
