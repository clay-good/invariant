// P9: Center-of-mass stability (ZMP) check

use crate::models::profile::StabilityConfig;
use crate::models::verdict::CheckResult;

/// Check that the center-of-mass (CoM) projected onto the ground plane (x, y)
/// falls within the support polygon defined in `stability_config`.
///
/// The polygon test uses a ray-casting algorithm: a horizontal ray is cast from
/// the query point and the number of edge crossings is counted.  An odd count
/// means the point is inside.
///
/// Returns a passing result when:
/// - `center_of_mass` is `None` (no CoM data provided), or
/// - `stability_config` is `None` (no stability spec in the profile), or
/// - `stability_config.enabled` is `false`, or
/// - the support polygon has fewer than 3 vertices (degenerate polygon).
pub fn check_stability(
    center_of_mass: Option<&[f64; 3]>,
    stability_config: Option<&StabilityConfig>,
) -> CheckResult {
    // Cannot evaluate — treat as passing.
    let (com, config) = match (center_of_mass, stability_config) {
        (Some(c), Some(s)) => (c, s),
        _ => {
            return CheckResult {
                name: "stability".to_string(),
                category: "physics".to_string(),
                passed: true,
                details: "stability check not evaluated (no data)".to_string(),
            };
        }
    };

    if !config.enabled {
        return CheckResult {
            name: "stability".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "stability check disabled".to_string(),
        };
    }

    let polygon = &config.support_polygon;
    if polygon.len() < 3 {
        return CheckResult {
            name: "stability".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "stability check not evaluated (degenerate polygon)".to_string(),
        };
    }

    // Reject non-finite CoM values.
    if !com[0].is_finite() || !com[1].is_finite() || !com[2].is_finite() {
        return CheckResult {
            name: "stability".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "center of mass contains NaN or infinite value".to_string(),
        };
    }

    // Project the 3-D CoM onto the 2-D ground plane (x, y).
    let px = com[0];
    let py = com[1];

    if point_in_polygon(px, py, polygon) {
        CheckResult {
            name: "stability".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "CoM ({:.4}, {:.4}) is within the support polygon",
                px, py
            ),
        }
    } else {
        CheckResult {
            name: "stability".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "CoM ({:.4}, {:.4}) is outside the support polygon",
                px, py
            ),
        }
    }
}

/// Ray-casting point-in-polygon test.
///
/// Casts a ray from `(px, py)` in the +x direction and counts how many edges of
/// `polygon` it crosses.  An odd count indicates the point is inside the polygon.
///
/// Edge cases handled:
/// - Horizontal edges are skipped (the ray runs parallel to them).
/// - Vertices exactly on the ray are handled by the half-open interval `[y_min, y_max)`.
fn point_in_polygon(px: f64, py: f64, polygon: &[[f64; 2]]) -> bool {
    let n = polygon.len();
    let mut inside = false;

    let mut j = n - 1;
    for i in 0..n {
        let xi = polygon[i][0];
        let yi = polygon[i][1];
        let xj = polygon[j][0];
        let yj = polygon[j][1];

        // Check whether the edge (j -> i) crosses the horizontal ray at py.
        // The half-open interval on y prevents double-counting shared vertices.
        let crosses_y = (yi > py) != (yj > py);
        if crosses_y {
            // x-coordinate of the intersection of the edge with the horizontal ray.
            let x_intersect = xj + (py - yj) * (xi - xj) / (yi - yj);
            if px < x_intersect {
                inside = !inside;
            }
        }

        j = i;
    }

    inside
}
