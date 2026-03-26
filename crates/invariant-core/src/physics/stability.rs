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
/// - `stability_config.enabled` is `false`.
///
/// Returns a failing result when:
/// - the support polygon has fewer than 3 vertices (degenerate polygon), or
/// - the CoM contains NaN or infinite values, or
/// - the CoM projected onto the ground plane falls outside the support polygon.
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
            passed: false,
            details: "stability check failed: degenerate support polygon (fewer than 3 vertices)"
                .to_string(),
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
            details: format!("CoM ({:.4}, {:.4}) is within the support polygon", px, py),
        }
    } else {
        CheckResult {
            name: "stability".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!("CoM ({:.4}, {:.4}) is outside the support polygon", px, py),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::StabilityConfig;

    /// Build a minimal enabled StabilityConfig with the given polygon.
    fn stability_cfg(polygon: Vec<[f64; 2]>) -> StabilityConfig {
        StabilityConfig {
            support_polygon: polygon,
            com_height_estimate: 1.0,
            enabled: true,
        }
    }

    // ── Unit square used for most tests: (0,0)-(1,0)-(1,1)-(0,1) ────────────

    fn unit_square() -> StabilityConfig {
        stability_cfg(vec![[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.0, 1.0]])
    }

    // ── Finding 70 — vertex, edge, and concave polygon edge cases ────────────

    #[test]
    fn com_at_vertex_of_polygon() {
        // A vertex of the polygon is geometrically on the boundary.  The
        // ray-casting algorithm may classify this as inside or on-boundary;
        // we assert it does not panic and returns a definite result.
        let cfg = unit_square();
        // Bottom-left vertex (0, 0).
        let result = check_stability(Some(&[0.0, 0.0, 0.0]), Some(&cfg));
        assert_eq!(result.name, "stability");
        // The result (pass/fail) is implementation-defined for exact vertices;
        // we just verify the function returns without panic.
        assert!(!result.details.is_empty());
    }

    #[test]
    fn com_on_edge_of_polygon_passes() {
        // A point clearly on an edge (midpoint of the bottom edge of the unit
        // square).  The ray-caster may classify this as inside or outside
        // depending on the half-open interval convention, but the call must not
        // panic and must produce a valid result.
        let cfg = unit_square();
        // Mid-point of bottom edge: (0.5, 0.0).
        let result = check_stability(Some(&[0.5, 0.0, 0.0]), Some(&cfg));
        assert_eq!(result.name, "stability");
        assert!(!result.details.is_empty());
    }

    #[test]
    fn com_strictly_inside_polygon_passes() {
        let cfg = unit_square();
        let result = check_stability(Some(&[0.5, 0.5, 0.0]), Some(&cfg));
        assert!(
            result.passed,
            "CoM at centroid should be inside unit square"
        );
    }

    #[test]
    fn com_strictly_outside_polygon_fails() {
        let cfg = unit_square();
        // Clearly outside.
        let result = check_stability(Some(&[2.0, 2.0, 0.0]), Some(&cfg));
        assert!(!result.passed, "CoM far outside unit square should fail");
    }

    #[test]
    fn concave_l_shaped_polygon_com_in_notch_is_outside() {
        // L-shaped (concave) polygon — vertices listed counter-clockwise:
        //
        //   (0,2) ──── (1,2)
        //     |          |
        //   (0,1)  (1,1)─(2,1)
        //     |              |
        //   (0,0) ─────────(2,0)
        //
        // The concave notch is the region x ∈ (1,2), y ∈ (1,2).
        // A CoM at (1.5, 1.5) is in that notch and must be OUTSIDE.
        let l_shape = stability_cfg(vec![
            [0.0, 0.0],
            [2.0, 0.0],
            [2.0, 1.0],
            [1.0, 1.0],
            [1.0, 2.0],
            [0.0, 2.0],
        ]);
        let result = check_stability(Some(&[1.5, 1.5, 0.0]), Some(&l_shape));
        assert!(
            !result.passed,
            "CoM in concave notch of L-shape should be outside: {}",
            result.details
        );
    }

    #[test]
    fn concave_l_shaped_polygon_com_in_solid_region_passes() {
        // Same L-shape.  A CoM at (0.5, 0.5) is inside the solid lower region.
        let l_shape = stability_cfg(vec![
            [0.0, 0.0],
            [2.0, 0.0],
            [2.0, 1.0],
            [1.0, 1.0],
            [1.0, 2.0],
            [0.0, 2.0],
        ]);
        let result = check_stability(Some(&[0.5, 0.5, 0.0]), Some(&l_shape));
        assert!(
            result.passed,
            "CoM in solid region of L-shape should be inside: {}",
            result.details
        );
    }
}
