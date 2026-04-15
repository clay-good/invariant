// Shared geometry primitives for physics checks.
//
// These are safety-critical functions used by multiple checks (P6, P10,
// ISO 15066). Centralizing them ensures bug fixes (like NaN fail-closed
// guards) are applied everywhere.

/// Returns `true` if `point` is inside or on the surface of the sphere
/// defined by `center` and `radius`.
///
/// **Fail-closed:** if any of `point`, `center`, or `radius` contains
/// NaN or Infinity, the function returns `true` (point treated as inside).
/// This ensures velocity scaling, exclusion zones, and force limits are
/// always enforced when sensor data is corrupt — the most conservative
/// safe behavior.
#[inline]
pub(crate) fn point_in_sphere(point: &[f64; 3], center: &[f64; 3], radius: f64) -> bool {
    if !radius.is_finite()
        || !center.iter().all(|v| v.is_finite())
        || !point.iter().all(|v| v.is_finite())
    {
        return true; // fail-closed: assume inside zone
    }
    let dx = point[0] - center[0];
    let dy = point[1] - center[1];
    let dz = point[2] - center[2];
    dx * dx + dy * dy + dz * dz <= radius * radius
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inside_sphere() {
        assert!(point_in_sphere(&[0.0, 0.0, 0.0], &[0.0, 0.0, 0.0], 1.0));
    }

    #[test]
    fn on_surface() {
        assert!(point_in_sphere(&[1.0, 0.0, 0.0], &[0.0, 0.0, 0.0], 1.0));
    }

    #[test]
    fn outside_sphere() {
        assert!(!point_in_sphere(&[2.0, 0.0, 0.0], &[0.0, 0.0, 0.0], 1.0));
    }

    #[test]
    fn nan_center_fail_closed() {
        assert!(point_in_sphere(
            &[5.0, 5.0, 5.0],
            &[f64::NAN, 0.0, 0.0],
            1.0
        ));
    }

    #[test]
    fn nan_radius_fail_closed() {
        assert!(point_in_sphere(
            &[5.0, 5.0, 5.0],
            &[0.0, 0.0, 0.0],
            f64::NAN
        ));
    }

    #[test]
    fn nan_point_fail_closed() {
        assert!(point_in_sphere(
            &[f64::NAN, 0.0, 0.0],
            &[0.0, 0.0, 0.0],
            1.0
        ));
    }

    #[test]
    fn inf_center_fail_closed() {
        assert!(point_in_sphere(
            &[0.0, 0.0, 0.0],
            &[f64::INFINITY, 0.0, 0.0],
            1.0
        ));
    }

    #[test]
    fn inf_point_fail_closed() {
        assert!(point_in_sphere(
            &[f64::INFINITY, 0.0, 0.0],
            &[0.0, 0.0, 0.0],
            1.0
        ));
    }
}
