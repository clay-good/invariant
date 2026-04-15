// P5: Workspace boundary check

use crate::models::command::EndEffectorPosition;
use crate::models::profile::WorkspaceBounds;
use crate::models::verdict::CheckResult;

/// Check that every end-effector position lies within the workspace bounding volume.
///
/// Currently supports [`WorkspaceBounds::Aabb`]. For each end-effector, all three
/// coordinates must satisfy `min[i] <= position[i] <= max[i]`.
///
/// If `end_effectors` is empty the check fails — positions are required to verify workspace bounds.
pub fn check_workspace_bounds(
    end_effectors: &[EndEffectorPosition],
    workspace: &WorkspaceBounds,
) -> CheckResult {
    if end_effectors.is_empty() {
        return CheckResult {
            name: "workspace_bounds".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "end_effector_positions required for workspace bounds check".to_string(),
            derating: None,
        };
    }

    let mut violations: Vec<String> = Vec::new();

    match workspace {
        WorkspaceBounds::Aabb { min, max } => {
            // Guard: min[i] <= max[i] for all axes.  ValidatorConfig normally
            // rejects profiles that violate this, but check at runtime rather
            // than with debug_assert so the protection holds in release builds
            // too (Finding 47).
            if min[0] > max[0] || min[1] > max[1] || min[2] > max[2] {
                return CheckResult {
                    name: "workspace_bounds".to_string(),
                    category: "physics".to_string(),
                    passed: false,
                    details: format!(
                        "invalid AABB configuration: min {min:?} is not <= max {max:?} on all axes"
                    ),
                    derating: None,
                };
            }
            for ee in end_effectors {
                let p = &ee.position;
                if !p[0].is_finite() || !p[1].is_finite() || !p[2].is_finite() {
                    violations.push(format!(
                        "'{}': position contains NaN or infinite value",
                        ee.name
                    ));
                } else if p[0] < min[0]
                    || p[0] > max[0]
                    || p[1] < min[1]
                    || p[1] > max[1]
                    || p[2] < min[2]
                    || p[2] > max[2]
                {
                    violations.push(format!(
                        "'{}': position [{:.6}, {:.6}, {:.6}] outside AABB \
                         min [{:.6}, {:.6}, {:.6}] max [{:.6}, {:.6}, {:.6}]",
                        ee.name, p[0], p[1], p[2], min[0], min[1], min[2], max[0], max[1], max[2]
                    ));
                }
            }
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "workspace_bounds".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all end-effectors within workspace bounds".to_string(),
            derating: None,
        }
    } else {
        CheckResult {
            name: "workspace_bounds".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        }
    }
}
