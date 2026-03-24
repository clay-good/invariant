// P5: Workspace boundary check

use crate::models::command::EndEffectorPosition;
use crate::models::profile::WorkspaceBounds;
use crate::models::verdict::CheckResult;

/// Check that every end-effector position lies within the workspace bounding volume.
///
/// Currently supports [`WorkspaceBounds::Aabb`]. For each end-effector, all three
/// coordinates must satisfy `min[i] <= position[i] <= max[i]`.
///
/// If `end_effectors` is empty the check passes trivially — there is nothing to verify.
pub fn check_workspace_bounds(
    end_effectors: &[EndEffectorPosition],
    workspace: &WorkspaceBounds,
) -> CheckResult {
    if end_effectors.is_empty() {
        return CheckResult {
            name: "workspace_bounds".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no end-effectors to check".to_string(),
        };
    }

    let mut violations: Vec<String> = Vec::new();

    match workspace {
        WorkspaceBounds::Aabb { min, max } => {
            for ee in end_effectors {
                let p = &ee.position;
                if !p[0].is_finite() || !p[1].is_finite() || !p[2].is_finite() {
                    violations.push(format!(
                        "'{}': position contains NaN or infinite value",
                        ee.name
                    ));
                } else if p[0] < min[0] || p[0] > max[0]
                    || p[1] < min[1] || p[1] > max[1]
                    || p[2] < min[2] || p[2] > max[2]
                {
                    violations.push(format!(
                        "'{}': position [{:.6}, {:.6}, {:.6}] outside AABB \
                         min [{:.6}, {:.6}, {:.6}] max [{:.6}, {:.6}, {:.6}]",
                        ee.name,
                        p[0], p[1], p[2],
                        min[0], min[1], min[2],
                        max[0], max[1], max[2]
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
        }
    } else {
        CheckResult {
            name: "workspace_bounds".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
    }
}
