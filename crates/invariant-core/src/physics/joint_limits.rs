// P1: Joint position limits check

use crate::models::command::JointState;
use crate::models::profile::JointDefinition;
use crate::models::verdict::CheckResult;

/// Check that every joint's position falls within its defined `[min, max]` range.
///
/// Each [`JointState`] in `joints` is matched to a [`JointDefinition`] by name.
/// A joint state with no matching definition is treated as a violation (unknown joint).
/// If `joints` is empty the check passes trivially.
pub fn check_joint_limits(
    joints: &[JointState],
    definitions: &[JointDefinition],
) -> CheckResult {
    let mut violations: Vec<String> = Vec::new();

    for state in joints {
        match definitions.iter().find(|d| d.name == state.name) {
            None => {
                violations.push(format!(
                    "'{}': unknown joint (no definition found)",
                    state.name
                ));
            }
            Some(def) => {
                if !state.position.is_finite() {
                    violations.push(format!(
                        "'{}': position is NaN or infinite",
                        state.name
                    ));
                } else if state.position < def.min || state.position > def.max {
                    violations.push(format!(
                        "'{}': position {:.6} outside [{:.6}, {:.6}]",
                        state.name, state.position, def.min, def.max
                    ));
                }
            }
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "joint_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all joints within limits".to_string(),
        }
    } else {
        CheckResult {
            name: "joint_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
    }
}
