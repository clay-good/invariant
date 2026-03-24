// P3: Joint torque limits check

use crate::models::command::JointState;
use crate::models::profile::JointDefinition;
use crate::models::verdict::CheckResult;

/// Check that every joint's effort (torque) magnitude does not exceed `max_torque`.
///
/// Each [`JointState`] is matched to a [`JointDefinition`] by name.
/// A joint state with no matching definition is treated as a violation.
/// If `joints` is empty the check passes trivially.
pub fn check_torque_limits(
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
                if !state.effort.is_finite() {
                    violations.push(format!(
                        "'{}': effort is NaN or infinite",
                        state.name
                    ));
                } else if state.effort.abs() > def.max_torque {
                    violations.push(format!(
                        "'{}': |effort| {:.6} exceeds max_torque {:.6}",
                        state.name,
                        state.effort.abs(),
                        def.max_torque
                    ));
                }
            }
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "torque_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all joints within torque limits".to_string(),
        }
    } else {
        CheckResult {
            name: "torque_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
    }
}
