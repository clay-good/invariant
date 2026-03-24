// P2: Joint velocity limits check

use crate::models::command::JointState;
use crate::models::profile::JointDefinition;
use crate::models::verdict::CheckResult;

/// Check that every joint's velocity magnitude does not exceed
/// `max_velocity * global_velocity_scale`.
///
/// Each [`JointState`] is matched to a [`JointDefinition`] by name.
/// A joint state with no matching definition is treated as a violation.
/// If `joints` is empty the check passes trivially.
pub fn check_velocity_limits(
    joints: &[JointState],
    definitions: &[JointDefinition],
    global_velocity_scale: f64,
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
                let limit = def.max_velocity * global_velocity_scale;
                if !state.velocity.is_finite() {
                    violations.push(format!(
                        "'{}': velocity is NaN or infinite",
                        state.name
                    ));
                } else if state.velocity.abs() > limit {
                    violations.push(format!(
                        "'{}': |velocity| {:.6} exceeds limit {:.6} (max_velocity {:.6} * scale {:.6})",
                        state.name,
                        state.velocity.abs(),
                        limit,
                        def.max_velocity,
                        global_velocity_scale
                    ));
                }
            }
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "velocity_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all joints within velocity limits".to_string(),
        }
    } else {
        CheckResult {
            name: "velocity_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
    }
}
