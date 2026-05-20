// P2: Joint velocity limits check

use std::collections::HashMap;

use crate::models::command::JointState;
use crate::models::profile::{JointDefinition, RealWorldMargins};
use crate::models::verdict::CheckResult;

/// Check that every joint's velocity magnitude does not exceed
/// `max_velocity * global_velocity_scale * (1 - velocity_margin)`.
///
/// When `margins` is `Some`, the limit is tightened by `velocity_margin`.
///
/// Each [`JointState`] is matched to a [`JointDefinition`] by name.
/// A joint state with no matching definition is treated as a violation.
/// If `joints` is empty the check passes trivially.
pub fn check_velocity_limits(
    joints: &[JointState],
    definitions: &[JointDefinition],
    global_velocity_scale: f64,
    margins: Option<&RealWorldMargins>,
) -> CheckResult {
    let def_map: HashMap<&str, &JointDefinition> =
        definitions.iter().map(|d| (d.name.as_str(), d)).collect();

    let mut violations: Vec<String> = Vec::new();

    for state in joints {
        match def_map.get(state.name.as_str()) {
            None => {
                violations.push(format!(
                    "'{}': unknown joint (no definition found)",
                    state.name
                ));
            }
            Some(def) => {
                let margin_factor = 1.0 - margins.map(|m| m.velocity_margin).unwrap_or(0.0);
                let limit = def.max_velocity * global_velocity_scale * margin_factor;
                if !state.velocity.is_finite() {
                    violations.push(format!("'{}': velocity is NaN or infinite", state.name));
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
            derating: None,
        }
    } else {
        CheckResult {
            name: "velocity_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        }
    }
}
