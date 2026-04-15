// P3: Joint torque limits check

use std::collections::HashMap;

use crate::models::command::JointState;
use crate::models::profile::{JointDefinition, RealWorldMargins};
use crate::models::verdict::CheckResult;

/// Check that every joint's effort (torque) magnitude does not exceed
/// `max_torque * (1 - torque_margin)`.
///
/// When `margins` is `Some`, the limit is tightened by `torque_margin`.
///
/// Each [`JointState`] is matched to a [`JointDefinition`] by name.
/// A joint state with no matching definition is treated as a violation.
/// If `joints` is empty the check passes trivially.
pub fn check_torque_limits(
    joints: &[JointState],
    definitions: &[JointDefinition],
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
                let margin_factor = 1.0 - margins.map(|m| m.torque_margin).unwrap_or(0.0);
                let limit = def.max_torque * margin_factor;
                if !state.effort.is_finite() {
                    violations.push(format!("'{}': effort is NaN or infinite", state.name));
                } else if state.effort.abs() > limit {
                    violations.push(format!(
                        "'{}': |effort| {:.6} exceeds max_torque {:.6}",
                        state.name,
                        state.effort.abs(),
                        limit
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
            derating: None,
        }
    } else {
        CheckResult {
            name: "torque_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        }
    }
}
