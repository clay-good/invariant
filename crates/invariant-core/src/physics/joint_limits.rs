// P1: Joint position limits check

use std::collections::HashMap;

use crate::models::command::JointState;
use crate::models::profile::{JointDefinition, RealWorldMargins};
use crate::models::verdict::CheckResult;

/// Check that every joint's position falls within its defined `[min, max]` range.
///
/// When `margins` is `Some`, the range is tightened by `position_margin`:
/// effective_min = min + margin * range, effective_max = max - margin * range.
/// This implements the Guardian mode conservative limits from Section 18.2.
///
/// Each [`JointState`] in `joints` is matched to a [`JointDefinition`] by name.
/// A joint state with no matching definition is treated as a violation (unknown joint).
/// If `joints` is empty the check passes trivially.
pub fn check_joint_limits(
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
                let margin_frac = margins.map(|m| m.position_margin).unwrap_or(0.0);
                let range = def.max - def.min;
                let effective_min = def.min + margin_frac * range;
                let effective_max = def.max - margin_frac * range;
                if !state.position.is_finite() {
                    violations.push(format!("'{}': position is NaN or infinite", state.name));
                } else if state.position < effective_min || state.position > effective_max {
                    violations.push(format!(
                        "'{}': position {:.6} outside [{:.6}, {:.6}]",
                        state.name, state.position, effective_min, effective_max
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
