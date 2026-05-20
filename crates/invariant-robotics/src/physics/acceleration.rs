// P4: Joint acceleration limits check

use std::collections::{HashMap, HashSet};

use crate::models::command::JointState;
use crate::models::profile::{JointDefinition, RealWorldMargins};
use crate::models::verdict::CheckResult;

/// Check that every joint's estimated acceleration does not exceed `max_acceleration`.
///
/// Acceleration is estimated as `|v_new - v_old| / delta_time` where `v_old` comes
/// from `previous_joints`. When `previous_joints` is `None` (first command) the check
/// passes trivially — there is no prior velocity to difference against.
///
/// Each [`JointState`] in `joints` is matched to the corresponding previous state and
/// to a [`JointDefinition`] by name. A joint that exists in `joints` but has no
/// matching definition is a violation. A joint that exists in `joints` but has no
/// entry in `previous_joints` is skipped for that joint (treated as first observation).
///
/// # Panics
/// Does not panic. Division by zero is avoided: if `delta_time <= 0.0` the check
/// reports a violation for every joint that would have been evaluated, noting that
/// `delta_time` is non-positive.
/// When `margins` is `Some`, the limit is tightened by `acceleration_margin`:
/// effective_max_accel = max_acceleration * (1 - acceleration_margin).
pub fn check_acceleration_limits(
    joints: &[JointState],
    previous_joints: Option<&[JointState]>,
    definitions: &[JointDefinition],
    delta_time: f64,
    margins: Option<&RealWorldMargins>,
) -> CheckResult {
    // First command — no previous state to diff against; pass trivially.
    let Some(prev) = previous_joints else {
        return CheckResult {
            name: "acceleration_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "skipped on first command (no previous joint states)".to_string(),
            derating: None,
        };
    };

    // Non-finite or non-positive delta_time makes acceleration undefined; treat as violation.
    if !delta_time.is_finite() || delta_time <= 0.0 {
        return CheckResult {
            name: "acceleration_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "delta_time {:.6} is non-positive; acceleration is undefined",
                delta_time
            ),
            derating: None,
        };
    }

    let def_map: HashMap<&str, &JointDefinition> =
        definitions.iter().map(|d| (d.name.as_str(), d)).collect();
    let prev_map: HashMap<&str, &JointState> = prev.iter().map(|p| (p.name.as_str(), p)).collect();

    // Build a set of current joint names for O(1) lookup in the vanishing-joint
    // check below.
    let current_names: HashSet<&str> = joints.iter().map(|s| s.name.as_str()).collect();

    let mut violations: Vec<String> = Vec::new();

    for state in joints {
        // Unknown joint — cannot evaluate; report as violation.
        let Some(def) = def_map.get(state.name.as_str()) else {
            violations.push(format!(
                "'{}': unknown joint (no definition found)",
                state.name
            ));
            continue;
        };

        // No previous entry for this joint — flag as violation.
        let Some(prev_state) = prev_map.get(state.name.as_str()) else {
            violations.push(format!(
                "'{}': no previous joint state (cannot compute acceleration)",
                state.name
            ));
            continue;
        };

        // Reject non-finite velocities.
        if !state.velocity.is_finite() || !prev_state.velocity.is_finite() {
            violations.push(format!("'{}': velocity is NaN or infinite", state.name));
            continue;
        }

        let margin_factor = 1.0 - margins.map(|m| m.acceleration_margin).unwrap_or(0.0);
        let limit = def.max_acceleration * margin_factor;
        let accel = (state.velocity - prev_state.velocity).abs() / delta_time;
        if accel > limit {
            violations.push(format!(
                "'{}': acceleration {:.6} exceeds max_acceleration {:.6}",
                state.name, accel, limit
            ));
        }
    }

    // Check for joints that were present in the previous command but have
    // vanished from the current one. A vanishing joint cannot be checked for
    // acceleration compliance and may indicate a dropped or malformed command.
    for prev_state in prev {
        if !current_names.contains(prev_state.name.as_str()) {
            violations.push(format!(
                "'{}': joint was present in previous command but is absent from current command",
                prev_state.name
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "acceleration_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all joints within acceleration limits".to_string(),
            derating: None,
        }
    } else {
        CheckResult {
            name: "acceleration_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        }
    }
}
