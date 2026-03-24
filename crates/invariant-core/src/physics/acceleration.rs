// P4: Joint acceleration limits check

use crate::models::command::JointState;
use crate::models::profile::JointDefinition;
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
pub fn check_acceleration_limits(
    joints: &[JointState],
    previous_joints: Option<&[JointState]>,
    definitions: &[JointDefinition],
    delta_time: f64,
) -> CheckResult {
    // First command — no previous state to diff against; pass trivially.
    let Some(prev) = previous_joints else {
        return CheckResult {
            name: "acceleration_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "skipped on first command (no previous joint states)".to_string(),
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
        };
    }

    let mut violations: Vec<String> = Vec::new();

    for state in joints {
        // Unknown joint — cannot evaluate; report as violation.
        let Some(def) = definitions.iter().find(|d| d.name == state.name) else {
            violations.push(format!(
                "'{}': unknown joint (no definition found)",
                state.name
            ));
            continue;
        };

        // No previous entry for this joint — flag as violation.
        let Some(prev_state) = prev.iter().find(|p| p.name == state.name) else {
            violations.push(format!(
                "'{}': no previous joint state (cannot compute acceleration)",
                state.name
            ));
            continue;
        };

        // Reject non-finite velocities.
        if !state.velocity.is_finite() || !prev_state.velocity.is_finite() {
            violations.push(format!(
                "'{}': velocity is NaN or infinite",
                state.name
            ));
            continue;
        }

        let accel = (state.velocity - prev_state.velocity).abs() / delta_time;
        if accel > def.max_acceleration {
            violations.push(format!(
                "'{}': acceleration {:.6} exceeds max_acceleration {:.6}",
                state.name, accel, def.max_acceleration
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "acceleration_limits".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "all joints within acceleration limits".to_string(),
        }
    } else {
        CheckResult {
            name: "acceleration_limits".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
    }
}
