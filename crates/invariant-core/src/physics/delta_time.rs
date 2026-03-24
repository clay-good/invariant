// P8: Time step bounds check

use crate::models::verdict::CheckResult;

/// Check that `delta_time` satisfies `0 < delta_time <= max_delta_time`.
///
/// A zero or negative time step is physically meaningless and indicates a
/// clock error or command replay.  A step exceeding `max_delta_time` may cause
/// the controller to integrate beyond its stability margin.
pub fn check_delta_time(delta_time: f64, max_delta_time: f64) -> CheckResult {
    if !delta_time.is_finite() || delta_time <= 0.0 {
        return CheckResult {
            name: "delta_time".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "delta_time {} is not finite and positive (must be > 0)",
                delta_time
            ),
        };
    }

    if !max_delta_time.is_finite() || delta_time > max_delta_time {
        return CheckResult {
            name: "delta_time".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: format!(
                "delta_time {:.9} s exceeds max_delta_time {:.9} s",
                delta_time, max_delta_time
            ),
        };
    }

    CheckResult {
        name: "delta_time".to_string(),
        category: "physics".to_string(),
        passed: true,
        details: format!("delta_time {:.9} s within bounds", delta_time),
    }
}
