//! Heartbeat monitor and safe-stop trigger.
//!
//! Preserves the timing + crypto behavior from `watchdog.rs` in
//! the sibling robotics project. The robotics-specific safe-stop payload (controlled
//! crouch etc.) is replaced by a generic `SafeStopAction` enum whose sole
//! bio variant is `SafeStopAction::HaltSynthesis`.
//!
//! The full timing logic is ported in Step 3; Step 0 only defines the
//! type shape so downstream crates can link.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A safe-stop action to execute when the watchdog times out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SafeStopAction {
    /// Halt all outstanding synthesis operations and quench the reaction bed.
    HaltSynthesis,
}

/// A single heartbeat sample from the firewall to the execution platform.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Monotonic sequence number of this heartbeat.
    pub sequence: u64,
    /// Timestamp the heartbeat was emitted.
    pub timestamp: DateTime<Utc>,
    /// Configured timeout in milliseconds — if the next heartbeat does not
    /// arrive within this window the platform must execute `on_timeout`.
    pub timeout_ms: u64,
    /// Action the platform must execute if this heartbeat is the last one.
    pub on_timeout: SafeStopAction,
    /// Base64-encoded Ed25519 signature over the canonical heartbeat JSON.
    pub signature: String,
    /// Key identifier of the signer.
    pub signer_kid: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_stop_halt_synthesis_serializes() {
        let v = serde_json::to_value(SafeStopAction::HaltSynthesis).unwrap();
        assert_eq!(v, serde_json::json!({"action": "halt_synthesis"}));
    }
}
