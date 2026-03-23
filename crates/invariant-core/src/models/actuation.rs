use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::command::JointState;

/// Produced only for APPROVED commands. The motor controller requires a valid
/// `actuation_signature` before executing any movement (M1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedActuationCommand {
    pub command_hash: String,
    pub command_sequence: u64,
    pub joint_states: Vec<JointState>,
    /// Typed timestamp (P1-3).
    pub timestamp: DateTime<Utc>,
    pub actuation_signature: String,
    pub signer_kid: String,
}
