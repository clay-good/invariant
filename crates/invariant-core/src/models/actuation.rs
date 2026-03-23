use serde::{Deserialize, Serialize};

use super::command::JointState;

/// Produced only for APPROVED commands. The motor controller requires a valid
/// `actuation_signature` before executing any movement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedActuationCommand {
    pub command_hash: String,
    pub command_sequence: u64,
    pub joint_states: Vec<JointState>,
    pub timestamp: String,
    pub actuation_signature: String,
    pub signer_kid: String,
}
