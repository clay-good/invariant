use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::command::JointState;

/// Produced only for APPROVED commands. The motor controller requires a valid
/// `actuation_signature` before executing any movement (M1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedActuationCommand {
    /// SHA-256 hash of the command this actuation command authorizes.
    pub command_hash: String,
    /// Monotonic sequence number copied from the approved command.
    pub command_sequence: u64,
    /// Joint states the motor controller should execute.
    pub joint_states: Vec<JointState>,
    /// Typed timestamp (P1-3).
    pub timestamp: DateTime<Utc>,
    /// Base64-encoded Ed25519 signature over the canonical actuation payload.
    pub actuation_signature: String,
    /// Key identifier of the signing key.
    pub signer_kid: String,
}
