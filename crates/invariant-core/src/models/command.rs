use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::authority::Operation;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Command {
    /// ISO 8601 / RFC 3339 timestamp. Typed as `DateTime<Utc>` to support
    /// replay-prevention logic (exp/nbf ordering) (P1-3).
    pub timestamp: DateTime<Utc>,
    pub source: String,
    /// Monotonic sequence number. Out-of-order or duplicate commands are rejected.
    pub sequence: u64,
    pub joint_states: Vec<JointState>,
    pub delta_time: f64,
    #[serde(default)]
    pub end_effector_positions: Vec<EndEffectorPosition>,
    #[serde(default)]
    pub center_of_mass: Option<[f64; 3]>,
    pub authority: CommandAuthority,
    /// Flat key-value metadata. Only `String` values are accepted to prevent
    /// deeply-nested JSON objects from causing stack-overflow DoS (P1-1).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JointState {
    pub name: String,
    pub position: f64,
    pub velocity: f64,
    pub effort: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndEffectorPosition {
    pub name: String,
    pub position: [f64; 3],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandAuthority {
    /// Base64-encoded COSE_Sign1 PCA chain.
    pub pca_chain: String,
    /// Operations this command requires. Validated against the decoded chain's final_ops.
    pub required_ops: Vec<Operation>,
}
