use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub timestamp: String,
    pub source: String,
    pub sequence: u64,
    pub joint_states: Vec<JointState>,
    pub delta_time: f64,
    #[serde(default)]
    pub end_effector_positions: Vec<EndEffectorPosition>,
    #[serde(default)]
    pub center_of_mass: Option<[f64; 3]>,
    pub authority: CommandAuthority,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointState {
    pub name: String,
    pub position: f64,
    pub velocity: f64,
    pub effort: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndEffectorPosition {
    pub name: String,
    pub position: [f64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAuthority {
    pub pca_chain: String,
    pub required_ops: Vec<String>,
}
