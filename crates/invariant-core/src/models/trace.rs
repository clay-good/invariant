use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An agent-replay compatible trace file. One per simulation environment per episode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub id: String,
    pub episode: u64,
    pub environment_id: u32,
    pub scenario: String,
    pub profile_name: String,
    pub steps: Vec<TraceStep>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    pub step: u64,
    pub timestamp: String,
    pub command: serde_json::Value,
    pub verdict: serde_json::Value,
    pub simulation_state: Option<serde_json::Value>,
}
