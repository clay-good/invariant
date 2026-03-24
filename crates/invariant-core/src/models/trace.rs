use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{command::Command, verdict::SignedVerdict};

/// An agent-replay compatible trace file. One per simulation environment per episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    pub id: String,
    pub episode: u64,
    pub environment_id: u32,
    pub scenario: String,
    pub profile_name: String,
    pub steps: Vec<TraceStep>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// A single step in a simulation trace.
///
/// Both `command` and `verdict` are typed (P2-7): storing them as `serde_json::Value`
/// would allow malformed traces to deserialise silently and require double-
/// deserialisation in the eval engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceStep {
    pub step: u64,
    /// Typed timestamp (P1-3).
    pub timestamp: DateTime<Utc>,
    pub command: Command,
    pub verdict: SignedVerdict,
    pub simulation_state: Option<serde_json::Value>,
}
