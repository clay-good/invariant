use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{command::Command, verdict::SignedVerdict};

/// An agent-replay compatible trace file. One per simulation environment per episode.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use invariant_robotics_core::models::trace::Trace;
///
/// let trace = Trace {
///     id: "trace-abc123".into(),
///     episode: 42,
///     environment_id: 7,
///     scenario: "pick_and_place".into(),
///     profile_name: "ur10e".into(),
///     steps: vec![],
///     metadata: HashMap::new(),
/// };
///
/// assert_eq!(trace.id, "trace-abc123");
/// assert_eq!(trace.episode, 42);
/// assert!(trace.steps.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    /// Unique trace identifier (UUID or content hash).
    pub id: String,
    /// Episode number within the simulation run.
    pub episode: u64,
    /// Simulation environment instance identifier.
    pub environment_id: u32,
    /// Scenario name (e.g. "pick_and_place", "door_operation").
    pub scenario: String,
    /// Robot profile name used for this trace.
    pub profile_name: String,
    /// Ordered sequence of command/verdict pairs.
    pub steps: Vec<TraceStep>,
    /// Arbitrary key/value metadata (scenario params, sim version, etc.).
    pub metadata: HashMap<String, serde_json::Value>,
}

/// A single step in a simulation trace.
///
/// Both `command` and `verdict` are typed (P2-7): storing them as `serde_json::Value`
/// would allow malformed traces to deserialise silently and require double-
/// deserialisation in the eval engine.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use invariant_robotics_core::models::trace::TraceStep;
/// use invariant_robotics_core::models::command::{Command, CommandAuthority, JointState};
/// use invariant_robotics_core::models::verdict::{SignedVerdict, Verdict, CheckResult, AuthoritySummary};
/// use invariant_robotics_core::models::authority::Operation;
///
/// let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
///     .unwrap()
///     .with_timezone(&chrono::Utc);
///
/// let cmd = Command {
///     timestamp: ts,
///     source: "sim".into(),
///     sequence: 0,
///     joint_states: vec![JointState { name: "shoulder_pan".into(), position: 0.0, velocity: 0.0, effort: 0.0 }],
///     delta_time: 0.02,
///     end_effector_positions: vec![],
///     center_of_mass: None,
///     authority: CommandAuthority {
///         pca_chain: "chain".into(),
///         required_ops: vec![Operation::new("actuate:arm:*").unwrap()],
///     },
///     metadata: HashMap::new(),
///     locomotion_state: None,
///     end_effector_forces: vec![],
///     estimated_payload_kg: None,
///     signed_sensor_readings: vec![],
///     zone_overrides: HashMap::new(),
///     environment_state: None,
/// };
///
/// let verdict = Verdict {
///     approved: true,
///     command_hash: "sha256:abc".into(),
///     command_sequence: 0,
///     timestamp: ts,
///     checks: vec![CheckResult::new("velocity", "physics", true, "ok")],
///     profile_name: "ur10e".into(),
///     profile_hash: "sha256:profile".into(),
///     authority_summary: AuthoritySummary {
///         origin_principal: "op@example.com".into(),
///         hop_count: 1,
///         operations_granted: vec!["actuate:arm:*".into()],
///         operations_required: vec!["actuate:arm:*".into()],
///     },
///     threat_analysis: None,
/// };
///
/// let step = TraceStep {
///     step: 0,
///     timestamp: ts,
///     command: cmd,
///     verdict: SignedVerdict { verdict, verdict_signature: "sig".into(), signer_kid: "kid".into() },
///     simulation_state: None,
/// };
///
/// assert_eq!(step.step, 0);
/// assert!(step.verdict.verdict.approved);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceStep {
    /// Zero-based step index within the trace.
    pub step: u64,
    /// Typed timestamp (P1-3).
    pub timestamp: DateTime<Utc>,
    /// The robot motion command submitted at this step.
    pub command: Command,
    /// The signed verdict produced by the validator for this command.
    pub verdict: SignedVerdict,
    /// Optional simulator state snapshot for replay and debugging.
    pub simulation_state: Option<serde_json::Value>,
}
