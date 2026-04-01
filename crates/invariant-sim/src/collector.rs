// Trace collector: aggregates per-step results into a complete Trace.
//
// One `TraceCollector` is instantiated per environment per episode. Steps are
// appended via `record_step`, and `finalize` consumes the collector and
// returns a `Trace` suitable for replay or evaluation.

use chrono::Utc;
use invariant_core::models::command::Command;
use invariant_core::models::trace::{Trace, TraceStep};
use invariant_core::models::verdict::SignedVerdict;
use std::collections::HashMap;

/// Accumulates steps for a single simulation episode.
pub struct TraceCollector {
    trace_id: String,
    episode: u64,
    environment_id: u32,
    scenario: String,
    profile_name: String,
    steps: Vec<TraceStep>,
}

impl TraceCollector {
    /// Create a new collector for an episode.
    ///
    /// * `trace_id` -- globally unique trace identifier.
    /// * `episode` -- zero-based episode index within the environment.
    /// * `environment_id` -- environment index in the campaign.
    /// * `scenario` -- name of the scenario that generated this episode.
    /// * `profile_name` -- name of the robot profile in use.
    /// * `expected_steps` -- expected number of steps in this episode.
    ///   Used to pre-allocate the internal step buffer with
    ///   `Vec::with_capacity(expected_steps)` to avoid repeated reallocations.
    ///   Pass `0` if the count is unknown.
    pub fn new(
        trace_id: String,
        episode: u64,
        environment_id: u32,
        scenario: String,
        profile_name: String,
        expected_steps: usize,
    ) -> Self {
        TraceCollector {
            trace_id,
            episode,
            environment_id,
            scenario,
            profile_name,
            steps: Vec::with_capacity(expected_steps),
        }
    }

    /// Append a validated step to the trace.
    ///
    /// * `step`    – zero-based step index within the episode.
    /// * `command` – the command that was validated.
    /// * `verdict` – the signed verdict returned by the validator.
    pub fn record_step(&mut self, step: u64, command: Command, verdict: SignedVerdict) {
        self.steps.push(TraceStep {
            step,
            timestamp: Utc::now(),
            command,
            verdict,
            simulation_state: None,
        });
    }

    /// Consume the collector and produce a complete `Trace`.
    ///
    /// The returned trace contains all recorded steps in insertion order.
    pub fn finalize(self) -> Trace {
        Trace {
            id: self.trace_id,
            episode: self.episode,
            environment_id: self.environment_id,
            scenario: self.scenario,
            profile_name: self.profile_name,
            steps: self.steps,
            metadata: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};

    fn make_command(seq: u64) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: seq,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 0.5,
                effort: 5.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
        }
    }

    fn make_verdict(approved: bool, seq: u64) -> SignedVerdict {
        SignedVerdict {
            verdict: Verdict {
                approved,
                command_hash: format!("sha256:{:064x}", seq),
                command_sequence: seq,
                timestamp: Utc::now(),
                checks: vec![CheckResult {
                    name: "authority".into(),
                    category: "authority".into(),
                    passed: approved,
                    details: "ok".into(),
                }],
                profile_name: "test_robot".into(),
                profile_hash: "sha256:abc".into(),
                threat_analysis: None,
                authority_summary: AuthoritySummary {
                    origin_principal: "alice".into(),
                    hop_count: 1,
                    operations_granted: vec!["actuate:*".into()],
                    operations_required: vec!["actuate:j1".into()],
                },
            },
            verdict_signature: "sig".into(),
            signer_kid: "kid-1".into(),
        }
    }

    #[test]
    fn empty_collector_produces_empty_trace() {
        let collector = TraceCollector::new(
            "trace-1".into(),
            0,
            0,
            "Baseline".into(),
            "franka_panda".into(),
            0,
        );
        let trace = collector.finalize();
        assert_eq!(trace.id, "trace-1");
        assert_eq!(trace.episode, 0);
        assert_eq!(trace.environment_id, 0);
        assert_eq!(trace.scenario, "Baseline");
        assert_eq!(trace.profile_name, "franka_panda");
        assert!(trace.steps.is_empty());
        assert!(trace.metadata.is_empty());
    }

    #[test]
    fn record_steps_preserved_in_order() {
        let mut collector = TraceCollector::new(
            "trace-2".into(),
            1,
            3,
            "PositionViolation".into(),
            "ur10".into(),
            5,
        );

        for i in 0..5u64 {
            collector.record_step(i, make_command(i), make_verdict(i % 2 == 0, i));
        }

        let trace = collector.finalize();
        assert_eq!(trace.steps.len(), 5);
        for (i, step) in trace.steps.iter().enumerate() {
            assert_eq!(step.step, i as u64);
            assert_eq!(step.command.sequence, i as u64);
        }
    }

    #[test]
    fn verdict_approved_status_preserved() {
        let mut collector = TraceCollector::new(
            "trace-3".into(),
            0,
            0,
            "Baseline".into(),
            "franka_panda".into(),
            2,
        );
        collector.record_step(0, make_command(0), make_verdict(true, 0));
        collector.record_step(1, make_command(1), make_verdict(false, 1));

        let trace = collector.finalize();
        assert!(trace.steps[0].verdict.verdict.approved);
        assert!(!trace.steps[1].verdict.verdict.approved);
    }

    #[test]
    fn finalize_fields_match_constructor() {
        let collector = TraceCollector::new(
            "my-id".into(),
            42,
            7,
            "VelocityViolation".into(),
            "humanoid_28dof".into(),
            0,
        );
        let trace = collector.finalize();
        assert_eq!(trace.id, "my-id");
        assert_eq!(trace.episode, 42);
        assert_eq!(trace.environment_id, 7);
        assert_eq!(trace.scenario, "VelocityViolation");
        assert_eq!(trace.profile_name, "humanoid_28dof");
    }
}
