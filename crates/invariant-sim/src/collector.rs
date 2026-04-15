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
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::collector::TraceCollector;
    ///
    /// // Create a collector for environment 0, episode 0 with 100 expected steps.
    /// let collector = TraceCollector::new(
    ///     "trace-abc123".to_string(),
    ///     0,   // episode
    ///     0,   // environment_id
    ///     "Baseline".to_string(),
    ///     "franka_panda".to_string(),
    ///     100, // expected_steps (hint for pre-allocation)
    /// );
    ///
    /// // A freshly created collector produces an empty trace.
    /// let trace = collector.finalize();
    /// assert_eq!(trace.id, "trace-abc123");
    /// assert_eq!(trace.episode, 0);
    /// assert_eq!(trace.environment_id, 0);
    /// assert_eq!(trace.scenario, "Baseline");
    /// assert_eq!(trace.profile_name, "franka_panda");
    /// assert!(trace.steps.is_empty());
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use chrono::Utc;
    /// use invariant_robotics_sim::collector::TraceCollector;
    /// use invariant_core::models::command::{Command, CommandAuthority, JointState};
    /// use invariant_core::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    ///
    /// let mut collector = TraceCollector::new(
    ///     "trace-1".to_string(),
    ///     0, 0, "Baseline".to_string(), "franka_panda".to_string(), 1,
    /// );
    ///
    /// let cmd = Command {
    ///     timestamp: Utc::now(),
    ///     source: "llm-agent".to_string(),
    ///     sequence: 0,
    ///     joint_states: vec![JointState {
    ///         name: "panda_joint1".to_string(),
    ///         position: 0.0,
    ///         velocity: 0.5,
    ///         effort: 10.0,
    ///     }],
    ///     delta_time: 0.01,
    ///     end_effector_positions: vec![],
    ///     center_of_mass: None,
    ///     authority: CommandAuthority {
    ///         pca_chain: String::new(),
    ///         required_ops: vec![],
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
    /// let verdict = SignedVerdict {
    ///     verdict: Verdict {
    ///         approved: true,
    ///         command_hash: "sha256:abc".to_string(),
    ///         command_sequence: 0,
    ///         timestamp: Utc::now(),
    ///         checks: vec![CheckResult {
    ///             name: "velocity".to_string(),
    ///             category: "physics".to_string(),
    ///             passed: true,
    ///             details: "within limits".to_string(),
    ///             derating: None,
    ///         }],
    ///         profile_name: "franka_panda".to_string(),
    ///         profile_hash: "sha256:def".to_string(),
    ///         threat_analysis: None,
    ///         authority_summary: AuthoritySummary {
    ///             origin_principal: "operator".to_string(),
    ///             hop_count: 1,
    ///             operations_granted: vec!["actuate:*".to_string()],
    ///             operations_required: vec!["actuate:panda_joint1".to_string()],
    ///         },
    ///     },
    ///     verdict_signature: "sig".to_string(),
    ///     signer_kid: "validator-key-1".to_string(),
    /// };
    ///
    /// collector.record_step(0, cmd, verdict);
    ///
    /// let trace = collector.finalize();
    /// assert_eq!(trace.steps.len(), 1);
    /// assert_eq!(trace.steps[0].step, 0);
    /// assert!(trace.steps[0].verdict.verdict.approved);
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::collector::TraceCollector;
    ///
    /// // An empty collector yields a trace with zero steps.
    /// let collector = TraceCollector::new(
    ///     "ep-trace".to_string(),
    ///     3,   // episode
    ///     7,   // environment_id
    ///     "ExclusionZone".to_string(),
    ///     "ur10".to_string(),
    ///     0,
    /// );
    ///
    /// let trace = collector.finalize();
    /// assert_eq!(trace.id, "ep-trace");
    /// assert_eq!(trace.episode, 3);
    /// assert_eq!(trace.environment_id, 7);
    /// assert_eq!(trace.scenario, "ExclusionZone");
    /// assert_eq!(trace.profile_name, "ur10");
    /// assert!(trace.steps.is_empty());
    /// assert!(trace.metadata.is_empty());
    /// ```
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
            signed_sensor_readings: vec![],
            zone_overrides: std::collections::HashMap::new(),
            environment_state: None,
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
                    derating: None,
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

    // =========================================================================
    // Per-profile collector tests
    // =========================================================================

    #[test]
    fn collector_for_franka_panda_profile() {
        let mut collector = TraceCollector::new(
            "panda-trace".into(),
            0,
            0,
            "Baseline".into(),
            "franka_panda".into(),
            10,
        );
        for i in 0..10u64 {
            collector.record_step(i, make_command(i), make_verdict(true, i));
        }
        let trace = collector.finalize();
        assert_eq!(trace.profile_name, "franka_panda");
        assert_eq!(trace.steps.len(), 10);
        for (i, step) in trace.steps.iter().enumerate() {
            assert_eq!(step.step, i as u64);
            assert!(step.verdict.verdict.approved);
        }
    }

    #[test]
    fn collector_for_ur10_profile() {
        let mut collector = TraceCollector::new(
            "ur10-trace".into(),
            5,
            2,
            "Aggressive".into(),
            "ur10".into(),
            8,
        );
        for i in 0..8u64 {
            collector.record_step(i, make_command(i + 100), make_verdict(i < 6, i));
        }
        let trace = collector.finalize();
        assert_eq!(trace.profile_name, "ur10");
        assert_eq!(trace.scenario, "Aggressive");
        assert_eq!(trace.episode, 5);
        assert_eq!(trace.environment_id, 2);
        assert_eq!(trace.steps.len(), 8);
        // First 6 approved, last 2 rejected
        assert!(trace.steps[5].verdict.verdict.approved);
        assert!(!trace.steps[6].verdict.verdict.approved);
        assert!(!trace.steps[7].verdict.verdict.approved);
    }

    #[test]
    fn collector_for_quadruped_profile() {
        let mut collector = TraceCollector::new(
            "quad-trace".into(),
            0,
            1,
            "LocomotionRunaway".into(),
            "quadruped_12dof".into(),
            20,
        );
        for i in 0..20u64 {
            collector.record_step(i, make_command(i), make_verdict(false, i));
        }
        let trace = collector.finalize();
        assert_eq!(trace.profile_name, "quadruped_12dof");
        assert_eq!(trace.scenario, "LocomotionRunaway");
        assert_eq!(trace.steps.len(), 20);
        for step in &trace.steps {
            assert!(!step.verdict.verdict.approved);
        }
    }

    #[test]
    fn collector_for_humanoid_profile() {
        let mut collector = TraceCollector::new(
            "humanoid-trace".into(),
            3,
            0,
            "LocomotionFall".into(),
            "humanoid_28dof".into(),
            15,
        );
        for i in 0..15u64 {
            collector.record_step(i, make_command(i), make_verdict(false, i));
        }
        let trace = collector.finalize();
        assert_eq!(trace.profile_name, "humanoid_28dof");
        assert_eq!(trace.scenario, "LocomotionFall");
        assert_eq!(trace.episode, 3);
        assert_eq!(trace.steps.len(), 15);
    }

    #[test]
    fn collector_for_ur10e_haas_cell_profile() {
        let mut collector = TraceCollector::new(
            "haas-trace".into(),
            0,
            0,
            "CncTending".into(),
            "ur10e_haas_cell".into(),
            6,
        );
        // CNC cycle: first 3 approved (zone disabled), last 3 rejected (zone active)
        for i in 0..3u64 {
            collector.record_step(i, make_command(i), make_verdict(true, i));
        }
        for i in 3..6u64 {
            collector.record_step(i, make_command(i), make_verdict(false, i));
        }
        let trace = collector.finalize();
        assert_eq!(trace.profile_name, "ur10e_haas_cell");
        assert_eq!(trace.scenario, "CncTending");
        assert_eq!(trace.steps.len(), 6);
        assert!(trace.steps[0].verdict.verdict.approved);
        assert!(trace.steps[2].verdict.verdict.approved);
        assert!(!trace.steps[3].verdict.verdict.approved);
        assert!(!trace.steps[5].verdict.verdict.approved);
    }

    // =========================================================================
    // Large-scale collector tests
    // =========================================================================

    #[test]
    fn collector_handles_large_step_count() {
        let mut collector = TraceCollector::new(
            "large-trace".into(),
            0,
            0,
            "Baseline".into(),
            "franka_panda".into(),
            1000,
        );
        for i in 0..1000u64 {
            collector.record_step(i, make_command(i), make_verdict(true, i));
        }
        let trace = collector.finalize();
        assert_eq!(trace.steps.len(), 1000);
        assert_eq!(trace.steps[0].step, 0);
        assert_eq!(trace.steps[999].step, 999);
    }

    #[test]
    fn collector_preserves_command_sequence_numbers() {
        let mut collector = TraceCollector::new(
            "seq-trace".into(),
            0,
            0,
            "Baseline".into(),
            "ur10".into(),
            5,
        );
        let seqs = [10u64, 20, 30, 40, 50];
        for (i, &seq) in seqs.iter().enumerate() {
            collector.record_step(i as u64, make_command(seq), make_verdict(true, seq));
        }
        let trace = collector.finalize();
        for (i, &expected_seq) in seqs.iter().enumerate() {
            assert_eq!(trace.steps[i].command.sequence, expected_seq);
        }
    }

    #[test]
    fn collector_step_indices_match() {
        let mut collector = TraceCollector::new(
            "idx-trace".into(),
            0,
            0,
            "Baseline".into(),
            "quadruped_12dof".into(),
            50,
        );
        for i in 0..50u64 {
            collector.record_step(i, make_command(i), make_verdict(i % 3 == 0, i));
        }
        let trace = collector.finalize();
        for (i, step) in trace.steps.iter().enumerate() {
            assert_eq!(step.step, i as u64, "step index mismatch at position {i}");
        }
    }

    #[test]
    fn collector_mixed_approval_pattern() {
        let mut collector = TraceCollector::new(
            "mixed-trace".into(),
            0,
            0,
            "ExclusionZone".into(),
            "humanoid_28dof".into(),
            10,
        );
        // Alternate approved/rejected
        for i in 0..10u64 {
            collector.record_step(i, make_command(i), make_verdict(i % 2 == 0, i));
        }
        let trace = collector.finalize();
        assert_eq!(trace.steps.len(), 10);
        let approved_count = trace
            .steps
            .iter()
            .filter(|s| s.verdict.verdict.approved)
            .count();
        let rejected_count = trace
            .steps
            .iter()
            .filter(|s| !s.verdict.verdict.approved)
            .count();
        assert_eq!(approved_count, 5);
        assert_eq!(rejected_count, 5);
    }

    #[test]
    fn collector_multi_environment_ids() {
        // Verify different environment IDs are preserved
        for env_id in 0..5u32 {
            let collector = TraceCollector::new(
                format!("env-{env_id}"),
                0,
                env_id,
                "Baseline".into(),
                "franka_panda".into(),
                0,
            );
            let trace = collector.finalize();
            assert_eq!(trace.environment_id, env_id);
        }
    }

    #[test]
    fn collector_multi_episode_ids() {
        for ep in 0..10u64 {
            let collector = TraceCollector::new(
                format!("ep-{ep}"),
                ep,
                0,
                "Baseline".into(),
                "ur10".into(),
                0,
            );
            let trace = collector.finalize();
            assert_eq!(trace.episode, ep);
        }
    }

    #[test]
    fn collector_all_scenarios_tracked() {
        let scenarios = [
            "Baseline",
            "Aggressive",
            "ExclusionZone",
            "AuthorityEscalation",
            "ChainForgery",
            "PromptInjection",
            "MultiAgentHandoff",
            "LocomotionRunaway",
            "LocomotionSlip",
            "LocomotionTrip",
            "LocomotionFall",
            "CncTending",
            "EnvironmentFault",
        ];
        for scenario in &scenarios {
            let collector = TraceCollector::new(
                format!("sc-{scenario}"),
                0,
                0,
                scenario.to_string(),
                "franka_panda".into(),
                0,
            );
            let trace = collector.finalize();
            assert_eq!(trace.scenario, *scenario);
        }
    }

    #[test]
    fn collector_all_five_profiles_tracked() {
        let profiles = [
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ];
        for profile in &profiles {
            let mut collector = TraceCollector::new(
                format!("prof-{profile}"),
                0,
                0,
                "Baseline".into(),
                profile.to_string(),
                3,
            );
            for i in 0..3u64 {
                collector.record_step(i, make_command(i), make_verdict(true, i));
            }
            let trace = collector.finalize();
            assert_eq!(trace.profile_name, *profile);
            assert_eq!(trace.steps.len(), 3);
        }
    }

    #[test]
    fn collector_verdict_check_results_preserved() {
        let mut collector = TraceCollector::new(
            "check-trace".into(),
            0,
            0,
            "Baseline".into(),
            "franka_panda".into(),
            1,
        );
        let verdict = make_verdict(true, 0);
        let check_name = verdict.verdict.checks[0].name.clone();
        collector.record_step(0, make_command(0), verdict);
        let trace = collector.finalize();
        assert_eq!(trace.steps[0].verdict.verdict.checks[0].name, check_name);
    }

    #[test]
    fn collector_timestamp_ordering() {
        let mut collector = TraceCollector::new(
            "time-trace".into(),
            0,
            0,
            "Baseline".into(),
            "franka_panda".into(),
            5,
        );
        for i in 0..5u64 {
            collector.record_step(i, make_command(i), make_verdict(true, i));
        }
        let trace = collector.finalize();
        // Timestamps should be non-decreasing (recorded sequentially)
        for w in trace.steps.windows(2) {
            assert!(
                w[1].timestamp >= w[0].timestamp,
                "timestamps must be non-decreasing"
            );
        }
    }
}
