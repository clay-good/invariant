// Trace diff with step-by-step divergence detection

use invariant_core::models::trace::Trace;

/// A single divergence between two traces.
///
/// # Examples
///
/// ```
/// use invariant_robotics_eval::differ::TraceDiff;
///
/// // TraceDiff can be constructed directly for testing or reporting.
/// let diff = TraceDiff {
///     step: 5,
///     field: "approved",
///     baseline: "true".into(),
///     candidate: "false".into(),
/// };
///
/// assert_eq!(diff.step, 5);
/// assert_eq!(diff.field, "approved");
/// assert_eq!(diff.baseline, "true");
/// assert_eq!(diff.candidate, "false");
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TraceDiff {
    /// The step index at which the divergence was detected.
    pub step: u64,
    /// The name of the diverging field. Always a static string literal —
    /// `diff_traces` only ever produces a fixed set of field names
    /// (`"approved"`, `"check_result"`, `"trace_length"`).
    pub field: &'static str,
    /// The value of the diverging field in the baseline trace.
    pub baseline: String,
    /// The value of the diverging field in the candidate trace.
    pub candidate: String,
}

/// Compare two traces and return divergences.
///
/// The function compares the overlapping steps of `baseline` and `candidate`
/// step-by-step.  For each shared step index it checks:
///
/// 1. Whether the top-level `approved` verdict differs.
/// 2. Whether any individual check result (`passed`) diverges between the two
///    traces for checks that share the same name.
///
/// After the shared prefix a length mismatch is reported as a single extra
/// `TraceDiff` entry.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use invariant_robotics_eval::differ::diff_traces;
/// use invariant_core::models::trace::{Trace, TraceStep};
/// use invariant_core::models::command::{Command, CommandAuthority, JointState};
/// use invariant_core::models::verdict::{SignedVerdict, Verdict, CheckResult, AuthoritySummary};
///
/// let ts = chrono::DateTime::parse_from_rfc3339("2024-06-01T12:00:00Z")
///     .unwrap()
///     .with_timezone(&chrono::Utc);
///
/// let make_step = |seq: u64, approved: bool| -> TraceStep {
///     let cmd = Command {
///         timestamp: ts, source: "robot-arm".into(), sequence: seq,
///         joint_states: vec![JointState { name: "shoulder".into(), position: 0.5,
///                                         velocity: 0.1, effort: 2.0 }],
///         delta_time: 0.02, end_effector_positions: vec![], center_of_mass: None,
///         authority: CommandAuthority { pca_chain: String::new(), required_ops: vec![] },
///         metadata: HashMap::new(), locomotion_state: None,
///         end_effector_forces: vec![], estimated_payload_kg: None,
///         signed_sensor_readings: vec![], zone_overrides: HashMap::new(),
///         environment_state: None,
///     };
///     let verdict = SignedVerdict {
///         verdict: Verdict {
///             approved,
///             command_hash: "hash".into(), command_sequence: seq, timestamp: ts,
///             checks: vec![CheckResult::new("authority", "authority", true, "ok")],
///             profile_name: "ur10e".into(), profile_hash: "phash".into(),
///             threat_analysis: None,
///             authority_summary: AuthoritySummary {
///                 origin_principal: "operator".into(), hop_count: 1,
///                 operations_granted: vec![], operations_required: vec![],
///             },
///         },
///         verdict_signature: "sig".into(), signer_kid: "kid".into(),
///     };
///     TraceStep { step: seq, timestamp: ts, command: cmd, verdict, simulation_state: None }
/// };
///
/// let make_trace = |steps: Vec<TraceStep>| Trace {
///     id: "trace-A".into(), episode: 0, environment_id: 0,
///     scenario: "welding-cycle".into(), profile_name: "ur10e".into(),
///     steps, metadata: HashMap::new(),
/// };
///
/// // Identical approval decisions produce no diffs.
/// let baseline  = make_trace(vec![make_step(0, true), make_step(1, true)]);
/// let candidate = make_trace(vec![make_step(0, true), make_step(1, true)]);
/// assert!(diff_traces(&baseline, &candidate).is_empty());
///
/// // A single approval flip is detected.
/// let divergent = make_trace(vec![make_step(0, true), make_step(1, false)]);
/// let diffs = diff_traces(&baseline, &divergent);
/// assert_eq!(diffs.len(), 1);
/// assert_eq!(diffs[0].step, 1);
/// assert_eq!(diffs[0].field, "approved");
///
/// // Different trace lengths produce a trace_length diff.
/// let shorter = make_trace(vec![make_step(0, true)]);
/// let len_diffs = diff_traces(&baseline, &shorter);
/// assert!(len_diffs.iter().any(|d| d.field == "trace_length"));
/// ```
pub fn diff_traces(baseline: &Trace, candidate: &Trace) -> Vec<TraceDiff> {
    let mut diffs = Vec::new();
    let min_len = baseline.steps.len().min(candidate.steps.len());

    for i in 0..min_len {
        let b = &baseline.steps[i];
        let c = &candidate.steps[i];
        if b.verdict.verdict.approved != c.verdict.verdict.approved {
            diffs.push(TraceDiff {
                step: b.step,
                field: "approved",
                baseline: b.verdict.verdict.approved.to_string(),
                candidate: c.verdict.verdict.approved.to_string(),
            });
        }

        // Compare per-check results for checks that share the same name.
        for base_check in &b.verdict.verdict.checks {
            if let Some(cand_check) = c
                .verdict
                .verdict
                .checks
                .iter()
                .find(|cc| cc.name == base_check.name)
            {
                if base_check.passed != cand_check.passed {
                    diffs.push(TraceDiff {
                        step: b.step,
                        field: "check_result",
                        baseline: format!("{}={}", base_check.name, base_check.passed),
                        candidate: format!("{}={}", cand_check.name, cand_check.passed),
                    });
                }
            }
        }
    }

    // Report length mismatches as a single trailing entry.
    if baseline.steps.len() != candidate.steps.len() {
        diffs.push(TraceDiff {
            step: min_len as u64,
            field: "trace_length",
            baseline: baseline.steps.len().to_string(),
            candidate: candidate.steps.len().to_string(),
        });
    }

    diffs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::models::trace::{Trace, TraceStep};
    use invariant_core::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use std::collections::HashMap;

    /// Returns a fixed, deterministic UTC timestamp for use in tests.
    ///
    /// Using a constant avoids non-determinism from `Utc::now()` and makes
    /// timestamp-ordering tests reproducible across runs.
    fn fixed_ts() -> chrono::DateTime<Utc> {
        // 2023-11-14 22:13:20 UTC — an arbitrary but stable reference point.
        Utc.timestamp_opt(1_700_000_000, 0).unwrap()
    }

    fn make_verdict(approved: bool) -> SignedVerdict {
        SignedVerdict {
            verdict: Verdict {
                approved,
                command_hash: "hash".into(),
                command_sequence: 0,
                timestamp: fixed_ts(),
                checks: vec![CheckResult {
                    name: "authority".into(),
                    category: "authority".into(),
                    passed: approved,
                    details: "ok".into(),
                    derating: None,
                }],
                profile_name: "test".into(),
                profile_hash: "hash".into(),
                threat_analysis: None,
                authority_summary: AuthoritySummary {
                    origin_principal: "op".into(),
                    hop_count: 1,
                    operations_granted: vec!["actuate:*".into()],
                    operations_required: vec!["actuate:j1".into()],
                },
            },
            verdict_signature: "sig".into(),
            signer_kid: "kid".into(),
        }
    }

    fn make_command() -> Command {
        Command {
            timestamp: fixed_ts(),
            source: "test".into(),
            sequence: 0,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: "".into(),
                required_ops: vec![],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        }
    }

    fn make_step(step: u64, approved: bool) -> TraceStep {
        TraceStep {
            step,
            timestamp: fixed_ts(),
            command: make_command(),
            verdict: make_verdict(approved),
            simulation_state: None,
        }
    }

    fn make_trace(steps: Vec<TraceStep>) -> Trace {
        Trace {
            id: "t".into(),
            episode: 0,
            environment_id: 0,
            scenario: "test".into(),
            profile_name: "test".into(),
            steps,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn identical_traces_produce_no_diffs() {
        let baseline = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let candidate = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let diffs = diff_traces(&baseline, &candidate);
        assert!(diffs.is_empty(), "expected no diffs, got {:?}", diffs);
    }

    #[test]
    fn single_step_divergence_is_detected() {
        let baseline = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let candidate = make_trace(vec![make_step(0, true), make_step(1, false)]);
        let diffs = diff_traces(&baseline, &candidate);
        // Step 1 diverges on both approved and the per-check result.
        assert!(
            !diffs.is_empty(),
            "expected at least one diff, got: {diffs:?}"
        );
        assert_eq!(diffs[0].step, 1);
        assert_eq!(diffs[0].field, "approved");
        assert_eq!(diffs[0].baseline, "true");
        assert_eq!(diffs[0].candidate, "false");
        // The authority check also diverges (passed tracks approved in test helper).
        let check_diffs: Vec<_> = diffs.iter().filter(|d| d.field == "check_result").collect();
        assert_eq!(check_diffs.len(), 1);
        assert!(check_diffs[0].baseline.contains("authority=true"));
        assert!(check_diffs[0].candidate.contains("authority=false"));
    }

    #[test]
    fn unequal_length_reports_trace_length_diff() {
        let baseline = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let candidate = make_trace(vec![make_step(0, true)]);
        let diffs = diff_traces(&baseline, &candidate);

        let len_diff = diffs
            .iter()
            .find(|d| d.field == "trace_length")
            .expect("expected a trace_length diff");
        assert_eq!(len_diff.baseline, "2");
        assert_eq!(len_diff.candidate, "1");
    }

    #[test]
    fn empty_vs_non_empty_reports_only_length_diff() {
        let baseline = make_trace(vec![]);
        let candidate = make_trace(vec![make_step(0, true)]);
        let diffs = diff_traces(&baseline, &candidate);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field, "trace_length");
    }

    #[test]
    fn both_empty_traces_produce_no_diffs() {
        let baseline = make_trace(vec![]);
        let candidate = make_trace(vec![]);
        let diffs = diff_traces(&baseline, &candidate);
        assert!(diffs.is_empty());
    }

    /// Per-check divergences are detected even when the top-level `approved`
    /// flag matches on both sides.
    #[test]
    fn matching_approval_with_diverging_checks_produces_check_diff() {
        let baseline = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let mut candidate = make_trace(vec![make_step(0, true), make_step(1, true)]);
        // Flip the single check result in candidate step 1 without changing
        // the top-level `approved` flag.
        candidate.steps[1].verdict.verdict.checks[0].passed = false;
        assert!(candidate.steps[1].verdict.verdict.approved);

        let diffs = diff_traces(&baseline, &candidate);
        assert_eq!(
            diffs.len(),
            1,
            "expected one check_result diff, got: {diffs:?}"
        );
        assert_eq!(diffs[0].step, 1);
        assert_eq!(diffs[0].field, "check_result");
        assert!(diffs[0].baseline.contains("authority=true"));
        assert!(diffs[0].candidate.contains("authority=false"));
    }
}
