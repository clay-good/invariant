// Trace diff with step-by-step divergence detection

use invariant_core::models::trace::Trace;

/// A single divergence between two traces.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceDiff {
    pub step: u64,
    /// The name of the diverging field. Always a static string literal —
    /// `diff_traces` only ever produces a fixed set of field names
    /// (`"approved"`, `"trace_length"`).
    pub field: &'static str,
    pub baseline: String,
    pub candidate: String,
}

/// Compare two traces and return divergences.
///
/// The function compares the overlapping steps of `baseline` and `candidate`
/// step-by-step.  For each shared step index it checks whether the top-level
/// `approved` verdict differs.  After the shared prefix a length mismatch is
/// reported as a single extra `TraceDiff` entry.
///
/// # Limitation — top-level comparison only
///
/// `diff_traces` inspects only the top-level `verdict.approved` field.
/// Per-check results within each verdict are **not** compared here.  Two traces
/// that both have `approved = true` on every step will produce zero diffs even
/// if their individual check results diverge.  Use `run_regression` from
/// `presets` for a deeper, per-check comparison.
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
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].step, 1);
        assert_eq!(diffs[0].field, "approved");
        assert_eq!(diffs[0].baseline, "true");
        assert_eq!(diffs[0].candidate, "false");
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

    /// Documents the top-level-only comparison limitation of `diff_traces`.
    ///
    /// Two traces with matching `approved = true` on every step produce zero
    /// diffs even when their per-check results diverge.  This is intentional
    /// for this function; use `run_regression` (in `presets`) for a deeper
    /// per-check comparison.
    #[test]
    fn matching_approval_with_diverging_checks_produces_no_diffs() {
        let baseline = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let mut candidate = make_trace(vec![make_step(0, true), make_step(1, true)]);
        // Flip the single check result in candidate step 1 without changing
        // the top-level `approved` flag — this is the divergence that
        // diff_traces does NOT surface.
        candidate.steps[1].verdict.verdict.checks[0].passed = false;
        // Approved flag is intentionally left `true` to demonstrate the gap.
        assert!(candidate.steps[1].verdict.verdict.approved);

        let diffs = diff_traces(&baseline, &candidate);
        assert!(
            diffs.is_empty(),
            "diff_traces only compares top-level approved; \
             per-check divergence is not detected here, got: {diffs:?}"
        );
    }
}
