// Deterministic eval presets: safety-check, completeness-check, regression-check.
//
// Each preset evaluates a Trace and returns an EvalReport containing per-step
// findings and an overall pass/fail verdict. Presets are pure functions — no I/O.

use std::collections::HashSet;

use invariant_core::models::trace::Trace;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("unknown preset: {0}")]
    UnknownPreset(String),
}

// ---------------------------------------------------------------------------
// Preset names
// ---------------------------------------------------------------------------

/// Known preset names.
pub const PRESET_SAFETY_CHECK: &str = "safety-check";
pub const PRESET_COMPLETENESS_CHECK: &str = "completeness-check";
pub const PRESET_REGRESSION_CHECK: &str = "regression-check";

/// Returns the list of available preset names.
pub fn list_presets() -> &'static [&'static str] {
    &[
        PRESET_SAFETY_CHECK,
        PRESET_COMPLETENESS_CHECK,
        PRESET_REGRESSION_CHECK,
    ]
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// A single finding from an eval preset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalFinding {
    pub step: u64,
    pub severity: Severity,
    pub message: String,
}

/// Finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// Result of running an eval preset on a trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalReport {
    pub preset: String,
    pub trace_id: String,
    pub passed: bool,
    pub findings: Vec<EvalFinding>,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Run a named preset against a trace. Returns an error for unknown presets.
pub fn run_preset(name: &str, trace: &Trace) -> Result<EvalReport, EvalError> {
    match name {
        PRESET_SAFETY_CHECK => Ok(safety_check(trace)),
        PRESET_COMPLETENESS_CHECK => Ok(completeness_check(trace)),
        PRESET_REGRESSION_CHECK => Ok(regression_check_single(trace)),
        _ => Err(EvalError::UnknownPreset(name.to_string())),
    }
}

/// Run a regression check comparing two traces.
pub fn run_regression(baseline: &Trace, candidate: &Trace) -> EvalReport {
    regression_check(baseline, candidate)
}

// ---------------------------------------------------------------------------
// safety-check
// ---------------------------------------------------------------------------

/// Verifies that every step in the trace has all checks passing.
///
/// Findings:
/// - ERROR for any step where `verdict.approved == false`
/// - ERROR for any individual check that failed
/// - WARNING for steps with empty check vectors
fn safety_check(trace: &Trace) -> EvalReport {
    let mut findings = Vec::new();
    let mut all_passed = true;
    let mut rejected: usize = 0;

    if trace.steps.is_empty() {
        all_passed = false;
        findings.push(EvalFinding {
            step: 0,
            severity: Severity::Warning,
            message: "trace contains no steps".into(),
        });
    }

    for step in &trace.steps {
        let verdict = &step.verdict.verdict;

        if verdict.checks.is_empty() {
            findings.push(EvalFinding {
                step: step.step,
                severity: Severity::Warning,
                message: "verdict has no checks".into(),
            });
        }

        if !verdict.approved {
            all_passed = false;
            rejected += 1;

            // Use .any() instead of collecting a Vec to check for failed checks.
            let has_failed = verdict.checks.iter().any(|c| !c.passed);

            if !has_failed {
                findings.push(EvalFinding {
                    step: step.step,
                    severity: Severity::Error,
                    message: "verdict rejected but no individual check failed".into(),
                });
            } else {
                for check in &verdict.checks {
                    if !check.passed {
                        findings.push(EvalFinding {
                            step: step.step,
                            severity: Severity::Error,
                            message: format!(
                                "check '{}' ({}) failed: {}",
                                check.name, check.category, check.details
                            ),
                        });
                    }
                }
            }
        }
    }

    let total = trace.steps.len();

    EvalReport {
        preset: PRESET_SAFETY_CHECK.into(),
        trace_id: trace.id.clone(),
        passed: all_passed,
        findings,
        summary: format!(
            "{}/{} steps approved, {} rejected",
            total - rejected,
            total,
            rejected,
        ),
    }
}

// ---------------------------------------------------------------------------
// completeness-check
// ---------------------------------------------------------------------------

/// Verifies trace completeness:
/// - Steps are present (non-empty trace)
/// - Step sequence numbers are monotonically increasing with no gaps
/// - Step sequence starts at 0
/// - Timestamps are non-decreasing
/// - All 11 expected checks (1 authority + 10 physics) are present per verdict
fn completeness_check(trace: &Trace) -> EvalReport {
    const EXPECTED_CHECKS: &[&str] = &[
        "authority",
        "joint_limits",
        "velocity_limits",
        "torque_limits",
        "acceleration_limits",
        "workspace_bounds",
        "exclusion_zones",
        "self_collision",
        "delta_time",
        "stability",
        "proximity_velocity",
    ];

    let mut findings = Vec::new();
    let mut all_passed = true;
    // Counters incremented inline to avoid two O(n) post-loop filter passes
    // over the findings Vec.
    let mut gap_count: usize = 0;
    let mut missing_count: usize = 0;

    if trace.steps.is_empty() {
        findings.push(EvalFinding {
            step: 0,
            severity: Severity::Error,
            message: "trace contains no steps".into(),
        });
        return EvalReport {
            preset: PRESET_COMPLETENESS_CHECK.into(),
            trace_id: trace.id.clone(),
            passed: false,
            findings,
            summary: "empty trace".into(),
        };
    }

    // Check step 0 exists
    if trace.steps[0].step != 0 {
        all_passed = false;
        findings.push(EvalFinding {
            step: trace.steps[0].step,
            severity: Severity::Error,
            message: format!(
                "first step has sequence {}, expected 0",
                trace.steps[0].step
            ),
        });
    }

    // Check monotonic step numbers and no gaps
    for window in trace.steps.windows(2) {
        let prev = &window[0];
        let curr = &window[1];

        if curr.step <= prev.step {
            // curr.step == prev.step  → duplicate step number
            // curr.step <  prev.step  → backwards / out-of-order step
            all_passed = false;
            gap_count += 1;
            findings.push(EvalFinding {
                step: curr.step,
                severity: Severity::Error,
                message: format!(
                    "duplicate or backwards step: {} -> {} (expected {})",
                    prev.step,
                    curr.step,
                    prev.step + 1
                ),
            });
        } else if curr.step > prev.step + 1 {
            all_passed = false;
            gap_count += 1;
            findings.push(EvalFinding {
                step: curr.step,
                severity: Severity::Error,
                message: format!(
                    "step sequence gap: {} -> {} (expected {})",
                    prev.step,
                    curr.step,
                    prev.step + 1
                ),
            });
        }

        // Timestamps must be non-decreasing
        if curr.timestamp < prev.timestamp {
            all_passed = false;
            findings.push(EvalFinding {
                step: curr.step,
                severity: Severity::Error,
                message: format!(
                    "timestamp regression: step {} ({}) < step {} ({})",
                    curr.step, curr.timestamp, prev.step, prev.timestamp
                ),
            });
        }
    }

    // Check that every verdict has the expected 11 checks
    for step in &trace.steps {
        let check_names: HashSet<&str> = step
            .verdict
            .verdict
            .checks
            .iter()
            .map(|c| c.name.as_str())
            .collect();

        for &expected in EXPECTED_CHECKS {
            if !check_names.contains(expected) {
                all_passed = false;
                missing_count += 1;
                findings.push(EvalFinding {
                    step: step.step,
                    severity: Severity::Error,
                    message: format!("missing check '{}'", expected),
                });
            }
        }
    }

    EvalReport {
        preset: PRESET_COMPLETENESS_CHECK.into(),
        trace_id: trace.id.clone(),
        passed: all_passed,
        findings,
        summary: format!(
            "{} steps, {} sequence gaps, {} missing checks",
            trace.steps.len(),
            gap_count,
            missing_count,
        ),
    }
}

// ---------------------------------------------------------------------------
// regression-check (single trace)
// ---------------------------------------------------------------------------

/// When run on a single trace, regression-check verifies internal consistency:
/// - The trace is non-empty (empty traces indicate a data-pipeline problem)
/// - `verdict.approved` matches whether all checks passed
/// - Command sequence numbers match step sequence numbers
fn regression_check_single(trace: &Trace) -> EvalReport {
    let mut findings = Vec::new();
    let mut all_passed = true;

    // An empty trace cannot be internally consistent — there is nothing to
    // verify.  Fail fast so downstream consumers are not misled by a vacuous
    // pass result.
    if trace.steps.is_empty() {
        return EvalReport {
            preset: PRESET_REGRESSION_CHECK.into(),
            trace_id: trace.id.clone(),
            passed: false,
            findings: vec![EvalFinding {
                step: 0,
                severity: Severity::Error,
                message: "trace contains no steps; cannot verify internal consistency".into(),
            }],
            summary: "0 steps checked for internal consistency".into(),
        };
    }

    for step in &trace.steps {
        let verdict = &step.verdict.verdict;
        let all_checks_pass = verdict.checks.iter().all(|c| c.passed);

        if verdict.approved != all_checks_pass {
            all_passed = false;
            findings.push(EvalFinding {
                step: step.step,
                severity: Severity::Error,
                message: format!(
                    "verdict.approved={} but check results imply {}",
                    verdict.approved, all_checks_pass,
                ),
            });
        }

        if verdict.command_sequence != step.step {
            all_passed = false;
            findings.push(EvalFinding {
                step: step.step,
                severity: Severity::Error,
                message: format!(
                    "command_sequence ({}) does not match step ({})",
                    verdict.command_sequence, step.step,
                ),
            });
        }
    }

    EvalReport {
        preset: PRESET_REGRESSION_CHECK.into(),
        trace_id: trace.id.clone(),
        passed: all_passed,
        findings,
        summary: format!(
            "{} steps checked for internal consistency",
            trace.steps.len()
        ),
    }
}

// ---------------------------------------------------------------------------
// Trace ID validation helpers
// ---------------------------------------------------------------------------

/// Maximum allowed length for a trace ID.
const TRACE_ID_MAX_LEN: usize = 128;

/// Checks whether every character in `id` is alphanumeric or one of `-_.`.
fn is_valid_trace_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= TRACE_ID_MAX_LEN
        && id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Returns the trace ID as-is if it is valid, otherwise returns a sanitized
/// fallback that strips disallowed characters and truncates to the maximum
/// allowed length. A `<sanitized>` suffix is appended to the fallback so
/// callers can detect that the original value was untrusted.
///
/// If stripping all disallowed characters leaves an empty string (e.g. the
/// input consists entirely of disallowed characters), the prefix `"unknown"`
/// is used instead so the returned value is always non-empty.
fn sanitize_trace_id(id: &str) -> String {
    if is_valid_trace_id(id) {
        id.to_string()
    } else {
        let cleaned: String = id
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .take(TRACE_ID_MAX_LEN.saturating_sub("<sanitized>".len()))
            .collect();
        let prefix = if cleaned.is_empty() {
            "unknown"
        } else {
            &cleaned
        };
        format!("{}<sanitized>", prefix)
    }
}

// ---------------------------------------------------------------------------
// regression-check (two traces)
// ---------------------------------------------------------------------------

/// Compares two traces for verdict consistency: for each step present in both
/// traces, the approval outcome must match. Differences are reported as errors.
fn regression_check(baseline: &Trace, candidate: &Trace) -> EvalReport {
    let mut findings = Vec::new();
    let mut all_passed = true;

    let min_steps = baseline.steps.len().min(candidate.steps.len());

    if baseline.steps.len() != candidate.steps.len() {
        all_passed = false;
        findings.push(EvalFinding {
            step: 0,
            severity: Severity::Warning,
            message: format!(
                "trace length mismatch: baseline has {} steps, candidate has {}",
                baseline.steps.len(),
                candidate.steps.len()
            ),
        });

        // Report the extra steps in the longer trace as individual findings.
        if baseline.steps.len() > candidate.steps.len() {
            for extra in &baseline.steps[min_steps..] {
                findings.push(EvalFinding {
                    step: extra.step,
                    severity: Severity::Error,
                    message: format!(
                        "step {} present in baseline but missing from candidate",
                        extra.step
                    ),
                });
            }
        } else {
            for extra in &candidate.steps[min_steps..] {
                findings.push(EvalFinding {
                    step: extra.step,
                    severity: Severity::Error,
                    message: format!(
                        "step {} present in candidate but missing from baseline",
                        extra.step
                    ),
                });
            }
        }
    }

    for i in 0..min_steps {
        let base_step = &baseline.steps[i];
        let cand_step = &candidate.steps[i];
        let base_approved = base_step.verdict.verdict.approved;
        let cand_approved = cand_step.verdict.verdict.approved;

        if base_approved != cand_approved {
            all_passed = false;
            findings.push(EvalFinding {
                step: base_step.step,
                severity: Severity::Error,
                message: format!(
                    "verdict regression: baseline={}, candidate={}",
                    base_approved, cand_approved
                ),
            });
        }

        // Check per-check result differences.
        //
        // Linear scan over the candidate checks for each baseline check.
        // With at most 11 checks per verdict (1 authority + 10 physics),
        // linear search avoids the per-step HashMap allocation overhead.
        for base_check in &base_step.verdict.verdict.checks {
            if let Some(cand_check) = cand_step
                .verdict
                .verdict
                .checks
                .iter()
                .find(|c| c.name == base_check.name)
            {
                if base_check.passed != cand_check.passed {
                    all_passed = false;
                    findings.push(EvalFinding {
                        step: base_step.step,
                        severity: Severity::Error,
                        message: format!(
                            "check '{}' changed: baseline={}, candidate={}",
                            base_check.name, base_check.passed, cand_check.passed
                        ),
                    });
                }
            }
        }

        // Report checks present in the candidate but absent from the baseline
        // as informational findings (not regressions).
        for cand_check in &cand_step.verdict.verdict.checks {
            let in_baseline = base_step
                .verdict
                .verdict
                .checks
                .iter()
                .any(|c| c.name == cand_check.name);
            if !in_baseline {
                findings.push(EvalFinding {
                    step: base_step.step,
                    severity: Severity::Info,
                    message: format!(
                        "check '{}' present in candidate but absent from baseline",
                        cand_check.name
                    ),
                });
            }
        }
    }

    let regressions = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();

    // Validate trace IDs before concatenation to avoid embedding untrusted
    // content in the composite trace_id field.
    let safe_baseline_id = sanitize_trace_id(&baseline.id);
    let safe_candidate_id = sanitize_trace_id(&candidate.id);

    EvalReport {
        preset: PRESET_REGRESSION_CHECK.into(),
        trace_id: format!("{}..{}", safe_baseline_id, safe_candidate_id),
        passed: all_passed,
        findings,
        summary: format!(
            "compared {} steps, {} regressions found",
            min_steps, regressions,
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::models::trace::{Trace, TraceStep};
    use invariant_core::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use std::collections::HashMap;

    /// Returns a fixed, deterministic UTC timestamp for use in tests.
    ///
    /// Using a constant avoids non-determinism from `Utc::now()` and makes
    /// timestamp-ordering tests reproducible.
    fn fixed_ts() -> DateTime<Utc> {
        // 2023-11-14 22:13:20 UTC — an arbitrary but stable reference point.
        Utc.timestamp_opt(1_700_000_000, 0).unwrap()
    }

    fn make_check(name: &str, category: &str, passed: bool) -> CheckResult {
        CheckResult {
            name: name.into(),
            category: category.into(),
            passed,
            details: if passed {
                "ok".into()
            } else {
                format!("{} failed", name)
            },
        }
    }

    fn all_checks(passed: bool) -> Vec<CheckResult> {
        vec![
            make_check("authority", "authority", passed),
            make_check("joint_limits", "physics", passed),
            make_check("velocity_limits", "physics", passed),
            make_check("torque_limits", "physics", passed),
            make_check("acceleration_limits", "physics", passed),
            make_check("workspace_bounds", "physics", passed),
            make_check("exclusion_zones", "physics", passed),
            make_check("self_collision", "physics", passed),
            make_check("delta_time", "physics", passed),
            make_check("stability", "physics", passed),
            make_check("proximity_velocity", "physics", passed),
        ]
    }

    fn make_command(seq: u64) -> Command {
        Command {
            timestamp: fixed_ts(),
            source: "test".into(),
            sequence: seq,
            joint_states: vec![JointState {
                name: "j0".into(),
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
        }
    }

    fn make_verdict(seq: u64, approved: bool) -> SignedVerdict {
        SignedVerdict {
            verdict: Verdict {
                approved,
                command_hash: format!("hash_{}", seq),
                command_sequence: seq,
                timestamp: fixed_ts(),
                checks: all_checks(approved),
                profile_name: "test_profile".into(),
                profile_hash: "profile_hash".into(),
                threat_analysis: None,
                authority_summary: AuthoritySummary {
                    origin_principal: "operator".into(),
                    hop_count: 1,
                    operations_granted: vec!["actuate:*".into()],
                    operations_required: vec!["actuate:j0".into()],
                },
            },
            verdict_signature: "sig".into(),
            signer_kid: "kid".into(),
        }
    }

    fn make_step(seq: u64, approved: bool) -> TraceStep {
        TraceStep {
            step: seq,
            timestamp: fixed_ts(),
            command: make_command(seq),
            verdict: make_verdict(seq, approved),
            simulation_state: None,
        }
    }

    fn make_trace(steps: Vec<TraceStep>) -> Trace {
        Trace {
            id: "trace-001".into(),
            episode: 0,
            environment_id: 0,
            scenario: "test".into(),
            profile_name: "test_profile".into(),
            steps,
            metadata: HashMap::new(),
        }
    }

    // --- list_presets ---

    #[test]
    fn test_list_presets() {
        let presets = list_presets();
        assert_eq!(presets.len(), 3);
        assert!(presets.contains(&"safety-check"));
        assert!(presets.contains(&"completeness-check"));
        assert!(presets.contains(&"regression-check"));
    }

    // --- run_preset dispatch ---

    #[test]
    fn test_unknown_preset() {
        let trace = make_trace(vec![]);
        let err = run_preset("nonexistent", &trace).unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn test_dispatch_safety_check() {
        let trace = make_trace(vec![make_step(0, true)]);
        let report = run_preset("safety-check", &trace).unwrap();
        assert_eq!(report.preset, "safety-check");
        assert!(report.passed);
    }

    #[test]
    fn test_dispatch_completeness_check() {
        let trace = make_trace(vec![make_step(0, true)]);
        let report = run_preset("completeness-check", &trace).unwrap();
        assert_eq!(report.preset, "completeness-check");
    }

    #[test]
    fn test_dispatch_regression_check() {
        let trace = make_trace(vec![make_step(0, true)]);
        let report = run_preset("regression-check", &trace).unwrap();
        assert_eq!(report.preset, "regression-check");
    }

    // --- safety-check ---

    #[test]
    fn test_safety_all_approved() {
        let trace = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = safety_check(&trace);
        assert!(report.passed);
        assert!(report.findings.is_empty());
        assert!(report.summary.contains("2/2 steps approved"));
    }

    #[test]
    fn test_safety_one_rejected() {
        let trace = make_trace(vec![make_step(0, true), make_step(1, false)]);
        let report = safety_check(&trace);
        assert!(!report.passed);
        assert!(!report.findings.is_empty());
        assert!(report.summary.contains("1 rejected"));
    }

    #[test]
    fn test_safety_empty_trace() {
        let trace = make_trace(vec![]);
        let report = safety_check(&trace);
        // An empty trace is treated as a failure: there is nothing to verify.
        assert!(!report.passed);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_safety_rejected_reports_failed_checks() {
        let trace = make_trace(vec![make_step(0, false)]);
        let report = safety_check(&trace);
        // All 11 checks fail in our test helper when approved=false
        let error_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert_eq!(error_findings.len(), 11);
        assert!(error_findings[0].message.contains("authority"));
    }

    // Finding 90: approved=false but all individual checks passed — the
    // "rejected but no individual check failed" branch must produce an Error.
    #[test]
    fn test_safety_approved_false_no_failed_checks() {
        let mut step = make_step(0, true); // start with a fully-passing step
                                           // Override: approved=false while all checks remain passed=true
        step.verdict.verdict.approved = false;
        // Confirm the checks are all still passing
        assert!(step.verdict.verdict.checks.iter().all(|c| c.passed));
        let trace = make_trace(vec![step]);
        let report = safety_check(&trace);
        assert!(!report.passed);
        let err_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert_eq!(err_findings.len(), 1);
        assert!(
            err_findings[0]
                .message
                .contains("verdict rejected but no individual check failed"),
            "unexpected message: {}",
            err_findings[0].message
        );
    }

    // Finding 91: empty checks vector on a step that is also approved — the
    // "verdict has no checks" Warning branch must fire without causing failure.
    #[test]
    fn test_safety_empty_checks_vector_warning() {
        let mut step = make_step(0, true);
        // Clear all checks; verdict.approved remains true
        step.verdict.verdict.checks.clear();
        let trace = make_trace(vec![step]);
        let report = safety_check(&trace);
        // approved=true with empty checks should not mark the report as failed
        assert!(report.passed);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Warning);
        assert!(
            report.findings[0].message.contains("verdict has no checks"),
            "unexpected message: {}",
            report.findings[0].message
        );
    }

    // --- completeness-check ---

    #[test]
    fn test_completeness_empty_trace() {
        let trace = make_trace(vec![]);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        assert!(report.summary.contains("empty trace"));
    }

    #[test]
    fn test_completeness_good_trace() {
        let trace = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = completeness_check(&trace);
        assert!(report.passed);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_completeness_bad_start() {
        let trace = make_trace(vec![make_step(1, true)]);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        assert!(report.findings[0].message.contains("expected 0"));
    }

    #[test]
    fn test_completeness_gap_in_steps() {
        // Step jumps from 0 to 2 — a sequence gap.
        let trace = make_trace(vec![make_step(0, true), make_step(2, true)]);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        let gap_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.message.contains("gap"))
            .collect();
        assert_eq!(gap_findings.len(), 1);
        assert!(
            gap_findings[0].message.contains("step sequence gap"),
            "unexpected message: {}",
            gap_findings[0].message
        );
    }

    #[test]
    fn test_completeness_duplicate_step_number() {
        // Two consecutive steps with the same sequence number — duplicate.
        let trace = make_trace(vec![make_step(0, true), make_step(0, true)]);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        let dup_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.message.contains("duplicate or backwards step"))
            .collect();
        assert_eq!(
            dup_findings.len(),
            1,
            "expected exactly one duplicate finding, got: {:?}",
            report.findings
        );
    }

    #[test]
    fn test_completeness_backwards_step_number() {
        // Step decreases from 1 to 0 — out-of-order / backwards.
        let trace = make_trace(vec![make_step(1, true), make_step(0, true)]);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        // The first-step-must-be-0 check fires too, but the backwards check must
        // also appear.
        let backwards_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.message.contains("duplicate or backwards step"))
            .collect();
        assert_eq!(
            backwards_findings.len(),
            1,
            "expected exactly one backwards-step finding, got: {:?}",
            report.findings
        );
    }

    #[test]
    fn test_completeness_timestamp_regression() {
        use chrono::Duration;
        let mut trace = make_trace(vec![make_step(0, true), make_step(1, true)]);
        trace.steps[1].timestamp = trace.steps[0].timestamp - Duration::seconds(10);
        let report = completeness_check(&trace);
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("timestamp regression")));
    }

    #[test]
    fn test_completeness_missing_check() {
        let mut trace = make_trace(vec![make_step(0, true)]);
        // Remove the last check (proximity_velocity)
        trace.steps[0].verdict.verdict.checks.pop();
        let report = completeness_check(&trace);
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("missing check 'proximity_velocity'")));
    }

    // --- regression-check (single) ---

    #[test]
    fn test_regression_single_consistent() {
        let trace = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = regression_check_single(&trace);
        assert!(report.passed);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_regression_single_inconsistent_verdict() {
        let mut trace = make_trace(vec![make_step(0, true)]);
        // Say approved=true but a check failed — inconsistency
        trace.steps[0].verdict.verdict.checks[0].passed = false;
        let report = regression_check_single(&trace);
        assert!(!report.passed);
        assert!(report.findings[0].message.contains("verdict.approved=true"));
    }

    #[test]
    fn test_regression_single_sequence_mismatch() {
        let mut trace = make_trace(vec![make_step(0, true)]);
        trace.steps[0].verdict.verdict.command_sequence = 99;
        let report = regression_check_single(&trace);
        // Sequence mismatch is an error: it indicates a structural inconsistency.
        assert!(!report.passed);
        assert_eq!(report.findings[0].severity, Severity::Error);
    }

    /// An empty trace must produce a failed report — a vacuous pass would be
    /// misleading for a safety/consistency check.
    #[test]
    fn test_regression_single_empty_trace_fails() {
        let trace = make_trace(vec![]);
        let report = regression_check_single(&trace);
        assert!(
            !report.passed,
            "regression_check_single must fail for an empty trace"
        );
        assert_eq!(
            report.findings.len(),
            1,
            "expected exactly one finding for empty trace"
        );
        assert_eq!(report.findings[0].severity, Severity::Error);
        assert!(
            report.findings[0]
                .message
                .contains("trace contains no steps"),
            "unexpected message: {}",
            report.findings[0].message
        );
    }

    // --- regression-check (two traces) ---

    #[test]
    fn test_regression_two_traces_match() {
        let baseline = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let candidate = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = run_regression(&baseline, &candidate);
        assert!(report.passed);
        assert_eq!(report.findings.len(), 0);
    }

    #[test]
    fn test_regression_two_traces_verdict_change() {
        let baseline = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let candidate = make_trace(vec![make_step(0, true), make_step(1, false)]);
        let report = run_regression(&baseline, &candidate);
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("verdict regression")));
    }

    #[test]
    fn test_regression_two_traces_length_mismatch() {
        let baseline = make_trace(vec![make_step(0, true)]);
        let candidate = make_trace(vec![make_step(0, true), make_step(1, true)]);
        let report = run_regression(&baseline, &candidate);
        // Length mismatch now sets all_passed = false.
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("length mismatch")));
        // The extra step in the candidate should produce an error finding.
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("missing from baseline")));
    }

    #[test]
    fn test_regression_check_level_diff() {
        let baseline = make_trace(vec![make_step(0, true)]);
        let mut candidate = make_trace(vec![make_step(0, true)]);
        // Both approved=true overall, but flip one check in candidate
        candidate.steps[0].verdict.verdict.checks[1].passed = false;
        candidate.steps[0].verdict.verdict.approved = false;
        let report = run_regression(&baseline, &candidate);
        assert!(!report.passed);
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("check 'joint_limits' changed")));
    }

    // Finding 92: both traces approved=true overall, but candidate has one
    // check flipped to passed=false while approved remains true.  The per-check
    // diff logic must surface an Error finding even though the top-level approval
    // outcome is the same on both sides.
    #[test]
    fn test_regression_check_level_diff_both_approved() {
        let baseline = make_trace(vec![make_step(0, true)]);
        let mut candidate = make_trace(vec![make_step(0, true)]);
        // Flip joint_limits to failed in candidate, keep overall approved=true
        candidate.steps[0].verdict.verdict.checks[1].passed = false;
        // approved intentionally left as true — only the check result diverges
        assert!(candidate.steps[0].verdict.verdict.approved);
        let report = run_regression(&baseline, &candidate);
        assert!(!report.passed, "check-level diff should cause failure");
        // There should be no top-level verdict regression finding
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.message.contains("verdict regression")),
            "should not have a top-level verdict regression"
        );
        // There should be a check-level Error finding for joint_limits
        let check_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error && f.message.contains("joint_limits"))
            .collect();
        assert_eq!(
            check_findings.len(),
            1,
            "expected exactly one check-level error for joint_limits"
        );
        assert!(check_findings[0]
            .message
            .contains("check 'joint_limits' changed"));
    }

    /// A check present in the candidate but absent from the baseline is reported
    /// as an informational finding rather than a regression error.
    #[test]
    fn test_regression_candidate_check_absent_from_baseline_is_info() {
        let baseline = make_trace(vec![make_step(0, true)]);
        let mut candidate = make_trace(vec![make_step(0, true)]);
        // Add an extra check to the candidate that is not in the baseline.
        candidate.steps[0]
            .verdict
            .verdict
            .checks
            .push(make_check("new_check", "physics", true));

        let report = run_regression(&baseline, &candidate);
        // The extra check must not cause a failure.
        assert!(
            report.passed,
            "extra check in candidate should not cause failure, findings: {:?}",
            report.findings
        );
        // It must appear as an Info finding.
        let info_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Info && f.message.contains("new_check"))
            .collect();
        assert_eq!(
            info_findings.len(),
            1,
            "expected exactly one Info finding for the new check, got: {:?}",
            report.findings
        );
        assert!(
            info_findings[0]
                .message
                .contains("present in candidate but absent from baseline"),
            "unexpected message: {}",
            info_findings[0].message
        );
    }

    /// Two empty traces produce a vacuous passed=true result with no findings
    /// (the regression loop has nothing to iterate over).  This test documents
    /// that behaviour so it is visible and deliberate rather than accidental.
    ///
    /// Note: if a stricter policy is desired (fail on empty traces), a guard
    /// analogous to the one in `regression_check_single` should be added to
    /// `regression_check`.
    #[test]
    fn test_run_regression_both_empty_traces_passes() {
        let baseline = make_trace(vec![]);
        let candidate = make_trace(vec![]);
        let report = run_regression(&baseline, &candidate);
        // Document the current behaviour: vacuous pass on two empty traces.
        assert!(
            report.passed,
            "run_regression on two empty traces currently returns passed=true (vacuous)"
        );
        assert!(
            report.findings.is_empty(),
            "expected no findings for two empty traces, got: {:?}",
            report.findings
        );
        assert_eq!(
            report.summary, "compared 0 steps, 0 regressions found",
            "unexpected summary: {}",
            report.summary
        );
    }

    // --- trace ID validation helpers ---

    #[test]
    fn test_is_valid_trace_id_accepts_clean_ids() {
        assert!(is_valid_trace_id("trace-001"));
        assert!(is_valid_trace_id("abc123"));
        assert!(is_valid_trace_id("my.trace_id-v2"));
    }

    #[test]
    fn test_is_valid_trace_id_rejects_empty() {
        assert!(!is_valid_trace_id(""));
    }

    #[test]
    fn test_is_valid_trace_id_rejects_too_long() {
        let long = "a".repeat(129);
        assert!(!is_valid_trace_id(&long));
    }

    #[test]
    fn test_is_valid_trace_id_rejects_special_chars() {
        assert!(!is_valid_trace_id("trace/001"));
        assert!(!is_valid_trace_id("trace\x00id"));
        assert!(!is_valid_trace_id("trace id"));
    }

    #[test]
    fn test_sanitize_trace_id_passthrough_valid() {
        let id = "trace-001";
        assert_eq!(sanitize_trace_id(id), "trace-001");
    }

    #[test]
    fn test_sanitize_trace_id_strips_invalid_chars() {
        // "trace/001 bad" → strip '/', ' ' → "trace001bad" → append "<sanitized>"
        let result = sanitize_trace_id("trace/001 bad");
        assert_eq!(result, "trace001bad<sanitized>");
    }

    #[test]
    fn test_sanitize_trace_id_all_disallowed_chars_uses_unknown_prefix() {
        // Input consists entirely of disallowed characters; after stripping,
        // cleaned is empty.  The result must use "unknown" as the prefix so
        // the returned value is always non-empty.
        let result = sanitize_trace_id("!@#$%^&*()");
        assert_eq!(result, "unknown<sanitized>");
    }

    #[test]
    fn test_sanitize_trace_id_truncates_long_ids() {
        let long = "a".repeat(200);
        let result = sanitize_trace_id(&long);
        assert!(result.len() <= TRACE_ID_MAX_LEN);
        assert!(result.ends_with("<sanitized>"));
    }

    #[test]
    fn test_regression_sanitizes_trace_ids_in_report() {
        // Trace IDs with invalid characters must be sanitized in the output.
        let mut baseline = make_trace(vec![make_step(0, true)]);
        let mut candidate = make_trace(vec![make_step(0, true)]);
        baseline.id = "trace/bad<id>".into();
        candidate.id = "cand id".into();
        let report = run_regression(&baseline, &candidate);
        assert!(
            report.trace_id.contains("<sanitized>"),
            "expected sanitized trace_id, got: {}",
            report.trace_id
        );
    }

    // --- EvalReport serialization ---

    #[test]
    fn test_eval_report_serialization() {
        let report = EvalReport {
            preset: "safety-check".into(),
            trace_id: "t1".into(),
            passed: true,
            findings: vec![EvalFinding {
                step: 0,
                severity: Severity::Info,
                message: "test".into(),
            }],
            summary: "ok".into(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let deser: EvalReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, deser);
    }
}
