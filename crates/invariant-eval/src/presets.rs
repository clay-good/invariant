// Deterministic eval presets: safety-check, completeness-check, regression-check

use serde::{Deserialize, Serialize};

use invariant_core::models::trace::Trace;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Severity of an individual eval finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// A single finding produced during evaluation of a trace step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub step: u64,
    pub severity: Severity,
    pub message: String,
}

/// Aggregate counts produced by an eval preset run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalSummary {
    /// Steps whose verdict has `approved == true`.
    pub approved_count: usize,
    /// Steps whose verdict has `approved == false`.
    pub rejected_count: usize,
    /// Steps where the command was approved but at least one check failed
    /// (safety-check preset only; 0 for other presets).
    pub violation_escapes: usize,
    /// Steps that have at least one Error-level finding
    /// (completeness-check preset only; 0 for other presets).
    pub incomplete_steps: usize,
    /// Free-form notes added by the preset.
    pub notes: Vec<String>,
}

/// The top-level result of running one eval preset against a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    pub preset: String,
    pub trace_id: String,
    pub total_steps: usize,
    /// `true` when the trace meets the preset's pass criteria (see each preset).
    pub passed: bool,
    pub findings: Vec<Finding>,
    pub summary: EvalSummary,
}

/// Which eval preset to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// Verify the validation pipeline made correct approve/reject decisions.
    SafetyCheck,
    /// Verify every step contains complete validation data.
    CompletenessCheck,
    /// Check trace consistency for regression testing.
    RegressionCheck,
}

impl Preset {
    /// Parse a preset by its canonical CLI name. Returns `None` for unknown names.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "safety-check" => Some(Self::SafetyCheck),
            "completeness-check" => Some(Self::CompletenessCheck),
            "regression-check" => Some(Self::RegressionCheck),
            _ => None,
        }
    }

    /// Return the canonical CLI name for this preset.
    pub fn name(self) -> &'static str {
        match self {
            Self::SafetyCheck => "safety-check",
            Self::CompletenessCheck => "completeness-check",
            Self::RegressionCheck => "regression-check",
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run `preset` against `trace` and return an `EvalReport`.
///
/// This function is purely deterministic: no I/O, no randomness.
pub fn evaluate(trace: &Trace, preset: Preset) -> EvalReport {
    match preset {
        Preset::SafetyCheck => run_safety_check(trace),
        Preset::CompletenessCheck => run_completeness_check(trace),
        Preset::RegressionCheck => run_regression_check(trace),
    }
}

// ---------------------------------------------------------------------------
// Helper — add a finding to the list
// ---------------------------------------------------------------------------

fn finding(step: u64, severity: Severity, message: impl Into<String>) -> Finding {
    Finding {
        step,
        severity,
        message: message.into(),
    }
}

// ---------------------------------------------------------------------------
// Preset 1: safety-check
// ---------------------------------------------------------------------------
//
// Pass criteria: violation_escapes == 0

fn run_safety_check(trace: &Trace) -> EvalReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut approved_count = 0usize;
    let mut rejected_count = 0usize;
    let mut violation_escapes = 0usize;

    let mut prev_sequence: Option<u64> = None;

    for ts in &trace.steps {
        let sv = &ts.verdict;
        let v = &sv.verdict;

        // --- 1. Violation escape: approved but a check failed ---
        if v.approved {
            approved_count += 1;
            let failed_check = v.checks.iter().find(|c| !c.passed);
            if let Some(fc) = failed_check {
                violation_escapes += 1;
                findings.push(finding(
                    ts.step,
                    Severity::Error,
                    format!(
                        "violation escape: command approved but check '{}' (category '{}') failed",
                        fc.name, fc.category
                    ),
                ));
            }
        } else {
            rejected_count += 1;

            // --- 2. Suspicious rejection: all checks passed but verdict rejected ---
            if v.checks.iter().all(|c| c.passed) && !v.checks.is_empty() {
                findings.push(finding(
                    ts.step,
                    Severity::Warning,
                    "suspicious rejection: all checks passed but command was rejected".to_string(),
                ));
            }
        }

        // --- 3. Monotonic sequence numbers ---
        if let Some(prev) = prev_sequence {
            if v.command_sequence <= prev {
                findings.push(finding(
                    ts.step,
                    Severity::Error,
                    format!(
                        "non-monotonic command_sequence: {} follows {}",
                        v.command_sequence, prev
                    ),
                ));
            }
        }
        prev_sequence = Some(v.command_sequence);
    }

    let passed = violation_escapes == 0;

    EvalReport {
        preset: Preset::SafetyCheck.name().to_string(),
        trace_id: trace.id.clone(),
        total_steps: trace.steps.len(),
        passed,
        findings,
        summary: EvalSummary {
            approved_count,
            rejected_count,
            violation_escapes,
            incomplete_steps: 0,
            notes: vec![],
        },
    }
}

// ---------------------------------------------------------------------------
// Preset 2: completeness-check
// ---------------------------------------------------------------------------
//
// Pass criteria: incomplete_steps == 0 (steps with at least one Error finding)

fn run_completeness_check(trace: &Trace) -> EvalReport {
    const EXPECTED_PHYSICS_CHECKS: usize = 10;
    const EXPECTED_AUTHORITY_CHECKS: usize = 1;

    let mut findings: Vec<Finding> = Vec::new();
    let mut approved_count = 0usize;
    let mut rejected_count = 0usize;

    let mut prev_timestamp: Option<chrono::DateTime<chrono::Utc>> = None;

    for ts in &trace.steps {
        let sv = &ts.verdict;
        let v = &sv.verdict;

        if v.approved {
            approved_count += 1;
        } else {
            rejected_count += 1;
        }

        // --- 1. Non-empty command_hash ---
        if v.command_hash.is_empty() {
            findings.push(finding(
                ts.step,
                Severity::Error,
                "missing command_hash in verdict".to_string(),
            ));
        }

        // --- 2. Physics checks present (at least 10) ---
        let physics_count = v
            .checks
            .iter()
            .filter(|c| c.category == "physics")
            .count();
        if physics_count < EXPECTED_PHYSICS_CHECKS {
            findings.push(finding(
                ts.step,
                Severity::Warning,
                format!(
                    "expected {} physics checks, found {}",
                    EXPECTED_PHYSICS_CHECKS, physics_count
                ),
            ));
        }

        // --- 3. Authority check present (at least 1) ---
        let authority_count = v
            .checks
            .iter()
            .filter(|c| c.category == "authority")
            .count();
        if authority_count < EXPECTED_AUTHORITY_CHECKS {
            findings.push(finding(
                ts.step,
                Severity::Warning,
                format!(
                    "expected {} authority check(s), found {}",
                    EXPECTED_AUTHORITY_CHECKS, authority_count
                ),
            ));
        }

        // --- 4. Signer present ---
        if sv.signer_kid.is_empty() {
            findings.push(finding(
                ts.step,
                Severity::Error,
                "missing signer_kid in signed verdict".to_string(),
            ));
        }

        // --- 5. Non-decreasing timestamps ---
        if let Some(prev) = prev_timestamp {
            if ts.timestamp < prev {
                findings.push(finding(
                    ts.step,
                    Severity::Warning,
                    format!(
                        "timestamp out of order: step timestamp {} is before previous {}",
                        ts.timestamp, prev
                    ),
                ));
            }
        }
        prev_timestamp = Some(ts.timestamp);
    }

    // Incomplete steps = steps with at least one Error-level finding
    let incomplete_steps = {
        let mut error_steps = std::collections::HashSet::new();
        for f in &findings {
            if f.severity == Severity::Error {
                error_steps.insert(f.step);
            }
        }
        error_steps.len()
    };

    let passed = incomplete_steps == 0;

    EvalReport {
        preset: Preset::CompletenessCheck.name().to_string(),
        trace_id: trace.id.clone(),
        total_steps: trace.steps.len(),
        passed,
        findings,
        summary: EvalSummary {
            approved_count,
            rejected_count,
            violation_escapes: 0,
            incomplete_steps,
            notes: vec![],
        },
    }
}

// ---------------------------------------------------------------------------
// Preset 3: regression-check
// ---------------------------------------------------------------------------
//
// Pass criteria: no Error-level findings

fn run_regression_check(trace: &Trace) -> EvalReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut approved_count = 0usize;
    let mut rejected_count = 0usize;
    let mut notes: Vec<String> = Vec::new();

    if trace.steps.is_empty() {
        return EvalReport {
            preset: Preset::RegressionCheck.name().to_string(),
            trace_id: trace.id.clone(),
            total_steps: 0,
            passed: true,
            findings,
            summary: EvalSummary {
                approved_count: 0,
                rejected_count: 0,
                violation_escapes: 0,
                incomplete_steps: 0,
                notes,
            },
        };
    }

    // Establish baselines from first step
    let first = &trace.steps[0];
    let baseline_profile_name = &first.verdict.verdict.profile_name;
    let baseline_profile_hash = &first.verdict.verdict.profile_hash;
    let baseline_signer_kid = &first.verdict.signer_kid;
    let baseline_check_count = first.verdict.verdict.checks.len();

    // Determine baseline origin_principal (only from steps where authority checks passed)
    let baseline_origin: Option<String> = trace.steps.iter().find_map(|ts| {
        let authority_passed = ts
            .verdict
            .verdict
            .checks
            .iter()
            .any(|c| c.category == "authority" && c.passed);
        if authority_passed {
            Some(
                ts.verdict
                    .verdict
                    .authority_summary
                    .origin_principal
                    .clone(),
            )
        } else {
            None
        }
    });

    for ts in &trace.steps {
        let sv = &ts.verdict;
        let v = &sv.verdict;

        if v.approved {
            approved_count += 1;
        } else {
            rejected_count += 1;
        }

        // --- 1. Profile consistency ---
        if &v.profile_name != baseline_profile_name {
            findings.push(finding(
                ts.step,
                Severity::Error,
                format!(
                    "profile_name mismatch: expected '{}', got '{}'",
                    baseline_profile_name, v.profile_name
                ),
            ));
        }
        if &v.profile_hash != baseline_profile_hash {
            findings.push(finding(
                ts.step,
                Severity::Error,
                format!(
                    "profile_hash mismatch: expected '{}', got '{}'",
                    baseline_profile_hash, v.profile_hash
                ),
            ));
        }

        // --- 2. Signer consistency ---
        if &sv.signer_kid != baseline_signer_kid {
            findings.push(finding(
                ts.step,
                Severity::Warning,
                format!(
                    "signer_kid mismatch: expected '{}', got '{}'",
                    baseline_signer_kid, sv.signer_kid
                ),
            ));
        }

        // --- 3. Check count consistency ---
        let check_count = v.checks.len();
        if check_count != baseline_check_count {
            findings.push(finding(
                ts.step,
                Severity::Warning,
                format!(
                    "check count variation: expected {}, got {}",
                    baseline_check_count, check_count
                ),
            ));
        }

        // --- 4. Authority origin consistency ---
        let authority_passed = v
            .checks
            .iter()
            .any(|c| c.category == "authority" && c.passed);
        if authority_passed {
            if let Some(ref baseline) = baseline_origin {
                let origin = &v.authority_summary.origin_principal;
                if origin != baseline {
                    findings.push(finding(
                        ts.step,
                        Severity::Warning,
                        format!(
                            "authority origin_principal mismatch: expected '{}', got '{}'",
                            baseline, origin
                        ),
                    ));
                }
            }
        }
    }

    if !findings.is_empty() {
        notes.push(format!(
            "{} finding(s) across {} step(s)",
            findings.len(),
            trace.steps.len()
        ));
    }

    let passed = findings.iter().all(|f| f.severity != Severity::Error);

    EvalReport {
        preset: Preset::RegressionCheck.name().to_string(),
        trace_id: trace.id.clone(),
        total_steps: trace.steps.len(),
        passed,
        findings,
        summary: EvalSummary {
            approved_count,
            rejected_count,
            violation_escapes: 0,
            incomplete_steps: 0,
            notes,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use invariant_core::models::{
        authority::Operation,
        command::{Command, CommandAuthority, JointState},
        trace::{Trace, TraceStep},
        verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict},
    };
    use std::collections::HashMap;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_check(name: &str, category: &str, passed: bool) -> CheckResult {
        CheckResult {
            name: name.to_string(),
            category: category.to_string(),
            passed,
            details: String::new(),
        }
    }

    /// 10 physics checks + 1 authority check, all passing by default.
    fn default_checks(all_pass: bool) -> Vec<CheckResult> {
        let mut checks = Vec::new();
        for i in 1..=10 {
            checks.push(make_check(
                &format!("physics_check_{}", i),
                "physics",
                all_pass,
            ));
        }
        checks.push(make_check("authority_check", "authority", all_pass));
        checks
    }

    fn make_verdict(approved: bool, sequence: u64, checks: Vec<CheckResult>) -> SignedVerdict {
        SignedVerdict {
            verdict: Verdict {
                approved,
                command_hash: format!("sha256:test_{}", sequence),
                command_sequence: sequence,
                timestamp: Utc::now(),
                checks,
                profile_name: "test_profile".to_string(),
                profile_hash: "sha256:profile_hash".to_string(),
                authority_summary: AuthoritySummary {
                    origin_principal: "operator_alice".to_string(),
                    hop_count: 1,
                    operations_granted: vec!["actuate:*".to_string()],
                    operations_required: vec!["actuate:arm".to_string()],
                },
            },
            verdict_signature: "test_sig".to_string(),
            signer_kid: "test-key-001".to_string(),
        }
    }

    fn make_command(sequence: u64) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".to_string(),
            sequence,
            joint_states: vec![JointState {
                name: "j1".to_string(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: "dGVzdA==".to_string(),
                required_ops: vec![Operation::new("actuate:arm").unwrap()],
            },
            metadata: HashMap::new(),
        }
    }

    fn make_step(step: u64, verdict: SignedVerdict) -> TraceStep {
        TraceStep {
            step,
            timestamp: Utc::now(),
            command: make_command(step),
            verdict,
            simulation_state: None,
        }
    }

    fn make_trace(steps: Vec<TraceStep>) -> Trace {
        Trace {
            id: "trace-001".to_string(),
            episode: 1,
            environment_id: 1,
            scenario: "test_scenario".to_string(),
            profile_name: "test_profile".to_string(),
            steps,
            metadata: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // safety-check tests
    // -----------------------------------------------------------------------

    #[test]
    fn safety_check_clean_trace_passes() {
        // All steps approved, all checks pass, monotonic sequences
        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, make_verdict(true, 2, default_checks(true))),
            make_step(3, make_verdict(true, 3, default_checks(true))),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::SafetyCheck);
        assert!(report.passed, "clean trace should pass safety-check");
        assert_eq!(report.summary.violation_escapes, 0);
        assert_eq!(report.summary.approved_count, 3);
        assert_eq!(report.summary.rejected_count, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn safety_check_violation_escape_fails() {
        // Step 2: approved but check failed — this is a violation escape
        let mut checks = default_checks(true);
        checks[0] = make_check("physics_check_1", "physics", false); // one failed check

        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, make_verdict(true, 2, checks)),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::SafetyCheck);
        assert!(!report.passed, "violation escape should fail safety-check");
        assert_eq!(report.summary.violation_escapes, 1);
        assert_eq!(
            report.findings.len(),
            1,
            "should have exactly one finding"
        );
        assert_eq!(report.findings[0].severity, Severity::Error);
        assert_eq!(report.findings[0].step, 2);
    }

    #[test]
    fn safety_check_valid_rejection_passes() {
        // Rejected with at least one failed check — correct behavior
        let mut checks = default_checks(true);
        checks[1] = make_check("physics_check_2", "physics", false);

        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, make_verdict(false, 2, checks)),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::SafetyCheck);
        assert!(report.passed, "valid rejection should pass safety-check");
        assert_eq!(report.summary.violation_escapes, 0);
        assert_eq!(report.summary.rejected_count, 1);
        // No error-level findings
        assert!(report.findings.iter().all(|f| f.severity != Severity::Error));
    }

    #[test]
    fn safety_check_suspicious_rejection_warns() {
        // All checks pass but command was rejected — suspicious
        let steps = vec![
            make_step(1, make_verdict(false, 1, default_checks(true))),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::SafetyCheck);
        // Still passes (no violation escapes), but has a Warning
        assert!(report.passed, "suspicious rejection still passes (no violation escape)");
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("suspicious rejection"));
    }

    #[test]
    fn safety_check_out_of_order_sequence_finds_error() {
        // Sequence goes 1, 3, 2 — out of order
        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, make_verdict(true, 3, default_checks(true))),
            make_step(3, make_verdict(true, 2, default_checks(true))),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::SafetyCheck);
        let errors: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(!errors.is_empty(), "should find non-monotonic sequence error");
        assert!(errors[0].message.contains("non-monotonic command_sequence"));
    }

    #[test]
    fn safety_check_duplicate_sequence_finds_error() {
        // Sequence 1, 1 — duplicate
        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, make_verdict(true, 1, default_checks(true))),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::SafetyCheck);
        let errors: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(!errors.is_empty(), "should find duplicate sequence error");
    }

    // -----------------------------------------------------------------------
    // completeness-check tests
    // -----------------------------------------------------------------------

    #[test]
    fn completeness_check_complete_trace_passes() {
        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, make_verdict(true, 2, default_checks(true))),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::CompletenessCheck);
        assert!(report.passed, "complete trace should pass completeness-check");
        assert_eq!(report.summary.incomplete_steps, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn completeness_check_missing_physics_checks_warns() {
        // Only 5 physics checks (fewer than 10)
        let checks: Vec<CheckResult> = (1..=5)
            .map(|i| make_check(&format!("physics_check_{}", i), "physics", true))
            .chain(std::iter::once(make_check(
                "authority_check",
                "authority",
                true,
            )))
            .collect();

        let steps = vec![make_step(1, make_verdict(true, 1, checks))];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::CompletenessCheck);
        // Warnings don't fail completeness check
        assert!(report.passed, "missing physics checks is a warning, not error");
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert!(!warnings.is_empty(), "should have warning for missing physics checks");
        assert!(warnings[0].message.contains("physics checks"));
    }

    #[test]
    fn completeness_check_missing_authority_check_warns() {
        // No authority check
        let checks: Vec<CheckResult> = (1..=10)
            .map(|i| make_check(&format!("physics_check_{}", i), "physics", true))
            .collect();

        let steps = vec![make_step(1, make_verdict(true, 1, checks))];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::CompletenessCheck);
        assert!(report.passed, "missing authority check is a warning, not error");
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.message.contains("authority check")));
    }

    #[test]
    fn completeness_check_empty_signer_finds_error() {
        let mut sv = make_verdict(true, 1, default_checks(true));
        sv.signer_kid = String::new(); // empty signer

        let steps = vec![make_step(1, sv)];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::CompletenessCheck);
        assert!(!report.passed, "empty signer_kid should fail completeness-check");
        assert_eq!(report.summary.incomplete_steps, 1);
        let errors: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(!errors.is_empty());
        assert!(errors[0].message.contains("signer_kid"));
    }

    #[test]
    fn completeness_check_empty_command_hash_finds_error() {
        let mut sv = make_verdict(true, 1, default_checks(true));
        sv.verdict.command_hash = String::new();

        let steps = vec![make_step(1, sv)];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::CompletenessCheck);
        assert!(!report.passed);
        let errors: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(!errors.is_empty());
        assert!(errors[0].message.contains("command_hash"));
    }

    // -----------------------------------------------------------------------
    // regression-check tests
    // -----------------------------------------------------------------------

    #[test]
    fn regression_check_consistent_trace_passes() {
        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, make_verdict(true, 2, default_checks(true))),
            make_step(3, make_verdict(true, 3, default_checks(true))),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::RegressionCheck);
        assert!(report.passed, "consistent trace should pass regression-check");
        assert!(
            report.findings.iter().all(|f| f.severity != Severity::Error),
            "no errors expected"
        );
    }

    #[test]
    fn regression_check_mixed_profile_names_finds_error() {
        let mut sv2 = make_verdict(true, 2, default_checks(true));
        sv2.verdict.profile_name = "different_profile".to_string();

        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, sv2),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::RegressionCheck);
        assert!(!report.passed, "mixed profile names should fail regression-check");
        let errors: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(!errors.is_empty());
        assert!(errors[0].message.contains("profile_name mismatch"));
    }

    #[test]
    fn regression_check_mixed_profile_hashes_finds_error() {
        let mut sv2 = make_verdict(true, 2, default_checks(true));
        sv2.verdict.profile_hash = "sha256:different_hash".to_string();

        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, sv2),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::RegressionCheck);
        assert!(!report.passed);
        let errors: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(errors.iter().any(|e| e.message.contains("profile_hash mismatch")));
    }

    #[test]
    fn regression_check_mixed_signers_warns() {
        let mut sv2 = make_verdict(true, 2, default_checks(true));
        sv2.signer_kid = "different-key-002".to_string();

        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, sv2),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::RegressionCheck);
        // Signer mismatch is Warning, so the report still passes
        assert!(report.passed, "signer mismatch is warning-only, should still pass");
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.message.contains("signer_kid mismatch")));
    }

    #[test]
    fn regression_check_mixed_check_counts_warns() {
        // Step 2 has one fewer check
        let checks2: Vec<CheckResult> = (1..=9)
            .map(|i| make_check(&format!("physics_check_{}", i), "physics", true))
            .chain(std::iter::once(make_check(
                "authority_check",
                "authority",
                true,
            )))
            .collect();

        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, make_verdict(true, 2, checks2)),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::RegressionCheck);
        assert!(report.passed, "check count variation is warning-only, should still pass");
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.message.contains("check count variation")));
    }

    #[test]
    fn regression_check_mixed_origin_principal_warns() {
        let mut sv2 = make_verdict(true, 2, default_checks(true));
        sv2.verdict.authority_summary.origin_principal = "operator_bob".to_string();

        let steps = vec![
            make_step(1, make_verdict(true, 1, default_checks(true))),
            make_step(2, sv2),
        ];
        let trace = make_trace(steps);
        let report = evaluate(&trace, Preset::RegressionCheck);
        assert!(report.passed, "origin_principal mismatch is warning-only");
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert!(warnings.iter().any(|w| w.message.contains("origin_principal mismatch")));
    }

    // -----------------------------------------------------------------------
    // Preset::from_name parsing
    // -----------------------------------------------------------------------

    #[test]
    fn preset_from_name_parses_all_variants() {
        assert_eq!(
            Preset::from_name("safety-check"),
            Some(Preset::SafetyCheck)
        );
        assert_eq!(
            Preset::from_name("completeness-check"),
            Some(Preset::CompletenessCheck)
        );
        assert_eq!(
            Preset::from_name("regression-check"),
            Some(Preset::RegressionCheck)
        );
    }

    #[test]
    fn preset_from_name_returns_none_for_unknown() {
        assert_eq!(Preset::from_name("unknown"), None);
        assert_eq!(Preset::from_name(""), None);
        assert_eq!(Preset::from_name("SafetyCheck"), None);
    }

    #[test]
    fn preset_name_roundtrips() {
        for p in [
            Preset::SafetyCheck,
            Preset::CompletenessCheck,
            Preset::RegressionCheck,
        ] {
            assert_eq!(Preset::from_name(p.name()), Some(p));
        }
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_empty_trace() {
        let trace = make_trace(vec![]);

        let s = evaluate(&trace, Preset::SafetyCheck);
        assert!(s.passed);
        assert_eq!(s.total_steps, 0);

        let c = evaluate(&trace, Preset::CompletenessCheck);
        assert!(c.passed);
        assert_eq!(c.total_steps, 0);

        let r = evaluate(&trace, Preset::RegressionCheck);
        assert!(r.passed);
        assert_eq!(r.total_steps, 0);
    }

    #[test]
    fn eval_report_contains_trace_id() {
        let mut trace = make_trace(vec![make_step(
            1,
            make_verdict(true, 1, default_checks(true)),
        )]);
        trace.id = "trace-unique-99".to_string();
        let report = evaluate(&trace, Preset::SafetyCheck);
        assert_eq!(report.trace_id, "trace-unique-99");
    }
}
