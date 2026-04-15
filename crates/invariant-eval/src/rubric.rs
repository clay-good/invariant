// Custom YAML/JSON rubric loader

use serde::Deserialize;

/// A rubric rule for trace evaluation.
///
/// # Examples
///
/// ```
/// use invariant_robotics_eval::rubric::RubricRule;
///
/// // A rule that requires the authority check to pass on every step.
/// let rule = RubricRule {
///     name: "authority_must_pass".into(),
///     check_name: "authority".into(),
///     expected_passed: true,
/// };
///
/// assert_eq!(rule.name, "authority_must_pass");
/// assert_eq!(rule.check_name, "authority");
/// assert!(rule.expected_passed);
///
/// // A rule that expects joint_limits to pass (safety requirement).
/// let jl_rule = RubricRule {
///     name: "joint_limits_must_pass".into(),
///     check_name: "joint_limits".into(),
///     expected_passed: true,
/// };
/// assert_eq!(jl_rule.check_name, "joint_limits");
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct RubricRule {
    /// Human-readable name for this rule (used in findings and error messages).
    pub name: String,
    /// Name of the verdict check this rule applies to.
    pub check_name: String,
    /// Whether the referenced check is expected to pass (`true`) or fail (`false`).
    pub expected_passed: bool,
}

/// A loaded rubric containing evaluation rules.
///
/// # Examples
///
/// ```
/// use invariant_robotics_eval::rubric::{Rubric, RubricRule};
///
/// let rubric = Rubric {
///     name: "arm-safety-rubric".into(),
///     rules: vec![
///         RubricRule { name: "authority_must_pass".into(),
///                      check_name: "authority".into(), expected_passed: true },
///         RubricRule { name: "joint_limits_must_pass".into(),
///                      check_name: "joint_limits".into(), expected_passed: true },
///     ],
/// };
///
/// assert_eq!(rubric.name, "arm-safety-rubric");
/// assert_eq!(rubric.rules.len(), 2);
/// assert_eq!(rubric.rules[0].check_name, "authority");
/// assert_eq!(rubric.rules[1].check_name, "joint_limits");
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct Rubric {
    /// Human-readable name identifying this rubric (used in report output).
    pub name: String,
    /// Ordered list of evaluation rules applied to each trace step.
    pub rules: Vec<RubricRule>,
}

use crate::presets::{EvalFinding, EvalReport, Severity};
use invariant_core::models::trace::Trace;

/// Evaluate a trace against a rubric, returning an `EvalReport`.
///
/// For each step in the trace, every rubric rule is checked: the rule's
/// `check_name` is looked up in the step's verdict checks, and the check's
/// `passed` value is compared against `expected_passed`.  A mismatch produces
/// an ERROR finding.  If a rule's `check_name` is not found in the step at
/// all, a WARNING is emitted.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use invariant_robotics_eval::rubric::{Rubric, RubricRule, run_rubric};
/// use invariant_robotics_eval::presets::Severity;
/// use invariant_core::models::trace::{Trace, TraceStep};
/// use invariant_core::models::command::{Command, CommandAuthority, JointState};
/// use invariant_core::models::verdict::{SignedVerdict, Verdict, CheckResult, AuthoritySummary};
///
/// let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
///     .unwrap()
///     .with_timezone(&chrono::Utc);
///
/// // Build a single-step trace where "authority" passed.
/// let cmd = Command {
///     timestamp: ts, source: "arm-controller".into(), sequence: 0,
///     joint_states: vec![JointState { name: "j1".into(), position: 0.0,
///                                     velocity: 0.0, effort: 0.0 }],
///     delta_time: 0.01, end_effector_positions: vec![], center_of_mass: None,
///     authority: CommandAuthority { pca_chain: String::new(), required_ops: vec![] },
///     metadata: HashMap::new(), locomotion_state: None,
///     end_effector_forces: vec![], estimated_payload_kg: None,
///     signed_sensor_readings: vec![], zone_overrides: HashMap::new(),
///     environment_state: None,
/// };
/// let verdict = SignedVerdict {
///     verdict: Verdict {
///         approved: true,
///         command_hash: "hash".into(), command_sequence: 0, timestamp: ts,
///         checks: vec![CheckResult::new("authority", "authority", true, "chain valid")],
///         profile_name: "test-arm".into(), profile_hash: "phash".into(),
///         threat_analysis: None,
///         authority_summary: AuthoritySummary {
///             origin_principal: "operator@example.com".into(), hop_count: 1,
///             operations_granted: vec!["actuate:*".into()],
///             operations_required: vec!["actuate:j1".into()],
///         },
///     },
///     verdict_signature: "sig".into(), signer_kid: "kid".into(),
/// };
/// let trace = Trace {
///     id: "episode-010".into(), episode: 10, environment_id: 0,
///     scenario: "pick-and-place".into(), profile_name: "test-arm".into(),
///     steps: vec![TraceStep { step: 0, timestamp: ts, command: cmd,
///                             verdict, simulation_state: None }],
///     metadata: HashMap::new(),
/// };
///
/// // A rubric requiring "authority" to pass — this trace satisfies it.
/// let rubric = Rubric {
///     name: "safety-rubric".into(),
///     rules: vec![RubricRule {
///         name: "authority_must_pass".into(),
///         check_name: "authority".into(),
///         expected_passed: true,
///     }],
/// };
///
/// let report = run_rubric(&rubric, &trace);
/// assert!(report.passed, "authority check passed, so rubric passes");
/// assert!(report.findings.iter().all(|f| f.severity != Severity::Error));
///
/// // A rubric requiring a check that doesn't exist in the trace emits warnings.
/// let strict_rubric = Rubric {
///     name: "strict-rubric".into(),
///     rules: vec![RubricRule {
///         name: "joint_limits_must_pass".into(),
///         check_name: "joint_limits".into(),
///         expected_passed: true,
///     }],
/// };
/// let warn_report = run_rubric(&strict_rubric, &trace);
/// // The check name is absent from the verdict — a WARNING is produced.
/// assert!(warn_report.findings.iter().any(|f| f.severity == Severity::Warning));
/// ```
pub fn run_rubric(rubric: &Rubric, trace: &Trace) -> EvalReport {
    let mut findings = Vec::new();
    let mut all_passed = true;

    for step in &trace.steps {
        let checks = &step.verdict.verdict.checks;
        for rule in &rubric.rules {
            let check = checks.iter().find(|c| c.name == rule.check_name);
            match check {
                Some(c) if c.passed != rule.expected_passed => {
                    all_passed = false;
                    findings.push(EvalFinding {
                        step: step.step,
                        severity: Severity::Error,
                        message: format!(
                            "rubric rule '{}': check '{}' was {} but expected {}",
                            rule.name,
                            rule.check_name,
                            if c.passed { "passed" } else { "failed" },
                            if rule.expected_passed {
                                "passed"
                            } else {
                                "failed"
                            },
                        ),
                    });
                }
                None => {
                    findings.push(EvalFinding {
                        step: step.step,
                        severity: Severity::Warning,
                        message: format!(
                            "rubric rule '{}': check '{}' not found in verdict",
                            rule.name, rule.check_name,
                        ),
                    });
                }
                _ => {} // matched expectation
            }
        }
    }

    let violations = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    EvalReport {
        preset: format!("rubric:{}", rubric.name),
        trace_id: trace.id.clone(),
        passed: all_passed,
        findings,
        summary: if all_passed {
            "all rubric rules satisfied".into()
        } else {
            format!("{violations} rubric violation(s) found")
        },
    }
}

/// Load a rubric from a JSON string.
///
/// Parses a JSON object with the following schema:
///
/// ```json
/// {
///     "name": "safety-rubric",
///     "rules": [
///         {"name": "authority_must_pass", "check_name": "authority", "expected_passed": true},
///         {"name": "joint_limits_must_pass", "check_name": "joint_limits", "expected_passed": true}
///     ]
/// }
/// ```
///
/// Returns `Err` with a descriptive message if the JSON is malformed, required
/// fields are missing, or any rule has an empty `check_name`.
///
/// # Examples
///
/// ```
/// use invariant_robotics_eval::rubric::load_rubric_json;
///
/// // Load a valid rubric from JSON.
/// let json = r#"{
///     "name": "arm-safety-rubric",
///     "rules": [
///         {"name": "authority_must_pass",   "check_name": "authority",   "expected_passed": true},
///         {"name": "joint_limits_must_pass","check_name": "joint_limits","expected_passed": true}
///     ]
/// }"#;
///
/// let rubric = load_rubric_json(json).expect("valid JSON should parse");
/// assert_eq!(rubric.name, "arm-safety-rubric");
/// assert_eq!(rubric.rules.len(), 2);
/// assert_eq!(rubric.rules[0].check_name, "authority");
/// assert!(rubric.rules[0].expected_passed);
///
/// // Malformed JSON returns an Err.
/// assert!(load_rubric_json("not-json").is_err());
///
/// // A rule with an empty check_name is rejected.
/// let bad = r#"{"name":"r","rules":[{"name":"x","check_name":"","expected_passed":true}]}"#;
/// let err = load_rubric_json(bad).unwrap_err();
/// assert!(err.contains("empty check_name"), "got: {err}");
/// ```
pub fn load_rubric_json(json: &str) -> Result<Rubric, String> {
    let rubric: Rubric =
        serde_json::from_str(json).map_err(|e| format!("failed to parse rubric JSON: {e}"))?;

    for (i, rule) in rubric.rules.iter().enumerate() {
        if rule.check_name.is_empty() {
            return Err(format!(
                "rule at index {i} (name: {:?}) has an empty check_name",
                rule.name
            ));
        }
    }

    Ok(rubric)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_rubric_json_returns_error_for_empty_input() {
        let result = load_rubric_json("");
        assert!(result.is_err());
    }

    #[test]
    fn rubric_rule_fields_are_accessible() {
        // Verify the public struct API is usable without going through the loader.
        let rule = RubricRule {
            name: "authority_must_pass".into(),
            check_name: "authority".into(),
            expected_passed: true,
        };
        assert_eq!(rule.name, "authority_must_pass");
        assert_eq!(rule.check_name, "authority");
        assert!(rule.expected_passed);
    }

    #[test]
    fn rubric_fields_are_accessible() {
        let rubric = Rubric {
            name: "safety-rubric".into(),
            rules: vec![RubricRule {
                name: "r1".into(),
                check_name: "joint_limits".into(),
                expected_passed: true,
            }],
        };
        assert_eq!(rubric.name, "safety-rubric");
        assert_eq!(rubric.rules.len(), 1);
        assert_eq!(rubric.rules[0].check_name, "joint_limits");
    }

    #[test]
    fn load_rubric_json_valid_round_trip() {
        let json = r#"{
            "name": "safety-rubric",
            "rules": [
                {"name": "authority_must_pass", "check_name": "authority", "expected_passed": true},
                {"name": "joint_limits_must_pass", "check_name": "joint_limits", "expected_passed": true}
            ]
        }"#;
        let rubric = load_rubric_json(json).expect("valid JSON should parse without error");
        assert_eq!(rubric.name, "safety-rubric");
        assert_eq!(rubric.rules.len(), 2);
        assert_eq!(rubric.rules[0].name, "authority_must_pass");
        assert_eq!(rubric.rules[0].check_name, "authority");
        assert!(rubric.rules[0].expected_passed);
        assert_eq!(rubric.rules[1].check_name, "joint_limits");
    }

    #[test]
    fn load_rubric_json_empty_rules_list() {
        let json = r#"{"name": "empty-rubric", "rules": []}"#;
        let rubric = load_rubric_json(json).expect("empty rules list should be accepted");
        assert_eq!(rubric.name, "empty-rubric");
        assert!(rubric.rules.is_empty());
    }

    #[test]
    fn load_rubric_json_missing_required_field_returns_error() {
        // `check_name` is absent from the single rule entry.
        let json = r#"{"name": "bad-rubric", "rules": [{"name": "r1", "expected_passed": true}]}"#;
        let result = load_rubric_json(json);
        assert!(
            result.is_err(),
            "missing check_name should produce an Err, not Ok"
        );
        let msg = result.unwrap_err();
        assert!(
            !msg.is_empty(),
            "error message should be non-empty, got: {msg}"
        );
    }

    #[test]
    fn load_rubric_json_empty_check_name_returns_error() {
        let json = r#"{"name": "bad-rubric", "rules": [{"name": "r1", "check_name": "", "expected_passed": true}]}"#;
        let result = load_rubric_json(json);
        assert!(result.is_err(), "empty check_name should produce an Err");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("empty check_name"),
            "error should mention empty check_name, got: {msg}"
        );
    }
}
