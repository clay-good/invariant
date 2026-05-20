//! Trace evaluation engine for biosynthesis firewall traces.
//!
//! A *trace* is a JSONL file. Each non-empty line is a JSON object with
//! either:
//! - `{ "kind": "verdict", ... <SignedVerdict fields> }` — a recorded verdict, or
//! - `{ "kind": "request", "command_sequence": <u64>, ... }` — a request
//!   that was submitted to the firewall but for which no verdict was
//!   produced (used to test the completeness preset).
//!
//! [`evaluate`] runs a [`Preset`]'s rubric set against the trace and
//! returns an [`EvalReport`] summarising per-rubric pass/fail and an
//! aggregate score.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use invariant_biosynthesis::models::verdict::SignedVerdict;

// ---------------------------------------------------------------------------
// Preset / rubric
// ---------------------------------------------------------------------------

/// Built-in evaluation presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    /// Every recorded verdict was approved AND every per-check `passed`
    /// flag was `true`.
    SafetyCheck,
    /// Every `request` line has a corresponding `verdict` line for the
    /// same `command_sequence`.
    Completeness,
    /// The trace's verdict approval timeline matches a golden trace's
    /// timeline (same length, same per-position approvals).
    Regression,
}

/// One rubric outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RubricResult {
    /// Stable rubric id.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this rubric passed.
    pub passed: bool,
    /// Free-form details (counts, mismatches).
    pub details: String,
}

/// Aggregated evaluation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    /// Preset that was applied.
    pub preset: Preset,
    /// Number of trace lines considered.
    pub line_count: usize,
    /// Number of `verdict` entries.
    pub verdict_count: usize,
    /// Number of `request` entries.
    pub request_count: usize,
    /// One entry per rubric.
    pub rubrics: Vec<RubricResult>,
    /// Whether every rubric passed.
    pub overall_pass: bool,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised by [`evaluate`].
#[derive(Debug, Error)]
pub enum EvalError {
    /// Could not read the trace file.
    #[error("read trace {path:?}: {reason}")]
    Io {
        /// Offending path.
        path: PathBuf,
        /// Underlying io error message.
        reason: String,
    },
    /// A trace line could not be parsed.
    #[error("parse trace line {line}: {reason}")]
    Parse {
        /// 1-indexed line number.
        line: usize,
        /// Parser error.
        reason: String,
    },
    /// The regression preset requires a golden trace.
    #[error("regression preset requires a golden trace")]
    GoldenRequired,
}

// ---------------------------------------------------------------------------
// Trace types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TraceLine {
    Request {
        command_sequence: u64,
    },
    Verdict {
        #[serde(flatten)]
        signed: Box<SignedVerdict>,
    },
}

#[derive(Debug, Default)]
struct ParsedTrace {
    lines: usize,
    requests: Vec<u64>,
    verdicts: Vec<SignedVerdict>,
}

fn parse_trace(path: &Path) -> Result<ParsedTrace, EvalError> {
    let f = fs::File::open(path).map_err(|e| EvalError::Io {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let mut t = ParsedTrace::default();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let raw = line.map_err(|e| EvalError::Io {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        if raw.trim().is_empty() {
            continue;
        }
        t.lines += 1;
        let parsed: TraceLine = serde_json::from_str(&raw).map_err(|e| EvalError::Parse {
            line: i + 1,
            reason: e.to_string(),
        })?;
        match parsed {
            TraceLine::Request { command_sequence } => t.requests.push(command_sequence),
            TraceLine::Verdict { signed } => t.verdicts.push(*signed),
        }
    }
    Ok(t)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate a trace file against `preset`.
///
/// `golden` is required for [`Preset::Regression`] and ignored otherwise.
pub fn evaluate(
    path: &Path,
    preset: Preset,
    golden: Option<&Path>,
) -> Result<EvalReport, EvalError> {
    let trace = parse_trace(path)?;
    let rubrics = match preset {
        Preset::SafetyCheck => safety_check_rubrics(&trace),
        Preset::Completeness => completeness_rubrics(&trace),
        Preset::Regression => {
            let golden_path = golden.ok_or(EvalError::GoldenRequired)?;
            let golden_trace = parse_trace(golden_path)?;
            regression_rubrics(&trace, &golden_trace)
        }
    };
    let overall_pass = rubrics.iter().all(|r| r.passed);
    Ok(EvalReport {
        preset,
        line_count: trace.lines,
        verdict_count: trace.verdicts.len(),
        request_count: trace.requests.len(),
        rubrics,
        overall_pass,
    })
}

fn safety_check_rubrics(trace: &ParsedTrace) -> Vec<RubricResult> {
    let mut rubrics = Vec::new();
    let approved = trace.verdicts.iter().filter(|v| v.verdict.approved).count();
    let total = trace.verdicts.len();
    rubrics.push(RubricResult {
        id: "all_verdicts_approved".into(),
        description: "every verdict carries approved=true".into(),
        passed: total > 0 && approved == total,
        details: format!("{approved}/{total} approved"),
    });
    let mut failing: Vec<String> = Vec::new();
    for v in &trace.verdicts {
        for c in &v.verdict.checks {
            if !c.passed {
                failing.push(format!(
                    "seq={} {}={:?}",
                    v.verdict.command_sequence, c.name, c.details
                ));
            }
        }
    }
    rubrics.push(RubricResult {
        id: "no_check_failures".into(),
        description: "no per-check passed=false in any verdict".into(),
        passed: failing.is_empty(),
        details: if failing.is_empty() {
            format!("{total} verdict(s) clean")
        } else {
            format!("failures: {}", failing.join("; "))
        },
    });
    rubrics
}

fn completeness_rubrics(trace: &ParsedTrace) -> Vec<RubricResult> {
    let mut rubrics = Vec::new();
    let verdict_seqs: HashSet<u64> = trace
        .verdicts
        .iter()
        .map(|v| v.verdict.command_sequence)
        .collect();
    let missing: Vec<u64> = trace
        .requests
        .iter()
        .copied()
        .filter(|s| !verdict_seqs.contains(s))
        .collect();
    rubrics.push(RubricResult {
        id: "every_request_has_verdict".into(),
        description: "every request line has a matching verdict for the same command_sequence"
            .into(),
        passed: missing.is_empty(),
        details: if missing.is_empty() {
            format!(
                "{} requests, {} verdicts, {} matched",
                trace.requests.len(),
                trace.verdicts.len(),
                verdict_seqs.len()
            )
        } else {
            format!("missing verdicts for sequences: {missing:?}")
        },
    });

    // Detect duplicate verdicts for the same command_sequence.
    let mut seen = HashSet::new();
    let mut dups: Vec<u64> = Vec::new();
    for v in &trace.verdicts {
        let s = v.verdict.command_sequence;
        if !seen.insert(s) {
            dups.push(s);
        }
    }
    rubrics.push(RubricResult {
        id: "no_duplicate_verdicts".into(),
        description: "no two verdicts share the same command_sequence".into(),
        passed: dups.is_empty(),
        details: if dups.is_empty() {
            "no duplicate sequences".into()
        } else {
            format!("duplicate sequences: {dups:?}")
        },
    });
    rubrics
}

fn regression_rubrics(trace: &ParsedTrace, golden: &ParsedTrace) -> Vec<RubricResult> {
    let mut rubrics = Vec::new();
    let len_match = trace.verdicts.len() == golden.verdicts.len();
    rubrics.push(RubricResult {
        id: "verdict_count_matches_golden".into(),
        description: "trace verdict count equals golden trace verdict count".into(),
        passed: len_match,
        details: format!(
            "trace={} golden={}",
            trace.verdicts.len(),
            golden.verdicts.len()
        ),
    });
    let pairs = trace.verdicts.iter().zip(golden.verdicts.iter());
    let mut diffs: Vec<String> = Vec::new();
    for (i, (a, b)) in pairs.enumerate() {
        if a.verdict.approved != b.verdict.approved {
            diffs.push(format!(
                "pos={i} trace={} golden={}",
                a.verdict.approved, b.verdict.approved
            ));
        }
    }
    rubrics.push(RubricResult {
        id: "approval_timeline_matches_golden".into(),
        description: "per-position approval flag matches golden trace".into(),
        passed: len_match && diffs.is_empty(),
        details: if len_match && diffs.is_empty() {
            "all approvals match".into()
        } else {
            format!("differences: {}", diffs.join("; "))
        },
    });
    rubrics
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use invariant_biosynthesis::models::verdict::{
        AuthoritySummary, CheckResult, SignedVerdict, Verdict,
    };
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn signed(seq: u64, approved: bool, checks: Vec<CheckResult>) -> SignedVerdict {
        SignedVerdict {
            verdict: Verdict {
                approved,
                command_hash: format!("sha256:{seq:x}"),
                command_sequence: seq,
                timestamp: Utc::now(),
                checks,
                profile_name: "p".into(),
                profile_hash: "sha256:p".into(),
                authority_summary: AuthoritySummary {
                    origin_principal: "x".into(),
                    hop_count: 0,
                    operations_granted: vec![],
                    operations_required: vec![],
                },
                threat_analysis: None,
            },
            verdict_signature: String::new(),
            signer_kid: "kid".into(),
        }
    }

    fn write_trace(lines: &[serde_json::Value]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for v in lines {
            writeln!(f, "{}", serde_json::to_string(v).unwrap()).unwrap();
        }
        f
    }

    fn verdict_line(s: &SignedVerdict) -> serde_json::Value {
        let mut v = serde_json::to_value(s).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("kind".into(), serde_json::json!("verdict"));
        v
    }

    fn request_line(seq: u64) -> serde_json::Value {
        serde_json::json!({"kind": "request", "command_sequence": seq})
    }

    // ---- SafetyCheck ----

    #[test]
    fn safety_check_passes_when_all_approved_and_clean() {
        let v1 = signed(
            1,
            true,
            vec![CheckResult::new("a", "authority", true, "ok")],
        );
        let v2 = signed(
            2,
            true,
            vec![CheckResult::new("a", "authority", true, "ok")],
        );
        let f = write_trace(&[verdict_line(&v1), verdict_line(&v2)]);
        let r = evaluate(f.path(), Preset::SafetyCheck, None).unwrap();
        assert!(r.overall_pass, "{:?}", r);
        assert_eq!(r.verdict_count, 2);
    }

    #[test]
    fn safety_check_fails_when_any_rejected() {
        let v1 = signed(1, true, vec![]);
        let v2 = signed(2, false, vec![]);
        let f = write_trace(&[verdict_line(&v1), verdict_line(&v2)]);
        let r = evaluate(f.path(), Preset::SafetyCheck, None).unwrap();
        assert!(!r.overall_pass);
    }

    #[test]
    fn safety_check_fails_when_check_passed_false() {
        let v = signed(
            1,
            true,
            vec![CheckResult::new("a", "authority", false, "bad")],
        );
        let f = write_trace(&[verdict_line(&v)]);
        let r = evaluate(f.path(), Preset::SafetyCheck, None).unwrap();
        assert!(!r.overall_pass);
        assert!(r
            .rubrics
            .iter()
            .any(|x| x.id == "no_check_failures" && !x.passed));
    }

    // ---- Completeness ----

    #[test]
    fn completeness_passes_when_all_requests_have_verdicts() {
        let v1 = signed(1, true, vec![]);
        let v2 = signed(2, true, vec![]);
        let f = write_trace(&[
            request_line(1),
            request_line(2),
            verdict_line(&v1),
            verdict_line(&v2),
        ]);
        let r = evaluate(f.path(), Preset::Completeness, None).unwrap();
        assert!(r.overall_pass);
        assert_eq!(r.request_count, 2);
        assert_eq!(r.verdict_count, 2);
    }

    #[test]
    fn completeness_fails_when_request_missing_verdict() {
        let v1 = signed(1, true, vec![]);
        let f = write_trace(&[request_line(1), request_line(2), verdict_line(&v1)]);
        let r = evaluate(f.path(), Preset::Completeness, None).unwrap();
        assert!(!r.overall_pass);
    }

    #[test]
    fn completeness_fails_on_duplicate_verdicts() {
        let v1 = signed(1, true, vec![]);
        let f = write_trace(&[request_line(1), verdict_line(&v1), verdict_line(&v1)]);
        let r = evaluate(f.path(), Preset::Completeness, None).unwrap();
        assert!(!r.overall_pass);
        assert!(r
            .rubrics
            .iter()
            .any(|x| x.id == "no_duplicate_verdicts" && !x.passed));
    }

    // ---- Regression ----

    #[test]
    fn regression_passes_when_traces_match() {
        let v1 = signed(1, true, vec![]);
        let v2 = signed(2, false, vec![]);
        let trace = write_trace(&[verdict_line(&v1), verdict_line(&v2)]);
        let golden = write_trace(&[verdict_line(&v1), verdict_line(&v2)]);
        let r = evaluate(trace.path(), Preset::Regression, Some(golden.path())).unwrap();
        assert!(r.overall_pass);
    }

    #[test]
    fn regression_fails_when_approval_timeline_diverges() {
        let v_a = signed(1, true, vec![]);
        let v_b = signed(1, false, vec![]);
        let trace = write_trace(&[verdict_line(&v_a)]);
        let golden = write_trace(&[verdict_line(&v_b)]);
        let r = evaluate(trace.path(), Preset::Regression, Some(golden.path())).unwrap();
        assert!(!r.overall_pass);
    }

    #[test]
    fn regression_fails_when_lengths_differ() {
        let v1 = signed(1, true, vec![]);
        let trace = write_trace(&[verdict_line(&v1), verdict_line(&v1)]);
        let golden = write_trace(&[verdict_line(&v1)]);
        let r = evaluate(trace.path(), Preset::Regression, Some(golden.path())).unwrap();
        assert!(!r.overall_pass);
    }

    #[test]
    fn regression_without_golden_errors() {
        let v1 = signed(1, true, vec![]);
        let trace = write_trace(&[verdict_line(&v1)]);
        let r = evaluate(trace.path(), Preset::Regression, None);
        assert!(matches!(r, Err(EvalError::GoldenRequired)));
    }

    // ---- Parse / IO ----

    #[test]
    fn parse_error_on_invalid_json() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "{{not valid json").unwrap();
        let r = evaluate(f.path(), Preset::SafetyCheck, None);
        assert!(matches!(r, Err(EvalError::Parse { .. })));
    }

    #[test]
    fn missing_file_io_error() {
        let r = evaluate(
            Path::new("/nonexistent/trace.jsonl"),
            Preset::SafetyCheck,
            None,
        );
        assert!(matches!(r, Err(EvalError::Io { .. })));
    }
}
