//! `eval` subcommand: run a preset rubric set against a trace JSONL file.
//!
//! Exit codes:
//! - 0 — every rubric in the preset passed
//! - 1 — at least one rubric failed
//! - 2 — usage error (regression preset without `--golden`)
//! - 3 — internal error (load / parse / write)

use std::fs;
use std::path::PathBuf;

use clap::{Args, ValueEnum};

use invariant_eval::biosynthesis::{evaluate, EvalError, Preset};

#[derive(Args, Debug)]
pub struct EvalArgs {
    /// Path to the trace JSONL file.
    #[arg(long, value_name = "TRACE")]
    pub trace: PathBuf,
    /// Preset rubric set to apply.
    #[arg(long, value_enum)]
    pub preset: PresetArg,
    /// Golden trace JSONL — required for `regression`.
    #[arg(long, value_name = "GOLDEN")]
    pub golden: Option<PathBuf>,
    /// Optional output path for the JSON report. Stdout when omitted.
    #[arg(long, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,
}

/// Clap-friendly preset enum, kept separate so the lib's [`Preset`] doesn't
/// take a clap dependency.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum PresetArg {
    /// Every recorded verdict was approved with no per-check failures.
    SafetyCheck,
    /// Every request line has a matching verdict.
    Completeness,
    /// Trace approval timeline matches a golden trace.
    Regression,
}

impl From<PresetArg> for Preset {
    fn from(p: PresetArg) -> Self {
        match p {
            PresetArg::SafetyCheck => Preset::SafetyCheck,
            PresetArg::Completeness => Preset::Completeness,
            PresetArg::Regression => Preset::Regression,
        }
    }
}

pub fn run(args: &EvalArgs) -> i32 {
    let report = match evaluate(&args.trace, args.preset.into(), args.golden.as_deref()) {
        Ok(r) => r,
        Err(EvalError::GoldenRequired) => {
            eprintln!("error: --golden is required for the regression preset");
            return 2;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return 3;
        }
    };

    eprintln!(
        "eval preset={:?} lines={} verdicts={} requests={} overall_pass={}",
        report.preset,
        report.line_count,
        report.verdict_count,
        report.request_count,
        report.overall_pass
    );
    for r in &report.rubrics {
        eprintln!(
            "  [{}] {}: {} — {}",
            if r.passed { "PASS" } else { "FAIL" },
            r.id,
            r.description,
            r.details
        );
    }

    let json = match serde_json::to_string_pretty(&report) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: serialize report: {e}");
            return 3;
        }
    };
    match &args.output {
        Some(p) => {
            if let Err(e) = fs::write(p, &json) {
                eprintln!("error: write {}: {e}", p.display());
                return 3;
            }
        }
        None => println!("{json}"),
    }

    if report.overall_pass {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_lines(lines: &[&str]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
        f
    }

    fn verdict_line(seq: u64, approved: bool) -> String {
        format!(
            r#"{{"kind":"verdict","approved":{approved},"command_hash":"sha256:x","command_sequence":{seq},"timestamp":"2026-04-25T12:00:00Z","checks":[],"profile_name":"p","profile_hash":"sha256:p","authority_summary":{{"origin_principal":"x","hop_count":0,"operations_granted":[],"operations_required":[]}},"verdict_signature":"","signer_kid":"k"}}"#
        )
    }

    fn request_line(seq: u64) -> String {
        format!(r#"{{"kind":"request","command_sequence":{seq}}}"#)
    }

    #[test]
    fn safety_check_pass_returns_zero() {
        let f = write_lines(&[&verdict_line(1, true), &verdict_line(2, true)]);
        let args = EvalArgs {
            trace: f.path().into(),
            preset: PresetArg::SafetyCheck,
            golden: None,
            output: None,
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn safety_check_fail_returns_one() {
        let f = write_lines(&[&verdict_line(1, true), &verdict_line(2, false)]);
        let args = EvalArgs {
            trace: f.path().into(),
            preset: PresetArg::SafetyCheck,
            golden: None,
            output: None,
        };
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn completeness_fail_returns_one() {
        let f = write_lines(&[&request_line(1), &request_line(2), &verdict_line(1, true)]);
        let args = EvalArgs {
            trace: f.path().into(),
            preset: PresetArg::Completeness,
            golden: None,
            output: None,
        };
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn regression_without_golden_returns_two() {
        let f = write_lines(&[&verdict_line(1, true)]);
        let args = EvalArgs {
            trace: f.path().into(),
            preset: PresetArg::Regression,
            golden: None,
            output: None,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn missing_trace_returns_three() {
        let args = EvalArgs {
            trace: PathBuf::from("/nonexistent/trace.jsonl"),
            preset: PresetArg::SafetyCheck,
            golden: None,
            output: None,
        };
        assert_eq!(run(&args), 3);
    }

    #[test]
    fn writes_report_to_output_file() {
        let f = write_lines(&[&verdict_line(1, true)]);
        let dir = tempfile::TempDir::new().unwrap();
        let out = dir.path().join("r.json");
        let args = EvalArgs {
            trace: f.path().into(),
            preset: PresetArg::SafetyCheck,
            golden: None,
            output: Some(out.clone()),
        };
        assert_eq!(run(&args), 0);
        let raw = fs::read_to_string(&out).unwrap();
        assert!(raw.contains("\"overall_pass\""));
    }
}
