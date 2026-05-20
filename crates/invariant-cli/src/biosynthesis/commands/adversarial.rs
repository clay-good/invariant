//! `adversarial` subcommand: run an attack suite (or all of them) through
//! the fuzz harness and surface mismatches.
//!
//! Exit codes:
//! - 0 — all cases matched expected verdicts
//! - 1 — one or more mismatches
//! - 2 — one or more cases errored before producing a verdict
//! - 3 — internal error (write failure, serialization)

use std::fs;
use std::path::PathBuf;

use clap::{Args, ValueEnum};

use invariant_fuzz::biosynthesis::{run as fuzz_run, run_all as fuzz_run_all, FuzzReport, Suite};

#[derive(Args, Debug)]
pub struct AdversarialArgs {
    /// Which attack suite to run. `all` runs every suite.
    #[arg(long, value_enum, default_value_t = SuiteArg::All)]
    pub suite: SuiteArg,
    /// Optional output path for the JSON report. Stdout when omitted.
    #[arg(long, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,
}

/// Clap-friendly suite enum, kept separate from the lib's [`Suite`] so the
/// fuzz crate doesn't take a clap dependency.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum SuiteArg {
    /// Protocol-level attacks.
    Protocol,
    /// Authority-level attacks.
    Authority,
    /// System-level attacks.
    System,
    /// Cognitive-layer attacks.
    Cognitive,
    /// Run every suite.
    All,
}

pub fn run(args: &AdversarialArgs) -> i32 {
    let report: FuzzReport = match args.suite {
        SuiteArg::Protocol => fuzz_run(Suite::Protocol),
        SuiteArg::Authority => fuzz_run(Suite::Authority),
        SuiteArg::System => fuzz_run(Suite::System),
        SuiteArg::Cognitive => fuzz_run(Suite::Cognitive),
        SuiteArg::All => fuzz_run_all(),
    };

    eprintln!(
        "adversarial: matches={} mismatches={} errors={} total={}",
        report.matches,
        report.mismatches,
        report.errors,
        report.cases.len()
    );
    for c in &report.cases {
        let tag = if c.error.is_some() {
            "ERROR"
        } else if c.matched {
            "OK"
        } else {
            "MISMATCH"
        };
        eprintln!(
            "  [{tag}] {} expected={:?} approved={}{}",
            c.id,
            c.expected,
            c.approved,
            c.error
                .as_deref()
                .map(|e| format!(" — {e}"))
                .unwrap_or_default()
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

    if report.errors > 0 {
        2
    } else if report.mismatches > 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn protocol_suite_succeeds() {
        let args = AdversarialArgs {
            suite: SuiteArg::Protocol,
            output: None,
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn all_suites_succeed() {
        let args = AdversarialArgs {
            suite: SuiteArg::All,
            output: None,
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn writes_report_to_output_file() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("r.json");
        let args = AdversarialArgs {
            suite: SuiteArg::Cognitive,
            output: Some(out.clone()),
        };
        assert_eq!(run(&args), 0);
        let raw = fs::read_to_string(&out).unwrap();
        assert!(raw.contains("\"matches\""));
    }
}
