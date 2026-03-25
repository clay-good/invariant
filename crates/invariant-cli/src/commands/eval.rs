use clap::Args;
use std::path::PathBuf;

use invariant_core::models::trace::Trace;
use invariant_eval::{evaluate, Preset};

#[derive(Args)]
pub struct EvalArgs {
    /// Path to the trace JSON file to evaluate (P2-12: explicit value_name).
    #[arg(value_name = "TRACE_FILE")]
    pub trace: PathBuf,
    /// Eval preset to run: safety-check, completeness-check, regression-check
    #[arg(long)]
    pub preset: Option<String>,
    #[arg(long, value_name = "RUBRIC_FILE")]
    pub rubric: Option<PathBuf>,
}

pub fn run(args: &EvalArgs) -> i32 {
    let preset = match &args.preset {
        Some(name) => match Preset::from_name(name) {
            Some(p) => p,
            None => {
                eprintln!(
                    "error: unknown preset '{}'. valid presets: safety-check, completeness-check, regression-check",
                    name
                );
                return 2;
            }
        },
        None => {
            if args.rubric.is_some() {
                eprintln!("invariant eval --rubric: not yet implemented (Step 13)");
                return 2;
            }
            eprintln!("error: --preset or --rubric is required");
            return 2;
        }
    };

    let trace_data = match std::fs::read_to_string(&args.trace) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("error: cannot read trace file '{}': {}", args.trace.display(), e);
            return 2;
        }
    };

    let trace: Trace = match serde_json::from_str(&trace_data) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: invalid trace JSON: {}", e);
            return 2;
        }
    };

    let report = evaluate(&trace, preset);

    // Print JSON report to stdout
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("error: failed to serialize report: {}", e);
            return 2;
        }
    }

    // Print human-readable summary to stderr
    eprintln!(
        "{}: {} ({} steps, {} approved, {} rejected)",
        report.preset,
        if report.passed { "PASSED" } else { "FAILED" },
        report.total_steps,
        report.summary.approved_count,
        report.summary.rejected_count,
    );

    if !report.findings.is_empty() {
        eprintln!("findings:");
        for f in &report.findings {
            eprintln!("  step {}: [{:?}] {}", f.step, f.severity, f.message);
        }
    }

    if report.passed { 0 } else { 1 }
}
