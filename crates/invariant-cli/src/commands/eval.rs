use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct EvalArgs {
    /// Path to the trace JSON file to evaluate (P2-12: explicit value_name).
    #[arg(value_name = "TRACE_FILE")]
    pub trace: PathBuf,
    #[arg(long)]
    pub preset: Option<String>,
    #[arg(long, value_name = "RUBRIC_FILE")]
    pub rubric: Option<PathBuf>,
}

pub fn run_stub() -> i32 {
    eprintln!("invariant eval: not yet implemented (Step 12)");
    2
}
