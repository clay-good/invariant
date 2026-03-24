use clap::Args;
use std::path::PathBuf;

/// Compare two trace files step-by-step and report divergence points (P2-15).
#[derive(Args)]
pub struct DiffArgs {
    /// First trace file.
    #[arg(value_name = "TRACE_A")]
    pub trace_a: PathBuf,
    /// Second trace file.
    #[arg(value_name = "TRACE_B")]
    pub trace_b: PathBuf,
}

pub fn run_stub() -> i32 {
    eprintln!("invariant diff: not yet implemented (Step 15)");
    2
}
