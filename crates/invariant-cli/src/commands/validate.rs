use clap::{Args, ValueEnum};
use std::path::PathBuf;

/// Operating mode for validation (P2-11: enum instead of free String).
#[derive(Debug, Clone, ValueEnum)]
pub enum ValidationMode {
    Guardian,
    Shadow,
}

#[derive(Args)]
pub struct ValidateArgs {
    /// Path to the robot profile JSON file.
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
    /// Path to a single command JSON file.
    /// Mutually exclusive with --batch (P2-10).
    #[arg(long, value_name = "COMMAND_FILE", conflicts_with = "batch")]
    pub command: Option<PathBuf>,
    /// Path to a batch JSONL file of commands.
    /// Mutually exclusive with --command (P2-10).
    #[arg(long, value_name = "BATCH_FILE", conflicts_with = "command")]
    pub batch: Option<PathBuf>,
    /// Path to the key file.
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    /// Validation mode: guardian (full firewall) or shadow (log-only) (P2-11).
    #[arg(long, value_enum, default_value = "guardian")]
    pub mode: ValidationMode,
}

pub fn run_stub() -> i32 {
    eprintln!("invariant validate: not yet implemented (Step 9)");
    2
}
