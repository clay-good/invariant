use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
    #[arg(long)]
    pub last: Option<usize>,
}

pub fn run_stub() -> i32 {
    eprintln!("invariant audit: not yet implemented (Step 9)");
    2
}
