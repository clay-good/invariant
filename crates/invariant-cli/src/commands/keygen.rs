use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub kid: String,
    /// Output path for the key file. Validated at the OS level via PathBuf (P3-8, P3-9).
    #[arg(long, value_name = "OUTPUT_FILE")]
    pub output: PathBuf,
}

pub fn run_stub() -> i32 {
    eprintln!("invariant keygen: not yet implemented (Step 11)");
    2
}
