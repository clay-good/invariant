use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct VerifyArgs {
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
    #[arg(long, value_name = "PUBKEY_FILE")]
    pub pubkey: PathBuf,
}

pub fn run_stub() -> i32 {
    eprintln!("invariant verify: not yet implemented (Step 9)");
    2
}
