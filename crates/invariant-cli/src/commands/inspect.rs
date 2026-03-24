use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct InspectArgs {
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
}

pub fn run_stub() -> i32 {
    eprintln!("invariant inspect: not yet implemented (Step 9)");
    2
}
