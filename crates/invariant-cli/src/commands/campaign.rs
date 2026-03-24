use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct CampaignArgs {
    #[arg(long, value_name = "CONFIG_FILE")]
    pub config: PathBuf,
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run_stub() -> i32 {
    eprintln!("invariant campaign: not yet implemented (Step 19)");
    2
}
