use clap::Args;

#[derive(Args)]
pub struct CampaignArgs {
    #[arg(long)]
    pub config: String,
    #[arg(long)]
    pub key: String,
    #[arg(long)]
    pub dry_run: bool,
}
