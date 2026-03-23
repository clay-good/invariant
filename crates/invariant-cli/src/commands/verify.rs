use clap::Args;

#[derive(Args)]
pub struct VerifyArgs {
    #[arg(long)]
    pub log: String,
    #[arg(long)]
    pub pubkey: String,
}
