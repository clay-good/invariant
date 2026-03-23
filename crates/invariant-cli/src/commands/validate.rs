use clap::Args;

#[derive(Args)]
pub struct ValidateArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long)]
    pub command: Option<String>,
    #[arg(long)]
    pub batch: Option<String>,
    #[arg(long)]
    pub key: String,
    #[arg(long, default_value = "guardian")]
    pub mode: String,
}
