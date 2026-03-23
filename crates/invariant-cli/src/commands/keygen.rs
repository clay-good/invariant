use clap::Args;

#[derive(Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub kid: String,
    #[arg(long)]
    pub output: String,
}
