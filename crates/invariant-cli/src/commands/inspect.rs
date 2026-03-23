use clap::Args;

#[derive(Args)]
pub struct InspectArgs {
    #[arg(long)]
    pub profile: String,
}
