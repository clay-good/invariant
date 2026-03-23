use clap::Args;

#[derive(Args)]
pub struct ServeArgs {
    #[arg(long)]
    pub profile: String,
    #[arg(long)]
    pub key: String,
    #[arg(long, default_value = "8080")]
    pub port: u16,
    #[arg(long)]
    pub trust_plane: bool,
}
