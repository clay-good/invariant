use clap::Args;

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long)]
    pub log: String,
    #[arg(long)]
    pub last: Option<usize>,
}
