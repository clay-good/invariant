use clap::Args;

#[derive(Args)]
pub struct EvalArgs {
    pub trace: String,
    #[arg(long)]
    pub preset: Option<String>,
    #[arg(long)]
    pub rubric: Option<String>,
}
