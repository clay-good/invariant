use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct ServeArgs {
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    /// TCP port for the embedded Trust Plane. Ports below 1024 require elevated
    /// privileges; use values >= 1024 for unprivileged operation (P3-10).
    #[arg(long, default_value = "8080", value_parser = clap::value_parser!(u16).range(1024..))]
    pub port: u16,
    #[arg(long)]
    pub trust_plane: bool,
}

pub fn run_stub() -> i32 {
    eprintln!("invariant serve: not yet implemented (Step 10)");
    2
}
