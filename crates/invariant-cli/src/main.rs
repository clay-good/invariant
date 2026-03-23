use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "invariant", version, about = "Cryptographic command-validation firewall for AI-controlled robots")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a command against a robot profile
    Validate(commands::validate::ValidateArgs),
    /// Display and verify audit logs
    Audit(commands::audit::AuditArgs),
    /// Verify audit log integrity
    Verify(commands::verify::VerifyArgs),
    /// Inspect a robot profile
    Inspect(commands::inspect::InspectArgs),
    /// Evaluate a trace file
    Eval(commands::eval::EvalArgs),
    /// Run a simulation campaign
    Campaign(commands::campaign::CampaignArgs),
    /// Generate a new Ed25519 key pair
    Keygen(commands::keygen::KeygenArgs),
    /// Run in embedded Trust Plane server mode
    Serve(commands::serve::ServeArgs),
}

fn main() {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    // Dispatch is implemented in each command module (Step 9).
    eprintln!("invariant: command dispatch not yet implemented");
    std::process::exit(2);
}
