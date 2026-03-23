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
    /// Display audit log entries
    Audit(commands::audit::AuditArgs),
    /// Verify audit log integrity
    Verify(commands::verify::VerifyArgs),
    /// Inspect a robot profile
    Inspect(commands::inspect::InspectArgs),
    /// Evaluate a trace file
    Eval(commands::eval::EvalArgs),
    /// Compare two trace files step-by-step
    Diff(commands::diff::DiffArgs),
    /// Run a simulation campaign
    Campaign(commands::campaign::CampaignArgs),
    /// Generate a new Ed25519 key pair
    Keygen(commands::keygen::KeygenArgs),
    /// Run in embedded Trust Plane server mode
    Serve(commands::serve::ServeArgs),
}

fn main() {
    // P2-9: use try_init() so tests can install their own subscriber without panic.
    let _ = tracing_subscriber::fmt::try_init();
    let cli = Cli::parse();
    // P2-8: dispatch is stubbed per-command; Step 9 wires the full implementations.
    let exit_code = match cli.command {
        Commands::Validate(_) => commands::validate::run_stub(),
        Commands::Audit(_) => commands::audit::run_stub(),
        Commands::Verify(_) => commands::verify::run_stub(),
        Commands::Inspect(_) => commands::inspect::run_stub(),
        Commands::Eval(_) => commands::eval::run_stub(),
        Commands::Diff(_) => commands::diff::run_stub(),
        Commands::Campaign(_) => commands::campaign::run_stub(),
        Commands::Keygen(_) => commands::keygen::run_stub(),
        Commands::Serve(_) => commands::serve::run_stub(),
    };
    std::process::exit(exit_code);
}
