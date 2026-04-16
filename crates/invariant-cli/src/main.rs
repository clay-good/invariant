#![forbid(unsafe_code)]

use clap::{CommandFactory, Parser, Subcommand};

mod commands;
pub mod key_file;

#[derive(Parser)]
#[command(
    name = "invariant",
    version,
    about = "Cryptographic command-validation firewall for AI-controlled robots"
)]
struct Cli {
    /// Verify the integrity of the Invariant binary itself (Section 10.3).
    #[arg(long)]
    verify_self: bool,

    #[command(subcommand)]
    command: Option<Commands>,
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
    /// Dual-instance differential validation (IEC 61508 dual-channel pattern)
    Differential(commands::differential::DifferentialArgs),
    /// Run a simulation campaign
    Campaign(commands::campaign::CampaignArgs),
    /// Generate a new Ed25519 key pair
    Keygen(commands::keygen::KeygenArgs),
    /// Run in embedded Trust Plane server mode
    Serve(commands::serve::ServeArgs),
    /// Run adversarial test suite against a profile
    Adversarial(commands::adversarial::AdversarialArgs),
    /// Measure validation pipeline latency (WCET benchmarking)
    Bench(commands::bench::BenchArgs),
    /// Profile management (init, validate)
    Profile(commands::profile_cmd::ProfileArgs),
    /// Generate compliance report mapping test results to standards
    Compliance(commands::compliance::ComplianceArgs),
    /// Verify a proof package
    VerifyPackage(commands::verify_package::VerifyPackageArgs),
    /// Sim-to-real transfer validation
    Transfer(commands::transfer::TransferArgs),
    /// Detect sequence gaps in audit logs
    AuditGaps(commands::audit_gaps::AuditGapsArgs),
    /// Generate a signed PCA from intent (template or direct specification)
    Intent(commands::intent::IntentArgs),
    /// Verify the integrity of the Invariant binary (Section 10.3)
    VerifySelf,
    /// Generate shell completions for bash, zsh, fish, elvish, or PowerShell
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

fn main() {
    // P2-9: use try_init() so tests can install their own subscriber without panic.
    let _ = tracing_subscriber::fmt::try_init();
    let cli = Cli::parse();

    // Handle --verify-self flag (short-circuits before subcommand dispatch).
    if cli.verify_self {
        std::process::exit(commands::verify_self::run());
    }

    let exit_code = match cli.command {
        Some(Commands::Validate(args)) => commands::validate::run(&args),
        Some(Commands::Audit(args)) => commands::audit::run(&args),
        Some(Commands::Verify(args)) => commands::verify::run(&args),
        Some(Commands::Inspect(args)) => commands::inspect::run(&args),
        Some(Commands::Keygen(args)) => commands::keygen::run(&args),
        Some(Commands::Eval(args)) => commands::eval::run(&args),
        Some(Commands::Diff(args)) => commands::diff::run(&args),
        Some(Commands::Differential(args)) => commands::differential::run(&args),
        Some(Commands::Campaign(args)) => commands::campaign::run(&args),
        Some(Commands::Serve(args)) => commands::serve::run(&args),
        Some(Commands::Adversarial(args)) => commands::adversarial::run(&args),
        Some(Commands::Bench(args)) => commands::bench::run(&args),
        Some(Commands::Profile(args)) => commands::profile_cmd::run(&args),
        Some(Commands::Compliance(args)) => commands::compliance::run(&args),
        Some(Commands::VerifyPackage(args)) => commands::verify_package::run(&args),
        Some(Commands::Transfer(args)) => commands::transfer::run(&args),
        Some(Commands::AuditGaps(args)) => commands::audit_gaps::run(&args),
        Some(Commands::Intent(args)) => commands::intent::run(&args),
        Some(Commands::VerifySelf) => commands::verify_self::run(),
        Some(Commands::Completions { shell }) => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "invariant",
                &mut std::io::stdout(),
            );
            0
        }
        None => {
            // No subcommand and no --verify-self: print help.
            Cli::command().print_help().unwrap();
            println!();
            2
        }
    };
    std::process::exit(exit_code);
}
