#![forbid(unsafe_code)]

use clap::{CommandFactory, Parser, Subcommand};

mod biosynthesis;
mod key_file;
mod robotics;

#[derive(Parser)]
#[command(
    name = "invariant",
    version,
    about = "Cryptographic command-validation firewall — robotics & biosynthesis."
)]
struct Cli {
    #[command(subcommand)]
    domain: Option<Domain>,
}

#[derive(Subcommand)]
enum Domain {
    /// Robotics domain: validate motion commands, audit logs, profiles.
    Robotics(robotics::RoboticsArgs),
    /// Biosynthesis domain: validate synthesis bundles, audit logs, profiles.
    Biosynthesis(biosynthesis::BiosynthesisArgs),
    /// Domain-agnostic key operations.
    Keys(KeysArgs),
    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(clap::Args)]
struct KeysArgs {
    #[command(subcommand)]
    cmd: KeysSubcommand,
}

#[derive(Subcommand)]
enum KeysSubcommand {
    /// Generate a new Ed25519 key pair (alias for `invariant robotics keygen`).
    Generate(robotics::commands::keygen::KeygenArgs),
}

fn main() {
    let _ = tracing_subscriber::fmt::try_init();
    let cli = Cli::parse();

    let exit = match cli.domain {
        Some(Domain::Robotics(a)) => robotics::run(a),
        Some(Domain::Biosynthesis(a)) => biosynthesis::run(a),
        Some(Domain::Keys(a)) => match a.cmd {
            KeysSubcommand::Generate(args) => robotics::commands::keygen::run(&args),
        },
        Some(Domain::Completions { shell }) => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "invariant",
                &mut std::io::stdout(),
            );
            0
        }
        None => {
            Cli::command().print_help().unwrap();
            println!();
            2
        }
    };
    std::process::exit(exit);
}
