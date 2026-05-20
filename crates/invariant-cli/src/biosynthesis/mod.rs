//! `invariant biosynthesis ...` subcommand tree.

pub mod commands;

use clap::{Args, Subcommand};

#[derive(Args)]
pub struct BiosynthesisArgs {
    #[command(subcommand)]
    cmd: BiosynthesisSubcommand,
}

#[derive(Subcommand)]
enum BiosynthesisSubcommand {
    /// Validate a synthesis bundle against a bio profile.
    Validate(commands::validate::ValidateArgs),
    /// Display audit log entries.
    Audit(commands::audit::AuditArgs),
    /// Verify audit log integrity.
    Verify(commands::verify::VerifyArgs),
    /// Detect sequence gaps in audit logs.
    AuditGaps(commands::audit_gaps::AuditGapsArgs),
    /// Inspect a bundle, profile, verdict, or audit log.
    Inspect(commands::inspect::InspectArgs),
    /// Generate a new Ed25519 key pair.
    Keygen(commands::keygen::KeygenArgs),
    /// List, show, or expand built-in task-intent templates.
    Intent(commands::intent::IntentArgs),
    /// Dual-instance differential validation.
    Differential(commands::differential::DifferentialArgs),
    /// Verify the integrity of the invariant binary.
    VerifySelf,
    /// Run an adversarial test suite.
    Adversarial(commands::adversarial::AdversarialArgs),
    /// Run a dry-run simulation campaign.
    Campaign(commands::campaign::CampaignArgs),
    /// Evaluate a trace file against a preset rubric set.
    Eval(commands::eval::EvalArgs),
}

pub fn run(args: BiosynthesisArgs) -> i32 {
    match args.cmd {
        BiosynthesisSubcommand::Validate(a) => commands::validate::run(&a),
        BiosynthesisSubcommand::Audit(a) => commands::audit::run(&a),
        BiosynthesisSubcommand::Verify(a) => commands::verify::run(&a),
        BiosynthesisSubcommand::AuditGaps(a) => commands::audit_gaps::run(&a),
        BiosynthesisSubcommand::Inspect(a) => commands::inspect::run(&a),
        BiosynthesisSubcommand::Keygen(a) => commands::keygen::run(&a),
        BiosynthesisSubcommand::Intent(a) => commands::intent::run(&a),
        BiosynthesisSubcommand::Differential(a) => commands::differential::run(&a),
        BiosynthesisSubcommand::VerifySelf => commands::verify_self::run(),
        BiosynthesisSubcommand::Adversarial(a) => commands::adversarial::run(&a),
        BiosynthesisSubcommand::Campaign(a) => commands::campaign::run(&a),
        BiosynthesisSubcommand::Eval(a) => commands::eval::run(&a),
    }
}
