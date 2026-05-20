//! `invariant robotics ...` subcommand tree.

pub mod commands;

use clap::{Args, Subcommand};

#[derive(Args)]
pub struct RoboticsArgs {
    #[command(subcommand)]
    cmd: RoboticsSubcommand,
}

#[derive(Subcommand)]
enum RoboticsSubcommand {
    /// Validate a command against a robot profile.
    Validate(commands::validate::ValidateArgs),
    /// Display audit log entries.
    Audit(commands::audit::AuditArgs),
    /// Verify audit log integrity.
    Verify(commands::verify::VerifyArgs),
    /// Detect sequence gaps in audit logs.
    AuditGaps(commands::audit_gaps::AuditGapsArgs),
    /// Inspect a robot profile.
    Inspect(commands::inspect::InspectArgs),
    /// Profile management (init, validate).
    Profile(commands::profile_cmd::ProfileArgs),
    /// Generate a new Ed25519 key pair.
    Keygen(commands::keygen::KeygenArgs),
    /// Generate a signed PCA from intent (template or direct specification).
    Intent(commands::intent::IntentArgs),
    /// Dual-instance differential validation (IEC 61508 dual-channel pattern).
    Differential(commands::differential::DifferentialArgs),
    /// Verify a proof package.
    VerifyPackage(commands::verify_package::VerifyPackageArgs),
    /// Generate compliance report mapping test results to standards.
    Compliance(commands::compliance::ComplianceArgs),
    /// Measure validation pipeline latency (WCET benchmarking).
    Bench(commands::bench::BenchArgs),
    /// Sim-to-real transfer validation.
    Transfer(commands::transfer::TransferArgs),
    /// Verify the integrity of the invariant binary.
    VerifySelf,
    /// Run an adversarial test suite against a profile.
    Adversarial(commands::adversarial::AdversarialArgs),
    /// Assemble a proof package from one or more campaign shard
    /// subdirectories (v11 1.5).
    Assemble(commands::assemble::AssembleArgs),
    /// Run a simulation campaign.
    Campaign(commands::campaign::CampaignArgs),
    /// Emit the per-category 15M-episode allocation table (and optionally
    /// write one YAML shard per profile). v11-5.4.
    Generate15m(commands::generate_15m::Generate15mArgs),
    /// Walk a directory of profile JSON files (or the built-in set) and
    /// validate each one. With `--strict`, also enforces cross-field
    /// consistency rules. v11-5.3.
    ValidateProfiles(commands::validate_profiles::ValidateProfilesArgs),
    /// Evaluate a trace file.
    Eval(commands::eval::EvalArgs),
    /// Compare two trace files step-by-step.
    Diff(commands::diff::DiffArgs),
    /// Run in embedded Trust Plane server mode.
    Serve(commands::serve::ServeArgs),
    /// Multi-robot coordination fleet status (v11 5.5).
    Fleet(commands::fleet::FleetArgs),
}

pub fn run(args: RoboticsArgs) -> i32 {
    match args.cmd {
        RoboticsSubcommand::Validate(a) => commands::validate::run(&a),
        RoboticsSubcommand::Audit(a) => commands::audit::run(&a),
        RoboticsSubcommand::Verify(a) => commands::verify::run(&a),
        RoboticsSubcommand::AuditGaps(a) => commands::audit_gaps::run(&a),
        RoboticsSubcommand::Inspect(a) => commands::inspect::run(&a),
        RoboticsSubcommand::Profile(a) => commands::profile_cmd::run(&a),
        RoboticsSubcommand::Keygen(a) => commands::keygen::run(&a),
        RoboticsSubcommand::Intent(a) => commands::intent::run(&a),
        RoboticsSubcommand::Differential(a) => commands::differential::run(&a),
        RoboticsSubcommand::VerifyPackage(a) => commands::verify_package::run(&a),
        RoboticsSubcommand::Compliance(a) => commands::compliance::run(&a),
        RoboticsSubcommand::Bench(a) => commands::bench::run(&a),
        RoboticsSubcommand::Transfer(a) => commands::transfer::run(&a),
        RoboticsSubcommand::VerifySelf => commands::verify_self::run(),
        RoboticsSubcommand::Adversarial(a) => commands::adversarial::run(&a),
        RoboticsSubcommand::Assemble(a) => commands::assemble::run(&a),
        RoboticsSubcommand::Campaign(a) => commands::campaign::run(&a),
        RoboticsSubcommand::Generate15m(a) => commands::generate_15m::run(&a),
        RoboticsSubcommand::ValidateProfiles(a) => commands::validate_profiles::run(&a),
        RoboticsSubcommand::Eval(a) => commands::eval::run(&a),
        RoboticsSubcommand::Diff(a) => commands::diff::run(&a),
        RoboticsSubcommand::Serve(a) => commands::serve::run(&a),
        RoboticsSubcommand::Fleet(a) => commands::fleet::run(&a),
    }
}
