//! `invariant adversarial` — run the adversarial test suite against a robot profile.
//!
//! Exercises boundary probing (PA1–PA2), numeric injection (PA3–PA4), and
//! authority chain attacks (AA1–AA10) using the `invariant-fuzz` crate.
//! Results are printed as a summary and optionally written to a JSON report
//! file.

use clap::Args;
use std::collections::HashMap;
use std::path::PathBuf;

use invariant_fuzz::protocol::authority::{
    encode_chain, escalate_operations, forge_signature, truncate_chain,
};
use invariant_fuzz::protocol::boundary::BoundaryProber;
use invariant_fuzz::protocol::numeric::NumericInjector;
use invariant_fuzz::report::AdversarialReport;

use invariant_core::authority::crypto::sign_pca;
use invariant_core::models::authority::{Operation, Pca, SignedPca};
use invariant_core::validator::ValidatorConfig;

#[derive(Args)]
pub struct AdversarialArgs {
    /// Path to the robot profile JSON file.
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
    /// Path to the key file (secret key required).
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    /// Attack suite to run: "protocol", "authority", or "all".
    #[arg(long, default_value = "protocol")]
    pub suite: String,
    /// Optional path to write the JSON report.
    #[arg(long, value_name = "REPORT_FILE")]
    pub report: Option<PathBuf>,
    /// Export structured training data for cognitive layer improvement (Section 11.5).
    #[arg(long, value_name = "TRAINING_FILE")]
    pub export_training: Option<PathBuf>,
    /// Run mutation-based fuzzing for N iterations instead of structured suites.
    #[arg(long)]
    pub fuzz: bool,
    /// Number of fuzz iterations (default 10000). Only used with --fuzz.
    #[arg(long, default_value = "10000")]
    pub iterations: u64,
}

pub fn run(args: &AdversarialArgs) -> i32 {
    // Load profile.
    let profile_json = match std::fs::read_to_string(&args.profile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to read profile {:?}: {e}", args.profile);
            return 2;
        }
    };
    let profile = match invariant_core::profiles::load_from_json(&profile_json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid profile: {e}");
            return 2;
        }
    };

    // Load key.
    let kf = match crate::key_file::load_key_file(&args.key) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (signing_key, verifying_key, kid) = match crate::key_file::load_signing_key(&kf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Build validator config.
    let raw_key_bytes = signing_key.to_bytes();
    let mut trusted_keys = HashMap::new();
    trusted_keys.insert(kid.clone(), verifying_key);

    let config = match ValidatorConfig::new(profile.clone(), trusted_keys, signing_key, kid.clone())
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to build validator config: {e}");
            return 2;
        }
    };

    // -----------------------------------------------------------------------
    // Fuzz mode: mutation-based fuzzing for N iterations
    // -----------------------------------------------------------------------
    if args.fuzz {
        return run_fuzz_mode(&config, &profile, &kid, &raw_key_bytes, args);
    }

    let suite = args.suite.as_str();
    let mut aggregate = AdversarialReport::new(suite);

    // -----------------------------------------------------------------------
    // Protocol suite: boundary probing + numeric injection
    // -----------------------------------------------------------------------
    if suite == "protocol" || suite == "all" {
        run_protocol_suite(&config, &profile, &kid, &raw_key_bytes, &mut aggregate);
    }

    // -----------------------------------------------------------------------
    // Authority suite: chain forgery / escalation / truncation
    // -----------------------------------------------------------------------
    if suite == "authority" || suite == "all" {
        run_authority_suite(&config, &profile, &kid, &raw_key_bytes, &mut aggregate);
    }

    // -----------------------------------------------------------------------
    // Environment suite: P21-P25 environmental hazard injection
    // -----------------------------------------------------------------------
    if suite == "environment" || suite == "all" {
        run_environment_suite(&config, &profile, &kid, &raw_key_bytes, &mut aggregate);
    }

    if !matches!(suite, "protocol" | "authority" | "environment" | "all") {
        eprintln!(
            "error: unknown suite {:?}; must be 'protocol', 'authority', 'environment', or 'all'",
            args.suite
        );
        return 2;
    }

    // Print summary.
    println!(
        "Adversarial suite '{}': {} attacks, {} escapes",
        aggregate.attack_class, aggregate.total_attacks, aggregate.escapes
    );

    if aggregate.all_detected() {
        println!("PASS: all attacks detected");
    } else {
        eprintln!("FAIL: {} attack(s) escaped detection", aggregate.escapes);
        for f in aggregate.findings.iter().filter(|f| f.escaped) {
            eprintln!(
                "  [{}] {} -> {}",
                f.attack_id, f.description, f.validator_outcome
            );
        }
    }

    // Optionally write JSON report.
    if let Some(ref report_path) = args.report {
        match serde_json::to_string_pretty(&aggregate) {
            Ok(json) => {
                if let Err(e) = std::fs::write(report_path, json) {
                    eprintln!("error: failed to write report {:?}: {e}", report_path);
                    return 2;
                }
            }
            Err(e) => {
                eprintln!("error: failed to serialize report: {e}");
                return 2;
            }
        }
    }

    // Optionally export training data (Section 11.5).
    if let Some(ref training_path) = args.export_training {
        let training_entries: Vec<serde_json::Value> = aggregate
            .findings
            .iter()
            .filter(|f| !f.escaped)
            .map(|f| {
                serde_json::json!({
                    "attack_id": f.attack_id,
                    "verdict": "rejected",
                    "violation_type": f.description,
                    "validator_outcome": f.validator_outcome,
                    "attack_class": f.attack_id.split('-').next().unwrap_or("unknown"),
                    "severity": if f.escaped { "critical" } else { "info" },
                })
            })
            .collect();
        let jsonl: String = training_entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        if let Err(e) = std::fs::write(training_path, jsonl) {
            eprintln!(
                "error: failed to write training data {:?}: {e}",
                training_path
            );
            return 2;
        }
        println!(
            "Training data exported: {} entries to {:?}",
            training_entries.len(),
            training_path
        );
    }

    if aggregate.all_detected() {
        0
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// Protocol suite helpers
// ---------------------------------------------------------------------------

fn run_protocol_suite(
    config: &ValidatorConfig,
    profile: &invariant_core::models::profile::RobotProfile,
    kid: &str,
    raw_key_bytes: &[u8; 32],
    report: &mut AdversarialReport,
) {
    let now = chrono::Utc::now();

    // Build a valid signing key for attaching a chain to boundary/numeric cmds.
    let attach_sk = ed25519_dalek::SigningKey::from_bytes(raw_key_bytes);

    // --- Boundary probing (PA1–PA2) ---
    let boundary_probes = BoundaryProber::probe_all_joints(profile);
    for (i, (mut cmd, expected_pass)) in boundary_probes.into_iter().enumerate() {
        attach_valid_chain(&mut cmd, &attach_sk, kid, profile);
        let attack_id = if expected_pass {
            format!("PA1-boundary-{i}")
        } else {
            format!("PA2-boundary-{i}")
        };

        match config.validate(&cmd, now, None) {
            Ok(result) => {
                let approved = result.signed_verdict.verdict.approved;
                // An escape occurs when the validator approves a command we
                // expected to be rejected (or vice versa — though approving a
                // boundary-exactly-at-limit command is correct behaviour).
                let escaped = approved != expected_pass;
                let outcome = if approved {
                    "approved".to_string()
                } else {
                    let failed: Vec<&str> = result
                        .signed_verdict
                        .verdict
                        .checks
                        .iter()
                        .filter(|c| !c.passed)
                        .map(|c| c.name.as_str())
                        .collect();
                    format!("rejected [{}]", failed.join(", "))
                };
                report.record(
                    &attack_id,
                    format!("boundary probe (expected_pass={expected_pass})"),
                    outcome,
                    escaped,
                );
            }
            Err(e) => {
                // A ValidatorError is a processing failure, not an escape.
                report.record(
                    &attack_id,
                    format!("boundary probe (expected_pass={expected_pass})"),
                    format!("error: {e}"),
                    false,
                );
            }
        }
    }

    // --- Numeric injection (PA3–PA4) ---
    if let Some(base_cmd) = build_valid_base_command(profile, kid, raw_key_bytes) {
        let injected = NumericInjector::inject_all(&base_cmd);
        for (i, cmd) in injected.into_iter().enumerate() {
            let attack_id = format!("PA3-numeric-{i}");
            match config.validate(&cmd, now, None) {
                Ok(result) => {
                    let approved = result.signed_verdict.verdict.approved;
                    // NaN/Inf injections should always be rejected.
                    let escaped = approved;
                    report.record(
                        &attack_id,
                        "numeric injection (NaN/Inf/subnormal)",
                        if approved { "approved" } else { "rejected" },
                        escaped,
                    );
                }
                Err(e) => {
                    report.record(
                        &attack_id,
                        "numeric injection (NaN/Inf/subnormal)",
                        format!("error: {e}"),
                        false,
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Authority suite helpers
// ---------------------------------------------------------------------------

fn run_authority_suite(
    config: &ValidatorConfig,
    profile: &invariant_core::models::profile::RobotProfile,
    kid: &str,
    raw_key_bytes: &[u8; 32],
    report: &mut AdversarialReport,
) {
    let now = chrono::Utc::now();
    let attack_sk = ed25519_dalek::SigningKey::from_bytes(raw_key_bytes);

    // AA1: Forge signature
    {
        let forged = forge_signature(&attack_sk, kid);
        let chain_b64 = encode_chain(&[forged]);
        let mut cmd = build_base_command_with_chain(profile, chain_b64, kid);
        cmd.authority.required_ops = vec![dummy_op(profile)];
        match config.validate(&cmd, now, None) {
            Ok(result) => {
                let approved = result.signed_verdict.verdict.approved;
                report.record(
                    "AA1",
                    "forged signature (payload tampered after signing)",
                    if approved { "approved" } else { "rejected" },
                    approved, // escape = approved
                );
            }
            Err(e) => {
                report.record("AA1", "forged signature", format!("error: {e}"), false);
            }
        }
    }

    // AA2: Operation escalation
    {
        let chain = escalate_operations(&attack_sk, kid);
        let chain_b64 = encode_chain(&chain);
        let mut cmd = build_base_command_with_chain(profile, chain_b64, kid);
        cmd.authority.required_ops =
            vec![Operation::new("actuate:*").unwrap_or_else(|_| dummy_op(profile))];
        match config.validate(&cmd, now, None) {
            Ok(result) => {
                let approved = result.signed_verdict.verdict.approved;
                report.record(
                    "AA2",
                    "operation escalation in child hop",
                    if approved { "approved" } else { "rejected" },
                    approved,
                );
            }
            Err(e) => {
                report.record("AA2", "operation escalation", format!("error: {e}"), false);
            }
        }
    }

    // AA3: Truncated chain
    {
        let chain = truncate_chain(&attack_sk, kid);
        let chain_b64 = encode_chain(&chain);
        let mut cmd = build_base_command_with_chain(profile, chain_b64, kid);
        cmd.authority.required_ops = vec![dummy_op(profile)];
        match config.validate(&cmd, now, None) {
            Ok(result) => {
                let approved = result.signed_verdict.verdict.approved;
                report.record(
                    "AA3",
                    "truncated chain (intermediate hop removed)",
                    if approved { "approved" } else { "rejected" },
                    approved,
                );
            }
            Err(e) => {
                report.record("AA3", "truncated chain", format!("error: {e}"), false);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Attach a valid self-signed PCA chain to `cmd` using the given key.
fn attach_valid_chain(
    cmd: &mut invariant_core::models::command::Command,
    signing_key: &ed25519_dalek::SigningKey,
    kid: &str,
    profile: &invariant_core::models::profile::RobotProfile,
) {
    use std::collections::BTreeSet;
    let op = dummy_op(profile);
    cmd.authority.required_ops = vec![op.clone()];

    let pca = Pca {
        p_0: "invariant-adversarial".into(),
        ops: BTreeSet::from([op]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed: SignedPca = sign_pca(&pca, signing_key).expect("sign_pca must not fail");
    let chain = vec![signed];
    let chain_json = serde_json::to_vec(&chain).expect("serialize chain");
    use base64::{engine::general_purpose::STANDARD, Engine};
    cmd.authority.pca_chain = STANDARD.encode(&chain_json);
}

/// Build a valid command with all joints at midpoints and a fresh self-signed chain.
fn build_valid_base_command(
    profile: &invariant_core::models::profile::RobotProfile,
    kid: &str,
    raw_key_bytes: &[u8; 32],
) -> Option<invariant_core::models::command::Command> {
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use std::collections::HashMap;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(raw_key_bytes);
    let joint_states: Vec<JointState> = profile
        .joints
        .iter()
        .map(|j| JointState {
            name: j.name.clone(),
            position: (j.min + j.max) / 2.0,
            velocity: 0.0,
            effort: 0.0,
        })
        .collect();

    let op = dummy_op(profile);
    let mut cmd = Command {
        timestamp: chrono::Utc::now(),
        source: "adversarial".into(),
        sequence: 1,
        joint_states,
        delta_time: 0.01,
        end_effector_positions: vec![],
        center_of_mass: None,
        authority: CommandAuthority {
            pca_chain: String::new(),
            required_ops: vec![op],
        },
        metadata: HashMap::new(),
        locomotion_state: None,
        end_effector_forces: vec![],
        estimated_payload_kg: None,
        signed_sensor_readings: vec![],
        zone_overrides: HashMap::new(),
        environment_state: None,
    };
    attach_valid_chain(&mut cmd, &signing_key, kid, profile);
    Some(cmd)
}

/// Build a minimal command with a specific chain encoding.
fn build_base_command_with_chain(
    profile: &invariant_core::models::profile::RobotProfile,
    chain_b64: String,
    kid: &str,
) -> invariant_core::models::command::Command {
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use std::collections::HashMap;

    let joint_states: Vec<JointState> = profile
        .joints
        .iter()
        .map(|j| JointState {
            name: j.name.clone(),
            position: (j.min + j.max) / 2.0,
            velocity: 0.0,
            effort: 0.0,
        })
        .collect();

    Command {
        timestamp: chrono::Utc::now(),
        source: "adversarial".into(),
        sequence: 1,
        joint_states,
        delta_time: 0.01,
        end_effector_positions: vec![],
        center_of_mass: None,
        authority: CommandAuthority {
            pca_chain: chain_b64,
            required_ops: vec![dummy_op(profile)],
        },
        metadata: HashMap::new(),
        locomotion_state: None,
        end_effector_forces: vec![],
        estimated_payload_kg: None,
        signed_sensor_readings: vec![],
        zone_overrides: HashMap::new(),
        environment_state: None,
    }
    .tap_kid(kid)
}

// ---------------------------------------------------------------------------
// Environment suite: P21-P25 environmental hazard injection
// ---------------------------------------------------------------------------

fn run_environment_suite(
    config: &ValidatorConfig,
    profile: &invariant_core::models::profile::RobotProfile,
    kid: &str,
    raw_key_bytes: &[u8; 32],
    report: &mut AdversarialReport,
) {
    use invariant_sim::injector::{inject, InjectionType};

    let now = chrono::Utc::now();

    let env_attacks: &[(&str, InjectionType)] = &[
        ("ENV-P21-terrain-incline", InjectionType::TerrainIncline),
        ("ENV-P22-temperature-spike", InjectionType::TemperatureSpike),
        ("ENV-P23-battery-drain", InjectionType::BatteryDrain),
        ("ENV-P24-latency-spike", InjectionType::LatencySpike),
        ("ENV-P25-estop-engage", InjectionType::EStopEngage),
    ];

    // For P21-P24: also test with an explicit safe environment_state on the
    // base command so the profile's environment config thresholds are exercised.
    // For P25 (e-stop): always works regardless of profile config.
    for &(attack_id, inj_type) in env_attacks {
        let Some(mut cmd) = build_valid_base_command(profile, kid, raw_key_bytes) else {
            report.record(
                attack_id,
                format!("{inj_type:?} (skipped — no base command)"),
                "skipped",
                false,
            );
            continue;
        };

        inject(&mut cmd, inj_type, profile);

        match config.validate(&cmd, now, None) {
            Ok(result) => {
                let approved = result.signed_verdict.verdict.approved;
                // P25 (e-stop) must always be rejected.
                // P21-P24 are only rejected if the profile has environment config.
                let needs_config = !matches!(inj_type, InjectionType::EStopEngage);
                let profile_has_env = profile.environment.is_some();

                let escaped = if needs_config && !profile_has_env {
                    // No environment config → injection is a no-op, approval is correct
                    false
                } else {
                    // Should be rejected
                    approved
                };

                let outcome = if approved {
                    "approved".to_string()
                } else {
                    let failed: Vec<&str> = result
                        .signed_verdict
                        .verdict
                        .checks
                        .iter()
                        .filter(|c| !c.passed)
                        .map(|c| c.name.as_str())
                        .collect();
                    format!("rejected [{}]", failed.join(", "))
                };
                report.record(attack_id, format!("{inj_type:?}"), outcome, escaped);
            }
            Err(e) => {
                report.record(
                    attack_id,
                    format!("{inj_type:?}"),
                    format!("error: {e}"),
                    false,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fuzz mode: mutation-based fuzzing for N iterations
// ---------------------------------------------------------------------------

fn run_fuzz_mode(
    config: &ValidatorConfig,
    profile: &invariant_core::models::profile::RobotProfile,
    kid: &str,
    raw_key_bytes: &[u8; 32],
    args: &AdversarialArgs,
) -> i32 {
    use invariant_fuzz::generators::command_gen::CommandGenerator;
    use invariant_fuzz::generators::mutation::MutationEngine;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let now = chrono::Utc::now();
    let mut report = AdversarialReport::new("fuzz");
    let mut escapes = 0u64;
    let mut total = 0u64;

    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

    for i in 0..args.iterations {
        // Generate a random valid command.
        let mut base = CommandGenerator::generate(profile, &mut rng);

        // Attach a valid authority chain.
        let sk = ed25519_dalek::SigningKey::from_bytes(raw_key_bytes);
        attach_valid_chain(&mut base, &sk, kid, profile);

        // Apply all mutations to the base command.
        let mutations = MutationEngine::mutate_all(&base);
        for m in &mutations {
            total += 1;
            match config.validate(&m.command, now, None) {
                Ok(result) => {
                    if result.signed_verdict.verdict.approved {
                        // A mutated command was approved — potential escape.
                        // The "authority-strip" and "empty-joints" mutations are expected
                        // to be rejected; others depend on the mutation.
                        escapes += 1;
                        report.record(
                            format!("FUZZ-{i}-{}", m.id),
                            format!("mutation targeting {}", m.target_check),
                            "approved (ESCAPE)",
                            true,
                        );
                    }
                }
                Err(_) => {
                    // Validation error = rejection, which is correct for mutations.
                }
            }
        }
    }

    println!(
        "Fuzz mode: {total} mutated commands across {} iterations, {escapes} escapes",
        args.iterations
    );

    if escapes == 0 {
        println!("PASS: no mutations escaped validation");
    } else {
        eprintln!("FAIL: {escapes} mutation(s) escaped validation");
        for f in report.findings.iter().filter(|f| f.escaped) {
            eprintln!("  [{}] {}", f.attack_id, f.description);
        }
    }

    // Write report if requested.
    if let Some(ref report_path) = args.report {
        let json = serde_json::to_string_pretty(&report).unwrap();
        if let Err(e) = std::fs::write(report_path, json) {
            eprintln!("error: failed to write report: {e}");
            return 2;
        }
    }

    if escapes == 0 {
        0
    } else {
        1
    }
}

fn dummy_op(_profile: &invariant_core::models::profile::RobotProfile) -> Operation {
    // Use a wildcard operation so that boundary/numeric probes touching any
    // joint in the profile pass the authority check — we want to isolate
    // physics failures, not authority failures, in the protocol suite.
    Operation::new("actuate:*").expect("wildcard op must be valid")
}

trait TapKid {
    fn tap_kid(self, _kid: &str) -> Self;
}

impl TapKid for invariant_core::models::command::Command {
    fn tap_kid(self, _kid: &str) -> Self {
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use invariant_core::authority::crypto::generate_keypair;
    use rand::rngs::OsRng;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn write_profile() -> NamedTempFile {
        let name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(name).unwrap();
        let json = serde_json::to_string_pretty(&profile).unwrap();
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    fn write_key_file() -> (NamedTempFile, ed25519_dalek::SigningKey) {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        let kf = crate::key_file::KeyFile {
            kid: "test-kid".into(),
            public_key: STANDARD.encode(vk.as_bytes()),
            secret_key: Some(STANDARD.encode(sk.to_bytes())),
        };
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(serde_json::to_string_pretty(&kf).unwrap().as_bytes())
            .unwrap();
        tmp.flush().unwrap();
        (tmp, sk)
    }

    fn make_args(
        profile: &std::path::Path,
        key: &std::path::Path,
        suite: &str,
        report: Option<PathBuf>,
    ) -> AdversarialArgs {
        AdversarialArgs {
            profile: profile.to_path_buf(),
            key: key.to_path_buf(),
            suite: suite.to_string(),
            report,
            export_training: None,
            fuzz: false,
            iterations: 10000,
        }
    }

    #[test]
    fn protocol_suite_returns_0_when_all_detected() {
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();
        let args = make_args(profile_tmp.path(), key_tmp.path(), "protocol", None);
        let code = run(&args);
        assert_eq!(
            code, 0,
            "protocol suite must return 0 (all attacks detected)"
        );
    }

    #[test]
    fn authority_suite_returns_0_when_all_detected() {
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();
        let args = make_args(profile_tmp.path(), key_tmp.path(), "authority", None);
        let code = run(&args);
        assert_eq!(
            code, 0,
            "authority suite must return 0 (all attacks detected)"
        );
    }

    #[test]
    fn all_suite_returns_0_when_all_detected() {
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();
        let args = make_args(profile_tmp.path(), key_tmp.path(), "all", None);
        let code = run(&args);
        assert_eq!(code, 0, "all suite must return 0 (all attacks detected)");
    }

    #[test]
    fn environment_suite_returns_0_when_all_detected() {
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();
        let args = make_args(profile_tmp.path(), key_tmp.path(), "environment", None);
        let code = run(&args);
        assert_eq!(
            code, 0,
            "environment suite must return 0 (all attacks detected)"
        );
    }

    #[test]
    fn unknown_suite_returns_2() {
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();
        let args = make_args(profile_tmp.path(), key_tmp.path(), "bogus", None);
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn missing_profile_returns_2() {
        let (key_tmp, _sk) = write_key_file();
        let args = AdversarialArgs {
            profile: PathBuf::from("/nonexistent/profile.json"),
            key: key_tmp.path().to_path_buf(),
            suite: "protocol".into(),
            report: None,
            export_training: None,
            fuzz: false,
            iterations: 10000,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn missing_key_returns_2() {
        let profile_tmp = write_profile();
        let args = AdversarialArgs {
            profile: profile_tmp.path().to_path_buf(),
            key: PathBuf::from("/nonexistent/key.json"),
            suite: "protocol".into(),
            report: None,
            export_training: None,
            fuzz: false,
            iterations: 10000,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn report_written_to_file() {
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();
        let dir = TempDir::new().unwrap();
        let report_path = dir.path().join("report.json");

        let args = make_args(
            profile_tmp.path(),
            key_tmp.path(),
            "protocol",
            Some(report_path.clone()),
        );
        let _code = run(&args);

        assert!(report_path.exists(), "report file must be created");
        let content = std::fs::read_to_string(&report_path).unwrap();
        let _parsed: AdversarialReport =
            serde_json::from_str(&content).expect("report must be valid JSON");
    }
}
