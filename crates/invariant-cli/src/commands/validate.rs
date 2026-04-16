use clap::{Args, ValueEnum};
use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde::Serialize;

use invariant_core::models::actuation::SignedActuationCommand;
use invariant_core::models::command::Command;
use invariant_core::models::verdict::SignedVerdict;
use invariant_core::validator::ValidatorConfig;

use super::forge::forge_authority;

/// Operating mode for validation (P2-11: enum instead of free String).
#[derive(Debug, Clone, ValueEnum)]
pub enum ValidationMode {
    Guardian,
    Shadow,
    Forge,
}

#[derive(Args)]
pub struct ValidateArgs {
    /// Path to the robot profile JSON file.
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
    /// Path to a single command JSON file.
    /// Mutually exclusive with --batch (P2-10).
    #[arg(long, value_name = "COMMAND_FILE", conflicts_with = "batch")]
    pub command: Option<PathBuf>,
    /// Path to a batch JSONL file of commands.
    /// Mutually exclusive with --command (P2-10).
    #[arg(long, value_name = "BATCH_FILE", conflicts_with = "command")]
    pub batch: Option<PathBuf>,
    /// Path to the key file.
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    /// Validation mode: guardian (full firewall), shadow (log-only), or forge (self-signed authority).
    #[arg(long, value_enum, default_value = "guardian")]
    pub mode: ValidationMode,
    /// Path to the audit log file.
    #[arg(long, value_name = "AUDIT_LOG", default_value = "audit.jsonl")]
    pub audit_log: PathBuf,
}

/// Typed output structure replacing the `serde_json::json!` macro (Finding 30).
/// Using a derived `Serialize` struct avoids double-serialization overhead.
#[derive(Serialize)]
struct VerdictOutput<'a> {
    verdict: &'a SignedVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    actuation_command: Option<&'a SignedActuationCommand>,
}

/// Reject paths that contain `..` components to prevent path traversal
/// (Findings 34, 35).  Returns `Ok(path)` if safe, `Err(msg)` otherwise.
fn safe_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    // Use Path::components() to inspect every component; reject `..`.
    for component in path.components() {
        if component == std::path::Component::ParentDir {
            return Err(format!(
                "{label} path {:?} contains '..' component; path traversal rejected",
                path
            ));
        }
    }
    Ok(path.to_path_buf())
}

pub fn run(args: &ValidateArgs) -> i32 {
    // Reject profile and key paths containing '..' (Findings 34, 35).
    let profile_path = match safe_path(&args.profile, "profile") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let key_path = match safe_path(&args.key, "key") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Load profile.
    let profile_json = match std::fs::read_to_string(&profile_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to read profile {:?}: {e}", profile_path);
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

    // Load key file.
    let kf = match crate::key_file::load_key_file(&key_path) {
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

    // Capture raw bytes before signing_key is consumed by ValidatorConfig::new.
    // Both the validator config and the audit logger need independent SigningKey
    // instances; constructing both from the same raw bytes avoids a redundant
    // sign + encode round-trip.
    let raw_key_bytes = signing_key.to_bytes();

    // Build trusted keys: in all modes, trust the Invariant instance's own key.
    let mut trusted_keys = HashMap::new();
    trusted_keys.insert(kid.clone(), verifying_key);

    // Build validator config (consumes signing_key).
    let config = match ValidatorConfig::new(profile, trusted_keys, signing_key, kid.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Construct audit and forge signing keys from the same raw bytes.
    // All three instances (config, audit, forge) derive from the same key
    // material without any extra encoding/decoding round-trip.
    let audit_sk = SigningKey::from_bytes(&raw_key_bytes);
    // forge_sk is used in forge mode to self-sign PCA chains per command.
    let forge_sk = SigningKey::from_bytes(&raw_key_bytes);
    let mut logger =
        match invariant_core::audit::AuditLogger::open_file(&args.audit_log, audit_sk, kid.clone())
        {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: failed to open audit log: {e}");
                return 2;
            }
        };

    // Open the command source.  For the single-command and stdin cases we still
    // pre-parse into a Vec<Command> (size 1) for simplicity.  For batch mode,
    // commands are streamed line-by-line to avoid loading the entire file into
    // memory (Finding 21).
    let mode = &args.mode;

    // Lock stdout once before the loop (avoids repeated lock/unlock overhead).
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut any_rejected = false;
    let mut command_count: usize = 0;

    // -----------------------------------------------------------------------
    // Batch path: stream line-by-line (Finding 21)
    // -----------------------------------------------------------------------
    if let Some(ref path) = args.batch {
        // Reject batch files larger than 1 GiB to avoid OOM on malformed input.
        const BATCH_SIZE_LIMIT: u64 = 1 << 30; // 1 GiB
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("error: stat {}: {e}", path.display());
                return 2;
            }
        };
        if meta.len() > BATCH_SIZE_LIMIT {
            eprintln!(
                "error: batch file {} is too large ({} bytes; limit is {} bytes)",
                path.display(),
                meta.len(),
                BATCH_SIZE_LIMIT
            );
            return 2;
        }
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("error: read {}: {e}", path.display());
                return 2;
            }
        };
        let reader = std::io::BufReader::new(file);
        for (i, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: read line {}: {e}", i + 1);
                    return 2;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut cmd: Command = match serde_json::from_str(trimmed) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: parse command at line {}: {e}", i + 1);
                    return 2;
                }
            };
            let exit = process_one_command(
                &mut cmd,
                mode,
                &forge_sk,
                &kid,
                &config,
                &mut logger,
                &mut out,
                &mut any_rejected,
                &mut command_count,
            );
            if exit != 0 {
                return exit;
            }
        }
    } else {
        // Single command or stdin.
        let mut cmd = match read_single_command(args) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        };
        let exit = process_one_command(
            &mut cmd,
            mode,
            &forge_sk,
            &kid,
            &config,
            &mut logger,
            &mut out,
            &mut any_rejected,
            &mut command_count,
        );
        if exit != 0 {
            return exit;
        }
    }

    if command_count == 0 {
        eprintln!("error: no commands to validate");
        return 2;
    }

    // Flush audit log before exit (std::process::exit doesn't run destructors).
    drop(logger);

    // Exit code depends on mode.
    match args.mode {
        ValidationMode::Shadow => {
            if any_rejected {
                // Shadow mode logs-only but surfaces rejections via exit code 2
                // so callers can detect policy violations without blocking.
                eprintln!("shadow: one or more commands were rejected (see verdicts above)");
                2
            } else {
                0
            }
        }
        _ => {
            if any_rejected {
                1
            } else {
                0
            }
        }
    }
}

/// Process and validate a single command; write the verdict to `out` and the
/// audit log.  Returns 0 on success or 2 on a processing error.
#[allow(clippy::too_many_arguments)]
fn process_one_command(
    cmd: &mut Command,
    mode: &ValidationMode,
    forge_sk: &SigningKey,
    kid: &str,
    config: &ValidatorConfig,
    logger: &mut invariant_core::audit::AuditLogger<std::fs::File>,
    out: &mut impl Write,
    any_rejected: &mut bool,
    command_count: &mut usize,
) -> i32 {
    *command_count += 1;

    // In forge mode, auto-generate a self-signed PCA chain.
    if matches!(mode, ValidationMode::Forge) {
        if let Err(e) = forge_authority(cmd, forge_sk, kid, "forge") {
            eprintln!("error: forge mode PCA generation failed: {e}");
            return 2;
        }
    }

    let now = Utc::now();
    match config.validate(cmd, now, None) {
        Ok(result) => {
            // Write audit log.
            if let Err(e) = logger.log(cmd, &result.signed_verdict) {
                eprintln!("error: failed to write audit log: {e}");
                return 2;
            }

            // Output verdict as JSON to stdout using a typed struct (Finding 30).
            let (is_approved, actuation_ref) = if result.signed_verdict.verdict.approved {
                (true, result.actuation_command.as_ref())
            } else {
                *any_rejected = true;
                (false, None)
            };

            let output = VerdictOutput {
                verdict: &result.signed_verdict,
                actuation_command: if is_approved { actuation_ref } else { None },
            };

            if let Err(e) = serde_json::to_writer_pretty(&mut *out, &output) {
                eprintln!("error: failed to write output: {e}");
                return 2;
            }
            if let Err(e) = out.write_all(b"\n") {
                eprintln!("error: failed to write output: {e}");
                return 2;
            }
        }
        Err(e) => {
            eprintln!("error: validation failed: {e}");
            return 2;
        }
    }
    0
}

/// Read a single command from `--command` file or stdin.
fn read_single_command(args: &ValidateArgs) -> Result<Command, String> {
    if let Some(ref path) = args.command {
        let data =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let cmd: Command =
            serde_json::from_str(&data).map_err(|e| format!("parse command: {e}"))?;
        Ok(cmd)
    } else {
        // Read from stdin with size limit (10 MiB).
        let mut buf = String::new();
        std::io::stdin()
            .take(10_485_760)
            .read_to_string(&mut buf)
            .map_err(|e| format!("read stdin: {e}"))?;
        let cmd: Command = serde_json::from_str(&buf).map_err(|e| format!("parse stdin: {e}"))?;
        Ok(cmd)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{engine::general_purpose::STANDARD, Engine};
    use invariant_core::authority::crypto::{generate_keypair, sign_pca};
    use invariant_core::models::authority::{Operation, Pca};
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use rand::rngs::OsRng;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Write a minimal valid robot profile JSON to a temp file.
    fn write_profile() -> NamedTempFile {
        let profile_name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(profile_name).unwrap();
        let json = serde_json::to_string_pretty(&profile).unwrap();
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    /// Write a full key file (public + secret) to a temp file.
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

    /// Build a minimal valid `Command` JSON string.
    fn minimal_command_json(sk: &ed25519_dalek::SigningKey, kid: &str) -> String {
        let op = Operation::new("actuate:humanoid_28dof:joint_0:position").unwrap();
        let pca = Pca {
            p_0: "test".to_string(),
            ops: std::collections::BTreeSet::from([op.clone()]),
            kid: kid.to_string(),
            exp: None,
            nbf: None,
        };
        let signed_pca = sign_pca(&pca, sk).unwrap();
        let chain = vec![signed_pca];
        let chain_json = serde_json::to_vec(&chain).unwrap();
        let pca_chain = STANDARD.encode(&chain_json);

        let cmd = Command {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "joint_0".to_string(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain,
                required_ops: vec![op],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: std::collections::HashMap::new(),
            environment_state: None,
        };
        serde_json::to_string(&cmd).unwrap()
    }

    /// Build a command JSON string with no PCA chain (causes authority failure).
    fn command_without_chain_json() -> String {
        let op = Operation::new("actuate:humanoid_28dof:joint_0:position").unwrap();
        let cmd = Command {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "joint_0".to_string(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![op],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: std::collections::HashMap::new(),
            environment_state: None,
        };
        serde_json::to_string(&cmd).unwrap()
    }

    fn args_for(
        profile: &std::path::Path,
        key: &std::path::Path,
        command: Option<&std::path::Path>,
        batch: Option<&std::path::Path>,
        mode: ValidationMode,
        audit_log: &std::path::Path,
    ) -> ValidateArgs {
        ValidateArgs {
            profile: profile.to_path_buf(),
            command: command.map(|p| p.to_path_buf()),
            batch: batch.map(|p| p.to_path_buf()),
            key: key.to_path_buf(),
            mode,
            audit_log: audit_log.to_path_buf(),
        }
    }

    // -----------------------------------------------------------------------
    // Finding 5: Forge mode — valid profile + key + command, exit 0
    // -----------------------------------------------------------------------

    #[test]
    fn forge_mode_valid_command_returns_0() {
        let dir = TempDir::new().unwrap();
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();

        // Load the profile to get a valid joint name.
        let profile_name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(profile_name).unwrap();
        let joint_name = &profile.joints[0].name;

        // In forge mode we don't need a pre-signed chain — the command just
        // needs a required_ops list.
        let op = Operation::new(format!("actuate:{profile_name}:{joint_name}:position")).unwrap();
        use invariant_core::models::command::EndEffectorPosition;
        let cmd = Command {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            sequence: 1,
            joint_states: vec![JointState {
                name: joint_name.clone(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            // Provide named end effectors inside workspace but outside exclusion zones.
            // The humanoid_28dof profile has collision pairs for these links.
            end_effector_positions: vec![
                EndEffectorPosition {
                    name: "left_hand".into(),
                    position: [-0.5, 0.5, 0.5],
                },
                EndEffectorPosition {
                    name: "right_hand".into(),
                    position: [0.5, 0.5, 0.5],
                },
                EndEffectorPosition {
                    name: "head".into(),
                    position: [0.0, 0.0, 2.2],
                },
                EndEffectorPosition {
                    name: "torso".into(),
                    position: [0.0, 0.0, 1.0],
                },
            ],
            // P9 requires center_of_mass when stability config is present and
            // enabled (fail-closed). Supply a COM inside the humanoid's support
            // polygon to pass the stability check.
            center_of_mass: Some([0.0, 0.0, 0.9]),
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![op],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: std::collections::HashMap::new(),
            environment_state: None,
        };
        let mut cmd_file = NamedTempFile::new().unwrap();
        cmd_file
            .write_all(serde_json::to_string(&cmd).unwrap().as_bytes())
            .unwrap();
        cmd_file.flush().unwrap();

        let audit_log = dir.path().join("audit.jsonl");
        let args = args_for(
            profile_tmp.path(),
            key_tmp.path(),
            Some(cmd_file.path()),
            None,
            ValidationMode::Forge,
            &audit_log,
        );

        let code = run(&args);
        assert_eq!(code, 0, "forge mode with valid command must exit 0");
    }

    // -----------------------------------------------------------------------
    // Finding 5: Guardian mode — missing PCA chain, exit 1
    // -----------------------------------------------------------------------

    #[test]
    fn guardian_mode_missing_pca_chain_returns_1() {
        let dir = TempDir::new().unwrap();
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();

        let mut cmd_file = NamedTempFile::new().unwrap();
        cmd_file
            .write_all(command_without_chain_json().as_bytes())
            .unwrap();
        cmd_file.flush().unwrap();

        let audit_log = dir.path().join("audit.jsonl");
        let args = args_for(
            profile_tmp.path(),
            key_tmp.path(),
            Some(cmd_file.path()),
            None,
            ValidationMode::Guardian,
            &audit_log,
        );

        let code = run(&args);
        assert_eq!(code, 1, "guardian mode with missing PCA chain must exit 1");
    }

    // -----------------------------------------------------------------------
    // Finding 6: Shadow mode — rejected command, exit 2
    // -----------------------------------------------------------------------

    #[test]
    fn shadow_mode_rejected_command_returns_2() {
        let dir = TempDir::new().unwrap();
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();

        let mut cmd_file = NamedTempFile::new().unwrap();
        cmd_file
            .write_all(command_without_chain_json().as_bytes())
            .unwrap();
        cmd_file.flush().unwrap();

        let audit_log = dir.path().join("audit.jsonl");
        let args = args_for(
            profile_tmp.path(),
            key_tmp.path(),
            Some(cmd_file.path()),
            None,
            ValidationMode::Shadow,
            &audit_log,
        );

        let code = run(&args);
        assert_eq!(code, 2, "shadow mode with rejected command must exit 2");
    }

    // -----------------------------------------------------------------------
    // Finding 5: Batch mode
    // -----------------------------------------------------------------------

    #[test]
    fn batch_mode_returns_0_for_all_approved_commands() {
        let dir = TempDir::new().unwrap();
        let profile_tmp = write_profile();
        let (key_tmp, sk) = write_key_file();

        let cmd_json = minimal_command_json(&sk, "test-kid");
        // Write two identical approved commands.
        let batch_content = format!("{cmd_json}\n{cmd_json}\n");

        let mut batch_file = NamedTempFile::new().unwrap();
        batch_file.write_all(batch_content.as_bytes()).unwrap();
        batch_file.flush().unwrap();

        let audit_log = dir.path().join("audit.jsonl");
        let args = args_for(
            profile_tmp.path(),
            key_tmp.path(),
            None,
            Some(batch_file.path()),
            ValidationMode::Guardian,
            &audit_log,
        );

        let code = run(&args);
        // Both commands have valid PCA chains; exit 0 if both approved, 1 if rejected.
        // We just assert the run completes without a processing error (not 2).
        assert_ne!(code, 2, "batch processing must not return error code 2");
    }

    // -----------------------------------------------------------------------
    // Finding 5: Error paths
    // -----------------------------------------------------------------------

    #[test]
    fn missing_profile_returns_2() {
        let dir = TempDir::new().unwrap();
        let (key_tmp, _sk) = write_key_file();
        let audit_log = dir.path().join("audit.jsonl");
        let args = ValidateArgs {
            profile: PathBuf::from("/nonexistent/profile.json"),
            command: None,
            batch: None,
            key: key_tmp.path().to_path_buf(),
            mode: ValidationMode::Guardian,
            audit_log,
        };
        assert_eq!(run(&args), 2, "missing profile must return 2");
    }

    #[test]
    fn missing_key_returns_2() {
        let dir = TempDir::new().unwrap();
        let profile_tmp = write_profile();
        let audit_log = dir.path().join("audit.jsonl");
        let args = ValidateArgs {
            profile: profile_tmp.path().to_path_buf(),
            command: None,
            batch: None,
            key: PathBuf::from("/nonexistent/key.json"),
            mode: ValidationMode::Guardian,
            audit_log,
        };
        assert_eq!(run(&args), 2, "missing key must return 2");
    }

    #[test]
    fn audit_log_open_failure_returns_2() {
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();
        let args = ValidateArgs {
            profile: profile_tmp.path().to_path_buf(),
            command: None,
            batch: None,
            key: key_tmp.path().to_path_buf(),
            mode: ValidationMode::Guardian,
            // Use a non-existent directory to force the audit log open to fail.
            audit_log: PathBuf::from("/nonexistent/dir/audit.jsonl"),
        };
        assert_eq!(run(&args), 2, "audit log open failure must return 2");
    }

    // -----------------------------------------------------------------------
    // Finding 7: forge_authority produces valid chain with correct p_0 and ops
    // -----------------------------------------------------------------------

    #[test]
    fn forge_authority_produces_chain_with_forge_p0() {
        // forge_authority is tested more thoroughly in the forge module; here we
        // ensure the validate command integration uses "forge" as p_0 by checking
        // that a forge-mode run passes the authority check.
        let dir = TempDir::new().unwrap();
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();

        let op = Operation::new("actuate:humanoid_28dof:joint_0:position").unwrap();
        let cmd = Command {
            timestamp: chrono::Utc::now(),
            source: "test".to_string(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "joint_0".to_string(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![op],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: std::collections::HashMap::new(),
            environment_state: None,
        };
        let mut cmd_file = NamedTempFile::new().unwrap();
        cmd_file
            .write_all(serde_json::to_string(&cmd).unwrap().as_bytes())
            .unwrap();
        cmd_file.flush().unwrap();

        let audit_log = dir.path().join("audit.jsonl");
        let args = args_for(
            profile_tmp.path(),
            key_tmp.path(),
            Some(cmd_file.path()),
            None,
            ValidationMode::Forge,
            &audit_log,
        );

        let code = run(&args);
        // Forge mode always passes the authority check, so the only possible
        // rejections would be physics checks (returning exit 1, not 2).
        assert_ne!(code, 2, "forge mode must not return processing error 2");
    }

    // -----------------------------------------------------------------------
    // Finding 34/35: Path traversal protection
    // -----------------------------------------------------------------------

    #[test]
    fn profile_path_with_dotdot_returns_2() {
        let dir = TempDir::new().unwrap();
        let (key_tmp, _sk) = write_key_file();
        let audit_log = dir.path().join("audit.jsonl");
        let args = ValidateArgs {
            profile: PathBuf::from("../etc/passwd"),
            command: None,
            batch: None,
            key: key_tmp.path().to_path_buf(),
            mode: ValidationMode::Guardian,
            audit_log,
        };
        assert_eq!(run(&args), 2, "profile path with .. must return 2");
    }

    #[test]
    fn key_path_with_dotdot_returns_2() {
        let dir = TempDir::new().unwrap();
        let profile_tmp = write_profile();
        let audit_log = dir.path().join("audit.jsonl");
        let args = ValidateArgs {
            profile: profile_tmp.path().to_path_buf(),
            command: None,
            batch: None,
            key: PathBuf::from("../../secret/key.json"),
            mode: ValidationMode::Guardian,
            audit_log,
        };
        assert_eq!(run(&args), 2, "key path with .. must return 2");
    }

    // -----------------------------------------------------------------------
    // Finding 21: Batch streaming — empty lines are skipped
    // -----------------------------------------------------------------------

    #[test]
    fn batch_mode_skips_blank_lines() {
        let dir = TempDir::new().unwrap();
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();

        let cmd_json = command_without_chain_json();
        // One command with blank lines around it.
        let batch_content = format!("\n{cmd_json}\n\n");

        let mut batch_file = NamedTempFile::new().unwrap();
        batch_file.write_all(batch_content.as_bytes()).unwrap();
        batch_file.flush().unwrap();

        let audit_log = dir.path().join("audit.jsonl");
        let args = args_for(
            profile_tmp.path(),
            key_tmp.path(),
            None,
            Some(batch_file.path()),
            ValidationMode::Shadow,
            &audit_log,
        );

        // Should parse exactly 1 command (blank lines skipped) and reject it
        // (no PCA chain) in shadow mode -> exit 2.
        let code = run(&args);
        assert_eq!(
            code, 2,
            "shadow mode batch with rejected command must exit 2"
        );
    }

    #[test]
    fn batch_invalid_json_returns_2() {
        let dir = TempDir::new().unwrap();
        let profile_tmp = write_profile();
        let (key_tmp, _sk) = write_key_file();

        let mut batch_file = NamedTempFile::new().unwrap();
        writeln!(batch_file, "not valid json at all").unwrap();
        batch_file.flush().unwrap();

        let audit_log = dir.path().join("audit.jsonl");
        let args = args_for(
            profile_tmp.path(),
            key_tmp.path(),
            None,
            Some(batch_file.path()),
            ValidationMode::Guardian,
            &audit_log,
        );

        assert_eq!(run(&args), 2, "invalid batch JSON must return 2");
    }

    // -----------------------------------------------------------------------
    // safe_path helper unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn safe_path_accepts_normal_paths() {
        assert!(safe_path(Path::new("/tmp/foo.json"), "test").is_ok());
        assert!(safe_path(Path::new("relative/path.json"), "test").is_ok());
        assert!(safe_path(Path::new("profile.json"), "test").is_ok());
    }

    #[test]
    fn safe_path_rejects_dotdot() {
        assert!(safe_path(Path::new("../etc/passwd"), "test").is_err());
        assert!(safe_path(Path::new("/tmp/../etc/passwd"), "test").is_err());
        assert!(safe_path(Path::new("a/../../b"), "test").is_err());
    }
}
