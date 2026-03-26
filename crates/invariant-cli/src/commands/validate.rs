use clap::{Args, ValueEnum};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use ed25519_dalek::SigningKey;

use invariant_core::authority::crypto::sign_pca;
use invariant_core::models::authority::Pca;
use invariant_core::models::command::Command;
use invariant_core::validator::ValidatorConfig;

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

pub fn run(args: &ValidateArgs) -> i32 {
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

    // Load key file.
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

    // Read commands.
    let commands = match read_commands(args) {
        Ok(cmds) => cmds,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    if commands.is_empty() {
        eprintln!("error: no commands to validate");
        return 2;
    }

    // Validate each command.
    // Lock stdout once before the loop: avoids repeated lock/unlock overhead
    // on every iteration and allows direct writing via to_writer_pretty,
    // eliminating the per-command intermediate String allocation.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut any_rejected = false;
    for mut cmd in commands {
        // In forge mode, auto-generate a self-signed PCA chain.
        if matches!(args.mode, ValidationMode::Forge) {
            if let Err(e) = forge_authority(&mut cmd, &forge_sk, &kid) {
                eprintln!("error: forge mode PCA generation failed: {e}");
                return 2;
            }
        }

        let now = Utc::now();
        match config.validate(&cmd, now, None) {
            Ok(result) => {
                // Write audit log.
                if let Err(e) = logger.log(&cmd, &result.signed_verdict) {
                    eprintln!("error: failed to write audit log: {e}");
                    return 2;
                }

                // Output verdict as JSON to stdout.
                let output = if result.signed_verdict.verdict.approved {
                    if let Some(ref actuation) = result.actuation_command {
                        serde_json::json!({
                            "verdict": result.signed_verdict,
                            "actuation_command": actuation,
                        })
                    } else {
                        serde_json::json!({ "verdict": result.signed_verdict })
                    }
                } else {
                    any_rejected = true;
                    serde_json::json!({ "verdict": result.signed_verdict })
                };

                if let Err(e) = serde_json::to_writer_pretty(&mut out, &output) {
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

/// Read commands from file, batch, or stdin.
fn read_commands(args: &ValidateArgs) -> Result<Vec<Command>, String> {
    if let Some(ref path) = args.command {
        let data =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let cmd: Command =
            serde_json::from_str(&data).map_err(|e| format!("parse command: {e}"))?;
        Ok(vec![cmd])
    } else if let Some(ref path) = args.batch {
        use std::io::BufRead;
        // Reject batch files larger than 1 GiB to avoid OOM on malformed input.
        const BATCH_SIZE_LIMIT: u64 = 1 << 30; // 1 GiB
        let meta = std::fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
        if meta.len() > BATCH_SIZE_LIMIT {
            return Err(format!(
                "batch file {} is too large ({} bytes; limit is {} bytes)",
                path.display(),
                meta.len(),
                BATCH_SIZE_LIMIT
            ));
        }
        let file =
            std::fs::File::open(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let reader = std::io::BufReader::new(file);
        let mut commands = Vec::new();
        for (i, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| format!("read line {}: {e}", i + 1))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let cmd: Command = serde_json::from_str(trimmed)
                .map_err(|e| format!("parse command at line {}: {e}", i + 1))?;
            commands.push(cmd);
        }
        Ok(commands)
    } else {
        // Read from stdin with size limit (10 MiB).
        let mut buf = String::new();
        std::io::stdin()
            .take(10_485_760)
            .read_to_string(&mut buf)
            .map_err(|e| format!("read stdin: {e}"))?;
        let cmd: Command = serde_json::from_str(&buf).map_err(|e| format!("parse stdin: {e}"))?;
        Ok(vec![cmd])
    }
}

/// In forge mode, generate a self-signed PCA chain that grants the command's required_ops.
fn forge_authority(cmd: &mut Command, signing_key: &SigningKey, kid: &str) -> Result<(), String> {
    let ops = cmd.authority.required_ops.iter().cloned().collect();

    let pca = Pca {
        p_0: "forge".to_string(),
        ops,
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };

    let signed = sign_pca(&pca, signing_key).map_err(|e| e.to_string())?;

    // Encode the chain as base64 JSON array of SignedPca.
    let chain = vec![signed];
    let chain_json = serde_json::to_vec(&chain).map_err(|e| e.to_string())?;
    cmd.authority.pca_chain = STANDARD.encode(&chain_json);

    Ok(())
}
