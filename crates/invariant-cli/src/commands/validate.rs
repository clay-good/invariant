use clap::{Args, ValueEnum};
use std::collections::HashMap;
use std::io::Read;
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

    // Build trusted keys: in all modes, trust the Invariant instance's own key.
    let mut trusted_keys = HashMap::new();
    trusted_keys.insert(kid.clone(), verifying_key);

    // Build validator config.
    let config = match ValidatorConfig::new(profile, trusted_keys, signing_key.clone(), kid.clone())
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Create audit logger (needs a second copy of the signing key since SigningKey doesn't Clone).
    let audit_sk = SigningKey::from_bytes(&signing_key.to_bytes());
    let mut logger =
        match invariant_core::audit::AuditLogger::new(&args.audit_log, audit_sk, kid.clone()) {
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
    let mut any_rejected = false;
    for mut cmd in commands {
        // In forge mode, auto-generate a self-signed PCA chain.
        if matches!(args.mode, ValidationMode::Forge) {
            if let Err(e) = forge_authority(&mut cmd, &signing_key, &kid) {
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

                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
            }
            Err(e) => {
                eprintln!("error: validation failed: {e}");
                return 2;
            }
        }
    }

    // Exit code depends on mode.
    match args.mode {
        ValidationMode::Shadow => 0, // shadow never blocks
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
        let data =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let mut commands = Vec::new();
        for (i, line) in data.lines().enumerate() {
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
        // Read from stdin.
        let mut buf = String::new();
        std::io::stdin()
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

