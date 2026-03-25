use clap::{Args, ValueEnum};
use std::io::{self, Read};
use std::path::PathBuf;

use chrono::Utc;
use invariant_core::keys::KeyFile;
use invariant_core::models::command::Command;
use invariant_core::validator::ValidatorConfig;

/// Operating mode for validation (P2-11: enum instead of free String).
#[derive(Debug, Clone, ValueEnum)]
pub enum ValidationMode {
    Guardian,
    Shadow,
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
    /// Validation mode: guardian (full firewall) or shadow (log-only) (P2-11).
    #[arg(long, value_enum, default_value = "guardian")]
    pub mode: ValidationMode,
}

pub fn run(args: &ValidateArgs) -> i32 {
    // Load and decode key file.
    let decoded = match KeyFile::load_and_decode(&args.key) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("invariant validate: {e}");
            return 2;
        }
    };

    // Load profile.
    let profile = match invariant_core::profiles::load_from_file(&args.profile) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("invariant validate: failed to load profile: {e}");
            return 2;
        }
    };

    // Build validator config.
    let config = match ValidatorConfig::new(
        profile,
        decoded.trusted_keys(),
        decoded.signing_key,
        decoded.kid,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("invariant validate: {e}");
            return 2;
        }
    };

    // Load commands.
    let commands = match load_commands(args) {
        Ok(cmds) => cmds,
        Err(e) => {
            eprintln!("invariant validate: {e}");
            return 2;
        }
    };

    if commands.is_empty() {
        eprintln!("invariant validate: no commands to validate");
        return 2;
    }

    // Validate each command.
    let is_shadow = matches!(args.mode, ValidationMode::Shadow);
    let mut all_approved = true;
    let mut previous_joints = None;

    for (i, cmd) in commands.iter().enumerate() {
        let now = Utc::now();
        match config.validate(cmd, now, previous_joints.as_deref()) {
            Ok(result) => {
                let verdict = &result.signed_verdict;
                if !verdict.verdict.approved {
                    all_approved = false;
                }

                // Output the signed verdict as JSON.
                match serde_json::to_string(&verdict) {
                    Ok(json) => println!("{json}"),
                    Err(e) => {
                        eprintln!("invariant validate: failed to serialize verdict: {e}");
                        return 2;
                    }
                }

                // In guardian mode, also output the actuation command if approved.
                if !is_shadow {
                    if let Some(ref actuation) = result.actuation_command {
                        match serde_json::to_string(actuation) {
                            Ok(json) => {
                                eprintln!(
                                    "invariant validate: command {} approved, actuation signed",
                                    cmd.sequence
                                );
                                // Actuation command goes to stderr for separation.
                                // The verdict JSON on stdout is the primary output.
                                let _ = json; // actuation is internal; verdict is the output
                            }
                            Err(e) => {
                                eprintln!(
                                    "invariant validate: failed to serialize actuation: {e}"
                                );
                                return 2;
                            }
                        }
                    }
                }

                // Track joint states for next command in batch.
                if commands.len() > 1 {
                    previous_joints = Some(cmd.joint_states.clone());
                }
            }
            Err(e) => {
                eprintln!("invariant validate: command {i}: {e}");
                return 2;
            }
        }
    }

    if all_approved {
        0
    } else {
        1
    }
}

fn load_commands(args: &ValidateArgs) -> Result<Vec<Command>, String> {
    if let Some(ref path) = args.command {
        // Single command file.
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read command file: {e}"))?;
        let cmd: Command =
            serde_json::from_str(&data).map_err(|e| format!("failed to parse command: {e}"))?;
        Ok(vec![cmd])
    } else if let Some(ref path) = args.batch {
        // Batch JSONL file.
        let data =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read batch file: {e}"))?;
        parse_jsonl_commands(&data)
    } else {
        // Read from stdin.
        let mut data = String::new();
        io::stdin()
            .lock()
            .read_to_string(&mut data)
            .map_err(|e| format!("failed to read stdin: {e}"))?;

        // Try as single JSON first, then as JSONL.
        if let Ok(cmd) = serde_json::from_str::<Command>(&data) {
            Ok(vec![cmd])
        } else {
            parse_jsonl_commands(&data)
        }
    }
}

fn parse_jsonl_commands(data: &str) -> Result<Vec<Command>, String> {
    let mut commands = Vec::new();
    for (i, line) in data.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let cmd: Command = serde_json::from_str(trimmed)
            .map_err(|e| format!("failed to parse command at line {}: {e}", i + 1))?;
        commands.push(cmd);
    }
    Ok(commands)
}
