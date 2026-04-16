//! `invariant differential` — Dual-instance differential validation.
//!
//! Validates a command (or batch of commands) through two independent validator
//! instances and compares their verdicts. Disagreements indicate potential bugs,
//! hardware faults, or edge-case behavior near rejection thresholds.
//!
//! Both instances use the same robot profile and trusted keys but have
//! independent signing keys (dual-channel pattern from IEC 61508).

use clap::Args;
use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde::Serialize;

use invariant_core::differential::{DifferentialResult, DifferentialValidator};
use invariant_core::models::command::Command;
use invariant_core::validator::ValidatorConfig;

use super::forge::forge_authority;

#[derive(Args)]
pub struct DifferentialArgs {
    /// Path to the robot profile JSON file.
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
    /// Path to a single command JSON file.
    #[arg(long, value_name = "COMMAND_FILE", conflicts_with = "batch")]
    pub command: Option<PathBuf>,
    /// Path to a batch JSONL file of commands.
    #[arg(long, value_name = "BATCH_FILE", conflicts_with = "command")]
    pub batch: Option<PathBuf>,
    /// Path to the key file for instance A.
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    /// Path to a second key file for instance B (optional; if omitted, a
    /// fresh ephemeral key is generated for the second instance).
    #[arg(long, value_name = "KEY_FILE_B")]
    pub key_b: Option<PathBuf>,
    /// Use forge mode (self-signed authority) for testing.
    #[arg(long)]
    pub forge: bool,
}

#[derive(Serialize)]
struct DiffOutput<'a> {
    command_sequence: u64,
    fully_agrees: bool,
    #[serde(flatten)]
    result: &'a DifferentialResult,
}

pub fn run(args: &DifferentialArgs) -> i32 {
    // Load profile.
    let profile_json = match std::fs::read_to_string(&args.profile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not read profile: {e}");
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

    // Load key A.
    let kf_a = match crate::key_file::load_key_file(&args.key) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: key A: {e}");
            return 2;
        }
    };
    let (sk_a, vk_a, kid_a) = match crate::key_file::load_signing_key(&kf_a) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: key A: {e}");
            return 2;
        }
    };

    // Save raw bytes before sk_a is consumed.
    let forge_key_bytes = sk_a.to_bytes();

    // Load or generate key B.
    let (sk_b, vk_b, kid_b) = if let Some(ref key_b_path) = args.key_b {
        let kf_b = match crate::key_file::load_key_file(key_b_path) {
            Ok(kf) => kf,
            Err(e) => {
                eprintln!("error: key B: {e}");
                return 2;
            }
        };
        match crate::key_file::load_signing_key(&kf_b) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: key B: {e}");
                return 2;
            }
        }
    } else {
        // Generate ephemeral key for instance B.
        use rand::rngs::OsRng;
        let sk = invariant_core::authority::crypto::generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk, "instance-b-ephemeral".to_string())
    };

    // Build trusted keys: both instances trust both keys.
    let mut trusted = HashMap::new();
    trusted.insert(kid_a.clone(), vk_a);
    trusted.insert(kid_b.clone(), vk_b);

    let config_a = match ValidatorConfig::new(profile.clone(), trusted.clone(), sk_a, kid_a.clone())
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: instance A config: {e}");
            return 2;
        }
    };
    let config_b = match ValidatorConfig::new(profile, trusted, sk_b, kid_b) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: instance B config: {e}");
            return 2;
        }
    };

    let diff = DifferentialValidator::new(&config_a, &config_b);
    let forge_sk = SigningKey::from_bytes(&forge_key_bytes);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut any_disagreement = false;
    let mut command_count: usize = 0;

    // Batch path.
    if let Some(ref path) = args.batch {
        const BATCH_SIZE_LIMIT: u64 = 1 << 30;
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("error: stat {}: {e}", path.display());
                return 2;
            }
        };
        if meta.len() > BATCH_SIZE_LIMIT {
            eprintln!("error: batch file too large");
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
            let exit = process_one(
                &mut cmd,
                args.forge,
                &forge_sk,
                &kid_a,
                &diff,
                &mut out,
                &mut any_disagreement,
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
        let exit = process_one(
            &mut cmd,
            args.forge,
            &forge_sk,
            &kid_a,
            &diff,
            &mut out,
            &mut any_disagreement,
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

    // Print summary.
    eprintln!(
        "differential: {command_count} command(s) validated, {} disagreement(s)",
        if any_disagreement { "FOUND" } else { "0" }
    );

    if any_disagreement {
        1
    } else {
        0
    }
}

#[allow(clippy::too_many_arguments)]
fn process_one(
    cmd: &mut Command,
    forge: bool,
    forge_sk: &SigningKey,
    kid: &str,
    diff: &DifferentialValidator<'_>,
    out: &mut impl Write,
    any_disagreement: &mut bool,
    command_count: &mut usize,
) -> i32 {
    *command_count += 1;

    if forge {
        if let Err(e) = forge_authority(cmd, forge_sk, kid, "forge") {
            eprintln!("error: forge mode PCA generation failed: {e}");
            return 2;
        }
    }

    let now = Utc::now();
    match diff.validate(cmd, now, None) {
        Ok(result) => {
            if !result.fully_agrees() {
                *any_disagreement = true;
            }

            let output = DiffOutput {
                command_sequence: result.command_sequence,
                fully_agrees: result.fully_agrees(),
                result: &result,
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
            eprintln!("error: differential validation failed: {e}");
            return 2;
        }
    }
    0
}

fn read_single_command(args: &DifferentialArgs) -> Result<Command, String> {
    if let Some(ref path) = args.command {
        let data =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let cmd: Command =
            serde_json::from_str(&data).map_err(|e| format!("parse command: {e}"))?;
        Ok(cmd)
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .take(10_485_760)
            .read_to_string(&mut buf)
            .map_err(|e| format!("read stdin: {e}"))?;
        let cmd: Command = serde_json::from_str(&buf).map_err(|e| format!("parse stdin: {e}"))?;
        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_profile_returns_2() {
        let args = DifferentialArgs {
            profile: PathBuf::from("/nonexistent/profile.json"),
            command: None,
            batch: None,
            key: PathBuf::from("/nonexistent/key.json"),
            key_b: None,
            forge: false,
        };
        assert_eq!(run(&args), 2);
    }
}
