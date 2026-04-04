//! `invariant profile` — profile management commands.
//!
//! Subcommands: `init`, `validate`, `sign`, `verify-signature`, `envelopes`, `show-envelope`.

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

use invariant_core::models::error::Validate;
use invariant_core::models::profile::{
    JointDefinition, JointType, RobotProfile, SafeStopProfile, WorkspaceBounds,
};

#[derive(Args)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub action: ProfileAction,
}

#[derive(Subcommand)]
pub enum ProfileAction {
    /// Initialize a new robot profile template.
    Init {
        /// Robot name.
        #[arg(long)]
        name: String,
        /// Number of joints.
        #[arg(long)]
        joints: u32,
        /// Output file path.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate an existing profile file.
    Validate {
        /// Path to the profile JSON file.
        #[arg(long)]
        profile: PathBuf,
    },
    /// List all built-in standard task envelopes (Section 17.3).
    Envelopes,
    /// Show a specific built-in envelope as JSON.
    ShowEnvelope {
        /// Envelope name (e.g. "delicate_pickup", "heavy_lift").
        #[arg(long)]
        name: String,
    },
    /// Sign a profile with an Ed25519 key (Section 8.3).
    /// Writes `profile_signature` and `profile_signer_kid` into the profile JSON.
    Sign {
        /// Path to the profile JSON file (modified in-place).
        #[arg(long)]
        profile: PathBuf,
        /// Path to the key file (JSON with `kid` and `secret_key`).
        #[arg(long)]
        key: PathBuf,
    },
    /// Verify a profile's Ed25519 signature.
    VerifySignature {
        /// Path to the signed profile JSON file.
        #[arg(long)]
        profile: PathBuf,
        /// Path to the key file (JSON with `kid` and `public_key`).
        #[arg(long)]
        key: PathBuf,
    },
}

pub fn run(args: &ProfileArgs) -> i32 {
    match &args.action {
        ProfileAction::Init {
            name,
            joints,
            output,
        } => run_init(name, *joints, output),
        ProfileAction::Validate { profile } => run_validate(profile),
        ProfileAction::Envelopes => run_list_envelopes(),
        ProfileAction::ShowEnvelope { name } => run_show_envelope(name),
        ProfileAction::Sign { profile, key } => run_sign(profile, key),
        ProfileAction::VerifySignature { profile, key } => run_verify_signature(profile, key),
    }
}

fn run_init(name: &str, joints: u32, output: &PathBuf) -> i32 {
    let joint_defs: Vec<JointDefinition> = (0..joints)
        .map(|i| JointDefinition {
            name: format!("joint_{i}"),
            joint_type: JointType::Revolute,
            min: -std::f64::consts::PI,
            max: std::f64::consts::PI,
            max_velocity: 5.0,
            max_torque: 50.0,
            max_acceleration: 25.0,
        })
        .collect();

    let profile = RobotProfile {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        joints: joint_defs,
        workspace: WorkspaceBounds::Aabb {
            min: [-2.0, -2.0, 0.0],
            max: [2.0, 2.0, 3.0],
        },
        exclusion_zones: vec![],
        proximity_zones: vec![],
        collision_pairs: vec![],
        stability: None,
        locomotion: None,
        end_effectors: vec![],
        max_delta_time: 0.1,
        min_collision_distance: 0.01,
        global_velocity_scale: 1.0,
        watchdog_timeout_ms: 50,
        safe_stop_profile: SafeStopProfile::default(),
        profile_signature: None,
        profile_signer_kid: None,
        config_sequence: None,
        real_world_margins: None,
        task_envelope: None,
        environment: None,
    };

    let json = match serde_json::to_string_pretty(&profile) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: failed to serialize profile: {e}");
            return 2;
        }
    };

    match std::fs::write(output, json) {
        Ok(()) => {
            println!("Profile template written to {}", output.display());
            0
        }
        Err(e) => {
            eprintln!("error: failed to write {}: {e}", output.display());
            2
        }
    }
}

fn run_validate(path: &PathBuf) -> i32 {
    let json = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not read {}: {e}", path.display());
            return 2;
        }
    };

    let profile: RobotProfile = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid JSON: {e}");
            return 2;
        }
    };

    match profile.validate() {
        Ok(()) => {
            println!(
                "Profile '{}' is valid ({} joints, {} exclusion zones)",
                profile.name,
                profile.joints.len(),
                profile.exclusion_zones.len()
            );
            0
        }
        Err(e) => {
            eprintln!("Validation failed: {e}");
            1
        }
    }
}

fn run_sign(profile_path: &Path, key_path: &Path) -> i32 {
    // Load profile.
    let json = match std::fs::read_to_string(profile_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not read {}: {e}", profile_path.display());
            return 2;
        }
    };
    let mut profile: RobotProfile = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid profile JSON: {e}");
            return 2;
        }
    };

    // Load key file.
    let kf = match crate::key_file::load_key_file(key_path) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (signing_key, _vk, kid) = match crate::key_file::load_signing_key(&kf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Clear existing signature fields before computing the canonical form.
    profile.profile_signature = None;
    profile.profile_signer_kid = None;

    // Compute canonical JSON (no signature fields, deterministic ordering via serde).
    let canonical = match serde_json::to_vec(&profile) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: failed to serialize profile: {e}");
            return 2;
        }
    };

    // Sign the canonical bytes.
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(&canonical);
    let sig_b64 = STANDARD.encode(signature.to_bytes());

    // Write signature back into the profile.
    profile.profile_signature = Some(sig_b64.clone());
    profile.profile_signer_kid = Some(kid.clone());

    // Write the signed profile back to the file.
    let output_json = match serde_json::to_string_pretty(&profile) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: failed to serialize signed profile: {e}");
            return 2;
        }
    };

    match std::fs::write(profile_path, output_json) {
        Ok(()) => {
            println!(
                "Profile '{}' signed with key '{}' (signature: {}...)",
                profile.name,
                kid,
                &sig_b64[..20.min(sig_b64.len())]
            );
            0
        }
        Err(e) => {
            eprintln!("error: failed to write {}: {e}", profile_path.display());
            2
        }
    }
}

fn run_verify_signature(profile_path: &Path, key_path: &Path) -> i32 {
    // Load profile.
    let json = match std::fs::read_to_string(profile_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not read {}: {e}", profile_path.display());
            return 2;
        }
    };
    let mut profile: RobotProfile = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid profile JSON: {e}");
            return 2;
        }
    };

    // Extract the signature before clearing.
    let sig_b64 = match &profile.profile_signature {
        Some(s) => s.clone(),
        None => {
            eprintln!("error: profile has no signature (profile_signature is null)");
            return 1;
        }
    };
    let signer_kid = profile.profile_signer_kid.clone().unwrap_or_default();

    // Load key file.
    let kf = match crate::key_file::load_key_file(key_path) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (vk, _key_kid) = match crate::key_file::load_verifying_key(&kf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Clear signature fields to reconstruct canonical form.
    profile.profile_signature = None;
    profile.profile_signer_kid = None;
    let canonical = match serde_json::to_vec(&profile) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: failed to serialize profile: {e}");
            return 2;
        }
    };

    // Decode and verify signature.
    let sig_bytes = match STANDARD.decode(&sig_b64) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: invalid base64 signature: {e}");
            return 1;
        }
    };
    let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: invalid signature bytes: {e}");
            return 1;
        }
    };

    use ed25519_dalek::Verifier;
    match vk.verify(&canonical, &signature) {
        Ok(()) => {
            println!(
                "Profile '{}' signature VALID (signer: {})",
                profile.name, signer_kid
            );
            0
        }
        Err(e) => {
            eprintln!("Profile '{}' signature INVALID: {e}", profile.name);
            1
        }
    }
}

fn run_list_envelopes() -> i32 {
    let envelopes = invariant_core::envelopes::builtin_envelopes();
    println!("Built-in task envelopes ({}):\n", envelopes.len());
    println!(
        "{:<20} {:>10} {:>12} {:>12}  Description",
        "Name", "Vel Scale", "Payload kg", "Force N"
    );
    println!("{:-<85}", "");
    for e in &envelopes {
        println!(
            "{:<20} {:>10} {:>12} {:>12}  {}",
            e.name,
            e.global_velocity_scale
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "-".into()),
            e.max_payload_kg
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "N/A".into()),
            e.end_effector_force_limit_n
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "-".into()),
            e.description,
        );
    }
    0
}

fn run_show_envelope(name: &str) -> i32 {
    match invariant_core::envelopes::builtin_envelope(name) {
        Some(env) => {
            let json = serde_json::to_string_pretty(&env).unwrap();
            println!("{json}");
            0
        }
        None => {
            eprintln!("error: unknown envelope '{name}'");
            eprintln!("Available envelopes:");
            for e in invariant_core::envelopes::builtin_envelopes() {
                eprintln!("  - {}", e.name);
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_nonexistent_file_returns_2() {
        let args = ProfileArgs {
            action: ProfileAction::Validate {
                profile: PathBuf::from("/nonexistent/profile.json"),
            },
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn init_creates_valid_profile() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("test_robot.json");
        let args = ProfileArgs {
            action: ProfileAction::Init {
                name: "test_robot".into(),
                joints: 7,
                output: output.clone(),
            },
        };
        assert_eq!(run(&args), 0);
        assert!(output.exists());

        // The generated profile should be valid.
        let json = std::fs::read_to_string(&output).unwrap();
        let profile: RobotProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile.name, "test_robot");
        assert_eq!(profile.joints.len(), 7);
        profile
            .validate()
            .expect("generated profile should be valid");
    }

    #[test]
    fn list_envelopes_returns_0() {
        let args = ProfileArgs {
            action: ProfileAction::Envelopes,
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn show_known_envelope_returns_0() {
        let args = ProfileArgs {
            action: ProfileAction::ShowEnvelope {
                name: "delicate_pickup".into(),
            },
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn show_unknown_envelope_returns_1() {
        let args = ProfileArgs {
            action: ProfileAction::ShowEnvelope {
                name: "nonexistent".into(),
            },
        };
        assert_eq!(run(&args), 1);
    }

    // ── Sign / verify-signature tests ──────────────────────────────────

    fn create_test_key_file(dir: &std::path::Path) -> PathBuf {
        use invariant_core::authority::crypto::generate_keypair;
        use rand::rngs::OsRng;

        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        let kf = crate::key_file::KeyFile {
            kid: "test-profile-signer".into(),
            public_key: base64::engine::general_purpose::STANDARD.encode(vk.to_bytes()),
            secret_key: Some(base64::engine::general_purpose::STANDARD.encode(sk.to_bytes())),
        };
        let key_path = dir.join("test_key.json");
        crate::key_file::write_key_file(&key_path, &kf).unwrap();
        key_path
    }

    fn create_test_profile(dir: &std::path::Path) -> PathBuf {
        let profile_path = dir.join("test_profile.json");
        let init_args = ProfileArgs {
            action: ProfileAction::Init {
                name: "sign_test".into(),
                joints: 3,
                output: profile_path.clone(),
            },
        };
        assert_eq!(run(&init_args), 0);
        profile_path
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let profile_path = create_test_profile(dir.path());
        let key_path = create_test_key_file(dir.path());

        // Sign.
        let sign_args = ProfileArgs {
            action: ProfileAction::Sign {
                profile: profile_path.clone(),
                key: key_path.clone(),
            },
        };
        assert_eq!(run(&sign_args), 0);

        // Verify the signed profile has signature fields.
        let json = std::fs::read_to_string(&profile_path).unwrap();
        let profile: RobotProfile = serde_json::from_str(&json).unwrap();
        assert!(profile.profile_signature.is_some());
        assert_eq!(
            profile.profile_signer_kid.as_deref(),
            Some("test-profile-signer")
        );

        // Verify signature.
        let verify_args = ProfileArgs {
            action: ProfileAction::VerifySignature {
                profile: profile_path,
                key: key_path,
            },
        };
        assert_eq!(run(&verify_args), 0);
    }

    #[test]
    fn verify_tampered_profile_fails() {
        let dir = tempfile::tempdir().unwrap();
        let profile_path = create_test_profile(dir.path());
        let key_path = create_test_key_file(dir.path());

        // Sign.
        let sign_args = ProfileArgs {
            action: ProfileAction::Sign {
                profile: profile_path.clone(),
                key: key_path.clone(),
            },
        };
        assert_eq!(run(&sign_args), 0);

        // Tamper: change the profile name.
        let mut json = std::fs::read_to_string(&profile_path).unwrap();
        json = json.replace("sign_test", "tampered_name");
        std::fs::write(&profile_path, json).unwrap();

        // Verify should fail.
        let verify_args = ProfileArgs {
            action: ProfileAction::VerifySignature {
                profile: profile_path,
                key: key_path,
            },
        };
        assert_eq!(run(&verify_args), 1);
    }

    #[test]
    fn verify_unsigned_profile_fails() {
        let dir = tempfile::tempdir().unwrap();
        let profile_path = create_test_profile(dir.path());
        let key_path = create_test_key_file(dir.path());

        // Don't sign — just try to verify.
        let verify_args = ProfileArgs {
            action: ProfileAction::VerifySignature {
                profile: profile_path,
                key: key_path,
            },
        };
        assert_eq!(run(&verify_args), 1);
    }

    #[test]
    fn sign_nonexistent_profile_returns_2() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = create_test_key_file(dir.path());
        let args = ProfileArgs {
            action: ProfileAction::Sign {
                profile: PathBuf::from("/nonexistent/profile.json"),
                key: key_path,
            },
        };
        assert_eq!(run(&args), 2);
    }
}
