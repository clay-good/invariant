//! `invariant profile` — profile management commands.
//!
//! Subcommands: `init` (generate template), `validate` (check a profile file).

use clap::{Args, Subcommand};
use std::path::PathBuf;

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
}

pub fn run(args: &ProfileArgs) -> i32 {
    match &args.action {
        ProfileAction::Init {
            name,
            joints,
            output,
        } => run_init(name, *joints, output),
        ProfileAction::Validate { profile } => run_validate(profile),
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
}
