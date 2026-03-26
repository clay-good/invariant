use clap::Args;
use invariant_core::models::profile::{JointType, SafeStopStrategy, WorkspaceBounds};
use std::path::PathBuf;

#[derive(Args)]
pub struct InspectArgs {
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
}

pub fn run(args: &InspectArgs) -> i32 {
    let json = match std::fs::read_to_string(&args.profile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "invariant inspect: failed to read {:?}: {}",
                args.profile, e
            );
            return 2;
        }
    };

    let profile = match invariant_core::profiles::load_from_json(&json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("invariant inspect: {}", e);
            return 2;
        }
    };

    // Profile name and version
    println!("Profile: {} v{}", profile.name, profile.version);

    // Joints
    println!("Joints: {}", profile.joints.len());
    for joint in &profile.joints {
        let type_str = match joint.joint_type {
            JointType::Revolute => "revolute",
            JointType::Prismatic => "prismatic",
        };
        println!(
            "  {} ({}) range [{}, {}] max_vel={} max_torque={} max_accel={}",
            joint.name,
            type_str,
            joint.min,
            joint.max,
            joint.max_velocity,
            joint.max_torque,
            joint.max_acceleration,
        );
    }

    // Workspace bounds
    match &profile.workspace {
        WorkspaceBounds::Aabb { min, max } => {
            println!(
                "Workspace: AABB [{}, {}, {}] to [{}, {}, {}]",
                min[0], min[1], min[2], max[0], max[1], max[2]
            );
        }
    }

    // Zones and collision pairs
    println!("Exclusion zones: {}", profile.exclusion_zones.len());
    println!("Proximity zones: {}", profile.proximity_zones.len());
    println!("Collision pairs: {}", profile.collision_pairs.len());

    // Safe-stop
    let strategy_str = match profile.safe_stop_profile.strategy {
        SafeStopStrategy::ControlledCrouch => "controlled_crouch",
        SafeStopStrategy::ImmediateStop => "immediate_stop",
        SafeStopStrategy::ParkPosition => "park_position",
    };
    println!(
        "Safe-stop: {} (max_decel={})",
        strategy_str, profile.safe_stop_profile.max_deceleration
    );

    // Watchdog, collision distance, velocity scale
    println!("Watchdog timeout: {} ms", profile.watchdog_timeout_ms);
    println!("Min collision distance: {}", profile.min_collision_distance);
    println!("Global velocity scale: {}", profile.global_velocity_scale);

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // A minimal valid profile JSON understood by `invariant_core::profiles::load_from_json`.
    const MINIMAL_PROFILE_JSON: &str = r#"{
        "name": "test_robot",
        "version": "1.0.0",
        "joints": [
            {
                "name": "j1",
                "type": "revolute",
                "min": -1.57,
                "max": 1.57,
                "max_velocity": 2.0,
                "max_torque": 50.0,
                "max_acceleration": 10.0
            }
        ],
        "workspace": {
            "type": "aabb",
            "min": [-1.0, -1.0, 0.0],
            "max": [1.0, 1.0, 2.0]
        },
        "max_delta_time": 0.01,
        "global_velocity_scale": 1.0
    }"#;

    fn write_tempfile(content: &str) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    fn args_for(path: &std::path::Path) -> InspectArgs {
        InspectArgs {
            profile: path.to_path_buf(),
        }
    }

    #[test]
    fn valid_profile_returns_0() {
        let tmp = write_tempfile(MINIMAL_PROFILE_JSON);
        let args = args_for(tmp.path());
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn invalid_json_returns_2() {
        let tmp = write_tempfile("this is not { valid } json");
        let args = args_for(tmp.path());
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn nonexistent_path_returns_2() {
        let args = InspectArgs {
            profile: std::path::PathBuf::from("/nonexistent/path/profile.json"),
        };
        assert_eq!(run(&args), 2);
    }
}
