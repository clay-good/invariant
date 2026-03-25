use clap::Args;
use std::path::PathBuf;

use invariant_core::models::profile::{JointType, SafeStopStrategy, WorkspaceBounds};

#[derive(Args)]
pub struct InspectArgs {
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
}

pub fn run(args: &InspectArgs) -> i32 {
    let json = match std::fs::read_to_string(&args.profile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("invariant inspect: failed to read {:?}: {}", args.profile, e);
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

