//! Built-in robot profile library.
//!
//! Embeds 4 validated profiles (humanoid 28-DOF, Franka Panda, quadruped 12-DOF,
//! UR10) and provides functions to load profiles from JSON strings or files.

use crate::models::error::{Validate, ValidationError};
use crate::models::profile::RobotProfile;
use std::path::Path;

/// Errors from profile loading.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("unknown built-in profile: {0:?} (available: {BUILTIN_NAMES:?})")]
    UnknownBuiltin(String),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// Embedded profile JSON sources.
const HUMANOID_28DOF_JSON: &str = include_str!("../../../profiles/humanoid_28dof.json");
const FRANKA_PANDA_JSON: &str = include_str!("../../../profiles/franka_panda.json");
const QUADRUPED_12DOF_JSON: &str = include_str!("../../../profiles/quadruped_12dof.json");
const UR10_JSON: &str = include_str!("../../../profiles/ur10.json");

/// Names of all built-in profiles.
pub const BUILTIN_NAMES: &[&str] = &[
    "humanoid_28dof",
    "franka_panda",
    "quadruped_12dof",
    "ur10",
];

/// Load a built-in profile by name. Returns a validated `RobotProfile`.
pub fn load_builtin(name: &str) -> Result<RobotProfile, ProfileError> {
    let json = match name {
        "humanoid_28dof" => HUMANOID_28DOF_JSON,
        "franka_panda" => FRANKA_PANDA_JSON,
        "quadruped_12dof" => QUADRUPED_12DOF_JSON,
        "ur10" => UR10_JSON,
        _ => return Err(ProfileError::UnknownBuiltin(name.to_string())),
    };
    load_from_str(json)
}

/// Parse and validate a `RobotProfile` from a JSON string.
pub fn load_from_str(json: &str) -> Result<RobotProfile, ProfileError> {
    let profile: RobotProfile = serde_json::from_str(json)?;
    profile.validate()?;
    Ok(profile)
}

/// Load and validate a `RobotProfile` from a JSON file.
pub fn load_from_file(path: &Path) -> Result<RobotProfile, ProfileError> {
    let json = std::fs::read_to_string(path)?;
    load_from_str(&json)
}

/// Return the raw embedded JSON for a built-in profile.
pub fn builtin_json(name: &str) -> Result<&'static str, ProfileError> {
    match name {
        "humanoid_28dof" => Ok(HUMANOID_28DOF_JSON),
        "franka_panda" => Ok(FRANKA_PANDA_JSON),
        "quadruped_12dof" => Ok(QUADRUPED_12DOF_JSON),
        "ur10" => Ok(UR10_JSON),
        _ => Err(ProfileError::UnknownBuiltin(name.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::{
        ExclusionZone, JointType, ProximityZone, SafeStopStrategy, WorkspaceBounds,
    };

    // ---- Built-in loading ----

    #[test]
    fn load_all_builtins() {
        for name in BUILTIN_NAMES {
            let profile = load_builtin(name).unwrap_or_else(|e| {
                panic!("failed to load built-in profile {name:?}: {e}")
            });
            assert_eq!(profile.name, *name);
        }
    }

    #[test]
    fn unknown_builtin_errors() {
        let err = load_builtin("nonexistent").unwrap_err();
        assert!(matches!(err, ProfileError::UnknownBuiltin(_)));
    }

    // ---- Humanoid 28-DOF ----

    #[test]
    fn humanoid_28dof_joint_count() {
        let p = load_builtin("humanoid_28dof").unwrap();
        assert_eq!(p.joints.len(), 28);
    }

    #[test]
    fn humanoid_28dof_all_revolute() {
        let p = load_builtin("humanoid_28dof").unwrap();
        for j in &p.joints {
            assert_eq!(j.joint_type, JointType::Revolute, "joint {} is not revolute", j.name);
        }
    }

    #[test]
    fn humanoid_28dof_joint_names_unique() {
        let p = load_builtin("humanoid_28dof").unwrap();
        let mut names: Vec<&str> = p.joints.iter().map(|j| j.name.as_str()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate joint names found");
    }

    #[test]
    fn humanoid_28dof_has_expected_joint_groups() {
        let p = load_builtin("humanoid_28dof").unwrap();
        let names: Vec<&str> = p.joints.iter().map(|j| j.name.as_str()).collect();
        // Must have left and right legs, arms, torso
        assert!(names.iter().any(|n| n.starts_with("left_hip")));
        assert!(names.iter().any(|n| n.starts_with("right_hip")));
        assert!(names.iter().any(|n| n.starts_with("left_shoulder")));
        assert!(names.iter().any(|n| n.starts_with("right_shoulder")));
        assert!(names.iter().any(|n| n.starts_with("torso_")));
    }

    #[test]
    fn humanoid_28dof_workspace() {
        let p = load_builtin("humanoid_28dof").unwrap();
        match &p.workspace {
            WorkspaceBounds::Aabb { min, max } => {
                // Humanoid workspace must include origin and extend upward
                assert!(min[2] <= 0.0, "workspace floor should be at or below ground");
                assert!(max[2] >= 2.0, "workspace ceiling should be at least 2m");
            }
        }
    }

    #[test]
    fn humanoid_28dof_exclusion_zones() {
        let p = load_builtin("humanoid_28dof").unwrap();
        assert!(p.exclusion_zones.len() >= 2, "humanoid should have at least 2 exclusion zones");
        let zone_names: Vec<&str> = p.exclusion_zones.iter().map(|z| match z {
            ExclusionZone::Aabb { name, .. } | ExclusionZone::Sphere { name, .. } => name.as_str(),
        }).collect();
        assert!(zone_names.contains(&"operator_zone"));
        assert!(zone_names.contains(&"head_clearance"));
    }

    #[test]
    fn humanoid_28dof_proximity_zones() {
        let p = load_builtin("humanoid_28dof").unwrap();
        assert!(p.proximity_zones.len() >= 2, "humanoid should have warning + critical zones");
    }

    #[test]
    fn humanoid_28dof_stability_enabled() {
        let p = load_builtin("humanoid_28dof").unwrap();
        let stability = p.stability.as_ref().expect("humanoid must have stability config");
        assert!(stability.enabled);
        assert!(stability.support_polygon.len() >= 3, "support polygon needs >= 3 vertices");
        assert!(stability.com_height_estimate > 0.0);
    }

    #[test]
    fn humanoid_28dof_collision_pairs() {
        let p = load_builtin("humanoid_28dof").unwrap();
        assert!(!p.collision_pairs.is_empty(), "humanoid should have collision pairs");
    }

    #[test]
    fn humanoid_28dof_safe_stop() {
        let p = load_builtin("humanoid_28dof").unwrap();
        assert_eq!(p.safe_stop_profile.strategy, SafeStopStrategy::ControlledCrouch);
        assert!(p.safe_stop_profile.max_deceleration > 0.0);
    }

    // ---- Franka Panda ----

    #[test]
    fn franka_panda_joint_count() {
        let p = load_builtin("franka_panda").unwrap();
        assert_eq!(p.joints.len(), 7, "Franka Panda has 7 DOF");
    }

    #[test]
    fn franka_panda_joint_names() {
        let p = load_builtin("franka_panda").unwrap();
        for (i, j) in p.joints.iter().enumerate() {
            assert_eq!(j.name, format!("panda_joint{}", i + 1));
        }
    }

    #[test]
    fn franka_panda_no_stability() {
        let p = load_builtin("franka_panda").unwrap();
        assert!(
            p.stability.is_none(),
            "Franka is a fixed-base arm — stability should be None"
        );
    }

    #[test]
    fn franka_panda_safe_stop_has_positions() {
        let p = load_builtin("franka_panda").unwrap();
        assert_eq!(
            p.safe_stop_profile.target_joint_positions.len(),
            7,
            "Franka safe-stop should define positions for all 7 joints"
        );
    }

    #[test]
    fn franka_panda_safe_stop_positions_within_limits() {
        let p = load_builtin("franka_panda").unwrap();
        for j in &p.joints {
            if let Some(&pos) = p.safe_stop_profile.target_joint_positions.get(&j.name) {
                assert!(
                    pos >= j.min && pos <= j.max,
                    "safe-stop position {pos} for {} is outside limits [{}, {}]",
                    j.name, j.min, j.max
                );
            }
        }
    }

    #[test]
    fn franka_panda_workspace() {
        let p = load_builtin("franka_panda").unwrap();
        match &p.workspace {
            WorkspaceBounds::Aabb { max, .. } => {
                // Franka reach ~855mm, workspace should be under 1m radius
                assert!(max[0] <= 1.0);
                assert!(max[1] <= 1.0);
            }
        }
    }

    // ---- Quadruped 12-DOF ----

    #[test]
    fn quadruped_12dof_joint_count() {
        let p = load_builtin("quadruped_12dof").unwrap();
        assert_eq!(p.joints.len(), 12, "quadruped has 12 DOF (3 per leg)");
    }

    #[test]
    fn quadruped_12dof_leg_groups() {
        let p = load_builtin("quadruped_12dof").unwrap();
        let names: Vec<&str> = p.joints.iter().map(|j| j.name.as_str()).collect();
        for prefix in &["fl_", "fr_", "rl_", "rr_"] {
            let count = names.iter().filter(|n| n.starts_with(prefix)).count();
            assert_eq!(count, 3, "leg {prefix} should have 3 joints");
        }
    }

    #[test]
    fn quadruped_12dof_stability_enabled() {
        let p = load_builtin("quadruped_12dof").unwrap();
        let stability = p.stability.as_ref().expect("quadruped must have stability config");
        assert!(stability.enabled);
        assert!(stability.support_polygon.len() >= 4, "quadruped support polygon should be >= 4 vertices");
    }

    #[test]
    fn quadruped_12dof_low_workspace() {
        let p = load_builtin("quadruped_12dof").unwrap();
        match &p.workspace {
            WorkspaceBounds::Aabb { max, .. } => {
                assert!(max[2] <= 1.0, "quadruped workspace ceiling should be low");
            }
        }
    }

    #[test]
    fn quadruped_12dof_fast_control() {
        let p = load_builtin("quadruped_12dof").unwrap();
        assert!(
            p.max_delta_time <= 0.02,
            "quadruped needs fast control loop (<=20ms)"
        );
    }

    // ---- UR10 ----

    #[test]
    fn ur10_joint_count() {
        let p = load_builtin("ur10").unwrap();
        assert_eq!(p.joints.len(), 6, "UR10 has 6 DOF");
    }

    #[test]
    fn ur10_no_stability() {
        let p = load_builtin("ur10").unwrap();
        assert!(p.stability.is_none(), "UR10 is a fixed-base arm — stability should be None");
    }

    #[test]
    fn ur10_safe_stop_has_positions() {
        let p = load_builtin("ur10").unwrap();
        assert_eq!(
            p.safe_stop_profile.target_joint_positions.len(),
            6,
            "UR10 safe-stop should define positions for all 6 joints"
        );
    }

    #[test]
    fn ur10_safe_stop_positions_within_limits() {
        let p = load_builtin("ur10").unwrap();
        for j in &p.joints {
            if let Some(&pos) = p.safe_stop_profile.target_joint_positions.get(&j.name) {
                assert!(
                    pos >= j.min && pos <= j.max,
                    "safe-stop position {pos} for {} is outside limits [{}, {}]",
                    j.name, j.min, j.max
                );
            }
        }
    }

    #[test]
    fn ur10_wide_joint_range() {
        let p = load_builtin("ur10").unwrap();
        // UR10 shoulder/wrist joints have ~+-2pi range
        let shoulder = &p.joints[0];
        assert!(shoulder.max - shoulder.min > 10.0, "UR10 shoulder should have wide range");
    }

    #[test]
    fn ur10_high_torque_shoulder() {
        let p = load_builtin("ur10").unwrap();
        let shoulder = &p.joints[0];
        assert!(shoulder.max_torque >= 300.0, "UR10 shoulder should have high torque");
    }

    // ---- Cross-profile checks ----

    #[test]
    fn all_profiles_have_positive_watchdog_timeout() {
        for name in BUILTIN_NAMES {
            let p = load_builtin(name).unwrap();
            assert!(p.watchdog_timeout_ms > 0, "{name}: watchdog_timeout_ms must be > 0");
        }
    }

    #[test]
    fn all_profiles_have_valid_velocity_scale() {
        for name in BUILTIN_NAMES {
            let p = load_builtin(name).unwrap();
            assert!(
                p.global_velocity_scale > 0.0 && p.global_velocity_scale <= 1.0,
                "{name}: global_velocity_scale out of range"
            );
        }
    }

    #[test]
    fn all_profiles_have_positive_max_delta_time() {
        for name in BUILTIN_NAMES {
            let p = load_builtin(name).unwrap();
            assert!(p.max_delta_time > 0.0, "{name}: max_delta_time must be > 0");
        }
    }

    #[test]
    fn all_profiles_joints_within_reasonable_limits() {
        for name in BUILTIN_NAMES {
            let p = load_builtin(name).unwrap();
            for j in &p.joints {
                assert!(j.min.is_finite(), "{name}/{}: min not finite", j.name);
                assert!(j.max.is_finite(), "{name}/{}: max not finite", j.name);
                assert!(j.max_velocity.is_finite() && j.max_velocity > 0.0,
                    "{name}/{}: invalid max_velocity", j.name);
                assert!(j.max_torque.is_finite() && j.max_torque > 0.0,
                    "{name}/{}: invalid max_torque", j.name);
                assert!(j.max_acceleration.is_finite() && j.max_acceleration > 0.0,
                    "{name}/{}: invalid max_acceleration", j.name);
            }
        }
    }

    #[test]
    fn all_profiles_exclusion_zones_valid() {
        for name in BUILTIN_NAMES {
            let p = load_builtin(name).unwrap();
            for zone in &p.exclusion_zones {
                match zone {
                    ExclusionZone::Aabb { min, max, .. } => {
                        assert!(min[0] < max[0] && min[1] < max[1] && min[2] < max[2],
                            "{name}: AABB exclusion zone has inverted bounds");
                    }
                    ExclusionZone::Sphere { radius, .. } => {
                        assert!(*radius > 0.0, "{name}: sphere exclusion zone has non-positive radius");
                    }
                }
            }
        }
    }

    #[test]
    fn all_profiles_proximity_zones_valid_scale() {
        for name in BUILTIN_NAMES {
            let p = load_builtin(name).unwrap();
            for zone in &p.proximity_zones {
                match zone {
                    ProximityZone::Sphere { velocity_scale, radius, .. } => {
                        assert!(*velocity_scale > 0.0 && *velocity_scale <= 1.0,
                            "{name}: proximity zone velocity_scale out of range");
                        assert!(*radius > 0.0,
                            "{name}: proximity zone has non-positive radius");
                    }
                }
            }
        }
    }

    // ---- load_from_str / load_from_file ----

    #[test]
    fn load_from_str_valid() {
        let json = builtin_json("humanoid_28dof").unwrap();
        let p = load_from_str(json).unwrap();
        assert_eq!(p.name, "humanoid_28dof");
    }

    #[test]
    fn load_from_str_invalid_json() {
        let err = load_from_str("not json").unwrap_err();
        assert!(matches!(err, ProfileError::Json(_)));
    }

    #[test]
    fn load_from_str_invalid_profile() {
        // Profile with inverted joint limits
        let json = r#"{
            "name": "bad",
            "version": "1.0.0",
            "joints": [{"name": "j1", "type": "revolute", "min": 1.0, "max": 0.0, "max_velocity": 1.0, "max_torque": 1.0, "max_acceleration": 1.0}],
            "workspace": {"type": "aabb", "min": [-1, -1, -1], "max": [1, 1, 1]},
            "max_delta_time": 0.1
        }"#;
        let err = load_from_str(json).unwrap_err();
        assert!(matches!(err, ProfileError::Validation(_)));
    }

    #[test]
    fn load_from_file_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../profiles/humanoid_28dof.json");
        let p = load_from_file(&path).unwrap();
        assert_eq!(p.name, "humanoid_28dof");
    }

    #[test]
    fn load_from_file_not_found() {
        let err = load_from_file(Path::new("/nonexistent/profile.json")).unwrap_err();
        assert!(matches!(err, ProfileError::Io(_)));
    }

    #[test]
    fn builtin_json_returns_raw() {
        for name in BUILTIN_NAMES {
            let json = builtin_json(name).unwrap();
            assert!(json.contains(name), "{name}: raw JSON should contain the profile name");
        }
    }

    #[test]
    fn builtin_json_unknown_errors() {
        let err = builtin_json("nope").unwrap_err();
        assert!(matches!(err, ProfileError::UnknownBuiltin(_)));
    }

    // ---- Round-trip: serialize then reload ----

    #[test]
    fn all_profiles_roundtrip_serde() {
        for name in BUILTIN_NAMES {
            let original = load_builtin(name).unwrap();
            let serialized = serde_json::to_string(&original).unwrap();
            let reloaded = load_from_str(&serialized).unwrap();
            assert_eq!(original, reloaded, "{name}: round-trip mismatch");
        }
    }
}
