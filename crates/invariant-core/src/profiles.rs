//! Profile library — built-in robot profiles embedded at compile time.
//!
//! Provides 4 validated profiles: humanoid_28dof, franka_panda, quadruped_12dof, ur10.
//! Custom profiles can be loaded from JSON strings or file bytes.

use std::sync::OnceLock;

use crate::models::error::{Validate, ValidationError};
use crate::models::profile::RobotProfile;
use thiserror::Error;

// Embed profile JSON at compile time.
const HUMANOID_28DOF_JSON: &str = include_str!("../../../profiles/humanoid_28dof.json");
const FRANKA_PANDA_JSON: &str = include_str!("../../../profiles/franka_panda.json");
const QUADRUPED_12DOF_JSON: &str = include_str!("../../../profiles/quadruped_12dof.json");
const UR10_JSON: &str = include_str!("../../../profiles/ur10.json");
const UR10E_HAAS_CELL_JSON: &str = include_str!("../../../profiles/ur10e_haas_cell.json");

// Process-lifetime caches for parsed and validated built-in profiles.
// Populated on first access; subsequent calls clone the cached value.
static CACHED_HUMANOID_28DOF: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_FRANKA_PANDA: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_QUADRUPED_12DOF: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_UR10: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_UR10E_HAAS_CELL: OnceLock<RobotProfile> = OnceLock::new();

/// Parse and validate a built-in profile from its embedded JSON constant.
///
/// # Why `expect()` is acceptable here
///
/// The JSON strings passed to this function are compile-time constants
/// (`include_str!` embeds the file bytes at build time). They are not
/// caller-supplied input. The CI suite exercises all four built-in profiles
/// in their own integration tests (`load_humanoid_28dof`, `load_franka_panda`,
/// etc.), so a malformed built-in profile would cause test failures before it
/// ever reaches production. Using `expect()` here converts a programmer error
/// (invalid built-in JSON) into an explicit, immediately actionable panic
/// rather than silently returning a half-constructed default or propagating an
/// obscure error. If you are adding a new built-in profile, validate the JSON
/// with `cargo test` before merging.
///
/// This function must NOT be called with untrusted or caller-supplied JSON.
/// Use `load_from_json` / `load_from_bytes` for that.
fn parse_and_validate(json: &str) -> RobotProfile {
    let profile: RobotProfile = serde_json::from_str(json)
        .expect("built-in profile JSON must be valid — see parse_and_validate doc comment");
    profile
        .validate()
        .expect("built-in profile must pass validation — see parse_and_validate doc comment");
    profile
}

/// Names of all built-in profiles.
const BUILTIN_NAMES: &[&str] = &["humanoid_28dof", "franka_panda", "quadruped_12dof", "ur10", "ur10e_haas_cell"];

/// Maximum JSON input size for custom profiles (256 KiB).
const MAX_PROFILE_JSON_BYTES: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("unknown built-in profile: {0:?}")]
    UnknownProfile(String),

    #[error("profile JSON exceeds maximum size of {max} bytes (got {got})")]
    InputTooLarge { got: usize, max: usize },

    #[error("profile JSON parse error: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("profile validation failed: {0}")]
    ValidationFailed(#[from] ValidationError),
}

/// Returns the list of built-in profile names.
pub fn list_builtins() -> &'static [&'static str] {
    BUILTIN_NAMES
}

/// Loads a built-in profile by name.
///
/// The profile is parsed and validated on first access, then cached for the
/// lifetime of the process. Subsequent calls clone the cached value, avoiding
/// repeated JSON parsing and validation.
pub fn load_builtin(name: &str) -> Result<RobotProfile, ProfileError> {
    let profile = match name {
        "humanoid_28dof" => CACHED_HUMANOID_28DOF
            .get_or_init(|| parse_and_validate(HUMANOID_28DOF_JSON))
            .clone(),
        "franka_panda" => CACHED_FRANKA_PANDA
            .get_or_init(|| parse_and_validate(FRANKA_PANDA_JSON))
            .clone(),
        "quadruped_12dof" => CACHED_QUADRUPED_12DOF
            .get_or_init(|| parse_and_validate(QUADRUPED_12DOF_JSON))
            .clone(),
        "ur10" => CACHED_UR10
            .get_or_init(|| parse_and_validate(UR10_JSON))
            .clone(),
        "ur10e_haas_cell" => CACHED_UR10E_HAAS_CELL
            .get_or_init(|| parse_and_validate(UR10E_HAAS_CELL_JSON))
            .clone(),
        _ => return Err(ProfileError::UnknownProfile(name.to_string())),
    };
    Ok(profile)
}

/// Loads and validates a profile from a JSON string.
///
/// Enforces a size cap to prevent memory exhaustion from untrusted input.
pub fn load_from_json(json: &str) -> Result<RobotProfile, ProfileError> {
    if json.len() > MAX_PROFILE_JSON_BYTES {
        return Err(ProfileError::InputTooLarge {
            got: json.len(),
            max: MAX_PROFILE_JSON_BYTES,
        });
    }
    let profile: RobotProfile = serde_json::from_str(json)?;
    profile.validate()?;
    Ok(profile)
}

/// Loads and validates a profile from raw JSON bytes.
///
/// Enforces a size cap to prevent memory exhaustion from untrusted input.
pub fn load_from_bytes(bytes: &[u8]) -> Result<RobotProfile, ProfileError> {
    if bytes.len() > MAX_PROFILE_JSON_BYTES {
        return Err(ProfileError::InputTooLarge {
            got: bytes.len(),
            max: MAX_PROFILE_JSON_BYTES,
        });
    }
    let profile: RobotProfile = serde_json::from_slice(bytes)?;
    profile.validate()?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::{JointType, SafeStopStrategy};

    // --- Built-in profile loading ---

    #[test]
    fn load_humanoid_28dof() {
        let p = load_builtin("humanoid_28dof").expect("load humanoid");
        assert_eq!(p.name, "humanoid_28dof");
        assert_eq!(p.version, "1.0.0");
        assert_eq!(p.joints.len(), 28);
        assert_eq!(p.exclusion_zones.len(), 2);
        assert_eq!(p.proximity_zones.len(), 2);
        assert_eq!(p.collision_pairs.len(), 5);
        assert!(p.stability.is_some());
        assert_eq!(
            p.safe_stop_profile.strategy,
            SafeStopStrategy::ControlledCrouch
        );
        assert_eq!(p.watchdog_timeout_ms, 50);
        // All joints are revolute
        assert!(p.joints.iter().all(|j| j.joint_type == JointType::Revolute));
    }

    #[test]
    fn load_franka_panda() {
        let p = load_builtin("franka_panda").expect("load franka");
        assert_eq!(p.name, "franka_panda");
        assert_eq!(p.joints.len(), 7);
        assert_eq!(p.exclusion_zones.len(), 2);
        assert_eq!(p.proximity_zones.len(), 1);
        assert_eq!(p.collision_pairs.len(), 2);
        assert!(p.stability.is_none());
        assert_eq!(p.watchdog_timeout_ms, 100);
        // Safe-stop has target positions for all 7 joints
        assert_eq!(p.safe_stop_profile.target_joint_positions.len(), 7);
    }

    #[test]
    fn load_quadruped_12dof() {
        let p = load_builtin("quadruped_12dof").expect("load quadruped");
        assert_eq!(p.name, "quadruped_12dof");
        assert_eq!(p.joints.len(), 12);
        assert_eq!(p.exclusion_zones.len(), 1);
        assert_eq!(p.proximity_zones.len(), 1);
        assert_eq!(p.collision_pairs.len(), 2);
        assert!(p.stability.is_some());
        assert_eq!(p.watchdog_timeout_ms, 50);
    }

    #[test]
    fn load_ur10() {
        let p = load_builtin("ur10").expect("load ur10");
        assert_eq!(p.name, "ur10");
        assert_eq!(p.joints.len(), 6);
        assert_eq!(p.exclusion_zones.len(), 2);
        assert_eq!(p.proximity_zones.len(), 2);
        assert_eq!(p.collision_pairs.len(), 2);
        assert!(p.stability.is_none());
        assert_eq!(p.watchdog_timeout_ms, 100);
        assert_eq!(p.safe_stop_profile.target_joint_positions.len(), 6);
    }

    // --- List builtins ---

    #[test]
    fn list_builtins_returns_all_five() {
        let names = list_builtins();
        assert_eq!(names.len(), 5);
        assert!(names.contains(&"humanoid_28dof"));
        assert!(names.contains(&"franka_panda"));
        assert!(names.contains(&"quadruped_12dof"));
        assert!(names.contains(&"ur10"));
    }

    // --- Error cases ---

    #[test]
    fn unknown_profile_returns_error() {
        let err = load_builtin("nonexistent").unwrap_err();
        assert!(matches!(err, ProfileError::UnknownProfile(name) if name == "nonexistent"));
    }

    #[test]
    fn load_from_json_valid() {
        let json = HUMANOID_28DOF_JSON;
        let p = load_from_json(json).expect("load from json");
        assert_eq!(p.name, "humanoid_28dof");
    }

    #[test]
    fn load_from_json_invalid_json() {
        let err = load_from_json("{ not valid json }").unwrap_err();
        assert!(matches!(err, ProfileError::ParseError(_)));
    }

    #[test]
    fn load_from_json_too_large() {
        let huge = "x".repeat(MAX_PROFILE_JSON_BYTES + 1);
        let err = load_from_json(&huge).unwrap_err();
        assert!(matches!(err, ProfileError::InputTooLarge { .. }));
    }

    #[test]
    fn load_from_json_exactly_at_limit() {
        // Finding 48: a string of exactly MAX_PROFILE_JSON_BYTES bytes must
        // NOT be rejected by the InputTooLarge guard (the guard is `> max`,
        // not `>= max`). It will fail with a parse error, but never InputTooLarge.
        let at_limit = "x".repeat(MAX_PROFILE_JSON_BYTES);
        assert_eq!(at_limit.len(), MAX_PROFILE_JSON_BYTES);
        let result = load_from_json(&at_limit);
        assert!(result.is_err());
        assert!(
            !matches!(result.unwrap_err(), ProfileError::InputTooLarge { .. }),
            "a string of exactly MAX_PROFILE_JSON_BYTES bytes must not return InputTooLarge"
        );
    }

    #[test]
    fn load_from_json_validation_failure() {
        // Profile with inverted joint limits
        let json = r#"{
            "name": "bad",
            "version": "1.0.0",
            "joints": [
                {"name": "j1", "type": "revolute", "min": 1.0, "max": 0.0,
                 "max_velocity": 1.0, "max_torque": 1.0, "max_acceleration": 1.0}
            ],
            "workspace": {"type": "aabb", "min": [-1,-1,-1], "max": [1,1,1]},
            "max_delta_time": 0.01,
            "global_velocity_scale": 1.0
        }"#;
        let err = load_from_json(json).unwrap_err();
        assert!(matches!(err, ProfileError::ValidationFailed(_)));
    }

    #[test]
    fn load_from_bytes_valid() {
        let p = load_from_bytes(FRANKA_PANDA_JSON.as_bytes()).expect("load from bytes");
        assert_eq!(p.name, "franka_panda");
    }

    #[test]
    fn load_from_bytes_too_large() {
        let huge = vec![b'x'; MAX_PROFILE_JSON_BYTES + 1];
        let err = load_from_bytes(&huge).unwrap_err();
        assert!(matches!(err, ProfileError::InputTooLarge { .. }));
    }

    #[test]
    fn load_from_bytes_invalid_json() {
        let err = load_from_bytes(b"{ not valid json }").unwrap_err();
        assert!(matches!(err, ProfileError::ParseError(_)));
    }

    // --- Round-trip: all builtins serialize and re-parse identically ---

    #[test]
    fn all_builtins_round_trip() {
        for name in list_builtins() {
            let original = load_builtin(name).unwrap();
            let json = serde_json::to_string(&original).unwrap();
            let reloaded = load_from_json(&json).unwrap();
            assert_eq!(original, reloaded, "round-trip failed for {name}");
        }
    }
}
