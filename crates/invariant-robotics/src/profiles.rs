//! Profile library — built-in robot profiles embedded at compile time.
//!
//! Provides 34 validated profiles covering humanoids, quadrupeds, collaborative arms,
//! dexterous hands, mobile manipulators, and adversarial test configurations.
//! Custom profiles can be loaded from JSON strings or file bytes.

use std::sync::OnceLock;

use crate::models::error::{Validate, ValidationError};
use crate::models::profile::RobotProfile;
use thiserror::Error;

// Embed profile JSON at compile time.
const HUMANOID_28DOF_JSON: &str = include_str!("../profiles/humanoid_28dof.json");
const FRANKA_PANDA_JSON: &str = include_str!("../profiles/franka_panda.json");
const QUADRUPED_12DOF_JSON: &str = include_str!("../profiles/quadruped_12dof.json");
const UR10_JSON: &str = include_str!("../profiles/ur10.json");
const UR10E_HAAS_CELL_JSON: &str = include_str!("../profiles/ur10e_haas_cell.json");
const UR10E_CNC_TENDING_JSON: &str = include_str!("../profiles/ur10e_cnc_tending.json");
const UNITREE_H1_JSON: &str = include_str!("../profiles/unitree_h1.json");
const UNITREE_G1_JSON: &str = include_str!("../profiles/unitree_g1.json");
const SPOT_JSON: &str = include_str!("../profiles/spot.json");
const KUKA_IIWA14_JSON: &str = include_str!("../profiles/kuka_iiwa14.json");
const KINOVA_GEN3_JSON: &str = include_str!("../profiles/kinova_gen3.json");
const ABB_GOFA_JSON: &str = include_str!("../profiles/abb_gofa.json");
const SHADOW_HAND_JSON: &str = include_str!("../profiles/shadow_hand.json");
const FOURIER_GR1_JSON: &str = include_str!("../profiles/fourier_gr1.json");
const TESLA_OPTIMUS_JSON: &str = include_str!("../profiles/tesla_optimus.json");
const FIGURE_02_JSON: &str = include_str!("../profiles/figure_02.json");
const BD_ATLAS_JSON: &str = include_str!("../profiles/bd_atlas.json");
const AGILITY_DIGIT_JSON: &str = include_str!("../profiles/agility_digit.json");
const SANCTUARY_PHOENIX_JSON: &str = include_str!("../profiles/sanctuary_phoenix.json");
const ONEX_NEO_JSON: &str = include_str!("../profiles/onex_neo.json");
const APPTRONIK_APOLLO_JSON: &str = include_str!("../profiles/apptronik_apollo.json");
const UNITREE_GO2_JSON: &str = include_str!("../profiles/unitree_go2.json");
const ANYBOTICS_ANYMAL_JSON: &str = include_str!("../profiles/anybotics_anymal.json");
const ALLEGRO_HAND_JSON: &str = include_str!("../profiles/allegro_hand.json");
const LEAP_HAND_JSON: &str = include_str!("../profiles/leap_hand.json");
const PSYONIC_ABILITY_JSON: &str = include_str!("../profiles/psyonic_ability.json");
const UNITREE_A1_JSON: &str = include_str!("../profiles/unitree_a1.json");
const SPOT_WITH_ARM_JSON: &str = include_str!("../profiles/spot_with_arm.json");
const HELLO_STRETCH_JSON: &str = include_str!("../profiles/hello_stretch.json");
const PAL_TIAGO_JSON: &str = include_str!("../profiles/pal_tiago.json");
const ADV_ZERO_MARGIN_JSON: &str = include_str!("../profiles/adversarial_zero_margin.json");
const ADV_MAX_WORKSPACE_JSON: &str = include_str!("../profiles/adversarial_max_workspace.json");
const ADV_SINGLE_JOINT_JSON: &str = include_str!("../profiles/adversarial_single_joint.json");
const ADV_MAX_JOINTS_JSON: &str = include_str!("../profiles/adversarial_max_joints.json");

// Process-lifetime caches for parsed and validated built-in profiles.
// Populated on first access; subsequent calls clone the cached value.
static CACHED_HUMANOID_28DOF: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_FRANKA_PANDA: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_QUADRUPED_12DOF: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_UR10: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_UR10E_HAAS_CELL: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_UR10E_CNC_TENDING: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_UNITREE_H1: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_UNITREE_G1: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_SPOT: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_KUKA_IIWA14: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_KINOVA_GEN3: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_ABB_GOFA: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_SHADOW_HAND: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_FOURIER_GR1: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_TESLA_OPTIMUS: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_FIGURE_02: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_BD_ATLAS: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_AGILITY_DIGIT: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_SANCTUARY_PHOENIX: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_ONEX_NEO: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_APPTRONIK_APOLLO: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_UNITREE_GO2: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_ANYBOTICS_ANYMAL: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_ALLEGRO_HAND: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_LEAP_HAND: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_PSYONIC_ABILITY: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_UNITREE_A1: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_SPOT_WITH_ARM: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_HELLO_STRETCH: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_PAL_TIAGO: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_ADV_ZERO_MARGIN: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_ADV_MAX_WORKSPACE: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_ADV_SINGLE_JOINT: OnceLock<RobotProfile> = OnceLock::new();
static CACHED_ADV_MAX_JOINTS: OnceLock<RobotProfile> = OnceLock::new();

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
const BUILTIN_NAMES: &[&str] = &[
    "humanoid_28dof",
    "franka_panda",
    "quadruped_12dof",
    "ur10",
    "ur10e_haas_cell",
    "ur10e_cnc_tending",
    "unitree_h1",
    "unitree_g1",
    "spot",
    "kuka_iiwa14",
    "kinova_gen3",
    "abb_gofa",
    "shadow_hand",
    "fourier_gr1",
    "tesla_optimus",
    "figure_02",
    "bd_atlas",
    "agility_digit",
    "sanctuary_phoenix",
    "onex_neo",
    "apptronik_apollo",
    "unitree_go2",
    "anybotics_anymal",
    "allegro_hand",
    "leap_hand",
    "psyonic_ability",
    "unitree_a1",
    "spot_with_arm",
    "hello_stretch",
    "pal_tiago",
    "adversarial_zero_margin",
    "adversarial_max_workspace",
    "adversarial_single_joint",
    "adversarial_max_joints",
];

/// Maximum JSON input size for custom profiles (256 KiB).
const MAX_PROFILE_JSON_BYTES: usize = 256 * 1024;

/// Errors that can occur when loading or parsing a robot profile.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// The requested built-in profile name does not exist.
    #[error("unknown built-in profile: {0:?}")]
    UnknownProfile(String),

    /// The supplied JSON byte length exceeds the maximum allowed size (256 KiB).
    #[error("profile JSON exceeds maximum size of {max} bytes (got {got})")]
    InputTooLarge {
        /// Actual byte length of the input.
        got: usize,
        /// Maximum allowed byte length.
        max: usize,
    },

    /// The JSON could not be parsed into a `RobotProfile`.
    #[error("profile JSON parse error: {0}")]
    ParseError(#[from] serde_json::Error),

    /// The parsed profile failed structural validation.
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
        "ur10e_cnc_tending" => CACHED_UR10E_CNC_TENDING
            .get_or_init(|| parse_and_validate(UR10E_CNC_TENDING_JSON))
            .clone(),
        "unitree_h1" => CACHED_UNITREE_H1
            .get_or_init(|| parse_and_validate(UNITREE_H1_JSON))
            .clone(),
        "unitree_g1" => CACHED_UNITREE_G1
            .get_or_init(|| parse_and_validate(UNITREE_G1_JSON))
            .clone(),
        "spot" => CACHED_SPOT
            .get_or_init(|| parse_and_validate(SPOT_JSON))
            .clone(),
        "kuka_iiwa14" => CACHED_KUKA_IIWA14
            .get_or_init(|| parse_and_validate(KUKA_IIWA14_JSON))
            .clone(),
        "kinova_gen3" => CACHED_KINOVA_GEN3
            .get_or_init(|| parse_and_validate(KINOVA_GEN3_JSON))
            .clone(),
        "abb_gofa" => CACHED_ABB_GOFA
            .get_or_init(|| parse_and_validate(ABB_GOFA_JSON))
            .clone(),
        "shadow_hand" => CACHED_SHADOW_HAND
            .get_or_init(|| parse_and_validate(SHADOW_HAND_JSON))
            .clone(),
        "fourier_gr1" => CACHED_FOURIER_GR1
            .get_or_init(|| parse_and_validate(FOURIER_GR1_JSON))
            .clone(),
        "tesla_optimus" => CACHED_TESLA_OPTIMUS
            .get_or_init(|| parse_and_validate(TESLA_OPTIMUS_JSON))
            .clone(),
        "figure_02" => CACHED_FIGURE_02
            .get_or_init(|| parse_and_validate(FIGURE_02_JSON))
            .clone(),
        "bd_atlas" => CACHED_BD_ATLAS
            .get_or_init(|| parse_and_validate(BD_ATLAS_JSON))
            .clone(),
        "agility_digit" => CACHED_AGILITY_DIGIT
            .get_or_init(|| parse_and_validate(AGILITY_DIGIT_JSON))
            .clone(),
        "sanctuary_phoenix" => CACHED_SANCTUARY_PHOENIX
            .get_or_init(|| parse_and_validate(SANCTUARY_PHOENIX_JSON))
            .clone(),
        "onex_neo" => CACHED_ONEX_NEO
            .get_or_init(|| parse_and_validate(ONEX_NEO_JSON))
            .clone(),
        "apptronik_apollo" => CACHED_APPTRONIK_APOLLO
            .get_or_init(|| parse_and_validate(APPTRONIK_APOLLO_JSON))
            .clone(),
        "unitree_go2" => CACHED_UNITREE_GO2
            .get_or_init(|| parse_and_validate(UNITREE_GO2_JSON))
            .clone(),
        "anybotics_anymal" => CACHED_ANYBOTICS_ANYMAL
            .get_or_init(|| parse_and_validate(ANYBOTICS_ANYMAL_JSON))
            .clone(),
        "allegro_hand" => CACHED_ALLEGRO_HAND
            .get_or_init(|| parse_and_validate(ALLEGRO_HAND_JSON))
            .clone(),
        "leap_hand" => CACHED_LEAP_HAND
            .get_or_init(|| parse_and_validate(LEAP_HAND_JSON))
            .clone(),
        "psyonic_ability" => CACHED_PSYONIC_ABILITY
            .get_or_init(|| parse_and_validate(PSYONIC_ABILITY_JSON))
            .clone(),
        "unitree_a1" => CACHED_UNITREE_A1
            .get_or_init(|| parse_and_validate(UNITREE_A1_JSON))
            .clone(),
        "spot_with_arm" => CACHED_SPOT_WITH_ARM
            .get_or_init(|| parse_and_validate(SPOT_WITH_ARM_JSON))
            .clone(),
        "hello_stretch" => CACHED_HELLO_STRETCH
            .get_or_init(|| parse_and_validate(HELLO_STRETCH_JSON))
            .clone(),
        "pal_tiago" => CACHED_PAL_TIAGO
            .get_or_init(|| parse_and_validate(PAL_TIAGO_JSON))
            .clone(),
        "adversarial_zero_margin" => CACHED_ADV_ZERO_MARGIN
            .get_or_init(|| parse_and_validate(ADV_ZERO_MARGIN_JSON))
            .clone(),
        "adversarial_max_workspace" => CACHED_ADV_MAX_WORKSPACE
            .get_or_init(|| parse_and_validate(ADV_MAX_WORKSPACE_JSON))
            .clone(),
        "adversarial_single_joint" => CACHED_ADV_SINGLE_JOINT
            .get_or_init(|| parse_and_validate(ADV_SINGLE_JOINT_JSON))
            .clone(),
        "adversarial_max_joints" => CACHED_ADV_MAX_JOINTS
            .get_or_init(|| parse_and_validate(ADV_MAX_JOINTS_JSON))
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

    #[test]
    fn load_unitree_h1() {
        let p = load_builtin("unitree_h1").expect("load unitree_h1");
        assert_eq!(p.name, "unitree_h1");
        assert_eq!(p.joints.len(), 19);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        assert!((loco.max_locomotion_velocity - 3.3).abs() < 0.01);
        assert!(p.environment.is_some());
        assert!(p.real_world_margins.is_some());
        assert_eq!(
            p.safe_stop_profile.strategy,
            SafeStopStrategy::ControlledCrouch
        );
        assert!(p.joints.iter().all(|j| j.joint_type == JointType::Revolute));
    }

    #[test]
    fn load_unitree_g1() {
        let p = load_builtin("unitree_g1").expect("load unitree_g1");
        assert_eq!(p.name, "unitree_g1");
        assert_eq!(p.joints.len(), 23);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        assert!((loco.max_locomotion_velocity - 2.0).abs() < 0.01);
        assert!(p.environment.is_some());
        assert!(p.real_world_margins.is_some());
        // G1 has head joints
        assert!(p.joints.iter().any(|j| j.name == "head_yaw"));
        assert!(p.joints.iter().any(|j| j.name == "head_pitch"));
    }

    #[test]
    fn load_spot() {
        let p = load_builtin("spot").expect("load spot");
        assert_eq!(p.name, "spot");
        assert_eq!(p.joints.len(), 12);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        assert!((loco.max_locomotion_velocity - 1.6).abs() < 0.01);
        assert_eq!(p.collision_pairs.len(), 4);
        assert!(p.environment.is_some());
        assert!(p.real_world_margins.is_some());
        // Spot has wider terrain tolerance
        let env = p.environment.as_ref().unwrap();
        assert!(env.max_safe_pitch_rad > 0.3);
    }

    #[test]
    fn load_kuka_iiwa14() {
        let p = load_builtin("kuka_iiwa14").expect("load kuka_iiwa14");
        assert_eq!(p.name, "kuka_iiwa14");
        assert_eq!(p.joints.len(), 7);
        assert!(p.stability.is_none());
        assert!(p.locomotion.is_none());
        assert_eq!(p.end_effectors.len(), 1);
        assert_eq!(p.end_effectors[0].name, "flange");
        assert!((p.end_effectors[0].max_payload_kg - 14.0).abs() < 0.01);
        assert_eq!(
            p.safe_stop_profile.strategy,
            SafeStopStrategy::ImmediateStop
        );
        assert_eq!(p.safe_stop_profile.target_joint_positions.len(), 7);
        assert!(p.environment.is_some());
        assert!(p.real_world_margins.is_some());
    }

    #[test]
    fn load_fourier_gr1() {
        let p = load_builtin("fourier_gr1").expect("load fourier_gr1");
        assert_eq!(p.name, "fourier_gr1");
        assert_eq!(p.joints.len(), 39);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        assert!((loco.max_locomotion_velocity - 1.39).abs() < 0.01);
        assert_eq!(p.end_effectors.len(), 2);
        assert_eq!(
            p.safe_stop_profile.strategy,
            SafeStopStrategy::ControlledCrouch
        );
    }

    #[test]
    fn load_tesla_optimus() {
        let p = load_builtin("tesla_optimus").expect("load tesla_optimus");
        assert_eq!(p.name, "tesla_optimus");
        assert_eq!(p.joints.len(), 28);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        assert!((loco.max_locomotion_velocity - 1.25).abs() < 0.01);
        assert_eq!(p.end_effectors.len(), 2);
    }

    #[test]
    fn load_figure_02() {
        let p = load_builtin("figure_02").expect("load figure_02");
        assert_eq!(p.name, "figure_02");
        assert_eq!(p.joints.len(), 42);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        assert_eq!(p.end_effectors.len(), 2);
        // Has per-finger joints
        assert!(p.joints.iter().any(|j| j.name == "left_hand_index"));
        assert!(p.joints.iter().any(|j| j.name == "right_hand_thumb_b"));
    }

    #[test]
    fn load_bd_atlas() {
        let p = load_builtin("bd_atlas").expect("load bd_atlas");
        assert_eq!(p.name, "bd_atlas");
        assert_eq!(p.joints.len(), 28);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        assert!((loco.max_locomotion_velocity - 2.5).abs() < 0.01);
        // Atlas is the most dynamic — highest GRF
        assert!(loco.max_ground_reaction_force > 1000.0);
        assert_eq!(p.end_effectors.len(), 2);
    }

    #[test]
    fn load_agility_digit() {
        let p = load_builtin("agility_digit").expect("load agility_digit");
        assert_eq!(p.name, "agility_digit");
        assert_eq!(p.joints.len(), 16);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        // Digit is legs-only, no arms
        assert!(p.end_effectors.is_empty());
        // Has unique leg structure with shin and tarsus
        assert!(p.joints.iter().any(|j| j.name == "left_tarsus"));
    }

    #[test]
    fn load_sanctuary_phoenix() {
        let p = load_builtin("sanctuary_phoenix").expect("load sanctuary_phoenix");
        assert_eq!(p.name, "sanctuary_phoenix");
        assert_eq!(p.joints.len(), 24);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        assert_eq!(p.end_effectors.len(), 2);
    }

    #[test]
    fn load_onex_neo() {
        let p = load_builtin("onex_neo").expect("load onex_neo");
        assert_eq!(p.name, "onex_neo");
        assert_eq!(p.joints.len(), 28);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        assert_eq!(p.end_effectors.len(), 2);
        // NEO designed for home — higher safety margins
        let margins = p.real_world_margins.as_ref().unwrap();
        assert!(margins.velocity_margin >= 0.20);
    }

    #[test]
    fn load_apptronik_apollo() {
        let p = load_builtin("apptronik_apollo").expect("load apptronik_apollo");
        assert_eq!(p.name, "apptronik_apollo");
        assert_eq!(p.joints.len(), 30);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        assert_eq!(p.end_effectors.len(), 2);
        // Apollo has high payload (25kg total, 12.5 per hand)
        assert!((p.end_effectors[0].max_payload_kg - 12.5).abs() < 0.01);
    }

    #[test]
    fn load_unitree_go2() {
        let p = load_builtin("unitree_go2").expect("load unitree_go2");
        assert_eq!(p.name, "unitree_go2");
        assert_eq!(p.joints.len(), 12);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        // Go2 is fast for its size
        assert!((loco.max_locomotion_velocity - 3.5).abs() < 0.01);
        assert_eq!(p.collision_pairs.len(), 4);
        assert!(p.environment.is_some());
    }

    #[test]
    fn load_anybotics_anymal() {
        let p = load_builtin("anybotics_anymal").expect("load anybotics_anymal");
        assert_eq!(p.name, "anybotics_anymal");
        assert_eq!(p.joints.len(), 12);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        // ANYmal has wider stance than Go2
        let stability = p.stability.as_ref().unwrap();
        assert!(stability.com_height_estimate > 0.4);
        let env = p.environment.as_ref().unwrap();
        // Industrial robot — wider terrain tolerance
        assert!(env.max_safe_pitch_rad > 0.3);
    }

    #[test]
    fn load_allegro_hand() {
        let p = load_builtin("allegro_hand").expect("load allegro_hand");
        assert_eq!(p.name, "allegro_hand");
        assert_eq!(p.joints.len(), 16);
        assert!(p.stability.is_none());
        assert!(p.locomotion.is_none());
        assert!(p.end_effectors.len() >= 2);
        assert_eq!(
            p.safe_stop_profile.strategy,
            SafeStopStrategy::ImmediateStop
        );
    }

    #[test]
    fn load_leap_hand() {
        let p = load_builtin("leap_hand").expect("load leap_hand");
        assert_eq!(p.name, "leap_hand");
        assert_eq!(p.joints.len(), 16);
        assert!(p.stability.is_none());
        assert!(p.locomotion.is_none());
        // LEAP has lighter actuators than Allegro
        let allegro = load_builtin("allegro_hand").unwrap();
        assert!(p.joints[0].max_torque < allegro.joints[0].max_torque);
    }

    #[test]
    fn load_psyonic_ability() {
        let p = load_builtin("psyonic_ability").expect("load psyonic_ability");
        assert_eq!(p.name, "psyonic_ability");
        assert_eq!(p.joints.len(), 6);
        assert!(p.stability.is_none());
        assert!(p.locomotion.is_none());
        assert!(!p.end_effectors.is_empty());
    }

    #[test]
    fn load_unitree_a1() {
        let p = load_builtin("unitree_a1").expect("load unitree_a1");
        assert_eq!(p.name, "unitree_a1");
        assert_eq!(p.joints.len(), 12);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        assert!((loco.max_locomotion_velocity - 3.3).abs() < 0.01);
        // A1 is lighter than Go2 — lower GRF
        let go2 = load_builtin("unitree_go2").unwrap();
        assert!(
            loco.max_ground_reaction_force
                <= go2.locomotion.as_ref().unwrap().max_ground_reaction_force
        );
    }

    #[test]
    fn load_spot_with_arm() {
        let p = load_builtin("spot_with_arm").expect("load spot_with_arm");
        assert_eq!(p.name, "spot_with_arm");
        assert_eq!(p.joints.len(), 19);
        assert!(p.stability.is_some());
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        // Slower than base Spot due to arm
        let spot = load_builtin("spot").unwrap();
        assert!(
            loco.max_locomotion_velocity
                < spot.locomotion.as_ref().unwrap().max_locomotion_velocity
        );
        // Has arm end effector
        assert!(!p.end_effectors.is_empty());
        assert!((p.end_effectors[0].max_payload_kg - 11.0).abs() < 0.01);
    }

    #[test]
    fn load_hello_stretch() {
        let p = load_builtin("hello_stretch").expect("load hello_stretch");
        assert_eq!(p.name, "hello_stretch");
        assert_eq!(p.joints.len(), 4);
        assert!(p.stability.is_none()); // wheeled base
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        assert!((loco.max_locomotion_velocity - 0.3).abs() < 0.01);
        // Has prismatic joints
        assert!(p
            .joints
            .iter()
            .any(|j| j.joint_type == JointType::Prismatic));
        assert!(!p.end_effectors.is_empty());
    }

    #[test]
    fn load_pal_tiago() {
        let p = load_builtin("pal_tiago").expect("load pal_tiago");
        assert_eq!(p.name, "pal_tiago");
        assert_eq!(p.joints.len(), 14);
        assert!(p.stability.is_none()); // wheeled base
        assert!(p.locomotion.is_some());
        let loco = p.locomotion.as_ref().unwrap();
        assert!((loco.max_locomotion_velocity - 1.0).abs() < 0.01);
        // Has prismatic joints (torso_lift, grippers)
        assert!(p
            .joints
            .iter()
            .any(|j| j.joint_type == JointType::Prismatic));
        assert!(!p.end_effectors.is_empty());
    }

    // --- List builtins ---

    #[test]
    fn list_builtins_returns_all() {
        let names = list_builtins();
        assert_eq!(names.len(), 34);
        assert!(names.contains(&"humanoid_28dof"));
        assert!(names.contains(&"franka_panda"));
        assert!(names.contains(&"quadruped_12dof"));
        assert!(names.contains(&"ur10"));
        assert!(names.contains(&"unitree_h1"));
        assert!(names.contains(&"unitree_g1"));
        assert!(names.contains(&"spot"));
        assert!(names.contains(&"kuka_iiwa14"));
        assert!(names.contains(&"fourier_gr1"));
        assert!(names.contains(&"tesla_optimus"));
        assert!(names.contains(&"figure_02"));
        assert!(names.contains(&"bd_atlas"));
        assert!(names.contains(&"agility_digit"));
        assert!(names.contains(&"sanctuary_phoenix"));
        assert!(names.contains(&"onex_neo"));
        assert!(names.contains(&"apptronik_apollo"));
        assert!(names.contains(&"unitree_go2"));
        assert!(names.contains(&"anybotics_anymal"));
        assert!(names.contains(&"allegro_hand"));
        assert!(names.contains(&"leap_hand"));
        assert!(names.contains(&"psyonic_ability"));
        assert!(names.contains(&"unitree_a1"));
        assert!(names.contains(&"spot_with_arm"));
        assert!(names.contains(&"hello_stretch"));
        assert!(names.contains(&"pal_tiago"));
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
