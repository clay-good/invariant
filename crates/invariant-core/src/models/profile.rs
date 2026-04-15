use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::collections::HashSet;

use super::error::{Validate, ValidationError};

// --- Enums for type-safe profile fields (P2-1, P2-2, P2-3, P1-6) ---

/// Joint kinematics type. Prevents silent dispatch on unknown type strings (P2-2).
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::profile::JointType;
///
/// let jt: JointType = serde_json::from_str(r#""revolute""#).unwrap();
/// assert_eq!(jt, JointType::Revolute);
///
/// let jt2: JointType = serde_json::from_str(r#""prismatic""#).unwrap();
/// assert_eq!(jt2, JointType::Prismatic);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JointType {
    /// A rotational joint that moves through an angular range.
    Revolute,
    /// A translational joint that slides along a linear axis.
    Prismatic,
}

/// Workspace bounding volume type. Prevents silent skip on unknown type strings (P2-1).
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::profile::BoundsType;
///
/// let bt: BoundsType = serde_json::from_str(r#""aabb""#).unwrap();
/// assert_eq!(bt, BoundsType::Aabb);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BoundsType {
    /// Axis-aligned bounding box defined by a min and max corner.
    Aabb,
}

/// Safe-stop behaviour strategy. Prevents silent watchdog failure on unknown strings (P1-6).
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::profile::SafeStopStrategy;
///
/// // Default strategy is ControlledCrouch
/// let default = SafeStopStrategy::default();
/// assert_eq!(default, SafeStopStrategy::ControlledCrouch);
///
/// let s: SafeStopStrategy = serde_json::from_str(r#""immediate_stop""#).unwrap();
/// assert_eq!(s, SafeStopStrategy::ImmediateStop);
///
/// let s2: SafeStopStrategy = serde_json::from_str(r#""park_position""#).unwrap();
/// assert_eq!(s2, SafeStopStrategy::ParkPosition);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafeStopStrategy {
    /// Gradually lower the robot's center of mass into a stable crouched pose (default).
    #[default]
    ControlledCrouch,
    /// Halt all motion immediately by cutting actuator commands.
    ImmediateStop,
    /// Move all joints to the designated park/home position.
    ParkPosition,
}

// --- CollisionPair (P3-6): named struct instead of positional [String; 2] ---

/// A pair of links that must be checked for self-collision (P3-6).
///
/// Serialised as a two-element JSON array `["link_a", "link_b"]` for backward
/// compatibility with existing profile files.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::profile::CollisionPair;
///
/// let pair = CollisionPair {
///     link_a: "upper_arm_link".into(),
///     link_b: "forearm_link".into(),
/// };
///
/// // Round-trip through JSON produces the two-element array format
/// let json = serde_json::to_string(&pair).unwrap();
/// assert_eq!(json, r#"["upper_arm_link","forearm_link"]"#);
///
/// let pair2: CollisionPair = serde_json::from_str(&json).unwrap();
/// assert_eq!(pair2.link_a, "upper_arm_link");
/// assert_eq!(pair2.link_b, "forearm_link");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionPair {
    /// Name of the first link in the collision pair.
    pub link_a: String,
    /// Name of the second link in the collision pair.
    pub link_b: String,
}

impl Serialize for CollisionPair {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(2))?;
        seq.serialize_element(&self.link_a)?;
        seq.serialize_element(&self.link_b)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for CollisionPair {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let arr: [String; 2] = Deserialize::deserialize(d)?;
        Ok(CollisionPair {
            link_a: arr[0].clone(),
            link_b: arr[1].clone(),
        })
    }
}

// --- Profile structs ---

/// Configuration profile for a robot, containing kinematic limits and safety zones.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::profile::{RobotProfile, WorkspaceBounds};
/// use invariant_robotics_core::models::error::Validate;
///
/// let json = r#"{
///   "name": "simple_arm",
///   "version": "1.0.0",
///   "joints": [
///     {
///       "name": "shoulder_pan",
///       "type": "revolute",
///       "min": -3.14159,
///       "max":  3.14159,
///       "max_velocity": 3.14,
///       "max_torque": 150.0,
///       "max_acceleration": 10.0
///     }
///   ],
///   "workspace": {
///     "type": "aabb",
///     "min": [-1.0, -1.0, 0.0],
///     "max": [ 1.0,  1.0, 2.0]
///   },
///   "max_delta_time": 0.05
/// }"#;
///
/// let profile: RobotProfile = serde_json::from_str(json).unwrap();
/// assert_eq!(profile.name, "simple_arm");
/// assert_eq!(profile.joints.len(), 1);
/// assert!(profile.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RobotProfile {
    /// Human-readable robot model name (e.g. `"ur10e"`).
    pub name: String,
    /// Semantic version string for this profile (e.g. `"1.0.0"`).
    pub version: String,
    /// Ordered list of joint definitions covering all controlled degrees of freedom.
    pub joints: Vec<JointDefinition>,
    /// Workspace bounding volume; commands that place the robot outside this volume are rejected.
    pub workspace: WorkspaceBounds,
    /// Spatial regions the robot must never enter; defaults to empty.
    #[serde(default)]
    pub exclusion_zones: Vec<ExclusionZone>,
    /// Zones that trigger velocity derating when a human is detected nearby; defaults to empty.
    #[serde(default)]
    pub proximity_zones: Vec<ProximityZone>,
    /// Link pairs that are checked for self-collision; defaults to empty.
    #[serde(default)]
    pub collision_pairs: Vec<CollisionPair>,
    /// Static stability configuration (ZMP/support-polygon check); absent disables check.
    #[serde(default)]
    pub stability: Option<StabilityConfig>,
    /// Locomotion safety limits for legged/mobile robots (P15–P20).
    /// Optional; locomotion checks are skipped when absent.
    #[serde(default)]
    pub locomotion: Option<LocomotionConfig>,
    /// Maximum allowed elapsed time between consecutive command timestamps (s).
    pub max_delta_time: f64,
    /// Minimum allowed clearance between self-collision link pairs (m); defaults to 0.01.
    #[serde(default = "default_min_collision_distance")]
    pub min_collision_distance: f64,
    /// Global velocity scale factor applied to all joints; must be in `(0.0, 1.0]`.
    #[serde(default = "default_velocity_scale")]
    pub global_velocity_scale: f64,
    /// Watchdog timeout in milliseconds; if no command arrives within this window the safe-stop is triggered.
    #[serde(default = "default_watchdog_timeout_ms")]
    pub watchdog_timeout_ms: u64,
    /// Behaviour and target state used when a safe-stop is triggered.
    #[serde(default)]
    pub safe_stop_profile: SafeStopProfile,
    /// End-effector configuration for manipulation safety checks (P11–P14).
    /// Optional; manipulation checks are skipped when absent.
    #[serde(default)]
    pub end_effectors: Vec<EndEffectorConfig>,
    /// Ed25519 signature over the canonical profile JSON (Section 8.3).
    /// Used to verify profile integrity at load time.
    #[serde(default)]
    pub profile_signature: Option<String>,
    /// Key identifier of the profile signer (Section 8.3).
    #[serde(default)]
    pub profile_signer_kid: Option<String>,
    /// Monotonic config version for anti-rollback (Section 8.3).
    #[serde(default)]
    pub config_sequence: Option<u64>,
    /// Per-joint real-world margins for sim-to-real transfer (Section 18.2).
    /// When present, Guardian mode tightens limits by these fractions.
    #[serde(default)]
    pub real_world_margins: Option<RealWorldMargins>,
    /// Task-scoped safety envelope overrides (Section 17).
    #[serde(default)]
    pub task_envelope: Option<TaskEnvelope>,
    /// Environmental awareness limits for P21–P25 checks (terrain, temperature,
    /// battery, latency). Optional; environmental checks are skipped when absent.
    #[serde(default)]
    pub environment: Option<EnvironmentConfig>,
}

fn default_min_collision_distance() -> f64 {
    0.01
}

fn default_velocity_scale() -> f64 {
    1.0
}

fn default_watchdog_timeout_ms() -> u64 {
    50
}

/// Maximum number of joints per profile (prevents memory-exhaustion DoS).
const MAX_JOINTS: usize = 256;
/// Maximum number of exclusion zones per profile.
const MAX_EXCLUSION_ZONES: usize = 256;
/// Maximum number of proximity zones per profile.
const MAX_PROXIMITY_ZONES: usize = 256;
/// Maximum number of collision pairs per profile.
const MAX_COLLISION_PAIRS: usize = 1024;

impl Validate for RobotProfile {
    fn validate(&self) -> Result<(), ValidationError> {
        // A profile must define at least one joint — zero joints would bypass
        // all joint-based physics checks (P1-P4, P10) vacuously.
        if self.joints.is_empty() {
            return Err(ValidationError::NoJoints);
        }

        // Collection length caps (R1-11) — reject oversized inputs early.
        if self.joints.len() > MAX_JOINTS {
            return Err(ValidationError::CollectionTooLarge {
                name: "joints",
                count: self.joints.len(),
                max: MAX_JOINTS,
            });
        }
        if self.exclusion_zones.len() > MAX_EXCLUSION_ZONES {
            return Err(ValidationError::CollectionTooLarge {
                name: "exclusion_zones",
                count: self.exclusion_zones.len(),
                max: MAX_EXCLUSION_ZONES,
            });
        }
        if self.proximity_zones.len() > MAX_PROXIMITY_ZONES {
            return Err(ValidationError::CollectionTooLarge {
                name: "proximity_zones",
                count: self.proximity_zones.len(),
                max: MAX_PROXIMITY_ZONES,
            });
        }
        if self.collision_pairs.len() > MAX_COLLISION_PAIRS {
            return Err(ValidationError::CollectionTooLarge {
                name: "collision_pairs",
                count: self.collision_pairs.len(),
                max: MAX_COLLISION_PAIRS,
            });
        }

        // P2-5: global_velocity_scale must be in (0.0, 1.0]
        if self.global_velocity_scale <= 0.0 || self.global_velocity_scale > 1.0 {
            return Err(ValidationError::VelocityScaleOutOfRange(
                self.global_velocity_scale,
            ));
        }

        // min_collision_distance must be strictly positive when collision_pairs
        // are defined; a value of 0.0 (or negative) would never flag any
        // collision and silently disable the self-collision check.
        if !self.collision_pairs.is_empty() && self.min_collision_distance <= 0.0 {
            return Err(ValidationError::InvalidMinCollisionDistance {
                value: self.min_collision_distance,
            });
        }

        // Reject duplicate joint names before per-joint validation.
        let mut joint_names: HashSet<&str> = HashSet::new();
        for joint in &self.joints {
            if !joint_names.insert(joint.name.as_str()) {
                return Err(ValidationError::DuplicateJointName {
                    name: joint.name.clone(),
                });
            }
        }

        // Validate workspace bounds
        self.workspace.validate()?;

        // Validate each joint
        for joint in &self.joints {
            joint.validate()?;
        }

        // Validate proximity zone velocity scales (P2-6)
        for zone in &self.proximity_zones {
            zone.validate()?;
        }

        // Validate task envelope tighten-only constraints (Section 17.2)
        if let Some(ref env) = self.task_envelope {
            self.validate_task_envelope(env)?;
        }

        // Validate stability config (P9) — polygon vertices must be finite,
        // com_height_estimate must be finite and positive, and an enabled config
        // must have >= 3 vertices (otherwise the ray-casting check always fails).
        // NaN polygon vertices would silently corrupt the ray-casting algorithm,
        // causing it to skip edges and produce incorrect inside/outside results.
        if let Some(ref stab) = self.stability {
            let err = |reason: String| ValidationError::StabilityConfigInvalid { reason };
            if !stab.com_height_estimate.is_finite() || stab.com_height_estimate <= 0.0 {
                return Err(err(format!(
                    "com_height_estimate must be finite and positive, got {}",
                    stab.com_height_estimate
                )));
            }
            if stab.enabled && stab.support_polygon.len() < 3 {
                return Err(err(format!(
                    "enabled stability config must have >= 3 polygon vertices, got {}",
                    stab.support_polygon.len()
                )));
            }
            for (i, vertex) in stab.support_polygon.iter().enumerate() {
                if !vertex[0].is_finite() || !vertex[1].is_finite() {
                    return Err(err(format!(
                        "support_polygon vertex {} has non-finite coordinates: [{}, {}]",
                        i, vertex[0], vertex[1]
                    )));
                }
            }
        }

        // max_delta_time must be finite and positive — zero or negative would
        // cause P8 (delta-time check) to either reject everything or behave
        // unpredictably.
        if !self.max_delta_time.is_finite() || self.max_delta_time <= 0.0 {
            return Err(ValidationError::InvalidMaxDeltaTime(self.max_delta_time));
        }

        // Validate locomotion config (P15-P20) — all fields must be finite and positive.
        if let Some(ref loco) = self.locomotion {
            let err = |reason: String| ValidationError::LocomotionConfigInvalid { reason };
            if !loco.max_locomotion_velocity.is_finite() || loco.max_locomotion_velocity <= 0.0 {
                return Err(err(format!(
                    "max_locomotion_velocity must be finite and positive, got {}",
                    loco.max_locomotion_velocity
                )));
            }
            if !loco.max_step_length.is_finite() || loco.max_step_length <= 0.0 {
                return Err(err(format!(
                    "max_step_length must be finite and positive, got {}",
                    loco.max_step_length
                )));
            }
            if !loco.min_foot_clearance.is_finite() || loco.min_foot_clearance < 0.0 {
                return Err(err(format!(
                    "min_foot_clearance must be finite and non-negative, got {}",
                    loco.min_foot_clearance
                )));
            }
            if !loco.max_ground_reaction_force.is_finite() || loco.max_ground_reaction_force <= 0.0
            {
                return Err(err(format!(
                    "max_ground_reaction_force must be finite and positive, got {}",
                    loco.max_ground_reaction_force
                )));
            }
            if !loco.friction_coefficient.is_finite()
                || loco.friction_coefficient <= 0.0
                || loco.friction_coefficient > 2.0
            {
                return Err(err(format!(
                    "friction_coefficient must be finite and in (0.0, 2.0], got {}",
                    loco.friction_coefficient
                )));
            }
            if !loco.max_heading_rate.is_finite() || loco.max_heading_rate <= 0.0 {
                return Err(err(format!(
                    "max_heading_rate must be finite and positive, got {}",
                    loco.max_heading_rate
                )));
            }
            if !loco.max_step_height.is_finite() || loco.max_step_height <= 0.0 {
                return Err(err(format!(
                    "max_step_height must be finite and positive, got {}",
                    loco.max_step_height
                )));
            }
            if loco.max_step_height <= loco.min_foot_clearance {
                return Err(err(format!(
                    "max_step_height ({}) must be greater than min_foot_clearance ({})",
                    loco.max_step_height, loco.min_foot_clearance
                )));
            }
        }

        // Validate real-world margins — each must be in [0.0, 1.0) and finite.
        // Negative margins would silently loosen limits (defeating Guardian mode).
        // Margins >= 1.0 would zero or invert effective limits (DoS or undefined).
        if let Some(ref m) = self.real_world_margins {
            let err = |reason: String| ValidationError::RealWorldMarginsInvalid { reason };
            for (name, val) in [
                ("position_margin", m.position_margin),
                ("velocity_margin", m.velocity_margin),
                ("torque_margin", m.torque_margin),
                ("acceleration_margin", m.acceleration_margin),
            ] {
                if !val.is_finite() || !(0.0..1.0).contains(&val) {
                    return Err(err(format!(
                        "{name} must be finite and in [0.0, 1.0), got {val}"
                    )));
                }
            }
        }

        // Validate end-effector configs (P11-P14)
        for ee in &self.end_effectors {
            let err = |reason: String| ValidationError::EndEffectorConfigInvalid {
                name: ee.name.clone(),
                reason,
            };
            if !ee.max_force_n.is_finite() || ee.max_force_n <= 0.0 {
                return Err(err(format!(
                    "max_force_n must be finite and positive, got {}",
                    ee.max_force_n
                )));
            }
            if !ee.max_grasp_force_n.is_finite() || ee.max_grasp_force_n <= 0.0 {
                return Err(err(format!(
                    "max_grasp_force_n must be finite and positive, got {}",
                    ee.max_grasp_force_n
                )));
            }
            if !ee.min_grasp_force_n.is_finite() || ee.min_grasp_force_n < 0.0 {
                return Err(err(format!(
                    "min_grasp_force_n must be finite and non-negative, got {}",
                    ee.min_grasp_force_n
                )));
            }
            if ee.min_grasp_force_n >= ee.max_grasp_force_n {
                return Err(err(format!(
                    "min_grasp_force_n ({}) must be less than max_grasp_force_n ({})",
                    ee.min_grasp_force_n, ee.max_grasp_force_n
                )));
            }
            if !ee.max_force_rate_n_per_s.is_finite() || ee.max_force_rate_n_per_s <= 0.0 {
                return Err(err(format!(
                    "max_force_rate_n_per_s must be finite and positive, got {}",
                    ee.max_force_rate_n_per_s
                )));
            }
            if !ee.max_payload_kg.is_finite() || ee.max_payload_kg < 0.0 {
                return Err(err(format!(
                    "max_payload_kg must be finite and non-negative, got {}",
                    ee.max_payload_kg
                )));
            }
        }

        // Validate environment config consistency (P21-P25)
        if let Some(ref env_cfg) = self.environment {
            let err = |reason: String| ValidationError::EnvironmentConfigInvalid { reason };

            if !env_cfg.max_safe_pitch_rad.is_finite() || env_cfg.max_safe_pitch_rad <= 0.0 {
                return Err(err(format!(
                    "max_safe_pitch_rad must be finite and positive, got {}",
                    env_cfg.max_safe_pitch_rad
                )));
            }
            if !env_cfg.max_safe_roll_rad.is_finite() || env_cfg.max_safe_roll_rad <= 0.0 {
                return Err(err(format!(
                    "max_safe_roll_rad must be finite and positive, got {}",
                    env_cfg.max_safe_roll_rad
                )));
            }
            if !env_cfg.max_operating_temperature_c.is_finite()
                || env_cfg.max_operating_temperature_c <= 0.0
            {
                return Err(err(format!(
                    "max_operating_temperature_c must be finite and positive, got {}",
                    env_cfg.max_operating_temperature_c
                )));
            }
            if env_cfg.critical_battery_pct >= env_cfg.low_battery_pct {
                return Err(err(format!(
                    "critical_battery_pct ({}) must be less than low_battery_pct ({})",
                    env_cfg.critical_battery_pct, env_cfg.low_battery_pct
                )));
            }
            if env_cfg.warning_latency_ms >= env_cfg.max_latency_ms {
                return Err(err(format!(
                    "warning_latency_ms ({}) must be less than max_latency_ms ({})",
                    env_cfg.warning_latency_ms, env_cfg.max_latency_ms
                )));
            }
            if !env_cfg.max_latency_ms.is_finite() || env_cfg.max_latency_ms <= 0.0 {
                return Err(err(format!(
                    "max_latency_ms must be finite and positive, got {}",
                    env_cfg.max_latency_ms
                )));
            }
        }

        Ok(())
    }
}

impl RobotProfile {
    /// Validate that a task envelope only tightens limits, never loosens them.
    fn validate_task_envelope(&self, env: &TaskEnvelope) -> Result<(), ValidationError> {
        let err = |reason: String| ValidationError::TaskEnvelopeInvalid {
            name: env.name.clone(),
            reason,
        };

        // Velocity scale must be <= profile's velocity scale.
        if let Some(env_scale) = env.global_velocity_scale {
            if env_scale > self.global_velocity_scale {
                return Err(err(format!(
                    "global_velocity_scale {} exceeds profile's {}",
                    env_scale, self.global_velocity_scale
                )));
            }
            if env_scale <= 0.0 {
                return Err(err(format!(
                    "global_velocity_scale {} must be positive",
                    env_scale
                )));
            }
        }

        // Envelope workspace must be a subset of profile workspace.
        if let Some(ref env_ws) = env.workspace {
            match (&self.workspace, env_ws) {
                (
                    WorkspaceBounds::Aabb {
                        min: p_min,
                        max: p_max,
                    },
                    WorkspaceBounds::Aabb {
                        min: e_min,
                        max: e_max,
                    },
                ) => {
                    for i in 0..3 {
                        if e_min[i] < p_min[i] || e_max[i] > p_max[i] {
                            return Err(err(format!(
                                "workspace not contained within profile workspace on axis {i} \
                                 (envelope [{}, {}] vs profile [{}, {}])",
                                e_min[i], e_max[i], p_min[i], p_max[i]
                            )));
                        }
                    }
                    // Envelope workspace must also be valid (min < max).
                    env_ws.validate()?;
                }
            }
        }

        // End-effector force limit must be <= profile's force limit.
        if let Some(env_force) = env.end_effector_force_limit_n {
            if env_force < 0.0 {
                return Err(err(format!(
                    "end_effector_force_limit_n {} must be non-negative",
                    env_force
                )));
            }
            for ee in &self.end_effectors {
                if env_force > ee.max_force_n {
                    return Err(err(format!(
                        "end_effector_force_limit_n {} exceeds profile end-effector '{}' max_force_n {}",
                        env_force, ee.name, ee.max_force_n
                    )));
                }
            }
        }

        // Payload limit must be <= profile's payload limit.
        if let Some(env_payload) = env.max_payload_kg {
            if env_payload < 0.0 {
                return Err(err(format!(
                    "max_payload_kg {} must be non-negative",
                    env_payload
                )));
            }
            for ee in &self.end_effectors {
                if env_payload > ee.max_payload_kg {
                    return Err(err(format!(
                        "max_payload_kg {} exceeds profile end-effector '{}' max_payload_kg {}",
                        env_payload, ee.name, ee.max_payload_kg
                    )));
                }
            }
        }

        // Additional exclusion zones collection size check.
        let total_zones = self.exclusion_zones.len() + env.additional_exclusion_zones.len();
        if total_zones > MAX_EXCLUSION_ZONES {
            return Err(err(format!(
                "total exclusion zones ({} profile + {} envelope = {}) exceeds maximum {}",
                self.exclusion_zones.len(),
                env.additional_exclusion_zones.len(),
                total_zones,
                MAX_EXCLUSION_ZONES
            )));
        }

        Ok(())
    }
}

/// Kinematic and safety limits for a single robot joint.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::profile::{JointDefinition, JointType};
/// use invariant_robotics_core::models::error::{Validate, ValidationError};
///
/// // Valid revolute joint
/// let joint = JointDefinition {
///     name: "wrist_3".into(),
///     joint_type: JointType::Revolute,
///     min: -6.283,   // -360 degrees
///     max:  6.283,   //  360 degrees
///     max_velocity: 3.14,    // rad/s
///     max_torque: 28.0,      // N·m
///     max_acceleration: 50.0,  // rad/s²
/// };
/// assert!(joint.validate().is_ok());
///
/// // Invalid: inverted limits
/// let bad = JointDefinition {
///     name: "bad".into(),
///     joint_type: JointType::Revolute,
///     min: 1.0,
///     max: -1.0,
///     max_velocity: 1.0,
///     max_torque: 1.0,
///     max_acceleration: 1.0,
/// };
/// assert!(matches!(bad.validate(), Err(ValidationError::JointLimitsInverted { .. })));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JointDefinition {
    /// Unique joint name matching the robot's kinematic description.
    pub name: String,
    /// Kinematic type of this joint (revolute or prismatic).
    #[serde(rename = "type")]
    pub joint_type: JointType,
    /// Lower position limit (rad for revolute, m for prismatic).
    pub min: f64,
    /// Upper position limit (rad for revolute, m for prismatic).
    pub max: f64,
    /// Maximum allowed joint velocity (rad/s or m/s).
    pub max_velocity: f64,
    /// Maximum allowed joint torque or force (N·m or N).
    pub max_torque: f64,
    /// Maximum allowed joint acceleration (rad/s² or m/s²).
    pub max_acceleration: f64,
}

impl Validate for JointDefinition {
    fn validate(&self) -> Result<(), ValidationError> {
        // P2-4: min must be strictly less than max
        if self.min >= self.max {
            return Err(ValidationError::JointLimitsInverted {
                name: self.name.clone(),
                min: self.min,
                max: self.max,
            });
        }
        // P2-4: positive-valued limits
        if self.max_velocity <= 0.0 {
            return Err(ValidationError::JointLimitNotPositive {
                name: self.name.clone(),
                field: "max_velocity",
                value: self.max_velocity,
            });
        }
        if self.max_torque <= 0.0 {
            return Err(ValidationError::JointLimitNotPositive {
                name: self.name.clone(),
                field: "max_torque",
                value: self.max_torque,
            });
        }
        if self.max_acceleration <= 0.0 {
            return Err(ValidationError::JointLimitNotPositive {
                name: self.name.clone(),
                field: "max_acceleration",
                value: self.max_acceleration,
            });
        }
        // Reject NaN/infinite values which would vacuously pass all comparisons.
        if !self.min.is_finite() || !self.max.is_finite() {
            return Err(ValidationError::JointLimitNotFinite {
                name: self.name.clone(),
                field: "min/max",
            });
        }
        if !self.max_velocity.is_finite() {
            return Err(ValidationError::JointLimitNotFinite {
                name: self.name.clone(),
                field: "max_velocity",
            });
        }
        if !self.max_torque.is_finite() {
            return Err(ValidationError::JointLimitNotFinite {
                name: self.name.clone(),
                field: "max_torque",
            });
        }
        if !self.max_acceleration.is_finite() {
            return Err(ValidationError::JointLimitNotFinite {
                name: self.name.clone(),
                field: "max_acceleration",
            });
        }
        Ok(())
    }
}

/// Workspace bounding volume — uses a tagged enum so unknown types are rejected
/// at deserialisation time rather than silently skipping the workspace check (P2-1).
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::profile::WorkspaceBounds;
/// use invariant_robotics_core::models::error::{Validate, ValidationError};
///
/// // Construct a valid AABB workspace
/// let ws = WorkspaceBounds::Aabb {
///     min: [-1.0, -1.0, 0.0],
///     max: [ 1.0,  1.0, 2.0],
/// };
/// assert!(ws.validate().is_ok());
///
/// // Inverted bounds are rejected
/// let bad = WorkspaceBounds::Aabb {
///     min: [1.0, 0.0, 0.0],
///     max: [0.0, 1.0, 1.0],  // x: min > max
/// };
/// assert!(matches!(bad.validate(), Err(ValidationError::WorkspaceBoundsInverted { .. })));
///
/// // Deserialise from the tagged JSON format
/// let json = r#"{"type":"aabb","min":[-0.5,-0.5,0.0],"max":[0.5,0.5,1.5]}"#;
/// let ws2: WorkspaceBounds = serde_json::from_str(json).unwrap();
/// assert!(ws2.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WorkspaceBounds {
    /// Axis-aligned bounding box workspace volume.
    Aabb {
        /// Minimum corner of the AABB `[x, y, z]` in metres.
        min: [f64; 3],
        /// Maximum corner of the AABB `[x, y, z]` in metres.
        max: [f64; 3],
    },
}

impl Validate for WorkspaceBounds {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            WorkspaceBounds::Aabb { min, max } => {
                for (i, (lo, hi)) in min.iter().zip(max.iter()).enumerate() {
                    if !lo.is_finite() || !hi.is_finite() {
                        return Err(ValidationError::WorkspaceBoundsNotFinite { axis: i });
                    }
                }
                if min[0] >= max[0] || min[1] >= max[1] || min[2] >= max[2] {
                    return Err(ValidationError::WorkspaceBoundsInverted {
                        min: *min,
                        max: *max,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Exclusion zone — tagged enum prevents unknown zone types from silently passing (P2-3 pattern).
/// `#[non_exhaustive]` allows new variants (e.g., `Cylinder`) without breaking downstream matches (P3-5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[non_exhaustive]
pub enum ExclusionZone {
    /// Axis-aligned bounding box exclusion zone.
    Aabb {
        /// Unique name identifying this exclusion zone.
        name: String,
        /// Minimum corner of the AABB `[x, y, z]` in metres.
        min: [f64; 3],
        /// Maximum corner of the AABB `[x, y, z]` in metres.
        max: [f64; 3],
        /// If `true`, this zone can be disabled at runtime via `Command.zone_overrides`.
        /// Conditional zones are ACTIVE by default (fail-closed) — they must be
        /// explicitly disabled by setting the override to `false`.
        #[serde(default)]
        conditional: bool,
    },
    /// Spherical exclusion zone.
    Sphere {
        /// Unique name identifying this exclusion zone.
        name: String,
        /// Centre of the sphere `[x, y, z]` in metres.
        center: [f64; 3],
        /// Radius of the sphere in metres.
        radius: f64,
        /// If `true`, this zone can be disabled at runtime via `Command.zone_overrides`.
        #[serde(default)]
        conditional: bool,
    },
}

/// Proximity zone — tagged enum consistent with `ExclusionZone` (P2-3).
/// `#[non_exhaustive]` future-proofs for additional zone shapes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[non_exhaustive]
pub enum ProximityZone {
    /// Spherical proximity zone that triggers velocity derating when occupied.
    Sphere {
        /// Unique name identifying this proximity zone.
        name: String,
        /// Centre of the sphere `[x, y, z]` in metres.
        center: [f64; 3],
        /// Radius of the sphere in metres.
        radius: f64,
        /// Must be in `(0.0, 1.0]` — values > 1.0 would allow speeds above hardware
        /// max near humans, defeating ISO/TS 15066 (P2-6).
        velocity_scale: f64,
        /// If `true`, the zone centre may be updated at runtime to track a moving obstacle.
        #[serde(default)]
        dynamic: bool,
    },
}

impl Validate for ProximityZone {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            ProximityZone::Sphere {
                name,
                radius,
                velocity_scale,
                ..
            } => {
                if !radius.is_finite() || *radius <= 0.0 {
                    return Err(ValidationError::ProximityRadiusInvalid {
                        name: name.clone(),
                        radius: *radius,
                    });
                }
                if *velocity_scale <= 0.0 || *velocity_scale > 1.0 {
                    return Err(ValidationError::ProximityVelocityScaleOutOfRange {
                        name: name.clone(),
                        scale: *velocity_scale,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Locomotion safety limits for legged/mobile robots (P15–P20).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocomotionConfig {
    /// Maximum allowed magnitude of the base linear velocity vector (m/s). (P15)
    pub max_locomotion_velocity: f64,
    /// Maximum allowed commanded step length (m). (P19)
    pub max_step_length: f64,
    /// Minimum required foot clearance height above ground for swing feet (m). (P16)
    pub min_foot_clearance: f64,
    /// Maximum allowed foot height during swing phase (m). (P16)
    ///
    /// Prevents stomping — a foot raised excessively high will slam down with
    /// dangerous force. Must be greater than `min_foot_clearance`.
    /// Defaults to 0.5 m for backward compatibility with profiles that omit it.
    #[serde(default = "default_max_step_height")]
    pub max_step_height: f64,
    /// Maximum allowed magnitude of the ground reaction force per foot (N). (P17)
    pub max_ground_reaction_force: f64,
    /// Coulomb friction coefficient for friction-cone constraint (dimensionless). (P18)
    pub friction_coefficient: f64,
    /// Maximum allowed heading (yaw) rate (rad/s). (P20)
    pub max_heading_rate: f64,
}

fn default_max_step_height() -> f64 {
    0.5
}

/// Environmental awareness limits for P21–P25 checks.
///
/// All thresholds have sensible defaults so profiles can opt in with just
/// `"environment": {}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    /// P21: Maximum safe pitch angle in radians (default: 15° = 0.2618 rad).
    #[serde(default = "default_max_pitch")]
    pub max_safe_pitch_rad: f64,
    /// P21: Maximum safe roll angle in radians (default: 10° = 0.1745 rad).
    #[serde(default = "default_max_roll")]
    pub max_safe_roll_rad: f64,
    /// P21: Warning pitch angle — above this, derate velocity (default: 8° = 0.1396 rad).
    #[serde(default = "default_warning_pitch")]
    pub warning_pitch_rad: f64,
    /// P21: Warning roll angle (default: 5° = 0.0873 rad).
    #[serde(default = "default_warning_roll")]
    pub warning_roll_rad: f64,
    /// P22: Maximum operating temperature in °C (default: 80.0).
    #[serde(default = "default_max_temp")]
    pub max_operating_temperature_c: f64,
    /// P22: Warning temperature — above this, derate torque (default: 65.0°C).
    #[serde(default = "default_warning_temp")]
    pub warning_temperature_c: f64,
    /// P23: Critical battery percentage — below this, reject all commands (default: 5.0).
    #[serde(default = "default_critical_battery")]
    pub critical_battery_pct: f64,
    /// P23: Low battery percentage — below this, derate velocity/torque (default: 15.0).
    #[serde(default = "default_low_battery")]
    pub low_battery_pct: f64,
    /// P24: Maximum acceptable round-trip communication latency in ms (default: 100.0).
    #[serde(default = "default_max_latency")]
    pub max_latency_ms: f64,
    /// P24: Warning latency threshold in ms — above this, derate velocity (default: 50.0).
    #[serde(default = "default_warning_latency")]
    pub warning_latency_ms: f64,
}

fn default_max_pitch() -> f64 {
    0.2618 // 15 degrees
}
fn default_max_roll() -> f64 {
    0.1745 // 10 degrees
}
fn default_warning_pitch() -> f64 {
    0.1396 // 8 degrees
}
fn default_warning_roll() -> f64 {
    0.0873 // 5 degrees
}
fn default_max_temp() -> f64 {
    80.0
}
fn default_warning_temp() -> f64 {
    65.0
}
fn default_critical_battery() -> f64 {
    5.0
}
fn default_low_battery() -> f64 {
    15.0
}
fn default_max_latency() -> f64 {
    100.0
}
fn default_warning_latency() -> f64 {
    50.0
}

/// Static stability configuration based on the support polygon and ZMP check (P9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StabilityConfig {
    /// Convex support polygon vertices `[x, y]` in the robot base frame (metres).
    /// Must contain at least 3 vertices when `enabled` is `true`.
    pub support_polygon: Vec<[f64; 2]>,
    /// Estimated height of the centre of mass above the ground plane (metres).
    pub com_height_estimate: f64,
    /// When `false`, the stability check is disabled entirely; defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Parameters governing the safe-stop behaviour when the watchdog fires (P1-6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafeStopProfile {
    /// Which safe-stop motion strategy to execute; defaults to `ControlledCrouch`.
    #[serde(default)]
    pub strategy: SafeStopStrategy,
    /// Maximum joint deceleration magnitude used during a controlled stop (rad/s² or m/s²).
    #[serde(default = "default_max_decel")]
    pub max_deceleration: f64,
    /// Target joint positions (in radians or metres) for the `ParkPosition` strategy.
    #[serde(default)]
    pub target_joint_positions: HashMap<String, f64>,
}

impl Default for SafeStopProfile {
    fn default() -> Self {
        SafeStopProfile {
            strategy: SafeStopStrategy::default(),
            max_deceleration: default_max_decel(),
            target_joint_positions: HashMap::new(),
        }
    }
}

fn default_max_decel() -> f64 {
    5.0
}

/// Per-end-effector safety limits for manipulation checks (P11–P14).
///
/// The `name` field is matched against `EndEffectorForce.name` in the command.
/// Only end-effectors listed here are subject to manipulation limit checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndEffectorConfig {
    /// Name identifying this end-effector (matched against command data by name).
    pub name: String,
    /// Maximum allowable Cartesian force magnitude in Newtons (P11).
    pub max_force_n: f64,
    /// Maximum allowable grasp (closing) force in Newtons (P12, upper bound).
    pub max_grasp_force_n: f64,
    /// Minimum required grasp force in Newtons when grasping (P12, lower bound).
    pub min_grasp_force_n: f64,
    /// Maximum allowable rate of change of force magnitude, in N/s (P13).
    pub max_force_rate_n_per_s: f64,
    /// Maximum payload mass in kilograms that this end-effector may carry (P14).
    pub max_payload_kg: f64,
}

/// Per-joint safety margins for sim-to-real transfer (Section 18.2).
///
/// In Guardian mode, limits are tightened by these fractions.
/// E.g. `velocity_margin: 0.15` means real-world velocity limit is
/// `max_velocity * (1 - 0.15)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RealWorldMargins {
    /// Fractional tightening applied to joint position limits in Guardian mode; must be in `[0.0, 1.0)`.
    #[serde(default)]
    pub position_margin: f64,
    /// Fractional tightening applied to joint velocity limits in Guardian mode; must be in `[0.0, 1.0)`.
    #[serde(default)]
    pub velocity_margin: f64,
    /// Fractional tightening applied to joint torque limits in Guardian mode; must be in `[0.0, 1.0)`.
    #[serde(default)]
    pub torque_margin: f64,
    /// Fractional tightening applied to joint acceleration limits in Guardian mode; must be in `[0.0, 1.0)`.
    #[serde(default)]
    pub acceleration_margin: f64,
}

/// Task-scoped safety envelope (Section 17).
///
/// Overrides base profile limits for a specific task. Envelopes can only
/// *tighten* limits, never loosen them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskEnvelope {
    /// Unique name identifying this task envelope (used in error messages).
    pub name: String,
    /// Human-readable description of the task this envelope applies to.
    #[serde(default)]
    pub description: String,
    /// Velocity scale override — must be <= profile's `global_velocity_scale`.
    #[serde(default)]
    pub global_velocity_scale: Option<f64>,
    /// Maximum payload override in kg.
    #[serde(default)]
    pub max_payload_kg: Option<f64>,
    /// End-effector force limit override in Newtons.
    #[serde(default)]
    pub end_effector_force_limit_n: Option<f64>,
    /// Tighter workspace bounds (must be contained within profile workspace).
    #[serde(default)]
    pub workspace: Option<WorkspaceBounds>,
    /// Additional exclusion zones (added on top of profile zones, never removed).
    #[serde(default)]
    pub additional_exclusion_zones: Vec<ExclusionZone>,
}
