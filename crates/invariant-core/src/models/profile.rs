use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

use super::error::{Validate, ValidationError};

// --- Enums for type-safe profile fields (P2-1, P2-2, P2-3, P1-6) ---

/// Joint kinematics type. Prevents silent dispatch on unknown type strings (P2-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JointType {
    Revolute,
    Prismatic,
}

/// Workspace bounding volume type. Prevents silent skip on unknown type strings (P2-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BoundsType {
    Aabb,
}

/// Safe-stop behaviour strategy. Prevents silent watchdog failure on unknown strings (P1-6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafeStopStrategy {
    #[default]
    ControlledCrouch,
    ImmediateStop,
    ParkPosition,
}


// --- CollisionPair (P3-6): named struct instead of positional [String; 2] ---

/// A pair of links that must be checked for self-collision (P3-6).
///
/// Serialised as a two-element JSON array `["link_a", "link_b"]` for backward
/// compatibility with existing profile files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionPair {
    pub link_a: String,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RobotProfile {
    pub name: String,
    pub version: String,
    pub joints: Vec<JointDefinition>,
    pub workspace: WorkspaceBounds,
    #[serde(default)]
    pub exclusion_zones: Vec<ExclusionZone>,
    #[serde(default)]
    pub proximity_zones: Vec<ProximityZone>,
    #[serde(default)]
    pub collision_pairs: Vec<CollisionPair>,
    #[serde(default)]
    pub stability: Option<StabilityConfig>,
    pub max_delta_time: f64,
    #[serde(default = "default_min_collision_distance")]
    pub min_collision_distance: f64,
    #[serde(default = "default_velocity_scale")]
    pub global_velocity_scale: f64,
    #[serde(default = "default_watchdog_timeout_ms")]
    pub watchdog_timeout_ms: u64,
    #[serde(default)]
    pub safe_stop_profile: SafeStopProfile,
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

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JointDefinition {
    pub name: String,
    #[serde(rename = "type")]
    pub joint_type: JointType,
    pub min: f64,
    pub max: f64,
    pub max_velocity: f64,
    pub max_torque: f64,
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
        Ok(())
    }
}

/// Workspace bounding volume — uses a tagged enum so unknown types are rejected
/// at deserialisation time rather than silently skipping the workspace check (P2-1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WorkspaceBounds {
    Aabb { min: [f64; 3], max: [f64; 3] },
}

impl Validate for WorkspaceBounds {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            WorkspaceBounds::Aabb { min, max } => {
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
    Aabb {
        name: String,
        min: [f64; 3],
        max: [f64; 3],
    },
    Sphere {
        name: String,
        center: [f64; 3],
        radius: f64,
    },
}

/// Proximity zone — tagged enum consistent with `ExclusionZone` (P2-3).
/// `#[non_exhaustive]` future-proofs for additional zone shapes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[non_exhaustive]
pub enum ProximityZone {
    Sphere {
        name: String,
        center: [f64; 3],
        radius: f64,
        /// Must be in `(0.0, 1.0]` — values > 1.0 would allow speeds above hardware
        /// max near humans, defeating ISO/TS 15066 (P2-6).
        velocity_scale: f64,
        #[serde(default)]
        dynamic: bool,
    },
}

impl Validate for ProximityZone {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            ProximityZone::Sphere {
                name,
                velocity_scale,
                ..
            } => {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StabilityConfig {
    pub support_polygon: Vec<[f64; 2]>,
    pub com_height_estimate: f64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafeStopProfile {
    #[serde(default)]
    pub strategy: SafeStopStrategy,
    #[serde(default = "default_max_decel")]
    pub max_deceleration: f64,
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
