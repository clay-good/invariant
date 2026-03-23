use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub collision_pairs: Vec<[String; 2]>,
    #[serde(default)]
    pub stability: Option<StabilityConfig>,
    pub max_delta_time: f64,
    #[serde(default = "default_velocity_scale")]
    pub global_velocity_scale: f64,
    #[serde(default = "default_watchdog_timeout_ms")]
    pub watchdog_timeout_ms: u64,
    #[serde(default)]
    pub safe_stop_profile: SafeStopProfile,
}

fn default_velocity_scale() -> f64 {
    1.0
}

fn default_watchdog_timeout_ms() -> u64 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointDefinition {
    pub name: String,
    #[serde(rename = "type")]
    pub joint_type: String,
    pub min: f64,
    pub max: f64,
    pub max_velocity: f64,
    pub max_torque: f64,
    pub max_acceleration: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceBounds {
    #[serde(rename = "type")]
    pub bounds_type: String,
    pub min: [f64; 3],
    pub max: [f64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProximityZone {
    pub name: String,
    #[serde(rename = "type")]
    pub zone_type: String,
    pub center: [f64; 3],
    pub radius: f64,
    pub velocity_scale: f64,
    #[serde(default)]
    pub dynamic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabilityConfig {
    pub support_polygon: Vec<[f64; 2]>,
    pub com_height_estimate: f64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SafeStopProfile {
    #[serde(default = "default_strategy")]
    pub strategy: String,
    #[serde(default = "default_max_decel")]
    pub max_deceleration: f64,
    #[serde(default)]
    pub target_joint_positions: std::collections::HashMap<String, f64>,
}

fn default_strategy() -> String {
    "controlled_crouch".to_string()
}

fn default_max_decel() -> f64 {
    5.0
}
