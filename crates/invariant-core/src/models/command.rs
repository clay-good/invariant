use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::authority::Operation;
use crate::sensor::SignedSensorReading;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Command {
    /// ISO 8601 / RFC 3339 timestamp. Typed as `DateTime<Utc>` to support
    /// replay-prevention logic (exp/nbf ordering) (P1-3).
    pub timestamp: DateTime<Utc>,
    pub source: String,
    /// Monotonic sequence number. Out-of-order or duplicate commands are rejected.
    pub sequence: u64,
    pub joint_states: Vec<JointState>,
    pub delta_time: f64,
    #[serde(default)]
    pub end_effector_positions: Vec<EndEffectorPosition>,
    #[serde(default)]
    pub center_of_mass: Option<[f64; 3]>,
    pub authority: CommandAuthority,
    /// Flat key-value metadata. Only `String` values are accepted to prevent
    /// deeply-nested JSON objects from causing stack-overflow DoS (P1-1).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// Locomotion state for legged robots (P15–P20). Optional; locomotion
    /// checks are skipped when absent.
    #[serde(default)]
    pub locomotion_state: Option<LocomotionState>,
    /// Per-end-effector force/torque readings for manipulation safety checks (P11-P13).
    #[serde(default)]
    pub end_effector_forces: Vec<EndEffectorForce>,
    /// Estimated mass of the grasped payload in kilograms, for payload limit check (P14).
    #[serde(default)]
    pub estimated_payload_kg: Option<f64>,
    /// Sensor readings with cryptographic signatures, for attestation and anomaly detection.
    #[serde(default)]
    pub signed_sensor_readings: Vec<SignedSensorReading>,
    /// Per-zone overrides for conditional exclusion zones (P6).
    /// Keys are zone names; `true` = zone active (enforced), `false` = zone disabled.
    /// Only applies to zones marked `conditional: true` in the profile.
    /// Non-conditional zones ignore this map. Conditional zones with no entry
    /// here default to active (fail-closed).
    /// Set by the edge PC cycle coordinator based on Haas I/O state, NOT by
    /// the cognitive layer.
    #[serde(default)]
    pub zone_overrides: HashMap<String, bool>,
    /// Environmental awareness state for P21–P25 checks (terrain, temperature,
    /// battery, latency, e-stop). Optional; environmental checks are skipped
    /// when absent.
    #[serde(default)]
    pub environment_state: Option<EnvironmentState>,
}

/// Environmental sensor data for P21–P25 checks.
///
/// All fields are optional. Checks for absent fields are gracefully skipped
/// (fail-open for advisory sensors, fail-closed for e-stop).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentState {
    /// IMU pitch angle in radians (positive = nose up). (P21)
    #[serde(default)]
    pub imu_pitch_rad: Option<f64>,
    /// IMU roll angle in radians (positive = right side down). (P21)
    #[serde(default)]
    pub imu_roll_rad: Option<f64>,
    /// Per-actuator temperature readings. (P22)
    #[serde(default)]
    pub actuator_temperatures: Vec<ActuatorTemperature>,
    /// Battery state of charge as a percentage (0.0–100.0). (P23)
    #[serde(default)]
    pub battery_percentage: Option<f64>,
    /// Round-trip communication latency in milliseconds. (P24)
    #[serde(default)]
    pub communication_latency_ms: Option<f64>,
    /// Whether the hardware emergency stop is engaged. (P25)
    #[serde(default)]
    pub e_stop_engaged: Option<bool>,
}

/// Temperature reading for a single actuator/joint motor. (P22)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActuatorTemperature {
    /// Joint name matching the robot profile.
    pub joint_name: String,
    /// Temperature in degrees Celsius.
    pub temperature_celsius: f64,
}

/// Locomotion state for a legged/mobile robot base (P15–P20).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocomotionState {
    /// Linear velocity of the robot base in world frame [vx, vy, vz] (m/s).
    pub base_velocity: [f64; 3],
    /// Yaw (heading) rate of the robot base (rad/s).
    pub heading_rate: f64,
    /// Per-foot state for all feet of the robot.
    pub feet: Vec<FootState>,
    /// Commanded step length (m).
    pub step_length: f64,
}

/// State of a single foot on a legged robot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FootState {
    /// Foot link name matching the robot URDF/profile.
    pub name: String,
    /// Foot position in world frame [x, y, z] (m). z is height above ground.
    pub position: [f64; 3],
    /// Whether the foot is currently in contact with the ground.
    pub contact: bool,
    /// Ground reaction force vector [fx, fy, fz] (N). Present only when
    /// force/torque sensing is available.
    #[serde(default)]
    pub ground_reaction_force: Option<[f64; 3]>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JointState {
    pub name: String,
    pub position: f64,
    pub velocity: f64,
    pub effort: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndEffectorPosition {
    pub name: String,
    pub position: [f64; 3],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandAuthority {
    /// Base64-encoded COSE_Sign1 PCA chain.
    pub pca_chain: String,
    /// Operations this command requires. Validated against the decoded chain's final_ops.
    pub required_ops: Vec<Operation>,
}

/// Force/torque measurement at a single end-effector (P11–P13).
///
/// `name` must match an [`EndEffectorConfig`](crate::models::profile::EndEffectorConfig)
/// in the robot profile for limit checks to fire. Entries with no matching profile
/// config are passed through without checking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndEffectorForce {
    /// Name identifying the end-effector (must match profile config to be checked).
    pub name: String,
    /// Cartesian force vector [fx, fy, fz] in Newtons.
    pub force: [f64; 3],
    /// Cartesian torque vector [tx, ty, tz] in Newton-metres.
    pub torque: [f64; 3],
    /// Scalar grasp force in Newtons (e.g. gripper closing force). Omitted when
    /// force/torque sensing is available but grasp force sensing is not.
    #[serde(default)]
    pub grasp_force: Option<f64>,
}
