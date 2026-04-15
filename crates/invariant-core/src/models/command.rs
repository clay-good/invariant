use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::authority::Operation;
use crate::sensor::SignedSensorReading;

/// A robot motion command submitted to the safety validator.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use invariant_robotics_core::models::command::{Command, JointState, CommandAuthority};
/// use invariant_robotics_core::models::authority::Operation;
///
/// let cmd = Command {
///     timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
///         .unwrap()
///         .with_timezone(&chrono::Utc),
///     source: "motion_planner_v2".into(),
///     sequence: 1,
///     joint_states: vec![
///         JointState { name: "shoulder_pan".into(),  position: 0.5,  velocity: 0.1, effort: 10.0 },
///         JointState { name: "shoulder_lift".into(), position: -1.2, velocity: 0.0, effort: 25.0 },
///     ],
///     delta_time: 0.02,
///     end_effector_positions: vec![],
///     center_of_mass: Some([0.0, 0.0, 0.9]),
///     authority: CommandAuthority {
///         pca_chain: "base64-cose-chain".into(),
///         required_ops: vec![Operation::new("actuate:arm:*").unwrap()],
///     },
///     metadata: HashMap::new(),
///     locomotion_state: None,
///     end_effector_forces: vec![],
///     estimated_payload_kg: Some(1.5),
///     signed_sensor_readings: vec![],
///     zone_overrides: HashMap::new(),
///     environment_state: None,
/// };
///
/// assert_eq!(cmd.sequence, 1);
/// assert_eq!(cmd.joint_states.len(), 2);
/// assert_eq!(cmd.source, "motion_planner_v2");
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Command {
    /// ISO 8601 / RFC 3339 timestamp. Typed as `DateTime<Utc>` to support
    /// replay-prevention logic (exp/nbf ordering) (P1-3).
    pub timestamp: DateTime<Utc>,
    /// Identifier of the cognitive layer or motion planner that issued this command.
    pub source: String,
    /// Monotonic sequence number. Out-of-order or duplicate commands are rejected.
    pub sequence: u64,
    /// Commanded state for each joint in the robot (P1–P4).
    pub joint_states: Vec<JointState>,
    /// Time since the previous command in seconds. Used for acceleration and rate checks (P4, P8).
    pub delta_time: f64,
    #[serde(default)]
    /// Cartesian positions of all end-effectors in world frame (P5–P7, P10).
    pub end_effector_positions: Vec<EndEffectorPosition>,
    #[serde(default)]
    /// Estimated center-of-mass position [x, y, z] in metres (P9 stability check).
    pub center_of_mass: Option<[f64; 3]>,
    /// Authority evidence: PCA chain + claimed operations.
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
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::command::EnvironmentState;
///
/// let env = EnvironmentState {
///     imu_pitch_rad: Some(0.05),   // ~3 degrees nose-up
///     imu_roll_rad: Some(-0.02),   // slight left roll
///     actuator_temperatures: vec![],
///     battery_percentage: Some(85.0),
///     communication_latency_ms: Some(12.0),
///     e_stop_engaged: Some(false),
/// };
///
/// assert_eq!(env.battery_percentage, Some(85.0));
/// assert_eq!(env.e_stop_engaged, Some(false));
/// ```
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
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::command::{LocomotionState, FootState};
///
/// let state = LocomotionState {
///     base_velocity: [0.3, 0.0, 0.0],   // 0.3 m/s forward
///     heading_rate: 0.1,                  // 0.1 rad/s yaw
///     feet: vec![
///         FootState { name: "LF".into(), position: [0.2, 0.1, 0.0], contact: true, ground_reaction_force: Some([0.0, 0.0, 250.0]) },
///         FootState { name: "RF".into(), position: [0.2, -0.1, 0.1], contact: false, ground_reaction_force: None },
///     ],
///     step_length: 0.35,
/// };
///
/// assert_eq!(state.base_velocity[0], 0.3);
/// assert_eq!(state.feet.len(), 2);
/// assert!(state.feet[0].contact);
/// ```
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
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::command::FootState;
///
/// let stance_foot = FootState {
///     name: "LH".into(),
///     position: [-0.15, 0.1, 0.0],
///     contact: true,
///     ground_reaction_force: Some([5.0, -3.0, 240.0]),
/// };
///
/// let swing_foot = FootState {
///     name: "RH".into(),
///     position: [-0.15, -0.1, 0.08],  // 8 cm above ground
///     contact: false,
///     ground_reaction_force: None,
/// };
///
/// assert!(stance_foot.contact);
/// assert!(!swing_foot.contact);
/// assert!(swing_foot.ground_reaction_force.is_none());
/// ```
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

/// Commanded state for a single robot joint.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::command::JointState;
///
/// // A revolute joint mid-range with moderate velocity
/// let js = JointState {
///     name: "elbow_flex".into(),
///     position: 1.57,  // ~90 degrees (radians)
///     velocity: 0.3,   // rad/s
///     effort: 45.0,    // N·m
/// };
///
/// assert_eq!(js.name, "elbow_flex");
/// assert!((js.position - std::f64::consts::FRAC_PI_2).abs() < 0.01);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JointState {
    /// Joint name matching the robot profile definition.
    pub name: String,
    /// Commanded position (rad for revolute, m for prismatic).
    pub position: f64,
    /// Commanded velocity (rad/s or m/s).
    pub velocity: f64,
    /// Commanded effort/torque (N·m or N).
    pub effort: f64,
}

/// Cartesian position of a named end-effector in world frame (metres).
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::command::EndEffectorPosition;
///
/// let ee = EndEffectorPosition {
///     name: "gripper_tcp".into(),
///     position: [0.5, -0.2, 0.8],  // x=0.5m, y=-0.2m, z=0.8m
/// };
///
/// assert_eq!(ee.name, "gripper_tcp");
/// assert_eq!(ee.position[2], 0.8);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndEffectorPosition {
    /// End-effector name matching the robot profile or URDF link name.
    pub name: String,
    /// Cartesian position [x, y, z] in world frame (metres).
    pub position: [f64; 3],
}

/// Authority evidence carried with a command: the PCA chain and claimed operations.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::command::CommandAuthority;
/// use invariant_robotics_core::models::authority::Operation;
///
/// let auth = CommandAuthority {
///     pca_chain: "base64-encoded-cose-sign1-chain".into(),
///     required_ops: vec![
///         Operation::new("actuate:arm:joints").unwrap(),
///         Operation::new("actuate:gripper:*").unwrap(),
///     ],
/// };
///
/// assert_eq!(auth.required_ops.len(), 2);
/// assert_eq!(auth.required_ops[0].as_str(), "actuate:arm:joints");
/// ```
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
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::command::EndEffectorForce;
///
/// let ee_force = EndEffectorForce {
///     name: "gripper_tcp".into(),
///     force: [2.5, -1.0, 8.0],    // [fx, fy, fz] in Newtons
///     torque: [0.1, 0.05, 0.0],   // [tx, ty, tz] in N·m
///     grasp_force: Some(15.0),    // 15 N closing force
/// };
///
/// assert_eq!(ee_force.name, "gripper_tcp");
/// assert_eq!(ee_force.grasp_force, Some(15.0));
///
/// // Without grasp sensing
/// let no_grasp = EndEffectorForce {
///     name: "wrist_sensor".into(),
///     force: [0.0, 0.0, 5.0],
///     torque: [0.0, 0.0, 0.0],
///     grasp_force: None,
/// };
/// assert!(no_grasp.grasp_force.is_none());
/// ```
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
