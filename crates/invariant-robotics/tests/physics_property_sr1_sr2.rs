//! Property-style randomised tests for the SR1 / SR2 sensor-range checks
//! split out in v11 5.1.
//!
//! Same shape as the other `physics_property_*.rs` files (256 cases per
//! property, hand-rolled deterministic LCG, three asserts per check).
//!
//! Covered:
//!   * SR1 — environment-side plausibility bounds (`check_sensor_range_env`)
//!     - IMU pitch / roll magnitude ≤ π rad
//!     - actuator temperature ∈ [−273.15, 1000] °C
//!     - battery_percentage ∈ [0, 100]
//!     - communication_latency_ms ≥ 0
//!   * SR2 — payload-side plausibility bounds (`check_sensor_range_payload`)
//!     - joint position magnitude ≤ 4π rad
//!     - joint velocity magnitude ≤ 1000 rad/s
//!     - end-effector position max-axis ≤ 1000 m
//!     - end-effector force magnitude ≤ 100 kN

use std::collections::HashMap;

use chrono::Utc;
use invariant_robotics::models::command::{
    ActuatorTemperature, Command, CommandAuthority, EndEffectorForce, EndEffectorPosition,
    EnvironmentState, JointState,
};
use invariant_robotics::physics::environment::{
    check_sensor_range_env, check_sensor_range_payload, SR2_MAX_EE_FORCE_N, SR2_MAX_EE_POSITION_M,
    SR2_MAX_JOINT_POSITION_RAD, SR2_MAX_JOINT_VELOCITY_RAD_S,
};

const CASES: usize = 256;

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn range(&mut self, lo: f64, hi: f64) -> f64 {
        let u = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        lo + (hi - lo) * u
    }
}

fn empty_env() -> EnvironmentState {
    EnvironmentState {
        imu_pitch_rad: None,
        imu_roll_rad: None,
        actuator_temperatures: Vec::new(),
        battery_percentage: None,
        communication_latency_ms: None,
        e_stop_engaged: None,
    }
}

fn empty_command() -> Command {
    Command {
        timestamp: Utc::now(),
        source: "test".into(),
        sequence: 1,
        joint_states: Vec::new(),
        delta_time: 0.01,
        end_effector_positions: Vec::new(),
        center_of_mass: None,
        authority: CommandAuthority {
            pca_chain: String::new(),
            required_ops: Vec::new(),
        },
        metadata: HashMap::new(),
        locomotion_state: None,
        end_effector_forces: Vec::new(),
        estimated_payload_kg: None,
        signed_sensor_readings: Vec::new(),
        zone_overrides: HashMap::new(),
        environment_state: None,
    }
}

// ============================================================================
// SR1 — environment-side plausibility
// ============================================================================

#[test]
fn sr1_in_bounds_always_passes() {
    let mut rng = Lcg::new(0xDA_AA_AA_AA);
    for _ in 0..CASES {
        let env = EnvironmentState {
            imu_pitch_rad: Some(rng.range(-std::f64::consts::PI, std::f64::consts::PI)),
            imu_roll_rad: Some(rng.range(-std::f64::consts::PI, std::f64::consts::PI)),
            actuator_temperatures: vec![ActuatorTemperature {
                joint_name: "j0".into(),
                temperature_celsius: rng.range(-273.15, 1000.0),
            }],
            battery_percentage: Some(rng.range(0.0, 100.0)),
            communication_latency_ms: Some(rng.range(0.0, 1_000_000.0)),
            e_stop_engaged: Some(false),
        };
        let r = check_sensor_range_env(&env);
        assert!(r.passed, "in-bounds should pass; details: {}", r.details);
    }
}

#[test]
fn sr1_at_boundaries_passes() {
    // Each axis exactly at its limit (boundary check uses strict `>`, so the
    // limits themselves are admitted).
    let env = EnvironmentState {
        imu_pitch_rad: Some(std::f64::consts::PI),
        imu_roll_rad: Some(-std::f64::consts::PI),
        actuator_temperatures: vec![
            ActuatorTemperature {
                joint_name: "cold".into(),
                temperature_celsius: -273.15,
            },
            ActuatorTemperature {
                joint_name: "hot".into(),
                temperature_celsius: 1000.0,
            },
        ],
        battery_percentage: Some(0.0),
        communication_latency_ms: Some(0.0),
        e_stop_engaged: Some(false),
    };
    let r = check_sensor_range_env(&env);
    assert!(
        r.passed,
        "boundary case should pass; details: {}",
        r.details
    );

    let env_high = EnvironmentState {
        battery_percentage: Some(100.0),
        ..empty_env()
    };
    let r = check_sensor_range_env(&env_high);
    assert!(r.passed, "battery 100 should pass; details: {}", r.details);
}

#[test]
fn sr1_above_pitch_limit_rejects() {
    let mut rng = Lcg::new(0xDA_BB_01_01);
    for _ in 0..CASES {
        let p = std::f64::consts::PI + rng.range(1e-6, 100.0);
        let env = EnvironmentState {
            imu_pitch_rad: Some(if rng.next_u64() & 1 == 0 { p } else { -p }),
            ..empty_env()
        };
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "pitch {p} should reject");
    }
}

#[test]
fn sr1_above_temperature_limit_rejects() {
    let mut rng = Lcg::new(0xDA_BB_02_02);
    for _ in 0..CASES {
        let over_hot = 1000.0 + rng.range(1e-6, 10_000.0);
        let env = EnvironmentState {
            actuator_temperatures: vec![ActuatorTemperature {
                joint_name: "j0".into(),
                temperature_celsius: over_hot,
            }],
            ..empty_env()
        };
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "temp {over_hot}°C should reject");
    }
}

#[test]
fn sr1_battery_outside_range_rejects() {
    let mut rng = Lcg::new(0xDA_BB_03_03);
    for _ in 0..CASES {
        let over = rng.range(1e-6, 1_000.0);
        let batt = if rng.next_u64() & 1 == 0 {
            100.0 + over
        } else {
            -over
        };
        let env = EnvironmentState {
            battery_percentage: Some(batt),
            ..empty_env()
        };
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "battery {batt}% should reject");
    }
}

#[test]
fn sr1_negative_latency_rejects() {
    let mut rng = Lcg::new(0xDA_BB_04_04);
    for _ in 0..CASES {
        let lat = -rng.range(1e-6, 1_000.0);
        let env = EnvironmentState {
            communication_latency_ms: Some(lat),
            ..empty_env()
        };
        let r = check_sensor_range_env(&env);
        assert!(!r.passed, "latency {lat} ms should reject");
    }
}

// ============================================================================
// SR2 — payload-side plausibility
// ============================================================================

#[test]
fn sr2_in_bounds_always_passes() {
    let mut rng = Lcg::new(0xDB_AA_AA_AA);
    for _ in 0..CASES {
        let mut cmd = empty_command();
        cmd.joint_states = vec![JointState {
            name: "j0".into(),
            position: rng.range(-SR2_MAX_JOINT_POSITION_RAD, SR2_MAX_JOINT_POSITION_RAD),
            velocity: rng.range(-SR2_MAX_JOINT_VELOCITY_RAD_S, SR2_MAX_JOINT_VELOCITY_RAD_S),
            effort: 0.0,
        }];
        cmd.end_effector_positions = vec![EndEffectorPosition {
            name: "tcp".into(),
            position: [
                rng.range(-SR2_MAX_EE_POSITION_M, SR2_MAX_EE_POSITION_M),
                rng.range(-SR2_MAX_EE_POSITION_M, SR2_MAX_EE_POSITION_M),
                rng.range(-SR2_MAX_EE_POSITION_M, SR2_MAX_EE_POSITION_M),
            ],
        }];
        // Pick a force magnitude well inside the plausibility envelope and
        // place it on +x so the magnitude equals exactly the scalar.
        let f_mag = rng.range(0.0, SR2_MAX_EE_FORCE_N * 0.9);
        cmd.end_effector_forces = vec![EndEffectorForce {
            name: "tcp".into(),
            force: [f_mag, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }];
        let r = check_sensor_range_payload(&cmd);
        assert!(
            r.passed,
            "in-bounds payload should pass; details: {}",
            r.details
        );
    }
}

#[test]
fn sr2_at_boundary_passes() {
    let mut cmd = empty_command();
    cmd.joint_states = vec![JointState {
        name: "j0".into(),
        position: SR2_MAX_JOINT_POSITION_RAD,
        velocity: SR2_MAX_JOINT_VELOCITY_RAD_S,
        effort: 0.0,
    }];
    cmd.end_effector_positions = vec![EndEffectorPosition {
        name: "tcp".into(),
        position: [SR2_MAX_EE_POSITION_M, 0.0, 0.0],
    }];
    cmd.end_effector_forces = vec![EndEffectorForce {
        name: "tcp".into(),
        force: [SR2_MAX_EE_FORCE_N, 0.0, 0.0],
        torque: [0.0, 0.0, 0.0],
        grasp_force: None,
    }];
    let r = check_sensor_range_payload(&cmd);
    assert!(r.passed, "boundary should pass; {}", r.details);
}

#[test]
fn sr2_above_joint_position_rejects() {
    let mut rng = Lcg::new(0xDB_BB_01);
    for _ in 0..CASES {
        let over = rng.range(1e-6, 100.0);
        let p = if rng.next_u64() & 1 == 0 {
            SR2_MAX_JOINT_POSITION_RAD + over
        } else {
            -(SR2_MAX_JOINT_POSITION_RAD + over)
        };
        let mut cmd = empty_command();
        cmd.joint_states = vec![JointState {
            name: "j0".into(),
            position: p,
            velocity: 0.0,
            effort: 0.0,
        }];
        let r = check_sensor_range_payload(&cmd);
        assert!(!r.passed, "position {p} should reject");
    }
}

#[test]
fn sr2_above_joint_velocity_rejects() {
    let mut rng = Lcg::new(0xDB_BB_02);
    for _ in 0..CASES {
        let over = rng.range(1e-6, 1_000.0);
        let v = SR2_MAX_JOINT_VELOCITY_RAD_S + over;
        let mut cmd = empty_command();
        cmd.joint_states = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: if rng.next_u64() & 1 == 0 { v } else { -v },
            effort: 0.0,
        }];
        let r = check_sensor_range_payload(&cmd);
        assert!(!r.passed, "velocity {v} should reject");
    }
}

#[test]
fn sr2_above_ee_position_rejects() {
    let mut rng = Lcg::new(0xDB_BB_03);
    for _ in 0..CASES {
        let over = rng.range(1e-3, 10_000.0);
        let axis = (rng.next_u64() % 3) as usize;
        let mut pos = [0.0, 0.0, 0.0];
        pos[axis] = if rng.next_u64() & 1 == 0 {
            SR2_MAX_EE_POSITION_M + over
        } else {
            -(SR2_MAX_EE_POSITION_M + over)
        };
        let mut cmd = empty_command();
        cmd.end_effector_positions = vec![EndEffectorPosition {
            name: "tcp".into(),
            position: pos,
        }];
        let r = check_sensor_range_payload(&cmd);
        assert!(!r.passed, "ee position {pos:?} should reject");
    }
}

#[test]
fn sr2_above_ee_force_rejects() {
    let mut rng = Lcg::new(0xDB_BB_04);
    for _ in 0..CASES {
        let over = rng.range(1.0, 1_000_000.0);
        let mag = SR2_MAX_EE_FORCE_N + over;
        let mut cmd = empty_command();
        cmd.end_effector_forces = vec![EndEffectorForce {
            name: "tcp".into(),
            force: [mag, 0.0, 0.0],
            torque: [0.0, 0.0, 0.0],
            grasp_force: None,
        }];
        let r = check_sensor_range_payload(&cmd);
        assert!(!r.passed, "force {mag} should reject");
    }
}
