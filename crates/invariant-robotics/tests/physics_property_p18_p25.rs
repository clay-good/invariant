//! Property-style randomised tests for P18 friction cone, P21 terrain
//! incline, P22 actuator temperature, P23 battery, P24 communication
//! latency, P25 emergency stop.
//!
//! Same skeleton as the other `physics_property_*.rs` files (256 cases
//! per property, hand-rolled deterministic LCG). For the four warning-
//! zoned env checks (P21–P24) each property has four cases:
//!     safe-zone  → PASS, derating = None
//!     warning    → PASS, derating = Some(..) (advisory)
//!     boundary   → PASS (strict `>` against max threshold)
//!     above max  → REJECT
//!
//! P18 / P25 are binary (PASS / REJECT only).

use invariant_robotics::models::command::{
    ActuatorTemperature, EnvironmentState, FootState, LocomotionState,
};
use invariant_robotics::models::profile::{EnvironmentConfig, LocomotionConfig};
use invariant_robotics::physics::environment::{
    check_actuator_temperature, check_battery_state, check_communication_latency,
    check_emergency_stop, check_terrain_incline,
};
use invariant_robotics::physics::friction_cone::check_friction_cone;

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

fn env_cfg() -> EnvironmentConfig {
    EnvironmentConfig {
        max_safe_pitch_rad: 0.30,
        max_safe_roll_rad: 0.20,
        warning_pitch_rad: 0.15,
        warning_roll_rad: 0.10,
        max_operating_temperature_c: 80.0,
        warning_temperature_c: 65.0,
        critical_battery_pct: 5.0,
        low_battery_pct: 15.0,
        max_latency_ms: 100.0,
        warning_latency_ms: 50.0,
    }
}

// ============================================================================
// P18 — friction cone (binary)
// ============================================================================

fn loco_cfg(mu: f64) -> LocomotionConfig {
    LocomotionConfig {
        max_locomotion_velocity: 1.5,
        max_step_length: 0.5,
        min_foot_clearance: 0.02,
        max_step_height: 0.5,
        max_ground_reaction_force: 500.0,
        friction_coefficient: mu,
        max_heading_rate: 1.0,
    }
}

fn contact_foot(fx: f64, fy: f64, fz: f64) -> FootState {
    FootState {
        name: "fl".into(),
        position: [0.0, 0.0, 0.0],
        contact: true,
        ground_reaction_force: Some([fx, fy, fz]),
    }
}

fn loco_with_feet(feet: Vec<FootState>) -> LocomotionState {
    LocomotionState {
        base_velocity: [0.0, 0.0, 0.0],
        heading_rate: 0.0,
        feet,
        step_length: 0.0,
    }
}

#[test]
fn p18_inside_cone_always_passes() {
    let mu = 0.7;
    let cfg = loco_cfg(mu);
    let mut rng = Lcg::new(0xE1_AA_AA_AA);
    for _ in 0..CASES {
        let fz = rng.range(1.0, 500.0);
        // Pick a random direction in the tangent plane and a magnitude in
        // [0, mu * fz] so the ratio stays inside the cone.
        let theta = rng.range(0.0, 2.0 * std::f64::consts::PI);
        let mag = rng.range(0.0, mu * fz);
        let fx = mag * theta.cos();
        let fy = mag * theta.sin();
        let state = loco_with_feet(vec![contact_foot(fx, fy, fz)]);
        let r = check_friction_cone(&state, &cfg);
        assert!(
            r.passed,
            "(fx={fx}, fy={fy}, fz={fz}) ratio {} should pass; {}",
            (fx * fx + fy * fy).sqrt() / fz,
            r.details
        );
    }
}

#[test]
fn p18_exact_cone_boundary_passes() {
    let mu = 0.7;
    let cfg = loco_cfg(mu);
    let fz = 100.0;
    let state = loco_with_feet(vec![contact_foot(mu * fz, 0.0, fz)]);
    let r = check_friction_cone(&state, &cfg);
    assert!(r.passed, "boundary should pass; {}", r.details);
}

#[test]
fn p18_outside_cone_rejects() {
    let mu = 0.7;
    let cfg = loco_cfg(mu);
    let mut rng = Lcg::new(0xE1_BB_BB_BB);
    for _ in 0..CASES {
        let fz = rng.range(1.0, 500.0);
        // Target ratio strictly > mu, with a small floor to avoid floating
        // noise bouncing it back inside.
        let extra = rng.range(1e-3, 5.0);
        let target_ratio = mu + extra;
        let theta = rng.range(0.0, 2.0 * std::f64::consts::PI);
        let mag = target_ratio * fz;
        let fx = mag * theta.cos();
        let fy = mag * theta.sin();
        let state = loco_with_feet(vec![contact_foot(fx, fy, fz)]);
        let r = check_friction_cone(&state, &cfg);
        assert!(
            !r.passed,
            "ratio {target_ratio} (fx={fx}, fy={fy}, fz={fz}) should reject"
        );
    }
}

// ============================================================================
// P25 — emergency stop (binary)
// ============================================================================

#[test]
fn p25_estop_disengaged_passes() {
    let env = EnvironmentState {
        e_stop_engaged: Some(false),
        ..empty_env()
    };
    let r = check_emergency_stop(&env);
    assert!(r.passed, "disengaged should pass; {}", r.details);
}

#[test]
fn p25_estop_engaged_rejects() {
    let env = EnvironmentState {
        e_stop_engaged: Some(true),
        ..empty_env()
    };
    let r = check_emergency_stop(&env);
    assert!(!r.passed, "engaged should reject");
}

#[test]
fn p25_estop_absent_passes_fail_open() {
    let env = empty_env();
    let r = check_emergency_stop(&env);
    assert!(r.passed, "absent e-stop should fail-open; {}", r.details);
}

// ============================================================================
// P22 — actuator temperature (warning-zoned)
// ============================================================================

fn env_with_temp(temp: f64) -> EnvironmentState {
    EnvironmentState {
        actuator_temperatures: vec![ActuatorTemperature {
            joint_name: "j0".into(),
            temperature_celsius: temp,
        }],
        ..empty_env()
    }
}

#[test]
fn p22_temp_in_safe_zone_passes_without_derating() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE2_AA_AA_AA);
    for _ in 0..CASES {
        // Strictly less than warning.
        let t = rng.range(-50.0, cfg.warning_temperature_c - 1e-6);
        let env = env_with_temp(t);
        let r = check_actuator_temperature(&env, &cfg);
        assert!(r.passed, "safe-zone temp {t} should pass; {}", r.details);
        assert!(
            r.derating.is_none(),
            "safe-zone temp {t} should NOT carry derating; got {:?}",
            r.derating
        );
    }
}

#[test]
fn p22_temp_in_warning_zone_passes_with_derating() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE2_BB_BB_BB);
    for _ in 0..CASES {
        // Strictly between warning and max.
        let lo = cfg.warning_temperature_c + 1e-6;
        let hi = cfg.max_operating_temperature_c - 1e-6;
        let t = rng.range(lo, hi);
        let env = env_with_temp(t);
        let r = check_actuator_temperature(&env, &cfg);
        assert!(r.passed, "warn-zone temp {t} should pass; {}", r.details);
        let derate = r.derating.expect("warn zone should carry derating advice");
        assert!(
            derate.torque_scale > 0.0 && derate.torque_scale < 1.0,
            "derate torque_scale {} ∉ (0,1)",
            derate.torque_scale
        );
    }
}

#[test]
fn p22_temp_at_max_passes() {
    let cfg = env_cfg();
    let env = env_with_temp(cfg.max_operating_temperature_c);
    let r = check_actuator_temperature(&env, &cfg);
    assert!(r.passed, "boundary temp should pass; {}", r.details);
}

#[test]
fn p22_temp_above_max_rejects() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE2_CC_CC_CC);
    for _ in 0..CASES {
        let t = cfg.max_operating_temperature_c + rng.range(1e-6, 500.0);
        let env = env_with_temp(t);
        let r = check_actuator_temperature(&env, &cfg);
        assert!(!r.passed, "above-max temp {t} should reject");
    }
}

// ============================================================================
// P23 — battery (warning-zoned, low side)
// ============================================================================

fn env_with_battery(pct: f64) -> EnvironmentState {
    EnvironmentState {
        battery_percentage: Some(pct),
        ..empty_env()
    }
}

#[test]
fn p23_battery_in_safe_zone_passes_without_derating() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE3_AA_AA_AA);
    for _ in 0..CASES {
        // ≥ low threshold.
        let pct = rng.range(cfg.low_battery_pct, 100.0);
        let env = env_with_battery(pct);
        let r = check_battery_state(&env, &cfg);
        assert!(
            r.passed,
            "safe-zone battery {pct}% should pass; {}",
            r.details
        );
        assert!(
            r.derating.is_none(),
            "safe-zone battery {pct}% should NOT carry derating"
        );
    }
}

#[test]
fn p23_battery_in_warning_zone_passes_with_derating() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE3_BB_BB_BB);
    for _ in 0..CASES {
        // Strictly between critical and low.
        let lo = cfg.critical_battery_pct + 1e-6;
        let hi = cfg.low_battery_pct - 1e-6;
        let pct = rng.range(lo, hi);
        let env = env_with_battery(pct);
        let r = check_battery_state(&env, &cfg);
        assert!(
            r.passed,
            "warn-zone battery {pct}% should pass; {}",
            r.details
        );
        let derate = r.derating.expect("warn zone should carry derating advice");
        assert!(
            derate.velocity_scale > 0.0 && derate.velocity_scale < 1.0,
            "derate velocity_scale {} ∉ (0,1)",
            derate.velocity_scale
        );
    }
}

#[test]
fn p23_battery_below_critical_rejects() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE3_CC_CC_CC);
    for _ in 0..CASES {
        let pct = cfg.critical_battery_pct - rng.range(1e-6, cfg.critical_battery_pct);
        let env = env_with_battery(pct);
        let r = check_battery_state(&env, &cfg);
        assert!(!r.passed, "below-critical battery {pct}% should reject");
    }
}

// ============================================================================
// P24 — communication latency (warning-zoned)
// ============================================================================

fn env_with_latency(ms: f64) -> EnvironmentState {
    EnvironmentState {
        communication_latency_ms: Some(ms),
        ..empty_env()
    }
}

#[test]
fn p24_latency_in_safe_zone_passes_without_derating() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE4_AA_AA_AA);
    for _ in 0..CASES {
        let ms = rng.range(0.0, cfg.warning_latency_ms - 1e-6);
        let env = env_with_latency(ms);
        let r = check_communication_latency(&env, &cfg);
        assert!(
            r.passed,
            "safe-zone latency {ms} should pass; {}",
            r.details
        );
        assert!(r.derating.is_none(), "safe-zone latency should NOT derate");
    }
}

#[test]
fn p24_latency_in_warning_zone_passes_with_derating() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE4_BB_BB_BB);
    for _ in 0..CASES {
        let lo = cfg.warning_latency_ms + 1e-6;
        let hi = cfg.max_latency_ms - 1e-6;
        let ms = rng.range(lo, hi);
        let env = env_with_latency(ms);
        let r = check_communication_latency(&env, &cfg);
        assert!(
            r.passed,
            "warn-zone latency {ms} should pass; {}",
            r.details
        );
        let derate = r.derating.expect("warn zone should carry derating advice");
        assert!(
            derate.velocity_scale > 0.0 && derate.velocity_scale < 1.0,
            "derate velocity_scale {} ∉ (0,1)",
            derate.velocity_scale
        );
    }
}

#[test]
fn p24_latency_above_max_rejects() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE4_CC_CC_CC);
    for _ in 0..CASES {
        let ms = cfg.max_latency_ms + rng.range(1e-6, 5_000.0);
        let env = env_with_latency(ms);
        let r = check_communication_latency(&env, &cfg);
        assert!(!r.passed, "above-max latency {ms} should reject");
    }
}

// ============================================================================
// P21 — terrain incline (warning-zoned, |angle| based)
// ============================================================================

fn env_with_pitch(pitch: f64) -> EnvironmentState {
    EnvironmentState {
        imu_pitch_rad: Some(pitch),
        ..empty_env()
    }
}

#[test]
fn p21_terrain_in_safe_zone_passes_without_derating() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE5_AA_AA_AA);
    for _ in 0..CASES {
        let mag = rng.range(0.0, cfg.warning_pitch_rad - 1e-6);
        let pitch = if rng.next_u64() & 1 == 0 { mag } else { -mag };
        let env = env_with_pitch(pitch);
        let r = check_terrain_incline(&env, &cfg);
        assert!(
            r.passed,
            "safe-zone pitch {pitch} should pass; {}",
            r.details
        );
        assert!(r.derating.is_none(), "safe-zone pitch should NOT derate");
    }
}

#[test]
fn p21_terrain_in_warning_zone_passes_with_derating() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE5_BB_BB_BB);
    for _ in 0..CASES {
        let lo = cfg.warning_pitch_rad + 1e-6;
        let hi = cfg.max_safe_pitch_rad - 1e-6;
        let mag = rng.range(lo, hi);
        let pitch = if rng.next_u64() & 1 == 0 { mag } else { -mag };
        let env = env_with_pitch(pitch);
        let r = check_terrain_incline(&env, &cfg);
        assert!(
            r.passed,
            "warn-zone pitch {pitch} should pass; {}",
            r.details
        );
        let derate = r.derating.expect("warn zone should carry derating advice");
        assert!(
            derate.velocity_scale > 0.0 && derate.velocity_scale < 1.0,
            "derate velocity_scale {} ∉ (0,1)",
            derate.velocity_scale
        );
    }
}

#[test]
fn p21_terrain_above_max_rejects() {
    let cfg = env_cfg();
    let mut rng = Lcg::new(0xE5_CC_CC_CC);
    for _ in 0..CASES {
        let mag = cfg.max_safe_pitch_rad + rng.range(1e-6, 2.0);
        let pitch = if rng.next_u64() & 1 == 0 { mag } else { -mag };
        let env = env_with_pitch(pitch);
        let r = check_terrain_incline(&env, &cfg);
        assert!(!r.passed, "above-max pitch {pitch} should reject");
    }
}
