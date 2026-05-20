//! Property-style randomised tests for physics checks P8 / P11–P14.
//!
//! Follow-up to `physics_property_p1_p5.rs` — same shape: hand-rolled
//! deterministic LCG, 256 cases per property, three asserts per check
//! (in-bounds → PASS, boundary → PASS, above-boundary → REJECT).
//!
//! Covered:
//!   * P8  — delta_time bounds                (check_delta_time)
//!   * P11 — end-effector force magnitude     (check_ee_force_limits)
//!   * P12 — grasp force window               (check_grasp_force_limits)
//!   * P13 — force rate of change             (check_force_rate_limits)
//!   * P14 — payload mass                     (check_payload_limits)
//!
//! v11 5.7 still wants property tests for the locomotion / environment /
//! geometry checks (P9, P10, P15–P25 + SR1 / SR2). Adding those uses the
//! same skeleton.

use invariant_robotics::models::command::{EndEffectorForce, JointState};
use invariant_robotics::models::profile::EndEffectorConfig;
use invariant_robotics::physics::delta_time::check_delta_time;
use invariant_robotics::physics::ee_force::check_ee_force_limits;
use invariant_robotics::physics::force_rate::check_force_rate_limits;
use invariant_robotics::physics::grasp_force::check_grasp_force_limits;
use invariant_robotics::physics::payload::check_payload_limits;

// Suppress an unused-import warning when only some helpers are used by the
// active tests. `JointState` is imported for shape parity with P1–P5; remove
// once P9/P10 are added.
const _: fn() = || {
    let _ = JointState {
        name: String::new(),
        position: 0.0,
        velocity: 0.0,
        effort: 0.0,
    };
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

fn ee_config(name: &str) -> EndEffectorConfig {
    EndEffectorConfig {
        name: name.to_string(),
        max_force_n: 100.0,
        max_grasp_force_n: 80.0,
        min_grasp_force_n: 5.0,
        max_force_rate_n_per_s: 500.0,
        max_payload_kg: 5.0,
    }
}

fn force(name: &str, magnitude: f64) -> EndEffectorForce {
    // Place all the magnitude on +x so |force| == magnitude.
    EndEffectorForce {
        name: name.to_string(),
        force: [magnitude, 0.0, 0.0],
        torque: [0.0, 0.0, 0.0],
        grasp_force: None,
    }
}

// ---------- P8 — delta_time -------------------------------------------------

#[test]
fn p8_delta_time_in_bounds_always_passes() {
    let max_dt = 0.05_f64;
    let mut rng = Lcg::new(0xA8_AA_AA_AA);
    for _ in 0..CASES {
        let dt = rng.range(1e-6, max_dt);
        let r = check_delta_time(dt, max_dt);
        assert!(r.passed, "in-bounds dt {dt} should pass; {}", r.details);
    }
}

#[test]
fn p8_delta_time_at_boundary_passes() {
    let max_dt = 0.05_f64;
    let r = check_delta_time(max_dt, max_dt);
    assert!(r.passed, "boundary dt should pass");
}

#[test]
fn p8_delta_time_above_boundary_rejects() {
    let max_dt = 0.05_f64;
    let mut rng = Lcg::new(0xA8_BB_BB_BB);
    for _ in 0..CASES {
        let dt = max_dt + rng.range(1e-9, 1.0);
        let r = check_delta_time(dt, max_dt);
        assert!(!r.passed, "above-boundary dt {dt} should reject");
    }
}

// ---------- P11 — end-effector force magnitude ------------------------------

#[test]
fn p11_ee_force_in_bounds_always_passes() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let mut rng = Lcg::new(0xB1_AA_AA_AA);
    for _ in 0..CASES {
        let mag = rng.range(0.0, cfg.max_force_n);
        let fs = vec![force("tcp", mag)];
        let r = check_ee_force_limits(&fs, &cfgs);
        assert!(r.passed, "in-bounds |F| {mag} should pass; {}", r.details);
    }
}

#[test]
fn p11_ee_force_at_boundary_passes() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let fs = vec![force("tcp", cfg.max_force_n)];
    let r = check_ee_force_limits(&fs, &cfgs);
    assert!(r.passed, "boundary should pass; {}", r.details);
}

#[test]
fn p11_ee_force_above_boundary_rejects() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let mut rng = Lcg::new(0xB1_BB_BB_BB);
    for _ in 0..CASES {
        let mag = cfg.max_force_n + rng.range(1e-6, 500.0);
        let fs = vec![force("tcp", mag)];
        let r = check_ee_force_limits(&fs, &cfgs);
        assert!(!r.passed, "out-of-bounds |F| {mag} should reject");
    }
}

// ---------- P12 — grasp force window ---------------------------------------

fn force_with_grasp(name: &str, grasp: f64) -> EndEffectorForce {
    EndEffectorForce {
        name: name.to_string(),
        force: [0.0, 0.0, 0.0],
        torque: [0.0, 0.0, 0.0],
        grasp_force: Some(grasp),
    }
}

#[test]
fn p12_grasp_in_bounds_always_passes() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let mut rng = Lcg::new(0xB2_AA_AA_AA);
    for _ in 0..CASES {
        let g = rng.range(cfg.min_grasp_force_n, cfg.max_grasp_force_n);
        let fs = vec![force_with_grasp("tcp", g)];
        let r = check_grasp_force_limits(&fs, &cfgs);
        assert!(r.passed, "in-window grasp {g} should pass; {}", r.details);
    }
}

#[test]
fn p12_grasp_at_boundary_passes() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    for &g in &[cfg.min_grasp_force_n, cfg.max_grasp_force_n] {
        let fs = vec![force_with_grasp("tcp", g)];
        let r = check_grasp_force_limits(&fs, &cfgs);
        assert!(r.passed, "boundary grasp {g} should pass; {}", r.details);
    }
}

#[test]
fn p12_grasp_outside_window_rejects() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let mut rng = Lcg::new(0xB2_BB_BB_BB);
    for _ in 0..CASES {
        let above = rng.range(1e-6, 200.0);
        let g = if rng.next_u64() & 1 == 0 {
            cfg.max_grasp_force_n + above
        } else {
            (cfg.min_grasp_force_n - above).max(-1000.0) // guard for non-finite
        };
        let fs = vec![force_with_grasp("tcp", g)];
        let r = check_grasp_force_limits(&fs, &cfgs);
        assert!(!r.passed, "out-of-window grasp {g} should reject");
    }
}

// ---------- P13 — force rate ------------------------------------------------

/// Derive `force_new` so `|norm(new) - norm(prev)| / dt == target_rate` (signed).
fn new_force_for_rate(prev_mag: f64, target_rate: f64, dt: f64, sign: f64) -> f64 {
    // |new - prev| / dt == |target_rate|  ⇒  new = prev ± rate * dt
    let new_mag = prev_mag + sign.signum() * target_rate.abs() * dt;
    new_mag.max(0.0)
}

#[test]
fn p13_force_rate_in_bounds_always_passes() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let mut rng = Lcg::new(0xB3_AA_AA_AA);
    for _ in 0..CASES {
        let dt = rng.range(1e-3, 0.05);
        let prev_mag = rng.range(0.0, cfg.max_force_n * 0.5);
        let target_rate = rng.range(0.0, cfg.max_force_rate_n_per_s);
        let sign = if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 };
        let new_mag = new_force_for_rate(prev_mag, target_rate, dt, sign);
        let prev = vec![force("tcp", prev_mag)];
        let curr = vec![force("tcp", new_mag)];
        let r = check_force_rate_limits(&curr, Some(&prev), &cfgs, dt);
        assert!(
            r.passed,
            "in-bounds rate {target_rate} (prev {prev_mag}, new {new_mag}, dt {dt}) should pass; {}",
            r.details
        );
    }
}

#[test]
fn p13_force_rate_at_boundary_passes() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let dt = 0.01;
    let prev_mag = 10.0;
    let new_mag = new_force_for_rate(prev_mag, cfg.max_force_rate_n_per_s, dt, 1.0);
    let prev = vec![force("tcp", prev_mag)];
    let curr = vec![force("tcp", new_mag)];
    let r = check_force_rate_limits(&curr, Some(&prev), &cfgs, dt);
    assert!(r.passed, "boundary rate should pass; {}", r.details);
}

#[test]
fn p13_force_rate_above_boundary_rejects() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let mut rng = Lcg::new(0xB3_BB_BB_BB);
    for _ in 0..CASES {
        let dt = rng.range(1e-3, 0.05);
        let prev_mag = rng.range(0.0, cfg.max_force_n * 0.5);
        // Push the rate strictly above the limit; use 1.0 N/s minimum buffer
        // to absorb float noise.
        let above = rng.range(1.0, 1_000.0);
        let target_rate = cfg.max_force_rate_n_per_s + above;
        let sign = if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 };
        let new_mag = new_force_for_rate(prev_mag, target_rate, dt, sign);
        let prev = vec![force("tcp", prev_mag)];
        let curr = vec![force("tcp", new_mag)];
        let r = check_force_rate_limits(&curr, Some(&prev), &cfgs, dt);
        assert!(
            !r.passed,
            "above-boundary rate {target_rate} (prev {prev_mag}, new {new_mag}, dt {dt}) should reject"
        );
    }
}

// ---------- P14 — payload limits --------------------------------------------

#[test]
fn p14_payload_in_bounds_always_passes() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let fs = vec![force("tcp", 0.0)];
    let mut rng = Lcg::new(0xB4_AA_AA_AA);
    for _ in 0..CASES {
        let m = rng.range(0.0, cfg.max_payload_kg);
        let r = check_payload_limits(&fs, Some(m), &cfgs);
        assert!(r.passed, "in-bounds m {m} should pass; {}", r.details);
    }
}

#[test]
fn p14_payload_at_boundary_passes() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let fs = vec![force("tcp", 0.0)];
    let r = check_payload_limits(&fs, Some(cfg.max_payload_kg), &cfgs);
    assert!(r.passed, "boundary should pass; {}", r.details);
}

#[test]
fn p14_payload_above_boundary_rejects() {
    let cfg = ee_config("tcp");
    let cfgs = vec![cfg.clone()];
    let fs = vec![force("tcp", 0.0)];
    let mut rng = Lcg::new(0xB4_BB_BB_BB);
    for _ in 0..CASES {
        let m = cfg.max_payload_kg + rng.range(1e-6, 100.0);
        let r = check_payload_limits(&fs, Some(m), &cfgs);
        assert!(!r.passed, "above-boundary m {m} should reject");
    }
}
