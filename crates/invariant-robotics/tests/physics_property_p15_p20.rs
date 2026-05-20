//! Property-style randomised tests for locomotion physics checks
//! P15 / P16 / P17 / P19 / P20.
//!
//! Same skeleton as `physics_property_p1_p5.rs` /
//! `physics_property_p8_p14.rs`: hand-rolled LCG, 256 cases per property,
//! three asserts (in-bounds → PASS, boundary → PASS, above-boundary → REJECT).
//!
//! Covered:
//!   * P15 — locomotion velocity magnitude     (check_locomotion_velocity)
//!   * P16 — foot clearance min/max window     (check_foot_clearance)
//!   * P17 — ground reaction force magnitude   (check_ground_reaction)
//!   * P19 — step length                       (check_step_length)
//!   * P20 — heading-rate magnitude            (check_heading_rate)
//!
//! P18 (friction cone) needs both a normal and tangential force vector and
//! a coefficient; queued as follow-up.

use invariant_robotics::models::command::{FootState, LocomotionState};
use invariant_robotics::models::profile::LocomotionConfig;
use invariant_robotics::physics::foot_clearance::check_foot_clearance;
use invariant_robotics::physics::ground_reaction::check_ground_reaction;
use invariant_robotics::physics::heading_rate::check_heading_rate;
use invariant_robotics::physics::locomotion_velocity::check_locomotion_velocity;
use invariant_robotics::physics::step_length::check_step_length;

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

fn loco_config() -> LocomotionConfig {
    LocomotionConfig {
        max_locomotion_velocity: 1.5,
        max_step_length: 0.7,
        min_foot_clearance: 0.02,
        max_step_height: 0.25,
        max_ground_reaction_force: 600.0,
        friction_coefficient: 0.7,
        max_heading_rate: 1.0,
    }
}

fn empty_loco() -> LocomotionState {
    LocomotionState {
        base_velocity: [0.0, 0.0, 0.0],
        heading_rate: 0.0,
        feet: Vec::new(),
        step_length: 0.0,
    }
}

// ---------- P15 — locomotion velocity magnitude -----------------------------

/// Project (vx, vy, vz) onto the unit-norm direction and scale by `target_speed`.
fn vel_for_speed(rng: &mut Lcg, target_speed: f64) -> [f64; 3] {
    // Random unit direction via rejection sampling on the cube.
    loop {
        let x = rng.range(-1.0, 1.0);
        let y = rng.range(-1.0, 1.0);
        let z = rng.range(-1.0, 1.0);
        let r2 = x * x + y * y + z * z;
        if r2 > 1e-6 && r2 <= 1.0 {
            let r = r2.sqrt();
            return [
                x / r * target_speed,
                y / r * target_speed,
                z / r * target_speed,
            ];
        }
    }
}

#[test]
fn p15_locomotion_velocity_in_bounds_always_passes() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC1_AA_AA_AA);
    for _ in 0..CASES {
        let speed = rng.range(0.0, cfg.max_locomotion_velocity);
        let v = vel_for_speed(&mut rng, speed);
        let loco = LocomotionState {
            base_velocity: v,
            ..empty_loco()
        };
        let r = check_locomotion_velocity(&loco, &cfg);
        assert!(r.passed, "speed {speed} should pass; {}", r.details);
    }
}

#[test]
fn p15_locomotion_velocity_at_boundary_passes() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC1_CC_CC_CC);
    let v = vel_for_speed(&mut rng, cfg.max_locomotion_velocity);
    let loco = LocomotionState {
        base_velocity: v,
        ..empty_loco()
    };
    let r = check_locomotion_velocity(&loco, &cfg);
    assert!(r.passed, "boundary speed should pass; {}", r.details);
}

#[test]
fn p15_locomotion_velocity_above_boundary_rejects() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC1_BB_BB_BB);
    for _ in 0..CASES {
        let speed = cfg.max_locomotion_velocity + rng.range(1e-6, 100.0);
        let v = vel_for_speed(&mut rng, speed);
        let loco = LocomotionState {
            base_velocity: v,
            ..empty_loco()
        };
        let r = check_locomotion_velocity(&loco, &cfg);
        assert!(!r.passed, "speed {speed} should reject");
    }
}

// ---------- P16 — foot clearance window -------------------------------------

fn swing_foot(z: f64) -> FootState {
    FootState {
        name: "RH".into(),
        position: [0.0, 0.0, z],
        contact: false,
        ground_reaction_force: None,
    }
}

#[test]
fn p16_foot_clearance_in_window_always_passes() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC2_AA_AA_AA);
    for _ in 0..CASES {
        let z = rng.range(cfg.min_foot_clearance, cfg.max_step_height);
        let loco = LocomotionState {
            feet: vec![swing_foot(z)],
            ..empty_loco()
        };
        let r = check_foot_clearance(&loco, &cfg);
        assert!(r.passed, "z {z} should pass; {}", r.details);
    }
}

#[test]
fn p16_foot_clearance_at_boundaries_passes() {
    let cfg = loco_config();
    for &z in &[cfg.min_foot_clearance, cfg.max_step_height] {
        let loco = LocomotionState {
            feet: vec![swing_foot(z)],
            ..empty_loco()
        };
        let r = check_foot_clearance(&loco, &cfg);
        assert!(r.passed, "boundary z {z} should pass; {}", r.details);
    }
}

#[test]
fn p16_foot_clearance_outside_window_rejects() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC2_BB_BB_BB);
    for _ in 0..CASES {
        let above = rng.range(1e-6, 1.0);
        let z = if rng.next_u64() & 1 == 0 {
            cfg.max_step_height + above
        } else {
            cfg.min_foot_clearance - above
        };
        let loco = LocomotionState {
            feet: vec![swing_foot(z)],
            ..empty_loco()
        };
        let r = check_foot_clearance(&loco, &cfg);
        assert!(!r.passed, "out-of-window z {z} should reject");
    }
}

// ---------- P17 — ground reaction force magnitude --------------------------

fn stance_foot(grf_mag: f64, rng: &mut Lcg) -> FootState {
    // Distribute the magnitude over a random unit direction.
    let v = vel_for_speed(rng, grf_mag);
    FootState {
        name: "LH".into(),
        position: [0.0, 0.0, 0.0],
        contact: true,
        ground_reaction_force: Some(v),
    }
}

#[test]
fn p17_grf_in_bounds_always_passes() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC3_AA_AA_AA);
    for _ in 0..CASES {
        let mag = rng.range(0.0, cfg.max_ground_reaction_force);
        let foot = stance_foot(mag, &mut rng);
        let loco = LocomotionState {
            feet: vec![foot],
            ..empty_loco()
        };
        let r = check_ground_reaction(&loco, &cfg);
        assert!(r.passed, "GRF |{mag}| should pass; {}", r.details);
    }
}

#[test]
fn p17_grf_at_boundary_passes() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC3_CC_CC_CC);
    let foot = stance_foot(cfg.max_ground_reaction_force, &mut rng);
    let loco = LocomotionState {
        feet: vec![foot],
        ..empty_loco()
    };
    let r = check_ground_reaction(&loco, &cfg);
    assert!(r.passed, "boundary GRF should pass; {}", r.details);
}

#[test]
fn p17_grf_above_boundary_rejects() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC3_BB_BB_BB);
    for _ in 0..CASES {
        let mag = cfg.max_ground_reaction_force + rng.range(1e-3, 5_000.0);
        let foot = stance_foot(mag, &mut rng);
        let loco = LocomotionState {
            feet: vec![foot],
            ..empty_loco()
        };
        let r = check_ground_reaction(&loco, &cfg);
        assert!(!r.passed, "GRF |{mag}| should reject");
    }
}

// ---------- P19 — step length ----------------------------------------------

#[test]
fn p19_step_length_in_bounds_always_passes() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC4_AA_AA_AA);
    for _ in 0..CASES {
        let s = rng.range(0.0, cfg.max_step_length);
        let loco = LocomotionState {
            step_length: s,
            ..empty_loco()
        };
        let r = check_step_length(&loco, &cfg);
        assert!(r.passed, "step {s} should pass; {}", r.details);
    }
}

#[test]
fn p19_step_length_at_boundary_passes() {
    let cfg = loco_config();
    let loco = LocomotionState {
        step_length: cfg.max_step_length,
        ..empty_loco()
    };
    let r = check_step_length(&loco, &cfg);
    assert!(r.passed, "boundary step should pass; {}", r.details);
}

#[test]
fn p19_step_length_above_boundary_rejects() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC4_BB_BB_BB);
    for _ in 0..CASES {
        let s = cfg.max_step_length + rng.range(1e-6, 10.0);
        let loco = LocomotionState {
            step_length: s,
            ..empty_loco()
        };
        let r = check_step_length(&loco, &cfg);
        assert!(!r.passed, "step {s} should reject");
    }
}

// ---------- P20 — heading-rate magnitude -----------------------------------

#[test]
fn p20_heading_rate_in_bounds_always_passes() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC5_AA_AA_AA);
    for _ in 0..CASES {
        let h = rng.range(-cfg.max_heading_rate, cfg.max_heading_rate);
        let loco = LocomotionState {
            heading_rate: h,
            ..empty_loco()
        };
        let r = check_heading_rate(&loco, &cfg);
        assert!(r.passed, "heading {h} should pass; {}", r.details);
    }
}

#[test]
fn p20_heading_rate_at_boundary_passes() {
    let cfg = loco_config();
    for &h in &[cfg.max_heading_rate, -cfg.max_heading_rate] {
        let loco = LocomotionState {
            heading_rate: h,
            ..empty_loco()
        };
        let r = check_heading_rate(&loco, &cfg);
        assert!(r.passed, "boundary heading {h} should pass; {}", r.details);
    }
}

#[test]
fn p20_heading_rate_above_boundary_rejects() {
    let cfg = loco_config();
    let mut rng = Lcg::new(0xC5_BB_BB_BB);
    for _ in 0..CASES {
        let above = rng.range(1e-6, 50.0);
        let h = if rng.next_u64() & 1 == 0 {
            cfg.max_heading_rate + above
        } else {
            -(cfg.max_heading_rate + above)
        };
        let loco = LocomotionState {
            heading_rate: h,
            ..empty_loco()
        };
        let r = check_heading_rate(&loco, &cfg);
        assert!(!r.passed, "heading {h} should reject");
    }
}
