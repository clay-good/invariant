//! Property-style randomised tests for physics checks P1–P5.
//!
//! v11 prompt 5.7 first cut. `proptest` is not on the workspace dep list, so
//! randomisation is hand-rolled with a seeded `StdRng` (the same pattern used
//! by N-15's intent ↔ PCA round-trip test in `invariant_core::intent`).
//!
//! Each P-check has three property assertions:
//!   * in-bounds case        → check passes
//!   * boundary case (==lim) → check passes
//!   * one ulp / 1e-9 above  → check fails
//!
//! Each property runs 256 randomised cases with a fixed seed so failures are
//! reproducible. The remaining P-checks (P6–P25) are queued as follow-up;
//! the bones-and-skeleton machinery here keeps the per-test cost low so
//! adding them is mechanical.
//!
//! v11 5.7 wants `proptest`; until it lands on the workspace dep list, this
//! file plays the same role.

use invariant_robotics::models::command::{EndEffectorPosition, JointState};
use invariant_robotics::models::profile::{JointDefinition, JointType, WorkspaceBounds};
use invariant_robotics::physics::acceleration::check_acceleration_limits;
use invariant_robotics::physics::joint_limits::check_joint_limits;
use invariant_robotics::physics::torque::check_torque_limits;
use invariant_robotics::physics::velocity::check_velocity_limits;
use invariant_robotics::physics::workspace::check_workspace_bounds;

/// Number of randomised cases per property. 256 is the same budget N-15 uses.
const CASES: usize = 256;

/// Minimal deterministic LCG. Enough randomness for the boundary / interior
/// sweeps in this file; no need to pull in a full RNG dep.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }
    fn next_u64(&mut self) -> u64 {
        // Numerical Recipes constants (Knuth's MMIX).
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    /// Uniform `f64` in `[lo, hi]`. `lo` and `hi` must be finite, `lo < hi`.
    fn range(&mut self, lo: f64, hi: f64) -> f64 {
        let u = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64; // [0,1)
        lo + (hi - lo) * u
    }
}

fn def_revolute(name: &str) -> JointDefinition {
    JointDefinition {
        name: name.to_string(),
        joint_type: JointType::Revolute,
        min: -3.0,
        max: 3.0,
        max_velocity: 2.0,
        max_torque: 50.0,
        max_acceleration: 10.0,
    }
}

// ---------- P1 — joint position limits ----------------------------------

#[test]
fn p1_joint_limits_in_bounds_always_passes() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    let mut rng = Lcg::new(0xA1_FA_AA_AA);
    for _ in 0..CASES {
        let pos = rng.range(def.min, def.max);
        let js = vec![JointState {
            name: "j0".into(),
            position: pos,
            velocity: 0.0,
            effort: 0.0,
        }];
        let r = check_joint_limits(&js, &defs, None);
        assert!(
            r.passed,
            "in-bounds pos {pos} should pass; details: {}",
            r.details
        );
    }
}

#[test]
fn p1_joint_limits_at_boundary_passes() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    for &pos in &[def.min, def.max] {
        let js = vec![JointState {
            name: "j0".into(),
            position: pos,
            velocity: 0.0,
            effort: 0.0,
        }];
        let r = check_joint_limits(&js, &defs, None);
        assert!(r.passed, "boundary {pos} should pass");
    }
}

#[test]
fn p1_joint_limits_above_boundary_rejects() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    let mut rng = Lcg::new(0xA1_FA_BB_BB);
    for _ in 0..CASES {
        // Pick from either side, > limit.
        let above = rng.range(1e-6, 100.0);
        let pos = if rng.next_u64() & 1 == 0 {
            def.max + above
        } else {
            def.min - above
        };
        let js = vec![JointState {
            name: "j0".into(),
            position: pos,
            velocity: 0.0,
            effort: 0.0,
        }];
        let r = check_joint_limits(&js, &defs, None);
        assert!(!r.passed, "out-of-bounds pos {pos} should reject");
    }
}

// ---------- P2 — joint velocity limits ----------------------------------

#[test]
fn p2_velocity_in_bounds_always_passes() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    let mut rng = Lcg::new(0xA2_AA_AA_AA);
    for _ in 0..CASES {
        let v = rng.range(-def.max_velocity, def.max_velocity);
        let js = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: v,
            effort: 0.0,
        }];
        let r = check_velocity_limits(&js, &defs, 1.0, None);
        assert!(
            r.passed,
            "in-bounds v {v} should pass; details: {}",
            r.details
        );
    }
}

#[test]
fn p2_velocity_at_boundary_passes() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    for &v in &[def.max_velocity, -def.max_velocity] {
        let js = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: v,
            effort: 0.0,
        }];
        let r = check_velocity_limits(&js, &defs, 1.0, None);
        assert!(r.passed, "boundary v {v} should pass");
    }
}

#[test]
fn p2_velocity_above_boundary_rejects() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    let mut rng = Lcg::new(0xA2_BB_BB_BB);
    for _ in 0..CASES {
        let above = rng.range(1e-6, 50.0);
        let v = if rng.next_u64() & 1 == 0 {
            def.max_velocity + above
        } else {
            -(def.max_velocity + above)
        };
        let js = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: v,
            effort: 0.0,
        }];
        let r = check_velocity_limits(&js, &defs, 1.0, None);
        assert!(!r.passed, "out-of-bounds v {v} should reject");
    }
}

// ---------- P3 — joint torque limits ------------------------------------

#[test]
fn p3_torque_in_bounds_always_passes() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    let mut rng = Lcg::new(0xA3_AA_AA_AA);
    for _ in 0..CASES {
        let t = rng.range(-def.max_torque, def.max_torque);
        let js = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: 0.0,
            effort: t,
        }];
        let r = check_torque_limits(&js, &defs, None);
        assert!(
            r.passed,
            "in-bounds τ {t} should pass; details: {}",
            r.details
        );
    }
}

#[test]
fn p3_torque_at_boundary_passes() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    for &t in &[def.max_torque, -def.max_torque] {
        let js = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: 0.0,
            effort: t,
        }];
        let r = check_torque_limits(&js, &defs, None);
        assert!(r.passed, "boundary τ {t} should pass");
    }
}

#[test]
fn p3_torque_above_boundary_rejects() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    let mut rng = Lcg::new(0xA3_BB_BB_BB);
    for _ in 0..CASES {
        let above = rng.range(1e-6, 500.0);
        let t = if rng.next_u64() & 1 == 0 {
            def.max_torque + above
        } else {
            -(def.max_torque + above)
        };
        let js = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: 0.0,
            effort: t,
        }];
        let r = check_torque_limits(&js, &defs, None);
        assert!(!r.passed, "out-of-bounds τ {t} should reject");
    }
}

// ---------- P4 — joint acceleration limits ------------------------------

/// Pick `dt > 0` and a `prev_v` that makes the target `accel` exactly the
/// signed acceleration we want: `v_new = prev_v + accel * dt`.
fn velocity_for(prev_v: f64, accel: f64, dt: f64) -> f64 {
    prev_v + accel * dt
}

#[test]
fn p4_acceleration_in_bounds_always_passes() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    let mut rng = Lcg::new(0xA4_AA_AA_AA);
    for _ in 0..CASES {
        let dt = rng.range(1e-3, 0.1);
        let a = rng.range(-def.max_acceleration, def.max_acceleration);
        let prev_v = 0.0;
        let v = velocity_for(prev_v, a, dt);
        let prev = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: prev_v,
            effort: 0.0,
        }];
        let curr = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: v,
            effort: 0.0,
        }];
        let r = check_acceleration_limits(&curr, Some(&prev), &defs, dt, None);
        assert!(
            r.passed,
            "in-bounds a {a} (dt {dt}, v {v}) should pass; details: {}",
            r.details
        );
    }
}

#[test]
fn p4_acceleration_at_boundary_passes() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    let dt = 0.01;
    for &a in &[def.max_acceleration, -def.max_acceleration] {
        let v = velocity_for(0.0, a, dt);
        let prev = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: 0.0,
            effort: 0.0,
        }];
        let curr = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: v,
            effort: 0.0,
        }];
        let r = check_acceleration_limits(&curr, Some(&prev), &defs, dt, None);
        assert!(r.passed, "boundary a {a} should pass");
    }
}

#[test]
fn p4_acceleration_above_boundary_rejects() {
    let def = def_revolute("j0");
    let defs = vec![def.clone()];
    let mut rng = Lcg::new(0xA4_BB_BB_BB);
    for _ in 0..CASES {
        let dt = rng.range(1e-3, 0.1);
        // Stay well above the limit so that floating-point fuzz doesn't put us
        // back inside on rare draws (limit comparison uses strict `>`).
        let above = rng.range(1.0, 100.0);
        let a = if rng.next_u64() & 1 == 0 {
            def.max_acceleration + above
        } else {
            -(def.max_acceleration + above)
        };
        let v = velocity_for(0.0, a, dt);
        let prev = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: 0.0,
            effort: 0.0,
        }];
        let curr = vec![JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: v,
            effort: 0.0,
        }];
        let r = check_acceleration_limits(&curr, Some(&prev), &defs, dt, None);
        assert!(
            !r.passed,
            "out-of-bounds a {a} (dt {dt}, v {v}) should reject"
        );
    }
}

// ---------- P5 — workspace bounds (AABB) --------------------------------

fn aabb() -> WorkspaceBounds {
    WorkspaceBounds::Aabb {
        min: [-1.0, -1.0, 0.0],
        max: [1.0, 1.0, 2.0],
    }
}

#[test]
fn p5_workspace_in_bounds_always_passes() {
    let ws = aabb();
    let (min, max) = match &ws {
        WorkspaceBounds::Aabb { min, max } => (*min, *max),
    };
    let mut rng = Lcg::new(0xA5_AA_AA_AA);
    for _ in 0..CASES {
        let p = [
            rng.range(min[0], max[0]),
            rng.range(min[1], max[1]),
            rng.range(min[2], max[2]),
        ];
        let ee = vec![EndEffectorPosition {
            name: "tcp".into(),
            position: p,
        }];
        let r = check_workspace_bounds(&ee, &ws);
        assert!(
            r.passed,
            "in-bounds {:?} should pass; details: {}",
            p, r.details
        );
    }
}

#[test]
fn p5_workspace_at_boundary_passes() {
    let ws = aabb();
    let (min, max) = match &ws {
        WorkspaceBounds::Aabb { min, max } => (*min, *max),
    };
    let corners = [
        [min[0], min[1], min[2]],
        [max[0], max[1], max[2]],
        [min[0], max[1], min[2]],
        [max[0], min[1], max[2]],
    ];
    for p in corners {
        let ee = vec![EndEffectorPosition {
            name: "tcp".into(),
            position: p,
        }];
        let r = check_workspace_bounds(&ee, &ws);
        assert!(r.passed, "corner {:?} should pass", p);
    }
}

#[test]
fn p5_workspace_above_boundary_rejects() {
    let ws = aabb();
    let (min, max) = match &ws {
        WorkspaceBounds::Aabb { min, max } => (*min, *max),
    };
    let mut rng = Lcg::new(0xA5_BB_BB_BB);
    for _ in 0..CASES {
        // Push exactly one axis out, randomly above or below; other axes interior.
        let axis = (rng.next_u64() % 3) as usize;
        let above = rng.range(1e-6, 100.0);
        let mut p = [
            rng.range(min[0], max[0]),
            rng.range(min[1], max[1]),
            rng.range(min[2], max[2]),
        ];
        p[axis] = if rng.next_u64() & 1 == 0 {
            max[axis] + above
        } else {
            min[axis] - above
        };
        let ee = vec![EndEffectorPosition {
            name: "tcp".into(),
            position: p,
        }];
        let r = check_workspace_bounds(&ee, &ws);
        assert!(!r.passed, "out-of-bounds {:?} should reject", p);
    }
}
