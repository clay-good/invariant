//! Property-style randomised tests for the four geometry-heavy physics
//! checks deferred from v11 5.7:
//!
//! * P6  — `check_exclusion_zones`   (AABB + sphere)
//! * P7  — `check_self_collision`    (pairwise Euclidean distance)
//! * P9  — `check_stability`         (point-in-convex-polygon ZMP)
//! * P10 — `check_proximity_velocity` (zone-scaled per-joint velocity cap)
//!
//! Each property runs `CASES = 256` cases through the same hand-rolled LCG
//! that the other `physics_property_*.rs` files use (deterministic, no
//! `proptest` dependency). The seed for each property is hard-coded so a
//! red CI run is reproducible from the assertion alone.

use std::collections::HashMap;

use invariant_robotics::models::command::{EndEffectorPosition, JointState};
use invariant_robotics::models::profile::{
    CollisionPair, ExclusionZone, JointDefinition, JointType, ProximityZone, StabilityConfig,
};
use invariant_robotics::physics::exclusion_zones::check_exclusion_zones;
use invariant_robotics::physics::proximity::check_proximity_velocity;
use invariant_robotics::physics::self_collision::check_self_collision;
use invariant_robotics::physics::stability::check_stability;

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

fn ee(name: &str, p: [f64; 3]) -> EndEffectorPosition {
    EndEffectorPosition {
        name: name.into(),
        position: p,
    }
}

// ============================================================================
// P6 — exclusion_zones
// ============================================================================
//
// We pick a canonical unit-cube AABB `[0,1]^3` and a unit sphere centred at
// `(5,5,5)` with radius 1. The two zones are disjoint, so every randomised
// point can be unambiguously labelled INSIDE-some-zone (REJECT) or OUTSIDE-
// both (PASS).

fn p6_zones() -> Vec<ExclusionZone> {
    vec![
        ExclusionZone::Aabb {
            name: "cube".into(),
            min: [0.0, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
            conditional: false,
        },
        ExclusionZone::Sphere {
            name: "ball".into(),
            center: [5.0, 5.0, 5.0],
            radius: 1.0,
            conditional: false,
        },
    ]
}

#[test]
fn p6_points_outside_all_zones_pass() {
    let zones = p6_zones();
    let overrides: HashMap<String, bool> = HashMap::new();
    let mut rng = Lcg::new(0xE6_AA_AA_AA);
    let mut accepted = 0usize;
    for _ in 0..CASES {
        // Sample from [-3, -2)^3 ∪ [3, 4)^3 region — strictly outside both zones.
        // Use a left half-space to be unambiguous.
        let x = rng.range(-3.0, -2.0);
        let y = rng.range(-3.0, -2.0);
        let z = rng.range(-3.0, -2.0);
        let r = check_exclusion_zones(&[ee("tcp", [x, y, z])], &zones, &overrides);
        assert!(
            r.passed,
            "point ({x},{y},{z}) is outside both zones but P6 rejected: {}",
            r.details
        );
        accepted += 1;
    }
    assert_eq!(accepted, CASES);
}

#[test]
fn p6_points_inside_aabb_reject() {
    let zones = p6_zones();
    let overrides: HashMap<String, bool> = HashMap::new();
    let mut rng = Lcg::new(0xE6_BB_BB_BB);
    for _ in 0..CASES {
        // Strictly interior of the unit cube.
        let x = rng.range(1e-3, 1.0 - 1e-3);
        let y = rng.range(1e-3, 1.0 - 1e-3);
        let z = rng.range(1e-3, 1.0 - 1e-3);
        let r = check_exclusion_zones(&[ee("tcp", [x, y, z])], &zones, &overrides);
        assert!(
            !r.passed,
            "point ({x},{y},{z}) is inside the AABB but P6 admitted: {}",
            r.details
        );
        assert!(r.details.contains("cube"));
    }
}

#[test]
fn p6_points_inside_sphere_reject() {
    let zones = p6_zones();
    let overrides: HashMap<String, bool> = HashMap::new();
    let mut rng = Lcg::new(0xE6_CC_CC_CC);
    for _ in 0..CASES {
        // Sample a random direction on the unit sphere by rejection on the
        // unit cube, then scale to a radius in (0, 1).
        let (dx, dy, dz) = loop {
            let x = rng.range(-1.0, 1.0);
            let y = rng.range(-1.0, 1.0);
            let z = rng.range(-1.0, 1.0);
            let n2 = x * x + y * y + z * z;
            if n2 > 1e-6 && n2 <= 1.0 {
                let n = n2.sqrt();
                break (x / n, y / n, z / n);
            }
        };
        let mag = rng.range(0.0, 1.0 - 1e-3);
        let p = [5.0 + dx * mag, 5.0 + dy * mag, 5.0 + dz * mag];
        let r = check_exclusion_zones(&[ee("tcp", p)], &zones, &overrides);
        assert!(
            !r.passed,
            "point ({p:?}) is inside the sphere but P6 admitted: {}",
            r.details
        );
        assert!(r.details.contains("ball"));
    }
}

#[test]
fn p6_conditional_zone_disabled_allows_interior_point() {
    let zones = vec![ExclusionZone::Aabb {
        name: "conditional".into(),
        min: [-1.0, -1.0, -1.0],
        max: [1.0, 1.0, 1.0],
        conditional: true,
    }];
    let mut overrides: HashMap<String, bool> = HashMap::new();
    overrides.insert("conditional".into(), false);
    let r = check_exclusion_zones(&[ee("tcp", [0.0, 0.0, 0.0])], &zones, &overrides);
    assert!(
        r.passed,
        "disabled conditional zone must let interior point pass; {}",
        r.details
    );
}

// ============================================================================
// P7 — self_collision
// ============================================================================
//
// Two-link scenario: link `a` is parked at the origin, link `b` is placed at
// a randomly sampled point on a sphere of radius `d`. We sweep `d` over a
// safe band and a violating band against a fixed `min_collision_distance`.

const P7_MIN_DIST: f64 = 0.10;

fn p7_pairs() -> Vec<CollisionPair> {
    vec![CollisionPair {
        link_a: "a".into(),
        link_b: "b".into(),
    }]
}

fn unit_dir(rng: &mut Lcg) -> [f64; 3] {
    loop {
        let x = rng.range(-1.0, 1.0);
        let y = rng.range(-1.0, 1.0);
        let z = rng.range(-1.0, 1.0);
        let n2 = x * x + y * y + z * z;
        if n2 > 1e-6 && n2 <= 1.0 {
            let n = n2.sqrt();
            return [x / n, y / n, z / n];
        }
    }
}

#[test]
fn p7_distance_above_minimum_passes() {
    let pairs = p7_pairs();
    let mut rng = Lcg::new(0xE7_AA_AA_AA);
    for _ in 0..CASES {
        // Strictly > min, with a 1e-6 floor to avoid floating noise sliding
        // below the threshold.
        let d = rng.range(P7_MIN_DIST + 1e-6, 5.0);
        let dir = unit_dir(&mut rng);
        let b = [dir[0] * d, dir[1] * d, dir[2] * d];
        let r = check_self_collision(&[ee("a", [0.0, 0.0, 0.0]), ee("b", b)], &pairs, P7_MIN_DIST);
        assert!(
            r.passed,
            "distance {d} > min {P7_MIN_DIST} should pass; {}",
            r.details
        );
    }
}

#[test]
fn p7_distance_below_minimum_rejects() {
    let pairs = p7_pairs();
    let mut rng = Lcg::new(0xE7_BB_BB_BB);
    for _ in 0..CASES {
        // Strictly < min.
        let d = rng.range(0.0, P7_MIN_DIST - 1e-6);
        let dir = unit_dir(&mut rng);
        let b = [dir[0] * d, dir[1] * d, dir[2] * d];
        let r = check_self_collision(&[ee("a", [0.0, 0.0, 0.0]), ee("b", b)], &pairs, P7_MIN_DIST);
        assert!(
            !r.passed,
            "distance {d} < min {P7_MIN_DIST} should reject; {}",
            r.details
        );
    }
}

#[test]
fn p7_missing_link_flagged() {
    let pairs = p7_pairs();
    let r = check_self_collision(&[ee("a", [0.0, 0.0, 0.0])], &pairs, P7_MIN_DIST);
    assert!(!r.passed);
    assert!(r.details.contains("'b'"));
}

// ============================================================================
// P9 — stability (point-in-convex-polygon)
// ============================================================================
//
// Use a regular hexagon centred at the origin with circumradius R=1. The
// hexagon is convex and the inscribed-circle / circumscribed-circle radii
// give clean acceptance/rejection bands:
//
//   r_in  = R * cos(π/6) ≈ 0.866   (any point inside disk of radius r_in is
//                                   guaranteed INSIDE the hexagon)
//   r_out = R                       (any point outside disk of radius r_out
//                                   is guaranteed OUTSIDE the hexagon)

fn hexagon_polygon() -> Vec<[f64; 2]> {
    let mut v = Vec::with_capacity(6);
    for k in 0..6 {
        let theta = (k as f64) * std::f64::consts::FRAC_PI_3;
        v.push([theta.cos(), theta.sin()]);
    }
    v
}

fn hex_cfg() -> StabilityConfig {
    StabilityConfig {
        support_polygon: hexagon_polygon(),
        com_height_estimate: 1.0,
        enabled: true,
    }
}

#[test]
fn p9_com_inside_inscribed_circle_passes() {
    let cfg = hex_cfg();
    let r_in = (std::f64::consts::FRAC_PI_6).cos();
    let mut rng = Lcg::new(0xE9_AA_AA_AA);
    for _ in 0..CASES {
        // Sample a 2-D point strictly inside the inscribed disk via rejection.
        let (x, y) = loop {
            let x = rng.range(-r_in, r_in);
            let y = rng.range(-r_in, r_in);
            if x * x + y * y < (r_in - 1e-3).powi(2) {
                break (x, y);
            }
        };
        let r = check_stability(Some(&[x, y, 0.0]), Some(&cfg));
        assert!(
            r.passed,
            "({x},{y}) inside inscribed disk should be inside hexagon; {}",
            r.details
        );
    }
}

#[test]
fn p9_com_outside_circumscribed_circle_rejects() {
    let cfg = hex_cfg();
    let mut rng = Lcg::new(0xE9_BB_BB_BB);
    for _ in 0..CASES {
        // Sample a point at radius strictly > 1 (the circumradius). Any such
        // point is guaranteed outside the hexagon.
        let theta = rng.range(0.0, 2.0 * std::f64::consts::PI);
        let r_mag = rng.range(1.0 + 1e-3, 10.0);
        let x = r_mag * theta.cos();
        let y = r_mag * theta.sin();
        let r = check_stability(Some(&[x, y, 0.0]), Some(&cfg));
        assert!(
            !r.passed,
            "({x},{y}) outside circumscribed disk should reject; {}",
            r.details
        );
    }
}

#[test]
fn p9_degenerate_polygon_rejects() {
    let cfg = StabilityConfig {
        support_polygon: vec![[0.0, 0.0], [1.0, 0.0]],
        com_height_estimate: 1.0,
        enabled: true,
    };
    let r = check_stability(Some(&[0.5, 0.5, 0.0]), Some(&cfg));
    assert!(!r.passed);
    assert!(r.details.contains("degenerate"));
}

#[test]
fn p9_disabled_check_always_passes() {
    let cfg = StabilityConfig {
        support_polygon: hexagon_polygon(),
        com_height_estimate: 1.0,
        enabled: false,
    };
    // CoM far outside the hexagon — but the check is disabled, so PASS.
    let r = check_stability(Some(&[100.0, 100.0, 0.0]), Some(&cfg));
    assert!(r.passed);
}

// ============================================================================
// P10 — proximity_velocity
// ============================================================================
//
// One joint with `max_velocity = 1.0 rad/s`. One spherical proximity zone
// centred at the origin with radius 1 and `velocity_scale = 0.5`. The EE is
// parked at the origin so the zone is always active. Effective limit then
// becomes `1.0 * 0.5 * global_scale`.

fn p10_joint_def() -> JointDefinition {
    JointDefinition {
        name: "j0".into(),
        joint_type: JointType::Revolute,
        min: -std::f64::consts::PI,
        max: std::f64::consts::PI,
        max_velocity: 1.0,
        max_torque: 50.0,
        max_acceleration: 10.0,
    }
}

fn p10_zones() -> Vec<ProximityZone> {
    vec![ProximityZone::Sphere {
        name: "human".into(),
        center: [0.0, 0.0, 0.0],
        radius: 1.0,
        velocity_scale: 0.5,
        dynamic: false,
    }]
}

#[test]
fn p10_velocity_below_scaled_limit_passes() {
    let defs = [p10_joint_def()];
    let zones = p10_zones();
    let ees = [ee("tcp", [0.0, 0.0, 0.0])]; // inside zone
    let global = 1.0_f64;
    let effective = 1.0 * 0.5 * global; // 0.5 rad/s
    let mut rng = Lcg::new(0xEA_AA_AA_AA);
    for _ in 0..CASES {
        let v = rng.range(-effective + 1e-6, effective - 1e-6);
        let joints = [JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: v,
            effort: 0.0,
        }];
        let r = check_proximity_velocity(&joints, &defs, &ees, &zones, global);
        assert!(
            r.passed,
            "v={v} within scaled limit should pass; {}",
            r.details
        );
    }
}

#[test]
fn p10_velocity_above_scaled_limit_rejects() {
    let defs = [p10_joint_def()];
    let zones = p10_zones();
    let ees = [ee("tcp", [0.0, 0.0, 0.0])];
    let global = 1.0_f64;
    let effective = 1.0 * 0.5 * global;
    let mut rng = Lcg::new(0xEA_BB_BB_BB);
    for _ in 0..CASES {
        // Sample |v| strictly > effective limit but still ≤ the absolute max.
        // The proximity-scaled limit is the violation we care about, not the
        // bare max_velocity.
        let mag = rng.range(effective + 1e-6, 1.0 - 1e-6);
        let v = if rng.next_u64() & 1 == 0 { mag } else { -mag };
        let joints = [JointState {
            name: "j0".into(),
            position: 0.0,
            velocity: v,
            effort: 0.0,
        }];
        let r = check_proximity_velocity(&joints, &defs, &ees, &zones, global);
        assert!(
            !r.passed,
            "v={v} above scaled limit {effective} should reject"
        );
        assert!(r.details.contains("j0"));
    }
}

#[test]
fn p10_no_ee_inside_zone_uses_full_velocity() {
    let defs = [p10_joint_def()];
    let zones = p10_zones();
    // EE far from the zone — proximity scaling does not apply, so the joint
    // velocity is gated only by the global scale (here 1.0). Pick a velocity
    // above the proximity-scaled limit (0.5) but below max_velocity (1.0).
    let ees = [ee("tcp", [10.0, 10.0, 10.0])];
    let joints = [JointState {
        name: "j0".into(),
        position: 0.0,
        velocity: 0.9,
        effort: 0.0,
    }];
    let r = check_proximity_velocity(&joints, &defs, &ees, &zones, 1.0);
    assert!(r.passed, "outside-zone velocity should pass; {}", r.details);
    assert!(r.details.contains("no end-effectors"));
}

#[test]
fn p10_global_scale_multiplies_through() {
    let defs = [p10_joint_def()];
    let zones = p10_zones();
    let ees = [ee("tcp", [0.0, 0.0, 0.0])];
    // global = 0.5 → effective limit = 1.0 * 0.5 * 0.5 = 0.25 rad/s.
    let joints = [JointState {
        name: "j0".into(),
        position: 0.0,
        velocity: 0.3,
        effort: 0.0,
    }];
    let r = check_proximity_velocity(&joints, &defs, &ees, &zones, 0.5);
    assert!(!r.passed, "v=0.3 > 0.25 effective limit should reject");
}
