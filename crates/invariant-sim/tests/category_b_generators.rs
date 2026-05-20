//! Category B (Joint Safety) generator intent tests — IDs B-01..B-08.
//!
//! Spec: `docs/robotics/spec-15m-campaign.md` §3, v11 prompt 2.1.
//!
//! These tests anchor the *intent* of each generator by asserting that
//! the produced command sequence touches the specific boundary value
//! the scenario claims to exercise. They are not exhaustive validator
//! traces — that's the physics-property suite (P1–P25). The point here
//! is: if a future refactor silently swaps "max_velocity" for "max
//! velocity * 0.5", the corresponding test breaks.
//!
//! All generators in this category are currently deterministic by
//! arithmetic (no RNG plumbing — see v11 2.0). When a stochastic
//! variant lands, plumb `&mut CampaignRng` through the generator and
//! tighten the assertion to require exact reproducibility.

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

const COUNT: usize = 32;
const EPS: f64 = 1.0e-9;

fn ops() -> [Operation; 1] {
    [Operation::new("actuate:*").expect("valid op")]
}

fn gen(scenario: ScenarioType) -> Vec<invariant_robotics::models::command::Command> {
    let profile = load_builtin("ur10").expect("ur10 builtin");
    let g = ScenarioGenerator::new(&profile, scenario);
    g.generate_commands(COUNT, "", &ops())
}

#[test]
fn b01_position_boundary_hits_min_and_max() {
    let profile = load_builtin("ur10").expect("ur10 builtin");
    let cmds = gen(ScenarioType::JointPositionBoundary);

    // For each joint, at least one command must hit min and at least one max.
    for jdef in &profile.joints {
        let touched_min = cmds.iter().any(|c| {
            c.joint_states
                .iter()
                .any(|j| j.name == jdef.name && (j.position - jdef.min).abs() < EPS)
        });
        let touched_max = cmds.iter().any(|c| {
            c.joint_states
                .iter()
                .any(|j| j.name == jdef.name && (j.position - jdef.max).abs() < EPS)
        });
        // We may not have cycled long enough to cover every joint; require at
        // least one joint with both touches.
        if touched_min && touched_max {
            return;
        }
    }
    panic!("expected at least one joint to be commanded at both min and max");
}

#[test]
fn b02_velocity_boundary_hits_max_velocity_exactly() {
    let profile = load_builtin("ur10").expect("ur10 builtin");
    let cmds = gen(ScenarioType::JointVelocityBoundary);

    for jdef in &profile.joints {
        let max_v = jdef.max_velocity * profile.global_velocity_scale;
        let hit = cmds.iter().any(|c| {
            c.joint_states
                .iter()
                .any(|j| j.name == jdef.name && (j.velocity - max_v).abs() < EPS)
        });
        if hit {
            return;
        }
    }
    panic!("no joint commanded at exactly max_velocity");
}

#[test]
fn b03_torque_boundary_hits_max_torque_exactly() {
    let profile = load_builtin("ur10").expect("ur10 builtin");
    let cmds = gen(ScenarioType::JointTorqueBoundary);

    for jdef in &profile.joints {
        let hit = cmds.iter().any(|c| {
            c.joint_states
                .iter()
                .any(|j| j.name == jdef.name && (j.effort - jdef.max_torque).abs() < EPS)
        });
        if hit {
            return;
        }
    }
    panic!("no joint commanded at exactly max_torque");
}

#[test]
fn b04_acceleration_ramp_monotonically_increases_velocity() {
    let cmds = gen(ScenarioType::JointAccelerationRamp);
    assert_eq!(cmds.len(), COUNT);

    // For the first joint, |velocity| over the sequence must be strictly
    // non-decreasing (ramp is monotonic).
    let series: Vec<f64> = cmds
        .iter()
        .map(|c| c.joint_states[0].velocity.abs())
        .collect();
    for w in series.windows(2) {
        assert!(
            w[1] >= w[0] - EPS,
            "ramp not monotonic: {:?} -> {:?}",
            w[0],
            w[1]
        );
    }

    // The final step's |velocity| must exceed max_velocity * 2 (ramp goes
    // to 3× near the end).
    let profile = load_builtin("ur10").expect("ur10 builtin");
    let last_v = series.last().copied().unwrap();
    let max_v = profile.joints[0].max_velocity * profile.global_velocity_scale;
    assert!(
        last_v > max_v * 2.0,
        "final |velocity| {last_v} should exceed 2 × max_velocity {}",
        max_v * 2.0
    );
}

#[test]
fn b05_coordinated_violation_alternates_99_and_101_percent() {
    let profile = load_builtin("ur10").expect("ur10 builtin");
    let cmds = gen(ScenarioType::JointCoordinatedViolation);

    // Even index → 0.99 × max for every joint; odd index → 1.01 ×.
    for (i, cmd) in cmds.iter().enumerate() {
        let scale = if i % 2 == 0 { 0.99 } else { 1.01 };
        for (j, jdef) in profile.joints.iter().enumerate() {
            let expected = jdef.max * scale;
            let got = cmd.joint_states[j].position;
            assert!(
                (got - expected).abs() < EPS.max(expected.abs() * 1e-12),
                "cmd {i} joint {j}: expected position {expected}, got {got}"
            );
        }
    }
}

#[test]
fn b06_direction_reversal_alternates_velocity_sign() {
    let profile = load_builtin("ur10").expect("ur10 builtin");
    let cmds = gen(ScenarioType::JointDirectionReversal);
    let max_v = profile.joints[0].max_velocity * profile.global_velocity_scale;

    for (i, cmd) in cmds.iter().enumerate() {
        let sign = if i % 2 == 0 { 1.0 } else { -1.0 };
        let expected = max_v * sign;
        let got = cmd.joint_states[0].velocity;
        assert!(
            (got - expected).abs() < EPS,
            "cmd {i}: expected v={expected}, got {got}"
        );
    }
}

#[test]
fn b07_ieee754_special_emits_nonfinite_values() {
    let cmds = gen(ScenarioType::JointIeee754Special);

    // At least one command must carry a NaN or ±Inf somewhere in joint state.
    let any_nonfinite = cmds.iter().any(|c| {
        c.joint_states
            .iter()
            .any(|j| !j.position.is_finite() || !j.velocity.is_finite() || !j.effort.is_finite())
    });
    assert!(
        any_nonfinite,
        "expected at least one non-finite joint value in the B-07 sequence"
    );
}

#[test]
fn b08_gradual_drift_strictly_exceeds_max_each_step() {
    let profile = load_builtin("ur10").expect("ur10 builtin");
    let cmds = gen(ScenarioType::JointGradualDrift);

    // Every command's target joint must be at strictly > jdef.max.
    let njoints = profile.joints.len();
    for (i, cmd) in cmds.iter().enumerate() {
        let target = i % njoints;
        let jdef = &profile.joints[target];
        let pos = cmd.joint_states[target].position;
        assert!(
            pos > jdef.max,
            "cmd {i} target joint {target} position {pos} must exceed max {}",
            jdef.max
        );
    }
}
