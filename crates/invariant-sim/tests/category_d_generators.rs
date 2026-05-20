//! Intent tests for Category D (Stability & Locomotion) generators that
//! close out v11 prompt 2.3. D-03/D-04/D-05/D-06/D-09 ship as legacy
//! `Locomotion*` variants. This file covers the remaining rows:
//!
//! - D-01 `ComStabilitySweep`
//! - D-02 `WalkingGaitValidation`
//! - D-07 `StepOverextension`
//! - D-08 `HeadingSpinout`
//! - D-10 `InclineWalking`
//!
//! Profile: `bd_atlas` — humanoid with `locomotion`, `stability`, and
//! `environment` configs, so every D-row's threshold is meaningful.

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

fn ops() -> Vec<Operation> {
    vec![Operation::new("actuate:*").unwrap()]
}

fn load_profile() -> invariant_robotics::models::profile::RobotProfile {
    load_builtin("bd_atlas").expect("bd_atlas profile must be available")
}

/// Helper: convex polygon containment via the same cross-product test
/// the validator uses. Polygon vertices in CCW order; returns true when
/// `(x, y)` lies in the closed polygon.
fn point_in_polygon(x: f64, y: f64, poly: &[[f64; 2]]) -> bool {
    let n = poly.len();
    if n < 3 {
        return false;
    }
    let mut prev_sign: Option<bool> = None;
    for i in 0..n {
        let a = poly[i];
        let b = poly[(i + 1) % n];
        let cross = (b[0] - a[0]) * (y - a[1]) - (b[1] - a[1]) * (x - a[0]);
        if cross.abs() < 1e-12 {
            continue; // on edge
        }
        let s = cross > 0.0;
        match prev_sign {
            None => prev_sign = Some(s),
            Some(p) if p != s => return false,
            _ => {}
        }
    }
    true
}

#[test]
fn d_01_cycles_four_com_positions_three_inside_one_outside() {
    let profile = load_profile();
    let stability = profile
        .stability
        .as_ref()
        .expect("bd_atlas has stability config");
    let polygon = &stability.support_polygon;
    let count = 32;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::ComStabilitySweep).generate_commands(
        count,
        "",
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    let mut inside_count = 0;
    let mut outside_count = 0;
    for (i, c) in cmds.iter().enumerate() {
        let com = c.center_of_mass.expect("D-01 always sets COM");
        let inside = point_in_polygon(com[0], com[1], polygon);
        match i % 4 {
            3 => {
                assert!(
                    !inside,
                    "mode 3 (translated +10 m) must be outside polygon: COM={com:?}"
                );
                outside_count += 1;
            }
            _ => {
                assert!(
                    inside,
                    "mode {} (centroid/vertex/midpoint) must be inside or on polygon: COM={com:?}",
                    i % 4
                );
                inside_count += 1;
            }
        }
        // Joint state stays baseline-safe.
        for js in &c.joint_states {
            assert!(js.position.is_finite() && js.velocity.is_finite());
        }
    }
    assert_eq!(outside_count, count / 4);
    assert_eq!(inside_count, count - outside_count);
}

#[test]
fn d_02_walking_gait_stays_within_locomotion_limits() {
    let profile = load_profile();
    let loco = profile
        .locomotion
        .as_ref()
        .expect("bd_atlas has locomotion config");
    let count = 20;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::WalkingGaitValidation)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let mut even_swing_right = 0;
    let mut odd_swing_left = 0;
    for (i, c) in cmds.iter().enumerate() {
        let ls = c
            .locomotion_state
            .as_ref()
            .expect("D-02 always sets locomotion_state");
        let vmag = (ls.base_velocity[0].powi(2)
            + ls.base_velocity[1].powi(2)
            + ls.base_velocity[2].powi(2))
        .sqrt();
        assert!(
            vmag <= loco.max_locomotion_velocity,
            "D-02 base_velocity {vmag} must stay at or below max {}",
            loco.max_locomotion_velocity
        );
        assert!(
            ls.heading_rate.abs() <= loco.max_heading_rate,
            "D-02 heading_rate {} within ±max {}",
            ls.heading_rate,
            loco.max_heading_rate
        );
        assert!(
            ls.step_length <= loco.max_step_length,
            "D-02 step_length {} within max {}",
            ls.step_length,
            loco.max_step_length
        );
        // Alternation: swing foot index flips by parity.
        let (stance, swing) = if i.is_multiple_of(2) { (0, 1) } else { (1, 0) };
        assert!(ls.feet[stance].contact);
        assert!(!ls.feet[swing].contact);
        let swing_h = ls.feet[swing].position[2];
        assert!(
            swing_h >= loco.min_foot_clearance && swing_h <= loco.max_step_height,
            "D-02 swing height {swing_h} must be in [{}, {}]",
            loco.min_foot_clearance,
            loco.max_step_height
        );
        if i.is_multiple_of(2) {
            even_swing_right += 1;
        } else {
            odd_swing_left += 1;
        }
    }
    assert!(even_swing_right > 0 && odd_swing_left > 0);
}

#[test]
fn d_07_step_length_ramps_past_max() {
    let profile = load_profile();
    let max_step = profile.locomotion.as_ref().unwrap().max_step_length;
    let count = 40;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::StepOverextension).generate_commands(
        count,
        "",
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    let steps: Vec<f64> = cmds
        .iter()
        .map(|c| c.locomotion_state.as_ref().unwrap().step_length)
        .collect();
    // First command is at 0.5× max.
    assert!((steps[0] - max_step * 0.5).abs() < 1e-9);
    // Monotonic non-decreasing.
    for w in steps.windows(2) {
        assert!(w[1] >= w[0], "step_length ramp must be monotonic");
    }
    // Final exceeds 2× max.
    assert!(
        *steps.last().unwrap() > max_step * 2.0,
        "D-07 final step_length {} must exceed 2× max {}",
        steps.last().unwrap(),
        max_step
    );
    // At least one command above the limit (failure side).
    assert!(steps.iter().any(|&s| s > max_step));
    // At least one command below the limit (pass side).
    assert!(steps.iter().any(|&s| s <= max_step));
}

#[test]
fn d_08_heading_rate_ramps_past_max() {
    let profile = load_profile();
    let max_heading = profile.locomotion.as_ref().unwrap().max_heading_rate;
    let count = 40;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::HeadingSpinout).generate_commands(
        count,
        "",
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    let rates: Vec<f64> = cmds
        .iter()
        .map(|c| c.locomotion_state.as_ref().unwrap().heading_rate)
        .collect();
    assert!((rates[0]).abs() < 1e-9, "D-08 first heading_rate ≈ 0");
    for w in rates.windows(2) {
        assert!(w[1] >= w[0]);
    }
    assert!(*rates.last().unwrap() > max_heading * 4.0);
    assert!(rates.iter().any(|&r| r > max_heading));
    assert!(rates.iter().any(|&r| r <= max_heading));
}

#[test]
fn d_10_pitch_ramps_past_max_safe_pitch() {
    let profile = load_profile();
    let env = profile
        .environment
        .as_ref()
        .expect("bd_atlas has environment config");
    let max_pitch = env.max_safe_pitch_rad;
    let warning_pitch = env.warning_pitch_rad;
    let count = 60;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::InclineWalking).generate_commands(
        count,
        "",
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    let pitches: Vec<f64> = cmds
        .iter()
        .map(|c| {
            c.environment_state
                .as_ref()
                .expect("D-10 always sets env state")
                .imu_pitch_rad
                .expect("D-10 always sets imu_pitch_rad")
        })
        .collect();
    assert!(pitches[0].abs() < 1e-9, "D-10 first pitch ≈ 0");
    for w in pitches.windows(2) {
        assert!(w[1] >= w[0], "D-10 pitch ramp must be monotonic");
    }
    let peak = 30.0_f64.to_radians();
    let last = *pitches.last().unwrap();
    assert!(
        last <= peak && last > peak * 0.95,
        "D-10 final pitch {last} should be just below 30° peak {peak}"
    );
    assert!(pitches.iter().any(|&p| p > max_pitch));
    assert!(pitches.iter().any(|&p| p > warning_pitch && p <= max_pitch));
    assert!(pitches.iter().any(|&p| p < warning_pitch));
}

#[test]
fn d_spec_id_bindings() {
    assert_eq!(ScenarioType::ComStabilitySweep.spec_id(), "D-01");
    assert_eq!(ScenarioType::WalkingGaitValidation.spec_id(), "D-02");
    assert_eq!(ScenarioType::StepOverextension.spec_id(), "D-07");
    assert_eq!(ScenarioType::HeadingSpinout.spec_id(), "D-08");
    assert_eq!(ScenarioType::InclineWalking.spec_id(), "D-10");
}
