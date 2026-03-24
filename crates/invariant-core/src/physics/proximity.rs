// P10: Proximity-based velocity scaling check

use crate::models::command::{EndEffectorPosition, JointState};
use crate::models::profile::{JointDefinition, ProximityZone};
use crate::models::verdict::CheckResult;

/// Check that all joint velocities respect proximity-zone velocity scaling.
///
/// # Algorithm
///
/// 1. For each end-effector, determine which proximity zones it is currently
///    inside (sphere intersection).
/// 2. Collect the minimum `velocity_scale` across all active zones.  If no
///    end-effector is inside any zone the check passes trivially.
/// 3. The effective velocity limit for each joint is:
///    `max_velocity * min_proximity_scale * global_velocity_scale`
/// 4. A violation is recorded for every joint whose `|velocity|` exceeds that
///    limit.
///
/// A joint that has no matching [`JointDefinition`] is flagged as a violation.
///
/// The check passes trivially when `joints`, `definitions`, `end_effectors`, or
/// `proximity_zones` is empty, or when no end-effector is inside any zone.
pub fn check_proximity_velocity(
    joints: &[JointState],
    definitions: &[JointDefinition],
    end_effectors: &[EndEffectorPosition],
    proximity_zones: &[ProximityZone],
    global_velocity_scale: f64,
) -> CheckResult {
    // Reject non-finite end-effector positions before proximity determination.
    let mut ee_violations: Vec<String> = Vec::new();
    for ee in end_effectors {
        if !ee.position[0].is_finite() || !ee.position[1].is_finite() || !ee.position[2].is_finite() {
            ee_violations.push(format!(
                "'{}': end-effector position contains NaN or infinite value",
                ee.name
            ));
        }
    }
    if !ee_violations.is_empty() {
        return CheckResult {
            name: "proximity_velocity".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: ee_violations.join("; "),
        };
    }

    // Determine the most-restrictive (minimum) velocity_scale across all zones
    // that currently contain at least one end-effector.
    let min_scale = active_proximity_scale(end_effectors, proximity_zones);

    let min_scale = match min_scale {
        Some(s) => s,
        None => {
            // No end-effector is inside any proximity zone — trivially passes.
            return CheckResult {
                name: "proximity_velocity".to_string(),
                category: "physics".to_string(),
                passed: true,
                details: "no end-effectors inside proximity zones".to_string(),
            };
        }
    };

    let mut violations: Vec<String> = Vec::new();

    for state in joints {
        let def = match definitions.iter().find(|d| d.name == state.name) {
            Some(d) => d,
            None => {
                violations.push(format!(
                    "'{}': unknown joint (no definition found)",
                    state.name
                ));
                continue;
            }
        };

        if !state.velocity.is_finite() {
            violations.push(format!(
                "'{}': velocity is NaN or infinite",
                state.name
            ));
            continue;
        }

        let effective_limit = def.max_velocity * min_scale * global_velocity_scale;
        let abs_vel = state.velocity.abs();

        if abs_vel > effective_limit {
            violations.push(format!(
                "'{}': |velocity| {:.6} rad/s > limit {:.6} rad/s \
                 (max_vel={:.6}, proximity_scale={:.4}, global_scale={:.4})",
                state.name, abs_vel, effective_limit,
                def.max_velocity, min_scale, global_velocity_scale
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "proximity_velocity".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: format!(
                "all joint velocities within proximity-scaled limits \
                 (proximity_scale={:.4}, global_scale={:.4})",
                min_scale, global_velocity_scale
            ),
        }
    } else {
        CheckResult {
            name: "proximity_velocity".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
        }
    }
}

/// Return the minimum `velocity_scale` across all proximity zones that contain
/// at least one of the supplied `end_effectors`, or `None` if no zone is active.
fn active_proximity_scale(
    end_effectors: &[EndEffectorPosition],
    proximity_zones: &[ProximityZone],
) -> Option<f64> {
    let mut min_scale: Option<f64> = None;

    for zone in proximity_zones {
        match zone {
            ProximityZone::Sphere {
                center,
                radius,
                velocity_scale,
                ..
            } => {
                let any_inside = end_effectors
                    .iter()
                    .any(|ee| point_in_sphere(&ee.position, center, *radius));

                if any_inside {
                    min_scale = Some(match min_scale {
                        None => *velocity_scale,
                        Some(current) => current.min(*velocity_scale),
                    });
                }
            }
        }
    }

    min_scale
}

/// Returns `true` if `point` is inside or on the surface of the sphere.
#[inline]
fn point_in_sphere(point: &[f64; 3], center: &[f64; 3], radius: f64) -> bool {
    let dx = point[0] - center[0];
    let dy = point[1] - center[1];
    let dz = point[2] - center[2];
    dx * dx + dy * dy + dz * dz <= radius * radius
}
