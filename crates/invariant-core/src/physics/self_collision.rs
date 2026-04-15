// P7: Self-collision distance check

use std::collections::HashMap;

use crate::models::command::EndEffectorPosition;
use crate::models::profile::CollisionPair;
use crate::models::verdict::CheckResult;

/// Check that every link pair in `collision_pairs` maintains at least
/// `min_collision_distance` between their end-effector positions.
///
/// Each link is looked up in `end_effectors` by name.  If either link in a pair
/// has no corresponding end-effector entry the pair is flagged as a violation.
///
/// If `collision_pairs` is empty the check passes trivially.
/// If `collision_pairs` is non-empty but `end_effectors` is empty the check fails —
/// positions are required to evaluate minimum-distance constraints.
pub fn check_self_collision(
    end_effectors: &[EndEffectorPosition],
    collision_pairs: &[CollisionPair],
    min_collision_distance: f64,
) -> CheckResult {
    // No collision pairs defined: nothing to check.
    if collision_pairs.is_empty() {
        return CheckResult {
            name: "self_collision".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no self-collision violations".to_string(),
            derating: None,
        };
    }

    // Collision pairs are defined but no positions provided: cannot verify — fail.
    if end_effectors.is_empty() {
        return CheckResult {
            name: "self_collision".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: "end_effector_positions required for self-collision check".to_string(),
            derating: None,
        };
    }

    let ee_map: HashMap<&str, &[f64; 3]> = end_effectors
        .iter()
        .map(|ee| (ee.name.as_str(), &ee.position))
        .collect();

    let mut violations: Vec<String> = Vec::new();

    for pair in collision_pairs {
        let pos_a = match ee_map.get(pair.link_a.as_str()) {
            Some(pos) => *pos,
            None => {
                violations.push(format!(
                    "'{}': link not found in end-effector positions",
                    pair.link_a
                ));
                continue;
            }
        };
        let pos_b = match ee_map.get(pair.link_b.as_str()) {
            Some(pos) => *pos,
            None => {
                violations.push(format!(
                    "'{}': link not found in end-effector positions",
                    pair.link_b
                ));
                continue;
            }
        };

        // Reject non-finite positions.
        if !pos_a.iter().all(|v| v.is_finite()) || !pos_b.iter().all(|v| v.is_finite()) {
            violations.push(format!(
                "'{}' and '{}': position contains NaN or infinite value",
                pair.link_a, pair.link_b
            ));
            continue;
        }

        let dist = euclidean_distance(pos_a, pos_b);
        if dist < min_collision_distance {
            violations.push(format!(
                "'{}' and '{}': distance {:.6} m < minimum {:.6} m",
                pair.link_a, pair.link_b, dist, min_collision_distance
            ));
        }
    }

    if violations.is_empty() {
        CheckResult {
            name: "self_collision".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no self-collision violations".to_string(),
            derating: None,
        }
    } else {
        CheckResult {
            name: "self_collision".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
            derating: None,
        }
    }
}

/// Euclidean distance between two 3-D points.
#[inline]
fn euclidean_distance(a: &[f64; 3], b: &[f64; 3]) -> f64 {
    let dx = a[0] - b[0];
    let dy = a[1] - b[1];
    let dz = a[2] - b[2];
    (dx * dx + dy * dy + dz * dz).sqrt()
}
