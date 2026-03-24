// P7: Self-collision distance check

use crate::models::command::EndEffectorPosition;
use crate::models::profile::CollisionPair;
use crate::models::verdict::CheckResult;

/// Check that every link pair in `collision_pairs` maintains at least
/// `min_collision_distance` between their end-effector positions.
///
/// Each link is looked up in `end_effectors` by name.  If either link in a pair
/// has no corresponding end-effector entry the pair is flagged as a violation.
///
/// If `end_effectors` or `collision_pairs` is empty the check passes trivially.
pub fn check_self_collision(
    end_effectors: &[EndEffectorPosition],
    collision_pairs: &[CollisionPair],
    min_collision_distance: f64,
) -> CheckResult {
    if end_effectors.is_empty() || collision_pairs.is_empty() {
        return CheckResult {
            name: "self_collision".to_string(),
            category: "physics".to_string(),
            passed: true,
            details: "no self-collision violations".to_string(),
        };
    }

    let mut violations: Vec<String> = Vec::new();

    for pair in collision_pairs {
        let pos_a = match end_effectors.iter().find(|ee| ee.name == pair.link_a) {
            Some(ee) => &ee.position,
            None => {
                violations.push(format!(
                    "'{}': link not found in end-effector positions",
                    pair.link_a
                ));
                continue;
            }
        };
        let pos_b = match end_effectors.iter().find(|ee| ee.name == pair.link_b) {
            Some(ee) => &ee.position,
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
        }
    } else {
        CheckResult {
            name: "self_collision".to_string(),
            category: "physics".to_string(),
            passed: false,
            details: violations.join("; "),
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
