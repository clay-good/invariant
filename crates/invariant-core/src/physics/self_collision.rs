// P7: Self-collision distance check

use crate::models::command::EndEffectorPosition;
use crate::models::profile::CollisionPair;
use crate::models::verdict::CheckResult;

/// Minimum allowed Euclidean distance (in metres) between any two links in a
/// collision pair before the check is considered failed.
const MIN_SELF_COLLISION_DIST: f64 = 0.01;

/// Check that every link pair in `collision_pairs` maintains at least
/// [`MIN_SELF_COLLISION_DIST`] (1 cm) between their end-effector positions.
///
/// Each link is looked up in `end_effectors` by name.  If either link in a pair
/// has no corresponding end-effector entry the pair is skipped — the check
/// cannot be evaluated without position data.
///
/// If `end_effectors` or `collision_pairs` is empty the check passes trivially.
pub fn check_self_collision(
    end_effectors: &[EndEffectorPosition],
    collision_pairs: &[CollisionPair],
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
            None => continue,
        };
        let pos_b = match end_effectors.iter().find(|ee| ee.name == pair.link_b) {
            Some(ee) => &ee.position,
            None => continue,
        };

        let dist = euclidean_distance(pos_a, pos_b);
        if dist < MIN_SELF_COLLISION_DIST {
            violations.push(format!(
                "'{}' and '{}': distance {:.6} m < minimum {:.6} m",
                pair.link_a, pair.link_b, dist, MIN_SELF_COLLISION_DIST
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
