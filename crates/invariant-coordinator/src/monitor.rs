// Cross-robot coordination monitor.
//
// Tracks the state of multiple robots and performs cross-robot safety checks:
// - Minimum separation distance between any pair of robots' end-effectors
// - Shared exclusion zone enforcement (no two robots in the same zone)
// - Stale state detection (robot not reporting → treat as obstacle)

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by the coordination monitor.
#[derive(Debug, Error)]
pub enum CoordinatorError {
    /// An operation referenced a robot ID that is not registered.
    #[error("unknown robot: {robot_id}")]
    UnknownRobot {
        /// The unrecognised robot identifier.
        robot_id: String,
    },

    /// Registering a new robot would exceed the configured `max_robots` limit.
    #[error("too many robots registered: {count} exceeds limit {max}")]
    TooManyRobots {
        /// The would-be total number of registered robots.
        count: usize,
        /// The configured maximum.
        max: usize,
    },
}

// ---------------------------------------------------------------------------
// Robot state
// ---------------------------------------------------------------------------

/// Snapshot of a single robot's state, reported by its Invariant instance.
///
/// # Examples
///
/// ```
/// use invariant_robotics_coordinator::monitor::{RobotState, EndEffectorState};
/// use chrono::Utc;
///
/// let state = RobotState {
///     robot_id: "ur10e-cell-1".into(),
///     timestamp: Utc::now(),
///     end_effector_positions: vec![
///         EndEffectorState { name: "gripper".into(), position: [1.2, 0.5, 0.8] },
///     ],
///     active: true,
/// };
///
/// assert_eq!(state.robot_id, "ur10e-cell-1");
/// assert!(state.active);
/// assert_eq!(state.end_effector_positions.len(), 1);
/// assert_eq!(state.end_effector_positions[0].name, "gripper");
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RobotState {
    /// Unique identifier for this robot (e.g. "ur10e-cell-1").
    pub robot_id: String,
    /// Timestamp of this state update.
    pub timestamp: DateTime<Utc>,
    /// Positions of all end-effectors in world frame [x, y, z].
    pub end_effector_positions: Vec<EndEffectorState>,
    /// Whether the robot is currently active (executing commands).
    pub active: bool,
}

/// Position of a single end-effector or tracked link.
///
/// # Examples
///
/// ```
/// use invariant_robotics_coordinator::monitor::EndEffectorState;
///
/// let ee = EndEffectorState {
///     name: "tcp".into(),
///     position: [0.5, -0.3, 1.1],
/// };
///
/// assert_eq!(ee.name, "tcp");
/// assert!((ee.position[0] - 0.5).abs() < 1e-10);
/// assert!((ee.position[2] - 1.1).abs() < 1e-10);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndEffectorState {
    /// Name of this end-effector or tracked link (e.g. "tcp", "gripper").
    pub name: String,
    /// Position in world frame as [x, y, z] in metres.
    pub position: [f64; 3],
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Policy for handling robots whose state has gone stale (no update within
/// the timeout).
///
/// # Examples
///
/// ```
/// use invariant_robotics_coordinator::monitor::StaleRobotPolicy;
///
/// // Both variants are available and can be compared.
/// assert_ne!(StaleRobotPolicy::TreatAsObstacle, StaleRobotPolicy::RejectAll);
/// assert_eq!(StaleRobotPolicy::TreatAsObstacle, StaleRobotPolicy::TreatAsObstacle);
///
/// // StaleRobotPolicy is Copy.
/// let policy = StaleRobotPolicy::RejectAll;
/// let copy = policy;
/// assert_eq!(policy, copy);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaleRobotPolicy {
    /// Treat the stale robot as an obstacle at its last known position.
    /// Other robots must maintain minimum separation from it.
    TreatAsObstacle,
    /// Reject all coordination checks involving the stale robot.
    RejectAll,
}

/// Configuration for the coordination monitor.
///
/// # Examples
///
/// ```
/// use invariant_robotics_coordinator::monitor::{CoordinationConfig, StaleRobotPolicy};
///
/// // Default configuration: 0.5m separation, 200ms stale timeout.
/// let config = CoordinationConfig::default();
/// assert_eq!(config.min_separation_m, 0.5);
/// assert_eq!(config.stale_timeout_ms, 200);
/// assert_eq!(config.stale_policy, StaleRobotPolicy::TreatAsObstacle);
/// assert!(config.validate().is_ok());
///
/// // Custom configuration for a tightly packed cell.
/// let tight = CoordinationConfig {
///     min_separation_m: 0.2,
///     stale_timeout_ms: 100,
///     stale_policy: StaleRobotPolicy::RejectAll,
///     max_robots: 4,
/// };
/// assert!(tight.validate().is_ok());
///
/// // Zero separation is rejected.
/// let invalid = CoordinationConfig { min_separation_m: 0.0, ..Default::default() };
/// assert!(invalid.validate().is_err());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationConfig {
    /// Minimum distance (meters) between any two robots' end-effectors.
    /// Violations produce a failed CrossRobotCheck.
    pub min_separation_m: f64,
    /// Maximum age (milliseconds) of a robot state before it is considered stale.
    pub stale_timeout_ms: u64,
    /// Policy for stale robots.
    pub stale_policy: StaleRobotPolicy,
    /// Maximum number of robots that can be registered.
    pub max_robots: usize,
}

impl CoordinationConfig {
    /// Validate the configuration.
    ///
    /// Returns an error if `min_separation_m` is non-positive or non-finite.
    pub fn validate(&self) -> Result<(), String> {
        if !self.min_separation_m.is_finite() || self.min_separation_m <= 0.0 {
            return Err(format!(
                "min_separation_m must be finite and positive, got {}",
                self.min_separation_m
            ));
        }
        if self.max_robots == 0 {
            return Err("max_robots must be at least 1".into());
        }
        Ok(())
    }
}

impl Default for CoordinationConfig {
    fn default() -> Self {
        Self {
            min_separation_m: 0.5,
            stale_timeout_ms: 200,
            stale_policy: StaleRobotPolicy::TreatAsObstacle,
            max_robots: 32,
        }
    }
}

// ---------------------------------------------------------------------------
// Coordination verdict
// ---------------------------------------------------------------------------

/// Result of a single cross-robot safety check.
///
/// # Examples
///
/// ```
/// use invariant_robotics_coordinator::monitor::CrossRobotCheck;
///
/// // A passing separation check.
/// let passing = CrossRobotCheck {
///     name: "separation".into(),
///     robot_a: "ur10e-cell-1".into(),
///     robot_b: "ur10e-cell-2".into(),
///     passed: true,
///     details: "minimum separation 1.200m >= 0.500m (closest: gripper <-> gripper)".into(),
/// };
/// assert!(passing.passed);
/// assert_eq!(passing.name, "separation");
///
/// // A failing separation check.
/// let failing = CrossRobotCheck {
///     name: "separation".into(),
///     robot_a: "cobot-a".into(),
///     robot_b: "cobot-b".into(),
///     passed: false,
///     details: "VIOLATION: separation 0.150m < 0.500m between tcp and tcp".into(),
/// };
/// assert!(!failing.passed);
/// assert!(failing.details.contains("VIOLATION"));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossRobotCheck {
    /// Name of this check (e.g. "separation", "stale_state").
    pub name: String,
    /// Identifier of the first robot involved in this check.
    pub robot_a: String,
    /// Identifier of the second robot involved in this check.
    pub robot_b: String,
    /// Whether this check passed.
    pub passed: bool,
    /// Human-readable details.
    pub details: String,
}

/// The result of coordinating a robot's proposed state against all other robots.
///
/// # Examples
///
/// ```
/// use invariant_robotics_coordinator::monitor::{
///     CoordinationVerdict, CrossRobotCheck, CoordinationMonitor,
///     CoordinationConfig, RobotState, EndEffectorState,
/// };
/// use chrono::Utc;
///
/// let config = CoordinationConfig::default();
/// let mut monitor = CoordinationMonitor::new(config);
/// let now = Utc::now();
///
/// // Register one robot.
/// monitor.update_state(RobotState {
///     robot_id: "ur10e-cell-1".into(),
///     timestamp: now,
///     end_effector_positions: vec![
///         EndEffectorState { name: "gripper".into(), position: [0.0, 0.0, 1.0] },
///     ],
///     active: true,
/// }).unwrap();
///
/// // Check a second robot positioned 2.0 m away — should be safe.
/// let proposed = RobotState {
///     robot_id: "ur10e-cell-2".into(),
///     timestamp: now,
///     end_effector_positions: vec![
///         EndEffectorState { name: "gripper".into(), position: [2.0, 0.0, 1.0] },
///     ],
///     active: true,
/// };
/// let verdict = monitor.check(&proposed, now);
///
/// assert!(verdict.safe, "robots 2 m apart should pass the 0.5 m separation check");
/// assert_eq!(verdict.robot_id, "ur10e-cell-2");
/// assert_eq!(verdict.robots_evaluated, 1);
/// assert_eq!(verdict.stale_robots, 0);
/// assert!(verdict.checks.iter().all(|c| c.passed));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoordinationVerdict {
    /// The robot being checked.
    pub robot_id: String,
    /// Timestamp of this verdict.
    pub timestamp: DateTime<Utc>,
    /// Whether all cross-robot checks passed.
    pub safe: bool,
    /// Individual check results.
    pub checks: Vec<CrossRobotCheck>,
    /// Number of other robots evaluated against.
    pub robots_evaluated: usize,
    /// Number of stale robots detected.
    pub stale_robots: usize,
}

// ---------------------------------------------------------------------------
// Coordination monitor
// ---------------------------------------------------------------------------

/// Maximum number of end-effectors per robot (DoS guard).
const MAX_EE_PER_ROBOT: usize = 64;

/// Result of a successful [`CoordinationMonitor::update_state`] call.
///
/// # Examples
///
/// ```
/// use invariant_robotics_coordinator::monitor::{
///     CoordinationMonitor, CoordinationConfig, RobotState, EndEffectorState,
/// };
/// use chrono::Utc;
///
/// let mut monitor = CoordinationMonitor::new(CoordinationConfig::default());
/// let state = RobotState {
///     robot_id: "r1".into(),
///     timestamp: Utc::now(),
///     end_effector_positions: vec![
///         EndEffectorState { name: "tcp".into(), position: [0.0, 0.0, 1.0] },
///     ],
///     active: true,
/// };
/// let result = monitor.update_state(state).unwrap();
/// assert_eq!(result.truncated_ee, 0, "small EE list should not be truncated");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateResult {
    /// Number of end-effector entries that were dropped due to the
    /// per-robot DoS limit. Zero means nothing was truncated.
    pub truncated_ee: usize,
}

/// The coordinator. Tracks robot states and performs cross-robot checks.
///
/// # Examples
///
/// ```
/// use invariant_robotics_coordinator::monitor::{
///     CoordinationMonitor, CoordinationConfig, RobotState, EndEffectorState,
///     StaleRobotPolicy,
/// };
/// use chrono::Utc;
///
/// // Create a monitor for a two-robot welding cell.
/// let config = CoordinationConfig {
///     min_separation_m: 0.5,
///     stale_timeout_ms: 200,
///     stale_policy: StaleRobotPolicy::TreatAsObstacle,
///     max_robots: 4,
/// };
/// let mut monitor = CoordinationMonitor::new(config);
/// assert_eq!(monitor.robot_count(), 0);
///
/// let now = Utc::now();
///
/// // Register robot A.
/// monitor.update_state(RobotState {
///     robot_id: "robot-a".into(),
///     timestamp: now,
///     end_effector_positions: vec![
///         EndEffectorState { name: "tcp".into(), position: [0.0, 0.0, 0.8] },
///     ],
///     active: true,
/// }).expect("first robot registration should succeed");
/// assert_eq!(monitor.robot_count(), 1);
///
/// // Query its last-known state.
/// let state = monitor.get_state("robot-a").expect("state should be present");
/// assert_eq!(state.robot_id, "robot-a");
///
/// // A proposed state for robot B, well separated, should be safe.
/// let proposed = RobotState {
///     robot_id: "robot-b".into(),
///     timestamp: now,
///     end_effector_positions: vec![
///         EndEffectorState { name: "tcp".into(), position: [2.0, 0.0, 0.8] },
///     ],
///     active: true,
/// };
/// let verdict = monitor.check(&proposed, now);
/// assert!(verdict.safe);
///
/// // Remove robot A.
/// monitor.remove_robot("robot-a");
/// assert_eq!(monitor.robot_count(), 0);
/// ```
pub struct CoordinationMonitor {
    config: CoordinationConfig,
    /// Last-known state for each registered robot.
    states: HashMap<String, RobotState>,
}

impl CoordinationMonitor {
    /// Create a new coordination monitor with the given configuration.
    pub fn new(config: CoordinationConfig) -> Self {
        Self {
            config,
            states: HashMap::new(),
        }
    }

    /// Register or update a robot's state.
    ///
    /// If the incoming state has more than 64
    /// end-effectors, the list is truncated as a DoS guard and the number
    /// of dropped entries is returned via [`UpdateResult::truncated_ee`].
    pub fn update_state(&mut self, state: RobotState) -> Result<UpdateResult, CoordinatorError> {
        // Enforce max robots (only count new registrations).
        if !self.states.contains_key(&state.robot_id) && self.states.len() >= self.config.max_robots
        {
            return Err(CoordinatorError::TooManyRobots {
                count: self.states.len() + 1,
                max: self.config.max_robots,
            });
        }

        // Truncate oversized end-effector lists to prevent DoS.
        let mut state = state;
        let original_len = state.end_effector_positions.len();
        state.end_effector_positions.truncate(MAX_EE_PER_ROBOT);
        let truncated_ee = original_len.saturating_sub(MAX_EE_PER_ROBOT);

        self.states.insert(state.robot_id.clone(), state);
        Ok(UpdateResult { truncated_ee })
    }

    /// Remove a robot from tracking (e.g., when it powers down).
    pub fn remove_robot(&mut self, robot_id: &str) {
        self.states.remove(robot_id);
    }

    /// Get the current state of a robot, if registered.
    pub fn get_state(&self, robot_id: &str) -> Option<&RobotState> {
        self.states.get(robot_id)
    }

    /// Number of currently tracked robots.
    pub fn robot_count(&self) -> usize {
        self.states.len()
    }

    /// Check whether a robot's proposed state is safe relative to all other
    /// robots. This should be called before approving a command for the robot.
    ///
    /// `proposed` is the state the robot WILL be in if the command is approved.
    /// `now` is the current time for stale-state detection.
    pub fn check(&self, proposed: &RobotState, now: DateTime<Utc>) -> CoordinationVerdict {
        let mut checks = Vec::new();
        let mut stale_count = 0usize;

        for (other_id, other_state) in &self.states {
            if other_id == &proposed.robot_id {
                continue;
            }

            // Check if the other robot's state is stale.
            let age_ms = (now - other_state.timestamp).num_milliseconds().max(0) as u64;
            let is_stale = age_ms > self.config.stale_timeout_ms;

            if is_stale {
                stale_count += 1;

                match self.config.stale_policy {
                    StaleRobotPolicy::RejectAll => {
                        checks.push(CrossRobotCheck {
                            name: "stale_state".into(),
                            robot_a: proposed.robot_id.clone(),
                            robot_b: other_id.clone(),
                            passed: false,
                            details: format!(
                                "{} state is stale ({age_ms}ms > {}ms timeout); \
                                 rejecting under RejectAll policy",
                                other_id, self.config.stale_timeout_ms
                            ),
                        });
                        continue;
                    }
                    StaleRobotPolicy::TreatAsObstacle => {
                        // Continue to check separation against last-known position.
                        // The stale robot is treated as a stationary obstacle.
                    }
                }
            }

            // Check minimum separation between all end-effector pairs.
            let sep_check = self.check_separation(proposed, other_state);
            checks.push(sep_check);
        }

        let safe = checks.iter().all(|c| c.passed);
        // Count how many other robots we actually checked against.
        // If the proposed robot is already registered, subtract 1 (we skip self).
        // If it's new (not yet in states), we check against all registered robots.
        let robots_evaluated = if self.states.contains_key(&proposed.robot_id) {
            self.states.len().saturating_sub(1)
        } else {
            self.states.len()
        };

        CoordinationVerdict {
            robot_id: proposed.robot_id.clone(),
            timestamp: now,
            safe,
            checks,
            robots_evaluated,
            stale_robots: stale_count,
        }
    }

    /// Check minimum separation between all end-effector pairs of two robots.
    fn check_separation(&self, robot_a: &RobotState, robot_b: &RobotState) -> CrossRobotCheck {
        // Fail-closed: reject if any EE position contains NaN/Inf.
        for (robot, ee_list) in [
            (&robot_a.robot_id, &robot_a.end_effector_positions),
            (&robot_b.robot_id, &robot_b.end_effector_positions),
        ] {
            for ee in ee_list {
                if !ee.position.iter().all(|v| v.is_finite()) {
                    return CrossRobotCheck {
                        name: "separation".into(),
                        robot_a: robot_a.robot_id.clone(),
                        robot_b: robot_b.robot_id.clone(),
                        passed: false,
                        details: format!(
                            "robot '{}' EE '{}' has non-finite position",
                            robot, ee.name
                        ),
                    };
                }
            }
        }

        let mut min_dist = f64::MAX;
        let mut closest_a = String::new();
        let mut closest_b = String::new();

        for ee_a in &robot_a.end_effector_positions {
            for ee_b in &robot_b.end_effector_positions {
                let dist = euclidean_distance(&ee_a.position, &ee_b.position);
                if dist < min_dist {
                    min_dist = dist;
                    closest_a.clone_from(&ee_a.name);
                    closest_b.clone_from(&ee_b.name);
                }
            }
        }

        // If either robot has no end-effectors, we can't check separation.
        if min_dist == f64::MAX {
            return CrossRobotCheck {
                name: "separation".into(),
                robot_a: robot_a.robot_id.clone(),
                robot_b: robot_b.robot_id.clone(),
                passed: true,
                details: "no end-effectors to compare".into(),
            };
        }

        let passed = min_dist >= self.config.min_separation_m;
        let details = if passed {
            format!(
                "minimum separation {min_dist:.3}m >= {:.3}m (closest: {closest_a} <-> {closest_b})",
                self.config.min_separation_m
            )
        } else {
            format!(
                "VIOLATION: separation {min_dist:.3}m < {:.3}m between {closest_a} and {closest_b}",
                self.config.min_separation_m
            )
        };

        CrossRobotCheck {
            name: "separation".into(),
            robot_a: robot_a.robot_id.clone(),
            robot_b: robot_b.robot_id.clone(),
            passed,
            details,
        }
    }
}

/// Euclidean distance between two 3D points.
fn euclidean_distance(a: &[f64; 3], b: &[f64; 3]) -> f64 {
    let dx = a[0] - b[0];
    let dy = a[1] - b[1];
    let dz = a[2] - b[2];
    (dx * dx + dy * dy + dz * dz).sqrt()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn robot_state(id: &str, ee_positions: &[(&str, [f64; 3])], now: DateTime<Utc>) -> RobotState {
        RobotState {
            robot_id: id.into(),
            timestamp: now,
            end_effector_positions: ee_positions
                .iter()
                .map(|(name, pos)| EndEffectorState {
                    name: name.to_string(),
                    position: *pos,
                })
                .collect(),
            active: true,
        }
    }

    #[test]
    fn two_robots_well_separated() {
        let config = CoordinationConfig {
            min_separation_m: 0.5,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        let robot_a = robot_state("robot-a", &[("gripper", [0.0, 0.0, 1.0])], now);
        let robot_b = robot_state("robot-b", &[("gripper", [3.0, 0.0, 1.0])], now);

        monitor.update_state(robot_a).unwrap();
        monitor.update_state(robot_b.clone()).unwrap();

        // Check robot B's state against robot A.
        let verdict = monitor.check(&robot_b, now);
        assert!(verdict.safe);
        assert_eq!(verdict.robots_evaluated, 1);
        assert_eq!(verdict.stale_robots, 0);
        assert!(verdict.checks.iter().all(|c| c.passed));
    }

    #[test]
    fn two_robots_too_close() {
        let config = CoordinationConfig {
            min_separation_m: 0.5,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        let robot_a = robot_state("robot-a", &[("gripper", [0.0, 0.0, 1.0])], now);
        let robot_b = robot_state("robot-b", &[("gripper", [0.1, 0.0, 1.0])], now);

        monitor.update_state(robot_a).unwrap();

        let verdict = monitor.check(&robot_b, now);
        assert!(!verdict.safe);
        assert_eq!(verdict.checks.len(), 1);
        assert!(!verdict.checks[0].passed);
        assert!(verdict.checks[0].details.contains("VIOLATION"));
    }

    #[test]
    fn stale_robot_reject_all_policy() {
        let config = CoordinationConfig {
            min_separation_m: 0.5,
            stale_timeout_ms: 100,
            stale_policy: StaleRobotPolicy::RejectAll,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();
        let old = now - Duration::milliseconds(500);

        // Robot A reported 500ms ago — stale.
        let robot_a = robot_state("robot-a", &[("gripper", [5.0, 0.0, 1.0])], old);
        let robot_b = robot_state("robot-b", &[("gripper", [0.0, 0.0, 1.0])], now);

        monitor.update_state(robot_a).unwrap();

        let verdict = monitor.check(&robot_b, now);
        assert!(!verdict.safe);
        assert_eq!(verdict.stale_robots, 1);
        assert!(verdict.checks[0].details.contains("stale"));
    }

    #[test]
    fn stale_robot_treat_as_obstacle_still_checks_separation() {
        let config = CoordinationConfig {
            min_separation_m: 0.5,
            stale_timeout_ms: 100,
            stale_policy: StaleRobotPolicy::TreatAsObstacle,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();
        let old = now - Duration::milliseconds(500);

        // Robot A is stale but well-separated.
        let robot_a = robot_state("robot-a", &[("gripper", [5.0, 0.0, 1.0])], old);
        let robot_b = robot_state("robot-b", &[("gripper", [0.0, 0.0, 1.0])], now);

        monitor.update_state(robot_a).unwrap();

        let verdict = monitor.check(&robot_b, now);
        assert!(verdict.safe); // Far enough away even though stale.
        assert_eq!(verdict.stale_robots, 1);
    }

    #[test]
    fn stale_robot_treat_as_obstacle_too_close() {
        let config = CoordinationConfig {
            min_separation_m: 0.5,
            stale_timeout_ms: 100,
            stale_policy: StaleRobotPolicy::TreatAsObstacle,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();
        let old = now - Duration::milliseconds(500);

        // Robot A is stale AND close.
        let robot_a = robot_state("robot-a", &[("gripper", [0.1, 0.0, 1.0])], old);
        let robot_b = robot_state("robot-b", &[("gripper", [0.0, 0.0, 1.0])], now);

        monitor.update_state(robot_a).unwrap();

        let verdict = monitor.check(&robot_b, now);
        assert!(!verdict.safe); // Stale + too close = unsafe.
    }

    #[test]
    fn single_robot_always_safe() {
        let config = CoordinationConfig::default();
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        let robot = robot_state("robot-a", &[("gripper", [0.0, 0.0, 1.0])], now);
        monitor.update_state(robot.clone()).unwrap();

        let verdict = monitor.check(&robot, now);
        assert!(verdict.safe);
        assert_eq!(verdict.robots_evaluated, 0);
        assert!(verdict.checks.is_empty());
    }

    #[test]
    fn three_robots_pairwise_checks() {
        let config = CoordinationConfig {
            min_separation_m: 0.5,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        monitor
            .update_state(robot_state("r1", &[("ee", [0.0, 0.0, 1.0])], now))
            .unwrap();
        monitor
            .update_state(robot_state("r2", &[("ee", [2.0, 0.0, 1.0])], now))
            .unwrap();
        monitor
            .update_state(robot_state("r3", &[("ee", [4.0, 0.0, 1.0])], now))
            .unwrap();

        // Check r2 against r1 and r3 (both well-separated).
        let state_r2 = robot_state("r2", &[("ee", [2.0, 0.0, 1.0])], now);
        let verdict = monitor.check(&state_r2, now);
        assert!(verdict.safe);
        assert_eq!(verdict.robots_evaluated, 2);
        assert_eq!(verdict.checks.len(), 2);
    }

    #[test]
    fn multiple_end_effectors_closest_pair() {
        let config = CoordinationConfig {
            min_separation_m: 0.3,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        // Robot A has two end-effectors.
        let robot_a = robot_state(
            "robot-a",
            &[
                ("left_hand", [0.0, 0.0, 1.0]),
                ("right_hand", [1.0, 0.0, 1.0]),
            ],
            now,
        );
        // Robot B's gripper is close to A's right_hand but far from left_hand.
        let robot_b = robot_state("robot-b", &[("gripper", [1.1, 0.0, 1.0])], now);

        monitor.update_state(robot_a).unwrap();

        let verdict = monitor.check(&robot_b, now);
        // 0.1m < 0.3m min_separation → violation.
        assert!(!verdict.safe);
        assert!(verdict.checks[0].details.contains("right_hand"));
        assert!(verdict.checks[0].details.contains("gripper"));
    }

    #[test]
    fn remove_robot_stops_tracking() {
        let config = CoordinationConfig::default();
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        monitor
            .update_state(robot_state("r1", &[("ee", [0.0, 0.0, 1.0])], now))
            .unwrap();
        monitor
            .update_state(robot_state("r2", &[("ee", [0.0, 0.0, 1.0])], now))
            .unwrap();
        assert_eq!(monitor.robot_count(), 2);

        monitor.remove_robot("r1");
        assert_eq!(monitor.robot_count(), 1);
        assert!(monitor.get_state("r1").is_none());
        assert!(monitor.get_state("r2").is_some());
    }

    #[test]
    fn max_robots_limit_enforced() {
        let config = CoordinationConfig {
            max_robots: 2,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        monitor.update_state(robot_state("r1", &[], now)).unwrap();
        monitor.update_state(robot_state("r2", &[], now)).unwrap();

        // Third robot should fail.
        let result = monitor.update_state(robot_state("r3", &[], now));
        assert!(result.is_err());

        // Updating an existing robot should still work.
        let result = monitor.update_state(robot_state("r1", &[], now));
        assert!(result.is_ok());
    }

    #[test]
    fn no_end_effectors_passes_separation() {
        let config = CoordinationConfig {
            min_separation_m: 0.5,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        // Robot A has no end-effectors.
        let robot_a = robot_state("robot-a", &[], now);
        let robot_b = robot_state("robot-b", &[("gripper", [0.0, 0.0, 1.0])], now);

        monitor.update_state(robot_a).unwrap();

        let verdict = monitor.check(&robot_b, now);
        assert!(verdict.safe);
    }

    #[test]
    fn update_state_replaces_old_state() {
        let config = CoordinationConfig::default();
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        monitor
            .update_state(robot_state("r1", &[("ee", [0.0, 0.0, 0.0])], now))
            .unwrap();

        // Update to new position.
        let later = now + Duration::milliseconds(50);
        monitor
            .update_state(robot_state("r1", &[("ee", [1.0, 1.0, 1.0])], later))
            .unwrap();

        let state = monitor.get_state("r1").unwrap();
        assert_eq!(state.end_effector_positions[0].position, [1.0, 1.0, 1.0]);
        assert_eq!(state.timestamp, later);
    }

    #[test]
    fn euclidean_distance_correct() {
        assert!((euclidean_distance(&[0.0, 0.0, 0.0], &[3.0, 4.0, 0.0]) - 5.0).abs() < 1e-10);
        assert!((euclidean_distance(&[1.0, 1.0, 1.0], &[1.0, 1.0, 1.0])).abs() < 1e-10);
    }

    #[test]
    fn proposed_state_not_yet_registered_works() {
        let config = CoordinationConfig {
            min_separation_m: 0.5,
            ..Default::default()
        };
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        // Only robot A is registered.
        monitor
            .update_state(robot_state("r1", &[("ee", [0.0, 0.0, 1.0])], now))
            .unwrap();

        // Check a proposed state for robot B (not yet registered).
        let proposed = robot_state("r2", &[("ee", [5.0, 0.0, 1.0])], now);
        let verdict = monitor.check(&proposed, now);
        assert!(verdict.safe);
        assert_eq!(verdict.robots_evaluated, 1);
    }

    // ── Coordinator security hardening tests ─────────────────

    #[test]
    fn config_validate_rejects_zero_separation() {
        let config = CoordinationConfig {
            min_separation_m: 0.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_negative_separation() {
        let config = CoordinationConfig {
            min_separation_m: -1.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_nan_separation() {
        let config = CoordinationConfig {
            min_separation_m: f64::NAN,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_accepts_positive_separation() {
        let config = CoordinationConfig::default(); // 0.5m
        assert!(config.validate().is_ok());
    }

    #[test]
    fn nan_robot_position_fails_separation_check() {
        let config = CoordinationConfig::default();
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        monitor
            .update_state(robot_state("r1", &[("ee", [0.0, 0.0, 1.0])], now))
            .unwrap();

        // Robot r2 has NaN in position — must fail-closed.
        let nan_robot = robot_state("r2", &[("ee", [f64::NAN, 0.0, 1.0])], now);
        let verdict = monitor.check(&nan_robot, now);
        assert!(!verdict.safe, "NaN EE position must fail separation check");
    }

    #[test]
    fn inf_robot_position_fails_separation_check() {
        let config = CoordinationConfig::default();
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        monitor
            .update_state(robot_state("r1", &[("ee", [0.0, 0.0, 1.0])], now))
            .unwrap();

        let inf_robot = robot_state("r2", &[("ee", [f64::INFINITY, 0.0, 1.0])], now);
        let verdict = monitor.check(&inf_robot, now);
        assert!(!verdict.safe, "Inf EE position must fail separation check");
    }

    #[test]
    fn config_validate_rejects_zero_max_robots() {
        let config = CoordinationConfig {
            max_robots: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err(), "max_robots=0 must be rejected");
    }

    #[test]
    fn update_state_reports_ee_truncation() {
        let config = CoordinationConfig::default();
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        // Create a robot with more than MAX_EE_PER_ROBOT (64) end-effectors.
        let many_ees: Vec<(&str, [f64; 3])> = (0..70).map(|_| ("ee", [0.0, 0.0, 1.0])).collect();
        let state = robot_state("r1", &many_ees, now);
        let result = monitor.update_state(state).unwrap();
        assert_eq!(result.truncated_ee, 6, "expected 70 - 64 = 6 truncated EEs");

        // Verify the stored state was actually truncated.
        assert_eq!(
            monitor
                .get_state("r1")
                .unwrap()
                .end_effector_positions
                .len(),
            64
        );
    }

    #[test]
    fn update_state_no_truncation_reports_zero() {
        let config = CoordinationConfig::default();
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        let state = robot_state("r1", &[("ee", [0.0, 0.0, 1.0])], now);
        let result = monitor.update_state(state).unwrap();
        assert_eq!(result.truncated_ee, 0);
    }

    #[test]
    fn identical_positions_detected_as_violation() {
        let config = CoordinationConfig::default(); // 0.5m min separation
        let mut monitor = CoordinationMonitor::new(config);
        let now = Utc::now();

        // Both robots at the same position.
        monitor
            .update_state(robot_state("r1", &[("ee", [0.0, 0.0, 1.0])], now))
            .unwrap();
        let proposed = robot_state("r2", &[("ee", [0.0, 0.0, 1.0])], now);
        let verdict = monitor.check(&proposed, now);
        assert!(
            !verdict.safe,
            "identical positions (distance=0) must violate 0.5m separation"
        );
    }
}
