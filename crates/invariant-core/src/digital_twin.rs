//! Real-time digital twin divergence detection (Section 18.3, Section 13 "Will Do").
//!
//! Compares **predicted** robot state (from the command/sim) against **observed**
//! state (from signed sensor readings or hardware feedback) in real time.
//! Detects when the physical robot diverges from the model — signaling that
//! simulation-derived safety margins may no longer be valid.
//!
//! Integration points:
//! - `DivergenceDetector` runs per-command in the validation loop
//! - Produces `MonitorResult`-compatible outputs for the incident pipeline
//! - Thresholds calibrated from `invariant transfer` reports
//!
//! # Architecture
//!
//! ```text
//!  Command (predicted joints)     Sensor feedback (observed joints)
//!          │                                  │
//!          ▼                                  ▼
//!    ┌─────────────────────────────────────────────┐
//!    │          DivergenceDetector                  │
//!    │                                             │
//!    │  Per-joint error: |predicted - observed|    │
//!    │  Sliding window statistics (mean, max, p99) │
//!    │  Drift rate: Δerror / Δtime                 │
//!    │  Accumulated divergence score               │
//!    │                                             │
//!    │  → DivergenceSnapshot (per-command)         │
//!    │  → MonitorResult (for incident pipeline)    │
//!    └─────────────────────────────────────────────┘
//! ```
//!
//! # Modes
//!
//! | Divergence Level | Action | Threshold |
//! |-----------------|--------|-----------|
//! | Normal | None | error < alert_threshold |
//! | Elevated | AlertOnly | alert_threshold ≤ error < reject_threshold |
//! | Critical | RejectAll | reject_threshold ≤ error < shutdown_threshold |
//! | Catastrophic | Shutdown | error ≥ shutdown_threshold |

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

use crate::models::command::JointState;
use crate::monitors::{MonitorAction, MonitorResult, MonitorSeverity};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the divergence detector.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::digital_twin::DivergenceConfig;
///
/// // Default configuration based on typical sim-to-real transfer reports.
/// let config = DivergenceConfig::default();
/// assert_eq!(config.window_size, 100);
/// assert!((config.position_alert_threshold - 0.03).abs() < 1e-9);
///
/// // Custom configuration from margin factors.
/// let custom = DivergenceConfig::from_margins(0.01, 0.05, 3.14);
/// assert!(custom.position_alert_threshold > 0.0);
/// assert!(custom.position_reject_threshold > custom.position_alert_threshold);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceConfig {
    /// Sliding window size (number of observations).
    pub window_size: usize,
    /// Position error threshold to emit an alert (radians).
    pub position_alert_threshold: f64,
    /// Position error threshold to reject all commands (radians).
    pub position_reject_threshold: f64,
    /// Position error threshold to trigger shutdown (radians).
    pub position_shutdown_threshold: f64,
    /// Velocity error threshold to emit an alert (rad/s).
    pub velocity_alert_threshold: f64,
    /// Velocity error threshold to reject all commands (rad/s).
    pub velocity_reject_threshold: f64,
    /// Drift rate threshold: if the mean error is growing faster than this
    /// per observation, emit an alert (radians/observation).
    pub drift_rate_alert: f64,
    /// Minimum number of observations before divergence checks activate.
    /// Avoids false positives during startup transients.
    pub warmup_observations: usize,
}

impl Default for DivergenceConfig {
    fn default() -> Self {
        Self {
            window_size: 100,
            // Derived from typical sim-to-real transfer reports (Section 18.4):
            // p99 position error ~0.018 rad, max ~0.031 rad.
            position_alert_threshold: 0.03,
            position_reject_threshold: 0.10,
            position_shutdown_threshold: 0.50,
            // Velocity p99 ~0.42 rad/s.
            velocity_alert_threshold: 0.50,
            velocity_reject_threshold: 1.50,
            // Drift: ~0.001 rad/observation is concerning.
            drift_rate_alert: 0.001,
            warmup_observations: 10,
        }
    }
}

impl DivergenceConfig {
    /// Create a config from a transfer report's recommended margins.
    ///
    /// Sets alert threshold = margin * max_limit, reject = 3× alert,
    /// shutdown = 10× alert.
    pub fn from_margins(position_margin: f64, velocity_margin: f64, max_position: f64) -> Self {
        let pos_alert = position_margin * max_position;
        let vel_alert = velocity_margin * 5.0; // Typical max_velocity
        Self {
            position_alert_threshold: pos_alert,
            position_reject_threshold: pos_alert * 3.0,
            position_shutdown_threshold: pos_alert * 10.0,
            velocity_alert_threshold: vel_alert,
            velocity_reject_threshold: vel_alert * 3.0,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Per-joint error record
// ---------------------------------------------------------------------------

/// Error measurements for a single joint at a single observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointError {
    /// Name of the joint this error record belongs to.
    pub joint_name: String,
    /// Absolute difference between predicted and observed position (rad or m).
    pub position_error: f64,
    /// Absolute difference between predicted and observed velocity (rad/s or m/s).
    pub velocity_error: f64,
    /// Absolute difference between predicted and observed effort (Nm or N).
    pub effort_error: f64,
}

// ---------------------------------------------------------------------------
// Observation record in the sliding window
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Observation {
    #[allow(dead_code)] // Retained for diagnostics and future per-joint alerting.
    joint_errors: Vec<JointError>,
    max_position_error: f64,
    max_velocity_error: f64,
    #[allow(dead_code)] // Retained for future drift-rate alerting.
    mean_position_error: f64,
}

// ---------------------------------------------------------------------------
// Divergence snapshot (per-command output)
// ---------------------------------------------------------------------------

/// A snapshot of divergence metrics at a single point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceSnapshot {
    /// Number of observations in the sliding window.
    pub window_count: usize,
    /// Per-joint errors for the most recent observation.
    pub joint_errors: Vec<JointError>,
    /// Maximum position error across all joints in this observation.
    pub max_position_error: f64,
    /// Maximum velocity error across all joints in this observation.
    pub max_velocity_error: f64,
    /// Mean position error across all joints in this observation.
    pub mean_position_error: f64,
    /// Sliding-window mean of max_position_error.
    pub window_mean_position_error: f64,
    /// Sliding-window max of max_position_error (worst case in window).
    pub window_max_position_error: f64,
    /// Sliding-window mean of max_velocity_error.
    pub window_mean_velocity_error: f64,
    /// Estimated drift rate: change in mean error per observation.
    pub drift_rate: f64,
    /// Whether an alert condition is active.
    pub alert: bool,
    /// The severity level of divergence.
    pub level: DivergenceLevel,
    /// Total observations processed (lifetime, not just window).
    pub total_observations: u64,
}

/// Divergence severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceLevel {
    /// Within expected sim-to-real error bounds.
    Normal,
    /// Elevated: divergence exceeds alert threshold.
    Elevated,
    /// Critical: divergence exceeds reject threshold.
    Critical,
    /// Catastrophic: divergence exceeds shutdown threshold.
    Catastrophic,
}

// ---------------------------------------------------------------------------
// DivergenceDetector
// ---------------------------------------------------------------------------

/// Real-time detector that compares predicted vs observed robot state.
///
/// Feed it pairs of (predicted, observed) joint states on every command
/// cycle. It maintains a sliding window of error statistics and produces
/// [`DivergenceSnapshot`] values for monitoring/logging and
/// `MonitorResult` values for the incident response pipeline.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::digital_twin::{DivergenceDetector, DivergenceLevel};
/// use invariant_robotics_core::models::command::JointState;
///
/// let mut detector = DivergenceDetector::with_defaults();
///
/// let predicted = vec![
///     JointState { name: "shoulder_pan_joint".to_string(), position: 0.0, velocity: 0.0, effort: 0.0 },
/// ];
/// let observed = vec![
///     JointState { name: "shoulder_pan_joint".to_string(), position: 0.001, velocity: 0.0, effort: 0.0 },
/// ];
///
/// // Small error (1 mrad) — within normal bounds.
/// let snapshot = detector.observe(&predicted, &observed);
/// assert_eq!(snapshot.level, DivergenceLevel::Normal);
/// assert!(snapshot.max_position_error < 0.01);
/// ```
pub struct DivergenceDetector {
    config: DivergenceConfig,
    window: VecDeque<Observation>,
    total_observations: u64,
    /// Running sum of mean_position_error for drift rate calculation.
    prev_window_mean: Option<f64>,
}

impl DivergenceDetector {
    /// Create a new detector with the given configuration.
    /// Create a new detector with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if `config.window_size` is 0 (would silently misconfigure the detector).
    pub fn new(config: DivergenceConfig) -> Self {
        assert!(
            config.window_size > 0,
            "DivergenceConfig::window_size must be >= 1"
        );
        Self {
            window: VecDeque::with_capacity(config.window_size),
            config,
            total_observations: 0,
            prev_window_mean: None,
        }
    }

    /// Create a detector with default thresholds.
    pub fn with_defaults() -> Self {
        Self::new(DivergenceConfig::default())
    }

    /// Observe a pair of predicted and actual joint states.
    ///
    /// `predicted` is the joint state from the command (what we expect).
    /// `observed` is the joint state from sensor feedback (what actually happened).
    ///
    /// Both slices must contain the same joints in the same order.
    /// Joints present in `predicted` but missing in `observed` (or vice versa)
    /// are silently skipped (matched by name).
    pub fn observe(
        &mut self,
        predicted: &[JointState],
        observed: &[JointState],
    ) -> DivergenceSnapshot {
        let joint_errors = compute_joint_errors(predicted, observed);

        let max_position_error = joint_errors
            .iter()
            .map(|e| e.position_error)
            .fold(0.0_f64, f64::max);
        let max_velocity_error = joint_errors
            .iter()
            .map(|e| e.velocity_error)
            .fold(0.0_f64, f64::max);
        let mean_position_error = if joint_errors.is_empty() {
            0.0
        } else {
            joint_errors.iter().map(|e| e.position_error).sum::<f64>() / joint_errors.len() as f64
        };

        let obs = Observation {
            joint_errors: joint_errors.clone(),
            max_position_error,
            max_velocity_error,
            mean_position_error,
        };

        // Push into sliding window.
        if self.window.len() >= self.config.window_size {
            self.window.pop_front();
        }
        self.window.push_back(obs);
        self.total_observations += 1;

        // Compute window statistics.
        let window_mean_pos = self
            .window
            .iter()
            .map(|o| o.max_position_error)
            .sum::<f64>()
            / self.window.len() as f64;
        let window_max_pos = self
            .window
            .iter()
            .map(|o| o.max_position_error)
            .fold(0.0_f64, f64::max);
        let window_mean_vel = self
            .window
            .iter()
            .map(|o| o.max_velocity_error)
            .sum::<f64>()
            / self.window.len() as f64;

        // Drift rate: how fast the mean error is changing.
        let drift_rate = if let Some(prev) = self.prev_window_mean {
            window_mean_pos - prev
        } else {
            0.0
        };
        self.prev_window_mean = Some(window_mean_pos);

        // Determine severity level.
        let in_warmup = self.total_observations < self.config.warmup_observations as u64;
        let level = if in_warmup {
            DivergenceLevel::Normal
        } else {
            classify_level(
                max_position_error,
                max_velocity_error,
                window_max_pos,
                &self.config,
            )
        };
        let alert = level != DivergenceLevel::Normal;

        DivergenceSnapshot {
            window_count: self.window.len(),
            joint_errors,
            max_position_error,
            max_velocity_error,
            mean_position_error,
            window_mean_position_error: window_mean_pos,
            window_max_position_error: window_max_pos,
            window_mean_velocity_error: window_mean_vel,
            drift_rate,
            alert,
            level,
            total_observations: self.total_observations,
        }
    }

    /// Convert the most recent snapshot into a `MonitorResult` for the
    /// incident response pipeline.
    pub fn to_monitor_result(&self, snapshot: &DivergenceSnapshot) -> MonitorResult {
        match snapshot.level {
            DivergenceLevel::Normal => MonitorResult {
                monitor: "digital_twin_divergence",
                severity: MonitorSeverity::Ok,
                action: MonitorAction::None,
                detail: format!(
                    "max_pos_err={:.4} max_vel_err={:.4} drift={:.6}",
                    snapshot.max_position_error,
                    snapshot.max_velocity_error,
                    snapshot.drift_rate,
                ),
            },
            DivergenceLevel::Elevated => MonitorResult {
                monitor: "digital_twin_divergence",
                severity: MonitorSeverity::Warning,
                action: MonitorAction::AlertOnly,
                detail: format!(
                    "elevated divergence: max_pos_err={:.4} (threshold={:.4}), drift={:.6}",
                    snapshot.max_position_error,
                    self.config.position_alert_threshold,
                    snapshot.drift_rate,
                ),
            },
            DivergenceLevel::Critical => MonitorResult {
                monitor: "digital_twin_divergence",
                severity: MonitorSeverity::Critical,
                action: MonitorAction::RejectAll,
                detail: format!(
                    "critical divergence: max_pos_err={:.4} (threshold={:.4})",
                    snapshot.window_max_position_error, self.config.position_reject_threshold,
                ),
            },
            DivergenceLevel::Catastrophic => MonitorResult {
                monitor: "digital_twin_divergence",
                severity: MonitorSeverity::Critical,
                action: MonitorAction::Shutdown,
                detail: format!(
                    "catastrophic divergence: max_pos_err={:.4} (threshold={:.4}) — possible mechanical failure",
                    snapshot.max_position_error, self.config.position_shutdown_threshold,
                ),
            },
        }
    }

    /// Reset the detector (e.g. after an operator clears an incident).
    pub fn reset(&mut self) {
        self.window.clear();
        self.total_observations = 0;
        self.prev_window_mean = None;
    }

    /// Current configuration.
    pub fn config(&self) -> &DivergenceConfig {
        &self.config
    }

    /// Number of observations processed (lifetime).
    pub fn total_observations(&self) -> u64 {
        self.total_observations
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn compute_joint_errors(predicted: &[JointState], observed: &[JointState]) -> Vec<JointError> {
    let mut errors = Vec::with_capacity(predicted.len());
    for pred in predicted {
        if let Some(obs) = observed.iter().find(|o| o.name == pred.name) {
            let position_error = (pred.position - obs.position).abs();
            let velocity_error = (pred.velocity - obs.velocity).abs();
            let effort_error = (pred.effort - obs.effort).abs();

            // Fail-closed: if any error is NaN/Inf (from non-finite sensor data),
            // treat it as the maximum possible error to ensure the divergence
            // detector escalates rather than silently classifying as Normal.
            errors.push(JointError {
                joint_name: pred.name.clone(),
                position_error: if position_error.is_finite() {
                    position_error
                } else {
                    f64::MAX
                },
                velocity_error: if velocity_error.is_finite() {
                    velocity_error
                } else {
                    f64::MAX
                },
                effort_error: if effort_error.is_finite() {
                    effort_error
                } else {
                    f64::MAX
                },
            });
        }
    }
    errors
}

fn classify_level(
    instant_pos_error: f64,
    instant_vel_error: f64,
    window_max_pos: f64,
    config: &DivergenceConfig,
) -> DivergenceLevel {
    // Catastrophic: instant position error exceeds shutdown threshold.
    if instant_pos_error >= config.position_shutdown_threshold {
        return DivergenceLevel::Catastrophic;
    }
    // Critical: window max exceeds reject threshold, or instant exceeds reject.
    if window_max_pos >= config.position_reject_threshold
        || instant_pos_error >= config.position_reject_threshold
        || instant_vel_error >= config.velocity_reject_threshold
    {
        return DivergenceLevel::Critical;
    }
    // Elevated: instant or window exceeds alert threshold.
    if instant_pos_error >= config.position_alert_threshold
        || instant_vel_error >= config.velocity_alert_threshold
    {
        return DivergenceLevel::Elevated;
    }
    DivergenceLevel::Normal
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn joint(name: &str, pos: f64, vel: f64, effort: f64) -> JointState {
        JointState {
            name: name.into(),
            position: pos,
            velocity: vel,
            effort,
        }
    }

    fn predicted_observed_pair(
        pos_offset: f64,
        vel_offset: f64,
    ) -> (Vec<JointState>, Vec<JointState>) {
        let predicted = vec![joint("j1", 1.0, 2.0, 10.0), joint("j2", -0.5, 1.0, 5.0)];
        let observed = vec![
            joint("j1", 1.0 + pos_offset, 2.0 + vel_offset, 10.0),
            joint("j2", -0.5 + pos_offset, 1.0 + vel_offset, 5.0),
        ];
        (predicted, observed)
    }

    // -- Config tests ---------------------------------------------------------

    #[test]
    fn default_config_has_sane_values() {
        let cfg = DivergenceConfig::default();
        assert!(cfg.position_alert_threshold > 0.0);
        assert!(cfg.position_reject_threshold > cfg.position_alert_threshold);
        assert!(cfg.position_shutdown_threshold > cfg.position_reject_threshold);
        assert!(cfg.window_size > 0);
        assert!(cfg.warmup_observations > 0);
    }

    #[test]
    fn config_from_margins() {
        let cfg = DivergenceConfig::from_margins(0.05, 0.15, std::f64::consts::TAU);
        assert!((cfg.position_alert_threshold - 0.314).abs() < 0.001);
        assert!(cfg.position_reject_threshold > cfg.position_alert_threshold);
    }

    // -- Joint error computation ----------------------------------------------

    #[test]
    fn compute_errors_identical_states() {
        let joints = vec![joint("j1", 1.0, 2.0, 10.0)];
        let errors = compute_joint_errors(&joints, &joints);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].position_error, 0.0);
        assert_eq!(errors[0].velocity_error, 0.0);
    }

    #[test]
    fn compute_errors_with_offset() {
        let pred = vec![joint("j1", 1.0, 2.0, 10.0)];
        let obs = vec![joint("j1", 1.05, 2.3, 10.0)];
        let errors = compute_joint_errors(&pred, &obs);
        assert!((errors[0].position_error - 0.05).abs() < 1e-9);
        assert!((errors[0].velocity_error - 0.3).abs() < 1e-9);
    }

    #[test]
    fn compute_errors_mismatched_names_skipped() {
        let pred = vec![joint("j1", 1.0, 0.0, 0.0), joint("j3", 0.0, 0.0, 0.0)];
        let obs = vec![joint("j1", 1.0, 0.0, 0.0), joint("j2", 0.0, 0.0, 0.0)];
        let errors = compute_joint_errors(&pred, &obs);
        // Only j1 matched.
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].joint_name, "j1");
    }

    #[test]
    fn compute_errors_empty_inputs() {
        let errors = compute_joint_errors(&[], &[]);
        assert!(errors.is_empty());
    }

    // -- DivergenceDetector basic tests ---------------------------------------

    #[test]
    fn detector_starts_empty() {
        let det = DivergenceDetector::with_defaults();
        assert_eq!(det.total_observations(), 0);
    }

    #[test]
    fn observe_zero_divergence_is_normal() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            ..Default::default()
        });
        let joints = vec![joint("j1", 1.0, 2.0, 10.0)];
        let snap = det.observe(&joints, &joints);
        assert_eq!(snap.level, DivergenceLevel::Normal);
        assert!(!snap.alert);
        assert_eq!(snap.max_position_error, 0.0);
        assert_eq!(snap.total_observations, 1);
    }

    #[test]
    fn observe_small_error_is_normal() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.01, 0.1);
        let snap = det.observe(&pred, &obs);
        assert_eq!(snap.level, DivergenceLevel::Normal);
        assert!(!snap.alert);
    }

    #[test]
    fn observe_elevated_divergence() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            position_alert_threshold: 0.02,
            position_reject_threshold: 0.10,
            position_shutdown_threshold: 0.50,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.05, 0.0);
        let snap = det.observe(&pred, &obs);
        assert_eq!(snap.level, DivergenceLevel::Elevated);
        assert!(snap.alert);
    }

    #[test]
    fn observe_critical_divergence() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            position_alert_threshold: 0.02,
            position_reject_threshold: 0.10,
            position_shutdown_threshold: 0.50,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.15, 0.0);
        let snap = det.observe(&pred, &obs);
        assert_eq!(snap.level, DivergenceLevel::Critical);
    }

    #[test]
    fn observe_catastrophic_divergence() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            position_shutdown_threshold: 0.50,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.60, 0.0);
        let snap = det.observe(&pred, &obs);
        assert_eq!(snap.level, DivergenceLevel::Catastrophic);
    }

    #[test]
    fn velocity_alert_threshold() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            velocity_alert_threshold: 0.3,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.0, 0.5);
        let snap = det.observe(&pred, &obs);
        assert_eq!(snap.level, DivergenceLevel::Elevated);
    }

    #[test]
    fn velocity_reject_threshold() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            velocity_reject_threshold: 1.0,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.0, 1.5);
        let snap = det.observe(&pred, &obs);
        assert_eq!(snap.level, DivergenceLevel::Critical);
    }

    // -- Warmup suppression ---------------------------------------------------

    #[test]
    fn warmup_suppresses_alerts() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 5,
            position_alert_threshold: 0.01,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.05, 0.0);

        // During warmup, even large errors report Normal.
        for i in 0..4 {
            let snap = det.observe(&pred, &obs);
            assert_eq!(snap.level, DivergenceLevel::Normal, "warmup obs {i}");
        }
        // After warmup, should detect elevated.
        let snap = det.observe(&pred, &obs);
        assert_eq!(snap.level, DivergenceLevel::Elevated);
    }

    // -- Sliding window -------------------------------------------------------

    #[test]
    fn window_respects_size_limit() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            window_size: 5,
            warmup_observations: 0,
            ..Default::default()
        });
        let joints = vec![joint("j1", 1.0, 0.0, 0.0)];
        for _ in 0..20 {
            det.observe(&joints, &joints);
        }
        assert_eq!(det.window.len(), 5);
        assert_eq!(det.total_observations(), 20);
    }

    #[test]
    fn window_statistics_update() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            window_size: 10,
            warmup_observations: 0,
            ..Default::default()
        });
        // First 5 observations: zero error.
        let joints = vec![joint("j1", 1.0, 0.0, 0.0)];
        for _ in 0..5 {
            det.observe(&joints, &joints);
        }
        // Next 5: 0.02 position error.
        let pred = vec![joint("j1", 1.0, 0.0, 0.0)];
        let obs = vec![joint("j1", 1.02, 0.0, 0.0)];
        let mut last_snap = det.observe(&pred, &obs);
        for _ in 0..4 {
            last_snap = det.observe(&pred, &obs);
        }
        // Window has 5×0.0 + 5×0.02 → mean ≈ 0.01.
        assert!(last_snap.window_mean_position_error > 0.005);
        assert!(last_snap.window_mean_position_error < 0.025);
        assert!((last_snap.window_max_position_error - 0.02).abs() < 1e-9);
    }

    // -- Drift rate -----------------------------------------------------------

    #[test]
    fn drift_rate_positive_when_error_growing() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            window_size: 50,
            warmup_observations: 0,
            ..Default::default()
        });
        let mut last_snap = None;
        for i in 0..20 {
            let offset = i as f64 * 0.001;
            let pred = vec![joint("j1", 1.0, 0.0, 0.0)];
            let obs = vec![joint("j1", 1.0 + offset, 0.0, 0.0)];
            last_snap = Some(det.observe(&pred, &obs));
        }
        let snap = last_snap.unwrap();
        // Drift rate should be positive since error is growing.
        assert!(snap.drift_rate > 0.0, "drift_rate={}", snap.drift_rate);
    }

    #[test]
    fn drift_rate_near_zero_for_constant_error() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            window_size: 50,
            warmup_observations: 0,
            ..Default::default()
        });
        let pred = vec![joint("j1", 1.0, 0.0, 0.0)];
        let obs = vec![joint("j1", 1.01, 0.0, 0.0)];
        let mut last_snap = None;
        for _ in 0..20 {
            last_snap = Some(det.observe(&pred, &obs));
        }
        let snap = last_snap.unwrap();
        // Constant error → drift ≈ 0.
        assert!(
            snap.drift_rate.abs() < 1e-9,
            "drift_rate={}",
            snap.drift_rate
        );
    }

    // -- MonitorResult integration -------------------------------------------

    #[test]
    fn monitor_result_normal() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            ..Default::default()
        });
        let joints = vec![joint("j1", 1.0, 0.0, 0.0)];
        let snap = det.observe(&joints, &joints);
        let result = det.to_monitor_result(&snap);
        assert!(result.is_ok());
        assert_eq!(result.action, MonitorAction::None);
    }

    #[test]
    fn monitor_result_elevated() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            position_alert_threshold: 0.01,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.05, 0.0);
        let snap = det.observe(&pred, &obs);
        let result = det.to_monitor_result(&snap);
        assert_eq!(result.severity, MonitorSeverity::Warning);
        assert_eq!(result.action, MonitorAction::AlertOnly);
        assert_eq!(result.monitor, "digital_twin_divergence");
    }

    #[test]
    fn monitor_result_critical() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            position_alert_threshold: 0.01,
            position_reject_threshold: 0.05,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.08, 0.0);
        let snap = det.observe(&pred, &obs);
        let result = det.to_monitor_result(&snap);
        assert_eq!(result.severity, MonitorSeverity::Critical);
        assert_eq!(result.action, MonitorAction::RejectAll);
    }

    #[test]
    fn monitor_result_catastrophic() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            position_shutdown_threshold: 0.30,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.40, 0.0);
        let snap = det.observe(&pred, &obs);
        let result = det.to_monitor_result(&snap);
        assert_eq!(result.severity, MonitorSeverity::Critical);
        assert_eq!(result.action, MonitorAction::Shutdown);
        assert!(result.detail.contains("catastrophic"));
    }

    // -- Reset ----------------------------------------------------------------

    #[test]
    fn reset_clears_state() {
        let mut det = DivergenceDetector::with_defaults();
        let joints = vec![joint("j1", 1.0, 0.0, 0.0)];
        for _ in 0..10 {
            det.observe(&joints, &joints);
        }
        assert_eq!(det.total_observations(), 10);

        det.reset();
        assert_eq!(det.total_observations(), 0);
        assert!(det.window.is_empty());
    }

    // -- Snapshot serde -------------------------------------------------------

    #[test]
    fn snapshot_serde_round_trip() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            ..Default::default()
        });
        let (pred, obs) = predicted_observed_pair(0.01, 0.05);
        let snap = det.observe(&pred, &obs);
        let json = serde_json::to_string(&snap).unwrap();
        let deserialized: DivergenceSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_observations, snap.total_observations);
        assert_eq!(deserialized.level, snap.level);
        assert_eq!(deserialized.joint_errors.len(), snap.joint_errors.len());
    }

    // -- Config serde ---------------------------------------------------------

    #[test]
    fn config_serde_round_trip() {
        let cfg = DivergenceConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let deserialized: DivergenceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.position_alert_threshold,
            cfg.position_alert_threshold
        );
        assert_eq!(deserialized.window_size, cfg.window_size);
    }

    // -- Multi-joint divergence -----------------------------------------------

    #[test]
    fn multi_joint_worst_case_reported() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            warmup_observations: 0,
            ..Default::default()
        });
        let pred = vec![
            joint("j1", 1.0, 0.0, 0.0),
            joint("j2", 2.0, 0.0, 0.0),
            joint("j3", 0.0, 0.0, 0.0),
        ];
        let obs = vec![
            joint("j1", 1.001, 0.0, 0.0), // 0.001
            joint("j2", 2.05, 0.0, 0.0),  // 0.05 — worst
            joint("j3", 0.01, 0.0, 0.0),  // 0.01
        ];
        let snap = det.observe(&pred, &obs);
        assert!((snap.max_position_error - 0.05).abs() < 1e-9);
        assert_eq!(snap.joint_errors.len(), 3);
    }

    // -- Window eviction pushes out old large errors --------------------------

    #[test]
    fn old_errors_evicted_from_window() {
        let mut det = DivergenceDetector::new(DivergenceConfig {
            window_size: 3,
            warmup_observations: 0,
            position_alert_threshold: 0.02,
            position_reject_threshold: 0.10,
            position_shutdown_threshold: 0.50,
            ..Default::default()
        });
        // Observation 1: large error.
        let pred = vec![joint("j1", 1.0, 0.0, 0.0)];
        let obs_big = vec![joint("j1", 1.05, 0.0, 0.0)];
        det.observe(&pred, &obs_big);

        // Observations 2-4: zero error (push the big one out).
        let obs_zero = vec![joint("j1", 1.0, 0.0, 0.0)];
        det.observe(&pred, &obs_zero);
        det.observe(&pred, &obs_zero);
        let snap = det.observe(&pred, &obs_zero);

        // Window now has 3 zero-error observations; the big one was evicted.
        assert_eq!(snap.window_count, 3);
        assert!(snap.window_max_position_error < 1e-9);
    }

    // ── NaN fail-closed tests ──────────────────────────────

    #[test]
    fn observe_nan_position_does_not_classify_as_normal() {
        // NaN in observed position must escalate to Catastrophic, not Normal.
        let config = DivergenceConfig {
            warmup_observations: 0, // no warmup
            ..DivergenceConfig::default()
        };
        let mut det = DivergenceDetector::new(config);
        let pred = vec![joint("j1", 0.0, 0.0, 0.0)];
        let obs = vec![joint("j1", f64::NAN, 0.0, 0.0)];
        let snap = det.observe(&pred, &obs);
        assert_ne!(
            snap.level,
            DivergenceLevel::Normal,
            "NaN position error must not classify as Normal"
        );
        // f64::MAX triggers Catastrophic (exceeds all thresholds).
        assert_eq!(snap.level, DivergenceLevel::Catastrophic);
    }

    #[test]
    fn observe_inf_velocity_does_not_classify_as_normal() {
        let config = DivergenceConfig {
            warmup_observations: 0,
            ..DivergenceConfig::default()
        };
        let mut det = DivergenceDetector::new(config);
        let pred = vec![joint("j1", 0.0, 0.0, 0.0)];
        let obs = vec![joint("j1", 0.0, f64::INFINITY, 0.0)];
        let snap = det.observe(&pred, &obs);
        assert_ne!(
            snap.level,
            DivergenceLevel::Normal,
            "Inf velocity error must not classify as Normal"
        );
    }

    #[test]
    fn nan_error_does_not_poison_subsequent_observations() {
        // After a NaN observation, subsequent clean observations should still
        // classify correctly (the NaN was converted to f64::MAX, not propagated).
        let config = DivergenceConfig {
            window_size: 2,
            warmup_observations: 0,
            ..DivergenceConfig::default()
        };
        let mut det = DivergenceDetector::new(config);
        let pred = vec![joint("j1", 0.0, 0.0, 0.0)];

        // First: NaN observation → Catastrophic.
        let obs_nan = vec![joint("j1", f64::NAN, 0.0, 0.0)];
        let snap = det.observe(&pred, &obs_nan);
        assert_eq!(snap.level, DivergenceLevel::Catastrophic);

        // Second: clean observation. Window still has the f64::MAX one.
        let obs_clean = vec![joint("j1", 0.0, 0.0, 0.0)];
        let snap2 = det.observe(&pred, &obs_clean);
        // The max_position_error for this observation is 0.0, but window still
        // contains the MAX entry, so window_max is still huge.
        assert!(snap2.max_position_error < 1e-9, "this observation is clean");

        // Third: push the MAX entry out of the window.
        let snap3 = det.observe(&pred, &obs_clean);
        // Now the window only has clean observations.
        assert!(snap3.window_max_position_error < 1e-9);
        assert_eq!(snap3.level, DivergenceLevel::Normal);
    }

    // ── window_size=0 validation ───────────────────────────

    #[test]
    #[should_panic(expected = "window_size must be >= 1")]
    fn detector_rejects_window_size_zero() {
        let config = DivergenceConfig {
            window_size: 0,
            ..DivergenceConfig::default()
        };
        let _det = DivergenceDetector::new(config);
    }
}
