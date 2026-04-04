// Runtime threat scoring engine (Section 11.3, Step 68).
//
// Implements the 5 behavioral detectors from the spec:
// 1. Boundary clustering  — commands near rejection thresholds
// 2. Authority probing    — repeated authority rejection patterns
// 3. Replay fingerprinting — similarity to previously-rejected commands
// 4. Drift detection      — gradual shift in command patterns
// 5. Anomaly scoring      — statistically unusual commands
//
// The `ThreatScorer` maintains a sliding window of recent commands and
// produces a `ThreatAnalysis` (already defined in the verdict schema)
// for each command evaluated.
//
// Design:
// - Stateful: tracks a window of recent commands for statistical analysis.
// - Deterministic given the same command sequence.
// - No I/O, no allocation beyond the fixed-size window.
// - Configurable alert threshold and window size.

use std::collections::{HashMap, VecDeque};

use crate::models::command::{Command, JointState};
use crate::models::profile::RobotProfile;
use crate::models::verdict::ThreatAnalysis;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the threat scoring engine.
#[derive(Debug, Clone)]
pub struct ThreatScorerConfig {
    /// Maximum number of recent commands to retain for analysis.
    pub window_size: usize,
    /// Composite threat score above which `alert` is set to `true`.
    pub alert_threshold: f64,
    /// Weights for combining individual scores into the composite.
    pub weights: ThreatWeights,
    /// Fraction of a joint's range that counts as "near boundary" (0.0-1.0).
    /// E.g., 0.05 means the outer 5% of each limit is the boundary band.
    pub boundary_band_fraction: f64,
}

/// Weights for combining individual threat scores.
#[derive(Debug, Clone)]
pub struct ThreatWeights {
    pub boundary_clustering: f64,
    pub authority_probing: f64,
    pub replay_similarity: f64,
    pub drift: f64,
    pub anomaly: f64,
}

impl Default for ThreatScorerConfig {
    fn default() -> Self {
        Self {
            window_size: 100,
            alert_threshold: 0.7,
            weights: ThreatWeights {
                boundary_clustering: 0.2,
                authority_probing: 0.25,
                replay_similarity: 0.2,
                drift: 0.2,
                anomaly: 0.15,
            },
            boundary_band_fraction: 0.05,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// A compact fingerprint of a command for replay detection.
#[derive(Debug, Clone)]
struct CommandFingerprint {
    /// Normalized joint positions (0.0-1.0 within joint range).
    positions: Vec<f64>,
    /// Whether this command was rejected.
    rejected: bool,
}

/// Running statistics for drift detection.
#[derive(Debug, Clone)]
struct DriftTracker {
    /// Per-joint running mean of positions.
    means: HashMap<String, f64>,
    /// Number of samples contributing to means.
    count: u64,
}

impl DriftTracker {
    fn new() -> Self {
        Self {
            means: HashMap::new(),
            count: 0,
        }
    }

    /// Update running means with new joint states. Returns the maximum
    /// absolute shift from the previous mean (0.0 if first sample).
    fn update(&mut self, joints: &[JointState]) -> f64 {
        self.count += 1;
        let mut max_shift = 0.0f64;

        for js in joints {
            let old_mean = self.means.get(&js.name).copied().unwrap_or(js.position);
            // Incremental mean: mean_new = mean_old + (x - mean_old) / n
            let new_mean = old_mean + (js.position - old_mean) / self.count as f64;
            let shift = (new_mean - old_mean).abs();
            if shift > max_shift {
                max_shift = shift;
            }
            self.means.insert(js.name.clone(), new_mean);
        }

        max_shift
    }
}

// ---------------------------------------------------------------------------
// Scorer
// ---------------------------------------------------------------------------

/// Runtime threat scoring engine.
///
/// Feed commands via `score()` and receive `ThreatAnalysis` values to
/// attach to verdicts. The scorer is stateful — it tracks a sliding
/// window of recent commands.
pub struct ThreatScorer {
    config: ThreatScorerConfig,
    /// Recent command fingerprints (newest at back).
    window: VecDeque<CommandFingerprint>,
    /// Rejected command fingerprints for replay detection.
    rejected_window: VecDeque<Vec<f64>>,
    /// Authority rejection counts per principal.
    authority_rejections: HashMap<String, u32>,
    /// Total authority checks.
    authority_checks: u32,
    /// Drift tracker for gradual position shifts.
    drift: DriftTracker,
}

impl ThreatScorer {
    /// Create a new scorer with the given configuration.
    pub fn new(config: ThreatScorerConfig) -> Self {
        let window_size = config.window_size;
        Self {
            config,
            window: VecDeque::with_capacity(window_size),
            rejected_window: VecDeque::with_capacity(window_size),
            authority_rejections: HashMap::new(),
            authority_checks: 0,
            drift: DriftTracker::new(),
        }
    }

    /// Create a scorer with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ThreatScorerConfig::default())
    }

    /// Score a command and return a `ThreatAnalysis`.
    ///
    /// `command` is the incoming command being validated.
    /// `profile` is the robot profile (needed for boundary analysis).
    /// `authority_passed` is whether the authority check passed.
    /// `principal` is the origin principal from the PCA chain (empty if auth failed).
    /// `approved` is whether the overall verdict is approved.
    pub fn score(
        &mut self,
        command: &Command,
        profile: &RobotProfile,
        authority_passed: bool,
        principal: &str,
        approved: bool,
    ) -> ThreatAnalysis {
        // 1. Boundary clustering
        let boundary_score = self.score_boundary_clustering(command, profile);

        // 2. Authority probing
        let authority_score = self.score_authority_probing(authority_passed, principal);

        // 3. Replay fingerprinting
        let normalized = normalize_positions(&command.joint_states, profile);
        let replay_score = self.score_replay_similarity(&normalized);

        // 4. Drift detection
        let drift_score = self.score_drift(command);

        // 5. Anomaly scoring
        let anomaly_score = self.score_anomaly(&normalized);

        // Record this command in the window.
        let fp = CommandFingerprint {
            positions: normalized.clone(),
            rejected: !approved,
        };
        self.window.push_back(fp);
        if self.window.len() > self.config.window_size {
            self.window.pop_front();
        }

        // Record rejected commands for replay detection.
        if !approved {
            self.rejected_window.push_back(normalized);
            if self.rejected_window.len() > self.config.window_size {
                self.rejected_window.pop_front();
            }
        }

        // Composite score.
        let w = &self.config.weights;
        let composite = boundary_score * w.boundary_clustering
            + authority_score * w.authority_probing
            + replay_score * w.replay_similarity
            + drift_score * w.drift
            + anomaly_score * w.anomaly;
        let composite = composite.clamp(0.0, 1.0);

        ThreatAnalysis {
            boundary_clustering_score: boundary_score,
            authority_probing_score: authority_score,
            replay_similarity_score: replay_score,
            drift_score,
            anomaly_score,
            composite_threat_score: composite,
            alert: composite > self.config.alert_threshold,
        }
    }

    // -- Detector 1: Boundary clustering ----------------------------------

    fn score_boundary_clustering(&self, command: &Command, profile: &RobotProfile) -> f64 {
        if command.joint_states.is_empty() || profile.joints.is_empty() {
            return 0.0;
        }

        let band = self.config.boundary_band_fraction;
        let mut near_boundary_count = 0u32;
        let mut total = 0u32;

        for js in &command.joint_states {
            if let Some(jd) = profile.joints.iter().find(|j| j.name == js.name) {
                let range = jd.max - jd.min;
                if range <= 0.0 {
                    continue;
                }
                total += 1;
                let band_size = range * band;
                let dist_to_min = (js.position - jd.min).abs();
                let dist_to_max = (js.position - jd.max).abs();
                if dist_to_min < band_size || dist_to_max < band_size {
                    near_boundary_count += 1;
                }
            }
        }

        if total == 0 {
            return 0.0;
        }

        // Score = fraction of joints near boundary, boosted by historical clustering.
        let current_fraction = near_boundary_count as f64 / total as f64;

        // Check history: how many recent commands were also near boundary?
        let recent_boundary_count = self
            .window
            .iter()
            .rev()
            .take(20)
            .filter(|fp| fp.positions.iter().any(|p| *p < band || *p > (1.0 - band)))
            .count();
        let historical_factor = if self.window.is_empty() {
            0.0
        } else {
            recent_boundary_count as f64 / self.window.len().min(20) as f64
        };

        ((current_fraction + historical_factor) / 2.0).clamp(0.0, 1.0)
    }

    // -- Detector 2: Authority probing ------------------------------------

    fn score_authority_probing(&mut self, authority_passed: bool, principal: &str) -> f64 {
        self.authority_checks += 1;

        if !authority_passed && !principal.is_empty() {
            *self
                .authority_rejections
                .entry(principal.to_string())
                .or_insert(0) += 1;
        }

        if self.authority_checks < 5 {
            return 0.0; // not enough data
        }

        // Score = max rejection rate across all principals.
        let max_rejection_rate = self
            .authority_rejections
            .values()
            .map(|&count| count as f64 / self.authority_checks as f64)
            .fold(0.0f64, f64::max);

        // Scale: 0.0 at 0% rejection, 1.0 at 50%+ rejection rate.
        (max_rejection_rate * 2.0).clamp(0.0, 1.0)
    }

    // -- Detector 3: Replay fingerprinting --------------------------------

    fn score_replay_similarity(&self, current_normalized: &[f64]) -> f64 {
        if self.rejected_window.is_empty() || current_normalized.is_empty() {
            return 0.0;
        }

        // Find the closest rejected command by Euclidean distance.
        let mut min_distance = f64::MAX;
        for rejected in &self.rejected_window {
            let dist = euclidean_distance(current_normalized, rejected);
            if dist < min_distance {
                min_distance = dist;
            }
        }

        // Score: small distance to a rejected command = suspicious.
        // Distance is in normalized [0,1] space, so max per-dim distance is 1.0.
        // Map distance [0, 0.1] to score [1.0, 0.0].
        (1.0 - min_distance / 0.1).clamp(0.0, 1.0)
    }

    // -- Detector 4: Drift detection --------------------------------------

    fn score_drift(&mut self, command: &Command) -> f64 {
        let max_shift = self.drift.update(&command.joint_states);

        // Normalize: a shift of 0.01 rad in the running mean is notable.
        // Scale: 0.0 at 0 shift, 1.0 at 0.05+ rad shift.
        (max_shift / 0.05).clamp(0.0, 1.0)
    }

    // -- Detector 5: Anomaly scoring --------------------------------------

    fn score_anomaly(&self, current_normalized: &[f64]) -> f64 {
        if self.window.len() < 10 || current_normalized.is_empty() {
            return 0.0;
        }

        // Compute mean and variance of each position dimension from history.
        let dim = current_normalized.len();
        let mut means = vec![0.0f64; dim];
        let mut vars = vec![0.0f64; dim];
        let n = self.window.len() as f64;

        for fp in &self.window {
            for (i, &p) in fp.positions.iter().enumerate().take(dim) {
                means[i] += p;
            }
        }
        for m in &mut means {
            *m /= n;
        }
        for fp in &self.window {
            for (i, &p) in fp.positions.iter().enumerate().take(dim) {
                let d = p - means[i];
                vars[i] += d * d;
            }
        }
        for v in &mut vars {
            *v /= n;
        }

        // Mahalanobis-like distance (independent dimensions).
        // For zero-variance dimensions (constant history), use absolute
        // deviation from mean — any deviation is anomalous.
        let mut z_scores_sum = 0.0f64;
        let mut counted = 0u32;
        for (i, &p) in current_normalized.iter().enumerate().take(dim) {
            let std_dev = vars[i].sqrt();
            let z = if std_dev > 1e-9 {
                ((p - means[i]) / std_dev).abs()
            } else {
                // Zero variance: any deviation from the constant value is
                // maximally anomalous. Scale the absolute difference by a
                // large factor so even small deviations produce high z.
                let diff = (p - means[i]).abs();
                if diff > 1e-9 {
                    10.0
                } else {
                    0.0
                }
            };
            z_scores_sum += z;
            counted += 1;
        }

        if counted == 0 {
            return 0.0;
        }

        let avg_z = z_scores_sum / counted as f64;
        // Map: z=2 → 0.33, z=4 → 1.0
        ((avg_z - 1.0) / 3.0).clamp(0.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Normalize joint positions to [0.0, 1.0] relative to profile limits.
fn normalize_positions(joints: &[JointState], profile: &RobotProfile) -> Vec<f64> {
    joints
        .iter()
        .filter_map(|js| {
            profile.joints.iter().find(|j| j.name == js.name).map(|jd| {
                let range = jd.max - jd.min;
                if range <= 0.0 {
                    0.5
                } else {
                    ((js.position - jd.min) / range).clamp(0.0, 1.0)
                }
            })
        })
        .collect()
}

/// Euclidean distance between two vectors in normalized space.
fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    let len = a.len().min(b.len());
    let mut sum = 0.0f64;
    for i in 0..len {
        let d = a[i] - b[i];
        sum += d * d;
    }
    sum.sqrt()
}

/// Cosine similarity between two vectors. Returns 0.0 for empty/zero vectors.
fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 0.0;
    }

    let mut dot = 0.0f64;
    let mut mag_a = 0.0f64;
    let mut mag_b = 0.0f64;

    for i in 0..len {
        dot += a[i] * b[i];
        mag_a += a[i] * a[i];
        mag_b += b[i] * b[i];
    }

    let denom = mag_a.sqrt() * mag_b.sqrt();
    if denom < 1e-12 {
        0.0
    } else {
        (dot / denom).clamp(-1.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::command::*;
    use crate::models::profile::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn test_profile() -> RobotProfile {
        RobotProfile {
            name: "test".into(),
            version: "1.0".into(),
            joints: vec![
                JointDefinition {
                    name: "j1".into(),
                    joint_type: JointType::Revolute,
                    min: -3.14,
                    max: 3.14,
                    max_velocity: 5.0,
                    max_torque: 100.0,
                    max_acceleration: 50.0,
                },
                JointDefinition {
                    name: "j2".into(),
                    joint_type: JointType::Revolute,
                    min: -1.57,
                    max: 1.57,
                    max_velocity: 5.0,
                    max_torque: 100.0,
                    max_acceleration: 50.0,
                },
            ],
            workspace: WorkspaceBounds::Aabb {
                min: [-2.0, -2.0, 0.0],
                max: [2.0, 2.0, 3.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            max_delta_time: 0.1,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None,
            end_effectors: vec![],
        }
    }

    fn make_command(j1_pos: f64, j2_pos: f64) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![
                JointState {
                    name: "j1".into(),
                    position: j1_pos,
                    velocity: 0.0,
                    effort: 0.0,
                },
                JointState {
                    name: "j2".into(),
                    position: j2_pos,
                    velocity: 0.0,
                    effort: 0.0,
                },
            ],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        }
    }

    #[test]
    fn default_scorer_produces_zero_scores_initially() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();
        let cmd = make_command(0.0, 0.0);

        let analysis = scorer.score(&cmd, &profile, true, "alice", true);

        assert_eq!(analysis.boundary_clustering_score, 0.0);
        assert_eq!(analysis.authority_probing_score, 0.0);
        assert_eq!(analysis.replay_similarity_score, 0.0);
        assert!(!analysis.alert);
    }

    #[test]
    fn boundary_clustering_detects_near_limit_commands() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        // Feed commands near j1 max limit (3.14)
        for _ in 0..20 {
            let cmd = make_command(3.10, 0.0); // within 5% band of max
            scorer.score(&cmd, &profile, true, "alice", true);
        }

        let cmd = make_command(3.12, 0.0);
        let analysis = scorer.score(&cmd, &profile, true, "alice", true);

        assert!(
            analysis.boundary_clustering_score > 0.3,
            "boundary score {} should be elevated for consistently near-limit commands",
            analysis.boundary_clustering_score
        );
    }

    #[test]
    fn boundary_clustering_low_for_centered_commands() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        for _ in 0..20 {
            let cmd = make_command(0.0, 0.0); // dead center
            scorer.score(&cmd, &profile, true, "alice", true);
        }

        let cmd = make_command(0.0, 0.0);
        let analysis = scorer.score(&cmd, &profile, true, "alice", true);

        assert!(
            analysis.boundary_clustering_score < 0.1,
            "boundary score {} should be low for centered commands",
            analysis.boundary_clustering_score
        );
    }

    #[test]
    fn authority_probing_detects_repeated_rejections() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        // Feed many authority failures from same principal.
        for _ in 0..20 {
            let cmd = make_command(0.0, 0.0);
            scorer.score(&cmd, &profile, false, "mallory", false);
        }

        let cmd = make_command(0.0, 0.0);
        let analysis = scorer.score(&cmd, &profile, false, "mallory", false);

        assert!(
            analysis.authority_probing_score > 0.5,
            "authority score {} should be high for repeated rejections",
            analysis.authority_probing_score
        );
    }

    #[test]
    fn authority_probing_zero_when_all_pass() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        for _ in 0..10 {
            let cmd = make_command(0.0, 0.0);
            scorer.score(&cmd, &profile, true, "alice", true);
        }

        let cmd = make_command(0.0, 0.0);
        let analysis = scorer.score(&cmd, &profile, true, "alice", true);

        assert_eq!(analysis.authority_probing_score, 0.0);
    }

    #[test]
    fn replay_similarity_detects_near_copy_of_rejected_command() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        // A rejected command.
        let rejected_cmd = make_command(2.5, 1.0);
        scorer.score(&rejected_cmd, &profile, true, "alice", false);

        // A very similar command (slight variation).
        let replay_cmd = make_command(2.501, 1.001);
        let analysis = scorer.score(&replay_cmd, &profile, true, "alice", true);

        assert!(
            analysis.replay_similarity_score > 0.5,
            "replay score {} should be high for near-copy of rejected command",
            analysis.replay_similarity_score
        );
    }

    #[test]
    fn replay_similarity_low_for_novel_commands() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        // A rejected command at one extreme.
        let rejected_cmd = make_command(3.0, 1.5);
        scorer.score(&rejected_cmd, &profile, true, "alice", false);

        // A completely different command.
        let novel_cmd = make_command(-2.0, -1.0);
        let analysis = scorer.score(&novel_cmd, &profile, true, "alice", true);

        assert!(
            analysis.replay_similarity_score < 0.3,
            "replay score {} should be low for novel command",
            analysis.replay_similarity_score
        );
    }

    #[test]
    fn drift_detection_tracks_gradual_shift() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        // Establish a baseline around 0.0.
        for _ in 0..50 {
            let cmd = make_command(0.0, 0.0);
            scorer.score(&cmd, &profile, true, "alice", true);
        }

        // Sudden shift.
        let cmd = make_command(1.0, 1.0);
        let analysis = scorer.score(&cmd, &profile, true, "alice", true);

        assert!(
            analysis.drift_score > 0.0,
            "drift score {} should be non-zero after position shift",
            analysis.drift_score
        );
    }

    #[test]
    fn anomaly_scoring_flags_outlier() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        // Establish a normal distribution around center.
        for _ in 0..50 {
            let cmd = make_command(0.0, 0.0);
            scorer.score(&cmd, &profile, true, "alice", true);
        }

        // An extreme outlier.
        let cmd = make_command(3.0, 1.5);
        let analysis = scorer.score(&cmd, &profile, true, "alice", true);

        assert!(
            analysis.anomaly_score > 0.2,
            "anomaly score {} should be elevated for outlier",
            analysis.anomaly_score
        );
    }

    #[test]
    fn anomaly_scoring_low_for_consistent_commands() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        for _ in 0..50 {
            let cmd = make_command(0.5, 0.3);
            scorer.score(&cmd, &profile, true, "alice", true);
        }

        let cmd = make_command(0.5, 0.3);
        let analysis = scorer.score(&cmd, &profile, true, "alice", true);

        assert!(
            analysis.anomaly_score < 0.1,
            "anomaly score {} should be low for consistent commands",
            analysis.anomaly_score
        );
    }

    #[test]
    fn alert_triggers_when_composite_exceeds_threshold() {
        let config = ThreatScorerConfig {
            alert_threshold: 0.3, // low threshold for testing
            ..ThreatScorerConfig::default()
        };
        let mut scorer = ThreatScorer::new(config);
        let profile = test_profile();

        // Create conditions that elevate multiple scores.
        for _ in 0..20 {
            let cmd = make_command(3.12, 1.55); // near boundaries
            scorer.score(&cmd, &profile, false, "mallory", false); // auth failures
        }

        let cmd = make_command(3.13, 1.56);
        let analysis = scorer.score(&cmd, &profile, false, "mallory", false);

        assert!(
            analysis.alert,
            "alert should trigger when composite {} exceeds threshold 0.3",
            analysis.composite_threat_score
        );
    }

    #[test]
    fn composite_score_is_weighted_sum() {
        let mut scorer = ThreatScorer::with_defaults();
        let profile = test_profile();

        let cmd = make_command(0.0, 0.0);
        let analysis = scorer.score(&cmd, &profile, true, "alice", true);

        // With all scores at 0, composite should be 0.
        assert_eq!(analysis.composite_threat_score, 0.0);
    }

    #[test]
    fn cosine_similarity_identical_vectors() {
        let a = vec![1.0, 2.0, 3.0];
        assert!((cosine_similarity(&a, &a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn cosine_similarity_orthogonal_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!(cosine_similarity(&a, &b).abs() < 1e-9);
    }

    #[test]
    fn normalize_positions_maps_to_unit_range() {
        let profile = test_profile();
        let joints = vec![
            JointState {
                name: "j1".into(),
                position: -3.14,
                velocity: 0.0,
                effort: 0.0,
            },
            JointState {
                name: "j2".into(),
                position: 1.57,
                velocity: 0.0,
                effort: 0.0,
            },
        ];

        let norm = normalize_positions(&joints, &profile);
        assert!((norm[0] - 0.0).abs() < 1e-9, "min should normalize to 0.0");
        assert!((norm[1] - 1.0).abs() < 1e-9, "max should normalize to 1.0");
    }

    #[test]
    fn window_does_not_exceed_configured_size() {
        let config = ThreatScorerConfig {
            window_size: 10,
            ..ThreatScorerConfig::default()
        };
        let mut scorer = ThreatScorer::new(config);
        let profile = test_profile();

        for _ in 0..50 {
            let cmd = make_command(0.0, 0.0);
            scorer.score(&cmd, &profile, true, "alice", true);
        }

        assert!(scorer.window.len() <= 10);
    }
}
