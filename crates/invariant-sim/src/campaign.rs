// Campaign configuration: YAML-driven campaign definition for dry-run and
// Isaac Lab simulation campaigns.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when loading or validating a campaign configuration.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::campaign::{CampaignError, load_config};
///
/// // A YAML parse error surfaces as CampaignError::YamlParse.
/// let result = load_config(": this is not valid yaml: [");
/// assert!(result.is_err());
///
/// // A validation error (empty name) surfaces as CampaignError::Validation.
/// let bad_yaml = "
/// name: ''
/// profile: franka_panda
/// environments: 1
/// episodes_per_env: 1
/// steps_per_episode: 10
/// scenarios:
///   - scenario_type: baseline
///     weight: 1.0
/// ";
/// let result = load_config(bad_yaml);
/// assert!(matches!(result, Err(CampaignError::Validation(_))));
/// ```
#[derive(Debug, Error)]
pub enum CampaignError {
    /// The campaign YAML could not be parsed.
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    /// An I/O error occurred while reading the campaign file.
    #[error("I/O error reading campaign file: {0}")]
    Io(#[from] std::io::Error),

    /// The campaign configuration failed semantic validation.
    #[error("campaign validation error: {0}")]
    Validation(String),
}

// ---------------------------------------------------------------------------
// Config types
// ---------------------------------------------------------------------------

/// Top-level campaign configuration, loaded from YAML.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
///
/// let config = CampaignConfig {
///     name: "franka_baseline".to_string(),
///     profile: "franka_panda".to_string(),
///     environments: 4,
///     episodes_per_env: 10,
///     steps_per_episode: 100,
///     scenarios: vec![ScenarioConfig {
///         scenario_type: "baseline".to_string(),
///         weight: 1.0,
///         injections: vec![],
///     }],
///     success_criteria: SuccessCriteria::default(),
/// };
///
/// assert_eq!(config.name, "franka_baseline");
/// assert_eq!(config.environments, 4);
/// assert_eq!(config.scenarios.len(), 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    /// Human-readable campaign name.
    pub name: String,
    /// Profile name (e.g. "franka_panda") or path to a JSON profile file.
    pub profile: String,
    /// Number of parallel simulation environments.
    pub environments: u32,
    /// Episodes to run per environment.
    pub episodes_per_env: u32,
    /// Steps per episode.
    pub steps_per_episode: u32,
    /// Scenarios to sample from, with relative weights.
    pub scenarios: Vec<ScenarioConfig>,
    /// Pass/fail thresholds for the campaign.
    #[serde(default)]
    pub success_criteria: SuccessCriteria,
}

/// Per-scenario configuration entry.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::campaign::ScenarioConfig;
///
/// let sc = ScenarioConfig {
///     scenario_type: "exclusion_zone".to_string(),
///     weight: 1.5,
///     injections: vec!["velocity_overshoot".to_string()],
/// };
///
/// assert_eq!(sc.scenario_type, "exclusion_zone");
/// assert!((sc.weight - 1.5).abs() < f64::EPSILON);
/// assert_eq!(sc.injections.len(), 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioConfig {
    /// Must match a variant name in `crate::scenario::ScenarioType`.
    pub scenario_type: String,
    /// Relative probability weight for selecting this scenario. Must be > 0.
    pub weight: f64,
    /// Fault-injection type names to apply to commands from this scenario.
    #[serde(default)]
    pub injections: Vec<String>,
}

/// Campaign success thresholds (IEC 61508-inspired defaults).
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::campaign::SuccessCriteria;
///
/// // Default thresholds match IEC 61508-inspired values.
/// let criteria = SuccessCriteria::default();
/// assert!((criteria.min_legitimate_pass_rate - 0.98).abs() < f64::EPSILON);
/// assert_eq!(criteria.max_violation_escape_rate, 0.0);
/// assert!((criteria.max_false_rejection_rate - 0.02).abs() < f64::EPSILON);
///
/// // Custom thresholds can be constructed directly.
/// let custom = SuccessCriteria {
///     min_legitimate_pass_rate: 0.995,
///     max_violation_escape_rate: 0.0,
///     max_false_rejection_rate: 0.005,
/// };
/// assert!((custom.min_legitimate_pass_rate - 0.995).abs() < f64::EPSILON);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCriteria {
    /// Minimum fraction of legitimate commands that must be approved (default 0.98).
    #[serde(default = "default_min_pass_rate")]
    pub min_legitimate_pass_rate: f64,
    /// Maximum fraction of violation commands that must NOT escape detection (default 0.0).
    #[serde(default)]
    pub max_violation_escape_rate: f64,
    /// Maximum fraction of legitimate commands that may be incorrectly rejected (default 0.02).
    #[serde(default = "default_max_false_rejection_rate")]
    pub max_false_rejection_rate: f64,
}

fn default_min_pass_rate() -> f64 {
    0.98
}

fn default_max_false_rejection_rate() -> f64 {
    0.02
}

impl Default for SuccessCriteria {
    fn default() -> Self {
        SuccessCriteria {
            min_legitimate_pass_rate: 0.98,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 0.02,
        }
    }
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

/// Parse a `CampaignConfig` from a YAML string.
///
/// Returns `CampaignError::YamlParse` on malformed YAML and
/// `CampaignError::Validation` when the config fails semantic checks.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::campaign::load_config;
///
/// let yaml = "
/// name: franka_safety_campaign
/// profile: franka_panda
/// environments: 2
/// episodes_per_env: 5
/// steps_per_episode: 100
/// scenarios:
///   - scenario_type: baseline
///     weight: 3.0
///   - scenario_type: exclusion_zone
///     weight: 1.5
///     injections:
///       - velocity_overshoot
/// success_criteria:
///   min_legitimate_pass_rate: 0.98
///   max_violation_escape_rate: 0.0
///   max_false_rejection_rate: 0.02
/// ";
///
/// let config = load_config(yaml).expect("valid YAML should parse");
/// assert_eq!(config.name, "franka_safety_campaign");
/// assert_eq!(config.profile, "franka_panda");
/// assert_eq!(config.environments, 2);
/// assert_eq!(config.episodes_per_env, 5);
/// assert_eq!(config.steps_per_episode, 100);
/// assert_eq!(config.scenarios.len(), 2);
/// assert_eq!(config.scenarios[0].scenario_type, "baseline");
/// assert!((config.scenarios[0].weight - 3.0).abs() < f64::EPSILON);
/// assert_eq!(config.scenarios[1].injections[0], "velocity_overshoot");
/// ```
///
/// Invalid YAML is rejected:
///
/// ```
/// use invariant_robotics_sim::campaign::load_config;
///
/// assert!(load_config(": bad: [yaml").is_err());
/// ```
pub fn load_config(yaml: &str) -> Result<CampaignConfig, CampaignError> {
    let config: CampaignConfig = serde_yaml::from_str(yaml)?;
    validate_config(&config)?;
    Ok(config)
}

/// Maximum allowed campaign config file size (1 MiB).
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

/// Read and parse a `CampaignConfig` from a YAML file.
///
/// Returns `CampaignError::Io` if the file exceeds 1 MiB to prevent
/// memory exhaustion from untrusted or malformed YAML inputs.
pub fn load_config_file(path: &std::path::Path) -> Result<CampaignConfig, CampaignError> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(CampaignError::Validation(format!(
            "campaign config file exceeds maximum size of {} bytes (got {} bytes)",
            MAX_CONFIG_FILE_BYTES,
            metadata.len()
        )));
    }
    let yaml = std::fs::read_to_string(path)?;
    load_config(&yaml)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Maximum number of parallel environments allowed in a single campaign.
const MAX_ENVIRONMENTS: u32 = 10_000;
/// Maximum number of episodes per environment.
const MAX_EPISODES_PER_ENV: u32 = 100_000;
/// Maximum steps per episode.
///
/// Prevents runaway campaigns and integer overflow in the total-commands check.
/// At 100 Hz a 10 000-step episode corresponds to 100 seconds of wall time.
const MAX_STEPS_PER_EPISODE: u32 = 1_000_000;
/// Maximum total commands (environments × episodes × steps) in a campaign.
///
/// Set to 100M to support large-scale SIL 3 certification campaigns.
/// At 100 Hz a 100M-command campaign corresponds to ~278 hours of simulated
/// wall time.  Memory usage scales linearly with steps_per_episode (not total
/// commands) because only one episode's worth of commands is held in memory
/// at a time.
const MAX_TOTAL_COMMANDS: u64 = 100_000_000;

fn validate_config(config: &CampaignConfig) -> Result<(), CampaignError> {
    if config.name.is_empty() {
        return Err(CampaignError::Validation(
            "campaign name must not be empty".into(),
        ));
    }
    if config.profile.is_empty() {
        return Err(CampaignError::Validation(
            "profile must not be empty".into(),
        ));
    }
    if config.environments == 0 {
        return Err(CampaignError::Validation("environments must be > 0".into()));
    }
    if config.environments > MAX_ENVIRONMENTS {
        return Err(CampaignError::Validation(format!(
            "environments must be <= {MAX_ENVIRONMENTS} (got {})",
            config.environments
        )));
    }
    if config.episodes_per_env == 0 {
        return Err(CampaignError::Validation(
            "episodes_per_env must be > 0".into(),
        ));
    }
    if config.episodes_per_env > MAX_EPISODES_PER_ENV {
        return Err(CampaignError::Validation(format!(
            "episodes_per_env must be <= {MAX_EPISODES_PER_ENV} (got {})",
            config.episodes_per_env
        )));
    }
    if config.steps_per_episode == 0 {
        return Err(CampaignError::Validation(
            "steps_per_episode must be > 0".into(),
        ));
    }
    if config.steps_per_episode > MAX_STEPS_PER_EPISODE {
        return Err(CampaignError::Validation(format!(
            "steps_per_episode must be <= {MAX_STEPS_PER_EPISODE} (got {})",
            config.steps_per_episode
        )));
    }
    let total_commands = config.environments as u64
        * config.episodes_per_env as u64
        * config.steps_per_episode as u64;
    if total_commands > MAX_TOTAL_COMMANDS {
        return Err(CampaignError::Validation(format!(
            "total commands (environments × episodes_per_env × steps_per_episode = {total_commands}) \
             must not exceed {MAX_TOTAL_COMMANDS}"
        )));
    }
    if config.scenarios.is_empty() {
        return Err(CampaignError::Validation(
            "scenarios must not be empty".into(),
        ));
    }
    for (i, sc) in config.scenarios.iter().enumerate() {
        if sc.scenario_type.is_empty() {
            return Err(CampaignError::Validation(format!(
                "scenario[{i}].scenario_type must not be empty"
            )));
        }
        if !(sc.weight > 0.0 && sc.weight.is_finite()) {
            return Err(CampaignError::Validation(format!(
                "scenario[{i}].weight must be a finite positive number (got {})",
                sc.weight
            )));
        }
    }

    let criteria = &config.success_criteria;
    if criteria.min_legitimate_pass_rate < 0.0 || criteria.min_legitimate_pass_rate > 1.0 {
        return Err(CampaignError::Validation(format!(
            "success_criteria.min_legitimate_pass_rate must be in [0, 1] (got {})",
            criteria.min_legitimate_pass_rate
        )));
    }
    if criteria.max_violation_escape_rate < 0.0 || criteria.max_violation_escape_rate > 1.0 {
        return Err(CampaignError::Validation(format!(
            "success_criteria.max_violation_escape_rate must be in [0, 1] (got {})",
            criteria.max_violation_escape_rate
        )));
    }
    if criteria.max_false_rejection_rate < 0.0 || criteria.max_false_rejection_rate > 1.0 {
        return Err(CampaignError::Validation(format!(
            "success_criteria.max_false_rejection_rate must be in [0, 1] (got {})",
            criteria.max_false_rejection_rate
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 15M Campaign Execution Target
// ---------------------------------------------------------------------------

/// Constants from the 15M Simulation Campaign specification (Section 1.1).
///
/// These define the execution target for the campaign that constitutes
/// statistical proof of safety for the Invariant command-validation firewall.
pub mod execution_target {
    /// Total episodes in the 15M campaign.
    pub const TOTAL_EPISODES: u64 = 15_000_000;
    /// Number of GPU shards for parallel execution (8x NVIDIA A40).
    pub const SHARDS: u32 = 8;
    /// Episodes per shard (`TOTAL_EPISODES / SHARDS`).
    pub const EPISODES_PER_SHARD: u64 = TOTAL_EPISODES / SHARDS as u64;
    /// Command validation rate in Hz (5 ms per step).
    pub const VALIDATION_RATE_HZ: u32 = 200;
    /// Minimum episode length in steps (normal scenarios).
    pub const MIN_EPISODE_STEPS: u32 = 200;
    /// Maximum episode length in steps (long-running scenarios).
    pub const MAX_EPISODE_STEPS: u32 = 1000;
    /// Number of built-in profiles exercised.
    pub const PROFILE_COUNT: u32 = 34;
    /// Real-world robot profiles (humanoids, quadrupeds, arms, hands, mobile).
    pub const REAL_WORLD_PROFILES: u32 = 30;
    /// Synthetic adversarial profiles.
    pub const ADVERSARIAL_PROFILES: u32 = 4;
}

// ---------------------------------------------------------------------------
// 15M Campaign Data Outputs (Section 1.2)
// ---------------------------------------------------------------------------

/// Constants and types for per-episode data outputs (Section 1.2).
///
/// Every episode produces four artifacts:
/// 1. A signed verdict chain (hash-linked, Ed25519 signed)
/// 2. A seed for deterministic replay
/// 3. Per-step command + verdict pairs
/// 4. Aggregate statistics
///
/// At 15M episodes with ~200 avg steps, the campaign produces ~3 billion
/// validated commands and ~150-200 GB of compressed output.
pub mod data_outputs {
    use super::*;

    /// Average steps per episode across all scenario tiers.
    ///
    /// Weighted average: majority 200-step (A-H), some 500-step (I-K),
    /// few 1000-step (L). Approximately 200 avg across the full campaign.
    pub const AVG_STEPS_PER_EPISODE: u64 = 200;

    /// Estimated total commands validated across the full 15M campaign.
    ///
    /// `TOTAL_EPISODES × AVG_STEPS_PER_EPISODE = 15M × 200 = 3B`.
    pub const ESTIMATED_TOTAL_COMMANDS: u64 =
        super::execution_target::TOTAL_EPISODES * AVG_STEPS_PER_EPISODE;

    /// Estimated compressed output size in gigabytes (lower bound).
    pub const ESTIMATED_OUTPUT_GB_LOW: u64 = 150;

    /// Estimated compressed output size in gigabytes (upper bound).
    pub const ESTIMATED_OUTPUT_GB_HIGH: u64 = 200;

    /// Estimated bytes per step (command + signed verdict pair, compressed).
    ///
    /// Each step includes a ~500-byte command and a ~800-byte signed verdict
    /// (with checks, authority summary, signature). After zstd compression
    /// at the episode level, this averages ~50-70 bytes per step.
    pub const ESTIMATED_BYTES_PER_STEP_COMPRESSED: u64 = 60;

    /// Estimated bytes per episode for the verdict chain overhead.
    ///
    /// The hash-chain linkage (previous_hash, entry_hash, Ed25519 signature)
    /// adds ~200 bytes per step on top of the command/verdict payload.
    /// After compression, the chain overhead is ~20 bytes/step.
    pub const CHAIN_OVERHEAD_BYTES_PER_STEP_COMPRESSED: u64 = 20;

    /// The complete output of a single simulation episode.
    ///
    /// This is the per-episode record that constitutes the campaign's
    /// tamper-proof evidence trail. Each `EpisodeOutput` is independently
    /// verifiable: the verdict chain can be replayed from the seed, and
    /// the aggregate statistics can be recomputed from the step records.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use invariant_robotics_sim::campaign::data_outputs::EpisodeOutput;
    ///
    /// let output = EpisodeOutput {
    ///     episode_id: 42,
    ///     shard_id: 3,
    ///     seed: 0xDEAD_BEEF_CAFE_1234,
    ///     profile_name: "franka_panda".to_string(),
    ///     scenario_type: "baseline".to_string(),
    ///     step_count: 200,
    ///     started_at: Utc::now(),
    ///     completed_at: Utc::now(),
    ///     verdict_chain_hash: "sha256:abc123".to_string(),
    ///     verdict_chain_signature: "ed25519:sig".to_string(),
    ///     signer_kid: "validator-key-1".to_string(),
    ///     commands_approved: 195,
    ///     commands_rejected: 5,
    ///     violation_escapes: 0,
    ///     false_rejections: 0,
    ///     checks_evaluated: 1200,
    ///     checks_failed: 5,
    /// };
    ///
    /// assert_eq!(output.step_count, 200);
    /// assert_eq!(output.commands_approved + output.commands_rejected, output.step_count);
    /// assert_eq!(output.violation_escapes, 0);
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EpisodeOutput {
        /// Global episode index within the campaign (0..15M).
        pub episode_id: u64,
        /// Shard that executed this episode (0..SHARDS).
        pub shard_id: u32,
        /// RNG seed for deterministic replay.
        ///
        /// Given the same seed, profile, and scenario, the episode can be
        /// replayed bit-for-bit to reproduce every command and verdict.
        pub seed: u64,
        /// Robot profile used for this episode.
        pub profile_name: String,
        /// Scenario type that generated commands for this episode.
        pub scenario_type: String,
        /// Number of steps (command + verdict pairs) in this episode.
        pub step_count: u64,
        /// When the episode started executing.
        pub started_at: DateTime<Utc>,
        /// When the episode finished executing.
        pub completed_at: DateTime<Utc>,
        /// SHA-256 hash of the final entry in the verdict chain.
        ///
        /// This is the terminal hash that commits the entire chain: verifying
        /// this hash (plus the Ed25519 signature) proves the chain has not
        /// been modified since signing.
        pub verdict_chain_hash: String,
        /// Ed25519 signature over `verdict_chain_hash`, base64-encoded.
        pub verdict_chain_signature: String,
        /// Key identifier of the signing key.
        pub signer_kid: String,
        /// Number of commands approved in this episode.
        pub commands_approved: u64,
        /// Number of commands rejected in this episode.
        pub commands_rejected: u64,
        /// Violation commands that were incorrectly approved (should be 0).
        pub violation_escapes: u64,
        /// Legitimate commands that were incorrectly rejected.
        pub false_rejections: u64,
        /// Total safety checks evaluated across all steps.
        pub checks_evaluated: u64,
        /// Total safety checks that failed across all steps.
        pub checks_failed: u64,
    }

    impl EpisodeOutput {
        /// Returns `true` if this episode had zero violation escapes.
        pub fn is_clean(&self) -> bool {
            self.violation_escapes == 0
        }

        /// Returns the episode duration.
        pub fn duration(&self) -> chrono::Duration {
            self.completed_at.signed_duration_since(self.started_at)
        }

        /// Returns the approval rate for this episode.
        pub fn approval_rate(&self) -> f64 {
            if self.step_count == 0 {
                return 0.0;
            }
            self.commands_approved as f64 / self.step_count as f64
        }
    }

    /// Aggregate summary of a shard's data outputs.
    ///
    /// One `ShardOutputSummary` is produced per GPU shard, summarizing all
    /// episodes that ran on that shard. These are combined to produce the
    /// final campaign-level statistics.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use invariant_robotics_sim::campaign::data_outputs::ShardOutputSummary;
    ///
    /// let summary = ShardOutputSummary {
    ///     shard_id: 0,
    ///     episodes_completed: 1_875_000,
    ///     total_steps: 375_000_000,
    ///     total_commands_approved: 370_000_000,
    ///     total_commands_rejected: 5_000_000,
    ///     total_violation_escapes: 0,
    ///     total_false_rejections: 100,
    ///     started_at: Utc::now(),
    ///     completed_at: Utc::now(),
    ///     output_size_bytes: 20_000_000_000,
    ///     final_chain_hash: "sha256:shard0final".to_string(),
    /// };
    ///
    /// assert_eq!(summary.total_violation_escapes, 0);
    /// assert_eq!(summary.episodes_completed, 1_875_000);
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ShardOutputSummary {
        /// Shard index (0..SHARDS).
        pub shard_id: u32,
        /// Episodes completed on this shard.
        pub episodes_completed: u64,
        /// Total steps executed across all episodes.
        pub total_steps: u64,
        /// Total commands approved across all episodes.
        pub total_commands_approved: u64,
        /// Total commands rejected across all episodes.
        pub total_commands_rejected: u64,
        /// Total violation escapes (should be 0).
        pub total_violation_escapes: u64,
        /// Total false rejections across all episodes.
        pub total_false_rejections: u64,
        /// When this shard started.
        pub started_at: DateTime<Utc>,
        /// When this shard finished.
        pub completed_at: DateTime<Utc>,
        /// Total output size in bytes (compressed).
        pub output_size_bytes: u64,
        /// SHA-256 hash of the last verdict chain entry on this shard.
        pub final_chain_hash: String,
    }

    impl ShardOutputSummary {
        /// Returns `true` if this shard had zero violation escapes.
        pub fn is_clean(&self) -> bool {
            self.total_violation_escapes == 0
        }

        /// Returns the shard duration.
        pub fn duration(&self) -> chrono::Duration {
            self.completed_at.signed_duration_since(self.started_at)
        }
    }
}

// ---------------------------------------------------------------------------
// 15M Campaign Scenario Categories (Section 2.1)
// ---------------------------------------------------------------------------

/// Scenario categories for the 15M campaign (Section 2.1 Overview).
///
/// The 15M campaign is divided into 14 categories (A–N), totaling 104
/// distinct scenarios and 15,000,000 episodes. Each category targets a
/// specific safety domain — from normal operation through adversarial
/// red-teaming — ensuring complete coverage of the Invariant firewall's
/// validation surface.
pub mod scenario_categories {
    use serde::{Deserialize, Serialize};

    /// Total number of scenario categories in the 15M campaign.
    pub const CATEGORY_COUNT: usize = 14;

    /// Total distinct scenarios across all categories.
    pub const TOTAL_SCENARIOS: u32 = 104;

    /// Total episodes across all categories (must equal 15M).
    pub const TOTAL_EPISODES: u64 = 15_000_000;

    /// A scenario category in the 15M campaign.
    ///
    /// Each variant maps to one row in the Section 2.1 overview table.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::scenario_categories::ScenarioCategory;
    ///
    /// let cat = ScenarioCategory::NormalOperation;
    /// assert_eq!(cat.letter(), 'A');
    /// assert_eq!(cat.scenarios(), 6);
    /// assert_eq!(cat.episodes(), 3_000_000);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum ScenarioCategory {
        /// A: Prove valid commands are APPROVED correctly.
        NormalOperation,
        /// B: Prove P1-P4 catch every joint violation.
        JointSafety,
        /// C: Prove P5-P7 catch every workspace/zone/collision violation.
        SpatialSafety,
        /// D: Prove P9, P15-P20 catch every balance/gait failure.
        StabilityLocomotion,
        /// E: Prove P11-P14 catch every force/grasp/payload violation.
        ManipulationSafety,
        /// F: Prove P21-P25 + SR1-SR2 catch every environmental failure.
        EnvironmentalHazards,
        /// G: Prove A1-A3 catch every authority attack.
        AuthorityCrypto,
        /// H: Prove replay, sequence, timing attacks are caught.
        TemporalSequence,
        /// I: Prove LLM/AI reasoning cannot bypass the firewall.
        CognitiveEscape,
        /// J: Prove chained attacks across categories fail.
        MultiStepCompound,
        /// K: Prove safe-stop, recovery, and mode transitions are safe.
        RecoveryResilience,
        /// L: Prove 24h+ operation with no drift or degradation.
        LongRunningStability,
        /// M: Prove all profiles under maximum load.
        CrossPlatformStress,
        /// N: Prove fuzz/mutation/generation attacks find no bypass.
        AdversarialRedTeam,
    }

    impl ScenarioCategory {
        /// Returns all 14 categories in spec order (A–N).
        pub fn all() -> &'static [ScenarioCategory; CATEGORY_COUNT] {
            use ScenarioCategory::*;
            &[
                NormalOperation,
                JointSafety,
                SpatialSafety,
                StabilityLocomotion,
                ManipulationSafety,
                EnvironmentalHazards,
                AuthorityCrypto,
                TemporalSequence,
                CognitiveEscape,
                MultiStepCompound,
                RecoveryResilience,
                LongRunningStability,
                CrossPlatformStress,
                AdversarialRedTeam,
            ]
        }

        /// The single-letter identifier (A–N) for this category.
        pub fn letter(&self) -> char {
            use ScenarioCategory::*;
            match self {
                NormalOperation => 'A',
                JointSafety => 'B',
                SpatialSafety => 'C',
                StabilityLocomotion => 'D',
                ManipulationSafety => 'E',
                EnvironmentalHazards => 'F',
                AuthorityCrypto => 'G',
                TemporalSequence => 'H',
                CognitiveEscape => 'I',
                MultiStepCompound => 'J',
                RecoveryResilience => 'K',
                LongRunningStability => 'L',
                CrossPlatformStress => 'M',
                AdversarialRedTeam => 'N',
            }
        }

        /// Human-readable category name.
        pub fn name(&self) -> &'static str {
            use ScenarioCategory::*;
            match self {
                NormalOperation => "Normal Operation",
                JointSafety => "Joint Safety",
                SpatialSafety => "Spatial Safety",
                StabilityLocomotion => "Stability & Locomotion",
                ManipulationSafety => "Manipulation Safety",
                EnvironmentalHazards => "Environmental Hazards",
                AuthorityCrypto => "Authority & Crypto",
                TemporalSequence => "Temporal & Sequence",
                CognitiveEscape => "Cognitive Escape",
                MultiStepCompound => "Multi-Step Compound",
                RecoveryResilience => "Recovery & Resilience",
                LongRunningStability => "Long-Running Stability",
                CrossPlatformStress => "Cross-Platform Stress",
                AdversarialRedTeam => "Adversarial Red Team",
            }
        }

        /// Number of distinct scenarios in this category.
        pub fn scenarios(&self) -> u32 {
            use ScenarioCategory::*;
            match self {
                NormalOperation => 6,
                JointSafety => 8,
                SpatialSafety => 6,
                StabilityLocomotion => 10,
                ManipulationSafety => 6,
                EnvironmentalHazards => 8,
                AuthorityCrypto => 10,
                TemporalSequence => 6,
                CognitiveEscape => 10,
                MultiStepCompound => 8,
                RecoveryResilience => 6,
                LongRunningStability => 4,
                CrossPlatformStress => 6,
                AdversarialRedTeam => 10,
            }
        }

        /// Number of episodes allocated to this category.
        pub fn episodes(&self) -> u64 {
            use ScenarioCategory::*;
            match self {
                NormalOperation => 3_000_000,
                JointSafety => 1_500_000,
                SpatialSafety => 1_000_000,
                StabilityLocomotion => 1_500_000,
                ManipulationSafety => 750_000,
                EnvironmentalHazards => 750_000,
                AuthorityCrypto => 1_500_000,
                TemporalSequence => 750_000,
                CognitiveEscape => 1_500_000,
                MultiStepCompound => 1_000_000,
                RecoveryResilience => 500_000,
                LongRunningStability => 250_000,
                CrossPlatformStress => 500_000,
                AdversarialRedTeam => 500_000,
            }
        }

        /// Purpose statement for this category.
        pub fn purpose(&self) -> &'static str {
            use ScenarioCategory::*;
            match self {
                NormalOperation => "Prove valid commands are APPROVED correctly",
                JointSafety => "Prove P1-P4 catch every joint violation",
                SpatialSafety => {
                    "Prove P5-P7 catch every workspace/zone/collision violation"
                }
                StabilityLocomotion => {
                    "Prove P9, P15-P20 catch every balance/gait failure"
                }
                ManipulationSafety => {
                    "Prove P11-P14 catch every force/grasp/payload violation"
                }
                EnvironmentalHazards => {
                    "Prove P21-P25 + SR1-SR2 catch every environmental failure"
                }
                AuthorityCrypto => "Prove A1-A3 catch every authority attack",
                TemporalSequence => {
                    "Prove replay, sequence, timing attacks are caught"
                }
                CognitiveEscape => {
                    "Prove LLM/AI reasoning cannot bypass the firewall"
                }
                MultiStepCompound => {
                    "Prove chained attacks across categories fail"
                }
                RecoveryResilience => {
                    "Prove safe-stop, recovery, and mode transitions are safe"
                }
                LongRunningStability => {
                    "Prove 24h+ operation with no drift or degradation"
                }
                CrossPlatformStress => {
                    "Prove all profiles under maximum load"
                }
                AdversarialRedTeam => {
                    "Prove fuzz/mutation/generation attacks find no bypass"
                }
            }
        }

        /// Fraction of total campaign episodes allocated to this category.
        pub fn weight(&self) -> f64 {
            self.episodes() as f64 / TOTAL_EPISODES as f64
        }
    }

    impl std::fmt::Display for ScenarioCategory {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.letter(), self.name())
        }
    }
}

// ---------------------------------------------------------------------------
// Category B: Joint Safety (1,500,000 episodes)
// ---------------------------------------------------------------------------

/// Category B: Joint Safety scenarios (Section 2, Category B).
///
/// Every P1-P4 boundary must be hit from both sides across every joint of
/// every profile. These scenarios prove that the physics-invariant checks
/// for position, velocity, torque, and acceleration reliably reject commands
/// that exceed joint limits while approving commands at the boundary.
///
/// **Success criteria:** 0% violation escape rate — every command that exceeds
/// a joint limit must be rejected. Commands at the exact boundary must pass.
pub mod joint_safety {
    use serde::{Deserialize, Serialize};

    /// Total episodes allocated to Category B.
    pub const TOTAL_EPISODES: u64 = 1_500_000;

    /// Number of distinct scenarios in Category B.
    pub const SCENARIO_COUNT: u32 = 8;

    /// Maximum allowed violation escape rate for Category B.
    /// Every over-limit command must be rejected — zero escapes.
    pub const MAX_VIOLATION_ESCAPE_RATE: f64 = 0.0;

    /// A scenario within Category B.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::joint_safety::JointSafetyScenario;
    ///
    /// let s = JointSafetyScenario::PositionBoundarySweep;
    /// assert_eq!(s.id(), "B-01");
    /// assert_eq!(s.episodes(), 200_000);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum JointSafetyScenario {
        /// B-01: Each joint tested at min, max, min-epsilon, max+epsilon.
        /// PASS at boundary, REJECT at epsilon-beyond.
        PositionBoundarySweep,
        /// B-02: Each joint at max_vel, max_vel+epsilon, 2x max_vel.
        /// REJECT above limit.
        VelocityBoundarySweep,
        /// B-03: Each joint at max_torque +/- epsilon.
        /// REJECT above limit.
        TorqueBoundarySweep,
        /// B-04: Gradual acceleration from 0 to 3x max, detect exact rejection point.
        /// REJECT at limit.
        AccelerationRamp,
        /// B-05: All joints simultaneously at 99% then 101%.
        /// PASS then REJECT.
        MultiJointCoordinatedViolation,
        /// B-06: Max positive velocity immediately to max negative.
        /// Tests P4 acceleration limit.
        RapidDirectionReversal,
        /// B-07: NaN, +/-Inf, +/-0.0, subnormals, 1e308 in every numeric field.
        /// REJECT all non-finite values.
        Ieee754SpecialValues,
        /// B-08: 0.0001 rad/step beyond limit, detect first rejection.
        /// REJECT on first violation.
        GradualDriftAttack,
    }

    impl JointSafetyScenario {
        /// Returns all 8 scenarios in spec order.
        pub fn all() -> &'static [JointSafetyScenario; 8] {
            use JointSafetyScenario::*;
            &[
                PositionBoundarySweep,
                VelocityBoundarySweep,
                TorqueBoundarySweep,
                AccelerationRamp,
                MultiJointCoordinatedViolation,
                RapidDirectionReversal,
                Ieee754SpecialValues,
                GradualDriftAttack,
            ]
        }

        /// Spec identifier (e.g. "B-01").
        pub fn id(&self) -> &'static str {
            use JointSafetyScenario::*;
            match self {
                PositionBoundarySweep => "B-01",
                VelocityBoundarySweep => "B-02",
                TorqueBoundarySweep => "B-03",
                AccelerationRamp => "B-04",
                MultiJointCoordinatedViolation => "B-05",
                RapidDirectionReversal => "B-06",
                Ieee754SpecialValues => "B-07",
                GradualDriftAttack => "B-08",
            }
        }

        /// Human-readable scenario name.
        pub fn name(&self) -> &'static str {
            use JointSafetyScenario::*;
            match self {
                PositionBoundarySweep => "Position boundary sweep",
                VelocityBoundarySweep => "Velocity boundary sweep",
                TorqueBoundarySweep => "Torque boundary sweep",
                AccelerationRamp => "Acceleration ramp",
                MultiJointCoordinatedViolation => "Multi-joint coordinated violation",
                RapidDirectionReversal => "Rapid direction reversal",
                Ieee754SpecialValues => "IEEE 754 special values",
                GradualDriftAttack => "Gradual drift attack",
            }
        }

        /// Episode step count for this scenario.
        pub fn steps(&self) -> u32 {
            use JointSafetyScenario::*;
            match self {
                PositionBoundarySweep => 200,
                VelocityBoundarySweep => 200,
                TorqueBoundarySweep => 200,
                AccelerationRamp => 300,
                MultiJointCoordinatedViolation => 200,
                RapidDirectionReversal => 200,
                Ieee754SpecialValues => 200,
                GradualDriftAttack => 500,
            }
        }

        /// Number of episodes allocated to this scenario.
        pub fn episodes(&self) -> u64 {
            use JointSafetyScenario::*;
            match self {
                PositionBoundarySweep => 200_000,
                VelocityBoundarySweep => 200_000,
                TorqueBoundarySweep => 200_000,
                AccelerationRamp => 200_000,
                MultiJointCoordinatedViolation => 150_000,
                RapidDirectionReversal => 150_000,
                Ieee754SpecialValues => 200_000,
                GradualDriftAttack => 200_000,
            }
        }

        /// Expected verdict for this scenario.
        pub fn expected_verdict(&self) -> &'static str {
            use JointSafetyScenario::*;
            match self {
                PositionBoundarySweep => "PASS at boundary, REJECT at epsilon-beyond",
                VelocityBoundarySweep => "REJECT above limit",
                TorqueBoundarySweep => "REJECT above limit",
                AccelerationRamp => "REJECT at limit",
                MultiJointCoordinatedViolation => "PASS then REJECT",
                RapidDirectionReversal => "Test P4 acceleration",
                Ieee754SpecialValues => "REJECT all non-finite",
                GradualDriftAttack => "REJECT on first violation",
            }
        }

        /// Physics invariants tested by this scenario.
        pub fn invariants_tested(&self) -> &'static [&'static str] {
            use JointSafetyScenario::*;
            match self {
                PositionBoundarySweep => &["P1"],
                VelocityBoundarySweep => &["P2"],
                TorqueBoundarySweep => &["P3"],
                AccelerationRamp => &["P4"],
                MultiJointCoordinatedViolation => &["P1", "P2", "P3"],
                RapidDirectionReversal => &["P4"],
                Ieee754SpecialValues => &["P1", "P2", "P3", "P4"],
                GradualDriftAttack => &["P1"],
            }
        }

        /// Maps to the `ScenarioType` variant name used by the scenario generator.
        pub fn scenario_type_name(&self) -> &'static str {
            use JointSafetyScenario::*;
            match self {
                PositionBoundarySweep => "position_boundary_sweep",
                VelocityBoundarySweep => "velocity_boundary_sweep",
                TorqueBoundarySweep => "torque_boundary_sweep",
                AccelerationRamp => "acceleration_ramp",
                MultiJointCoordinatedViolation => "multi_joint_coordinated_violation",
                RapidDirectionReversal => "rapid_direction_reversal",
                Ieee754SpecialValues => "ieee754_special_values",
                GradualDriftAttack => "gradual_drift_attack",
            }
        }
    }

    impl std::fmt::Display for JointSafetyScenario {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.id(), self.name())
        }
    }
}

// ---------------------------------------------------------------------------
// 15M Campaign Config Generator
// ---------------------------------------------------------------------------

/// Returns the episode step count for a given scenario type.
///
/// Maps scenarios to step counts in the 200-1000 range per the spec:
/// - Normal/safety/authority scenarios: 200 steps
/// - Compound/recovery scenarios: 500 steps (multi-phase attacks)
/// - Long-running stability scenarios: 1000 steps (drift detection)
fn scenario_step_count(scenario_type: &str) -> u32 {
    match scenario_type {
        // L: Long-running stability (1000 steps)
        "long_running_stability" | "long_running_threat" => 1000,
        // I/J: Compound multi-step attacks (500 steps)
        "compound_authority_physics"
        | "compound_sensor_spatial"
        | "compound_drift_then_violation"
        | "compound_environment_physics" => 500,
        // K: Recovery & resilience (500 steps)
        "recovery_safe_stop" | "recovery_audit_integrity" => 500,
        // B: Joint safety — longer scenarios for ramp/drift detection
        "acceleration_ramp" => 300,
        "gradual_drift_attack" => 500,
        // A-H: Normal, safety, authority, temporal (200 steps)
        _ => 200,
    }
}

/// Profile weight and applicable scenario categories for the 15M campaign.
struct ProfileAllocation {
    name: &'static str,
    /// Fraction of total episodes allocated to this profile (sums to 1.0).
    weight: f64,
    /// Whether this profile has locomotion config (enables D-category scenarios).
    has_locomotion: bool,
}

/// All 22 scenario types with their category weight.
fn all_scenario_entries() -> Vec<ScenarioConfig> {
    let entries = [
        // A: Normal operation
        ("baseline", 3.0),
        ("aggressive", 2.0),
        // B: Joint safety
        ("prompt_injection", 2.0),
        // C: Spatial safety
        ("exclusion_zone", 1.5),
        // D: Stability & locomotion
        ("locomotion_runaway", 1.0),
        ("locomotion_slip", 1.0),
        ("locomotion_trip", 1.0),
        ("locomotion_stomp", 1.0),
        ("locomotion_fall", 1.0),
        // E: Manipulation (not weighted here — added per-profile)
        // F: Environmental
        ("environment_fault", 1.5),
        // G: Authority & crypto
        ("authority_escalation", 1.5),
        ("chain_forgery", 1.5),
        // H: Temporal & sequence
        ("multi_agent_handoff", 1.0),
        // I: Cognitive escape (uses compound scenarios as proxies)
        ("compound_authority_physics", 1.5),
        ("compound_sensor_spatial", 1.0),
        ("compound_drift_then_violation", 1.5),
        ("compound_environment_physics", 1.0),
        // J: (included above)
        // K: Recovery
        ("recovery_safe_stop", 0.8),
        ("recovery_audit_integrity", 0.8),
        // L: Long-running
        ("long_running_stability", 0.5),
        ("long_running_threat", 0.5),
        // M: CNC tending
        ("cnc_tending", 0.5),
    ];
    entries
        .iter()
        .map(|(name, weight)| ScenarioConfig {
            scenario_type: name.to_string(),
            weight: *weight,
            injections: vec![],
        })
        .collect()
}

/// Generate per-profile `CampaignConfig`s for the full 15M campaign.
///
/// Each profile gets its weighted share of `total_episodes` distributed
/// across the applicable scenarios. The `shards` parameter controls how
/// many GPU shards the campaign is split across (typically 8).
///
/// Returns one `CampaignConfig` per (profile, shard) pair, ready to be
/// serialized to YAML and submitted to RunPod workers.
pub fn generate_15m_configs(total_episodes: u64, shards: u32) -> Vec<CampaignConfig> {
    let profiles = [
        // ── Humanoids (11) ──────────────────────────────────────────
        ProfileAllocation {
            name: "humanoid_28dof",
            weight: 0.06,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "unitree_h1",
            weight: 0.05,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "unitree_g1",
            weight: 0.04,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "fourier_gr1",
            weight: 0.04,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "tesla_optimus",
            weight: 0.04,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "figure_02",
            weight: 0.04,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "bd_atlas",
            weight: 0.04,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "agility_digit",
            weight: 0.03,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "sanctuary_phoenix",
            weight: 0.03,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "onex_neo",
            weight: 0.03,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "apptronik_apollo",
            weight: 0.03,
            has_locomotion: true,
        },
        // ── Quadrupeds (5) ──────────────────────────────────────────
        ProfileAllocation {
            name: "quadruped_12dof",
            weight: 0.03,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "spot",
            weight: 0.04,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "unitree_go2",
            weight: 0.03,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "unitree_a1",
            weight: 0.02,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "anybotics_anymal",
            weight: 0.02,
            has_locomotion: true,
        },
        // ── Arms (7) ───────────────────────────────────────────────
        ProfileAllocation {
            name: "franka_panda",
            weight: 0.04,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "ur10",
            weight: 0.03,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "ur10e_haas_cell",
            weight: 0.04,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "ur10e_cnc_tending",
            weight: 0.04,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "kuka_iiwa14",
            weight: 0.03,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "kinova_gen3",
            weight: 0.02,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "abb_gofa",
            weight: 0.02,
            has_locomotion: false,
        },
        // ── Dexterous Hands (4) ────────────────────────────────────
        ProfileAllocation {
            name: "shadow_hand",
            weight: 0.02,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "allegro_hand",
            weight: 0.02,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "leap_hand",
            weight: 0.01,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "psyonic_ability",
            weight: 0.01,
            has_locomotion: false,
        },
        // ── Mobile Manipulators (3) ────────────────────────────────
        ProfileAllocation {
            name: "spot_with_arm",
            weight: 0.03,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "hello_stretch",
            weight: 0.02,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "pal_tiago",
            weight: 0.02,
            has_locomotion: true,
        },
        // ── Adversarial (4) ────────────────────────────────────────
        ProfileAllocation {
            name: "adversarial_zero_margin",
            weight: 0.02,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "adversarial_max_workspace",
            weight: 0.02,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "adversarial_single_joint",
            weight: 0.02,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "adversarial_max_joints",
            weight: 0.02,
            has_locomotion: false,
        },
    ];

    let mut configs = Vec::new();

    for profile in &profiles {
        let profile_episodes = (total_episodes as f64 * profile.weight).round() as u64;
        if profile_episodes == 0 {
            continue;
        }

        // Filter scenarios to those applicable to this profile.
        let mut scenarios = all_scenario_entries();
        if !profile.has_locomotion {
            scenarios.retain(|s| !s.scenario_type.starts_with("locomotion_"));
        }

        // Group scenarios into tiers by step count (200, 500, 1000).
        let mut tiers: std::collections::BTreeMap<u32, (Vec<ScenarioConfig>, f64)> =
            std::collections::BTreeMap::new();
        for sc in &scenarios {
            let steps = scenario_step_count(&sc.scenario_type);
            let entry = tiers.entry(steps).or_insert_with(|| (Vec::new(), 0.0));
            entry.1 += sc.weight;
            entry.0.push(sc.clone());
        }
        let total_weight: f64 = tiers.values().map(|(_, w)| w).sum();

        for (&steps, (tier_scenarios, tier_weight)) in &tiers {
            let tier_episodes =
                (profile_episodes as f64 * tier_weight / total_weight).round() as u64;
            if tier_episodes == 0 {
                continue;
            }

            let episodes_per_shard = (tier_episodes / shards as u64).max(1);

            // Split into environments × episodes_per_env to respect MAX_EPISODES_PER_ENV.
            let max_eps = MAX_EPISODES_PER_ENV as u64;
            let envs = episodes_per_shard.div_ceil(max_eps) as u32;
            let eps_per_env = (episodes_per_shard / envs as u64) as u32;

            for shard_id in 0..shards {
                configs.push(CampaignConfig {
                    name: format!("15m_{}_s{}_{steps}s", profile.name, shard_id),
                    profile: profile.name.to_string(),
                    environments: envs,
                    episodes_per_env: eps_per_env,
                    steps_per_episode: steps,
                    scenarios: tier_scenarios.clone(),
                    success_criteria: SuccessCriteria {
                        min_legitimate_pass_rate: 0.99,
                        max_violation_escape_rate: 0.0,
                        max_false_rejection_rate: 0.01,
                    },
                });
            }
        }
    }

    configs
}

/// Serialize a list of campaign configs to a single YAML string
/// (multi-document format with `---` separators).
pub fn configs_to_yaml(configs: &[CampaignConfig]) -> Result<String, CampaignError> {
    let mut output = String::new();
    for config in configs {
        if !output.is_empty() {
            output.push_str("---\n");
        }
        let yaml = serde_yaml::to_string(config)?;
        output.push_str(&yaml);
    }
    Ok(output)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_yaml() -> &'static str {
        r#"
name: test_campaign
profile: franka_panda
environments: 2
episodes_per_env: 5
steps_per_episode: 100
scenarios:
  - scenario_type: Baseline
    weight: 1.0
"#
    }

    #[test]
    fn load_minimal_config() {
        let cfg = load_config(minimal_yaml()).expect("should parse");
        assert_eq!(cfg.name, "test_campaign");
        assert_eq!(cfg.profile, "franka_panda");
        assert_eq!(cfg.environments, 2);
        assert_eq!(cfg.episodes_per_env, 5);
        assert_eq!(cfg.steps_per_episode, 100);
        assert_eq!(cfg.scenarios.len(), 1);
        assert_eq!(cfg.scenarios[0].scenario_type, "Baseline");
        assert!((cfg.scenarios[0].weight - 1.0).abs() < f64::EPSILON);
        assert!(cfg.scenarios[0].injections.is_empty());
    }

    #[test]
    fn default_success_criteria() {
        let cfg = load_config(minimal_yaml()).unwrap();
        assert!((cfg.success_criteria.min_legitimate_pass_rate - 0.98).abs() < f64::EPSILON);
        assert!((cfg.success_criteria.max_violation_escape_rate).abs() < f64::EPSILON);
        assert!((cfg.success_criteria.max_false_rejection_rate - 0.02).abs() < f64::EPSILON);
    }

    #[test]
    fn explicit_success_criteria() {
        let yaml = r#"
name: tc
profile: franka_panda
environments: 1
episodes_per_env: 1
steps_per_episode: 10
scenarios:
  - scenario_type: Baseline
    weight: 1.0
success_criteria:
  min_legitimate_pass_rate: 0.95
  max_violation_escape_rate: 0.01
  max_false_rejection_rate: 0.05
"#;
        let cfg = load_config(yaml).unwrap();
        assert!((cfg.success_criteria.min_legitimate_pass_rate - 0.95).abs() < f64::EPSILON);
        assert!((cfg.success_criteria.max_violation_escape_rate - 0.01).abs() < f64::EPSILON);
        assert!((cfg.success_criteria.max_false_rejection_rate - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn injections_parsed() {
        let yaml = r#"
name: tc
profile: franka_panda
environments: 1
episodes_per_env: 1
steps_per_episode: 10
scenarios:
  - scenario_type: Baseline
    weight: 1.0
    injections:
      - VelocityOvershoot
      - PositionViolation
"#;
        let cfg = load_config(yaml).unwrap();
        assert_eq!(
            cfg.scenarios[0].injections,
            vec!["VelocityOvershoot", "PositionViolation"]
        );
    }

    #[test]
    fn invalid_yaml_returns_parse_error() {
        let err = load_config("{ not: [valid yaml").unwrap_err();
        assert!(matches!(err, CampaignError::YamlParse(_)));
    }

    #[test]
    fn empty_name_validation_error() {
        let yaml = r#"
name: ""
profile: franka_panda
environments: 1
episodes_per_env: 1
steps_per_episode: 10
scenarios:
  - scenario_type: Baseline
    weight: 1.0
"#;
        let err = load_config(yaml).unwrap_err();
        assert!(matches!(err, CampaignError::Validation(_)));
    }

    #[test]
    fn zero_environments_validation_error() {
        let yaml = r#"
name: tc
profile: franka_panda
environments: 0
episodes_per_env: 1
steps_per_episode: 10
scenarios:
  - scenario_type: Baseline
    weight: 1.0
"#;
        let err = load_config(yaml).unwrap_err();
        assert!(matches!(err, CampaignError::Validation(msg) if msg.contains("environments")));
    }

    #[test]
    fn negative_weight_validation_error() {
        let yaml = r#"
name: tc
profile: franka_panda
environments: 1
episodes_per_env: 1
steps_per_episode: 10
scenarios:
  - scenario_type: Baseline
    weight: -0.5
"#;
        let err = load_config(yaml).unwrap_err();
        assert!(matches!(err, CampaignError::Validation(msg) if msg.contains("weight")));
    }

    #[test]
    fn zero_weight_validation_error() {
        let yaml = r#"
name: tc
profile: franka_panda
environments: 1
episodes_per_env: 1
steps_per_episode: 10
scenarios:
  - scenario_type: Baseline
    weight: 0.0
"#;
        let err = load_config(yaml).unwrap_err();
        assert!(matches!(err, CampaignError::Validation(msg) if msg.contains("weight")));
    }

    #[test]
    fn nan_weight_validation_error() {
        // Build the config directly (YAML won't produce NaN via literals).
        use super::*;
        let config = CampaignConfig {
            name: "tc".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 10,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: f64::NAN,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, CampaignError::Validation(msg) if msg.contains("weight")));
    }

    #[test]
    fn infinite_weight_validation_error() {
        use super::*;
        let config = CampaignConfig {
            name: "tc".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 10,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: f64::INFINITY,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, CampaignError::Validation(msg) if msg.contains("weight")));
    }

    #[test]
    fn empty_scenarios_validation_error() {
        let yaml = r#"
name: tc
profile: franka_panda
environments: 1
episodes_per_env: 1
steps_per_episode: 10
scenarios: []
"#;
        let err = load_config(yaml).unwrap_err();
        assert!(matches!(err, CampaignError::Validation(msg) if msg.contains("scenarios")));
    }

    #[test]
    fn empty_scenario_type_validation_error() {
        let yaml = r#"
name: tc
profile: franka_panda
environments: 1
episodes_per_env: 1
steps_per_episode: 10
scenarios:
  - scenario_type: ""
    weight: 1.0
"#;
        let err = load_config(yaml).unwrap_err();
        assert!(matches!(err, CampaignError::Validation(ref msg) if msg.contains("scenario_type")));
    }

    #[test]
    fn load_config_file_nonexistent() {
        let err = load_config_file(std::path::Path::new("/nonexistent/campaign.yaml")).unwrap_err();
        assert!(matches!(err, CampaignError::Io(_)));
    }

    // --- Finding 68: 1 MiB file-size limit ---

    #[test]
    fn load_config_file_exceeds_max_size_returns_validation_error() {
        // Write a file larger than MAX_CONFIG_FILE_BYTES (1 MiB = 1_048_576 bytes).
        let tmp_path = std::env::temp_dir().join("invariant_oversized_campaign.yaml");
        // Fill with 1 MiB + 1 byte of spaces (valid UTF-8 but not valid YAML campaign).
        let big_content = " ".repeat(1024 * 1024 + 1);
        std::fs::write(&tmp_path, big_content).expect("write oversized file");

        let err = load_config_file(&tmp_path).unwrap_err();
        let _ = std::fs::remove_file(&tmp_path); // cleanup
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("exceeds maximum size")),
            "expected Validation error about max size, got: {err:?}"
        );
    }

    // --- Finding 69: MAX_TOTAL_COMMANDS boundary ---

    #[test]
    fn total_commands_at_max_is_valid() {
        // MAX_TOTAL_COMMANDS = 100_000_000.
        // 100 envs × 1 ep × 1_000_000 steps = 100_000_000 exactly.
        let config = CampaignConfig {
            name: "boundary_test".to_string(),
            profile: "franka_panda".to_string(),
            environments: 100,
            episodes_per_env: 1,
            steps_per_episode: 1_000_000,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        // Exactly at the limit: must succeed.
        assert!(
            validate_config(&config).is_ok(),
            "total == MAX_TOTAL_COMMANDS must be valid"
        );
    }

    #[test]
    fn total_commands_above_max_returns_validation_error() {
        // 101 envs × 1 ep × 1_000_000 steps = 101_000_000 > MAX_TOTAL_COMMANDS.
        let config = CampaignConfig {
            name: "over_limit".to_string(),
            profile: "franka_panda".to_string(),
            environments: 101,
            episodes_per_env: 1,
            steps_per_episode: 1_000_000,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let err = validate_config(&config).unwrap_err();
        assert!(matches!(err, CampaignError::Validation(_)));
    }

    // --- Finding 70: MAX_ENVIRONMENTS and MAX_EPISODES_PER_ENV upper bounds ---

    #[test]
    fn environments_above_max_returns_validation_error() {
        let config = CampaignConfig {
            name: "too_many_envs".to_string(),
            profile: "franka_panda".to_string(),
            environments: 10_001, // MAX_ENVIRONMENTS + 1
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let err = validate_config(&config).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("environments")),
            "got: {err:?}"
        );
    }

    #[test]
    fn episodes_per_env_above_max_returns_validation_error() {
        let config = CampaignConfig {
            name: "too_many_eps".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 100_001, // MAX_EPISODES_PER_ENV + 1
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let err = validate_config(&config).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("episodes_per_env")),
            "got: {err:?}"
        );
    }

    #[test]
    fn steps_per_episode_above_max_returns_validation_error() {
        let config = CampaignConfig {
            name: "too_many_steps".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1_000_001, // MAX_STEPS_PER_EPISODE + 1
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let err = validate_config(&config).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("steps_per_episode")),
            "got: {err:?}"
        );
    }

    // --- Finding 71: success_criteria out-of-range ---

    #[test]
    fn min_legitimate_pass_rate_above_one_returns_validation_error() {
        let yaml = r#"
name: tc
profile: franka_panda
environments: 1
episodes_per_env: 1
steps_per_episode: 1
scenarios:
  - scenario_type: Baseline
    weight: 1.0
success_criteria:
  min_legitimate_pass_rate: 1.1
  max_violation_escape_rate: 0.0
  max_false_rejection_rate: 0.0
"#;
        let err = load_config(yaml).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("min_legitimate_pass_rate")),
            "got: {err:?}"
        );
    }

    #[test]
    fn min_legitimate_pass_rate_below_zero_returns_validation_error() {
        let config = CampaignConfig {
            name: "tc".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria {
                min_legitimate_pass_rate: -0.01,
                max_violation_escape_rate: 0.0,
                max_false_rejection_rate: 0.0,
            },
        };
        let err = validate_config(&config).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("min_legitimate_pass_rate")),
            "got: {err:?}"
        );
    }

    #[test]
    fn max_violation_escape_rate_above_one_returns_validation_error() {
        let config = CampaignConfig {
            name: "tc".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria {
                min_legitimate_pass_rate: 0.98,
                max_violation_escape_rate: 1.5,
                max_false_rejection_rate: 0.02,
            },
        };
        let err = validate_config(&config).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("max_violation_escape_rate")),
            "got: {err:?}"
        );
    }

    #[test]
    fn max_violation_escape_rate_below_zero_returns_validation_error() {
        let config = CampaignConfig {
            name: "tc".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria {
                min_legitimate_pass_rate: 0.98,
                max_violation_escape_rate: -0.1,
                max_false_rejection_rate: 0.02,
            },
        };
        let err = validate_config(&config).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("max_violation_escape_rate")),
            "got: {err:?}"
        );
    }

    #[test]
    fn max_false_rejection_rate_above_one_returns_validation_error() {
        let config = CampaignConfig {
            name: "tc".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria {
                min_legitimate_pass_rate: 0.98,
                max_violation_escape_rate: 0.0,
                max_false_rejection_rate: 2.0,
            },
        };
        let err = validate_config(&config).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("max_false_rejection_rate")),
            "got: {err:?}"
        );
    }

    #[test]
    fn max_false_rejection_rate_below_zero_returns_validation_error() {
        let config = CampaignConfig {
            name: "tc".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria {
                min_legitimate_pass_rate: 0.98,
                max_violation_escape_rate: 0.0,
                max_false_rejection_rate: -0.5,
            },
        };
        let err = validate_config(&config).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("max_false_rejection_rate")),
            "got: {err:?}"
        );
    }

    // --- Finding 72: empty profile string ---

    #[test]
    fn empty_profile_returns_validation_error() {
        let yaml = r#"
name: tc
profile: ""
environments: 1
episodes_per_env: 1
steps_per_episode: 1
scenarios:
  - scenario_type: Baseline
    weight: 1.0
"#;
        let err = load_config(yaml).unwrap_err();
        assert!(
            matches!(&err, CampaignError::Validation(msg) if msg.contains("profile")),
            "got: {err:?}"
        );
    }

    // ── Execution target constants ──────────────────────────────────

    #[test]
    fn execution_target_episodes_per_shard_consistent() {
        use super::execution_target::*;
        assert_eq!(EPISODES_PER_SHARD, TOTAL_EPISODES / SHARDS as u64);
        assert_eq!(EPISODES_PER_SHARD, 1_875_000);
    }

    #[test]
    fn execution_target_profile_count_consistent() {
        use super::execution_target::*;
        assert_eq!(PROFILE_COUNT, REAL_WORLD_PROFILES + ADVERSARIAL_PROFILES);
        assert_eq!(PROFILE_COUNT, 34);
    }

    #[test]
    fn execution_target_validation_rate() {
        use super::execution_target::*;
        assert_eq!(VALIDATION_RATE_HZ, 200);
        // 200 Hz = 5 ms per step
        assert_eq!(1000 / VALIDATION_RATE_HZ, 5);
    }

    #[test]
    fn execution_target_step_range() {
        use super::execution_target::*;
        assert_eq!(MIN_EPISODE_STEPS, 200);
        assert_eq!(MAX_EPISODE_STEPS, 1000);
        assert!(MIN_EPISODE_STEPS < MAX_EPISODE_STEPS);
    }

    // ── Scenario step count mapping ─────────────────────────────────

    #[test]
    fn scenario_step_count_normal_scenarios_200() {
        assert_eq!(super::scenario_step_count("baseline"), 200);
        assert_eq!(super::scenario_step_count("aggressive"), 200);
        assert_eq!(super::scenario_step_count("prompt_injection"), 200);
        assert_eq!(super::scenario_step_count("exclusion_zone"), 200);
        assert_eq!(super::scenario_step_count("authority_escalation"), 200);
        assert_eq!(super::scenario_step_count("chain_forgery"), 200);
        assert_eq!(super::scenario_step_count("locomotion_runaway"), 200);
    }

    #[test]
    fn scenario_step_count_compound_recovery_500() {
        assert_eq!(super::scenario_step_count("compound_authority_physics"), 500);
        assert_eq!(super::scenario_step_count("compound_sensor_spatial"), 500);
        assert_eq!(super::scenario_step_count("compound_drift_then_violation"), 500);
        assert_eq!(super::scenario_step_count("compound_environment_physics"), 500);
        assert_eq!(super::scenario_step_count("recovery_safe_stop"), 500);
        assert_eq!(super::scenario_step_count("recovery_audit_integrity"), 500);
    }

    #[test]
    fn scenario_step_count_long_running_1000() {
        assert_eq!(super::scenario_step_count("long_running_stability"), 1000);
        assert_eq!(super::scenario_step_count("long_running_threat"), 1000);
    }

    #[test]
    fn scenario_step_count_within_spec_range() {
        use super::execution_target::*;
        let scenarios = super::all_scenario_entries();
        for sc in &scenarios {
            let steps = super::scenario_step_count(&sc.scenario_type);
            assert!(
                steps >= MIN_EPISODE_STEPS && steps <= MAX_EPISODE_STEPS,
                "scenario {} has {} steps, must be in [{}, {}]",
                sc.scenario_type, steps, MIN_EPISODE_STEPS, MAX_EPISODE_STEPS
            );
        }
    }

    // ── 15M campaign config generator tests ───────────────────────────

    // ── Scenario categories (Section 2.1) ────────────────────────────

    #[test]
    fn scenario_categories_count() {
        use super::scenario_categories::*;
        assert_eq!(ScenarioCategory::all().len(), CATEGORY_COUNT);
        assert_eq!(CATEGORY_COUNT, 14);
    }

    #[test]
    fn scenario_categories_total_scenarios() {
        use super::scenario_categories::*;
        let sum: u32 = ScenarioCategory::all().iter().map(|c| c.scenarios()).sum();
        assert_eq!(sum, TOTAL_SCENARIOS);
        assert_eq!(TOTAL_SCENARIOS, 104);
    }

    #[test]
    fn scenario_categories_total_episodes() {
        use super::scenario_categories::*;
        let sum: u64 = ScenarioCategory::all().iter().map(|c| c.episodes()).sum();
        assert_eq!(sum, TOTAL_EPISODES);
        assert_eq!(TOTAL_EPISODES, 15_000_000);
    }

    #[test]
    fn scenario_categories_letters_a_through_n() {
        use super::scenario_categories::*;
        let letters: Vec<char> = ScenarioCategory::all().iter().map(|c| c.letter()).collect();
        assert_eq!(
            letters,
            vec!['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N']
        );
    }

    #[test]
    fn scenario_categories_unique_letters() {
        use super::scenario_categories::*;
        let mut letters: Vec<char> = ScenarioCategory::all().iter().map(|c| c.letter()).collect();
        letters.sort();
        letters.dedup();
        assert_eq!(letters.len(), CATEGORY_COUNT);
    }

    #[test]
    fn scenario_categories_all_have_nonzero_episodes() {
        use super::scenario_categories::*;
        for cat in ScenarioCategory::all() {
            assert!(
                cat.episodes() > 0,
                "category {} must have > 0 episodes",
                cat.letter()
            );
        }
    }

    #[test]
    fn scenario_categories_all_have_nonzero_scenarios() {
        use super::scenario_categories::*;
        for cat in ScenarioCategory::all() {
            assert!(
                cat.scenarios() > 0,
                "category {} must have > 0 scenarios",
                cat.letter()
            );
        }
    }

    #[test]
    fn scenario_categories_weights_sum_to_one() {
        use super::scenario_categories::*;
        let sum: f64 = ScenarioCategory::all().iter().map(|c| c.weight()).sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "category weights must sum to 1.0, got {sum}"
        );
    }

    #[test]
    fn scenario_categories_normal_operation_largest() {
        use super::scenario_categories::*;
        let normal = ScenarioCategory::NormalOperation;
        for cat in ScenarioCategory::all() {
            assert!(
                normal.episodes() >= cat.episodes(),
                "Normal Operation (A) should have the most episodes, but {} has more",
                cat.letter()
            );
        }
    }

    #[test]
    fn scenario_categories_display_format() {
        use super::scenario_categories::ScenarioCategory;
        let display = format!("{}", ScenarioCategory::NormalOperation);
        assert_eq!(display, "A: Normal Operation");
        let display = format!("{}", ScenarioCategory::AdversarialRedTeam);
        assert_eq!(display, "N: Adversarial Red Team");
    }

    #[test]
    fn scenario_categories_purpose_nonempty() {
        use super::scenario_categories::*;
        for cat in ScenarioCategory::all() {
            assert!(
                !cat.purpose().is_empty(),
                "category {} must have a purpose",
                cat.letter()
            );
        }
    }

    #[test]
    fn scenario_categories_name_nonempty() {
        use super::scenario_categories::*;
        for cat in ScenarioCategory::all() {
            assert!(
                !cat.name().is_empty(),
                "category {} must have a name",
                cat.letter()
            );
        }
    }

    #[test]
    fn scenario_categories_serialization_round_trip() {
        use super::scenario_categories::ScenarioCategory;
        let cat = ScenarioCategory::CognitiveEscape;
        let json = serde_json::to_string(&cat).expect("must serialize");
        let back: ScenarioCategory = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(back, cat);
    }

    #[test]
    fn scenario_categories_episodes_consistent_with_execution_target() {
        use super::scenario_categories;
        use super::execution_target;
        assert_eq!(
            scenario_categories::TOTAL_EPISODES,
            execution_target::TOTAL_EPISODES,
            "scenario categories total must match execution target total"
        );
    }

    // ── 15M campaign config generator tests ───────────────────────────

    #[test]
    fn generate_15m_produces_tiered_configs_for_all_profiles() {
        let configs = generate_15m_configs(15_000_000, 8);
        // 34 profiles × 3 step tiers × 8 shards = 816 configs
        // (each profile has scenarios in all 3 tiers: 200, 500, 1000)
        assert_eq!(configs.len(), 816, "34 profiles × 3 tiers × 8 shards");
    }

    #[test]
    fn generate_15m_total_episodes_approximately_correct() {
        let configs = generate_15m_configs(15_000_000, 8);
        let total: u64 = configs
            .iter()
            .map(|c| c.environments as u64 * c.episodes_per_env as u64)
            .sum();
        // Allow 5% tolerance due to integer rounding across profiles × tiers × shards
        assert!(
            (14_000_000..=16_000_000).contains(&total),
            "total episodes {total} should be ~15M"
        );
    }

    #[test]
    fn generate_15m_all_configs_have_scenarios() {
        let configs = generate_15m_configs(15_000_000, 8);
        for config in &configs {
            assert!(
                !config.scenarios.is_empty(),
                "config {} must have scenarios",
                config.name
            );
        }
    }

    #[test]
    fn generate_15m_configs_have_correct_step_counts() {
        let configs = generate_15m_configs(15_000_000, 8);
        for config in &configs {
            let expected_steps = config
                .scenarios
                .iter()
                .map(|s| super::scenario_step_count(&s.scenario_type))
                .next()
                .unwrap();
            assert_eq!(
                config.steps_per_episode, expected_steps,
                "config {} steps_per_episode must match scenario tier",
                config.name
            );
        }
    }

    #[test]
    fn generate_15m_locomotion_profiles_have_locomotion_scenarios() {
        let configs = generate_15m_configs(15_000_000, 8);
        let humanoid_configs: Vec<_> = configs
            .iter()
            .filter(|c| c.name.starts_with("15m_humanoid_28dof_"))
            .collect();
        assert!(
            humanoid_configs
                .iter()
                .any(|c| c.scenarios.iter().any(|s| s.scenario_type == "locomotion_runaway")),
            "humanoid must have locomotion_runaway scenario in some tier"
        );
    }

    #[test]
    fn generate_15m_arm_profiles_skip_locomotion_scenarios() {
        let configs = generate_15m_configs(15_000_000, 8);
        let panda_configs: Vec<_> = configs
            .iter()
            .filter(|c| c.name.starts_with("15m_franka_panda_"))
            .collect();
        for config in &panda_configs {
            assert!(
                !config
                    .scenarios
                    .iter()
                    .any(|s| s.scenario_type.starts_with("locomotion_")),
                "franka_panda must not have locomotion scenarios"
            );
        }
    }

    #[test]
    fn generate_15m_configs_serializable_to_yaml() {
        let configs = generate_15m_configs(1_000_000, 2);
        let yaml = configs_to_yaml(&configs).expect("must serialize");
        assert!(yaml.contains("15m_"));
        assert!(yaml.contains("scenarios:"));
    }

    #[test]
    fn generate_15m_success_criteria_strict() {
        let configs = generate_15m_configs(15_000_000, 8);
        for config in &configs {
            assert_eq!(
                config.success_criteria.max_violation_escape_rate, 0.0,
                "zero escape rate required for {}",
                config.name
            );
        }
    }

    #[test]
    fn generate_15m_step_tiers_present() {
        let configs = generate_15m_configs(15_000_000, 8);
        let step_counts: std::collections::BTreeSet<u32> =
            configs.iter().map(|c| c.steps_per_episode).collect();
        assert!(step_counts.contains(&200), "must have 200-step configs");
        assert!(step_counts.contains(&500), "must have 500-step configs");
        assert!(step_counts.contains(&1000), "must have 1000-step configs");
    }

    #[test]
    fn generate_15m_majority_episodes_are_short() {
        let configs = generate_15m_configs(15_000_000, 8);
        let short_episodes: u64 = configs
            .iter()
            .filter(|c| c.steps_per_episode == 200)
            .map(|c| c.environments as u64 * c.episodes_per_env as u64)
            .sum();
        let total_episodes: u64 = configs
            .iter()
            .map(|c| c.environments as u64 * c.episodes_per_env as u64)
            .sum();
        let fraction = short_episodes as f64 / total_episodes as f64;
        assert!(
            fraction > 0.50,
            "majority of episodes should be 200-step (got {:.1}%)",
            fraction * 100.0
        );
    }

    // ── Data output constants (Section 1.2) ─────────────────────────

    #[test]
    fn data_outputs_estimated_total_commands() {
        use super::data_outputs::*;
        use super::execution_target::*;
        assert_eq!(ESTIMATED_TOTAL_COMMANDS, TOTAL_EPISODES * AVG_STEPS_PER_EPISODE);
        assert_eq!(ESTIMATED_TOTAL_COMMANDS, 3_000_000_000);
    }

    #[test]
    fn data_outputs_size_range_valid() {
        use super::data_outputs::*;
        assert!(ESTIMATED_OUTPUT_GB_LOW < ESTIMATED_OUTPUT_GB_HIGH);
        assert_eq!(ESTIMATED_OUTPUT_GB_LOW, 150);
        assert_eq!(ESTIMATED_OUTPUT_GB_HIGH, 200);
    }

    #[test]
    fn data_outputs_per_step_compression_plausible() {
        use super::data_outputs::*;
        // Verify the per-step estimates are consistent with the total output range.
        let bytes_per_step = ESTIMATED_BYTES_PER_STEP_COMPRESSED + CHAIN_OVERHEAD_BYTES_PER_STEP_COMPRESSED;
        let total_bytes = ESTIMATED_TOTAL_COMMANDS * bytes_per_step;
        let total_gb = total_bytes / (1024 * 1024 * 1024);
        assert!(
            total_gb >= ESTIMATED_OUTPUT_GB_LOW && total_gb <= ESTIMATED_OUTPUT_GB_HIGH * 2,
            "per-step estimate ({bytes_per_step} B/step) yields {total_gb} GB, expected ~{ESTIMATED_OUTPUT_GB_LOW}-{ESTIMATED_OUTPUT_GB_HIGH} GB"
        );
    }

    // ── EpisodeOutput tests ─────────────────────────────────────────

    #[test]
    fn episode_output_is_clean_when_no_escapes() {
        use super::data_outputs::EpisodeOutput;
        let output = EpisodeOutput {
            episode_id: 0,
            shard_id: 0,
            seed: 42,
            profile_name: "franka_panda".into(),
            scenario_type: "baseline".into(),
            step_count: 200,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            verdict_chain_hash: "sha256:abc".into(),
            verdict_chain_signature: "sig".into(),
            signer_kid: "kid-1".into(),
            commands_approved: 195,
            commands_rejected: 5,
            violation_escapes: 0,
            false_rejections: 0,
            checks_evaluated: 1200,
            checks_failed: 5,
        };
        assert!(output.is_clean());
    }

    #[test]
    fn episode_output_not_clean_when_escapes() {
        use super::data_outputs::EpisodeOutput;
        let output = EpisodeOutput {
            episode_id: 1,
            shard_id: 0,
            seed: 99,
            profile_name: "ur10".into(),
            scenario_type: "authority_escalation".into(),
            step_count: 200,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            verdict_chain_hash: "sha256:def".into(),
            verdict_chain_signature: "sig2".into(),
            signer_kid: "kid-1".into(),
            commands_approved: 1,
            commands_rejected: 199,
            violation_escapes: 1,
            false_rejections: 0,
            checks_evaluated: 1200,
            checks_failed: 199,
        };
        assert!(!output.is_clean());
    }

    #[test]
    fn episode_output_approval_rate() {
        use super::data_outputs::EpisodeOutput;
        let output = EpisodeOutput {
            episode_id: 0,
            shard_id: 0,
            seed: 1,
            profile_name: "franka_panda".into(),
            scenario_type: "baseline".into(),
            step_count: 100,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            verdict_chain_hash: "sha256:x".into(),
            verdict_chain_signature: "sig".into(),
            signer_kid: "kid".into(),
            commands_approved: 80,
            commands_rejected: 20,
            violation_escapes: 0,
            false_rejections: 0,
            checks_evaluated: 600,
            checks_failed: 20,
        };
        assert!((output.approval_rate() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn episode_output_approval_rate_zero_steps() {
        use super::data_outputs::EpisodeOutput;
        let output = EpisodeOutput {
            episode_id: 0,
            shard_id: 0,
            seed: 0,
            profile_name: "franka_panda".into(),
            scenario_type: "baseline".into(),
            step_count: 0,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            verdict_chain_hash: String::new(),
            verdict_chain_signature: String::new(),
            signer_kid: String::new(),
            commands_approved: 0,
            commands_rejected: 0,
            violation_escapes: 0,
            false_rejections: 0,
            checks_evaluated: 0,
            checks_failed: 0,
        };
        assert!((output.approval_rate()).abs() < f64::EPSILON);
    }

    #[test]
    fn episode_output_serialization_round_trip() {
        use super::data_outputs::EpisodeOutput;
        let output = EpisodeOutput {
            episode_id: 42,
            shard_id: 3,
            seed: 0xDEAD_BEEF_CAFE_1234,
            profile_name: "humanoid_28dof".into(),
            scenario_type: "compound_authority_physics".into(),
            step_count: 500,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            verdict_chain_hash: "sha256:terminal".into(),
            verdict_chain_signature: "ed25519:final_sig".into(),
            signer_kid: "validator-key-2".into(),
            commands_approved: 490,
            commands_rejected: 10,
            violation_escapes: 0,
            false_rejections: 0,
            checks_evaluated: 3000,
            checks_failed: 10,
        };
        let json = serde_json::to_string(&output).expect("must serialize");
        let back: EpisodeOutput = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(back.episode_id, 42);
        assert_eq!(back.shard_id, 3);
        assert_eq!(back.seed, 0xDEAD_BEEF_CAFE_1234);
        assert_eq!(back.step_count, 500);
        assert_eq!(back.violation_escapes, 0);
    }

    // ── ShardOutputSummary tests ────────────────────────────────────

    #[test]
    fn shard_output_summary_is_clean() {
        use super::data_outputs::ShardOutputSummary;
        let summary = ShardOutputSummary {
            shard_id: 0,
            episodes_completed: 1_875_000,
            total_steps: 375_000_000,
            total_commands_approved: 370_000_000,
            total_commands_rejected: 5_000_000,
            total_violation_escapes: 0,
            total_false_rejections: 100,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output_size_bytes: 20_000_000_000,
            final_chain_hash: "sha256:shard0".into(),
        };
        assert!(summary.is_clean());
    }

    #[test]
    fn shard_output_summary_not_clean_on_escape() {
        use super::data_outputs::ShardOutputSummary;
        let summary = ShardOutputSummary {
            shard_id: 1,
            episodes_completed: 1_875_000,
            total_steps: 375_000_000,
            total_commands_approved: 370_000_001,
            total_commands_rejected: 4_999_999,
            total_violation_escapes: 1,
            total_false_rejections: 0,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output_size_bytes: 20_000_000_000,
            final_chain_hash: "sha256:shard1".into(),
        };
        assert!(!summary.is_clean());
    }

    #[test]
    fn shard_output_summary_serialization_round_trip() {
        use super::data_outputs::ShardOutputSummary;
        let summary = ShardOutputSummary {
            shard_id: 7,
            episodes_completed: 1_875_000,
            total_steps: 375_000_000,
            total_commands_approved: 370_000_000,
            total_commands_rejected: 5_000_000,
            total_violation_escapes: 0,
            total_false_rejections: 50,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output_size_bytes: 19_500_000_000,
            final_chain_hash: "sha256:shard7final".into(),
        };
        let json = serde_json::to_string(&summary).expect("must serialize");
        let back: ShardOutputSummary = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(back.shard_id, 7);
        assert_eq!(back.episodes_completed, 1_875_000);
        assert_eq!(back.total_violation_escapes, 0);
    }

    // ── Category B: Joint Safety ──────────────────────────────────────

    #[test]
    fn joint_safety_scenario_count() {
        use super::joint_safety::*;
        assert_eq!(SCENARIO_COUNT, 8);
        assert_eq!(JointSafetyScenario::all().len(), SCENARIO_COUNT as usize);
    }

    #[test]
    fn joint_safety_total_episodes() {
        use super::joint_safety::*;
        assert_eq!(TOTAL_EPISODES, 1_500_000);
        let sum: u64 = JointSafetyScenario::all().iter().map(|s| s.episodes()).sum();
        assert_eq!(sum, TOTAL_EPISODES);
    }

    #[test]
    fn joint_safety_episodes_consistent_with_category() {
        use super::joint_safety;
        use super::scenario_categories::ScenarioCategory;
        assert_eq!(
            joint_safety::TOTAL_EPISODES,
            ScenarioCategory::JointSafety.episodes(),
        );
    }

    #[test]
    fn joint_safety_scenario_count_consistent_with_category() {
        use super::joint_safety;
        use super::scenario_categories::ScenarioCategory;
        assert_eq!(
            joint_safety::SCENARIO_COUNT,
            ScenarioCategory::JointSafety.scenarios(),
        );
    }

    #[test]
    fn joint_safety_ids_sequential() {
        use super::joint_safety::JointSafetyScenario;
        let ids: Vec<&str> = JointSafetyScenario::all().iter().map(|s| s.id()).collect();
        assert_eq!(
            ids,
            vec!["B-01", "B-02", "B-03", "B-04", "B-05", "B-06", "B-07", "B-08"]
        );
    }

    #[test]
    fn joint_safety_steps_within_spec_range() {
        use super::joint_safety::JointSafetyScenario;
        for s in JointSafetyScenario::all() {
            assert!(
                s.steps() >= 200 && s.steps() <= 1000,
                "{} has {} steps, must be in [200, 1000]",
                s.id(),
                s.steps()
            );
        }
    }

    #[test]
    fn joint_safety_steps_match_scenario_step_count() {
        use super::joint_safety::JointSafetyScenario;
        for s in JointSafetyScenario::all() {
            assert_eq!(
                s.steps(),
                super::scenario_step_count(s.scenario_type_name()),
                "{} steps must match scenario_step_count(\"{}\")",
                s.id(),
                s.scenario_type_name()
            );
        }
    }

    #[test]
    fn joint_safety_specific_episode_allocations() {
        use super::joint_safety::JointSafetyScenario::*;
        assert_eq!(PositionBoundarySweep.episodes(), 200_000);
        assert_eq!(VelocityBoundarySweep.episodes(), 200_000);
        assert_eq!(TorqueBoundarySweep.episodes(), 200_000);
        assert_eq!(AccelerationRamp.episodes(), 200_000);
        assert_eq!(MultiJointCoordinatedViolation.episodes(), 150_000);
        assert_eq!(RapidDirectionReversal.episodes(), 150_000);
        assert_eq!(Ieee754SpecialValues.episodes(), 200_000);
        assert_eq!(GradualDriftAttack.episodes(), 200_000);
    }

    #[test]
    fn joint_safety_specific_step_counts() {
        use super::joint_safety::JointSafetyScenario::*;
        assert_eq!(PositionBoundarySweep.steps(), 200);
        assert_eq!(VelocityBoundarySweep.steps(), 200);
        assert_eq!(TorqueBoundarySweep.steps(), 200);
        assert_eq!(AccelerationRamp.steps(), 300);
        assert_eq!(MultiJointCoordinatedViolation.steps(), 200);
        assert_eq!(RapidDirectionReversal.steps(), 200);
        assert_eq!(Ieee754SpecialValues.steps(), 200);
        assert_eq!(GradualDriftAttack.steps(), 500);
    }

    #[test]
    fn joint_safety_zero_escape_rate() {
        use super::joint_safety::*;
        assert!((MAX_VIOLATION_ESCAPE_RATE).abs() < f64::EPSILON);
    }

    #[test]
    fn joint_safety_all_scenarios_have_names() {
        use super::joint_safety::JointSafetyScenario;
        for s in JointSafetyScenario::all() {
            assert!(!s.name().is_empty(), "{} must have a name", s.id());
        }
    }

    #[test]
    fn joint_safety_all_scenarios_have_expected_verdicts() {
        use super::joint_safety::JointSafetyScenario;
        for s in JointSafetyScenario::all() {
            assert!(
                !s.expected_verdict().is_empty(),
                "{} must have an expected verdict",
                s.id()
            );
        }
    }

    #[test]
    fn joint_safety_all_scenarios_have_invariants() {
        use super::joint_safety::JointSafetyScenario;
        for s in JointSafetyScenario::all() {
            assert!(
                !s.invariants_tested().is_empty(),
                "{} must test at least one invariant",
                s.id()
            );
        }
    }

    #[test]
    fn joint_safety_invariants_are_p1_through_p4() {
        use super::joint_safety::JointSafetyScenario;
        let valid = ["P1", "P2", "P3", "P4"];
        for s in JointSafetyScenario::all() {
            for inv in s.invariants_tested() {
                assert!(
                    valid.contains(inv),
                    "{} references invariant {} which is not P1-P4",
                    s.id(),
                    inv
                );
            }
        }
    }

    #[test]
    fn joint_safety_display_format() {
        use super::joint_safety::JointSafetyScenario;
        let display = format!("{}", JointSafetyScenario::PositionBoundarySweep);
        assert_eq!(display, "B-01: Position boundary sweep");
    }

    #[test]
    fn joint_safety_serialization_round_trip() {
        use super::joint_safety::JointSafetyScenario;
        let s = JointSafetyScenario::Ieee754SpecialValues;
        let json = serde_json::to_string(&s).expect("must serialize");
        let back: JointSafetyScenario = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(back, s);
    }

    #[test]
    fn joint_safety_all_scenarios_unique() {
        use super::joint_safety::JointSafetyScenario;
        let scenarios: Vec<_> = JointSafetyScenario::all().to_vec();
        for (i, a) in scenarios.iter().enumerate() {
            for (j, b) in scenarios.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "scenarios must be unique");
                }
            }
        }
    }

    #[test]
    fn joint_safety_scenario_type_names_nonempty() {
        use super::joint_safety::JointSafetyScenario;
        for s in JointSafetyScenario::all() {
            assert!(
                !s.scenario_type_name().is_empty(),
                "{} must have a scenario_type_name",
                s.id()
            );
        }
    }

    #[test]
    fn joint_safety_scenario_step_count_entries() {
        assert_eq!(super::scenario_step_count("acceleration_ramp"), 300);
        assert_eq!(super::scenario_step_count("gradual_drift_attack"), 500);
        assert_eq!(super::scenario_step_count("position_boundary_sweep"), 200);
        assert_eq!(super::scenario_step_count("velocity_boundary_sweep"), 200);
        assert_eq!(super::scenario_step_count("torque_boundary_sweep"), 200);
        assert_eq!(super::scenario_step_count("multi_joint_coordinated_violation"), 200);
        assert_eq!(super::scenario_step_count("rapid_direction_reversal"), 200);
        assert_eq!(super::scenario_step_count("ieee754_special_values"), 200);
    }
}
