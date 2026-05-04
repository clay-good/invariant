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
// 15M Campaign — Proof of Safety (Purpose)
// ---------------------------------------------------------------------------

/// Statistical proof of safety constants from the campaign specification (Purpose).
///
/// At 15M validated decisions with zero bypasses, the 99.9% confidence upper
/// bound on the bypass rate is < 0.0000461% — fewer than 1 in 2.2 million.
///
/// The math: for a Bernoulli process with `n` trials and 0 observed failures,
/// the one-sided Clopper-Pearson upper bound at confidence level `c` is:
///
///   p_upper = 1 - (1 - c)^(1/n)
///
/// With n = 15,000,000 and c = 0.999:
///
///   p_upper = 1 - 0.001^(1/15_000_000) ≈ 4.605e-7 ≈ 0.0000461%
pub mod proof_of_safety {
    /// Confidence level for the statistical proof (99.9%).
    pub const CONFIDENCE_LEVEL: f64 = 0.999;

    /// Total episodes required for the statistical proof.
    pub const REQUIRED_EPISODES: u64 = 15_000_000;

    /// Upper bound on bypass rate at 99.9% confidence with zero failures
    /// across 15M episodes (as a fraction, not percentage).
    ///
    /// `1 - (1 - 0.999)^(1/15_000_000) ≈ 4.605e-7`
    pub const BYPASS_RATE_UPPER_BOUND: f64 = 4.605e-7;

    /// The reciprocal of the bypass rate upper bound: one bypass per this
    /// many decisions at most (≈ 2.17 million).
    pub const ONE_IN_N_DECISIONS: u64 = 2_171_472;

    /// Compute the one-sided Clopper-Pearson upper bound on failure rate
    /// given `n` trials, 0 observed failures, and confidence level `c`.
    ///
    /// Returns `1 - (1 - c)^(1/n)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::proof_of_safety::clopper_pearson_upper;
    ///
    /// let bound = clopper_pearson_upper(15_000_000, 0.999);
    /// assert!((bound - 4.605e-7).abs() < 1e-9);
    /// ```
    pub fn clopper_pearson_upper(n: u64, confidence: f64) -> f64 {
        1.0 - (1.0 - confidence).powf(1.0 / n as f64)
    }

    /// Returns `true` if the campaign results constitute statistical proof
    /// of safety: the required number of episodes were completed and zero
    /// violation escapes were observed.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::proof_of_safety::is_proof_of_safety;
    ///
    /// assert!(is_proof_of_safety(15_000_000, 0));
    /// assert!(!is_proof_of_safety(14_999_999, 0));
    /// assert!(!is_proof_of_safety(15_000_000, 1));
    /// ```
    pub fn is_proof_of_safety(episodes_completed: u64, violation_escapes: u64) -> bool {
        episodes_completed >= REQUIRED_EPISODES && violation_escapes == 0
    }
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
    /// Target hardware: GPU model used for each shard.
    pub const GPU_TYPE: &str = "NVIDIA A40";
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
    /// Estimated wall-clock time lower bound in hours (8x NVIDIA A40 on RunPod).
    pub const ESTIMATED_WALL_TIME_HOURS_LOW: u32 = 4;
    /// Estimated wall-clock time upper bound in hours (8x NVIDIA A40 on RunPod).
    pub const ESTIMATED_WALL_TIME_HOURS_HIGH: u32 = 6;
    /// Estimated RunPod cost lower bound in USD.
    pub const ESTIMATED_COST_USD_LOW: u32 = 30;
    /// Estimated RunPod cost upper bound in USD.
    pub const ESTIMATED_COST_USD_HIGH: u32 = 40;
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
    use sha2::{Digest, Sha256};

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

    // -----------------------------------------------------------------------
    // Verdict chain types
    // -----------------------------------------------------------------------

    /// Genesis hash used as `previous_hash` for the first entry in every chain.
    ///
    /// This is the all-zeros SHA-256 digest encoded as `sha256:` followed by
    /// 64 hex zeros — a value that cannot arise from real data and unambiguously
    /// marks the chain anchor.
    pub const GENESIS_HASH: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    /// Compute the SHA-256 of `data`, returning `"sha256:<hex>"`.
    fn sha256_hex(data: &[u8]) -> String {
        let digest = Sha256::digest(data);
        format!("sha256:{:064x}", digest)
    }

    /// A single entry in the verdict chain.
    ///
    /// Each entry commits to its step index, the hash of the `SignedVerdict`
    /// for that step, and the hash of the preceding entry.  The `entry_hash`
    /// field is the SHA-256 of the concatenation
    /// `step_le_bytes || previous_hash_bytes || verdict_hash_bytes`,
    /// which binds the entry irrevocably to its position and predecessor.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::data_outputs::{VerdictChainBuilder, GENESIS_HASH};
    ///
    /// let mut builder = VerdictChainBuilder::new();
    /// // An empty builder has the genesis hash as its terminal hash.
    /// assert_eq!(builder.terminal_hash(), GENESIS_HASH);
    /// ```
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct VerdictChainEntry {
        /// Zero-based step index within the episode.
        pub step: u64,
        /// SHA-256 of the JSON-serialised `SignedVerdict` for this step.
        pub verdict_hash: String,
        /// Hash of the preceding entry, or [`GENESIS_HASH`] for step 0.
        pub previous_hash: String,
        /// SHA-256 of `step_le_bytes || previous_hash_bytes || verdict_hash_bytes`.
        ///
        /// Verifying this field for every entry in sequence proves the chain
        /// has not been modified or reordered.
        pub entry_hash: String,
    }

    impl VerdictChainEntry {
        /// Compute `entry_hash` from the constituent fields.
        ///
        /// The preimage is: `step.to_le_bytes() || previous_hash.as_bytes() || verdict_hash.as_bytes()`.
        fn compute_entry_hash(step: u64, previous_hash: &str, verdict_hash: &str) -> String {
            let mut input = Vec::with_capacity(8 + previous_hash.len() + verdict_hash.len());
            input.extend_from_slice(&step.to_le_bytes());
            input.extend_from_slice(previous_hash.as_bytes());
            input.extend_from_slice(verdict_hash.as_bytes());
            sha256_hex(&input)
        }
    }

    /// A hash-linked chain of verdict entries for a single simulation episode.
    ///
    /// The chain is built step-by-step via [`VerdictChainBuilder`] and can be
    /// verified in full with [`VerdictChain::verify`].  The terminal hash of the
    /// chain (the `entry_hash` of the last entry, or [`GENESIS_HASH`] for an
    /// empty episode) is stored in [`EpisodeOutput::verdict_chain_hash`] and
    /// signed with an Ed25519 key to form the tamper-proof audit record.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::data_outputs::{VerdictChainBuilder, GENESIS_HASH};
    ///
    /// let chain = VerdictChainBuilder::new().finalize();
    /// assert_eq!(chain.len(), 0);
    /// assert_eq!(chain.terminal_hash(), GENESIS_HASH);
    /// assert!(chain.verify());
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VerdictChain {
        /// Ordered entries, one per validated step.
        pub entries: Vec<VerdictChainEntry>,
    }

    impl VerdictChain {
        /// Number of entries in the chain.
        pub fn len(&self) -> usize {
            self.entries.len()
        }

        /// Returns `true` when the chain has no entries.
        pub fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }

        /// The hash of the last entry, or [`GENESIS_HASH`] for an empty chain.
        ///
        /// This value is stored in [`EpisodeOutput::verdict_chain_hash`] and
        /// signed with the validator's Ed25519 key.
        pub fn terminal_hash(&self) -> &str {
            self.entries
                .last()
                .map(|e| e.entry_hash.as_str())
                .unwrap_or(GENESIS_HASH)
        }

        /// Verify that every entry's `entry_hash` and `previous_hash` linkage
        /// is consistent with the chain starting from [`GENESIS_HASH`].
        ///
        /// Returns `true` if the chain is intact, `false` if any entry has
        /// been tampered with or if the order has been altered.
        ///
        /// # Examples
        ///
        /// ```
        /// use invariant_robotics_sim::campaign::data_outputs::VerdictChainBuilder;
        ///
        /// let mut builder = VerdictChainBuilder::new();
        /// builder.push_verdict_hash(0, "sha256:aaa");
        /// builder.push_verdict_hash(1, "sha256:bbb");
        /// let chain = builder.finalize();
        /// assert!(chain.verify());
        /// assert_eq!(chain.len(), 2);
        /// ```
        pub fn verify(&self) -> bool {
            let mut expected_prev = GENESIS_HASH.to_string();
            for entry in &self.entries {
                if entry.previous_hash != expected_prev {
                    return false;
                }
                let expected_hash = VerdictChainEntry::compute_entry_hash(
                    entry.step,
                    &entry.previous_hash,
                    &entry.verdict_hash,
                );
                if entry.entry_hash != expected_hash {
                    return false;
                }
                expected_prev = entry.entry_hash.clone();
            }
            true
        }
    }

    /// Incrementally builds a [`VerdictChain`] as steps are validated.
    ///
    /// One `VerdictChainBuilder` is created per episode and receives one
    /// verdict per step.  After all steps have been recorded, [`VerdictChainBuilder::finalize`]
    /// consumes the builder and returns the complete, verifiable chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::data_outputs::VerdictChainBuilder;
    ///
    /// let mut builder = VerdictChainBuilder::new();
    /// // Hash a verdict's JSON and push it into the chain.
    /// builder.push_verdict_hash(0, "sha256:deadbeef");
    /// builder.push_verdict_hash(1, "sha256:cafebabe");
    /// let chain = builder.finalize();
    /// assert_eq!(chain.len(), 2);
    /// assert!(chain.verify());
    /// ```
    pub struct VerdictChainBuilder {
        entries: Vec<VerdictChainEntry>,
        previous_hash: String,
    }

    impl Default for VerdictChainBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl VerdictChainBuilder {
        /// Create a new builder anchored at [`GENESIS_HASH`].
        pub fn new() -> Self {
            VerdictChainBuilder {
                entries: Vec::new(),
                previous_hash: GENESIS_HASH.to_string(),
            }
        }

        /// Current terminal hash (hash of the last pushed entry, or [`GENESIS_HASH`]).
        pub fn terminal_hash(&self) -> &str {
            &self.previous_hash
        }

        /// Append an entry using a pre-computed `verdict_hash`.
        ///
        /// Use this when you have already serialised and hashed the
        /// `SignedVerdict` externally.
        ///
        /// Returns a reference to the newly appended [`VerdictChainEntry`].
        pub fn push_verdict_hash(&mut self, step: u64, verdict_hash: &str) -> &VerdictChainEntry {
            let entry_hash =
                VerdictChainEntry::compute_entry_hash(step, &self.previous_hash, verdict_hash);
            let entry = VerdictChainEntry {
                step,
                verdict_hash: verdict_hash.to_string(),
                previous_hash: self.previous_hash.clone(),
                entry_hash: entry_hash.clone(),
            };
            self.previous_hash = entry_hash;
            self.entries.push(entry);
            self.entries.last().unwrap()
        }

        /// Append an entry by hashing the JSON-serialised `SignedVerdict`.
        ///
        /// Serialises `verdict` to JSON, hashes it with SHA-256, and appends
        /// the resulting entry to the chain.  Returns `None` if serialisation
        /// fails (which cannot happen for well-formed `SignedVerdict` values).
        pub fn push_signed_verdict(
            &mut self,
            step: u64,
            verdict: &invariant_core::models::verdict::SignedVerdict,
        ) -> Option<&VerdictChainEntry> {
            let json = serde_json::to_vec(verdict).ok()?;
            let verdict_hash = sha256_hex(&json);
            Some(self.push_verdict_hash(step, &verdict_hash))
        }

        /// Consume the builder and return the completed [`VerdictChain`].
        pub fn finalize(self) -> VerdictChain {
            VerdictChain {
                entries: self.entries,
            }
        }
    }

    /// A single step's command + verdict pair.
    ///
    /// This is the atomic unit of the campaign evidence trail: one command
    /// submitted to the validator and the signed verdict it produced. The
    /// full episode output consists of a sequence of these records plus
    /// aggregate statistics.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::data_outputs::StepRecord;
    ///
    /// let record = StepRecord {
    ///     step_index: 0,
    ///     command_hash: "sha256:cmd0".to_string(),
    ///     command_sequence: 1,
    ///     approved: true,
    ///     checks_evaluated: 6,
    ///     checks_failed: 0,
    ///     verdict_hash: "sha256:v0".to_string(),
    ///     previous_verdict_hash: None,
    /// };
    ///
    /// assert_eq!(record.step_index, 0);
    /// assert!(record.approved);
    /// assert!(record.previous_verdict_hash.is_none());
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StepRecord {
        /// Zero-based step index within the episode.
        pub step_index: u64,
        /// SHA-256 hash of the command submitted at this step.
        pub command_hash: String,
        /// Monotonic sequence number of the command.
        pub command_sequence: u64,
        /// Whether the command was approved (`true`) or rejected (`false`).
        pub approved: bool,
        /// Number of safety checks evaluated at this step.
        pub checks_evaluated: u32,
        /// Number of safety checks that failed at this step.
        pub checks_failed: u32,
        /// SHA-256 hash of the verdict at this step.
        pub verdict_hash: String,
        /// Hash of the previous step's verdict (forming the hash chain).
        ///
        /// `None` for the first step in an episode.
        pub previous_verdict_hash: Option<String>,
    }

    impl StepRecord {
        /// Returns `true` if this step links to a previous verdict (not the first step).
        pub fn is_chained(&self) -> bool {
            self.previous_verdict_hash.is_some()
        }
    }

    /// Estimate the compressed output size in bytes for a single episode.
    ///
    /// Uses the per-step size constants (`ESTIMATED_BYTES_PER_STEP_COMPRESSED`
    /// and `CHAIN_OVERHEAD_BYTES_PER_STEP_COMPRESSED`) to compute a compressed
    /// byte estimate for an episode with the given number of steps.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::data_outputs::estimate_episode_bytes;
    ///
    /// let bytes = estimate_episode_bytes(200);
    /// // 200 steps × (60 + 20) bytes/step = 16,000 bytes
    /// assert_eq!(bytes, 16_000);
    /// ```
    pub fn estimate_episode_bytes(steps: u64) -> u64 {
        steps * (ESTIMATED_BYTES_PER_STEP_COMPRESSED + CHAIN_OVERHEAD_BYTES_PER_STEP_COMPRESSED)
    }

    /// Estimate the total compressed output size in bytes for the full campaign.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::data_outputs::estimate_campaign_bytes;
    ///
    /// let bytes = estimate_campaign_bytes(15_000_000, 200);
    /// let gb = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    /// // Should be in the 150-200 GB range
    /// assert!(gb > 100.0 && gb < 300.0);
    /// ```
    pub fn estimate_campaign_bytes(total_episodes: u64, avg_steps: u64) -> u64 {
        total_episodes
            * avg_steps
            * (ESTIMATED_BYTES_PER_STEP_COMPRESSED + CHAIN_OVERHEAD_BYTES_PER_STEP_COMPRESSED)
    }

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

    /// Campaign-level manifest aggregating all shard outputs.
    ///
    /// This is the top-level data output record for the entire 15M campaign.
    /// It combines per-shard summaries into a single verifiable artifact that
    /// proves the campaign ran to completion with the claimed results.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::Utc;
    /// use invariant_robotics_sim::campaign::data_outputs::{CampaignOutputManifest, ShardOutputSummary};
    ///
    /// let shards: Vec<ShardOutputSummary> = (0..8u32).map(|i| ShardOutputSummary {
    ///     shard_id: i,
    ///     episodes_completed: 100,
    ///     total_steps: 20_000,
    ///     total_commands_approved: 19_000,
    ///     total_commands_rejected: 1_000,
    ///     total_violation_escapes: 0,
    ///     total_false_rejections: 5,
    ///     started_at: Utc::now(),
    ///     completed_at: Utc::now(),
    ///     output_size_bytes: 1_000_000,
    ///     final_chain_hash: format!("sha256:shard{i}"),
    /// }).collect();
    ///
    /// let manifest = CampaignOutputManifest::from_shards(shards);
    /// assert_eq!(manifest.total_episodes, 800);
    /// assert_eq!(manifest.total_steps, 160_000);
    /// assert_eq!(manifest.total_violation_escapes, 0);
    /// assert!(manifest.is_clean());
    /// assert_eq!(manifest.shard_count, 8);
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CampaignOutputManifest {
        /// Number of shards that contributed to this campaign.
        pub shard_count: u32,
        /// Total episodes completed across all shards.
        pub total_episodes: u64,
        /// Total steps executed across all shards.
        pub total_steps: u64,
        /// Total commands approved across all shards.
        pub total_commands_approved: u64,
        /// Total commands rejected across all shards.
        pub total_commands_rejected: u64,
        /// Total violation escapes across all shards (must be 0 for proof).
        pub total_violation_escapes: u64,
        /// Total false rejections across all shards.
        pub total_false_rejections: u64,
        /// Total compressed output size in bytes across all shards.
        pub total_output_size_bytes: u64,
        /// Per-shard final chain hashes, ordered by shard_id.
        pub shard_chain_hashes: Vec<String>,
        /// Per-shard summaries, ordered by shard_id.
        pub shards: Vec<ShardOutputSummary>,
    }

    impl CampaignOutputManifest {
        /// Aggregate a set of shard summaries into a campaign manifest.
        ///
        /// Shards are sorted by `shard_id` in the output.
        pub fn from_shards(mut shards: Vec<ShardOutputSummary>) -> Self {
            shards.sort_by_key(|s| s.shard_id);

            let shard_count = shards.len() as u32;
            let total_episodes = shards.iter().map(|s| s.episodes_completed).sum();
            let total_steps = shards.iter().map(|s| s.total_steps).sum();
            let total_commands_approved = shards.iter().map(|s| s.total_commands_approved).sum();
            let total_commands_rejected = shards.iter().map(|s| s.total_commands_rejected).sum();
            let total_violation_escapes = shards.iter().map(|s| s.total_violation_escapes).sum();
            let total_false_rejections = shards.iter().map(|s| s.total_false_rejections).sum();
            let total_output_size_bytes = shards.iter().map(|s| s.output_size_bytes).sum();
            let shard_chain_hashes = shards.iter().map(|s| s.final_chain_hash.clone()).collect();

            CampaignOutputManifest {
                shard_count,
                total_episodes,
                total_steps,
                total_commands_approved,
                total_commands_rejected,
                total_violation_escapes,
                total_false_rejections,
                total_output_size_bytes,
                shard_chain_hashes,
                shards,
            }
        }

        /// Returns `true` if the entire campaign had zero violation escapes.
        pub fn is_clean(&self) -> bool {
            self.total_violation_escapes == 0
        }

        /// Returns the campaign-wide approval rate.
        pub fn approval_rate(&self) -> f64 {
            let total = self.total_commands_approved + self.total_commands_rejected;
            if total == 0 {
                return 0.0;
            }
            self.total_commands_approved as f64 / total as f64
        }

        /// Returns the estimated output size in gigabytes.
        pub fn output_size_gb(&self) -> f64 {
            self.total_output_size_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
        }
    }
}

// ---------------------------------------------------------------------------
// 15M Campaign Scenario Categories (Section 2.1)
// ---------------------------------------------------------------------------

/// Scenario categories for the 15M campaign (Section 2.1 Overview).
///
/// The 15M campaign is divided into 14 categories (A–N), totaling 106
/// distinct scenarios and 15,000,000 episodes. Each category targets a
/// specific safety domain — from normal operation through adversarial
/// red-teaming — ensuring complete coverage of the Invariant firewall's
/// validation surface.
pub mod scenario_categories {
    use serde::{Deserialize, Serialize};

    /// Total number of scenario categories in the 15M campaign.
    pub const CATEGORY_COUNT: usize = 14;

    /// Total distinct scenarios across all categories.
    pub const TOTAL_SCENARIOS: u32 = 106;

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
    /// assert_eq!(cat.scenarios(), 8);
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
                NormalOperation => 8,
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
                SpatialSafety => "Prove P5-P7 catch every workspace/zone/collision violation",
                StabilityLocomotion => "Prove P9, P15-P20 catch every balance/gait failure",
                ManipulationSafety => "Prove P11-P14 catch every force/grasp/payload violation",
                EnvironmentalHazards => "Prove P21-P25 + SR1-SR2 catch every environmental failure",
                AuthorityCrypto => "Prove A1-A3 catch every authority attack",
                TemporalSequence => "Prove replay, sequence, timing attacks are caught",
                CognitiveEscape => "Prove LLM/AI reasoning cannot bypass the firewall",
                MultiStepCompound => "Prove chained attacks across categories fail",
                RecoveryResilience => "Prove safe-stop, recovery, and mode transitions are safe",
                LongRunningStability => "Prove 24h+ operation with no drift or degradation",
                CrossPlatformStress => "Prove all profiles under maximum load",
                AdversarialRedTeam => "Prove fuzz/mutation/generation attacks find no bypass",
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
// Category A: Normal Operation (3,000,000 episodes)
// ---------------------------------------------------------------------------

/// Category A scenario specifications for the 15M campaign.
///
/// These 8 scenarios prove Invariant does not over-reject. False positives are
/// as dangerous as false negatives — a robot that freezes mid-surgery or drops
/// a part because the firewall was too aggressive is a safety failure.
///
/// **Success criteria:** 100% approval rate (zero false rejections for valid commands).
pub mod category_a {
    /// Total episodes allocated to Category A.
    ///
    /// The overview table (Section 2.1) rounds this to 3,000,000. The detailed
    /// per-scenario allocations below sum to 3,100,000; the detailed values
    /// are canonical.
    pub const TOTAL_EPISODES: u64 = 3_100_000;

    /// Number of distinct scenarios in Category A.
    pub const SCENARIO_COUNT: u32 = 8;

    /// Category A requires zero false rejections.
    pub const REQUIRED_APPROVAL_RATE: f64 = 1.0;

    /// Category A requires zero false rejections (explicit count).
    pub const MAX_FALSE_REJECTIONS: u64 = 0;

    /// A single Category A scenario specification.
    #[derive(Debug, Clone)]
    pub struct NormalOperationScenario {
        /// Scenario identifier (e.g. "A-01").
        pub id: &'static str,
        /// Human-readable name.
        pub name: &'static str,
        /// Scenario type key matching `ScenarioType` variant (snake_case).
        pub scenario_type: &'static str,
        /// Steps per episode.
        pub steps: u32,
        /// Episodes allocated to this scenario.
        pub episodes: u64,
        /// Profile names that participate in this scenario.
        pub profiles: &'static [&'static str],
        /// Physics/authority invariants exercised (pass path).
        pub invariants_exercised: &'static [&'static str],
    }

    /// All 34 profile names in the campaign (30 real-world + 4 adversarial).
    pub const ALL_PROFILES: &[&str] = &[
        "humanoid_28dof",
        "unitree_h1",
        "unitree_g1",
        "fourier_gr1",
        "tesla_optimus",
        "figure_02",
        "bd_atlas",
        "agility_digit",
        "sanctuary_phoenix",
        "onex_neo",
        "apptronik_apollo",
        "quadruped_12dof",
        "spot",
        "unitree_go2",
        "unitree_a1",
        "anybotics_anymal",
        "franka_panda",
        "ur10",
        "ur10e_haas_cell",
        "ur10e_cnc_tending",
        "kuka_iiwa14",
        "kinova_gen3",
        "abb_gofa",
        "shadow_hand",
        "allegro_hand",
        "leap_hand",
        "psyonic_ability",
        "spot_with_arm",
        "hello_stretch",
        "pal_tiago",
        "adversarial_zero_margin",
        "adversarial_max_workspace",
        "adversarial_single_joint",
        "adversarial_max_joints",
    ];

    /// Arms + humanoids subset for A-03 pick-and-place.
    pub const PICK_AND_PLACE_PROFILES: &[&str] = &[
        "franka_panda",
        "kuka_iiwa14",
        "kinova_gen3",
        "abb_gofa",
        "ur10",
        "ur10e_haas_cell",
        "ur10e_cnc_tending",
        "humanoid_28dof",
        "unitree_h1",
        "unitree_g1",
    ];

    /// Legged profiles for A-04 walking gait.
    pub const WALKING_GAIT_PROFILES: &[&str] = &[
        "spot",
        "quadruped_12dof",
        "unitree_h1",
        "unitree_g1",
        "humanoid_28dof",
    ];

    /// Cobot profiles for A-05 human-proximate collaborative work.
    pub const COLLABORATIVE_PROFILES: &[&str] = &[
        "franka_panda",
        "kinova_gen3",
        "abb_gofa",
        "kuka_iiwa14",
        "ur10",
        "ur10e_haas_cell",
        "shadow_hand",
        "humanoid_28dof",
    ];

    /// UR10e variants for A-06 CNC tending.
    pub const CNC_TENDING_PROFILES: &[&str] = &["ur10e_haas_cell", "ur10e_cnc_tending"];

    /// Dexterous profiles for A-07.
    pub const DEXTEROUS_PROFILES: &[&str] = &["shadow_hand", "kinova_gen3", "franka_panda"];

    /// A-01: Baseline safe operation.
    pub const A01_BASELINE: NormalOperationScenario = NormalOperationScenario {
        id: "A-01",
        name: "Baseline safe operation",
        scenario_type: "baseline",
        steps: 200,
        episodes: 500_000,
        profiles: ALL_PROFILES,
        invariants_exercised: &["P1", "P2", "P3", "P4", "P5", "P7", "P8", "A1", "A2", "A3"],
    };

    /// A-02: Full-speed nominal trajectory.
    pub const A02_AGGRESSIVE: NormalOperationScenario = NormalOperationScenario {
        id: "A-02",
        name: "Full-speed nominal trajectory",
        scenario_type: "aggressive",
        steps: 500,
        episodes: 400_000,
        profiles: ALL_PROFILES,
        invariants_exercised: &["P1", "P2", "P3", "P4", "P5", "P8", "A1", "A2", "A3"],
    };

    /// A-03: Pick-and-place cycle.
    pub const A03_PICK_AND_PLACE: NormalOperationScenario = NormalOperationScenario {
        id: "A-03",
        name: "Pick-and-place cycle",
        scenario_type: "pick_and_place",
        steps: 300,
        episodes: 400_000,
        profiles: PICK_AND_PLACE_PROFILES,
        invariants_exercised: &[
            "P1", "P2", "P3", "P4", "P5", "P11", "P13", "P14", "A1", "A2", "A3",
        ],
    };

    /// A-04: Walking gait cycle.
    pub const A04_WALKING_GAIT: NormalOperationScenario = NormalOperationScenario {
        id: "A-04",
        name: "Walking gait cycle",
        scenario_type: "walking_gait",
        steps: 1000,
        episodes: 400_000,
        profiles: WALKING_GAIT_PROFILES,
        invariants_exercised: &[
            "P9", "P15", "P16", "P17", "P18", "P19", "P20", "A1", "A2", "A3",
        ],
    };

    /// A-05: Human-proximate collaborative work.
    pub const A05_COLLABORATIVE: NormalOperationScenario = NormalOperationScenario {
        id: "A-05",
        name: "Human-proximate collaborative work",
        scenario_type: "collaborative_work",
        steps: 500,
        episodes: 400_000,
        profiles: COLLABORATIVE_PROFILES,
        invariants_exercised: &["P1", "P2", "P3", "P5", "A1", "A2", "A3"],
    };

    /// A-06: CNC tending full production cycle.
    pub const A06_CNC_TENDING: NormalOperationScenario = NormalOperationScenario {
        id: "A-06",
        name: "CNC tending full cycle",
        scenario_type: "cnc_tending_full_cycle",
        steps: 400,
        episodes: 400_000,
        profiles: CNC_TENDING_PROFILES,
        invariants_exercised: &["P5", "P6", "C3", "A1", "A2", "A3"],
    };

    /// A-07: Dexterous manipulation.
    pub const A07_DEXTEROUS: NormalOperationScenario = NormalOperationScenario {
        id: "A-07",
        name: "Dexterous manipulation",
        scenario_type: "dexterous_manipulation",
        steps: 300,
        episodes: 300_000,
        profiles: DEXTEROUS_PROFILES,
        invariants_exercised: &["P1", "P2", "P3", "P4", "P5", "A1", "A2", "A3"],
    };

    /// A-08: Multi-robot coordinated task.
    pub const A08_MULTI_ROBOT: NormalOperationScenario = NormalOperationScenario {
        id: "A-08",
        name: "Multi-robot coordinated task",
        scenario_type: "multi_robot_coordinated",
        steps: 500,
        episodes: 300_000,
        profiles: ALL_PROFILES,
        invariants_exercised: &["P8", "A1", "A2", "A3"],
    };

    /// All 8 Category A scenarios in spec order.
    pub fn all() -> &'static [NormalOperationScenario; SCENARIO_COUNT as usize] {
        &[
            A01_BASELINE,
            A02_AGGRESSIVE,
            A03_PICK_AND_PLACE,
            A04_WALKING_GAIT,
            A05_COLLABORATIVE,
            A06_CNC_TENDING,
            A07_DEXTEROUS,
            A08_MULTI_ROBOT,
        ]
    }

    /// Total commands generated across all Category A episodes.
    ///
    /// Sum of `episodes × steps` for each scenario.
    pub fn total_commands() -> u64 {
        all().iter().map(|s| s.episodes * s.steps as u64).sum()
    }

    /// Verify that a scenario type string is a Category A scenario.
    pub fn is_category_a(scenario_type: &str) -> bool {
        all().iter().any(|s| s.scenario_type == scenario_type)
    }
}

// ---------------------------------------------------------------------------
// 15M Campaign Purpose & Statistical Claims (Purpose section)
// ---------------------------------------------------------------------------

/// Statistical safety claims for the 15M campaign (Purpose section).
///
/// This module encodes the campaign's raison d'etre: at 15M validated
/// decisions with zero bypasses, the Clopper-Pearson exact binomial
/// confidence interval yields an upper bound on the bypass rate that
/// constitutes statistical proof of safety.
///
/// The campaign covers every robot morphology, every physics invariant
/// (P1-P25) at boundary conditions, every authority attack (A1-A3),
/// every sensor/environmental fault, every temporal/coordination/recovery
/// scenario, and every adversarial strategy a white-box attacker could
/// employ. The audit trail is the **black box record** — cryptographically
/// signed, hash-chained, and tamper-proof.
pub mod purpose {
    /// Total episodes required for the statistical proof.
    pub const TOTAL_EPISODES: u64 = 15_000_000;

    /// Number of observed bypasses required for the proof to hold.
    pub const REQUIRED_BYPASSES: u64 = 0;

    /// 95% confidence upper bound on bypass rate (Clopper-Pearson).
    ///
    /// `1 - 0.05^(1/15_000_000) ≈ 2.00 × 10⁻⁷`
    pub const BYPASS_RATE_UPPER_95: f64 = 1.997_176_379_479_565_2e-7;

    /// 99% confidence upper bound on bypass rate (Clopper-Pearson).
    ///
    /// `1 - 0.01^(1/15_000_000) ≈ 3.07 × 10⁻⁷`
    pub const BYPASS_RATE_UPPER_99: f64 = 3.070_176_066_696_386e-7;

    /// 99.9% confidence upper bound on bypass rate (Clopper-Pearson).
    ///
    /// `1 - 0.001^(1/15_000_000) ≈ 4.61 × 10⁻⁷` — fewer than 1 in 2.2 million.
    pub const BYPASS_RATE_UPPER_999: f64 = 4.605_169_126_037_367_3e-7;

    /// Human-readable equivalent of the 99.9% bound: "fewer than 1 in N".
    pub const BYPASS_RATE_EQUIV_ONE_IN: u64 = 2_200_000;

    /// Compute the Clopper-Pearson upper bound for 0 successes in `n` trials.
    ///
    /// For k=0 observed events the exact formula simplifies to:
    /// `upper = 1 - alpha^(1/n)`
    ///
    /// # Panics
    ///
    /// Panics if `alpha` is not in (0, 1) or `n` is 0.
    pub fn clopper_pearson_upper_bound(n: u64, alpha: f64) -> f64 {
        assert!(n > 0, "n must be > 0");
        assert!(alpha > 0.0 && alpha < 1.0, "alpha must be in (0, 1)");
        1.0 - alpha.powf(1.0 / n as f64)
    }

    /// Coverage domains that the campaign must exercise.
    ///
    /// Each variant represents a class of safety evidence the campaign
    /// produces, as enumerated in the Purpose section.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum CoverageDomain {
        /// Every robot morphology in deployment today.
        RobotMorphology,
        /// Every physics invariant (P1-P25) at boundary conditions.
        PhysicsInvariants,
        /// Every authority attack an AI/LLM could attempt.
        AuthorityAttacks,
        /// Every sensor spoofing and environmental fault.
        SensorEnvironmental,
        /// Every temporal, coordination, and recovery scenario.
        TemporalCoordination,
        /// Every adversarial strategy a white-box attacker could employ.
        AdversarialStrategies,
    }

    impl CoverageDomain {
        /// Returns all coverage domains in spec order.
        pub fn all() -> &'static [CoverageDomain; 6] {
            use CoverageDomain::*;
            &[
                RobotMorphology,
                PhysicsInvariants,
                AuthorityAttacks,
                SensorEnvironmental,
                TemporalCoordination,
                AdversarialStrategies,
            ]
        }

        /// Human-readable description of this coverage domain.
        pub fn description(&self) -> &'static str {
            use CoverageDomain::*;
            match self {
                RobotMorphology => "Every robot morphology in deployment today",
                PhysicsInvariants => "Every physics invariant (P1-P25) at boundary conditions",
                AuthorityAttacks => "Every authority attack an AI/LLM could attempt",
                SensorEnvironmental => "Every sensor spoofing and environmental fault",
                TemporalCoordination => "Every temporal, coordination, and recovery scenario",
                AdversarialStrategies => {
                    "Every adversarial strategy a white-box attacker could employ"
                }
            }
        }
    }

    /// The campaign's audit trail properties.
    pub mod audit_trail {
        /// The audit trail is cryptographically signed.
        pub const SIGNED: bool = true;
        /// The audit trail is hash-chained (each entry links to the previous).
        pub const HASH_CHAINED: bool = true;
        /// The audit trail is tamper-proof (any modification breaks the chain).
        pub const TAMPER_PROOF: bool = true;
        /// Signature algorithm used for the verdict chain.
        pub const SIGNATURE_ALGORITHM: &str = "Ed25519";
    }
}

// ---------------------------------------------------------------------------
// Category A: Normal Operation (Section 2.2.A)
// ---------------------------------------------------------------------------

/// Scenario specifications for Category A: Normal Operation (3,000,000 episodes).
///
/// These prove Invariant does not over-reject. False positives are as dangerous
/// as false negatives — a robot that freezes mid-surgery or drops a part because
/// the firewall was too aggressive is a safety failure.
///
/// **Success criteria:** 100% approval rate (zero false rejections for valid
/// commands).
pub mod normal_operation {
    use serde::{Deserialize, Serialize};

    /// Total episodes allocated to Category A.
    pub const TOTAL_EPISODES: u64 = 3_100_000;

    /// Number of distinct scenarios in Category A (A-01 through A-08).
    pub const SCENARIO_COUNT: u32 = 8;

    /// A normal operation scenario in the 15M campaign.
    ///
    /// Each variant maps to one row in the Category A table.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::normal_operation::NormalScenario;
    ///
    /// let scenario = NormalScenario::BaselineSafeOperation;
    /// assert_eq!(scenario.id(), "A-01");
    /// assert_eq!(scenario.episodes(), 500_000);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum NormalScenario {
        /// A-01: All commands within safe limits across all 34 profiles.
        BaselineSafeOperation,
        /// A-02: Commands at full speed but within all limits.
        FullSpeedNominalTrajectory,
        /// A-03: Pick-and-place cycle for arms + humanoids (9 profiles).
        PickAndPlaceCycle,
        /// A-04: Walking gait cycle for legged robots (5 profiles).
        WalkingGaitCycle,
        /// A-05: Collaborative work with human-proximate cobots (8 profiles).
        HumanProximateCollaborative,
        /// A-06: Full CNC tending cycle for UR10e variants (2 profiles).
        CncTendingFullCycle,
        /// A-07: Dexterous manipulation for Shadow Hand, Kinova, Franka.
        DexterousManipulation,
        /// A-08: Multi-robot coordinated task across all pairs of profiles.
        MultiRobotCoordinated,
    }

    impl NormalScenario {
        /// Returns all 8 scenarios in spec order.
        pub fn all() -> &'static [NormalScenario; 8] {
            use NormalScenario::*;
            &[
                BaselineSafeOperation,
                FullSpeedNominalTrajectory,
                PickAndPlaceCycle,
                WalkingGaitCycle,
                HumanProximateCollaborative,
                CncTendingFullCycle,
                DexterousManipulation,
                MultiRobotCoordinated,
            ]
        }

        /// Scenario identifier (e.g. "A-01").
        pub fn id(&self) -> &'static str {
            use NormalScenario::*;
            match self {
                BaselineSafeOperation => "A-01",
                FullSpeedNominalTrajectory => "A-02",
                PickAndPlaceCycle => "A-03",
                WalkingGaitCycle => "A-04",
                HumanProximateCollaborative => "A-05",
                CncTendingFullCycle => "A-06",
                DexterousManipulation => "A-07",
                MultiRobotCoordinated => "A-08",
            }
        }

        /// Human-readable scenario name.
        pub fn name(&self) -> &'static str {
            use NormalScenario::*;
            match self {
                BaselineSafeOperation => "Baseline safe operation",
                FullSpeedNominalTrajectory => "Full-speed nominal trajectory",
                PickAndPlaceCycle => "Pick-and-place cycle",
                WalkingGaitCycle => "Walking gait cycle",
                HumanProximateCollaborative => "Human-proximate collaborative work",
                CncTendingFullCycle => "CNC tending full cycle",
                DexterousManipulation => "Dexterous manipulation",
                MultiRobotCoordinated => "Multi-robot coordinated task",
            }
        }

        /// Number of episodes allocated to this scenario.
        pub fn episodes(&self) -> u64 {
            use NormalScenario::*;
            match self {
                BaselineSafeOperation => 500_000,
                FullSpeedNominalTrajectory => 400_000,
                PickAndPlaceCycle => 400_000,
                WalkingGaitCycle => 400_000,
                HumanProximateCollaborative => 400_000,
                CncTendingFullCycle => 400_000,
                DexterousManipulation => 300_000,
                MultiRobotCoordinated => 300_000,
            }
        }

        /// Expected verdict for this scenario — all commands must be approved.
        pub fn expected_verdict(&self) -> ExpectedVerdict {
            ExpectedVerdict::Pass
        }

        /// Steps per episode for this scenario (per spec).
        pub fn steps(&self) -> u32 {
            use NormalScenario::*;
            match self {
                BaselineSafeOperation => 200,
                FullSpeedNominalTrajectory => 500,
                PickAndPlaceCycle => 300,
                WalkingGaitCycle => 1000,
                HumanProximateCollaborative => 500,
                CncTendingFullCycle => 400,
                DexterousManipulation => 300,
                MultiRobotCoordinated => 500,
            }
        }

        /// Profile coverage description for this scenario.
        pub fn profile_coverage(&self) -> &'static str {
            use NormalScenario::*;
            match self {
                BaselineSafeOperation => "All 34 profiles",
                FullSpeedNominalTrajectory => "All 34 profiles",
                PickAndPlaceCycle => "Arms + humanoids (9 profiles)",
                WalkingGaitCycle => "Legged (5 profiles)",
                HumanProximateCollaborative => "Cobots (8 profiles)",
                CncTendingFullCycle => "UR10e variants (2 profiles)",
                DexterousManipulation => "Shadow Hand, Kinova, Franka",
                MultiRobotCoordinated => "All pairs of profiles",
            }
        }

        /// Detailed description of what this scenario tests.
        pub fn description(&self) -> &'static str {
            use NormalScenario::*;
            match self {
                BaselineSafeOperation => {
                    "All joint states at midpoint, EE inside workspace, \
                     valid authority. Every command must be APPROVED."
                }
                FullSpeedNominalTrajectory => {
                    "Commands at 95% of all limits (position, velocity, torque). \
                     All within bounds — must be APPROVED."
                }
                PickAndPlaceCycle => {
                    "Simulated pick-and-place: alternating approach, grasp, lift, \
                     move, place phases. All within safe limits."
                }
                WalkingGaitCycle => {
                    "Full gait cycle with valid locomotion state, foot contacts, \
                     and base velocity within P15-P20 limits."
                }
                HumanProximateCollaborative => {
                    "EE within proximity zones with velocity scaled per P10. \
                     All commands respect proximity scaling — must be APPROVED."
                }
                CncTendingFullCycle => {
                    "Complete CNC tending cycle with zone overrides correctly \
                     synchronized. EE safe in each phase — must be APPROVED."
                }
                DexterousManipulation => {
                    "Fine-grained joint movements within limits for dexterous \
                     manipulation tasks. All forces within P11-P14."
                }
                MultiRobotCoordinated => {
                    "Valid commands from alternating sources with monotonic \
                     sequences and correct authority. Must be APPROVED."
                }
            }
        }

        /// Fraction of Category A episodes allocated to this scenario.
        pub fn weight(&self) -> f64 {
            self.episodes() as f64 / TOTAL_EPISODES as f64
        }
    }

    impl std::fmt::Display for NormalScenario {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.id(), self.name())
        }
    }

    /// Expected verdict classification for a scenario.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum ExpectedVerdict {
        /// All commands should be approved.
        Pass,
    }

    impl ExpectedVerdict {
        /// Whether this verdict requires zero false rejections.
        pub fn requires_zero_false_rejections(&self) -> bool {
            true
        }
    }
}

// ---------------------------------------------------------------------------
// Category C: Spatial Safety (Section 2.2.C)
// ---------------------------------------------------------------------------

/// Scenario specifications for Category C: Spatial Safety (1,000,000 episodes).
///
/// Every exclusion zone shape, workspace boundary, and collision pair.
/// Exercises physics invariants P5 (workspace bounds), P6 (exclusion zones),
/// and P7 (self-collision distance).
pub mod spatial_safety {
    use serde::{Deserialize, Serialize};

    /// Total episodes allocated to Category C.
    pub const TOTAL_EPISODES: u64 = 1_000_000;

    /// Number of distinct scenarios in Category C (C-01 through C-06).
    pub const SCENARIO_COUNT: u32 = 6;

    /// Physics invariants exercised by this category.
    pub const INVARIANTS: &[&str] = &["P5", "P6", "P7"];

    /// A spatial safety scenario in the 15M campaign.
    ///
    /// Each variant maps to one row in the Category C table.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_sim::campaign::spatial_safety::SpatialScenario;
    ///
    /// let scenario = SpatialScenario::WorkspaceBoundarySweep;
    /// assert_eq!(scenario.id(), "C-01");
    /// assert_eq!(scenario.episodes(), 200_000);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum SpatialScenario {
        /// C-01: EE at every face, edge, corner of AABB +/- 1mm.
        WorkspaceBoundarySweep,
        /// C-02: EE approaching each exclusion zone from 6 directions.
        ExclusionZonePenetration,
        /// C-03: Enable/disable zones during CNC cycle, test each transition.
        ConditionalZoneStateMachine,
        /// C-04: Collision pairs converging from safe distance to contact.
        SelfCollisionApproach,
        /// C-05: EE at intersection of multiple overlapping zones.
        OverlappingZoneBoundaries,
        /// C-06: NaN/Inf in zone bounds, EE positions, workspace corners.
        CorruptSpatialData,
    }

    impl SpatialScenario {
        /// Returns all 6 scenarios in spec order.
        pub fn all() -> &'static [SpatialScenario; 6] {
            use SpatialScenario::*;
            &[
                WorkspaceBoundarySweep,
                ExclusionZonePenetration,
                ConditionalZoneStateMachine,
                SelfCollisionApproach,
                OverlappingZoneBoundaries,
                CorruptSpatialData,
            ]
        }

        /// Scenario identifier (e.g. "C-01").
        pub fn id(&self) -> &'static str {
            use SpatialScenario::*;
            match self {
                WorkspaceBoundarySweep => "C-01",
                ExclusionZonePenetration => "C-02",
                ConditionalZoneStateMachine => "C-03",
                SelfCollisionApproach => "C-04",
                OverlappingZoneBoundaries => "C-05",
                CorruptSpatialData => "C-06",
            }
        }

        /// Human-readable scenario name.
        pub fn name(&self) -> &'static str {
            use SpatialScenario::*;
            match self {
                WorkspaceBoundarySweep => "Workspace boundary sweep",
                ExclusionZonePenetration => "Exclusion zone penetration",
                ConditionalZoneStateMachine => "Conditional zone state machine",
                SelfCollisionApproach => "Self-collision approach",
                OverlappingZoneBoundaries => "Overlapping zone boundaries",
                CorruptSpatialData => "Corrupt spatial data",
            }
        }

        /// Number of episodes allocated to this scenario.
        pub fn episodes(&self) -> u64 {
            use SpatialScenario::*;
            match self {
                WorkspaceBoundarySweep => 200_000,
                ExclusionZonePenetration => 200_000,
                ConditionalZoneStateMachine => 100_000,
                SelfCollisionApproach => 200_000,
                OverlappingZoneBoundaries => 100_000,
                CorruptSpatialData => 200_000,
            }
        }

        /// Expected verdict for this scenario.
        pub fn expected_verdict(&self) -> ExpectedVerdict {
            use SpatialScenario::*;
            match self {
                WorkspaceBoundarySweep => ExpectedVerdict::Mixed,
                ExclusionZonePenetration => ExpectedVerdict::Reject,
                ConditionalZoneStateMachine => ExpectedVerdict::Mixed,
                SelfCollisionApproach => ExpectedVerdict::Reject,
                OverlappingZoneBoundaries => ExpectedVerdict::Mixed,
                CorruptSpatialData => ExpectedVerdict::Reject,
            }
        }

        /// Detailed description of what this scenario tests.
        pub fn description(&self) -> &'static str {
            use SpatialScenario::*;
            match self {
                WorkspaceBoundarySweep => {
                    "EE at every face, edge, corner of AABB +/- 1mm. \
                     PASS inside, REJECT outside."
                }
                ExclusionZonePenetration => {
                    "EE approaching each exclusion zone from 6 directions. \
                     REJECT on entry."
                }
                ConditionalZoneStateMachine => {
                    "Enable/disable zones during CNC cycle, test each transition. \
                     Mixed pass/reject depending on zone state."
                }
                SelfCollisionApproach => {
                    "Collision pairs converging from safe distance to contact. \
                     REJECT at min_distance."
                }
                OverlappingZoneBoundaries => {
                    "EE at intersection of multiple zones. \
                     Correct zone identified."
                }
                CorruptSpatialData => {
                    "NaN/Inf in zone bounds, EE positions, workspace corners. \
                     REJECT (fail-closed)."
                }
            }
        }

        /// Fraction of Category C episodes allocated to this scenario.
        pub fn weight(&self) -> f64 {
            self.episodes() as f64 / TOTAL_EPISODES as f64
        }
    }

    impl std::fmt::Display for SpatialScenario {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.id(), self.name())
        }
    }

    /// Expected verdict classification for a scenario.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum ExpectedVerdict {
        /// All commands should be approved.
        Pass,
        /// All commands should be rejected.
        Reject,
        /// Some commands pass, some are rejected (scenario-dependent).
        Mixed,
    }

    impl ExpectedVerdict {
        /// Whether this verdict requires zero violation escapes.
        pub fn requires_zero_escapes(&self) -> bool {
            // All scenarios require zero escapes — a violation that slips
            // through is always a campaign failure.
            true
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
        // A-04: Walking gait cycle (1000 steps)
        "walking_gait" => 1000,
        // I/J: Compound multi-step attacks (500 steps)
        "compound_authority_physics"
        | "compound_sensor_spatial"
        | "compound_drift_then_violation"
        | "compound_environment_physics" => 500,
        // K: Recovery & resilience (500 steps)
        "recovery_safe_stop" | "recovery_audit_integrity" => 500,
        // A-02: Full-speed nominal trajectory (500 steps)
        "aggressive" | "full_speed_nominal" => 500,
        // A-05: Human-proximate collaborative work (500 steps)
        "collaborative_work" | "human_proximate" => 500,
        // A-08: Multi-robot coordinated task (500 steps)
        "multi_robot_coordinated" => 500,
        // B: Joint safety — longer scenarios for ramp/drift detection
        "gradual_drift_attack" => 500,
        // A-06: CNC tending full cycle (400 steps)
        "cnc_tending_full_cycle" | "nominal_cnc_tending" => 400,
        // A-03: Pick-and-place cycle (300 steps)
        "pick_and_place" => 300,
        // A-07: Dexterous manipulation (300 steps)
        "dexterous_manipulation" => 300,
        // B: Joint safety — acceleration ramp detection
        "acceleration_ramp" => 300,
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
    /// Whether this profile is a CNC tending variant (enables A-06).
    is_cnc: bool,
    /// Whether this is a dexterous hand or arm profile (enables A-03, A-07).
    is_arm_or_hand: bool,
}

/// All 30 scenario types with their category weight.
fn all_scenario_entries() -> Vec<ScenarioConfig> {
    let entries = [
        // A: Normal operation
        ("baseline", 3.0),
        ("aggressive", 2.0),
        ("pick_and_place", 1.5),
        ("walking_gait", 1.5),
        ("collaborative_work", 1.5),
        ("human_proximate", 1.5),
        ("cnc_tending_full_cycle", 1.5),
        ("nominal_cnc_tending", 1.5),
        ("dexterous_manipulation", 1.0),
        ("multi_robot_coordinated", 1.0),
        // B: Joint safety
        ("joint_position_boundary", 1.5),
        ("joint_velocity_boundary", 1.5),
        ("joint_torque_boundary", 1.5),
        ("joint_acceleration_ramp", 1.5),
        ("joint_coordinated_violation", 1.0),
        ("joint_direction_reversal", 1.0),
        ("joint_ieee754_special", 1.5),
        ("joint_gradual_drift", 1.5),
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
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "unitree_h1",
            weight: 0.05,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "unitree_g1",
            weight: 0.04,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "fourier_gr1",
            weight: 0.04,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "tesla_optimus",
            weight: 0.04,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "figure_02",
            weight: 0.04,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "bd_atlas",
            weight: 0.04,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "agility_digit",
            weight: 0.03,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "sanctuary_phoenix",
            weight: 0.03,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "onex_neo",
            weight: 0.03,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "apptronik_apollo",
            weight: 0.03,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        // ── Quadrupeds (5) ──────────────────────────────────────────
        ProfileAllocation {
            name: "quadruped_12dof",
            weight: 0.03,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: false,
        },
        ProfileAllocation {
            name: "spot",
            weight: 0.04,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: false,
        },
        ProfileAllocation {
            name: "unitree_go2",
            weight: 0.03,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: false,
        },
        ProfileAllocation {
            name: "unitree_a1",
            weight: 0.02,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: false,
        },
        ProfileAllocation {
            name: "anybotics_anymal",
            weight: 0.02,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: false,
        },
        // ── Arms (7) ───────────────────────────────────────────────
        ProfileAllocation {
            name: "franka_panda",
            weight: 0.04,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "ur10",
            weight: 0.03,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "ur10e_haas_cell",
            weight: 0.04,
            has_locomotion: false,
            is_cnc: true,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "ur10e_cnc_tending",
            weight: 0.04,
            has_locomotion: false,
            is_cnc: true,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "kuka_iiwa14",
            weight: 0.03,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "kinova_gen3",
            weight: 0.02,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "abb_gofa",
            weight: 0.02,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        // ── Dexterous Hands (4) ────────────────────────────────────
        ProfileAllocation {
            name: "shadow_hand",
            weight: 0.02,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "allegro_hand",
            weight: 0.02,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "leap_hand",
            weight: 0.01,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "psyonic_ability",
            weight: 0.01,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        // ── Mobile Manipulators (3) ────────────────────────────────
        ProfileAllocation {
            name: "spot_with_arm",
            weight: 0.03,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "hello_stretch",
            weight: 0.02,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "pal_tiago",
            weight: 0.02,
            has_locomotion: true,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        // ── Adversarial (4) ────────────────────────────────────────
        ProfileAllocation {
            name: "adversarial_zero_margin",
            weight: 0.02,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "adversarial_max_workspace",
            weight: 0.02,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "adversarial_single_joint",
            weight: 0.02,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
        },
        ProfileAllocation {
            name: "adversarial_max_joints",
            weight: 0.02,
            has_locomotion: false,
            is_cnc: false,
            is_arm_or_hand: true,
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
            scenarios.retain(|s| {
                !s.scenario_type.starts_with("locomotion_") && s.scenario_type != "walking_gait"
            });
        }
        if !profile.is_cnc {
            scenarios.retain(|s| s.scenario_type != "cnc_tending_full_cycle");
        }
        if !profile.is_arm_or_hand {
            scenarios.retain(|s| {
                s.scenario_type != "pick_and_place" && s.scenario_type != "dexterous_manipulation"
            });
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
    fn execution_target_gpu_type() {
        use super::execution_target::*;
        assert_eq!(GPU_TYPE, "NVIDIA A40");
    }

    #[test]
    fn execution_target_step_range() {
        use super::execution_target::*;
        assert_eq!(MIN_EPISODE_STEPS, 200);
        assert_eq!(MAX_EPISODE_STEPS, 1000);
        const _: () = assert!(MIN_EPISODE_STEPS < MAX_EPISODE_STEPS);
    }

    #[test]
    fn execution_target_wall_time_range() {
        use super::execution_target::*;
        assert_eq!(ESTIMATED_WALL_TIME_HOURS_LOW, 4);
        assert_eq!(ESTIMATED_WALL_TIME_HOURS_HIGH, 6);
        const { assert!(ESTIMATED_WALL_TIME_HOURS_LOW < ESTIMATED_WALL_TIME_HOURS_HIGH) };
    }

    #[test]
    fn execution_target_cost_range() {
        use super::execution_target::*;
        assert_eq!(ESTIMATED_COST_USD_LOW, 30);
        assert_eq!(ESTIMATED_COST_USD_HIGH, 40);
        const { assert!(ESTIMATED_COST_USD_LOW < ESTIMATED_COST_USD_HIGH) };
    }

    // ── Scenario step count mapping ─────────────────────────────────

    #[test]
    fn scenario_step_count_normal_scenarios_200() {
        // A-01: Baseline and non-Category-A adversarial scenarios default to 200.
        assert_eq!(super::scenario_step_count("baseline"), 200);
        assert_eq!(super::scenario_step_count("prompt_injection"), 200);
        assert_eq!(super::scenario_step_count("exclusion_zone"), 200);
        assert_eq!(super::scenario_step_count("authority_escalation"), 200);
        assert_eq!(super::scenario_step_count("chain_forgery"), 200);
        assert_eq!(super::scenario_step_count("locomotion_runaway"), 200);
        // Joint safety scenarios are 200 steps
        assert_eq!(super::scenario_step_count("joint_position_boundary"), 200);
        assert_eq!(super::scenario_step_count("joint_velocity_boundary"), 200);
        assert_eq!(super::scenario_step_count("joint_torque_boundary"), 200);
        assert_eq!(super::scenario_step_count("joint_acceleration_ramp"), 200);
        assert_eq!(
            super::scenario_step_count("joint_coordinated_violation"),
            200
        );
        assert_eq!(super::scenario_step_count("joint_direction_reversal"), 200);
        assert_eq!(super::scenario_step_count("joint_ieee754_special"), 200);
        assert_eq!(super::scenario_step_count("joint_gradual_drift"), 200);
    }

    #[test]
    fn scenario_step_count_category_a_varied() {
        assert_eq!(super::scenario_step_count("aggressive"), 500);
        assert_eq!(super::scenario_step_count("collaborative_work"), 500);
        assert_eq!(super::scenario_step_count("multi_robot_coordinated"), 500);
        assert_eq!(super::scenario_step_count("cnc_tending_full_cycle"), 400);
        assert_eq!(super::scenario_step_count("pick_and_place"), 300);
        assert_eq!(super::scenario_step_count("dexterous_manipulation"), 300);
        assert_eq!(super::scenario_step_count("walking_gait"), 1000);
    }

    #[test]
    fn scenario_step_count_category_a_variable() {
        // A-02: Full-speed nominal trajectory (500 steps)
        assert_eq!(super::scenario_step_count("aggressive"), 500);
        // A-03: Pick-and-place cycle (300 steps)
        assert_eq!(super::scenario_step_count("pick_and_place"), 300);
        // A-04: Walking gait cycle (1000 steps)
        assert_eq!(super::scenario_step_count("walking_gait"), 1000);
        // A-05: Human-proximate collaborative work (500 steps)
        assert_eq!(super::scenario_step_count("collaborative_work"), 500);
        // A-06: CNC tending full cycle (400 steps)
        assert_eq!(super::scenario_step_count("cnc_tending_full_cycle"), 400);
        // A-07: Dexterous manipulation (300 steps)
        assert_eq!(super::scenario_step_count("dexterous_manipulation"), 300);
        // A-08: Multi-robot coordinated task (500 steps)
        assert_eq!(super::scenario_step_count("multi_robot_coordinated"), 500);
    }

    #[test]
    fn scenario_step_count_category_a_scenarios() {
        assert_eq!(super::scenario_step_count("baseline"), 200);
        assert_eq!(super::scenario_step_count("aggressive"), 500);
        assert_eq!(super::scenario_step_count("pick_and_place"), 300);
        assert_eq!(super::scenario_step_count("walking_gait"), 1000);
        assert_eq!(super::scenario_step_count("collaborative_work"), 500);
        assert_eq!(super::scenario_step_count("cnc_tending_full_cycle"), 400);
        assert_eq!(super::scenario_step_count("dexterous_manipulation"), 300);
        assert_eq!(super::scenario_step_count("multi_robot_coordinated"), 500);
    }

    #[test]
    fn scenario_step_count_compound_recovery_500() {
        assert_eq!(
            super::scenario_step_count("compound_authority_physics"),
            500
        );
        assert_eq!(super::scenario_step_count("compound_sensor_spatial"), 500);
        assert_eq!(
            super::scenario_step_count("compound_drift_then_violation"),
            500
        );
        assert_eq!(
            super::scenario_step_count("compound_environment_physics"),
            500
        );
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
                (MIN_EPISODE_STEPS..=MAX_EPISODE_STEPS).contains(&steps),
                "scenario {} has {} steps, must be in [{}, {}]",
                sc.scenario_type,
                steps,
                MIN_EPISODE_STEPS,
                MAX_EPISODE_STEPS
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
        assert_eq!(TOTAL_SCENARIOS, 106);
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
        use super::execution_target;
        use super::scenario_categories;
        assert_eq!(
            scenario_categories::TOTAL_EPISODES,
            execution_target::TOTAL_EPISODES,
            "scenario categories total must match execution target total"
        );
    }

    // ── Category A: Normal Operation tests ─────────────────────────

    #[test]
    fn category_a_total_episodes() {
        use super::category_a;
        assert_eq!(category_a::TOTAL_EPISODES, 3_100_000);
    }

    #[test]
    fn category_a_scenario_count() {
        use super::category_a;
        assert_eq!(category_a::SCENARIO_COUNT, 8);
        assert_eq!(category_a::all().len(), category_a::SCENARIO_COUNT as usize);
    }

    #[test]
    fn category_a_episodes_sum_to_total() {
        use super::category_a;
        let sum: u64 = category_a::all().iter().map(|s| s.episodes).sum();
        assert_eq!(
            sum,
            category_a::TOTAL_EPISODES,
            "individual scenario episodes must sum to category total"
        );
    }

    #[test]
    fn category_a_episodes_at_least_scenario_category() {
        use super::{category_a, scenario_categories::ScenarioCategory};
        // Detailed per-scenario allocations (3,100,000) exceed the overview
        // table's rounded 3,000,000. The detailed values are canonical.
        assert!(
            category_a::TOTAL_EPISODES >= ScenarioCategory::NormalOperation.episodes(),
            "category_a total must be >= overview table"
        );
    }

    #[test]
    fn category_a_step_counts_match_scenario_step_count() {
        use super::category_a;
        for scenario in category_a::all() {
            let steps = super::scenario_step_count(scenario.scenario_type);
            assert_eq!(
                steps, scenario.steps,
                "step count mismatch for {} ({})",
                scenario.id, scenario.scenario_type
            );
        }
    }

    #[test]
    fn category_a_all_profiles_count() {
        use super::category_a;
        assert_eq!(category_a::ALL_PROFILES.len(), 34);
    }

    #[test]
    fn category_a_profile_subsets_are_subsets_of_all() {
        use super::category_a;
        let all: std::collections::HashSet<&str> =
            category_a::ALL_PROFILES.iter().copied().collect();
        for scenario in category_a::all() {
            for profile in scenario.profiles {
                assert!(
                    all.contains(profile),
                    "{}: profile {} not in ALL_PROFILES",
                    scenario.id,
                    profile
                );
            }
        }
    }

    #[test]
    fn category_a_scenario_types_are_valid() {
        use super::category_a;
        let known = super::all_scenario_entries();
        let known_types: std::collections::HashSet<&str> =
            known.iter().map(|s| s.scenario_type.as_str()).collect();
        for scenario in category_a::all() {
            assert!(
                known_types.contains(scenario.scenario_type),
                "{}: scenario_type {} not in all_scenario_entries",
                scenario.id,
                scenario.scenario_type
            );
        }
    }

    #[test]
    fn category_a_ids_are_sequential() {
        use super::category_a;
        for (i, scenario) in category_a::all().iter().enumerate() {
            let expected = format!("A-{:02}", i + 1);
            assert_eq!(scenario.id, expected, "scenario IDs must be A-01..A-08");
        }
    }

    #[test]
    fn category_a_required_approval_rate() {
        use super::category_a;
        assert!(
            (category_a::REQUIRED_APPROVAL_RATE - 1.0).abs() < f64::EPSILON,
            "Category A requires 100% approval"
        );
        assert_eq!(category_a::MAX_FALSE_REJECTIONS, 0);
    }

    #[test]
    fn category_a_is_category_a_lookup() {
        use super::category_a;
        assert!(category_a::is_category_a("baseline"));
        assert!(category_a::is_category_a("aggressive"));
        assert!(category_a::is_category_a("pick_and_place"));
        assert!(category_a::is_category_a("walking_gait"));
        assert!(category_a::is_category_a("collaborative_work"));
        assert!(category_a::is_category_a("cnc_tending_full_cycle"));
        assert!(category_a::is_category_a("dexterous_manipulation"));
        assert!(category_a::is_category_a("multi_robot_coordinated"));
        assert!(!category_a::is_category_a("prompt_injection"));
        assert!(!category_a::is_category_a("exclusion_zone"));
    }

    #[test]
    fn category_a_total_commands() {
        use super::category_a;
        let total = category_a::total_commands();
        // A-01: 500k*200 + A-02: 400k*500 + A-03: 400k*300 + A-04: 400k*1000
        // + A-05: 400k*500 + A-06: 400k*400 + A-07: 300k*300 + A-08: 300k*500
        let expected: u64 = 500_000 * 200
            + 400_000 * 500
            + 400_000 * 300
            + 400_000 * 1000
            + 400_000 * 500
            + 400_000 * 400
            + 300_000 * 300
            + 300_000 * 500;
        assert_eq!(total, expected);
    }

    #[test]
    fn category_a_steps_within_spec_range() {
        use super::{category_a, execution_target};
        for scenario in category_a::all() {
            assert!(
                scenario.steps >= execution_target::MIN_EPISODE_STEPS
                    && scenario.steps <= execution_target::MAX_EPISODE_STEPS,
                "{}: {} steps outside [{}, {}]",
                scenario.id,
                scenario.steps,
                execution_target::MIN_EPISODE_STEPS,
                execution_target::MAX_EPISODE_STEPS,
            );
        }
    }

    #[test]
    fn category_a_invariants_nonempty() {
        use super::category_a;
        for scenario in category_a::all() {
            assert!(
                !scenario.invariants_exercised.is_empty(),
                "{}: must exercise at least one invariant",
                scenario.id
            );
        }
    }

    #[test]
    fn category_a_pick_and_place_profiles() {
        use super::category_a;
        assert_eq!(category_a::PICK_AND_PLACE_PROFILES.len(), 10);
    }

    #[test]
    fn category_a_walking_gait_profiles() {
        use super::category_a;
        assert_eq!(category_a::WALKING_GAIT_PROFILES.len(), 5);
    }

    #[test]
    fn category_a_collaborative_profiles() {
        use super::category_a;
        assert_eq!(category_a::COLLABORATIVE_PROFILES.len(), 8);
    }

    #[test]
    fn category_a_cnc_tending_profiles() {
        use super::category_a;
        assert_eq!(category_a::CNC_TENDING_PROFILES.len(), 2);
    }

    #[test]
    fn category_a_dexterous_profiles() {
        use super::category_a;
        assert_eq!(category_a::DEXTEROUS_PROFILES.len(), 3);
    }

    // ── 15M campaign config generator tests ───────────────────────────

    #[test]
    fn generate_15m_produces_tiered_configs_for_all_profiles() {
        let configs = generate_15m_configs(15_000_000, 8);
        // With Category A's variable step counts (200, 300, 400, 500, 1000),
        // each profile gets a different number of tiers depending on which
        // scenarios apply (CNC gets 400-step tier, legged gets 1000-step, etc.).
        // Verify a reasonable number of configs: at least 34 × 8 (one tier min).
        assert!(
            configs.len() >= 34 * 8,
            "must have at least one tier per profile × shard (got {})",
            configs.len()
        );
        // And all 34 profiles should be represented.
        let profile_names: std::collections::HashSet<_> =
            configs.iter().map(|c| c.profile.as_str()).collect();
        assert_eq!(profile_names.len(), 34, "all 34 profiles must be present");
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
            humanoid_configs.iter().any(|c| c
                .scenarios
                .iter()
                .any(|s| s.scenario_type == "locomotion_runaway")),
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
    fn generate_15m_short_episodes_are_largest_tier() {
        let configs = generate_15m_configs(15_000_000, 8);
        let mut tier_counts: std::collections::BTreeMap<u32, u64> =
            std::collections::BTreeMap::new();
        for c in &configs {
            *tier_counts.entry(c.steps_per_episode).or_default() +=
                c.environments as u64 * c.episodes_per_env as u64;
        }
        let short_episodes = tier_counts.get(&200).copied().unwrap_or(0);
        let max_tier = tier_counts.values().copied().max().unwrap_or(0);
        assert_eq!(
            short_episodes, max_tier,
            "200-step tier should be the largest (got {short_episodes} vs max {max_tier})"
        );
    }

    // ── Data output constants (Section 1.2) ─────────────────────────

    #[test]
    fn data_outputs_estimated_total_commands() {
        use super::data_outputs::*;
        use super::execution_target::*;
        assert_eq!(
            ESTIMATED_TOTAL_COMMANDS,
            TOTAL_EPISODES * AVG_STEPS_PER_EPISODE
        );
        assert_eq!(ESTIMATED_TOTAL_COMMANDS, 3_000_000_000);
    }

    #[test]
    fn data_outputs_size_range_valid() {
        use super::data_outputs::*;
        const _: () = assert!(ESTIMATED_OUTPUT_GB_LOW < ESTIMATED_OUTPUT_GB_HIGH);
        assert_eq!(ESTIMATED_OUTPUT_GB_LOW, 150);
        assert_eq!(ESTIMATED_OUTPUT_GB_HIGH, 200);
    }

    #[test]
    fn data_outputs_per_step_compression_plausible() {
        use super::data_outputs::*;
        // Verify the per-step estimates are consistent with the total output range.
        let bytes_per_step =
            ESTIMATED_BYTES_PER_STEP_COMPRESSED + CHAIN_OVERHEAD_BYTES_PER_STEP_COMPRESSED;
        let total_bytes = ESTIMATED_TOTAL_COMMANDS * bytes_per_step;
        let total_gb = total_bytes / (1024 * 1024 * 1024);
        assert!(
            (ESTIMATED_OUTPUT_GB_LOW..=ESTIMATED_OUTPUT_GB_HIGH * 2).contains(&total_gb),
            "per-step estimate ({bytes_per_step} B/step) yields {total_gb} GB, expected ~{ESTIMATED_OUTPUT_GB_LOW}-{ESTIMATED_OUTPUT_GB_HIGH} GB"
        );
    }

    // ── VerdictChain tests ──────────────────────────────────────────

    #[test]
    fn empty_chain_has_genesis_terminal_hash() {
        use super::data_outputs::{VerdictChainBuilder, GENESIS_HASH};
        let chain = VerdictChainBuilder::new().finalize();
        assert_eq!(chain.terminal_hash(), GENESIS_HASH);
        assert_eq!(chain.len(), 0);
        assert!(chain.is_empty());
    }

    #[test]
    fn empty_chain_verifies() {
        use super::data_outputs::VerdictChainBuilder;
        let chain = VerdictChainBuilder::new().finalize();
        assert!(chain.verify());
    }

    #[test]
    fn builder_terminal_hash_matches_chain_terminal() {
        use super::data_outputs::VerdictChainBuilder;
        let mut builder = VerdictChainBuilder::new();
        builder.push_verdict_hash(0, "sha256:aaa");
        builder.push_verdict_hash(1, "sha256:bbb");
        let terminal = builder.terminal_hash().to_string();
        let chain = builder.finalize();
        assert_eq!(chain.terminal_hash(), terminal);
    }

    #[test]
    fn single_entry_chain_verifies() {
        use super::data_outputs::VerdictChainBuilder;
        let mut builder = VerdictChainBuilder::new();
        builder.push_verdict_hash(0, "sha256:deadbeef");
        let chain = builder.finalize();
        assert_eq!(chain.len(), 1);
        assert!(chain.verify());
    }

    #[test]
    fn multi_entry_chain_verifies() {
        use super::data_outputs::VerdictChainBuilder;
        let mut builder = VerdictChainBuilder::new();
        for i in 0..10u64 {
            builder.push_verdict_hash(i, &format!("sha256:{:064x}", i));
        }
        let chain = builder.finalize();
        assert_eq!(chain.len(), 10);
        assert!(chain.verify());
    }

    #[test]
    fn chain_entry_previous_hash_is_chained() {
        use super::data_outputs::{VerdictChainBuilder, GENESIS_HASH};
        let mut builder = VerdictChainBuilder::new();
        builder.push_verdict_hash(0, "sha256:aaa");
        builder.push_verdict_hash(1, "sha256:bbb");
        let chain = builder.finalize();
        // First entry links to GENESIS_HASH
        assert_eq!(chain.entries[0].previous_hash, GENESIS_HASH);
        // Second entry links to first entry's hash
        assert_eq!(chain.entries[1].previous_hash, chain.entries[0].entry_hash);
    }

    #[test]
    fn tampered_entry_hash_fails_verify() {
        use super::data_outputs::VerdictChainBuilder;
        let mut builder = VerdictChainBuilder::new();
        builder.push_verdict_hash(0, "sha256:aaa");
        builder.push_verdict_hash(1, "sha256:bbb");
        let mut chain = builder.finalize();
        // Tamper with the entry_hash of the first entry
        chain.entries[0].entry_hash = "sha256:tampered".to_string();
        assert!(!chain.verify());
    }

    #[test]
    fn tampered_verdict_hash_fails_verify() {
        use super::data_outputs::VerdictChainBuilder;
        let mut builder = VerdictChainBuilder::new();
        builder.push_verdict_hash(0, "sha256:aaa");
        builder.push_verdict_hash(1, "sha256:bbb");
        let mut chain = builder.finalize();
        // Tamper with the verdict_hash of the first entry
        chain.entries[0].verdict_hash = "sha256:tampered".to_string();
        assert!(!chain.verify());
    }

    #[test]
    fn tampered_previous_hash_fails_verify() {
        use super::data_outputs::VerdictChainBuilder;
        let mut builder = VerdictChainBuilder::new();
        builder.push_verdict_hash(0, "sha256:aaa");
        builder.push_verdict_hash(1, "sha256:bbb");
        let mut chain = builder.finalize();
        // Break the linkage of the second entry
        chain.entries[1].previous_hash = "sha256:tampered".to_string();
        assert!(!chain.verify());
    }

    #[test]
    fn push_signed_verdict_produces_verifiable_chain() {
        use super::data_outputs::VerdictChainBuilder;
        use chrono::Utc;
        use invariant_core::models::verdict::{
            AuthoritySummary, CheckResult, SignedVerdict, Verdict,
        };

        let make_sv = |seq: u64, approved: bool| SignedVerdict {
            verdict: Verdict {
                approved,
                command_hash: format!("sha256:{seq:064x}"),
                command_sequence: seq,
                timestamp: Utc::now(),
                checks: vec![CheckResult {
                    name: "joint_limits".into(),
                    category: "physics".into(),
                    passed: approved,
                    details: "ok".into(),
                    derating: None,
                }],
                profile_name: "franka_panda".into(),
                profile_hash: "sha256:profile".into(),
                threat_analysis: None,
                authority_summary: AuthoritySummary {
                    origin_principal: "operator".into(),
                    hop_count: 1,
                    operations_granted: vec![],
                    operations_required: vec![],
                },
            },
            verdict_signature: "sig".into(),
            signer_kid: "kid-1".into(),
        };

        let mut builder = VerdictChainBuilder::new();
        for i in 0..5u64 {
            let sv = make_sv(i, i % 2 == 0);
            let entry = builder.push_signed_verdict(i, &sv);
            assert!(entry.is_some(), "push_signed_verdict must succeed");
        }
        let chain = builder.finalize();
        assert_eq!(chain.len(), 5);
        assert!(chain.verify());
    }

    #[test]
    fn chain_terminal_hash_differs_from_genesis() {
        use super::data_outputs::{VerdictChainBuilder, GENESIS_HASH};
        let mut builder = VerdictChainBuilder::new();
        builder.push_verdict_hash(0, "sha256:data");
        let chain = builder.finalize();
        assert_ne!(chain.terminal_hash(), GENESIS_HASH);
    }

    #[test]
    fn two_chains_same_verdicts_same_terminal() {
        use super::data_outputs::VerdictChainBuilder;
        let verdicts = ["sha256:aaa", "sha256:bbb", "sha256:ccc"];
        let mut b1 = VerdictChainBuilder::new();
        let mut b2 = VerdictChainBuilder::new();
        for (i, v) in verdicts.iter().enumerate() {
            b1.push_verdict_hash(i as u64, v);
            b2.push_verdict_hash(i as u64, v);
        }
        assert_eq!(b1.finalize().terminal_hash(), b2.finalize().terminal_hash());
    }

    #[test]
    fn two_chains_different_verdicts_different_terminal() {
        use super::data_outputs::VerdictChainBuilder;
        let mut b1 = VerdictChainBuilder::new();
        let mut b2 = VerdictChainBuilder::new();
        b1.push_verdict_hash(0, "sha256:aaa");
        b2.push_verdict_hash(0, "sha256:bbb");
        assert_ne!(b1.finalize().terminal_hash(), b2.finalize().terminal_hash());
    }

    #[test]
    fn chain_serialization_round_trip() {
        use super::data_outputs::VerdictChainBuilder;
        let mut builder = VerdictChainBuilder::new();
        builder.push_verdict_hash(0, "sha256:aaa");
        builder.push_verdict_hash(1, "sha256:bbb");
        let chain = builder.finalize();
        let json = serde_json::to_string(&chain).expect("must serialize");
        let back: super::data_outputs::VerdictChain =
            serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(back.len(), 2);
        assert!(back.verify());
        assert_eq!(back.terminal_hash(), chain.terminal_hash());
    }

    // ── StepRecord tests ───────────────────────────────────────────

    #[test]
    fn step_record_first_step_not_chained() {
        use super::data_outputs::StepRecord;
        let record = StepRecord {
            step_index: 0,
            command_hash: "sha256:cmd0".into(),
            command_sequence: 1,
            approved: true,
            checks_evaluated: 6,
            checks_failed: 0,
            verdict_hash: "sha256:v0".into(),
            previous_verdict_hash: None,
        };
        assert!(!record.is_chained());
    }

    #[test]
    fn step_record_subsequent_step_is_chained() {
        use super::data_outputs::StepRecord;
        let record = StepRecord {
            step_index: 1,
            command_hash: "sha256:cmd1".into(),
            command_sequence: 2,
            approved: false,
            checks_evaluated: 6,
            checks_failed: 2,
            verdict_hash: "sha256:v1".into(),
            previous_verdict_hash: Some("sha256:v0".into()),
        };
        assert!(record.is_chained());
    }

    #[test]
    fn step_record_serialization_round_trip() {
        use super::data_outputs::StepRecord;
        let record = StepRecord {
            step_index: 42,
            command_hash: "sha256:deadbeef".into(),
            command_sequence: 43,
            approved: true,
            checks_evaluated: 8,
            checks_failed: 0,
            verdict_hash: "sha256:verdict42".into(),
            previous_verdict_hash: Some("sha256:verdict41".into()),
        };
        let json = serde_json::to_string(&record).expect("must serialize");
        let back: StepRecord = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(back.step_index, 42);
        assert_eq!(back.command_sequence, 43);
        assert!(back.approved);
        assert!(back.is_chained());
    }

    // ── estimate functions tests ──────────────────────────────────────

    #[test]
    fn estimate_episode_bytes_matches_constants() {
        use super::data_outputs::*;
        let expected =
            200 * (ESTIMATED_BYTES_PER_STEP_COMPRESSED + CHAIN_OVERHEAD_BYTES_PER_STEP_COMPRESSED);
        assert_eq!(estimate_episode_bytes(200), expected);
    }

    #[test]
    fn estimate_episode_bytes_zero_steps() {
        use super::data_outputs::estimate_episode_bytes;
        assert_eq!(estimate_episode_bytes(0), 0);
    }

    #[test]
    fn estimate_campaign_bytes_in_expected_range() {
        use super::data_outputs::estimate_campaign_bytes;
        let bytes = estimate_campaign_bytes(15_000_000, 200);
        let gb = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        assert!(
            (100.0..=300.0).contains(&gb),
            "15M campaign estimate should be ~150-200 GB, got {gb:.1} GB"
        );
    }

    #[test]
    fn estimate_campaign_bytes_consistent_with_per_episode() {
        use super::data_outputs::*;
        let per_ep = estimate_episode_bytes(200);
        let total = estimate_campaign_bytes(1000, 200);
        assert_eq!(total, per_ep * 1000);
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

    // ── Proof of safety (Purpose) ────────────────────────────────

    #[test]
    fn clopper_pearson_upper_at_15m() {
        use super::proof_of_safety::*;
        let bound = clopper_pearson_upper(REQUIRED_EPISODES, CONFIDENCE_LEVEL);
        assert!(
            (bound - BYPASS_RATE_UPPER_BOUND).abs() < 1e-9,
            "bound {bound} should ≈ {BYPASS_RATE_UPPER_BOUND}"
        );
    }

    #[test]
    fn clopper_pearson_upper_monotonically_decreasing_with_n() {
        use super::proof_of_safety::clopper_pearson_upper;
        let b1 = clopper_pearson_upper(1_000_000, 0.999);
        let b2 = clopper_pearson_upper(15_000_000, 0.999);
        assert!(b1 > b2, "more episodes => lower bound");
    }

    #[test]
    fn one_in_n_decisions_consistent() {
        use super::proof_of_safety::*;
        let computed = (1.0 / BYPASS_RATE_UPPER_BOUND).floor() as u64;
        // Allow a small tolerance due to the constant being a rounded approximation.
        assert!(
            (computed as i64 - ONE_IN_N_DECISIONS as i64).unsigned_abs() < 1000,
            "1/{BYPASS_RATE_UPPER_BOUND} = {computed}, expected ≈ {ONE_IN_N_DECISIONS}"
        );
    }

    #[test]
    fn is_proof_of_safety_requires_15m_and_zero_escapes() {
        use super::proof_of_safety::*;
        assert!(is_proof_of_safety(15_000_000, 0));
        assert!(is_proof_of_safety(20_000_000, 0)); // more than required is fine
        assert!(!is_proof_of_safety(14_999_999, 0));
        assert!(!is_proof_of_safety(15_000_000, 1));
        assert!(!is_proof_of_safety(0, 0));
    }

    // ── CampaignOutputManifest tests ─────────────────────────────────

    fn make_shard_summary(
        shard_id: u32,
        episodes: u64,
        escapes: u64,
    ) -> super::data_outputs::ShardOutputSummary {
        super::data_outputs::ShardOutputSummary {
            shard_id,
            episodes_completed: episodes,
            total_steps: episodes * 200,
            total_commands_approved: episodes * 195,
            total_commands_rejected: episodes * 5,
            total_violation_escapes: escapes,
            total_false_rejections: 0,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            output_size_bytes: episodes * 12_000,
            final_chain_hash: format!("sha256:shard{shard_id}"),
        }
    }

    #[test]
    fn campaign_manifest_from_shards_aggregates_totals() {
        use super::data_outputs::CampaignOutputManifest;
        let shards: Vec<_> = (0..8u32)
            .map(|i| make_shard_summary(i, 1_875_000, 0))
            .collect();
        let manifest = CampaignOutputManifest::from_shards(shards);
        assert_eq!(manifest.shard_count, 8);
        assert_eq!(manifest.total_episodes, 15_000_000);
        assert_eq!(manifest.total_steps, 15_000_000 * 200);
        assert_eq!(manifest.total_violation_escapes, 0);
        assert!(manifest.is_clean());
    }

    #[test]
    fn campaign_manifest_not_clean_when_any_shard_has_escapes() {
        use super::data_outputs::CampaignOutputManifest;
        let mut shards: Vec<_> = (0..8u32).map(|i| make_shard_summary(i, 100, 0)).collect();
        shards[3].total_violation_escapes = 1;
        let manifest = CampaignOutputManifest::from_shards(shards);
        assert_eq!(manifest.total_violation_escapes, 1);
        assert!(!manifest.is_clean());
    }

    #[test]
    fn campaign_manifest_shards_sorted_by_id() {
        use super::data_outputs::CampaignOutputManifest;
        // Supply shards out of order
        let shards = vec![
            make_shard_summary(7, 100, 0),
            make_shard_summary(0, 100, 0),
            make_shard_summary(3, 100, 0),
        ];
        let manifest = CampaignOutputManifest::from_shards(shards);
        assert_eq!(manifest.shards[0].shard_id, 0);
        assert_eq!(manifest.shards[1].shard_id, 3);
        assert_eq!(manifest.shards[2].shard_id, 7);
    }

    #[test]
    fn campaign_manifest_chain_hashes_match_shard_order() {
        use super::data_outputs::CampaignOutputManifest;
        let shards: Vec<_> = (0..4u32).map(|i| make_shard_summary(i, 50, 0)).collect();
        let manifest = CampaignOutputManifest::from_shards(shards);
        for (i, hash) in manifest.shard_chain_hashes.iter().enumerate() {
            assert_eq!(hash, &format!("sha256:shard{i}"));
        }
    }

    #[test]
    fn campaign_manifest_approval_rate() {
        use super::data_outputs::CampaignOutputManifest;
        let shards = vec![make_shard_summary(0, 1000, 0)];
        let manifest = CampaignOutputManifest::from_shards(shards);
        // 195_000 approved / 200_000 total = 0.975
        assert!((manifest.approval_rate() - 0.975).abs() < 1e-10);
    }

    #[test]
    fn campaign_manifest_approval_rate_zero_steps() {
        use super::data_outputs::CampaignOutputManifest;
        let manifest = CampaignOutputManifest::from_shards(vec![]);
        assert!((manifest.approval_rate()).abs() < f64::EPSILON);
    }

    #[test]
    fn campaign_manifest_output_size_gb() {
        use super::data_outputs::CampaignOutputManifest;
        let shards: Vec<_> = (0..8u32)
            .map(|i| {
                let mut s = make_shard_summary(i, 100, 0);
                s.output_size_bytes = 20 * 1024 * 1024 * 1024; // 20 GB each
                s
            })
            .collect();
        let manifest = CampaignOutputManifest::from_shards(shards);
        assert!((manifest.output_size_gb() - 160.0).abs() < 0.1);
    }

    #[test]
    fn campaign_manifest_serialization_round_trip() {
        use super::data_outputs::CampaignOutputManifest;
        let shards: Vec<_> = (0..2u32).map(|i| make_shard_summary(i, 500, 0)).collect();
        let manifest = CampaignOutputManifest::from_shards(shards);
        let json = serde_json::to_string(&manifest).expect("must serialize");
        let back: CampaignOutputManifest = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(back.shard_count, 2);
        assert_eq!(back.total_episodes, 1000);
        assert_eq!(back.total_violation_escapes, 0);
        assert_eq!(back.shard_chain_hashes.len(), 2);
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
        let sum: u64 = JointSafetyScenario::all()
            .iter()
            .map(|s| s.episodes())
            .sum();
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
        assert_eq!(
            super::scenario_step_count("multi_joint_coordinated_violation"),
            200
        );
        assert_eq!(super::scenario_step_count("rapid_direction_reversal"), 200);
        assert_eq!(super::scenario_step_count("ieee754_special_values"), 200);
    }

    // ── Category C: Spatial Safety ───────────────────────────────────

    #[test]
    fn spatial_safety_scenario_count() {
        use super::spatial_safety::*;
        assert_eq!(SpatialScenario::all().len(), SCENARIO_COUNT as usize);
        assert_eq!(SCENARIO_COUNT, 6);
    }

    #[test]
    fn spatial_safety_total_episodes() {
        use super::spatial_safety::*;
        let sum: u64 = SpatialScenario::all().iter().map(|s| s.episodes()).sum();
        assert_eq!(sum, TOTAL_EPISODES);
        assert_eq!(TOTAL_EPISODES, 1_000_000);
    }

    #[test]
    fn spatial_safety_total_matches_category() {
        use super::scenario_categories::ScenarioCategory;
        use super::spatial_safety;
        assert_eq!(
            spatial_safety::TOTAL_EPISODES,
            ScenarioCategory::SpatialSafety.episodes(),
            "spatial_safety total must match ScenarioCategory::SpatialSafety"
        );
    }

    #[test]
    fn spatial_safety_scenario_count_matches_category() {
        use super::scenario_categories::ScenarioCategory;
        use super::spatial_safety;
        assert_eq!(
            spatial_safety::SCENARIO_COUNT,
            ScenarioCategory::SpatialSafety.scenarios(),
            "spatial_safety scenario count must match ScenarioCategory::SpatialSafety"
        );
    }

    #[test]
    fn spatial_safety_ids_sequential() {
        use super::spatial_safety::SpatialScenario;
        let ids: Vec<&str> = SpatialScenario::all().iter().map(|s| s.id()).collect();
        assert_eq!(ids, vec!["C-01", "C-02", "C-03", "C-04", "C-05", "C-06"]);
    }

    #[test]
    fn spatial_safety_all_have_nonzero_episodes() {
        use super::spatial_safety::SpatialScenario;
        for scenario in SpatialScenario::all() {
            assert!(
                scenario.episodes() > 0,
                "scenario {} must have > 0 episodes",
                scenario.id()
            );
        }
    }

    #[test]
    fn spatial_safety_names_nonempty() {
        use super::spatial_safety::SpatialScenario;
        for scenario in SpatialScenario::all() {
            assert!(
                !scenario.name().is_empty(),
                "scenario {} must have a name",
                scenario.id()
            );
        }
    }

    #[test]
    fn spatial_safety_descriptions_nonempty() {
        use super::spatial_safety::SpatialScenario;
        for scenario in SpatialScenario::all() {
            assert!(
                !scenario.description().is_empty(),
                "scenario {} must have a description",
                scenario.id()
            );
        }
    }

    #[test]
    fn spatial_safety_weights_sum_to_one() {
        use super::spatial_safety::SpatialScenario;
        let sum: f64 = SpatialScenario::all().iter().map(|s| s.weight()).sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "spatial safety weights must sum to 1.0, got {sum}"
        );
    }

    #[test]
    fn spatial_safety_expected_verdicts_correct() {
        use super::spatial_safety::{ExpectedVerdict, SpatialScenario};
        // C-01: Mixed (PASS inside, REJECT outside)
        assert_eq!(
            SpatialScenario::WorkspaceBoundarySweep.expected_verdict(),
            ExpectedVerdict::Mixed
        );
        // C-02: REJECT on entry
        assert_eq!(
            SpatialScenario::ExclusionZonePenetration.expected_verdict(),
            ExpectedVerdict::Reject
        );
        // C-03: Mixed (depends on zone state)
        assert_eq!(
            SpatialScenario::ConditionalZoneStateMachine.expected_verdict(),
            ExpectedVerdict::Mixed
        );
        // C-04: REJECT at min_distance
        assert_eq!(
            SpatialScenario::SelfCollisionApproach.expected_verdict(),
            ExpectedVerdict::Reject
        );
        // C-05: Mixed (correct zone identified)
        assert_eq!(
            SpatialScenario::OverlappingZoneBoundaries.expected_verdict(),
            ExpectedVerdict::Mixed
        );
        // C-06: REJECT (fail-closed)
        assert_eq!(
            SpatialScenario::CorruptSpatialData.expected_verdict(),
            ExpectedVerdict::Reject
        );
    }

    #[test]
    fn spatial_safety_all_require_zero_escapes() {
        use super::spatial_safety::SpatialScenario;
        for scenario in SpatialScenario::all() {
            assert!(
                scenario.expected_verdict().requires_zero_escapes(),
                "scenario {} must require zero violation escapes",
                scenario.id()
            );
        }
    }

    #[test]
    fn spatial_safety_invariants_cover_p5_p6_p7() {
        use super::spatial_safety::INVARIANTS;
        assert!(
            INVARIANTS.contains(&"P5"),
            "must exercise P5 (workspace bounds)"
        );
        assert!(
            INVARIANTS.contains(&"P6"),
            "must exercise P6 (exclusion zones)"
        );
        assert!(
            INVARIANTS.contains(&"P7"),
            "must exercise P7 (self-collision)"
        );
    }

    #[test]
    fn spatial_safety_display_format() {
        use super::spatial_safety::SpatialScenario;
        let display = format!("{}", SpatialScenario::WorkspaceBoundarySweep);
        assert_eq!(display, "C-01: Workspace boundary sweep");
        let display = format!("{}", SpatialScenario::CorruptSpatialData);
        assert_eq!(display, "C-06: Corrupt spatial data");
    }

    #[test]
    fn spatial_safety_serialization_round_trip() {
        use super::spatial_safety::SpatialScenario;
        let scenario = SpatialScenario::SelfCollisionApproach;
        let json = serde_json::to_string(&scenario).expect("must serialize");
        let back: SpatialScenario = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(back, scenario);
    }

    #[test]
    fn spatial_safety_episode_distribution() {
        use super::spatial_safety::SpatialScenario;
        // Verify specific episode counts from the spec table
        assert_eq!(SpatialScenario::WorkspaceBoundarySweep.episodes(), 200_000);
        assert_eq!(
            SpatialScenario::ExclusionZonePenetration.episodes(),
            200_000
        );
        assert_eq!(
            SpatialScenario::ConditionalZoneStateMachine.episodes(),
            100_000
        );
        assert_eq!(SpatialScenario::SelfCollisionApproach.episodes(), 200_000);
        assert_eq!(
            SpatialScenario::OverlappingZoneBoundaries.episodes(),
            100_000
        );
        assert_eq!(SpatialScenario::CorruptSpatialData.episodes(), 200_000);
    }

    #[test]
    fn spatial_safety_expected_verdict_serialization() {
        use super::spatial_safety::ExpectedVerdict;
        for verdict in [
            ExpectedVerdict::Pass,
            ExpectedVerdict::Reject,
            ExpectedVerdict::Mixed,
        ] {
            let json = serde_json::to_string(&verdict).expect("must serialize");
            let back: ExpectedVerdict = serde_json::from_str(&json).expect("must deserialize");
            assert_eq!(back, verdict);
        }
    }

    // ── Purpose & statistical claims (Purpose section) ────────────────

    #[test]
    fn purpose_total_episodes_matches_execution_target() {
        assert_eq!(
            super::purpose::TOTAL_EPISODES,
            super::execution_target::TOTAL_EPISODES,
            "purpose and execution_target must agree on total episodes"
        );
    }

    #[test]
    fn purpose_required_bypasses_is_zero() {
        assert_eq!(super::purpose::REQUIRED_BYPASSES, 0);
    }

    #[test]
    fn purpose_confidence_bounds_ordered() {
        use super::purpose::*;
        // Tighter confidence requires a wider bound
        const _: () = assert!(BYPASS_RATE_UPPER_95 < BYPASS_RATE_UPPER_99);
        const _: () = assert!(BYPASS_RATE_UPPER_99 < BYPASS_RATE_UPPER_999);
    }

    #[test]
    fn purpose_999_bound_matches_spec_claim() {
        use super::purpose::*;
        // Spec claims < 0.0000461% = 4.61e-7
        const _: () = assert!(BYPASS_RATE_UPPER_999 < 4.62e-7);
        const _: () = assert!(BYPASS_RATE_UPPER_999 > 4.60e-7);
    }

    #[test]
    fn purpose_equiv_one_in_consistent_with_bound() {
        use super::purpose::*;
        // 1/BYPASS_RATE_UPPER_999 should be approximately BYPASS_RATE_EQUIV_ONE_IN
        let computed_one_in = (1.0 / BYPASS_RATE_UPPER_999).round() as u64;
        let tolerance = 200_000; // allow rounding tolerance
        assert!(
            computed_one_in.abs_diff(BYPASS_RATE_EQUIV_ONE_IN) < tolerance,
            "1/{} = {} should be ~{} (diff {})",
            BYPASS_RATE_UPPER_999,
            computed_one_in,
            BYPASS_RATE_EQUIV_ONE_IN,
            computed_one_in.abs_diff(BYPASS_RATE_EQUIV_ONE_IN)
        );
    }

    #[test]
    fn purpose_clopper_pearson_reproduces_constants() {
        use super::purpose::*;
        let bound_999 = clopper_pearson_upper_bound(15_000_000, 0.001);
        assert!(
            (bound_999 - BYPASS_RATE_UPPER_999).abs() < 1e-10,
            "clopper_pearson(15M, 0.001) = {}, expected ~{}",
            bound_999,
            BYPASS_RATE_UPPER_999
        );

        let bound_99 = clopper_pearson_upper_bound(15_000_000, 0.01);
        assert!(
            (bound_99 - BYPASS_RATE_UPPER_99).abs() < 1e-10,
            "clopper_pearson(15M, 0.01) = {}, expected ~{}",
            bound_99,
            BYPASS_RATE_UPPER_99
        );

        let bound_95 = clopper_pearson_upper_bound(15_000_000, 0.05);
        assert!(
            (bound_95 - BYPASS_RATE_UPPER_95).abs() < 1e-10,
            "clopper_pearson(15M, 0.05) = {}, expected ~{}",
            bound_95,
            BYPASS_RATE_UPPER_95
        );
    }

    #[test]
    fn purpose_clopper_pearson_monotonic_in_n() {
        use super::purpose::clopper_pearson_upper_bound;
        // More episodes = tighter bound
        let bound_1m = clopper_pearson_upper_bound(1_000_000, 0.001);
        let bound_5m = clopper_pearson_upper_bound(5_000_000, 0.001);
        let bound_15m = clopper_pearson_upper_bound(15_000_000, 0.001);
        assert!(bound_1m > bound_5m, "1M bound must be wider than 5M");
        assert!(bound_5m > bound_15m, "5M bound must be wider than 15M");
    }

    #[test]
    #[should_panic(expected = "n must be > 0")]
    fn purpose_clopper_pearson_panics_on_zero_n() {
        super::purpose::clopper_pearson_upper_bound(0, 0.05);
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0, 1)")]
    fn purpose_clopper_pearson_panics_on_alpha_zero() {
        super::purpose::clopper_pearson_upper_bound(100, 0.0);
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0, 1)")]
    fn purpose_clopper_pearson_panics_on_alpha_one() {
        super::purpose::clopper_pearson_upper_bound(100, 1.0);
    }

    #[test]
    fn purpose_coverage_domains_count() {
        use super::purpose::CoverageDomain;
        assert_eq!(CoverageDomain::all().len(), 6);
    }

    #[test]
    fn purpose_coverage_domains_all_have_descriptions() {
        use super::purpose::CoverageDomain;
        for domain in CoverageDomain::all() {
            assert!(
                !domain.description().is_empty(),
                "domain {:?} must have a description",
                domain
            );
        }
    }

    #[test]
    fn purpose_coverage_domains_unique() {
        use super::purpose::CoverageDomain;
        let domains: Vec<_> = CoverageDomain::all().to_vec();
        for (i, a) in domains.iter().enumerate() {
            for (j, b) in domains.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "domains must be unique");
                }
            }
        }
    }

    #[test]
    fn purpose_audit_trail_properties() {
        use super::purpose::audit_trail;
        const _: () = assert!(audit_trail::SIGNED);
        const _: () = assert!(audit_trail::HASH_CHAINED);
        const _: () = assert!(audit_trail::TAMPER_PROOF);
        assert_eq!(audit_trail::SIGNATURE_ALGORITHM, "Ed25519");
    }

    // ── Category A: Normal Operation ──────────────────────────────────

    #[test]
    fn normal_operation_scenario_count() {
        use super::normal_operation::*;
        assert_eq!(SCENARIO_COUNT, 8);
        assert_eq!(NormalScenario::all().len(), SCENARIO_COUNT as usize);
    }

    #[test]
    fn normal_operation_total_episodes() {
        use super::normal_operation::*;
        assert_eq!(TOTAL_EPISODES, 3_100_000);
        let sum: u64 = NormalScenario::all().iter().map(|s| s.episodes()).sum();
        assert_eq!(sum, TOTAL_EPISODES);
    }

    #[test]
    fn normal_operation_scenario_count_consistent_with_category() {
        use super::normal_operation;
        use super::scenario_categories::ScenarioCategory;
        assert_eq!(
            normal_operation::SCENARIO_COUNT,
            ScenarioCategory::NormalOperation.scenarios(),
        );
    }

    #[test]
    fn normal_operation_ids_sequential() {
        use super::normal_operation::NormalScenario;
        let ids: Vec<&str> = NormalScenario::all().iter().map(|s| s.id()).collect();
        assert_eq!(
            ids,
            vec!["A-01", "A-02", "A-03", "A-04", "A-05", "A-06", "A-07", "A-08"]
        );
    }

    #[test]
    fn normal_operation_steps_within_spec_range() {
        use super::normal_operation::NormalScenario;
        for s in NormalScenario::all() {
            assert!(
                s.steps() >= 200 && s.steps() <= 1000,
                "{} has {} steps, must be in [200, 1000]",
                s.id(),
                s.steps()
            );
        }
    }

    #[test]
    fn normal_operation_baseline_has_most_episodes() {
        use super::normal_operation::NormalScenario;
        let baseline = NormalScenario::BaselineSafeOperation;
        for s in NormalScenario::all() {
            assert!(
                baseline.episodes() >= s.episodes(),
                "A-01 should have the most episodes, but {} has more",
                s.id()
            );
        }
    }

    #[test]
    fn normal_operation_all_scenarios_have_names() {
        use super::normal_operation::NormalScenario;
        for s in NormalScenario::all() {
            assert!(!s.name().is_empty(), "{} must have a name", s.id());
        }
    }

    #[test]
    fn normal_operation_display_format() {
        use super::normal_operation::NormalScenario;
        let display = format!("{}", NormalScenario::BaselineSafeOperation);
        assert_eq!(display, "A-01: Baseline safe operation");
    }

    #[test]
    fn normal_operation_serialization_round_trip() {
        use super::normal_operation::NormalScenario;
        let s = NormalScenario::WalkingGaitCycle;
        let json = serde_json::to_string(&s).expect("must serialize");
        let back: NormalScenario = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(back, s);
    }

    #[test]
    fn normal_operation_all_scenarios_unique() {
        use super::normal_operation::NormalScenario;
        let scenarios: Vec<_> = NormalScenario::all().to_vec();
        for (i, a) in scenarios.iter().enumerate() {
            for (j, b) in scenarios.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "scenarios must be unique");
                }
            }
        }
    }
}
