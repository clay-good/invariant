// Campaign configuration: YAML-driven campaign definition for dry-run and
// Isaac Lab simulation campaigns.

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
    #[serde(default)]
    pub max_false_rejection_rate: f64,
}

fn default_min_pass_rate() -> f64 {
    0.98
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
// 15M Campaign Config Generator (spec-15m-campaign.md Step 3)
// ---------------------------------------------------------------------------

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
        ProfileAllocation {
            name: "humanoid_28dof",
            weight: 0.10,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "unitree_h1",
            weight: 0.08,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "unitree_g1",
            weight: 0.07,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "ur10e_haas_cell",
            weight: 0.09,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "ur10e_cnc_tending",
            weight: 0.07,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "franka_panda",
            weight: 0.07,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "kuka_iiwa14",
            weight: 0.06,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "kinova_gen3",
            weight: 0.05,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "abb_gofa",
            weight: 0.05,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "spot",
            weight: 0.07,
            has_locomotion: true,
        },
        ProfileAllocation {
            name: "quadruped_12dof",
            weight: 0.05,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "shadow_hand",
            weight: 0.04,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "ur10",
            weight: 0.04,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "adversarial_zero_margin",
            weight: 0.04,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "adversarial_max_workspace",
            weight: 0.04,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "adversarial_single_joint",
            weight: 0.04,
            has_locomotion: false,
        },
        ProfileAllocation {
            name: "adversarial_max_joints",
            weight: 0.04,
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

        let episodes_per_shard = (profile_episodes / shards as u64).max(1);
        let steps_per_episode: u32 = 200;

        // Split into environments × episodes_per_env to respect MAX_EPISODES_PER_ENV.
        let max_eps = MAX_EPISODES_PER_ENV as u64;
        let envs = episodes_per_shard.div_ceil(max_eps) as u32;
        let eps_per_env = (episodes_per_shard / envs as u64) as u32;

        for shard_id in 0..shards {
            configs.push(CampaignConfig {
                name: format!("15m_{}_{}", profile.name, shard_id),
                profile: profile.name.to_string(),
                environments: envs,
                episodes_per_env: eps_per_env,
                steps_per_episode,
                scenarios: scenarios.clone(),
                success_criteria: SuccessCriteria {
                    min_legitimate_pass_rate: 0.99,
                    max_violation_escape_rate: 0.0,
                    max_false_rejection_rate: 0.01,
                },
            });
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

    // ── 15M campaign config generator tests ───────────────────────────

    #[test]
    fn generate_15m_produces_configs_for_all_profiles() {
        let configs = generate_15m_configs(15_000_000, 8);
        // 17 profiles × 8 shards = 136 configs
        assert_eq!(configs.len(), 136, "17 profiles × 8 shards");
    }

    #[test]
    fn generate_15m_total_episodes_approximately_correct() {
        let configs = generate_15m_configs(15_000_000, 8);
        let total: u64 = configs
            .iter()
            .map(|c| c.environments as u64 * c.episodes_per_env as u64)
            .sum();
        // Allow 5% tolerance due to integer rounding across 17 profiles × 8 shards
        assert!(
            total >= 14_000_000 && total <= 16_000_000,
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
    fn generate_15m_locomotion_profiles_have_locomotion_scenarios() {
        let configs = generate_15m_configs(15_000_000, 8);
        let humanoid_config = configs
            .iter()
            .find(|c| c.name.starts_with("15m_humanoid_28dof_"))
            .unwrap();
        assert!(
            humanoid_config
                .scenarios
                .iter()
                .any(|s| s.scenario_type == "locomotion_runaway"),
            "humanoid must have locomotion_runaway scenario"
        );
    }

    #[test]
    fn generate_15m_arm_profiles_skip_locomotion_scenarios() {
        let configs = generate_15m_configs(15_000_000, 8);
        let panda_config = configs
            .iter()
            .find(|c| c.name.starts_with("15m_franka_panda_"))
            .unwrap();
        assert!(
            !panda_config
                .scenarios
                .iter()
                .any(|s| s.scenario_type.starts_with("locomotion_")),
            "franka_panda must not have locomotion scenarios"
        );
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
}
