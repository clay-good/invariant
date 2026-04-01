// Campaign configuration: YAML-driven campaign definition for dry-run and
// Isaac Lab simulation campaigns.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum CampaignError {
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("I/O error reading campaign file: {0}")]
    Io(#[from] std::io::Error),

    #[error("campaign validation error: {0}")]
    Validation(String),
}

// ---------------------------------------------------------------------------
// Config types
// ---------------------------------------------------------------------------

/// Top-level campaign configuration, loaded from YAML.
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
const MAX_TOTAL_COMMANDS: u64 = 10_000_000;

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
        // MAX_TOTAL_COMMANDS = 10_000_000. Use 1 env × 10_000_000 steps × 1 episode
        // but stay within per-field limits.  Use 10 envs × 1_000_000 steps = 10M.
        // However MAX_STEPS_PER_EPISODE = 1_000_000 and MAX_ENVIRONMENTS = 10_000.
        // 10 × 1 × 1_000_000 = 10_000_000 exactly.
        let config = CampaignConfig {
            name: "boundary_test".to_string(),
            profile: "franka_panda".to_string(),
            environments: 10,
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
        // 10 envs × 1 episode × 1_000_001 steps = 10_000_010 > MAX_TOTAL_COMMANDS.
        let config = CampaignConfig {
            name: "over_limit".to_string(),
            profile: "franka_panda".to_string(),
            environments: 10,
            episodes_per_env: 1,
            steps_per_episode: 1_000_001,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        // steps_per_episode > MAX_STEPS_PER_EPISODE fires first, but
        // the resulting total would also exceed MAX_TOTAL_COMMANDS.
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
}
