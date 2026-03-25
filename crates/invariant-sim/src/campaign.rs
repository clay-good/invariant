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

/// Read and parse a `CampaignConfig` from a YAML file.
pub fn load_config_file(path: &std::path::Path) -> Result<CampaignConfig, CampaignError> {
    let yaml = std::fs::read_to_string(path)?;
    load_config(&yaml)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_config(config: &CampaignConfig) -> Result<(), CampaignError> {
    if config.name.is_empty() {
        return Err(CampaignError::Validation("campaign name must not be empty".into()));
    }
    if config.profile.is_empty() {
        return Err(CampaignError::Validation("profile must not be empty".into()));
    }
    if config.environments == 0 {
        return Err(CampaignError::Validation("environments must be > 0".into()));
    }
    if config.episodes_per_env == 0 {
        return Err(CampaignError::Validation("episodes_per_env must be > 0".into()));
    }
    if config.steps_per_episode == 0 {
        return Err(CampaignError::Validation("steps_per_episode must be > 0".into()));
    }
    if config.scenarios.is_empty() {
        return Err(CampaignError::Validation("scenarios must not be empty".into()));
    }
    for (i, sc) in config.scenarios.iter().enumerate() {
        if sc.scenario_type.is_empty() {
            return Err(CampaignError::Validation(
                format!("scenario[{i}].scenario_type must not be empty"),
            ));
        }
        if sc.weight <= 0.0 {
            return Err(CampaignError::Validation(
                format!("scenario[{i}].weight must be > 0 (got {})", sc.weight),
            ));
        }
    }

    let criteria = &config.success_criteria;
    if criteria.min_legitimate_pass_rate < 0.0 || criteria.min_legitimate_pass_rate > 1.0 {
        return Err(CampaignError::Validation(
            format!(
                "success_criteria.min_legitimate_pass_rate must be in [0, 1] (got {})",
                criteria.min_legitimate_pass_rate
            ),
        ));
    }
    if criteria.max_violation_escape_rate < 0.0 || criteria.max_violation_escape_rate > 1.0 {
        return Err(CampaignError::Validation(
            format!(
                "success_criteria.max_violation_escape_rate must be in [0, 1] (got {})",
                criteria.max_violation_escape_rate
            ),
        ));
    }
    if criteria.max_false_rejection_rate < 0.0 || criteria.max_false_rejection_rate > 1.0 {
        return Err(CampaignError::Validation(
            format!(
                "success_criteria.max_false_rejection_rate must be in [0, 1] (got {})",
                criteria.max_false_rejection_rate
            ),
        ));
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
        assert_eq!(cfg.scenarios[0].injections, vec!["VelocityOvershoot", "PositionViolation"]);
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
    fn load_config_file_nonexistent() {
        let err = load_config_file(std::path::Path::new("/nonexistent/campaign.yaml")).unwrap_err();
        assert!(matches!(err, CampaignError::Io(_)));
    }
}
