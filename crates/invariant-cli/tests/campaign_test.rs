//! End-to-end campaign integration tests.
//!
//! Runs dry-run simulation campaigns through the `run_dry_campaign` pipeline
//! and verifies aggregate results.

use invariant_sim::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
use invariant_sim::isaac::dry_run::run_dry_campaign;

fn baseline_config(steps: u32) -> CampaignConfig {
    CampaignConfig {
        name: "integration-test".to_string(),
        profile: "franka_panda".to_string(),
        environments: 1,
        episodes_per_env: 1,
        steps_per_episode: steps,
        scenarios: vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        success_criteria: SuccessCriteria::default(),
    }
}

// ---------------------------------------------------------------------------
// Test: baseline campaign runs and produces a report
// ---------------------------------------------------------------------------

#[test]
fn baseline_campaign_produces_report() {
    let config = baseline_config(20);
    let report = run_dry_campaign(&config, Some([42u8; 32])).unwrap();
    assert_eq!(report.total_commands, 20);
    assert!(
        report.total_approved > 0,
        "baseline should have approved commands"
    );
}

// ---------------------------------------------------------------------------
// Test: prompt injection campaign — all rejected
// ---------------------------------------------------------------------------

#[test]
fn prompt_injection_campaign_all_rejected() {
    let config = CampaignConfig {
        name: "prompt-injection-test".to_string(),
        profile: "franka_panda".to_string(),
        environments: 1,
        episodes_per_env: 1,
        steps_per_episode: 20,
        scenarios: vec![ScenarioConfig {
            scenario_type: "prompt_injection".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        success_criteria: SuccessCriteria::default(),
    };
    let report = run_dry_campaign(&config, Some([42u8; 32])).unwrap();
    assert_eq!(report.total_commands, 20);
    assert_eq!(
        report.total_approved, 0,
        "prompt injection must reject all commands"
    );
}

// ---------------------------------------------------------------------------
// Test: authority escalation — all rejected
// ---------------------------------------------------------------------------

#[test]
fn authority_escalation_all_rejected() {
    let config = CampaignConfig {
        name: "authority-escalation-test".to_string(),
        profile: "franka_panda".to_string(),
        environments: 1,
        episodes_per_env: 1,
        steps_per_episode: 10,
        scenarios: vec![ScenarioConfig {
            scenario_type: "authority_escalation".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        success_criteria: SuccessCriteria::default(),
    };
    let report = run_dry_campaign(&config, Some([42u8; 32])).unwrap();
    assert_eq!(report.total_commands, 10);
    assert_eq!(
        report.total_approved, 0,
        "authority escalation must reject all"
    );
}

// ---------------------------------------------------------------------------
// Test: chain forgery — all rejected
// ---------------------------------------------------------------------------

#[test]
fn chain_forgery_all_rejected() {
    let config = CampaignConfig {
        name: "chain-forgery-test".to_string(),
        profile: "humanoid_28dof".to_string(),
        environments: 1,
        episodes_per_env: 1,
        steps_per_episode: 10,
        scenarios: vec![ScenarioConfig {
            scenario_type: "chain_forgery".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        success_criteria: SuccessCriteria::default(),
    };
    let report = run_dry_campaign(&config, Some([42u8; 32])).unwrap();
    assert_eq!(report.total_commands, 10);
    assert_eq!(
        report.total_approved, 0,
        "chain forgery must reject all"
    );
}

// ---------------------------------------------------------------------------
// Test: all 11 scenario types run without error
// ---------------------------------------------------------------------------

#[test]
fn all_scenario_types_run_without_error() {
    let scenario_names = [
        "baseline",
        "aggressive",
        "exclusion_zone",
        "authority_escalation",
        "chain_forgery",
        "prompt_injection",
        "multi_agent_handoff",
        "locomotion_runaway",
        "locomotion_slip",
        "locomotion_trip",
        "locomotion_fall",
    ];

    for name in &scenario_names {
        let config = CampaignConfig {
            name: format!("test-{name}"),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 5,
            scenarios: vec![ScenarioConfig {
                scenario_type: name.to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let result = run_dry_campaign(&config, Some([42u8; 32]));
        assert!(
            result.is_ok(),
            "scenario '{name}' failed: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().total_commands, 5);
    }
}

// ---------------------------------------------------------------------------
// Test: campaign with fault injection
// ---------------------------------------------------------------------------

#[test]
fn campaign_with_velocity_injection() {
    let config = CampaignConfig {
        name: "velocity-injection-test".to_string(),
        profile: "franka_panda".to_string(),
        environments: 1,
        episodes_per_env: 1,
        steps_per_episode: 10,
        scenarios: vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec!["velocity_overshoot".to_string()],
        }],
        success_criteria: SuccessCriteria::default(),
    };
    let report = run_dry_campaign(&config, Some([42u8; 32])).unwrap();
    assert_eq!(report.total_commands, 10);
    assert_eq!(
        report.total_approved, 0,
        "velocity overshoot injection must reject all"
    );
}
