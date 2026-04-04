//! CNC tending dry-run campaign integration test.
//!
//! Runs a campaign matching `cnc_tending_dry_run.yaml` against the production
//! `ur10e_cnc_tending` profile to verify:
//!   - All scenario types execute without errors
//!   - Zero violation escapes across 100K commands
//!   - CNC tending conditional zone toggle works end-to-end
//!   - Campaign criteria are met (PASSED)

use invariant_sim::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
use invariant_sim::isaac::dry_run::run_dry_campaign;

/// Build the CNC tending dry-run campaign config (matches cnc_tending_dry_run.yaml).
fn cnc_tending_config() -> CampaignConfig {
    CampaignConfig {
        name: "cnc_tending_dry_run_test".to_string(),
        profile: "ur10e_cnc_tending".to_string(),
        environments: 1,
        episodes_per_env: 100,
        steps_per_episode: 1000,
        scenarios: vec![
            ScenarioConfig {
                scenario_type: "baseline".into(),
                weight: 0.01,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "aggressive".into(),
                weight: 0.47,
                injections: vec![
                    "position_violation".into(),
                    "velocity_overshoot".into(),
                    "torque_spike".into(),
                ],
            },
            ScenarioConfig {
                scenario_type: "exclusion_zone".into(),
                weight: 0.19,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "baseline".into(),
                weight: 0.09,
                injections: vec!["torque_spike".into()],
            },
            ScenarioConfig {
                scenario_type: "baseline".into(),
                weight: 0.05,
                injections: vec!["nan_injection".into()],
            },
            ScenarioConfig {
                scenario_type: "authority_escalation".into(),
                weight: 0.05,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "chain_forgery".into(),
                weight: 0.04,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "baseline".into(),
                weight: 0.05,
                injections: vec!["velocity_overshoot".into(), "position_violation".into()],
            },
            ScenarioConfig {
                scenario_type: "cnc_tending".into(),
                weight: 0.04,
                injections: vec![],
            },
        ],
        success_criteria: SuccessCriteria {
            min_legitimate_pass_rate: 0.0,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 1.0,
        },
    }
}

fn seed() -> Option<[u8; 32]> {
    Some([42u8; 32])
}

#[test]
fn cnc_campaign_zero_escapes() {
    let config = cnc_tending_config();
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(report.total_commands, 100_000);
    assert_eq!(
        report.violation_escape_count, 0,
        "production campaign must have zero violation escapes"
    );
    assert!(report.criteria_met, "campaign criteria must be met");
}

#[test]
fn cnc_campaign_exercises_all_scenario_types() {
    let config = cnc_tending_config();
    let report = run_dry_campaign(&config, seed()).unwrap();
    for expected in &[
        "baseline",
        "aggressive",
        "exclusion_zone",
        "authority_escalation",
        "chain_forgery",
        "cnc_tending",
    ] {
        assert!(
            report.per_scenario.contains_key(*expected),
            "{expected} scenario must appear in report"
        );
    }
}

#[test]
fn cnc_campaign_cnc_tending_has_mixed_verdicts() {
    let config = cnc_tending_config();
    let report = run_dry_campaign(&config, seed()).unwrap();
    let cnc = report
        .per_scenario
        .get("cnc_tending")
        .expect("cnc_tending must appear");
    assert!(cnc.approved > 0, "CNC loading phase must approve commands");
    assert!(cnc.rejected > 0, "CNC cutting phase must reject commands");
    assert_eq!(cnc.escaped, 0, "CNC tending must have zero escapes");
}

#[test]
fn cnc_campaign_adversarial_all_rejected() {
    let config = cnc_tending_config();
    let report = run_dry_campaign(&config, seed()).unwrap();
    for name in &["exclusion_zone", "authority_escalation", "chain_forgery"] {
        let s = report.per_scenario.get(*name).unwrap();
        assert_eq!(s.approved, 0, "{name} must have zero approved commands");
        assert_eq!(s.escaped, 0, "{name} must have zero escapes");
    }
}
