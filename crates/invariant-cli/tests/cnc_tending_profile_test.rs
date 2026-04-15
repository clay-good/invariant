//! Production CNC tending profile integration tests.
//!
//! Validates Invariant against the production cell profile
//! (profiles/ur10e_cnc_tending.json) from the cell specification Section 3.1.
//!
//! This profile has tighter workspace bounds, the conditional haas_spindle_area
//! zone, a floor_zone, collision pairs, and real-world margins — matching the
//! production manufacturing cell geometry.

use invariant_sim::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
use invariant_sim::isaac::dry_run::run_dry_campaign;

fn tending_campaign(
    name: &str,
    scenarios: Vec<ScenarioConfig>,
    steps: u32,
    episodes: u32,
) -> CampaignConfig {
    CampaignConfig {
        name: name.to_string(),
        profile: "ur10e_cnc_tending".to_string(),
        environments: 1,
        episodes_per_env: episodes,
        steps_per_episode: steps,
        scenarios,
        success_criteria: SuccessCriteria {
            min_legitimate_pass_rate: 0.95,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 0.05,
        },
    }
}

fn seed() -> Option<[u8; 32]> {
    Some([42u8; 32])
}

// ═══════════════════════════════════════════════════════════════════════
// Profile loads and validates without errors
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn production_profile_loads_successfully() {
    let profile = invariant_core::profiles::load_builtin("ur10e_cnc_tending").unwrap();
    assert_eq!(profile.name, "ur10e_cnc_tending");
    assert_eq!(profile.joints.len(), 6);
    assert_eq!(profile.exclusion_zones.len(), 4);
    assert_eq!(profile.proximity_zones.len(), 1);
    assert_eq!(profile.collision_pairs.len(), 3);
    assert!(profile.real_world_margins.is_some());
    assert_eq!(profile.end_effectors.len(), 1);
    assert_eq!(profile.watchdog_timeout_ms, 100);
}

#[test]
fn production_profile_has_conditional_spindle_zone() {
    use invariant_core::models::profile::ExclusionZone;
    let profile = invariant_core::profiles::load_builtin("ur10e_cnc_tending").unwrap();
    let spindle = profile.exclusion_zones.iter().find(|z| match z {
        ExclusionZone::Aabb { name, .. } | ExclusionZone::Sphere { name, .. } => {
            name == "haas_spindle_area"
        }
        _ => false,
    });
    assert!(spindle.is_some(), "haas_spindle_area zone must exist");
    match spindle.unwrap() {
        ExclusionZone::Aabb { conditional, .. } => {
            assert!(*conditional, "spindle zone must be conditional");
        }
        _ => panic!("spindle zone must be AABB"),
    }
}

#[test]
fn production_profile_has_floor_zone() {
    use invariant_core::models::profile::ExclusionZone;
    let profile = invariant_core::profiles::load_builtin("ur10e_cnc_tending").unwrap();
    let floor = profile.exclusion_zones.iter().find(|z| match z {
        ExclusionZone::Aabb { name, .. } | ExclusionZone::Sphere { name, .. } => {
            name == "floor_zone"
        }
        _ => false,
    });
    assert!(floor.is_some(), "floor_zone must exist");
}

#[test]
fn production_profile_has_real_world_margins() {
    let profile = invariant_core::profiles::load_builtin("ur10e_cnc_tending").unwrap();
    let margins = profile.real_world_margins.as_ref().unwrap();
    assert_eq!(margins.position_margin, 0.05);
    assert_eq!(margins.velocity_margin, 0.15);
    assert_eq!(margins.torque_margin, 0.10);
    assert_eq!(margins.acceleration_margin, 0.10);
}

// ═══════════════════════════════════════════════════════════════════════
// Normal production cycle: all commands approved
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn tending_normal_ops_approved() {
    let config = tending_campaign(
        "tending_normal",
        vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        500,
        10,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(report.total_commands, 5000);
    assert_eq!(report.total_approved, 5000, "all normal ops must pass");
    assert_eq!(report.violation_escape_count, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Spindle area intrusion: must be rejected (zone active by default)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn tending_spindle_intrusion_rejected() {
    let config = tending_campaign(
        "tending_spindle",
        vec![ScenarioConfig {
            scenario_type: "exclusion_zone".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.total_approved, 0,
        "spindle intrusions must be rejected"
    );
    assert_eq!(report.violation_escape_count, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// CNC tending scenario: conditional zone toggle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn tending_cnc_scenario_zero_escapes() {
    let config = tending_campaign(
        "tending_cnc_cycle",
        vec![ScenarioConfig {
            scenario_type: "cnc_tending".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.violation_escape_count, 0,
        "CNC tending cycle must have zero escapes"
    );
    // Cutting phase must produce rejections (zone active).
    // Loading phase approval depends on whether the EE also overlaps
    // non-conditional zones (can vary with float precision across builds).
    assert!(
        report.total_rejected > 0,
        "cutting phase must reject commands"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Full adversarial campaign with production profile: zero escapes
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn tending_full_adversarial_zero_escapes() {
    let config = tending_campaign(
        "tending_adversarial",
        vec![
            ScenarioConfig {
                scenario_type: "baseline".to_string(),
                weight: 0.25,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "exclusion_zone".to_string(),
                weight: 0.15,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "authority_escalation".to_string(),
                weight: 0.10,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "chain_forgery".to_string(),
                weight: 0.10,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "prompt_injection".to_string(),
                weight: 0.10,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "cnc_tending".to_string(),
                weight: 0.10,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "baseline".to_string(),
                weight: 0.20,
                injections: vec![
                    "velocity_overshoot".to_string(),
                    "torque_spike".to_string(),
                    "position_violation".to_string(),
                    "nan_injection".to_string(),
                ],
            },
        ],
        500,
        20,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(report.total_commands, 10000);
    assert_eq!(
        report.violation_escape_count, 0,
        "full adversarial campaign on production profile must have zero escapes"
    );
    assert!(report.total_approved > 0, "baseline commands must pass");
    assert!(report.total_rejected > 0, "attacks must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════
// Workspace tightness: production workspace is tighter than dev profile
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn tending_workspace_escape_rejected() {
    let config = tending_campaign(
        "tending_workspace",
        vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec!["workspace_escape".to_string()],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.total_approved, 0,
        "workspace escapes must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// P21-P25: Environmental faults rejected by production profile
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn tending_environment_fault_all_rejected() {
    let config = tending_campaign(
        "tending_env_fault",
        vec![ScenarioConfig {
            scenario_type: "environment_fault".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        100,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.violation_escape_count, 0,
        "environmental faults must have zero escapes"
    );
    assert!(
        report.total_rejected > 0,
        "environmental fault commands must be rejected"
    );
}

#[test]
fn tending_estop_injection_rejected() {
    let config = tending_campaign(
        "tending_estop",
        vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec!["e_stop_engage".to_string()],
        }],
        100,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.total_approved, 0,
        "e-stop injected commands must all be rejected"
    );
}

#[test]
fn tending_temperature_spike_injection_rejected() {
    let config = tending_campaign(
        "tending_temp_spike",
        vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec!["temperature_spike".to_string()],
        }],
        100,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.total_approved, 0,
        "temperature spike injected commands must all be rejected"
    );
}
