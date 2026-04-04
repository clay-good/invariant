//! UR10e + Haas VF-2 CNC cell integration tests.
//!
//! These tests validate Invariant against the actual production cell profile
//! (profiles/ur10e_haas_cell.json) with scenarios specific to CNC tending:
//! spindle zone intrusion, operator proximity, gripper force limits,
//! watchdog timeout, and full adversarial campaigns.

use invariant_sim::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
use invariant_sim::isaac::dry_run::run_dry_campaign;

fn cell_campaign(
    name: &str,
    scenarios: Vec<ScenarioConfig>,
    steps: u32,
    episodes: u32,
) -> CampaignConfig {
    CampaignConfig {
        name: name.to_string(),
        profile: "ur10e_haas_cell".to_string(),
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
// Normal production cycle: all commands approved
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_normal_ops_all_approved() {
    let config = cell_campaign(
        "normal_ops",
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
    assert_eq!(
        report.total_approved, 5000,
        "all normal ops must be approved"
    );
    assert_eq!(report.violation_escape_count, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Spindle zone intrusion: robot reaches into CNC enclosure
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_spindle_intrusion_all_rejected() {
    let config = cell_campaign(
        "spindle_intrusion",
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
        "spindle zone intrusions must all be rejected"
    );
    assert_eq!(report.violation_escape_count, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Velocity overshoot: arm moves too fast near the machine
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_velocity_overshoot_rejected() {
    let config = cell_campaign(
        "velocity_attack",
        vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec!["velocity_overshoot".to_string()],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.total_approved, 0,
        "velocity overshoot must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Torque spike: gripper applies excessive force (crushing workpiece)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_torque_spike_rejected() {
    let config = cell_campaign(
        "torque_attack",
        vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec!["torque_spike".to_string()],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(report.total_approved, 0, "torque spikes must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════
// Position violation: joints commanded past limits
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_position_violation_rejected() {
    let config = cell_campaign(
        "position_attack",
        vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec!["position_violation".to_string()],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.total_approved, 0,
        "position violations must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Authority strip: edge PC crashes, no valid PCA chain
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_authority_strip_rejected() {
    let config = cell_campaign(
        "brain_crash",
        vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec!["authority_strip".to_string()],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.total_approved, 0,
        "commands without authority must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// NaN injection: sensor spoofing / corrupted data
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_nan_injection_rejected() {
    let config = cell_campaign(
        "nan_attack",
        vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec!["nan_injection".to_string()],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.total_approved, 0,
        "NaN-injected commands must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// LLM hallucination: 10x position, 5x velocity
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_llm_hallucination_rejected() {
    let config = cell_campaign(
        "hallucination",
        vec![ScenarioConfig {
            scenario_type: "prompt_injection".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(
        report.total_approved, 0,
        "hallucinated commands must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Chain forgery: attacker tries to forge authority chain
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_chain_forgery_rejected() {
    let config = cell_campaign(
        "forgery",
        vec![ScenarioConfig {
            scenario_type: "chain_forgery".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        200,
        5,
    );
    let report = run_dry_campaign(&config, seed()).unwrap();
    assert_eq!(report.total_approved, 0, "forged chains must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════
// Full adversarial: mixed attack campaign, zero escapes
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_full_adversarial_zero_escapes() {
    let config = cell_campaign(
        "full_adversarial",
        vec![
            ScenarioConfig {
                scenario_type: "baseline".to_string(),
                weight: 0.3,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "exclusion_zone".to_string(),
                weight: 0.15,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "authority_escalation".to_string(),
                weight: 0.1,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "chain_forgery".to_string(),
                weight: 0.1,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "prompt_injection".to_string(),
                weight: 0.1,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "baseline".to_string(),
                weight: 0.25,
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
        "full adversarial campaign must have zero escapes"
    );
    assert!(
        report.total_approved > 0,
        "some baseline commands must be approved"
    );
    assert!(
        report.total_rejected > 0,
        "attack commands must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Workspace escape: arm reaches outside cell boundaries
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cnc_cell_workspace_escape_rejected() {
    let config = cell_campaign(
        "workspace_escape",
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
