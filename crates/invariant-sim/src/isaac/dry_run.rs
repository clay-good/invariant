// DryRunOrchestrator: runs campaign simulations without Isaac Lab.
//
// Loads a robot profile, generates Ed25519 keypairs for authority signing,
// builds PCA chains for legitimate scenarios, then drives each environment x
// episode x step through the Invariant validator and records results.

use std::collections::BTreeSet;
use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use invariant_core::authority::crypto::{generate_keypair, sign_pca};
use invariant_core::models::authority::{Operation, Pca, SignedPca};
use invariant_core::models::verdict::SignedVerdict;
use invariant_core::validator::ValidatorConfig;
use rand::rngs::OsRng;
use thiserror::Error;

use crate::campaign::CampaignConfig;
use crate::injector::{inject, InjectionType};
use crate::reporter::{CampaignReport, CampaignReporter};
use crate::scenario::{ScenarioGenerator, ScenarioType};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum DryRunError {
    #[error("profile load failed: {0}")]
    ProfileLoad(#[from] invariant_core::profiles::ProfileError),

    #[error("validator construction failed: {0}")]
    ValidatorBuild(#[from] invariant_core::validator::ValidatorError),

    #[error("unknown scenario type: {0:?}")]
    UnknownScenario(String),

    #[error("unknown injection type: {0:?}")]
    UnknownInjection(String),

    #[error("PCA signing failed: {0}")]
    PcaSign(#[from] invariant_core::models::error::AuthorityError),

    #[error("PCA chain serialization failed: {reason}")]
    PcaSerialize { reason: String },
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run a dry campaign (no Isaac Lab) and return the aggregated report.
///
/// For each environment × episode combination:
/// 1. A scenario is selected by weighted sampling (using a simple deterministic
///    scheme — no external RNG dependency to keep the function deterministic).
/// 2. Commands are generated via `ScenarioGenerator`.
/// 3. Optional fault injections are applied on top.
/// 4. Each command is validated through `ValidatorConfig::validate`.
/// 5. Results are recorded in `CampaignReporter`.
pub fn run_dry_campaign(config: &CampaignConfig) -> Result<CampaignReport, DryRunError> {
    // Guard against an empty scenarios slice that would cause select_scenario
    // to panic.  This can happen when run_dry_campaign is called with a
    // hand-constructed config that bypasses load_config validation.
    if config.scenarios.is_empty() {
        return Err(DryRunError::UnknownScenario(
            "campaign config contains no scenarios".to_string(),
        ));
    }

    // --- Profile loading ---
    let profile = load_profile(&config.profile)?;

    // --- Keypair setup ---
    // One root PCA key (trusted by the validator) and one signing key for
    // the validator itself.
    let mut rng = OsRng;
    let pca_sk = generate_keypair(&mut rng);
    let pca_vk = pca_sk.verifying_key();
    let validator_sk = generate_keypair(&mut rng);
    let pca_kid = "dry-run-root".to_string();
    let validator_kid = "dry-run-validator".to_string();

    // Build the trusted-keys map: only our root PCA key is trusted.
    let mut trusted_keys = HashMap::new();
    trusted_keys.insert(pca_kid.clone(), pca_vk);

    // --- Validator ---
    let validator =
        ValidatorConfig::new(profile.clone(), trusted_keys, validator_sk, validator_kid)?;

    // --- Required operations for all legitimate commands ---
    let required_ops = vec![Operation::new("actuate:*").expect("valid op string")];

    // --- Build a signed PCA chain for legitimate scenarios ---
    // A single-hop chain granting "actuate:*" signed by the trusted root key.
    let pca_claim = Pca {
        p_0: "dry-run-principal".to_string(),
        ops: {
            let mut s = BTreeSet::new();
            s.insert(Operation::new("actuate:*").expect("valid op string"));
            s
        },
        kid: pca_kid.clone(),
        exp: None,
        nbf: None,
    };
    let signed_pca = sign_pca(&pca_claim, &pca_sk)?;
    let pca_chain_b64 = encode_pca_chain(&[signed_pca])?;

    // --- Scenario weight prefix sums (for weighted selection) ---
    let total_weight: f64 = config.scenarios.iter().map(|s| s.weight).sum();
    let prefix: Vec<f64> = config
        .scenarios
        .iter()
        .scan(0.0_f64, |acc, s| {
            *acc += s.weight;
            Some(*acc)
        })
        .collect();

    // --- Reporter ---
    let mut reporter = CampaignReporter::new(config.name.clone(), config.success_criteria.clone());

    let profile_name = profile.name.clone();

    // --- Main simulation loop ---
    let total_episodes = config.environments as u64 * config.episodes_per_env as u64;
    for ep_idx in 0..total_episodes {
        // Select scenario deterministically from episode index.
        let scenario_cfg = select_scenario(ep_idx, total_weight, &prefix, &config.scenarios);
        let scenario_type = parse_scenario_type(&scenario_cfg.scenario_type)?;

        // Parse injection types.
        let injections: Vec<InjectionType> = scenario_cfg
            .injections
            .iter()
            .map(|s| parse_injection_type(s))
            .collect::<Result<Vec<_>, _>>()?;

        let expected_reject = is_expected_reject(scenario_type);

        // Generate commands for this episode.
        let gen = ScenarioGenerator::new(&profile, scenario_type);
        let mut commands = gen.generate_commands(
            config.steps_per_episode as usize,
            &pca_chain_b64,
            &required_ops,
        );

        // Apply fault injections (if any).
        if !injections.is_empty() {
            for cmd in commands.iter_mut() {
                for &inj in &injections {
                    inject(cmd, inj, &profile);
                }
            }
        }

        // Validate each command and record results.
        // Recompute `now` for each command so that timestamp-based checks
        // (e.g. replay detection, expiry) use a fresh wall-clock value rather
        // than a single frozen instant captured before the loop.
        for cmd in &commands {
            let now = Utc::now();
            let result = match validator.validate(cmd, now, None) {
                Ok(r) => r,
                Err(e) => {
                    // Truly fatal validator error (serialization failure).
                    // Build a synthetic rejection verdict so we never drop a command.
                    // Log the full error for debugging; expose only a generic
                    // message in the verdict to avoid leaking internal details.
                    eprintln!("[invariant-sim] validator error: {e}");
                    let sv = make_error_verdict(&profile_name, String::new(), now);
                    reporter.record_result(
                        &profile_name,
                        &scenario_cfg.scenario_type,
                        expected_reject,
                        &sv,
                    );
                    continue;
                }
            };
            reporter.record_result(
                &profile_name,
                &scenario_cfg.scenario_type,
                expected_reject,
                &result.signed_verdict,
            );
        }
    }

    Ok(reporter.finalize())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load a robot profile by name (built-in) or from a JSON file path.
fn load_profile(
    profile_spec: &str,
) -> Result<invariant_core::models::profile::RobotProfile, DryRunError> {
    // Try built-in names first.
    match invariant_core::profiles::load_builtin(profile_spec) {
        Ok(p) => return Ok(p),
        Err(invariant_core::profiles::ProfileError::UnknownProfile(_)) => {} // fall through to file
        Err(e) => return Err(DryRunError::ProfileLoad(e)),
    }

    // Treat as a file path.  Validate before reading to prevent path
    // traversal: reject paths containing `..` components and require a
    // `.json` extension.
    let path = std::path::Path::new(profile_spec);
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(DryRunError::ProfileLoad(
            invariant_core::profiles::ProfileError::UnknownProfile(
                "path traversal not allowed in profile path".to_string(),
            ),
        ));
    }
    if path.extension().and_then(|e| e.to_str()) != Some("json") {
        return Err(DryRunError::ProfileLoad(
            invariant_core::profiles::ProfileError::UnknownProfile(
                "profile file path must end with .json".to_string(),
            ),
        ));
    }

    let bytes = std::fs::read(path).map_err(|_| {
        DryRunError::ProfileLoad(invariant_core::profiles::ProfileError::UnknownProfile(
            profile_spec.to_string(),
        ))
    })?;
    invariant_core::profiles::load_from_bytes(&bytes).map_err(DryRunError::ProfileLoad)
}

/// Weighted scenario selection: uses a simple deterministic hash of `ep_idx`.
fn select_scenario<'a>(
    ep_idx: u64,
    total_weight: f64,
    prefix: &[f64],
    scenarios: &'a [crate::campaign::ScenarioConfig],
) -> &'a crate::campaign::ScenarioConfig {
    // Map episode index to [0, total_weight) using modular arithmetic on a
    // prime stride to spread selection evenly.
    let t = (ep_idx as f64 * 0.618_033_988_749_895 * total_weight) % total_weight;
    for (i, &cum) in prefix.iter().enumerate() {
        if t < cum {
            return &scenarios[i];
        }
    }
    // Fallback to last scenario (handles floating-point edge case where t == total_weight).
    scenarios.last().expect("scenarios must not be empty")
}

/// Map scenario type name string to the `ScenarioType` enum.
/// Accepts both PascalCase and snake_case (e.g. "Baseline" or "baseline").
fn parse_scenario_type(name: &str) -> Result<ScenarioType, DryRunError> {
    match name {
        "Baseline" | "baseline" => Ok(ScenarioType::Baseline),
        "Aggressive" | "aggressive" => Ok(ScenarioType::Aggressive),
        "ExclusionZone" | "exclusion_zone" => Ok(ScenarioType::ExclusionZone),
        "AuthorityEscalation" | "authority_escalation" => Ok(ScenarioType::AuthorityEscalation),
        "ChainForgery" | "chain_forgery" => Ok(ScenarioType::ChainForgery),
        "PromptInjection" | "prompt_injection" => Ok(ScenarioType::PromptInjection),
        "MultiAgentHandoff" | "multi_agent_handoff" => Ok(ScenarioType::MultiAgentHandoff),
        other => Err(DryRunError::UnknownScenario(other.to_string())),
    }
}

/// Map injection type name string to the `InjectionType` enum.
fn parse_injection_type(name: &str) -> Result<InjectionType, DryRunError> {
    match name {
        "VelocityOvershoot" => Ok(InjectionType::VelocityOvershoot),
        "PositionViolation" => Ok(InjectionType::PositionViolation),
        "TorqueSpike" => Ok(InjectionType::TorqueSpike),
        "WorkspaceEscape" => Ok(InjectionType::WorkspaceEscape),
        "DeltaTimeViolation" => Ok(InjectionType::DeltaTimeViolation),
        "SelfCollision" => Ok(InjectionType::SelfCollision),
        "StabilityViolation" => Ok(InjectionType::StabilityViolation),
        "AuthorityStrip" => Ok(InjectionType::AuthorityStrip),
        "ReplayAttack" => Ok(InjectionType::ReplayAttack),
        "NanInjection" => Ok(InjectionType::NanInjection),
        other => Err(DryRunError::UnknownInjection(other.to_string())),
    }
}

/// Returns `true` if commands from this scenario type should be rejected by
/// the validator.  `Baseline` and `Aggressive` are legitimate; all others
/// exercise specific violation classes.
fn is_expected_reject(scenario: ScenarioType) -> bool {
    !matches!(scenario, ScenarioType::Baseline | ScenarioType::Aggressive)
}

/// Base64-encode a `Vec<SignedPca>` chain as required by `CommandAuthority.pca_chain`.
fn encode_pca_chain(hops: &[SignedPca]) -> Result<String, DryRunError> {
    let json = serde_json::to_vec(hops).map_err(|e| DryRunError::PcaSerialize {
        reason: e.to_string(),
    })?;
    Ok(STANDARD.encode(&json))
}

/// Build a synthetic rejection `SignedVerdict` for fatal validator errors.
///
/// Used so that every command contributes exactly one result to the reporter
/// even when `ValidatorConfig::validate` returns `Err(...)`.
///
/// The `details` field is deliberately generic to avoid leaking internal
/// error messages to callers.  Full error information is logged to stderr.
fn make_error_verdict(
    profile_name: &str,
    _error_detail: String,
    now: chrono::DateTime<Utc>,
) -> SignedVerdict {
    use invariant_core::models::verdict::{AuthoritySummary, CheckResult, Verdict};
    SignedVerdict {
        verdict: Verdict {
            approved: false,
            command_hash: "sha256:error".to_string(),
            command_sequence: 0,
            timestamp: now,
            checks: vec![CheckResult {
                name: "validator_error".to_string(),
                category: "system".to_string(),
                passed: false,
                details: "internal validation error".to_string(),
            }],
            profile_name: profile_name.to_string(),
            profile_hash: String::new(),
            authority_summary: AuthoritySummary {
                origin_principal: String::new(),
                hop_count: 0,
                operations_granted: vec![],
                operations_required: vec![],
            },
        },
        verdict_signature: String::new(),
        signer_kid: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};

    fn baseline_config(steps: u32) -> CampaignConfig {
        CampaignConfig {
            name: "dry_run_test".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: steps,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        }
    }

    fn violation_config() -> CampaignConfig {
        CampaignConfig {
            name: "dry_run_violation_test".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 2,
            steps_per_episode: 3,
            scenarios: vec![
                ScenarioConfig {
                    scenario_type: "Baseline".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "AuthorityEscalation".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
            ],
            success_criteria: SuccessCriteria::default(),
        }
    }

    // --- Basic smoke test ---

    #[test]
    fn dry_run_baseline_completes() {
        let config = baseline_config(5);
        let report = run_dry_campaign(&config).expect("dry run must complete");
        assert_eq!(report.campaign_name, "dry_run_test");
        assert_eq!(report.total_commands, 5);
    }

    #[test]
    fn dry_run_baseline_all_approved() {
        let config = baseline_config(10);
        let report = run_dry_campaign(&config).expect("dry run must complete");
        // All baseline commands should be approved (valid PCA chain, valid physics).
        assert_eq!(
            report.total_approved, 10,
            "all baseline commands must be approved"
        );
        assert_eq!(report.total_rejected, 0);
        assert!((report.approval_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn dry_run_authority_escalation_all_rejected() {
        let config = CampaignConfig {
            name: "auth_test".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 4,
            scenarios: vec![ScenarioConfig {
                scenario_type: "AuthorityEscalation".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config).expect("dry run must complete");
        assert_eq!(report.total_commands, 4);
        // AuthorityEscalation commands have no PCA chain — must all be rejected.
        assert_eq!(
            report.total_rejected, 4,
            "all authority-escalation commands must be rejected"
        );
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn dry_run_violation_escape_count_zero() {
        let config = violation_config();
        let report = run_dry_campaign(&config).expect("dry run must complete");
        assert_eq!(
            report.violation_escape_count, 0,
            "no violation should escape a correct validator"
        );
    }

    #[test]
    fn dry_run_criteria_met_on_clean_run() {
        let config = baseline_config(20);
        let report = run_dry_campaign(&config).expect("dry run must complete");
        assert!(
            report.criteria_met,
            "criteria must be met on a baseline-only campaign"
        );
    }

    // --- Multi-environment / multi-episode ---

    #[test]
    fn dry_run_multi_env_total_commands_correct() {
        let config = CampaignConfig {
            name: "multi".to_string(),
            profile: "franka_panda".to_string(),
            environments: 3,
            episodes_per_env: 4,
            steps_per_episode: 5,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config).expect("dry run must complete");
        // 3 * 4 * 5 = 60 commands total.
        assert_eq!(report.total_commands, 60);
    }

    // --- Scenario parsing ---

    #[test]
    fn unknown_scenario_returns_error() {
        let config = CampaignConfig {
            name: "bad".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "NonExistentScenario".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let err = run_dry_campaign(&config).unwrap_err();
        assert!(matches!(err, DryRunError::UnknownScenario(_)));
    }

    #[test]
    fn unknown_injection_returns_error() {
        let config = CampaignConfig {
            name: "bad_inj".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec!["GhostInjection".to_string()],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let err = run_dry_campaign(&config).unwrap_err();
        assert!(matches!(err, DryRunError::UnknownInjection(_)));
    }

    // --- Empty scenarios ---

    #[test]
    fn empty_scenarios_returns_error_not_panic() {
        // Build the config directly, bypassing load_config validation, to
        // exercise the early guard inside run_dry_campaign.
        let config = CampaignConfig {
            name: "empty_sc".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![],
            success_criteria: SuccessCriteria::default(),
        };
        let err = run_dry_campaign(&config).unwrap_err();
        assert!(matches!(err, DryRunError::UnknownScenario(_)));
    }

    // --- Unknown profile ---

    #[test]
    fn unknown_profile_returns_error() {
        let config = CampaignConfig {
            name: "bad_profile".to_string(),
            profile: "nonexistent_robot".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let err = run_dry_campaign(&config).unwrap_err();
        assert!(matches!(err, DryRunError::ProfileLoad(_)));
    }

    // --- is_expected_reject ---

    #[test]
    fn expected_reject_classification() {
        assert!(!is_expected_reject(ScenarioType::Baseline));
        assert!(!is_expected_reject(ScenarioType::Aggressive));
        assert!(is_expected_reject(ScenarioType::ExclusionZone));
        assert!(is_expected_reject(ScenarioType::AuthorityEscalation));
        assert!(is_expected_reject(ScenarioType::ChainForgery));
        assert!(is_expected_reject(ScenarioType::PromptInjection));
        assert!(is_expected_reject(ScenarioType::MultiAgentHandoff));
    }

    // --- Weighted scenario selection coverage ---

    #[test]
    fn weighted_selection_covers_all_scenarios() {
        let scenarios = vec![
            ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 3.0,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "AuthorityEscalation".to_string(),
                weight: 1.0,
                injections: vec![],
            },
        ];
        let total_weight = 4.0_f64;
        let prefix: Vec<f64> = scenarios
            .iter()
            .scan(0.0_f64, |acc, s| {
                *acc += s.weight;
                Some(*acc)
            })
            .collect();

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for ep_idx in 0..100u64 {
            let sc = select_scenario(ep_idx, total_weight, &prefix, &scenarios);
            seen.insert(sc.scenario_type.clone());
        }
        assert!(seen.contains("Baseline"), "Baseline must be selected");
        assert!(
            seen.contains("AuthorityEscalation"),
            "AuthorityEscalation must be selected"
        );
    }

    // --- Multiple profiles ---

    #[test]
    fn dry_run_works_with_all_builtin_profiles() {
        for profile_name in &["franka_panda", "ur10", "quadruped_12dof", "humanoid_28dof"] {
            let config = CampaignConfig {
                name: format!("test_{profile_name}"),
                profile: profile_name.to_string(),
                environments: 1,
                episodes_per_env: 1,
                steps_per_episode: 3,
                scenarios: vec![ScenarioConfig {
                    scenario_type: "Baseline".to_string(),
                    weight: 1.0,
                    injections: vec![],
                }],
                success_criteria: SuccessCriteria::default(),
            };
            let report = run_dry_campaign(&config)
                .unwrap_or_else(|e| panic!("dry run failed for {profile_name}: {e}"));
            assert_eq!(report.total_commands, 3, "profile {profile_name}");
        }
    }

    // --- Injections applied ---

    #[test]
    fn velocity_overshoot_injection_causes_rejections() {
        let config = CampaignConfig {
            name: "inj_test".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 5,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec!["VelocityOvershoot".to_string()],
            }],
            success_criteria: SuccessCriteria {
                min_legitimate_pass_rate: 0.0,
                max_violation_escape_rate: 1.0,
                max_false_rejection_rate: 1.0,
            },
        };
        let report = run_dry_campaign(&config).expect("dry run must complete");
        // Baseline + VelocityOvershoot -> all commands should be rejected.
        assert_eq!(
            report.total_rejected, 5,
            "VelocityOvershoot injection must cause all commands to be rejected"
        );
    }
}
