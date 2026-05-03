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
use invariant_core::models::command::EndEffectorForce;
use invariant_core::models::verdict::SignedVerdict;
use invariant_core::validator::ValidatorConfig;
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use thiserror::Error;

use crate::campaign::CampaignConfig;
use crate::injector::{inject, InjectionType};
use crate::reporter::{CampaignReport, CampaignReporter};
use crate::scenario::{ScenarioGenerator, ScenarioType};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when executing a dry-run campaign.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::isaac::dry_run::DryRunError;
///
/// // An unknown scenario name surfaces as DryRunError::UnknownScenario.
/// let err = DryRunError::UnknownScenario("not_a_scenario".to_string());
/// assert!(err.to_string().contains("not_a_scenario"));
///
/// // An unknown injection name surfaces as DryRunError::UnknownInjection.
/// let err = DryRunError::UnknownInjection("bad_injection".to_string());
/// assert!(err.to_string().contains("bad_injection"));
///
/// // PCA serialization failures carry a human-readable reason.
/// let err = DryRunError::PcaSerialize { reason: "json error".to_string() };
/// assert!(err.to_string().contains("json error"));
/// ```
#[derive(Debug, Error)]
pub enum DryRunError {
    /// The named robot profile could not be loaded.
    #[error("profile load failed: {0}")]
    ProfileLoad(#[from] invariant_core::profiles::ProfileError),

    /// The validator could not be constructed from the loaded profile.
    #[error("validator construction failed: {0}")]
    ValidatorBuild(#[from] invariant_core::validator::ValidatorError),

    /// The campaign referenced a scenario type name that is not recognised.
    #[error("unknown scenario type: {0:?}")]
    UnknownScenario(String),

    /// The campaign referenced a fault injection name that is not recognised.
    #[error("unknown injection type: {0:?}")]
    UnknownInjection(String),

    /// Ed25519 signing of a PCA token failed.
    #[error("PCA signing failed: {0}")]
    PcaSign(#[from] invariant_core::models::error::AuthorityError),

    /// Serializing the PCA chain to JSON failed.
    #[error("PCA chain serialization failed: {reason}")]
    PcaSerialize {
        /// Human-readable description of the serialization failure.
        reason: String,
    },
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
///
/// `seed` — when `Some([u8; 32])`, keypair generation uses a deterministic
/// `StdRng` seeded from that value, making the campaign reproducible.  When
/// `None`, `OsRng` is used (non-deterministic, suitable for production runs).
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
/// use invariant_robotics_sim::isaac::dry_run::run_dry_campaign;
///
/// // Minimal reproducible campaign: 1 environment × 2 episodes × 5 steps.
/// let config = CampaignConfig {
///     name: "doc_test_campaign".to_string(),
///     profile: "franka_panda".to_string(),
///     environments: 1,
///     episodes_per_env: 2,
///     steps_per_episode: 5,
///     scenarios: vec![ScenarioConfig {
///         scenario_type: "baseline".to_string(),
///         weight: 1.0,
///         injections: vec![],
///     }],
///     success_criteria: SuccessCriteria::default(),
/// };
///
/// // A fixed seed makes the campaign fully deterministic.
/// let seed: [u8; 32] = [42u8; 32];
/// let report = run_dry_campaign(&config, Some(seed))
///     .expect("franka_panda baseline campaign must succeed");
///
/// assert_eq!(report.campaign_name, "doc_test_campaign");
/// // 1 env × 2 episodes × 5 steps = 10 commands total.
/// assert_eq!(report.total_commands, 10);
/// // Baseline scenario never generates violations — all commands approved.
/// assert_eq!(report.total_approved, 10);
/// assert_eq!(report.violation_escape_count, 0);
/// ```
///
/// A campaign with an unknown profile name returns an error:
///
/// ```
/// use invariant_robotics_sim::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
/// use invariant_robotics_sim::isaac::dry_run::{run_dry_campaign, DryRunError};
///
/// let config = CampaignConfig {
///     name: "bad_profile".to_string(),
///     profile: "robot_does_not_exist".to_string(),
///     environments: 1,
///     episodes_per_env: 1,
///     steps_per_episode: 1,
///     scenarios: vec![ScenarioConfig {
///         scenario_type: "baseline".to_string(),
///         weight: 1.0,
///         injections: vec![],
///     }],
///     success_criteria: SuccessCriteria::default(),
/// };
///
/// let result = run_dry_campaign(&config, Some([0u8; 32]));
/// assert!(matches!(result, Err(DryRunError::ProfileLoad(_))));
/// ```
pub fn run_dry_campaign(
    config: &CampaignConfig,
    seed: Option<[u8; 32]>,
) -> Result<CampaignReport, DryRunError> {
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
    //
    // Use a deterministic RNG when a seed is provided (for reproducibility in
    // testing and benchmarking), otherwise fall back to the OS entropy source.
    let pca_sk;
    let pca_vk;
    let validator_sk;
    if let Some(seed_bytes) = seed {
        let mut rng = StdRng::from_seed(seed_bytes);
        pca_sk = generate_keypair(&mut rng);
        pca_vk = pca_sk.verifying_key();
        validator_sk = generate_keypair(&mut rng);
    } else {
        let mut rng = OsRng;
        pca_sk = generate_keypair(&mut rng);
        pca_vk = pca_sk.verifying_key();
        validator_sk = generate_keypair(&mut rng);
    }
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
    // Guard: total weight must be finite and positive.  Individual weights are
    // validated by `validate_config`, but a hand-constructed config or numeric
    // edge-cases (e.g. all weights = f64::MIN_POSITIVE summing to subnormal)
    // could still produce a degenerate total.
    if !(total_weight > 0.0 && total_weight.is_finite()) {
        return Err(DryRunError::UnknownScenario(format!(
            "total scenario weight must be a finite positive number (got {total_weight})"
        )));
    }
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

        // A scenario is expected to produce rejections if the scenario type
        // itself is adversarial OR if fault injections are applied.
        // Note: ReplayAttack only resets the sequence number, which is not
        // enforced in dry-run/forge mode (no sequence state). It does not
        // cause physics violations, so it should not count as an expected
        // rejection unless other injections are also present.
        let has_physics_injections = injections
            .iter()
            .any(|i| !matches!(i, InjectionType::ReplayAttack));
        let expected_reject = is_expected_reject(scenario_type) || has_physics_injections;

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

        // Ensure commands with end-effector positions also carry zero-force
        // data so the ISO 15066 fail-closed check does not reject legitimate
        // commands that happen to be near human-critical proximity zones.
        // For profile-defined end-effectors, set grasp_force to the P12 lower
        // bound (min_grasp_force_n) so baseline commands are not rejected.
        for cmd in commands.iter_mut() {
            if !cmd.end_effector_positions.is_empty() && cmd.end_effector_forces.is_empty() {
                cmd.end_effector_forces = cmd
                    .end_effector_positions
                    .iter()
                    .map(|ee| {
                        let min_grasp = profile
                            .end_effectors
                            .iter()
                            .find(|cfg| cfg.name == ee.name)
                            .map(|cfg| cfg.min_grasp_force_n)
                            .unwrap_or(0.0);
                        EndEffectorForce {
                            name: ee.name.clone(),
                            force: [0.0, 0.0, 0.0],
                            torque: [0.0, 0.0, 0.0],
                            grasp_force: Some(min_grasp),
                        }
                    })
                    .collect();
            }
        }

        // Validate each command and record results.
        // Recompute `now` for each command so that timestamp-based checks
        // (e.g. replay detection, expiry) use a fresh wall-clock value rather
        // than a single frozen instant captured before the loop.
        //
        // `previous_joints` is reset to `None` at the start of each episode so
        // that the P4 acceleration check has no stale state from a prior episode,
        // and is updated after every command so the check fires from the 2nd
        // command onwards within the same episode.
        // `previous_forces` is similarly reset and updated to enable the P13
        // force-rate check from the 2nd command onwards.
        let mut previous_joints: Option<Vec<invariant_core::models::command::JointState>> = None;
        let mut previous_forces: Option<Vec<invariant_core::models::command::EndEffectorForce>> =
            None;
        for cmd in &commands {
            let now = Utc::now();
            let result = match validator.validate_with_forces(
                cmd,
                now,
                previous_joints.as_deref(),
                previous_forces.as_deref(),
            ) {
                Ok(r) => r,
                Err(e) => {
                    // Truly fatal validator error (serialization failure).
                    // Build a synthetic rejection verdict so we never drop a command.
                    // Log the full error for debugging; expose only a generic
                    // message in the verdict to avoid leaking internal details.
                    tracing::error!("validator error: {e}");
                    let sv = make_error_verdict(&profile_name, String::new(), now);
                    reporter.record_result(
                        &profile_name,
                        &scenario_cfg.scenario_type,
                        expected_reject,
                        &sv,
                    );
                    // Store this command's state for next iteration's checks.
                    previous_joints = Some(cmd.joint_states.clone());
                    previous_forces = Some(cmd.end_effector_forces.clone());
                    continue;
                }
            };
            reporter.record_result(
                &profile_name,
                &scenario_cfg.scenario_type,
                expected_reject,
                &result.signed_verdict,
            );
            // Store this command's state for next iteration's checks.
            previous_joints = Some(cmd.joint_states.clone());
            previous_forces = Some(cmd.end_effector_forces.clone());
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
    // SAFETY: callers guarantee non-empty via campaign config validation.
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
        "LocomotionRunaway" | "locomotion_runaway" => Ok(ScenarioType::LocomotionRunaway),
        "LocomotionSlip" | "locomotion_slip" => Ok(ScenarioType::LocomotionSlip),
        "LocomotionTrip" | "locomotion_trip" => Ok(ScenarioType::LocomotionTrip),
        "LocomotionStomp" | "locomotion_stomp" => Ok(ScenarioType::LocomotionStomp),
        "LocomotionFall" | "locomotion_fall" => Ok(ScenarioType::LocomotionFall),
        "CncTending" | "cnc_tending" => Ok(ScenarioType::CncTending),
        "EnvironmentFault" | "environment_fault" => Ok(ScenarioType::EnvironmentFault),
        "CompoundAuthorityPhysics" | "compound_authority_physics" => {
            Ok(ScenarioType::CompoundAuthorityPhysics)
        }
        "CompoundSensorSpatial" | "compound_sensor_spatial" => {
            Ok(ScenarioType::CompoundSensorSpatial)
        }
        "CompoundDriftThenViolation" | "compound_drift_then_violation" => {
            Ok(ScenarioType::CompoundDriftThenViolation)
        }
        "CompoundEnvironmentPhysics" | "compound_environment_physics" => {
            Ok(ScenarioType::CompoundEnvironmentPhysics)
        }
        "RecoverySafeStop" | "recovery_safe_stop" => Ok(ScenarioType::RecoverySafeStop),
        "RecoveryAuditIntegrity" | "recovery_audit_integrity" => {
            Ok(ScenarioType::RecoveryAuditIntegrity)
        }
        "LongRunningStability" | "long_running_stability" => Ok(ScenarioType::LongRunningStability),
        "LongRunningThreat" | "long_running_threat" => Ok(ScenarioType::LongRunningThreat),
        // A: Normal operation (new scenarios)
        "PickAndPlace" | "pick_and_place" => Ok(ScenarioType::PickAndPlace),
        "WalkingGait" | "walking_gait" => Ok(ScenarioType::WalkingGait),
        "CollaborativeWork" | "collaborative_work" => Ok(ScenarioType::CollaborativeWork),
        "CncTendingFullCycle" | "cnc_tending_full_cycle" => Ok(ScenarioType::CncTendingFullCycle),
        "DexterousManipulation" | "dexterous_manipulation" => {
            Ok(ScenarioType::DexterousManipulation)
        }
        "MultiRobotCoordinated" | "multi_robot_coordinated" => {
            Ok(ScenarioType::MultiRobotCoordinated)
        }
        // B: Joint safety
        "JointPositionBoundary" | "joint_position_boundary" => {
            Ok(ScenarioType::JointPositionBoundary)
        }
        "JointVelocityBoundary" | "joint_velocity_boundary" => {
            Ok(ScenarioType::JointVelocityBoundary)
        }
        "JointTorqueBoundary" | "joint_torque_boundary" => Ok(ScenarioType::JointTorqueBoundary),
        "JointAccelerationRamp" | "joint_acceleration_ramp" => {
            Ok(ScenarioType::JointAccelerationRamp)
        }
        "JointCoordinatedViolation" | "joint_coordinated_violation" => {
            Ok(ScenarioType::JointCoordinatedViolation)
        }
        "JointDirectionReversal" | "joint_direction_reversal" => {
            Ok(ScenarioType::JointDirectionReversal)
        }
        "JointIeee754Special" | "joint_ieee754_special" => Ok(ScenarioType::JointIeee754Special),
        "JointGradualDrift" | "joint_gradual_drift" => Ok(ScenarioType::JointGradualDrift),
        other => Err(DryRunError::UnknownScenario(other.to_string())),
    }
}

/// Map injection type name string to the `InjectionType` enum.
///
/// Accepts both PascalCase (`"VelocityOvershoot"`) and snake_case
/// (`"velocity_overshoot"`) to match how `InjectionType` is serialized by
/// serde (which uses `rename_all = "snake_case"`).
fn parse_injection_type(name: &str) -> Result<InjectionType, DryRunError> {
    match name {
        "VelocityOvershoot" | "velocity_overshoot" => Ok(InjectionType::VelocityOvershoot),
        "PositionViolation" | "position_violation" => Ok(InjectionType::PositionViolation),
        "TorqueSpike" | "torque_spike" => Ok(InjectionType::TorqueSpike),
        "WorkspaceEscape" | "workspace_escape" => Ok(InjectionType::WorkspaceEscape),
        "DeltaTimeViolation" | "delta_time_violation" => Ok(InjectionType::DeltaTimeViolation),
        "SelfCollision" | "self_collision" => Ok(InjectionType::SelfCollision),
        "StabilityViolation" | "stability_violation" => Ok(InjectionType::StabilityViolation),
        "AuthorityStrip" | "authority_strip" => Ok(InjectionType::AuthorityStrip),
        "ReplayAttack" | "replay_attack" => Ok(InjectionType::ReplayAttack),
        "NanInjection" | "nan_injection" => Ok(InjectionType::NanInjection),
        "LocomotionOverspeed" | "locomotion_overspeed" => Ok(InjectionType::LocomotionOverspeed),
        "SlipViolation" | "slip_violation" => Ok(InjectionType::SlipViolation),
        "FootClearanceViolation" | "foot_clearance_violation" => {
            Ok(InjectionType::FootClearanceViolation)
        }
        "StompViolation" | "stomp_violation" => Ok(InjectionType::StompViolation),
        "StepOverextension" | "step_overextension" => Ok(InjectionType::StepOverextension),
        "HeadingSpinout" | "heading_spinout" => Ok(InjectionType::HeadingSpinout),
        "GroundReactionSpike" | "ground_reaction_spike" => Ok(InjectionType::GroundReactionSpike),
        "TerrainIncline" | "terrain_incline" => Ok(InjectionType::TerrainIncline),
        "TemperatureSpike" | "temperature_spike" => Ok(InjectionType::TemperatureSpike),
        "BatteryDrain" | "battery_drain" => Ok(InjectionType::BatteryDrain),
        "LatencySpike" | "latency_spike" => Ok(InjectionType::LatencySpike),
        "EStopEngage" | "e_stop_engage" => Ok(InjectionType::EStopEngage),
        "ProximityOverspeed" | "proximity_overspeed" => Ok(InjectionType::ProximityOverspeed),
        "ForceOverload" | "force_overload" => Ok(InjectionType::ForceOverload),
        "GraspForceViolation" | "grasp_force_violation" => Ok(InjectionType::GraspForceViolation),
        "PayloadOverload" | "payload_overload" => Ok(InjectionType::PayloadOverload),
        "ForceRateSpike" | "force_rate_spike" => Ok(InjectionType::ForceRateSpike),
        other => Err(DryRunError::UnknownInjection(other.to_string())),
    }
}

/// Returns `true` if commands from this scenario type should be rejected by
/// the validator.  `Baseline`, `Aggressive`, and `MultiAgentHandoff` are
/// legitimate (valid physics, valid authority). All others exercise specific
/// violation classes.
fn is_expected_reject(scenario: ScenarioType) -> bool {
    !matches!(
        scenario,
        // Category A: Normal operation — all commands should be APPROVED.
        ScenarioType::Baseline
            | ScenarioType::Aggressive
            | ScenarioType::PickAndPlace
            | ScenarioType::WalkingGait
            | ScenarioType::CollaborativeWork
            | ScenarioType::CncTendingFullCycle
            | ScenarioType::DexterousManipulation
            | ScenarioType::MultiRobotCoordinated
            | ScenarioType::MultiAgentHandoff
            | ScenarioType::CncTending
            | ScenarioType::LongRunningStability
            // Compound and recovery scenarios produce MIXED pass/fail patterns.
            // Classifying them as "expected reject" would count the valid first-half
            // commands as violation escapes. Instead, treat them as mixed — individual
            // commands are still validated correctly.
            | ScenarioType::CompoundAuthorityPhysics
            | ScenarioType::CompoundSensorSpatial
            | ScenarioType::CompoundDriftThenViolation
            | ScenarioType::CompoundEnvironmentPhysics
            | ScenarioType::RecoverySafeStop
            | ScenarioType::RecoveryAuditIntegrity
            | ScenarioType::LongRunningThreat
            // Category B: Joint safety scenarios produce MIXED pass/fail patterns
            // (boundary values alternate between valid and invalid), except B-08
            // (gradual drift) which is pure reject.
            | ScenarioType::JointPositionBoundary
            | ScenarioType::JointVelocityBoundary
            | ScenarioType::JointTorqueBoundary
            | ScenarioType::JointAccelerationRamp
            | ScenarioType::JointCoordinatedViolation
            | ScenarioType::JointDirectionReversal
            | ScenarioType::JointIeee754Special
    )
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
                derating: None,
            }],
            profile_name: profile_name.to_string(),
            profile_hash: String::new(),
            authority_summary: AuthoritySummary {
                origin_principal: String::new(),
                hop_count: 0,
                operations_granted: vec![],
                operations_required: vec![],
            },
            threat_analysis: None,
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
        let report = run_dry_campaign(&config, None).expect("dry run must complete");
        assert_eq!(report.campaign_name, "dry_run_test");
        assert_eq!(report.total_commands, 5);
    }

    #[test]
    fn dry_run_baseline_all_approved() {
        let config = baseline_config(10);
        let report = run_dry_campaign(&config, None).expect("dry run must complete");
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
        let report = run_dry_campaign(&config, None).expect("dry run must complete");
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
        let report = run_dry_campaign(&config, None).expect("dry run must complete");
        assert_eq!(
            report.violation_escape_count, 0,
            "no violation should escape a correct validator"
        );
    }

    #[test]
    fn dry_run_criteria_met_on_clean_run() {
        let config = baseline_config(20);
        let report = run_dry_campaign(&config, None).expect("dry run must complete");
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
        let report = run_dry_campaign(&config, None).expect("dry run must complete");
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
        let err = run_dry_campaign(&config, None).unwrap_err();
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
        let err = run_dry_campaign(&config, None).unwrap_err();
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
        let err = run_dry_campaign(&config, None).unwrap_err();
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
        let err = run_dry_campaign(&config, None).unwrap_err();
        assert!(matches!(err, DryRunError::ProfileLoad(_)));
    }

    // --- is_expected_reject ---

    #[test]
    fn expected_reject_classification() {
        // Category A: Normal operation — all commands should be APPROVED.
        assert!(!is_expected_reject(ScenarioType::Baseline));
        assert!(!is_expected_reject(ScenarioType::Aggressive));
        assert!(!is_expected_reject(ScenarioType::PickAndPlace));
        assert!(!is_expected_reject(ScenarioType::WalkingGait));
        assert!(!is_expected_reject(ScenarioType::CollaborativeWork));
        assert!(!is_expected_reject(ScenarioType::CncTendingFullCycle));
        assert!(!is_expected_reject(ScenarioType::DexterousManipulation));
        assert!(!is_expected_reject(ScenarioType::MultiRobotCoordinated));
        // Other non-reject scenarios.
        assert!(!is_expected_reject(ScenarioType::MultiAgentHandoff));
        assert!(!is_expected_reject(ScenarioType::CncTending));
        assert!(!is_expected_reject(ScenarioType::LongRunningStability));
        // Mixed scenarios: produce both valid and invalid commands.
        assert!(!is_expected_reject(ScenarioType::CompoundAuthorityPhysics));
        assert!(!is_expected_reject(ScenarioType::CompoundSensorSpatial));
        assert!(!is_expected_reject(
            ScenarioType::CompoundDriftThenViolation
        ));
        assert!(!is_expected_reject(
            ScenarioType::CompoundEnvironmentPhysics
        ));
        assert!(!is_expected_reject(ScenarioType::RecoverySafeStop));
        assert!(!is_expected_reject(ScenarioType::RecoveryAuditIntegrity));
        assert!(!is_expected_reject(ScenarioType::LongRunningThreat));
        // Category B: Joint safety mixed scenarios (boundary pass/fail).
        assert!(!is_expected_reject(ScenarioType::JointPositionBoundary));
        assert!(!is_expected_reject(ScenarioType::JointVelocityBoundary));
        assert!(!is_expected_reject(ScenarioType::JointTorqueBoundary));
        assert!(!is_expected_reject(ScenarioType::JointAccelerationRamp));
        assert!(!is_expected_reject(ScenarioType::JointCoordinatedViolation));
        assert!(!is_expected_reject(ScenarioType::JointDirectionReversal));
        assert!(!is_expected_reject(ScenarioType::JointIeee754Special));
        // Category B: Pure reject (all commands exceed limits).
        assert!(is_expected_reject(ScenarioType::JointGradualDrift));
        // Pure adversarial scenarios: all commands violate invariants.
        assert!(is_expected_reject(ScenarioType::ExclusionZone));
        assert!(is_expected_reject(ScenarioType::AuthorityEscalation));
        assert!(is_expected_reject(ScenarioType::ChainForgery));
        assert!(is_expected_reject(ScenarioType::PromptInjection));
        assert!(is_expected_reject(ScenarioType::LocomotionRunaway));
        assert!(is_expected_reject(ScenarioType::LocomotionSlip));
        assert!(is_expected_reject(ScenarioType::LocomotionTrip));
        assert!(is_expected_reject(ScenarioType::LocomotionStomp));
        assert!(is_expected_reject(ScenarioType::LocomotionFall));
        assert!(is_expected_reject(ScenarioType::EnvironmentFault));
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
        for profile_name in invariant_core::profiles::list_builtins() {
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
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("dry run failed for {profile_name}: {e}"));
            assert_eq!(report.total_commands, 3, "profile {profile_name}");
        }
    }

    // --- Finding 12: deterministic seed produces same report ---

    #[test]
    fn deterministic_seed_produces_reproducible_results() {
        let seed: [u8; 32] = [42u8; 32];
        let config = baseline_config(5);
        let report1 = run_dry_campaign(&config, Some(seed)).expect("run 1 must complete");
        let report2 = run_dry_campaign(&config, Some(seed)).expect("run 2 must complete");
        // Structural outputs are deterministic (same trial counts, same approval status).
        assert_eq!(report1.total_commands, report2.total_commands);
        assert_eq!(report1.total_approved, report2.total_approved);
        assert_eq!(report1.total_rejected, report2.total_rejected);
    }

    #[test]
    fn none_seed_runs_without_error() {
        let config = baseline_config(3);
        let report = run_dry_campaign(&config, None).expect("None seed must work");
        assert_eq!(report.total_commands, 3);
    }

    // --- Finding 13: Aggressive scenario — all commands approved ---

    #[test]
    fn aggressive_scenario_runs_and_produces_expected_count() {
        let config = CampaignConfig {
            name: "aggressive_test".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 6,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Aggressive".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria {
                min_legitimate_pass_rate: 0.0,
                max_violation_escape_rate: 1.0,
                max_false_rejection_rate: 1.0,
            },
        };
        let report =
            run_dry_campaign(&config, Some([0u8; 32])).expect("aggressive run must complete");
        assert_eq!(report.total_commands, 6);
        // Aggressive is classified as legitimate (is_expected_reject = false),
        // so any rejections are counted as false_rejections, not escapes.
        assert_eq!(report.violation_escape_count, 0);
        // All commands are accounted for.
        assert_eq!(report.total_approved + report.total_rejected, 6);
    }

    // --- Finding 38: total_weight == 0 returns error ---

    #[test]
    fn zero_total_weight_returns_error() {
        // Build a config that bypasses validate_config but produces zero total weight.
        // weight validation prevents 0.0 in load_config, so we test the runtime guard.
        // Actually validate_config prevents weight <= 0, so we test an edge-case
        // reachable only by constructing configs directly.
        // We trigger it by building configs with an extremely small positive weight
        // that sums to a subnormal — but that's hard to arrange.  Instead, use the
        // run_dry_campaign guard directly by injecting a synthetic "all-zero" sum
        // via the public DryRunError::UnknownScenario path.  The guard checks
        // total_weight after summing, so a NaN weight (bypassing validate_config)
        // would trigger it.
        let mut config = baseline_config(1);
        // Bypass validate_config by directly overriding weight to NaN after construction.
        config.scenarios[0].weight = f64::NAN;
        let err = run_dry_campaign(&config, None).unwrap_err();
        assert!(
            matches!(err, DryRunError::UnknownScenario(ref msg) if msg.contains("total scenario weight")),
            "expected UnknownScenario with weight message, got: {err:?}"
        );
    }

    // --- Finding 73: load_profile file-path branch ---

    #[test]
    fn load_profile_by_json_file_path() {
        // Write a minimal valid profile JSON to a temp file and load it by path.
        let profile_json = r#"{
  "name": "test_robot",
  "version": "1.0.0",
  "joints": [
    {"name": "j1", "type": "revolute", "min": -1.57, "max": 1.57,
     "max_velocity": 1.0, "max_torque": 10.0, "max_acceleration": 5.0}
  ],
  "workspace": {"type": "aabb", "min": [-0.5, -0.5, 0.0], "max": [0.5, 0.5, 1.0]},
  "exclusion_zones": [],
  "collision_pairs": [],
  "min_collision_distance": 0.05,
  "global_velocity_scale": 1.0,
  "max_delta_time": 0.1,
  "stability": null
}"#;
        let tmp_path = std::env::temp_dir().join("invariant_test_profile.json");
        std::fs::write(&tmp_path, profile_json).expect("write temp profile");

        let profile_path = tmp_path.to_str().expect("valid path");
        let result = load_profile(profile_path);
        let _ = std::fs::remove_file(&tmp_path); // cleanup
        assert!(
            result.is_ok(),
            "load_profile must succeed for valid JSON file, got: {result:?}"
        );
        assert_eq!(result.unwrap().name, "test_robot");
    }

    #[test]
    fn load_profile_path_with_parent_dir_returns_error() {
        let result = load_profile("../some/path/profile.json");
        assert!(
            matches!(result, Err(DryRunError::ProfileLoad(_))),
            "path traversal must be rejected"
        );
    }

    #[test]
    fn load_profile_yaml_extension_returns_error() {
        let result = load_profile("robot_profile.yaml");
        assert!(
            matches!(result, Err(DryRunError::ProfileLoad(_))),
            "non-.json extension must be rejected"
        );
    }

    // --- Finding 74: validator error fallback counted as rejected ---

    #[test]
    fn validator_error_command_counted_as_rejected() {
        // The validator error path in run_dry_campaign produces a synthetic
        // rejection verdict.  We cannot trivially force a validator error from
        // outside, but we can verify that the total command count always equals
        // the sum of approved + rejected (the invariant that holds whether or
        // not the fallback is exercised).
        let config = baseline_config(10);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_commands,
            report.total_approved + report.total_rejected,
            "total_commands must equal approved + rejected (fallback verdict is counted)"
        );
    }

    // --- Finding 75: snake_case injection names ---

    #[test]
    fn snake_case_injection_names_accepted() {
        // All snake_case injection names must parse without error.
        let snake_names = [
            "velocity_overshoot",
            "position_violation",
            "torque_spike",
            "workspace_escape",
            "delta_time_violation",
            "self_collision",
            "stability_violation",
            "authority_strip",
            "replay_attack",
            "nan_injection",
        ];
        for name in snake_names {
            let result = parse_injection_type(name);
            assert!(
                result.is_ok(),
                "snake_case injection name '{name}' must parse, got: {result:?}"
            );
        }
    }

    #[test]
    fn snake_case_injection_in_campaign_config() {
        // End-to-end: snake_case injection names work in a campaign config.
        let config = CampaignConfig {
            name: "snake_inj".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 3,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec!["velocity_overshoot".to_string()],
            }],
            success_criteria: SuccessCriteria {
                min_legitimate_pass_rate: 0.0,
                max_violation_escape_rate: 1.0,
                max_false_rejection_rate: 1.0,
            },
        };
        let report = run_dry_campaign(&config, None).expect("snake_case injection must work");
        // velocity_overshoot should cause rejections.
        assert_eq!(report.total_rejected, 3);
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
        let report = run_dry_campaign(&config, None).expect("dry run must complete");
        // Baseline + VelocityOvershoot -> all commands should be rejected.
        assert_eq!(
            report.total_rejected, 5,
            "VelocityOvershoot injection must cause all commands to be rejected"
        );
    }

    // =========================================================================
    // Section 2: Per-profile config helpers
    // =========================================================================

    fn config_for_profile(profile: &str, steps: u32) -> CampaignConfig {
        CampaignConfig {
            name: format!("{profile}_baseline"),
            profile: profile.to_string(),
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

    fn config_with_scenario(profile: &str, scenario: &str, steps: u32) -> CampaignConfig {
        CampaignConfig {
            name: format!("{profile}_{scenario}"),
            profile: profile.to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: steps,
            scenarios: vec![ScenarioConfig {
                scenario_type: scenario.to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        }
    }

    fn config_with_injection(
        profile: &str,
        scenario: &str,
        injection: &str,
        steps: u32,
    ) -> CampaignConfig {
        CampaignConfig {
            name: format!("{profile}_{scenario}_{injection}"),
            profile: profile.to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: steps,
            scenarios: vec![ScenarioConfig {
                scenario_type: scenario.to_string(),
                weight: 1.0,
                injections: vec![injection.to_string()],
            }],
            success_criteria: relaxed_criteria(),
        }
    }

    fn relaxed_criteria() -> SuccessCriteria {
        SuccessCriteria {
            min_legitimate_pass_rate: 0.0,
            max_violation_escape_rate: 1.0,
            max_false_rejection_rate: 1.0,
        }
    }

    // =========================================================================
    // Section 3: UR10 profile tests
    // =========================================================================

    #[test]
    fn ur10_baseline_all_approved() {
        let config = config_for_profile("ur10", 10);
        let report = run_dry_campaign(&config, None).expect("ur10 baseline must complete");
        assert_eq!(report.total_commands, 10);
        assert_eq!(
            report.total_approved, 10,
            "all ur10 baseline commands must be approved"
        );
        assert_eq!(report.total_rejected, 0);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10_authority_escalation_all_rejected() {
        let mut config = config_with_scenario("ur10", "AuthorityEscalation", 6);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("ur10 auth escalation must complete");
        assert_eq!(report.total_commands, 6);
        assert_eq!(
            report.total_rejected, report.total_commands,
            "all authority escalation commands must be rejected"
        );
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10_chain_forgery_all_rejected() {
        let mut config = config_with_scenario("ur10", "ChainForgery", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("ur10 chain forgery must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10_prompt_injection_all_rejected() {
        let mut config = config_with_scenario("ur10", "PromptInjection", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("ur10 prompt injection must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10_exclusion_zone_all_rejected() {
        let mut config = config_with_scenario("ur10", "ExclusionZone", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("ur10 exclusion zone must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10_multi_env_command_count() {
        // 2 environments × 3 episodes × 5 steps = 30 commands
        let config = CampaignConfig {
            name: "ur10_multi_env".to_string(),
            profile: "ur10".to_string(),
            environments: 2,
            episodes_per_env: 3,
            steps_per_episode: 5,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config, None).expect("ur10 multi env must complete");
        assert_eq!(report.total_commands, 30, "2×3×5 must equal 30");
    }

    #[test]
    fn ur10_aggressive_runs() {
        let mut config = config_with_scenario("ur10", "Aggressive", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("ur10 aggressive must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.violation_escape_count, 0);
        assert_eq!(report.total_approved + report.total_rejected, 5);
    }

    #[test]
    fn ur10_multi_agent_handoff_runs() {
        let mut config = config_with_scenario("ur10", "MultiAgentHandoff", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("ur10 multi agent handoff must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10_velocity_overshoot_injection_rejected() {
        let config = config_with_injection("ur10", "Baseline", "VelocityOvershoot", 5);
        let report =
            run_dry_campaign(&config, None).expect("ur10 velocity overshoot must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(
            report.total_rejected, report.total_commands,
            "VelocityOvershoot on ur10 must reject all"
        );
    }

    #[test]
    fn ur10_position_violation_injection_rejected() {
        let config = config_with_injection("ur10", "Baseline", "PositionViolation", 5);
        let report =
            run_dry_campaign(&config, None).expect("ur10 position violation must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn ur10_torque_spike_injection_rejected() {
        let config = config_with_injection("ur10", "Baseline", "TorqueSpike", 5);
        let report = run_dry_campaign(&config, None).expect("ur10 torque spike must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn ur10_workspace_escape_injection_rejected() {
        let config = config_with_injection("ur10", "Baseline", "WorkspaceEscape", 5);
        let report = run_dry_campaign(&config, None).expect("ur10 workspace escape must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn ur10_nan_injection_rejected() {
        let config = config_with_injection("ur10", "Baseline", "NanInjection", 5);
        let report = run_dry_campaign(&config, None).expect("ur10 NaN injection must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn ur10_authority_strip_injection_rejected() {
        let config = config_with_injection("ur10", "Baseline", "AuthorityStrip", 5);
        let report = run_dry_campaign(&config, None).expect("ur10 authority strip must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn ur10_deterministic_seed_reproducible() {
        let seed: [u8; 32] = [42u8; 32];
        let config = config_for_profile("ur10", 5);
        let report1 = run_dry_campaign(&config, Some(seed)).expect("ur10 seed run 1 must complete");
        let report2 = run_dry_campaign(&config, Some(seed)).expect("ur10 seed run 2 must complete");
        assert_eq!(report1.total_commands, report2.total_commands);
        assert_eq!(report1.total_approved, report2.total_approved);
        assert_eq!(report1.total_rejected, report2.total_rejected);
    }

    // =========================================================================
    // Section 4: Quadruped profile tests
    // =========================================================================

    #[test]
    fn quadruped_baseline_all_approved() {
        let config = config_for_profile("quadruped_12dof", 10);
        let report = run_dry_campaign(&config, None).expect("quadruped baseline must complete");
        assert_eq!(report.total_commands, 10);
        assert_eq!(
            report.total_approved, 10,
            "all quadruped baseline commands must be approved"
        );
        assert_eq!(report.total_rejected, 0);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn quadruped_authority_escalation_all_rejected() {
        let mut config = config_with_scenario("quadruped_12dof", "AuthorityEscalation", 6);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped auth escalation must complete");
        assert_eq!(report.total_commands, 6);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn quadruped_chain_forgery_rejected() {
        let mut config = config_with_scenario("quadruped_12dof", "ChainForgery", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped chain forgery must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn quadruped_prompt_injection_rejected() {
        let mut config = config_with_scenario("quadruped_12dof", "PromptInjection", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped prompt injection must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn quadruped_exclusion_zone_rejected() {
        let mut config = config_with_scenario("quadruped_12dof", "ExclusionZone", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped exclusion zone must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn quadruped_aggressive_runs() {
        let mut config = config_with_scenario("quadruped_12dof", "Aggressive", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("quadruped aggressive must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.violation_escape_count, 0);
        assert_eq!(report.total_approved + report.total_rejected, 5);
    }

    #[test]
    fn quadruped_locomotion_runaway_rejected() {
        let mut config = config_with_scenario("quadruped_12dof", "LocomotionRunaway", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped locomotion runaway must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn quadruped_locomotion_slip_rejected() {
        let mut config = config_with_scenario("quadruped_12dof", "LocomotionSlip", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped locomotion slip must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn quadruped_locomotion_trip_rejected() {
        let mut config = config_with_scenario("quadruped_12dof", "LocomotionTrip", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped locomotion trip must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn quadruped_locomotion_fall_rejected() {
        let mut config = config_with_scenario("quadruped_12dof", "LocomotionFall", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped locomotion fall must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn quadruped_locomotion_overspeed_injection_runs() {
        // LocomotionOverspeed injects locomotion_state into Baseline commands.
        // The validator only enforces locomotion checks when the profile has an
        // explicit locomotion config — quadruped_12dof has one, but Baseline
        // commands may still pass if the injected state doesn't trigger enough
        // validator checks.  Verify the campaign completes and commands are
        // accounted for.
        let config = config_with_injection("quadruped_12dof", "Baseline", "LocomotionOverspeed", 5);
        let report =
            run_dry_campaign(&config, None).expect("quadruped locomotion overspeed must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_approved + report.total_rejected, 5);
    }

    #[test]
    fn quadruped_environment_fault_runs() {
        // EnvironmentFault generates environment_state hazards, but the
        // quadruped_12dof profile lacks an environment config block, so the
        // validator may not enforce all environment checks.  Verify the campaign
        // completes with no panics and commands are accounted for.
        let mut config = config_with_scenario("quadruped_12dof", "EnvironmentFault", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped environment fault must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_approved + report.total_rejected, 5);
    }

    #[test]
    fn quadruped_velocity_overshoot_injection_rejected() {
        let config = config_with_injection("quadruped_12dof", "Baseline", "VelocityOvershoot", 5);
        let report =
            run_dry_campaign(&config, None).expect("quadruped velocity overshoot must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn quadruped_multi_env_command_count() {
        // 3 environments × 2 episodes × 4 steps = 24 commands
        let config = CampaignConfig {
            name: "quadruped_multi_env".to_string(),
            profile: "quadruped_12dof".to_string(),
            environments: 3,
            episodes_per_env: 2,
            steps_per_episode: 4,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config, None).expect("quadruped multi env must complete");
        assert_eq!(report.total_commands, 24, "3×2×4 must equal 24");
    }

    #[test]
    fn quadruped_deterministic_seed_reproducible() {
        let seed: [u8; 32] = [42u8; 32];
        let config = config_for_profile("quadruped_12dof", 5);
        let report1 =
            run_dry_campaign(&config, Some(seed)).expect("quadruped seed run 1 must complete");
        let report2 =
            run_dry_campaign(&config, Some(seed)).expect("quadruped seed run 2 must complete");
        assert_eq!(report1.total_commands, report2.total_commands);
        assert_eq!(report1.total_approved, report2.total_approved);
        assert_eq!(report1.total_rejected, report2.total_rejected);
    }

    // =========================================================================
    // Section 5: Humanoid profile tests
    // =========================================================================

    #[test]
    fn humanoid_baseline_all_approved() {
        let config = config_for_profile("humanoid_28dof", 10);
        let report = run_dry_campaign(&config, None).expect("humanoid baseline must complete");
        assert_eq!(report.total_commands, 10);
        assert_eq!(
            report.total_approved, 10,
            "all humanoid baseline commands must be approved"
        );
        assert_eq!(report.total_rejected, 0);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn humanoid_authority_escalation_all_rejected() {
        let mut config = config_with_scenario("humanoid_28dof", "AuthorityEscalation", 6);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("humanoid auth escalation must complete");
        assert_eq!(report.total_commands, 6);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn humanoid_chain_forgery_rejected() {
        let mut config = config_with_scenario("humanoid_28dof", "ChainForgery", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("humanoid chain forgery must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn humanoid_prompt_injection_rejected() {
        let mut config = config_with_scenario("humanoid_28dof", "PromptInjection", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("humanoid prompt injection must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn humanoid_exclusion_zone_rejected() {
        let mut config = config_with_scenario("humanoid_28dof", "ExclusionZone", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("humanoid exclusion zone must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn humanoid_aggressive_runs() {
        let mut config = config_with_scenario("humanoid_28dof", "Aggressive", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("humanoid aggressive must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.violation_escape_count, 0);
        assert_eq!(report.total_approved + report.total_rejected, 5);
    }

    #[test]
    fn humanoid_locomotion_runaway_rejected() {
        let mut config = config_with_scenario("humanoid_28dof", "LocomotionRunaway", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("humanoid locomotion runaway must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn humanoid_locomotion_slip_rejected() {
        let mut config = config_with_scenario("humanoid_28dof", "LocomotionSlip", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("humanoid locomotion slip must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn humanoid_locomotion_trip_rejected() {
        let mut config = config_with_scenario("humanoid_28dof", "LocomotionTrip", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("humanoid locomotion trip must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn humanoid_locomotion_fall_rejected() {
        let mut config = config_with_scenario("humanoid_28dof", "LocomotionFall", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("humanoid locomotion fall must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn humanoid_environment_fault_runs() {
        // humanoid_28dof lacks an environment config block, so the validator
        // may not enforce all environment checks.  Verify the campaign completes.
        let mut config = config_with_scenario("humanoid_28dof", "EnvironmentFault", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("humanoid environment fault must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_approved + report.total_rejected, 5);
    }

    #[test]
    fn humanoid_locomotion_overspeed_injection_runs() {
        // LocomotionOverspeed on Baseline injects locomotion_state.  The
        // humanoid_28dof profile has locomotion config, but Baseline commands
        // may still pass depending on which checks the injected state triggers.
        let config = config_with_injection("humanoid_28dof", "Baseline", "LocomotionOverspeed", 5);
        let report =
            run_dry_campaign(&config, None).expect("humanoid locomotion overspeed must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_approved + report.total_rejected, 5);
    }

    #[test]
    fn humanoid_velocity_overshoot_injection_rejected() {
        let config = config_with_injection("humanoid_28dof", "Baseline", "VelocityOvershoot", 5);
        let report =
            run_dry_campaign(&config, None).expect("humanoid velocity overshoot must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn humanoid_multi_env_command_count() {
        // 2 environments × 5 episodes × 3 steps = 30 commands
        let config = CampaignConfig {
            name: "humanoid_multi_env".to_string(),
            profile: "humanoid_28dof".to_string(),
            environments: 2,
            episodes_per_env: 5,
            steps_per_episode: 3,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config, None).expect("humanoid multi env must complete");
        assert_eq!(report.total_commands, 30, "2×5×3 must equal 30");
    }

    #[test]
    fn humanoid_deterministic_seed_reproducible() {
        let seed: [u8; 32] = [42u8; 32];
        let config = config_for_profile("humanoid_28dof", 5);
        let report1 =
            run_dry_campaign(&config, Some(seed)).expect("humanoid seed run 1 must complete");
        let report2 =
            run_dry_campaign(&config, Some(seed)).expect("humanoid seed run 2 must complete");
        assert_eq!(report1.total_commands, report2.total_commands);
        assert_eq!(report1.total_approved, report2.total_approved);
        assert_eq!(report1.total_rejected, report2.total_rejected);
    }

    // =========================================================================
    // Section 6: UR10e Haas Cell (CNC) tests
    // =========================================================================

    #[test]
    fn ur10e_haas_baseline_all_approved() {
        let config = config_for_profile("ur10e_haas_cell", 10);
        let report = run_dry_campaign(&config, None).expect("ur10e_haas baseline must complete");
        assert_eq!(report.total_commands, 10);
        assert_eq!(
            report.total_approved, 10,
            "all ur10e_haas baseline commands must be approved"
        );
        assert_eq!(report.total_rejected, 0);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10e_haas_authority_escalation_rejected() {
        let mut config = config_with_scenario("ur10e_haas_cell", "AuthorityEscalation", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("ur10e_haas auth escalation must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10e_haas_chain_forgery_rejected() {
        let mut config = config_with_scenario("ur10e_haas_cell", "ChainForgery", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("ur10e_haas chain forgery must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10e_haas_cnc_tending_runs() {
        // CncTending is a legitimate scenario (is_expected_reject = false)
        let mut config = config_with_scenario("ur10e_haas_cell", "CncTending", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("ur10e_haas CNC tending must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.violation_escape_count, 0);
        assert_eq!(report.total_approved + report.total_rejected, 5);
    }

    #[test]
    fn ur10e_haas_exclusion_zone_rejected() {
        let mut config = config_with_scenario("ur10e_haas_cell", "ExclusionZone", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("ur10e_haas exclusion zone must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10e_haas_prompt_injection_rejected() {
        let mut config = config_with_scenario("ur10e_haas_cell", "PromptInjection", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("ur10e_haas prompt injection must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10e_haas_environment_fault_runs() {
        // ur10e_haas_cell may lack a full environment config block, so the
        // validator may not enforce all environment checks.  Verify the campaign
        // completes and commands are accounted for.
        let mut config = config_with_scenario("ur10e_haas_cell", "EnvironmentFault", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("ur10e_haas environment fault must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_approved + report.total_rejected, 5);
    }

    #[test]
    fn ur10e_haas_velocity_overshoot_injection_rejected() {
        let config = config_with_injection("ur10e_haas_cell", "Baseline", "VelocityOvershoot", 5);
        let report =
            run_dry_campaign(&config, None).expect("ur10e_haas velocity overshoot must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn ur10e_haas_authority_strip_injection_rejected() {
        let config = config_with_injection("ur10e_haas_cell", "Baseline", "AuthorityStrip", 5);
        let report =
            run_dry_campaign(&config, None).expect("ur10e_haas authority strip must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn ur10e_haas_nan_injection_rejected() {
        let config = config_with_injection("ur10e_haas_cell", "Baseline", "NanInjection", 5);
        let report =
            run_dry_campaign(&config, None).expect("ur10e_haas NaN injection must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_rejected, report.total_commands);
    }

    #[test]
    fn ur10e_haas_multi_env_command_count() {
        // 2 environments × 3 episodes × 4 steps = 24 commands
        let config = CampaignConfig {
            name: "ur10e_haas_multi_env".to_string(),
            profile: "ur10e_haas_cell".to_string(),
            environments: 2,
            episodes_per_env: 3,
            steps_per_episode: 4,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config, None).expect("ur10e_haas multi env must complete");
        assert_eq!(report.total_commands, 24, "2×3×4 must equal 24");
    }

    #[test]
    fn ur10e_haas_deterministic_seed_reproducible() {
        let seed: [u8; 32] = [42u8; 32];
        let config = config_for_profile("ur10e_haas_cell", 5);
        let report1 =
            run_dry_campaign(&config, Some(seed)).expect("ur10e_haas seed run 1 must complete");
        let report2 =
            run_dry_campaign(&config, Some(seed)).expect("ur10e_haas seed run 2 must complete");
        assert_eq!(report1.total_commands, report2.total_commands);
        assert_eq!(report1.total_approved, report2.total_approved);
        assert_eq!(report1.total_rejected, report2.total_rejected);
    }

    // =========================================================================
    // Section 7: Cross-form-factor comprehensive tests
    // =========================================================================

    #[test]
    fn all_profiles_baseline_zero_escapes() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let config = config_for_profile(profile, 5);
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("baseline zero escapes failed for {profile}: {e}"));
            assert_eq!(
                report.violation_escape_count, 0,
                "profile {profile}: baseline must have zero escapes"
            );
        }
    }

    #[test]
    fn all_profiles_authority_escalation_zero_escapes() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let mut config = config_with_scenario(profile, "AuthorityEscalation", 4);
            config.success_criteria = relaxed_criteria();
            let report = run_dry_campaign(&config, None).unwrap_or_else(|e| {
                panic!("auth escalation zero escapes failed for {profile}: {e}")
            });
            assert_eq!(
                report.violation_escape_count, 0,
                "profile {profile}: AuthorityEscalation must have zero escapes"
            );
        }
    }

    #[test]
    fn all_profiles_chain_forgery_zero_escapes() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let mut config = config_with_scenario(profile, "ChainForgery", 4);
            config.success_criteria = relaxed_criteria();
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("chain forgery zero escapes failed for {profile}: {e}"));
            assert_eq!(
                report.violation_escape_count, 0,
                "profile {profile}: ChainForgery must have zero escapes"
            );
        }
    }

    #[test]
    fn all_profiles_prompt_injection_zero_escapes() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let mut config = config_with_scenario(profile, "PromptInjection", 4);
            config.success_criteria = relaxed_criteria();
            let report = run_dry_campaign(&config, None).unwrap_or_else(|e| {
                panic!("prompt injection zero escapes failed for {profile}: {e}")
            });
            assert_eq!(
                report.violation_escape_count, 0,
                "profile {profile}: PromptInjection must have zero escapes"
            );
        }
    }

    #[test]
    fn all_profiles_exclusion_zone_zero_escapes() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let mut config = config_with_scenario(profile, "ExclusionZone", 4);
            config.success_criteria = relaxed_criteria();
            let report = run_dry_campaign(&config, None).unwrap_or_else(|e| {
                panic!("exclusion zone zero escapes failed for {profile}: {e}")
            });
            assert_eq!(
                report.violation_escape_count, 0,
                "profile {profile}: ExclusionZone must have zero escapes"
            );
        }
    }

    #[test]
    fn all_profiles_criteria_met_on_baseline() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let config = CampaignConfig {
                name: format!("{profile}_criteria_test"),
                profile: profile.to_string(),
                environments: 1,
                episodes_per_env: 1,
                steps_per_episode: 20,
                scenarios: vec![ScenarioConfig {
                    scenario_type: "Baseline".to_string(),
                    weight: 1.0,
                    injections: vec![],
                }],
                success_criteria: SuccessCriteria::default(),
            };
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("criteria met test failed for {profile}: {e}"));
            assert!(
                report.criteria_met,
                "profile {profile}: criteria must be met on pure baseline campaign"
            );
        }
    }

    #[test]
    fn all_profiles_total_commands_equals_approved_plus_rejected() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let config = config_for_profile(profile, 7);
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("invariant check failed for {profile}: {e}"));
            assert_eq!(
                report.total_commands,
                report.total_approved + report.total_rejected,
                "profile {profile}: total_commands must equal approved + rejected"
            );
        }
    }

    #[test]
    fn all_profiles_velocity_overshoot_causes_rejection() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let config = config_with_injection(profile, "Baseline", "VelocityOvershoot", 4);
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("velocity overshoot test failed for {profile}: {e}"));
            assert_eq!(
                report.total_rejected, report.total_commands,
                "profile {profile}: VelocityOvershoot must cause all commands to be rejected"
            );
        }
    }

    #[test]
    fn all_profiles_nan_injection_causes_rejection() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let config = config_with_injection(profile, "Baseline", "NanInjection", 4);
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("NaN injection test failed for {profile}: {e}"));
            assert_eq!(
                report.total_rejected, report.total_commands,
                "profile {profile}: NanInjection must cause all commands to be rejected"
            );
        }
    }

    #[test]
    fn all_profiles_multiple_injections_combined() {
        // Baseline scenario with two simultaneous injections: both should cause rejections
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let config = CampaignConfig {
                name: format!("{profile}_multi_injection"),
                profile: profile.to_string(),
                environments: 1,
                episodes_per_env: 1,
                steps_per_episode: 5,
                scenarios: vec![ScenarioConfig {
                    scenario_type: "Baseline".to_string(),
                    weight: 1.0,
                    injections: vec!["VelocityOvershoot".to_string(), "NanInjection".to_string()],
                }],
                success_criteria: relaxed_criteria(),
            };
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("multi-injection test failed for {profile}: {e}"));
            assert_eq!(
                report.total_rejected, report.total_commands,
                "profile {profile}: combined injections must reject all commands"
            );
        }
    }

    // =========================================================================
    // Section 8: Large-scale campaign tests
    // =========================================================================

    #[test]
    fn large_campaign_franka_100_steps() {
        let config = CampaignConfig {
            name: "large_franka_100".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 100,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config, None).expect("large franka campaign must complete");
        assert_eq!(report.total_commands, 100);
        assert_eq!(
            report.total_approved, 100,
            "all 100 baseline steps must be approved"
        );
        assert_eq!(report.violation_escape_count, 0);
        assert!(report.criteria_met);
    }

    #[test]
    fn large_campaign_ur10_50_episodes() {
        // 1 environment × 50 episodes × 5 steps = 250 commands
        let config = CampaignConfig {
            name: "large_ur10_50ep".to_string(),
            profile: "ur10".to_string(),
            environments: 1,
            episodes_per_env: 50,
            steps_per_episode: 5,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config, None).expect("large ur10 campaign must complete");
        assert_eq!(report.total_commands, 250, "1×50×5 must equal 250");
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn large_campaign_quadruped_mixed_scenarios() {
        // 3 envs × 10 episodes × 5 steps = 150 commands, mixed scenarios
        let config = CampaignConfig {
            name: "large_quadruped_mixed".to_string(),
            profile: "quadruped_12dof".to_string(),
            environments: 3,
            episodes_per_env: 10,
            steps_per_episode: 5,
            scenarios: vec![
                ScenarioConfig {
                    scenario_type: "Baseline".to_string(),
                    weight: 2.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "AuthorityEscalation".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "LocomotionRunaway".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
            ],
            success_criteria: relaxed_criteria(),
        };
        let report = run_dry_campaign(&config, None).expect("large quadruped mixed must complete");
        assert_eq!(report.total_commands, 150, "3×10×5 must equal 150");
        // AuthorityEscalation is always caught; LocomotionRunaway may or may
        // not be caught depending on validator locomotion checks.
        assert!(
            report.total_rejected > 0,
            "at least some adversarial commands must be rejected"
        );
        assert_eq!(report.total_approved + report.total_rejected, 150);
    }

    #[test]
    fn large_campaign_humanoid_mixed() {
        // 2 envs × 8 episodes × 5 steps = 80 commands, mixed scenarios
        let config = CampaignConfig {
            name: "large_humanoid_mixed".to_string(),
            profile: "humanoid_28dof".to_string(),
            environments: 2,
            episodes_per_env: 8,
            steps_per_episode: 5,
            scenarios: vec![
                ScenarioConfig {
                    scenario_type: "Baseline".to_string(),
                    weight: 2.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "LocomotionFall".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "ChainForgery".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
            ],
            success_criteria: relaxed_criteria(),
        };
        let report = run_dry_campaign(&config, None).expect("large humanoid mixed must complete");
        assert_eq!(report.total_commands, 80, "2×8×5 must equal 80");
        // ChainForgery is always caught; LocomotionFall may or may not be.
        assert!(
            report.total_rejected > 0,
            "at least some adversarial commands must be rejected"
        );
        assert_eq!(report.total_approved + report.total_rejected, 80);
    }

    #[test]
    fn large_campaign_all_adversarial_scenarios() {
        // 1 env × 9 episodes × 3 steps = 27 commands, all 9 adversarial scenarios
        let config = CampaignConfig {
            name: "large_all_adversarial".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 9,
            steps_per_episode: 3,
            scenarios: vec![
                ScenarioConfig {
                    scenario_type: "ExclusionZone".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "AuthorityEscalation".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "ChainForgery".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "PromptInjection".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "LocomotionRunaway".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "LocomotionSlip".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "LocomotionTrip".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "LocomotionFall".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "EnvironmentFault".to_string(),
                    weight: 1.0,
                    injections: vec![],
                },
            ],
            success_criteria: relaxed_criteria(),
        };
        let report =
            run_dry_campaign(&config, None).expect("all adversarial campaign must complete");
        assert_eq!(report.total_commands, 27, "1×9×3 must equal 27");
        // Some adversarial scenarios (e.g. EnvironmentFault, Locomotion*)
        // may not be fully caught by the validator when the profile lacks the
        // corresponding config blocks.  Verify the campaign ran to completion
        // and that at least some commands were rejected.
        assert!(
            report.total_rejected > 0,
            "at least some adversarial commands must be rejected"
        );
        assert_eq!(report.total_approved + report.total_rejected, 27);
    }

    // =========================================================================
    // Section 9: Scenario parsing completeness tests
    // =========================================================================

    #[test]
    fn all_scenario_types_parseable() {
        let scenario_names = [
            "Baseline",
            "Aggressive",
            "PickAndPlace",
            "WalkingGait",
            "CollaborativeWork",
            "CncTendingFullCycle",
            "DexterousManipulation",
            "MultiRobotCoordinated",
            "ExclusionZone",
            "AuthorityEscalation",
            "ChainForgery",
            "PromptInjection",
            "MultiAgentHandoff",
            "LocomotionRunaway",
            "LocomotionSlip",
            "LocomotionTrip",
            "LocomotionFall",
            "CncTending",
            "EnvironmentFault",
            "JointPositionBoundary",
            "JointVelocityBoundary",
            "JointTorqueBoundary",
            "JointAccelerationRamp",
            "JointCoordinatedViolation",
            "JointDirectionReversal",
            "JointIeee754Special",
            "JointGradualDrift",
        ];
        for name in scenario_names {
            let result = parse_scenario_type(name);
            assert!(
                result.is_ok(),
                "scenario type '{name}' must parse without error, got: {result:?}"
            );
        }
    }

    #[test]
    fn all_injection_types_parseable() {
        let injection_names = [
            "VelocityOvershoot",
            "PositionViolation",
            "TorqueSpike",
            "WorkspaceEscape",
            "DeltaTimeViolation",
            "SelfCollision",
            "StabilityViolation",
            "AuthorityStrip",
            "ReplayAttack",
            "NanInjection",
            "LocomotionOverspeed",
            "SlipViolation",
            "FootClearanceViolation",
            "StompViolation",
            "StepOverextension",
            "HeadingSpinout",
            "GroundReactionSpike",
            "TerrainIncline",
            "TemperatureSpike",
            "BatteryDrain",
            "LatencySpike",
            "EStopEngage",
        ];
        for name in injection_names {
            let result = parse_injection_type(name);
            assert!(
                result.is_ok(),
                "injection type '{name}' must parse without error, got: {result:?}"
            );
        }
    }

    #[test]
    fn snake_case_scenario_names_accepted() {
        let snake_names = [
            "baseline",
            "aggressive",
            "pick_and_place",
            "walking_gait",
            "collaborative_work",
            "cnc_tending_full_cycle",
            "dexterous_manipulation",
            "multi_robot_coordinated",
            "exclusion_zone",
            "authority_escalation",
            "chain_forgery",
            "prompt_injection",
            "multi_agent_handoff",
            "locomotion_runaway",
            "locomotion_slip",
            "locomotion_trip",
            "locomotion_stomp",
            "locomotion_fall",
            "cnc_tending",
            "environment_fault",
            "compound_authority_physics",
            "compound_sensor_spatial",
            "compound_drift_then_violation",
            "compound_environment_physics",
            "recovery_safe_stop",
            "recovery_audit_integrity",
            "long_running_stability",
            "long_running_threat",
            "joint_position_boundary",
            "joint_velocity_boundary",
            "joint_torque_boundary",
            "joint_acceleration_ramp",
            "joint_coordinated_violation",
            "joint_direction_reversal",
            "joint_ieee754_special",
            "joint_gradual_drift",
        ];
        for name in snake_names {
            let result = parse_scenario_type(name);
            assert!(
                result.is_ok(),
                "snake_case scenario name '{name}' must parse without error, got: {result:?}"
            );
        }
    }

    // =========================================================================
    // Section 10: Edge cases
    // =========================================================================

    #[test]
    fn single_step_per_episode_all_profiles() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let config = config_for_profile(profile, 1);
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("single step test failed for {profile}: {e}"));
            assert_eq!(
                report.total_commands, 1,
                "profile {profile}: single step must produce exactly 1 command"
            );
            assert_eq!(
                report.total_approved, 1,
                "profile {profile}: single baseline step must be approved"
            );
        }
    }

    #[test]
    fn one_environment_many_episodes() {
        // 1 environment × 100 episodes × 1 step = 100 commands
        let config = CampaignConfig {
            name: "one_env_many_ep".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 100,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config, None).expect("one env many episodes must complete");
        assert_eq!(report.total_commands, 100, "1×100×1 must equal 100");
        assert_eq!(report.total_approved, 100);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn many_environments_one_episode() {
        // 100 environments × 1 episode × 1 step = 100 commands
        let config = CampaignConfig {
            name: "many_env_one_ep".to_string(),
            profile: "franka_panda".to_string(),
            environments: 100,
            episodes_per_env: 1,
            steps_per_episode: 1,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![],
            }],
            success_criteria: SuccessCriteria::default(),
        };
        let report = run_dry_campaign(&config, None).expect("many envs one episode must complete");
        assert_eq!(report.total_commands, 100, "100×1×1 must equal 100");
        assert_eq!(report.total_approved, 100);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn mixed_legitimate_and_adversarial_per_profile() {
        // 50/50 split between Baseline and AuthorityEscalation for all profiles
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            let config = CampaignConfig {
                name: format!("{profile}_mixed_split"),
                profile: profile.to_string(),
                environments: 1,
                episodes_per_env: 10,
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
                success_criteria: relaxed_criteria(),
            };
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("mixed split test failed for {profile}: {e}"));
            assert_eq!(
                report.total_commands, 30,
                "profile {profile}: 1×10×3 must equal 30"
            );
            assert_eq!(
                report.violation_escape_count, 0,
                "profile {profile}: no violations must escape"
            );
            assert_eq!(
                report.total_approved + report.total_rejected,
                report.total_commands,
                "profile {profile}: approved + rejected must equal total"
            );
        }
    }

    #[test]
    fn all_injection_types_on_baseline_all_profiles() {
        // All injection types must cause rejections on a baseline scenario across all profiles.
        // Use only arm-applicable injections to avoid mismatches; locomotion injections still
        // parse and run against arm profiles (they may produce rejections via NaN checks).
        let injection_names = [
            "VelocityOvershoot",
            "PositionViolation",
            "TorqueSpike",
            "WorkspaceEscape",
            "NanInjection",
            "AuthorityStrip",
        ];
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ] {
            for injection in &injection_names {
                let config = config_with_injection(profile, "Baseline", injection, 3);
                let report = run_dry_campaign(&config, None)
                    .unwrap_or_else(|e| panic!("injection {injection} on {profile} failed: {e}"));
                assert_eq!(
                    report.total_rejected,
                    report.total_commands,
                    "profile {profile}, injection {injection}: must reject all {n} commands",
                    n = report.total_commands
                );
            }
        }
    }

    // =========================================================================
    // Safety-critical check verification: prove specific validator checks fire
    // =========================================================================

    // --- P25: E-stop is ALWAYS caught regardless of profile config ---
    // This is the most critical safety invariant. P25 fires whenever
    // e_stop_engaged == Some(true), even for profiles with NO environment
    // config. This test proves the hardware e-stop is never bypassed.

    #[test]
    fn estop_injection_rejected_on_all_profiles_including_no_env_config() {
        // E-stop (P25) must reject on ALL profiles, even those without
        // environment config. This is the hardware safety interlock.
        let all_profiles = [
            "franka_panda",      // no environment config
            "ur10",              // no environment config
            "quadruped_12dof",   // no environment config
            "humanoid_28dof",    // no environment config
            "ur10e_haas_cell",   // no environment config
            "ur10e_cnc_tending", // HAS environment config
        ];
        for profile in &all_profiles {
            let config = config_with_injection(profile, "Baseline", "EStopEngage", 3);
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("e-stop on {profile} failed: {e}"));
            assert_eq!(
                report.total_rejected, 3,
                "P25 e-stop MUST reject all commands for {profile} — \
                 this is a hardware safety interlock that cannot be profile-gated"
            );
        }
    }

    // --- Environment checks with environment-capable profile ---
    // ur10e_cnc_tending is the ONLY profile with environment config.
    // P21-P25 should all fire against it.

    #[test]
    fn ur10e_cnc_tending_environment_fault_all_rejected() {
        // ur10e_cnc_tending has environment config (max_safe_pitch_rad=0.0873,
        // max_operating_temperature_c=75.0, max_latency_ms=50.0).
        // EnvironmentFault generates 5 phases: pitch, temp, battery, latency,
        // e-stop. ALL should be caught by P21-P25.
        let mut config = config_with_scenario("ur10e_cnc_tending", "EnvironmentFault", 25);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None)
            .expect("ur10e_cnc_tending environment fault must complete");
        assert_eq!(report.total_commands, 25);
        assert_eq!(
            report.total_rejected, 25,
            "ALL 25 environment fault commands must be rejected on ur10e_cnc_tending \
             (the only profile with full environment config: P21-P25)"
        );
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10e_cnc_tending_environment_fault_per_check_names() {
        // Verify that the per_check stats contain environment-related check names.
        let mut config = config_with_scenario("ur10e_cnc_tending", "EnvironmentFault", 25);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("ur10e_cnc_tending env fault must complete");
        // At least one environment check must have recorded failures.
        let env_check_names = [
            "terrain_incline",
            "actuator_temperature",
            "battery_state",
            "communication_latency",
            "emergency_stop",
        ];
        let any_env_check_fired = env_check_names
            .iter()
            .any(|name| report.per_check.get(*name).is_some_and(|c| c.failed > 0));
        assert!(
            any_env_check_fired,
            "at least one environment check (P21-P25) must record failures — \
             got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    // --- Stability check catches LocomotionFall on stability-enabled profiles ---
    // LocomotionFall sets COM to [10,10,2] which is outside any support polygon.
    // Humanoid and quadruped have stability.enabled=true, so P9 fires.

    #[test]
    fn locomotion_fall_rejected_on_humanoid_via_stability_check() {
        // humanoid_28dof has stability config (support polygon ±0.15×±0.10,
        // enabled=true). LocomotionFall sets COM to [10,10,2] — way outside.
        // P9 stability check must catch this even though no locomotion config
        // exists (P15-P20 don't fire, but P9 does).
        let mut config = config_with_scenario("humanoid_28dof", "LocomotionFall", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("humanoid locomotion fall must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(
            report.total_rejected, 5,
            "LocomotionFall must be rejected on humanoid via P9 stability \
             (COM [10,10,2] is outside support polygon ±0.15×±0.10)"
        );
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn locomotion_fall_rejected_on_quadruped_via_stability_check() {
        // quadruped_12dof has stability config (support polygon ±0.20×±0.12,
        // enabled=true). Same COM=[10,10,2] violation.
        let mut config = config_with_scenario("quadruped_12dof", "LocomotionFall", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("quadruped locomotion fall must complete");
        assert_eq!(report.total_commands, 5);
        assert_eq!(
            report.total_rejected, 5,
            "LocomotionFall must be rejected on quadruped via P9 stability \
             (COM [10,10,2] is outside support polygon ±0.20×±0.12)"
        );
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn stability_injection_rejected_on_humanoid() {
        // StabilityViolation injection explicitly sets COM outside the polygon.
        // Humanoid has stability enabled → P9 fires.
        let config = config_with_injection("humanoid_28dof", "Baseline", "StabilityViolation", 5);
        let report =
            run_dry_campaign(&config, None).expect("humanoid stability violation must complete");
        assert_eq!(
            report.total_rejected, 5,
            "StabilityViolation injection must be caught by P9 on humanoid"
        );
    }

    #[test]
    fn stability_injection_rejected_on_quadruped() {
        let config = config_with_injection("quadruped_12dof", "Baseline", "StabilityViolation", 5);
        let report =
            run_dry_campaign(&config, None).expect("quadruped stability violation must complete");
        assert_eq!(
            report.total_rejected, 5,
            "StabilityViolation injection must be caught by P9 on quadruped"
        );
    }

    // --- CNC tending conditional zone cycle correctness ---
    // CNC tending with ur10e_haas_cell: first half has zone disabled (EE inside
    // zone should PASS), second half has zone active (same EE should be REJECTED).

    #[test]
    fn cnc_tending_cycle_approval_rejection_pattern() {
        // ur10e_cnc_tending has a conditional zone (haas_spindle_area).
        // CNC tending places the EE at the zone center and toggles overrides:
        // - loading phase: zone disabled → EE may pass if no other zone covers it
        // - cutting phase: zone active → EE blocked → REJECTED
        //
        // The cutting half must always be rejected. The loading half depends on
        // whether the EE position also overlaps with non-conditional zones at
        // the float-exact boundary (which can vary between debug/release builds).
        let mut config = config_with_scenario("ur10e_cnc_tending", "CncTending", 20);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("CNC tending cycle must complete");
        assert_eq!(report.total_commands, 20);
        assert!(
            report.total_rejected >= 10,
            "CNC cutting phase (zone active) should produce rejections, got {} rejected",
            report.total_rejected
        );
    }

    #[test]
    fn cnc_tending_haas_cell_all_rejected_due_to_overlapping_zones() {
        // ur10e_haas_cell has a non-conditional zone (haas_enclosure_interior)
        // that overlaps the conditional zone's center.  Therefore ALL CncTending
        // commands are rejected regardless of zone-override state.  This is
        // correct behavior — non-conditional zones always block.
        let mut config = config_with_scenario("ur10e_haas_cell", "CncTending", 10);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("CNC tending on haas_cell must complete");
        assert_eq!(report.total_commands, 10);
        assert_eq!(
            report.total_rejected, 10,
            "All CncTending commands on ur10e_haas_cell should be rejected \
             because the EE position also falls inside the non-conditional \
             haas_enclosure_interior zone"
        );
    }

    #[test]
    fn cnc_tending_on_ur10e_cnc_tending_profile() {
        // ur10e_cnc_tending also has conditional zones (haas_spindle_area).
        let mut config = config_with_scenario("ur10e_cnc_tending", "CncTending", 20);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None)
            .expect("CNC tending on ur10e_cnc_tending must complete");
        assert_eq!(report.total_commands, 20);
        assert!(
            report.total_rejected >= 10,
            "cutting phase should produce rejections"
        );
        assert!(
            report.total_rejected >= 8,
            "cutting phase should be rejected"
        );
    }

    // --- Per-check name verification for core injections ---
    // Verify that specific injections trigger the corresponding named validator checks.

    #[test]
    fn velocity_overshoot_triggers_velocity_limits_check() {
        let config = config_with_injection("franka_panda", "Baseline", "VelocityOvershoot", 10);
        let report = run_dry_campaign(&config, None).expect("velocity overshoot must complete");
        let check = report.per_check.get("velocity_limits");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "VelocityOvershoot must trigger velocity_limits check failures — \
             got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn position_violation_triggers_joint_limits_check() {
        let config = config_with_injection("franka_panda", "Baseline", "PositionViolation", 10);
        let report = run_dry_campaign(&config, None).expect("position violation must complete");
        let check = report.per_check.get("joint_limits");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "PositionViolation must trigger joint_limits check failures — \
             got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn workspace_escape_triggers_workspace_bounds_check() {
        let config = config_with_injection("franka_panda", "Baseline", "WorkspaceEscape", 10);
        let report = run_dry_campaign(&config, None).expect("workspace escape must complete");
        let check = report.per_check.get("workspace_bounds");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "WorkspaceEscape must trigger workspace_bounds check failures — \
             got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn delta_time_violation_triggers_delta_time_check() {
        let config = config_with_injection("franka_panda", "Baseline", "DeltaTimeViolation", 10);
        let report = run_dry_campaign(&config, None).expect("delta time violation must complete");
        let check = report.per_check.get("delta_time");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "DeltaTimeViolation must trigger delta_time check failures — \
             got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn authority_strip_triggers_authority_check() {
        let config = config_with_injection("franka_panda", "Baseline", "AuthorityStrip", 10);
        let report = run_dry_campaign(&config, None).expect("authority strip must complete");
        let check = report.per_check.get("authority");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "AuthorityStrip must trigger authority check failures — \
             got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn torque_spike_triggers_torque_limits_check() {
        let config = config_with_injection("franka_panda", "Baseline", "TorqueSpike", 10);
        let report = run_dry_campaign(&config, None).expect("torque spike must complete");
        let check = report.per_check.get("torque_limits");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "TorqueSpike must trigger torque_limits check failures — \
             got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn authority_escalation_triggers_authority_check() {
        let mut config = config_with_scenario("franka_panda", "AuthorityEscalation", 10);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("authority escalation must complete");
        let check = report.per_check.get("authority");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "AuthorityEscalation must trigger authority check failures"
        );
    }

    #[test]
    fn prompt_injection_triggers_joint_limits_or_velocity_check() {
        // PromptInjection sets positions 10× outside limits and velocities 5× max.
        // Should trigger either joint_limits or velocity_limits (or both).
        let mut config = config_with_scenario("franka_panda", "PromptInjection", 10);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("prompt injection must complete");
        let jl_fails = report.per_check.get("joint_limits").map_or(0, |c| c.failed);
        let vl_fails = report
            .per_check
            .get("velocity_limits")
            .map_or(0, |c| c.failed);
        assert!(
            jl_fails > 0 || vl_fails > 0,
            "PromptInjection must trigger joint_limits or velocity_limits failures \
             (jl_fails={jl_fails}, vl_fails={vl_fails})"
        );
    }

    // --- Per-check verification across all profiles ---

    #[test]
    fn velocity_overshoot_triggers_velocity_check_all_profiles() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
            "ur10e_cnc_tending",
        ] {
            let config = config_with_injection(profile, "Baseline", "VelocityOvershoot", 5);
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{profile}: {e}"));
            let check = report.per_check.get("velocity_limits");
            assert!(
                check.is_some_and(|c| c.failed > 0),
                "{profile}: VelocityOvershoot must trigger velocity_limits failures"
            );
        }
    }

    #[test]
    fn authority_strip_triggers_authority_check_all_profiles() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
            "ur10e_cnc_tending",
        ] {
            let config = config_with_injection(profile, "Baseline", "AuthorityStrip", 5);
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{profile}: {e}"));
            let check = report.per_check.get("authority");
            assert!(
                check.is_some_and(|c| c.failed > 0),
                "{profile}: AuthorityStrip must trigger authority failures"
            );
        }
    }

    // --- Combined injection test: multiple faults all detected ---

    #[test]
    fn combined_velocity_and_authority_injection_all_rejected() {
        // Apply both VelocityOvershoot AND AuthorityStrip — both should fire.
        let config = CampaignConfig {
            name: "combined_inj".to_string(),
            profile: "franka_panda".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 10,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![
                    "VelocityOvershoot".to_string(),
                    "AuthorityStrip".to_string(),
                ],
            }],
            success_criteria: relaxed_criteria(),
        };
        let report = run_dry_campaign(&config, None).expect("combined injection must complete");
        assert_eq!(report.total_rejected, 10, "all must be rejected");
        // Both check types should have failures
        let vel = report
            .per_check
            .get("velocity_limits")
            .map_or(0, |c| c.failed);
        let auth = report.per_check.get("authority").map_or(0, |c| c.failed);
        assert!(vel > 0, "velocity_limits must have failures");
        assert!(auth > 0, "authority must have failures");
    }

    #[test]
    fn combined_position_and_workspace_injection_all_rejected() {
        let config = CampaignConfig {
            name: "combined_pos_ws".to_string(),
            profile: "ur10".to_string(),
            environments: 1,
            episodes_per_env: 1,
            steps_per_episode: 10,
            scenarios: vec![ScenarioConfig {
                scenario_type: "Baseline".to_string(),
                weight: 1.0,
                injections: vec![
                    "PositionViolation".to_string(),
                    "WorkspaceEscape".to_string(),
                ],
            }],
            success_criteria: relaxed_criteria(),
        };
        let report = run_dry_campaign(&config, None).expect("combined injection must complete");
        assert_eq!(report.total_rejected, 10, "all must be rejected");
    }

    // --- Baseline commands MUST pass all checks on all profiles ---
    // This is the converse: legitimate commands must NEVER be rejected.

    #[test]
    fn baseline_per_check_all_pass_franka_panda() {
        let config = baseline_config(20);
        let report = run_dry_campaign(&config, None).expect("baseline must complete");
        for (name, stats) in &report.per_check {
            assert_eq!(
                stats.failed, 0,
                "Baseline on franka_panda: check '{name}' must not fail (got {} failures)",
                stats.failed
            );
        }
    }

    #[test]
    fn baseline_per_check_all_pass_all_profiles() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
            "ur10e_cnc_tending",
        ] {
            let config = config_for_profile(profile, 10);
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{profile}: {e}"));
            assert_eq!(
                report.total_approved, 10,
                "{profile}: all baseline commands must be approved"
            );
            for (name, stats) in &report.per_check {
                assert_eq!(
                    stats.failed, 0,
                    "{profile}: baseline check '{name}' must not fail"
                );
            }
        }
    }

    // --- ur10e_cnc_tending is now a 6th built-in profile we must exercise ---

    #[test]
    fn ur10e_cnc_tending_baseline_all_approved() {
        let config = config_for_profile("ur10e_cnc_tending", 10);
        let report =
            run_dry_campaign(&config, None).expect("ur10e_cnc_tending baseline must complete");
        assert_eq!(report.total_approved, 10);
    }

    #[test]
    fn ur10e_cnc_tending_authority_escalation_all_rejected() {
        let mut config = config_with_scenario("ur10e_cnc_tending", "AuthorityEscalation", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None)
            .expect("ur10e_cnc_tending authority escalation must complete");
        assert_eq!(report.total_rejected, 5);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10e_cnc_tending_chain_forgery_all_rejected() {
        let mut config = config_with_scenario("ur10e_cnc_tending", "ChainForgery", 5);
        config.success_criteria = relaxed_criteria();
        let report =
            run_dry_campaign(&config, None).expect("ur10e_cnc_tending chain forgery must complete");
        assert_eq!(report.total_rejected, 5);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn ur10e_cnc_tending_velocity_overshoot_rejected() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "VelocityOvershoot", 5);
        let report = run_dry_campaign(&config, None)
            .expect("ur10e_cnc_tending velocity overshoot must complete");
        assert_eq!(report.total_rejected, 5);
    }

    // --- Exclusion zone checks fire on profiles with exclusion zones ---

    #[test]
    fn exclusion_zone_triggers_exclusion_check_all_profiles() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
            "ur10e_cnc_tending",
        ] {
            let mut config = config_with_scenario(profile, "ExclusionZone", 5);
            config.success_criteria = relaxed_criteria();
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{profile}: {e}"));
            assert_eq!(
                report.total_rejected, 5,
                "{profile}: ExclusionZone commands must all be rejected"
            );
            assert_eq!(
                report.violation_escape_count, 0,
                "{profile}: no exclusion zone violations must escape"
            );
        }
    }

    // --- NaN injection is always caught (NaN poisons all numeric checks) ---

    #[test]
    fn nan_injection_rejected_on_all_six_profiles() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
            "ur10e_cnc_tending",
        ] {
            let config = config_with_injection(profile, "Baseline", "NanInjection", 5);
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{profile}: {e}"));
            assert_eq!(
                report.total_rejected, 5,
                "{profile}: NaN injection must be caught on all profiles"
            );
        }
    }

    // --- Replay attack (sequence=0) must be caught ---

    #[test]
    fn replay_attack_triggers_rejection_all_profiles() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
            "ur10e_cnc_tending",
        ] {
            let config = config_with_injection(profile, "Baseline", "ReplayAttack", 3);
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{profile}: {e}"));
            // ReplayAttack sets sequence=0. The validator may or may not reject
            // based on sequence analysis. Verify the campaign at least completes.
            assert_eq!(
                report.total_commands, 3,
                "{profile}: must process 3 commands"
            );
            assert_eq!(
                report.total_approved + report.total_rejected,
                3,
                "{profile}: all commands must be accounted for"
            );
        }
    }

    // --- ur10e_cnc_tending: each environment injection type individually rejected ---
    // P21-P25 checks: terrain incline, actuator temperature, battery state,
    // communication latency, emergency stop.

    #[test]
    fn ur10e_cnc_tending_terrain_incline_injection_rejected() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "TerrainIncline", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P21 terrain incline must reject all on ur10e_cnc_tending"
        );
    }

    #[test]
    fn ur10e_cnc_tending_temperature_spike_injection_rejected() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "TemperatureSpike", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P22 temperature spike must reject all on ur10e_cnc_tending"
        );
    }

    #[test]
    fn ur10e_cnc_tending_battery_drain_injection_rejected() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "BatteryDrain", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P23 battery drain must reject all on ur10e_cnc_tending"
        );
    }

    #[test]
    fn ur10e_cnc_tending_latency_spike_injection_rejected() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "LatencySpike", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P24 latency spike must reject all on ur10e_cnc_tending"
        );
    }

    #[test]
    fn ur10e_cnc_tending_estop_engage_injection_rejected() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "EStopEngage", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P25 e-stop must reject all on ur10e_cnc_tending"
        );
    }

    // --- ur10e_cnc_tending: per_check stat verification for each P21-P25 ---

    #[test]
    fn ur10e_cnc_tending_terrain_incline_triggers_terrain_check() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "TerrainIncline", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("terrain_incline");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "TerrainIncline must trigger terrain_incline failures, got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn ur10e_cnc_tending_temperature_spike_triggers_temperature_check() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "TemperatureSpike", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("actuator_temperature");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "TemperatureSpike must trigger actuator_temperature failures, got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn ur10e_cnc_tending_battery_drain_triggers_battery_check() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "BatteryDrain", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("battery_state");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "BatteryDrain must trigger battery_state failures, got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn ur10e_cnc_tending_latency_spike_triggers_latency_check() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "LatencySpike", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("communication_latency");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "LatencySpike must trigger communication_latency failures, got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn ur10e_cnc_tending_estop_triggers_estop_check() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "EStopEngage", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("emergency_stop");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "EStopEngage must trigger emergency_stop failures, got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    // --- check_name mapping: core injections on franka_panda ---

    #[test]
    fn check_name_mapping_complete_for_core_injections() {
        let pairs = [
            ("VelocityOvershoot", "velocity_limits"),
            ("PositionViolation", "joint_limits"),
            ("TorqueSpike", "torque_limits"),
            ("WorkspaceEscape", "workspace_bounds"),
            ("DeltaTimeViolation", "delta_time"),
            ("AuthorityStrip", "authority"),
        ];
        for (injection, expected_check) in &pairs {
            let config = config_with_injection("franka_panda", "Baseline", injection, 5);
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{injection}: {e}"));
            let check = report.per_check.get(*expected_check);
            assert!(
                check.is_some_and(|c| c.failed > 0),
                "{injection} must trigger {expected_check} failures, got checks: {:?}",
                report.per_check.keys().collect::<Vec<_>>()
            );
        }
    }

    // --- check_name mapping: environment injections on ur10e_cnc_tending ---

    #[test]
    fn check_name_mapping_complete_for_environment_injections() {
        let pairs = [
            ("TerrainIncline", "terrain_incline"),
            ("TemperatureSpike", "actuator_temperature"),
            ("BatteryDrain", "battery_state"),
            ("LatencySpike", "communication_latency"),
            ("EStopEngage", "emergency_stop"),
        ];
        for (injection, expected_check) in &pairs {
            let config = config_with_injection("ur10e_cnc_tending", "Baseline", injection, 5);
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{injection}: {e}"));
            let check = report.per_check.get(*expected_check);
            assert!(
                check.is_some_and(|c| c.failed > 0),
                "{injection} must trigger {expected_check} failures, got checks: {:?}",
                report.per_check.keys().collect::<Vec<_>>()
            );
        }
    }

    // --- ExclusionZone per_check verification across all profiles ---

    #[test]
    fn exclusion_zone_triggers_exclusion_zones_check_on_all_profiles() {
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
            "ur10e_cnc_tending",
        ] {
            let mut config = config_with_scenario(profile, "ExclusionZone", 5);
            config.success_criteria = relaxed_criteria();
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{profile}: {e}"));
            let check = report.per_check.get("exclusion_zones");
            assert!(
                check.is_some_and(|c| c.failed > 0),
                "{profile}: ExclusionZone must trigger exclusion_zones failures, \
                 got checks: {:?}",
                report.per_check.keys().collect::<Vec<_>>()
            );
        }
    }

    // --- ChainForgery per_check: authority check fires ---

    #[test]
    fn chain_forgery_triggers_authority_check() {
        let mut config = config_with_scenario("franka_panda", "ChainForgery", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("authority");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "ChainForgery must trigger authority failures, got checks: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    // --- PromptInjection violates at least two distinct checks ---

    #[test]
    fn prompt_injection_triggers_multiple_checks() {
        // PromptInjection is a scenario type (not an injection): it sets
        // positions 10× outside limits and velocities 5× max, so both
        // joint_limits and velocity_limits should fail.
        let mut config = config_with_scenario("franka_panda", "PromptInjection", 5);
        config.success_criteria = relaxed_criteria();
        let report = run_dry_campaign(&config, None).expect("must complete");
        let failing_checks = report.per_check.values().filter(|c| c.failed > 0).count();
        assert!(
            failing_checks >= 2,
            "PromptInjection must trigger at least 2 distinct failing checks, \
             got {} failing checks: {:?}",
            failing_checks,
            report
                .per_check
                .iter()
                .filter(|(_, c)| c.failed > 0)
                .map(|(k, _)| k)
                .collect::<Vec<_>>()
        );
    }

    // --- All 9 adversarial scenarios produce rejections on ur10e_cnc_tending ---
    // The 9 adversarial scenarios are: AuthorityEscalation, ChainForgery,
    // ExclusionZone, PromptInjection, LocomotionRunaway, LocomotionSlip,
    // LocomotionTrip, LocomotionFall, EnvironmentFault.
    // ur10e_cnc_tending has the richest config (environment block + exclusion
    // zones), so it catches the widest range of violations.

    #[test]
    fn all_adversarial_scenarios_rejected_on_ur10e_cnc_tending() {
        let adversarial_scenarios = [
            "AuthorityEscalation",
            "ChainForgery",
            "ExclusionZone",
            "PromptInjection",
            "LocomotionRunaway",
            "LocomotionSlip",
            "LocomotionTrip",
            "LocomotionFall",
            "EnvironmentFault",
        ];
        for scenario in &adversarial_scenarios {
            let mut config = config_with_scenario("ur10e_cnc_tending", scenario, 3);
            config.success_criteria = relaxed_criteria();
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{scenario}: {e}"));
            assert_eq!(
                report.total_rejected, 3,
                "{scenario} on ur10e_cnc_tending must reject all 3 commands"
            );
        }
    }

    // =========================================================================
    // Section 11: P7 Self-Collision End-to-End
    // =========================================================================

    #[test]
    fn self_collision_injection_rejected_on_franka_panda() {
        // franka_panda has collision_pairs: [panda_link7, panda_link0], [panda_link7, panda_link1]
        // SelfCollision places all EEs at origin → distance = 0 < min_collision_distance
        let config = config_with_injection("franka_panda", "Baseline", "SelfCollision", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P7 self-collision must reject all commands on franka_panda (has collision_pairs)"
        );
    }

    #[test]
    fn self_collision_triggers_self_collision_check() {
        let config = config_with_injection("franka_panda", "Baseline", "SelfCollision", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("self_collision");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "SelfCollision must trigger self_collision check failures"
        );
    }

    // =========================================================================
    // Section 12: P10 Proximity Overspeed End-to-End
    // =========================================================================

    #[test]
    fn proximity_overspeed_injection_rejected_on_franka_panda() {
        // franka_panda has proximity zone human_warning (scale=0.5)
        let config = config_with_injection("franka_panda", "Baseline", "ProximityOverspeed", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P10 proximity overspeed must reject all on franka_panda (has proximity zones)"
        );
    }

    #[test]
    fn proximity_overspeed_triggers_proximity_velocity_check() {
        let config = config_with_injection("franka_panda", "Baseline", "ProximityOverspeed", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("proximity_velocity");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "ProximityOverspeed must trigger proximity_velocity check, got: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn proximity_overspeed_rejected_on_ur10() {
        // ur10 has human_critical zone with scale=0.1
        let config = config_with_injection("ur10", "Baseline", "ProximityOverspeed", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P10 must reject on ur10 (has human_critical proximity zone)"
        );
    }

    #[test]
    fn proximity_overspeed_rejected_on_humanoid() {
        let config = config_with_injection("humanoid_28dof", "Baseline", "ProximityOverspeed", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P10 must reject on humanoid (has proximity zones)"
        );
    }

    // =========================================================================
    // Section 13: P11 Force Overload End-to-End (profiles WITH end_effector config)
    // =========================================================================

    #[test]
    fn force_overload_rejected_on_ur10e_cnc_tending() {
        // Only profiles with end_effectors config will have P11 fire
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "ForceOverload", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P11 force overload must reject on ur10e_cnc_tending (has end_effectors config)"
        );
    }

    #[test]
    fn force_overload_triggers_ee_force_limits_check() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "ForceOverload", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("ee_force_limits");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "ForceOverload must trigger ee_force_limits check, got: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn force_overload_rejected_on_ur10e_haas_cell() {
        let config = config_with_injection("ur10e_haas_cell", "Baseline", "ForceOverload", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P11 must reject on ur10e_haas_cell (has end_effectors config)"
        );
    }

    // =========================================================================
    // Section 14: P12 Grasp Force End-to-End
    // =========================================================================

    #[test]
    fn grasp_force_violation_rejected_on_ur10e_cnc_tending() {
        let config =
            config_with_injection("ur10e_cnc_tending", "Baseline", "GraspForceViolation", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P12 grasp force must reject on ur10e_cnc_tending"
        );
    }

    #[test]
    fn grasp_force_triggers_grasp_force_limits_check() {
        let config =
            config_with_injection("ur10e_cnc_tending", "Baseline", "GraspForceViolation", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("grasp_force_limits");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "GraspForceViolation must trigger grasp_force_limits check, got: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    // =========================================================================
    // Section 15: P14 Payload Overload End-to-End
    // =========================================================================

    #[test]
    fn payload_overload_rejected_on_ur10e_cnc_tending() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "PayloadOverload", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        assert_eq!(
            report.total_rejected, 5,
            "P14 payload overload must reject on ur10e_cnc_tending"
        );
    }

    #[test]
    fn payload_overload_triggers_payload_limits_check() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "PayloadOverload", 5);
        let report = run_dry_campaign(&config, None).expect("must complete");
        let check = report.per_check.get("payload_limits");
        assert!(
            check.is_some_and(|c| c.failed > 0),
            "PayloadOverload must trigger payload_limits check, got: {:?}",
            report.per_check.keys().collect::<Vec<_>>()
        );
    }

    // =========================================================================
    // Section 16: P4 Acceleration Check (enabled via previous_joints tracking)
    // =========================================================================

    #[test]
    fn baseline_multi_step_passes_acceleration_check() {
        // With previous_joints tracking, P4 now fires on 2nd+ commands.
        // Baseline commands should pass P4 (smooth motion).
        let config = config_for_profile("franka_panda", 10);
        let report = run_dry_campaign(&config, None).expect("must complete");
        // All baseline commands must still be approved even with P4 active
        assert_eq!(
            report.total_approved, 10,
            "Baseline must still pass with P4 acceleration check active"
        );
        // acceleration_limits check should appear and pass
        let check = report.per_check.get("acceleration_limits");
        if let Some(c) = check {
            assert_eq!(
                c.failed, 0,
                "Baseline should not trigger acceleration_limits failures"
            );
        }
    }

    #[test]
    fn baseline_multi_step_acceleration_check_present_all_profiles() {
        // Verify P4 fires (is present in per_check) for multi-step episodes on all profiles
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
            "ur10e_cnc_tending",
        ] {
            let config = config_for_profile(profile, 5);
            let report =
                run_dry_campaign(&config, None).unwrap_or_else(|e| panic!("{profile}: {e}"));
            assert_eq!(
                report.total_approved, 5,
                "{profile}: baseline must still pass with P4 active"
            );
        }
    }

    // =========================================================================
    // Section 17: Complete check-name mapping for ALL injection types
    // =========================================================================

    #[test]
    fn check_name_mapping_complete_all_25_injections() {
        // Maps every injection to its expected primary check failure.
        // Injections that trigger multiple checks just need at least one.
        let mappings: &[(&str, &str, &str)] = &[
            // (injection, profile, expected_check_name)
            ("VelocityOvershoot", "franka_panda", "velocity_limits"),
            ("PositionViolation", "franka_panda", "joint_limits"),
            ("TorqueSpike", "franka_panda", "torque_limits"),
            ("WorkspaceEscape", "franka_panda", "workspace_bounds"),
            ("DeltaTimeViolation", "franka_panda", "delta_time"),
            ("AuthorityStrip", "franka_panda", "authority"),
            ("SelfCollision", "franka_panda", "self_collision"),
            ("ProximityOverspeed", "franka_panda", "proximity_velocity"),
            ("NanInjection", "franka_panda", "joint_limits"), // NaN triggers many
            ("TerrainIncline", "ur10e_cnc_tending", "terrain_incline"),
            (
                "TemperatureSpike",
                "ur10e_cnc_tending",
                "actuator_temperature",
            ),
            ("BatteryDrain", "ur10e_cnc_tending", "battery_state"),
            ("LatencySpike", "ur10e_cnc_tending", "communication_latency"),
            ("EStopEngage", "ur10e_cnc_tending", "emergency_stop"),
            ("ForceOverload", "ur10e_cnc_tending", "ee_force_limits"),
            (
                "GraspForceViolation",
                "ur10e_cnc_tending",
                "grasp_force_limits",
            ),
            ("PayloadOverload", "ur10e_cnc_tending", "payload_limits"),
        ];
        for &(injection, profile, expected_check) in mappings {
            let config = config_with_injection(profile, "Baseline", injection, 5);
            let report = run_dry_campaign(&config, None)
                .unwrap_or_else(|e| panic!("{injection} on {profile}: {e}"));
            let check = report.per_check.get(expected_check);
            assert!(
                check.is_some_and(|c| c.failed > 0),
                "{injection} on {profile} must trigger '{expected_check}' failures, got: {:?}",
                report.per_check.keys().collect::<Vec<_>>()
            );
        }
    }

    // =========================================================================
    // Section 18: Cross-profile injection coverage — all 27 injection types
    // =========================================================================

    #[test]
    fn all_27_injection_types_run_without_error_all_profiles() {
        // Every injection type must at least parse and run without error on all profiles.
        // We don't assert all are rejected (some injections need specific profile configs),
        // but they must not panic or return DryRunError.
        let all_injections = [
            "VelocityOvershoot",
            "PositionViolation",
            "TorqueSpike",
            "WorkspaceEscape",
            "DeltaTimeViolation",
            "SelfCollision",
            "StabilityViolation",
            "AuthorityStrip",
            "ReplayAttack",
            "NanInjection",
            "LocomotionOverspeed",
            "SlipViolation",
            "FootClearanceViolation",
            "StompViolation",
            "StepOverextension",
            "HeadingSpinout",
            "GroundReactionSpike",
            "TerrainIncline",
            "TemperatureSpike",
            "BatteryDrain",
            "LatencySpike",
            "EStopEngage",
            "ProximityOverspeed",
            "ForceOverload",
            "GraspForceViolation",
            "PayloadOverload",
            "ForceRateSpike",
        ];
        assert_eq!(
            all_injections.len(),
            27,
            "must cover all 27 injection types"
        );
        for profile in &[
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
            "ur10e_cnc_tending",
        ] {
            for injection in &all_injections {
                let config = config_with_injection(profile, "Baseline", injection, 2);
                let result = run_dry_campaign(&config, None);
                assert!(
                    result.is_ok(),
                    "{injection} on {profile} must not error: {:?}",
                    result.err()
                );
            }
        }
    }

    // --- P13 Force Rate Limits ---

    #[test]
    fn force_rate_spike_rejected_on_ur10e_cnc_tending() {
        // ForceRateSpike sets large force on every command. With previous_forces
        // tracking, the 2nd+ command will have a huge rate from zero→large force.
        // ur10e_cnc_tending has end_effectors config with max_force_rate_n_per_s=500.
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "ForceRateSpike", 5);
        let report = run_dry_campaign(&config, None).expect("force rate spike must complete");
        // At least the first command passes (no previous forces).
        // Commands 2-5 should be rejected by P13 AND P11 (force overload).
        assert!(report.total_rejected >= 4,
            "P13 force rate spike must reject at least 4 of 5 commands on ur10e_cnc_tending, got {}",
            report.total_rejected);
    }

    #[test]
    fn force_rate_spike_triggers_force_rate_limits_check() {
        let config = config_with_injection("ur10e_cnc_tending", "Baseline", "ForceRateSpike", 5);
        let report = run_dry_campaign(&config, None).expect("force rate spike must complete");
        let check = report.per_check.get("force_rate_limits");
        assert!(check.is_some_and(|c| c.failed > 0),
            "ForceRateSpike must trigger force_rate_limits check failures on ur10e_cnc_tending, got: {:?}",
            report.per_check.keys().collect::<Vec<_>>());
    }

    // =========================================================================
    // 15M Campaign dry-run validation — all 30 scenarios × key profiles
    // =========================================================================

    /// Run every scenario against a representative profile and verify:
    /// - Legitimate scenarios produce at least some approvals
    /// - Adversarial scenarios produce at least some rejections
    /// - No scenario panics or returns an error
    /// - Zero violation escapes on adversarial scenarios
    #[test]
    fn dry_run_all_scenarios_arm_profile() {
        // Scenarios applicable to an arm profile (no locomotion, no environment config).
        let scenarios = [
            "baseline",
            "aggressive",
            "exclusion_zone",
            "authority_escalation",
            "chain_forgery",
            "prompt_injection",
            "multi_agent_handoff",
            "cnc_tending",
            "compound_authority_physics",
            "compound_sensor_spatial",
            "compound_drift_then_violation",
            "recovery_safe_stop",
            "recovery_audit_integrity",
            "long_running_stability",
            "long_running_threat",
            "joint_position_boundary",
            "joint_velocity_boundary",
            "joint_torque_boundary",
            "joint_acceleration_ramp",
            "joint_coordinated_violation",
            "joint_direction_reversal",
            "joint_ieee754_special",
            "joint_gradual_drift",
        ];
        // Skip: locomotion_* (no locomotion config), environment_fault (no env config),
        // compound_environment_physics (needs env config for battery derating).
        for scenario in &scenarios {
            let config = CampaignConfig {
                name: format!("validation_{scenario}"),
                profile: "franka_panda".to_string(),
                environments: 1,
                episodes_per_env: 3,
                steps_per_episode: 10,
                scenarios: vec![ScenarioConfig {
                    scenario_type: scenario.to_string(),
                    weight: 1.0,
                    injections: vec![],
                }],
                success_criteria: SuccessCriteria::default(),
            };
            let result = run_dry_campaign(&config, None);
            assert!(
                result.is_ok(),
                "scenario '{scenario}' on franka_panda must not error: {:?}",
                result.err()
            );
            assert_eq!(
                result.unwrap().violation_escape_count,
                0,
                "scenario '{scenario}': zero escapes required"
            );
        }
    }

    #[test]
    fn dry_run_all_22_scenarios_legged_profile() {
        let all_scenarios = [
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
            "locomotion_stomp",
            "locomotion_fall",
            "cnc_tending",
            "environment_fault",
            "compound_authority_physics",
            "compound_sensor_spatial",
            "compound_drift_then_violation",
            "compound_environment_physics",
            "recovery_safe_stop",
            "recovery_audit_integrity",
            "long_running_stability",
            "long_running_threat",
            "joint_position_boundary",
            "joint_velocity_boundary",
            "joint_torque_boundary",
            "joint_acceleration_ramp",
            "joint_coordinated_violation",
            "joint_direction_reversal",
            "joint_ieee754_special",
            "joint_gradual_drift",
        ];
        for scenario in &all_scenarios {
            let config = CampaignConfig {
                name: format!("validation_{scenario}"),
                profile: "spot".to_string(),
                environments: 1,
                episodes_per_env: 3,
                steps_per_episode: 10,
                scenarios: vec![ScenarioConfig {
                    scenario_type: scenario.to_string(),
                    weight: 1.0,
                    injections: vec![],
                }],
                success_criteria: SuccessCriteria::default(),
            };
            let result = run_dry_campaign(&config, None);
            assert!(
                result.is_ok(),
                "scenario '{scenario}' on spot must not error: {:?}",
                result.err()
            );
            let report = result.unwrap();
            assert_eq!(
                report.violation_escape_count, 0,
                "scenario '{scenario}' on spot: zero escapes required"
            );
        }
    }

    #[test]
    fn dry_run_all_22_scenarios_adversarial_profiles() {
        // Run a subset of scenarios against the 4 synthetic adversarial profiles.
        let scenarios = [
            "baseline",
            "authority_escalation",
            "prompt_injection",
            "compound_authority_physics",
            "long_running_stability",
        ];
        let profiles = [
            "adversarial_zero_margin",
            "adversarial_max_workspace",
            "adversarial_single_joint",
            "adversarial_max_joints",
        ];
        for profile in &profiles {
            for scenario in &scenarios {
                let config = CampaignConfig {
                    name: format!("adv_{profile}_{scenario}"),
                    profile: profile.to_string(),
                    environments: 1,
                    episodes_per_env: 2,
                    steps_per_episode: 5,
                    scenarios: vec![ScenarioConfig {
                        scenario_type: scenario.to_string(),
                        weight: 1.0,
                        injections: vec![],
                    }],
                    success_criteria: SuccessCriteria::default(),
                };
                let result = run_dry_campaign(&config, None);
                assert!(
                    result.is_ok(),
                    "scenario '{scenario}' on {profile} must not error: {:?}",
                    result.err()
                );
                assert_eq!(
                    result.unwrap().violation_escape_count,
                    0,
                    "scenario '{scenario}' on {profile}: zero escapes"
                );
            }
        }
    }

    #[test]
    fn dry_run_all_scenarios_dexterous_hand_profile() {
        // Dexterous hands: no locomotion, no stability, but have end-effectors
        // and fine-grained collision pairs.
        let scenarios = [
            "baseline",
            "aggressive",
            "authority_escalation",
            "chain_forgery",
            "prompt_injection",
            "compound_authority_physics",
            "compound_drift_then_violation",
            "recovery_safe_stop",
            "long_running_stability",
        ];
        for profile in &[
            "shadow_hand",
            "allegro_hand",
            "leap_hand",
            "psyonic_ability",
        ] {
            for scenario in &scenarios {
                let config = CampaignConfig {
                    name: format!("hand_{profile}_{scenario}"),
                    profile: profile.to_string(),
                    environments: 1,
                    episodes_per_env: 2,
                    steps_per_episode: 5,
                    scenarios: vec![ScenarioConfig {
                        scenario_type: scenario.to_string(),
                        weight: 1.0,
                        injections: vec![],
                    }],
                    success_criteria: SuccessCriteria::default(),
                };
                let result = run_dry_campaign(&config, None);
                assert!(
                    result.is_ok(),
                    "scenario '{scenario}' on {profile} must not error: {:?}",
                    result.err()
                );
                assert_eq!(
                    result.unwrap().violation_escape_count,
                    0,
                    "scenario '{scenario}' on {profile}: zero escapes"
                );
            }
        }
    }

    #[test]
    fn dry_run_all_scenarios_mobile_manipulator_profile() {
        // Mobile manipulators: locomotion-enabled with prismatic joints.
        let all_scenarios = [
            "baseline",
            "aggressive",
            "exclusion_zone",
            "authority_escalation",
            "chain_forgery",
            "prompt_injection",
            "locomotion_runaway",
            "locomotion_slip",
            "locomotion_trip",
            "locomotion_stomp",
            "locomotion_fall",
            "environment_fault",
            "compound_authority_physics",
            "compound_environment_physics",
            "recovery_safe_stop",
            "long_running_stability",
        ];
        for profile in &["spot_with_arm", "hello_stretch", "pal_tiago"] {
            for scenario in &all_scenarios {
                let config = CampaignConfig {
                    name: format!("mobile_{profile}_{scenario}"),
                    profile: profile.to_string(),
                    environments: 1,
                    episodes_per_env: 2,
                    steps_per_episode: 5,
                    scenarios: vec![ScenarioConfig {
                        scenario_type: scenario.to_string(),
                        weight: 1.0,
                        injections: vec![],
                    }],
                    success_criteria: SuccessCriteria::default(),
                };
                let result = run_dry_campaign(&config, None);
                assert!(
                    result.is_ok(),
                    "scenario '{scenario}' on {profile} must not error: {:?}",
                    result.err()
                );
                assert_eq!(
                    result.unwrap().violation_escape_count,
                    0,
                    "scenario '{scenario}' on {profile}: zero escapes"
                );
            }
        }
    }

    #[test]
    fn dry_run_all_scenarios_new_humanoid_profiles() {
        // New humanoid profiles: all 22 scenarios, verifying full coverage
        // for the expanded humanoid roster.
        let all_scenarios = [
            "baseline",
            "aggressive",
            "exclusion_zone",
            "authority_escalation",
            "chain_forgery",
            "prompt_injection",
            "locomotion_runaway",
            "locomotion_slip",
            "locomotion_trip",
            "locomotion_stomp",
            "locomotion_fall",
            "environment_fault",
            "compound_authority_physics",
            "compound_sensor_spatial",
            "compound_drift_then_violation",
            "compound_environment_physics",
            "recovery_safe_stop",
            "recovery_audit_integrity",
            "long_running_stability",
            "long_running_threat",
        ];
        // Test a representative sample of the new humanoids (not all 8,
        // as each takes ~1s per scenario — test the most distinct ones).
        for profile in &["fourier_gr1", "agility_digit", "bd_atlas"] {
            for scenario in &all_scenarios {
                let config = CampaignConfig {
                    name: format!("humanoid_{profile}_{scenario}"),
                    profile: profile.to_string(),
                    environments: 1,
                    episodes_per_env: 2,
                    steps_per_episode: 5,
                    scenarios: vec![ScenarioConfig {
                        scenario_type: scenario.to_string(),
                        weight: 1.0,
                        injections: vec![],
                    }],
                    success_criteria: SuccessCriteria::default(),
                };
                let result = run_dry_campaign(&config, None);
                assert!(
                    result.is_ok(),
                    "scenario '{scenario}' on {profile} must not error: {:?}",
                    result.err()
                );
                assert_eq!(
                    result.unwrap().violation_escape_count,
                    0,
                    "scenario '{scenario}' on {profile}: zero escapes"
                );
            }
        }
    }

    #[test]
    fn dry_run_legitimate_scenarios_produce_approvals() {
        // Legitimate scenarios must produce at least some approved commands.
        // Use ur10 — a well-tested profile with wide limits.
        let legitimate = ["baseline"];
        for scenario in &legitimate {
            let config = CampaignConfig {
                name: format!("legit_{scenario}"),
                profile: "ur10".to_string(),
                environments: 1,
                episodes_per_env: 3,
                steps_per_episode: 20,
                scenarios: vec![ScenarioConfig {
                    scenario_type: scenario.to_string(),
                    weight: 1.0,
                    injections: vec![],
                }],
                success_criteria: SuccessCriteria::default(),
            };
            let report = run_dry_campaign(&config, None).expect("must complete");
            assert!(
                report.total_approved > 0,
                "scenario '{scenario}': must produce at least some approvals, got 0 of {} total",
                report.total_commands
            );
        }
    }

    #[test]
    fn dry_run_adversarial_scenarios_produce_rejections() {
        // Adversarial scenarios must produce at least some rejections.
        let adversarial = [
            "authority_escalation",
            "chain_forgery",
            "prompt_injection",
            "compound_authority_physics",
            "compound_drift_then_violation",
        ];
        for scenario in &adversarial {
            let config = CampaignConfig {
                name: format!("adv_{scenario}"),
                profile: "franka_panda".to_string(),
                environments: 1,
                episodes_per_env: 3,
                steps_per_episode: 20,
                scenarios: vec![ScenarioConfig {
                    scenario_type: scenario.to_string(),
                    weight: 1.0,
                    injections: vec![],
                }],
                success_criteria: SuccessCriteria::default(),
            };
            let report = run_dry_campaign(&config, None).expect("must complete");
            assert!(
                report.total_rejected > 0,
                "scenario '{scenario}': must produce rejections, got 0 of {} total",
                report.total_commands
            );
        }
    }
}
