//! Campaign-YAML schema validation (v11-5.14).
//!
//! Loads every committed `campaigns/*.yaml`, verifies each `scenario_type`
//! resolves to a `ScenarioType` variant, each `profile` resolves to a
//! built-in robot profile (or to a JSON file under `profiles/robotics/`),
//! and the headline numeric fields fall in sane ranges. Catches silent
//! drift between the committed campaign configs and the source enums
//! they reference.

use std::path::{Path, PathBuf};

use invariant_sim::robotics::campaign::CampaignConfig;
use invariant_sim::robotics::scenario::ScenarioType;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above the crate manifest")
        .to_path_buf()
}

fn campaigns_dir() -> PathBuf {
    repo_root().join("campaigns")
}

fn profiles_dir() -> PathBuf {
    repo_root().join("profiles").join("robotics")
}

fn list_campaigns() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(campaigns_dir()).expect("campaigns/ must exist") {
        let path = entry.unwrap().path();
        if path
            .extension()
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn load(path: &Path) -> CampaignConfig {
    // Bypass `load_config`'s built-in `validate_config` — some committed
    // campaigns (e.g. `cnc_tending_1m.yaml`) exceed the per-config command
    // ceiling on purpose (they shard across many runners). The schema test
    // is about *shape*, not about whether a config fits in a single
    // process; the validator's range checks are exercised in their own
    // unit tests inside `invariant-sim`.
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_yaml::from_str::<CampaignConfig>(&text)
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Re-derives the snake_case spelling serde uses for `ScenarioType`. The
/// enum carries `#[serde(rename_all = "snake_case")]` so this match is
/// the authoritative mapping table for the YAML side.
///
/// Hand-written so a new enum variant trips the exhaustiveness check.
fn scenario_type_from_snake(s: &str) -> Option<ScenarioType> {
    use ScenarioType::*;
    Some(match s {
        "baseline" => Baseline,
        "aggressive" => Aggressive,
        "pick_and_place" => PickAndPlace,
        "walking_gait" => WalkingGait,
        "collaborative_work" => CollaborativeWork,
        "cnc_tending_full_cycle" => CncTendingFullCycle,
        "dexterous_manipulation" => DexterousManipulation,
        "multi_robot_coordinated" => MultiRobotCoordinated,
        "exclusion_zone" => ExclusionZone,
        "authority_escalation" => AuthorityEscalation,
        "chain_forgery" => ChainForgery,
        "prompt_injection" => PromptInjection,
        "multi_agent_handoff" => MultiAgentHandoff,
        "locomotion_runaway" => LocomotionRunaway,
        "locomotion_slip" => LocomotionSlip,
        "locomotion_trip" => LocomotionTrip,
        "locomotion_stomp" => LocomotionStomp,
        "locomotion_fall" => LocomotionFall,
        "cnc_tending" => CncTending,
        "environment_fault" => EnvironmentFault,
        "joint_position_boundary" => JointPositionBoundary,
        "joint_velocity_boundary" => JointVelocityBoundary,
        "joint_torque_boundary" => JointTorqueBoundary,
        "joint_acceleration_ramp" => JointAccelerationRamp,
        "joint_coordinated_violation" => JointCoordinatedViolation,
        "joint_direction_reversal" => JointDirectionReversal,
        "joint_ieee754_special" => JointIeee754Special,
        "joint_gradual_drift" => JointGradualDrift,
        "compound_authority_physics" => CompoundAuthorityPhysics,
        "compound_sensor_spatial" => CompoundSensorSpatial,
        "compound_drift_then_violation" => CompoundDriftThenViolation,
        "compound_environment_physics" => CompoundEnvironmentPhysics,
        "recovery_safe_stop" => RecoverySafeStop,
        "recovery_audit_integrity" => RecoveryAuditIntegrity,
        "long_running_stability" => LongRunningStability,
        "long_running_threat" => LongRunningThreat,
        "human_proximate" => HumanProximate,
        "nominal_cnc_tending" => NominalCncTending,
        "sequence_replay" => SequenceReplay,
        "sequence_gap" => SequenceGap,
        "delta_time_attack" => DeltaTimeAttack,
        "stale_command" => StaleCommand,
        "corrupt_spatial_data" => CorruptSpatialData,
        "payload_overload" => PayloadOverload,
        "force_limit_sweep" => ForceLimitSweep,
        "grasp_force_envelope" => GraspForceEnvelope,
        "force_rate_spike" => ForceRateSpike,
        "future_dated_sensor" => FutureDatedSensor,
        "temperature_ramp" => TemperatureRamp,
        "battery_drain" => BatteryDrain,
        "latency_spike" => LatencySpike,
        "e_stop_engage_release" => EStopEngageRelease,
        "sensor_range_implausible" => SensorRangeImplausible,
        "sensor_payload_range" => SensorPayloadRange,
        "sensor_fusion_inconsistency" => SensorFusionInconsistency,
        "com_stability_sweep" => ComStabilitySweep,
        "walking_gait_validation" => WalkingGaitValidation,
        "step_overextension" => StepOverextension,
        "heading_spinout" => HeadingSpinout,
        "incline_walking" => InclineWalking,
        "workspace_boundary_sweep" => WorkspaceBoundarySweep,
        "self_collision_approach" => SelfCollisionApproach,
        "overlapping_zone_boundaries" => OverlappingZoneBoundaries,
        "estop_recovery_cycle" => EstopRecoveryCycle,
        "million_entry_audit" => MillionEntryAudit,
        "counter_saturation" => CounterSaturation,
        "valid_invalid_alternating" => ValidInvalidAlternating,
        "maximum_payload_command" => MaximumPayloadCommand,
        "minimum_valid_command" => MinimumValidCommand,
        "nan_authority_bypass" => NanAuthorityBypass,
        "profile_probing_targeted" => ProfileProbingTargeted,
        "multi_robot_distraction" => MultiRobotDistraction,
        "watchdog_recovery_cycle" => WatchdogRecoveryCycle,
        "distraction_flooding" => DistractionFlooding,
        "error_mining" => ErrorMining,
        "gradual_drift_escape" => GradualDriftEscape,
        "semantic_confusion" => SemanticConfusion,
        "watchdog_timeout_replay" => WatchdogTimeoutReplay,
        "timing_exploitation" => TimingExploitation,
        "rate_stress_sustained" => RateStressSustained,
        "iso15066_human_proximity_force" => Iso15066HumanProximityForce,
        "bimanual_coordination" => BimanualCoordination,
        "mixed_profiles_audit" => MixedProfilesAudit,
        "profile_probing_binary_search" => ProfileProbingBinarySearch,
        "rollback_replay" => RollbackReplay,
        "profile_reload_during_operation" => ProfileReloadDuringOperation,
        "pure_fuzz" => PureFuzz,
        "authority_laundering" => AuthorityLaundering,
        "watchdog_manipulation" => WatchdogManipulation,
        "multi_agent_collusion" => MultiAgentCollusion,
        "validator_restart" => ValidatorRestart,
        "valid_authority_chain" => ValidAuthorityChain,
        "forged_signature" => ForgedSignature,
        "privilege_escalation" => PrivilegeEscalation,
        "expired_chain" => ExpiredChain,
        "key_substitution" => KeySubstitution,
        "provenance_mutation" => ProvenanceMutation,
        "wildcard_exploit" => WildcardExploit,
        "red_team_fuzz_generation" => RedTeamFuzzGeneration,
        "red_team_fuzz_mutation" => RedTeamFuzzMutation,
        "red_team_fuzz_unicode" => RedTeamFuzzUnicode,
        "red_team_fuzz_integer_boundary" => RedTeamFuzzIntegerBoundary,
        "cross_chain_splice" => CrossChainSplice,
        _ => return None,
    })
}

fn profile_is_known(profile: &str) -> bool {
    // Built-in name?
    if invariant_robotics::profiles::list_builtins().contains(&profile) {
        return true;
    }
    // Filename under profiles/robotics/?
    profiles_dir().join(format!("{profile}.json")).is_file()
}

#[test]
fn every_campaign_parses_as_yaml() {
    let paths = list_campaigns();
    assert!(
        !paths.is_empty(),
        "expected at least one campaign YAML under campaigns/"
    );
    for path in paths {
        let _ = load(&path); // load() panics on parse error
    }
}

#[test]
fn every_scenario_type_resolves_to_a_variant() {
    for path in list_campaigns() {
        let config = load(&path);
        for scenario in &config.scenarios {
            let resolved = scenario_type_from_snake(&scenario.scenario_type);
            assert!(
                resolved.is_some(),
                "{}: scenario_type {:?} does not resolve to any ScenarioType variant",
                path.display(),
                scenario.scenario_type
            );
        }
    }
}

#[test]
fn every_profile_name_is_known() {
    for path in list_campaigns() {
        let config = load(&path);
        assert!(
            profile_is_known(&config.profile),
            "{}: profile {:?} is not a built-in name and no profiles/robotics/{}.json exists",
            path.display(),
            config.profile,
            config.profile
        );
    }
}

#[test]
fn numeric_fields_are_in_sane_ranges() {
    // Loose ranges; the goal is to catch obvious mis-types (e.g. 0
    // episodes_per_env, episodes_per_env above 1e8) rather than to
    // hand-tune per-campaign.
    for path in list_campaigns() {
        let config = load(&path);
        assert!(
            (1..=1024).contains(&config.environments),
            "{}: environments={} out of range [1, 1024]",
            path.display(),
            config.environments
        );
        assert!(
            (1..=100_000_000).contains(&config.episodes_per_env),
            "{}: episodes_per_env={} out of range [1, 1e8]",
            path.display(),
            config.episodes_per_env
        );
        assert!(
            (1..=10_000_000).contains(&config.steps_per_episode),
            "{}: steps_per_episode={} out of range [1, 1e7]",
            path.display(),
            config.steps_per_episode
        );
        let total_weight: f64 = config.scenarios.iter().map(|s| s.weight).sum();
        assert!(
            total_weight > 0.0,
            "{}: total scenario weight must be > 0, got {total_weight}",
            path.display()
        );
        // Weights should be a positive distribution. The campaign runner
        // re-normalises before sampling, so the sum doesn't have to equal
        // 1.0 exactly — some committed configs are 0.99-ish from hand
        // editing. We only insist the sum is strictly positive and not
        // wildly off (e.g. all zeros, or a typo'd 10×).
        assert!(
            (0.5..=2.0).contains(&total_weight),
            "{}: total weight {} should fall in [0.5, 2.0] (runner re-normalises)",
            path.display(),
            total_weight
        );
    }
}

#[test]
fn scenario_type_from_snake_is_complete_for_variants_in_use() {
    // Defence in depth: every snake-case spelling we hand-rolled above
    // must map back to a real variant. If someone removes a variant from
    // ScenarioType, this trips before any real campaign run picks up
    // the breakage.
    for variant in ScenarioType::all() {
        let snake = serde_json::to_string(variant)
            .unwrap()
            .trim_matches('"')
            .to_string();
        assert!(
            scenario_type_from_snake(&snake).is_some(),
            "variant {variant:?} (snake={snake}) is not in scenario_type_from_snake — \
             the test helper is stale"
        );
    }
}
