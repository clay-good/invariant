/// Signed actuation command produced for approved commands (M1).
pub mod actuation;
/// Audit log entry types: `AuditEntry` and `SignedAuditEntry`.
pub mod audit;
/// PIC authority chain data types: `Pca`, `SignedPca`, `Operation`, `AuthorityChain`.
pub mod authority;
/// Robot motion command submitted to the safety validator.
pub mod command;
/// Validation error types and the `Validate` trait.
pub mod error;
/// Robot profile schema: joints, workspace, exclusion zones, locomotion config, etc.
pub mod profile;
/// Simulation trace types: `Trace` and `TraceStep`.
pub mod trace;
/// Safety verdict types: `Verdict`, `SignedVerdict`, `CheckResult`, `AuthoritySummary`.
pub mod verdict;

#[cfg(test)]
mod tests {
    use super::error::Validate;
    use super::profile::{RobotProfile, SafeStopStrategy, WorkspaceBounds};

    #[test]
    fn deserialize_humanoid_profile() {
        let json = include_str!("../../profiles/humanoid_28dof.json");
        let profile: RobotProfile =
            serde_json::from_str(json).expect("deserialize humanoid profile");
        assert_eq!(profile.name, "humanoid_28dof");
        assert_eq!(profile.joints.len(), 28);
        assert_eq!(
            profile.safe_stop_profile.strategy,
            SafeStopStrategy::ControlledCrouch
        );
        profile.validate().expect("humanoid profile is valid");
    }

    #[test]
    fn operation_validates_chars() {
        use super::authority::Operation;
        assert!(Operation::new("actuate:humanoid:left_arm:*").is_ok());
        assert!(Operation::new("").is_err());
        assert!(Operation::new("bad op").is_err());
        assert!(Operation::new("ok-op_1.2:*").is_ok());
    }

    #[test]
    fn joint_definition_validates_limits() {
        use super::profile::{JointDefinition, JointType};
        let bad = JointDefinition {
            name: "j".into(),
            joint_type: JointType::Revolute,
            min: 1.0,
            max: 0.0, // inverted
            max_velocity: 1.0,
            max_torque: 1.0,
            max_acceleration: 1.0,
        };
        assert!(bad.validate().is_err());

        let zero_vel = JointDefinition {
            max_velocity: 0.0,
            ..bad.clone()
        };
        // first error is inverted limits, so fix those first
        let ok = JointDefinition {
            min: -1.0,
            max: 1.0,
            max_velocity: 0.0,
            ..bad
        };
        assert!(ok.validate().is_err()); // zero velocity
        let _ = zero_vel; // suppress unused
    }

    #[test]
    fn joint_nan_min_max_rejected() {
        use super::error::ValidationError;
        use super::profile::{JointDefinition, JointType};
        let nan_min = JointDefinition {
            name: "j_nan".into(),
            joint_type: JointType::Revolute,
            min: f64::NAN,
            max: 1.0,
            max_velocity: 1.0,
            max_torque: 1.0,
            max_acceleration: 1.0,
        };
        assert!(matches!(
            nan_min.validate(),
            Err(ValidationError::JointLimitNotFinite {
                field: "min/max",
                ..
            })
        ));
        let inf_max = JointDefinition {
            min: -1.0,
            max: f64::INFINITY,
            ..nan_min.clone()
        };
        assert!(matches!(
            inf_max.validate(),
            Err(ValidationError::JointLimitNotFinite {
                field: "min/max",
                ..
            })
        ));
    }

    #[test]
    fn joint_nan_velocity_torque_acceleration_rejected() {
        use super::error::ValidationError;
        use super::profile::{JointDefinition, JointType};
        let base = JointDefinition {
            name: "j".into(),
            joint_type: JointType::Revolute,
            min: -1.0,
            max: 1.0,
            max_velocity: 1.0,
            max_torque: 1.0,
            max_acceleration: 1.0,
        };
        let nan_vel = JointDefinition {
            max_velocity: f64::NAN,
            ..base.clone()
        };
        assert!(matches!(
            nan_vel.validate(),
            Err(ValidationError::JointLimitNotFinite {
                field: "max_velocity",
                ..
            })
        ));
        let nan_torque = JointDefinition {
            max_torque: f64::NAN,
            ..base.clone()
        };
        assert!(matches!(
            nan_torque.validate(),
            Err(ValidationError::JointLimitNotFinite {
                field: "max_torque",
                ..
            })
        ));
        let nan_accel = JointDefinition {
            max_acceleration: f64::NAN,
            ..base
        };
        assert!(matches!(
            nan_accel.validate(),
            Err(ValidationError::JointLimitNotFinite {
                field: "max_acceleration",
                ..
            })
        ));
    }

    #[test]
    fn workspace_bounds_nan_rejected() {
        use super::error::ValidationError;
        use super::profile::WorkspaceBounds;
        let nan_x = WorkspaceBounds::Aabb {
            min: [f64::NAN, 0.0, 0.0],
            max: [1.0, 1.0, 1.0],
        };
        assert!(matches!(
            nan_x.validate(),
            Err(ValidationError::WorkspaceBoundsNotFinite { axis: 0 })
        ));
        let inf_y = WorkspaceBounds::Aabb {
            min: [0.0, f64::NEG_INFINITY, 0.0],
            max: [1.0, 1.0, 1.0],
        };
        assert!(matches!(
            inf_y.validate(),
            Err(ValidationError::WorkspaceBoundsNotFinite { axis: 1 })
        ));
    }

    // ── Finding 75: ProximityZone velocity_scale boundary tests ──────────────

    #[test]
    fn proximity_zone_velocity_scale_zero_rejected() {
        use super::error::ValidationError;
        use super::profile::ProximityZone;
        let zone = ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 0.0,
            dynamic: false,
        };
        assert!(matches!(
            zone.validate(),
            Err(ValidationError::ProximityVelocityScaleOutOfRange { .. })
        ));
    }

    #[test]
    fn proximity_zone_velocity_scale_negative_rejected() {
        use super::error::ValidationError;
        use super::profile::ProximityZone;
        let zone = ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: -0.1,
            dynamic: false,
        };
        assert!(matches!(
            zone.validate(),
            Err(ValidationError::ProximityVelocityScaleOutOfRange { .. })
        ));
    }

    #[test]
    fn proximity_zone_velocity_scale_above_one_rejected() {
        use super::error::ValidationError;
        use super::profile::ProximityZone;
        let zone = ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 1.01,
            dynamic: false,
        };
        assert!(matches!(
            zone.validate(),
            Err(ValidationError::ProximityVelocityScaleOutOfRange { .. })
        ));
    }

    #[test]
    fn proximity_zone_velocity_scale_one_accepted() {
        use super::profile::ProximityZone;
        // velocity_scale = 1.0 is the upper inclusive boundary; it must pass.
        let zone = ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: 1.0,
            velocity_scale: 1.0,
            dynamic: false,
        };
        assert!(zone.validate().is_ok());
    }

    #[test]
    fn proximity_zone_nan_radius_rejected() {
        use super::error::ValidationError;
        use super::profile::ProximityZone;
        let nan_radius = ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: f64::NAN,
            velocity_scale: 0.5,
            dynamic: false,
        };
        assert!(matches!(
            nan_radius.validate(),
            Err(ValidationError::ProximityRadiusInvalid { .. })
        ));
        let zero_radius = ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: 0.0,
            velocity_scale: 0.5,
            dynamic: false,
        };
        assert!(matches!(
            zero_radius.validate(),
            Err(ValidationError::ProximityRadiusInvalid { .. })
        ));
        let neg_radius = ProximityZone::Sphere {
            name: "zone".into(),
            center: [0.0, 0.0, 0.0],
            radius: -1.0,
            velocity_scale: 0.5,
            dynamic: false,
        };
        assert!(matches!(
            neg_radius.validate(),
            Err(ValidationError::ProximityRadiusInvalid { .. })
        ));
    }

    // ── Finding 73: collection cap violation tests ────────────────────────────

    fn minimal_joint(name: &str) -> super::profile::JointDefinition {
        use super::profile::{JointDefinition, JointType};
        JointDefinition {
            name: name.into(),
            joint_type: JointType::Revolute,
            min: -1.0,
            max: 1.0,
            max_velocity: 1.0,
            max_torque: 1.0,
            max_acceleration: 1.0,
        }
    }

    fn base_profile() -> super::profile::RobotProfile {
        use super::profile::{RobotProfile, SafeStopProfile, WorkspaceBounds};
        RobotProfile {
            name: "cap_test".into(),
            version: "1.0".into(),
            joints: vec![minimal_joint("j0")],
            workspace: WorkspaceBounds::Aabb {
                min: [-1.0, -1.0, -1.0],
                max: [1.0, 1.0, 1.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            max_delta_time: 0.1,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None,
            locomotion: None,
            end_effectors: vec![],
        }
    }

    #[test]
    fn joints_over_256_rejected() {
        use super::error::ValidationError;
        let mut profile = base_profile();
        // 257 joints with unique names to avoid DuplicateJointName.
        profile.joints = (0..=256).map(|i| minimal_joint(&format!("j{i}"))).collect();
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::CollectionTooLarge { name: "joints", .. })
        ));
    }

    #[test]
    fn exclusion_zones_over_256_rejected() {
        use super::error::ValidationError;
        use super::profile::ExclusionZone;
        let mut profile = base_profile();
        profile.exclusion_zones = (0..=256)
            .map(|i| ExclusionZone::Sphere {
                name: format!("ez{i}"),
                center: [0.0, 0.0, 0.0],
                radius: 0.1,
                conditional: false,
            })
            .collect();
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::CollectionTooLarge {
                name: "exclusion_zones",
                ..
            })
        ));
    }

    #[test]
    fn proximity_zones_over_256_rejected() {
        use super::error::ValidationError;
        use super::profile::ProximityZone;
        let mut profile = base_profile();
        profile.proximity_zones = (0..=256)
            .map(|i| ProximityZone::Sphere {
                name: format!("pz{i}"),
                center: [0.0, 0.0, 0.0],
                radius: 0.1,
                velocity_scale: 0.5,
                dynamic: false,
            })
            .collect();
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::CollectionTooLarge {
                name: "proximity_zones",
                ..
            })
        ));
    }

    #[test]
    fn collision_pairs_over_1024_rejected() {
        use super::error::ValidationError;
        use super::profile::CollisionPair;
        let mut profile = base_profile();
        profile.collision_pairs = (0..=1024)
            .map(|i| CollisionPair {
                link_a: format!("a{i}"),
                link_b: format!("b{i}"),
            })
            .collect();
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::CollectionTooLarge {
                name: "collision_pairs",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_joint_names_rejected() {
        use super::error::ValidationError;
        use super::profile::{
            JointDefinition, JointType, RobotProfile, SafeStopProfile, WorkspaceBounds,
        };
        let joint = JointDefinition {
            name: "elbow".into(),
            joint_type: JointType::Revolute,
            min: -1.0,
            max: 1.0,
            max_velocity: 1.0,
            max_torque: 1.0,
            max_acceleration: 1.0,
        };
        let profile = RobotProfile {
            name: "test".into(),
            version: "1.0".into(),
            joints: vec![joint.clone(), joint.clone()],
            workspace: WorkspaceBounds::Aabb {
                min: [-1.0, -1.0, -1.0],
                max: [1.0, 1.0, 1.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            max_delta_time: 0.01,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None,
            locomotion: None,
            end_effectors: vec![],
        };
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::DuplicateJointName { name }) if name == "elbow"
        ));
    }

    // ── Task envelope validation (Section 17.2) ────────────────────────

    use super::profile::{EndEffectorConfig, TaskEnvelope};

    fn envelope_base_profile() -> super::profile::RobotProfile {
        let mut p = base_profile();
        p.global_velocity_scale = 0.8;
        p.end_effectors = vec![EndEffectorConfig {
            name: "gripper".into(),
            max_force_n: 100.0,
            max_grasp_force_n: 80.0,
            min_grasp_force_n: 5.0,
            max_force_rate_n_per_s: 500.0,
            max_payload_kg: 10.0,
        }];
        p
    }

    fn valid_envelope() -> TaskEnvelope {
        TaskEnvelope {
            name: "test_task".into(),
            description: String::new(),
            global_velocity_scale: Some(0.5),
            max_payload_kg: Some(5.0),
            end_effector_force_limit_n: Some(50.0),
            workspace: None,
            additional_exclusion_zones: vec![],
        }
    }

    #[test]
    fn valid_envelope_passes_validation() {
        let mut profile = envelope_base_profile();
        profile.task_envelope = Some(valid_envelope());
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn envelope_velocity_scale_exceeding_profile_rejected() {
        let mut profile = envelope_base_profile();
        let mut env = valid_envelope();
        env.global_velocity_scale = Some(0.9); // exceeds profile 0.8
        profile.task_envelope = Some(env);
        let result = profile.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("global_velocity_scale"));
    }

    #[test]
    fn envelope_velocity_scale_zero_rejected() {
        let mut profile = envelope_base_profile();
        let mut env = valid_envelope();
        env.global_velocity_scale = Some(0.0);
        profile.task_envelope = Some(env);
        assert!(profile.validate().is_err());
    }

    #[test]
    fn envelope_workspace_outside_profile_rejected() {
        let mut profile = envelope_base_profile();
        // Profile workspace: [-1, -1, -1] to [1, 1, 1]
        let mut env = valid_envelope();
        env.workspace = Some(WorkspaceBounds::Aabb {
            min: [-2.0, -1.0, -1.0], // min[0] = -2.0 < profile min[0] = -1.0
            max: [1.0, 1.0, 1.0],
        });
        profile.task_envelope = Some(env);
        let result = profile.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("workspace"));
    }

    #[test]
    fn envelope_workspace_contained_passes() {
        let mut profile = envelope_base_profile();
        let mut env = valid_envelope();
        env.workspace = Some(WorkspaceBounds::Aabb {
            min: [-0.5, -0.5, -0.5],
            max: [0.5, 0.5, 0.5],
        });
        profile.task_envelope = Some(env);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn envelope_force_limit_exceeding_profile_rejected() {
        let mut profile = envelope_base_profile();
        let mut env = valid_envelope();
        env.end_effector_force_limit_n = Some(150.0); // exceeds gripper max_force_n 100
        profile.task_envelope = Some(env);
        let result = profile.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("end_effector_force_limit_n"));
    }

    #[test]
    fn envelope_payload_exceeding_profile_rejected() {
        let mut profile = envelope_base_profile();
        let mut env = valid_envelope();
        env.max_payload_kg = Some(15.0); // exceeds gripper max_payload_kg 10
        profile.task_envelope = Some(env);
        let result = profile.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_payload_kg"));
    }

    #[test]
    fn envelope_no_end_effectors_force_limit_passes() {
        // If profile has no end-effectors, force/payload limits in envelope
        // pass trivially (nothing to compare against).
        let mut profile = base_profile(); // no end_effectors
        let mut env = valid_envelope();
        env.end_effector_force_limit_n = Some(50.0);
        env.max_payload_kg = Some(5.0);
        env.global_velocity_scale = Some(0.5);
        profile.task_envelope = Some(env);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn envelope_none_passes_validation() {
        let profile = envelope_base_profile();
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn envelope_negative_payload_rejected() {
        let mut profile = envelope_base_profile();
        let mut env = valid_envelope();
        env.max_payload_kg = Some(-1.0);
        profile.task_envelope = Some(env);
        assert!(profile.validate().is_err());
    }

    // --- EnvironmentConfig validation ---

    #[test]
    fn validate_environment_config_valid() {
        let json = r#"{
            "name": "test", "version": "1.0.0",
            "joints": [{"name":"j1","type":"revolute","min":-1.0,"max":1.0,"max_velocity":1.0,"max_torque":10.0,"max_acceleration":5.0}], "workspace": {"type": "aabb", "min": [-1,-1,0], "max": [1,1,2]},
            "max_delta_time": 0.1,
            "environment": {}
        }"#;
        let profile: RobotProfile = serde_json::from_str(json).unwrap();
        assert!(
            profile.validate().is_ok(),
            "default EnvironmentConfig should be valid"
        );
    }

    #[test]
    fn validate_environment_config_critical_ge_low_battery() {
        use super::error::ValidationError;
        let json = r#"{
            "name": "test", "version": "1.0.0",
            "joints": [{"name":"j1","type":"revolute","min":-1.0,"max":1.0,"max_velocity":1.0,"max_torque":10.0,"max_acceleration":5.0}], "workspace": {"type": "aabb", "min": [-1,-1,0], "max": [1,1,2]},
            "max_delta_time": 0.1,
            "environment": {"critical_battery_pct": 20.0, "low_battery_pct": 10.0}
        }"#;
        let profile: RobotProfile = serde_json::from_str(json).unwrap();
        match profile.validate() {
            Err(ValidationError::EnvironmentConfigInvalid { reason }) => {
                assert!(reason.contains("critical_battery_pct"));
            }
            other => panic!("expected EnvironmentConfigInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_environment_config_warning_ge_max_latency() {
        use super::error::ValidationError;
        let json = r#"{
            "name": "test", "version": "1.0.0",
            "joints": [{"name":"j1","type":"revolute","min":-1.0,"max":1.0,"max_velocity":1.0,"max_torque":10.0,"max_acceleration":5.0}], "workspace": {"type": "aabb", "min": [-1,-1,0], "max": [1,1,2]},
            "max_delta_time": 0.1,
            "environment": {"warning_latency_ms": 200.0, "max_latency_ms": 100.0}
        }"#;
        let profile: RobotProfile = serde_json::from_str(json).unwrap();
        match profile.validate() {
            Err(ValidationError::EnvironmentConfigInvalid { reason }) => {
                assert!(reason.contains("warning_latency_ms"));
            }
            other => panic!("expected EnvironmentConfigInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_environment_config_negative_pitch() {
        use super::error::ValidationError;
        let json = r#"{
            "name": "test", "version": "1.0.0",
            "joints": [{"name":"j1","type":"revolute","min":-1.0,"max":1.0,"max_velocity":1.0,"max_torque":10.0,"max_acceleration":5.0}], "workspace": {"type": "aabb", "min": [-1,-1,0], "max": [1,1,2]},
            "max_delta_time": 0.1,
            "environment": {"max_safe_pitch_rad": -0.5}
        }"#;
        let profile: RobotProfile = serde_json::from_str(json).unwrap();
        match profile.validate() {
            Err(ValidationError::EnvironmentConfigInvalid { reason }) => {
                assert!(reason.contains("max_safe_pitch_rad"));
            }
            other => panic!("expected EnvironmentConfigInvalid, got {other:?}"),
        }
    }

    // ── New validation rule tests ─────────────────────────────────────────────

    fn validation_test_profile() -> super::profile::RobotProfile {
        use super::profile::{
            JointDefinition, JointType, RobotProfile, SafeStopProfile, WorkspaceBounds,
        };
        RobotProfile {
            name: "test".into(),
            version: "1.0.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -1.0,
                max: 1.0,
                max_velocity: 1.0,
                max_torque: 10.0,
                max_acceleration: 5.0,
            }],
            workspace: WorkspaceBounds::Aabb {
                min: [-1.0, -1.0, 0.0],
                max: [1.0, 1.0, 2.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            max_delta_time: 0.01,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None,
            end_effectors: vec![],
        }
    }

    // ── Rule 1: NoJoints ─────────────────────────────────────────────────────

    #[test]
    fn validate_no_joints_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        profile.joints = vec![];
        assert!(matches!(profile.validate(), Err(ValidationError::NoJoints)));
    }

    // ── Rule 2: InvalidMaxDeltaTime ──────────────────────────────────────────

    #[test]
    fn validate_max_delta_time_zero_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        profile.max_delta_time = 0.0;
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::InvalidMaxDeltaTime(v)) if v == 0.0
        ));
    }

    #[test]
    fn validate_max_delta_time_negative_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        profile.max_delta_time = -0.01;
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::InvalidMaxDeltaTime(_))
        ));
    }

    #[test]
    fn validate_max_delta_time_nan_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        profile.max_delta_time = f64::NAN;
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::InvalidMaxDeltaTime(_))
        ));
    }

    #[test]
    fn validate_max_delta_time_infinite_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        profile.max_delta_time = f64::INFINITY;
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::InvalidMaxDeltaTime(_))
        ));
    }

    #[test]
    fn validate_max_delta_time_positive_passes() {
        let profile = validation_test_profile(); // max_delta_time = 0.01
        assert!(profile.validate().is_ok());
    }

    // ── Rule 3: LocomotionConfigInvalid ──────────────────────────────────────

    fn valid_locomotion() -> super::profile::LocomotionConfig {
        use super::profile::LocomotionConfig;
        LocomotionConfig {
            max_locomotion_velocity: 1.5,
            max_step_length: 0.3,
            min_foot_clearance: 0.05,
            max_step_height: 0.5,
            max_ground_reaction_force: 200.0,
            friction_coefficient: 0.8,
            max_heading_rate: 1.0,
        }
    }

    #[test]
    fn validate_locomotion_valid_passes() {
        let mut profile = validation_test_profile();
        profile.locomotion = Some(valid_locomotion());
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn validate_locomotion_zero_velocity_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut loco = valid_locomotion();
        loco.max_locomotion_velocity = 0.0;
        profile.locomotion = Some(loco);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::LocomotionConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_locomotion_negative_step_length_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut loco = valid_locomotion();
        loco.max_step_length = -0.1;
        profile.locomotion = Some(loco);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::LocomotionConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_locomotion_nan_friction_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut loco = valid_locomotion();
        loco.friction_coefficient = f64::NAN;
        profile.locomotion = Some(loco);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::LocomotionConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_locomotion_friction_above_two_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut loco = valid_locomotion();
        loco.friction_coefficient = 2.1;
        profile.locomotion = Some(loco);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::LocomotionConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_locomotion_zero_grf_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut loco = valid_locomotion();
        loco.max_ground_reaction_force = 0.0;
        profile.locomotion = Some(loco);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::LocomotionConfigInvalid { .. })
        ));
    }

    // ── Rule 4: RealWorldMarginsInvalid ──────────────────────────────────────

    fn valid_margins() -> super::profile::RealWorldMargins {
        use super::profile::RealWorldMargins;
        RealWorldMargins {
            position_margin: 0.05,
            velocity_margin: 0.10,
            torque_margin: 0.08,
            acceleration_margin: 0.12,
        }
    }

    #[test]
    fn validate_real_world_margins_valid_passes() {
        let mut profile = validation_test_profile();
        profile.real_world_margins = Some(valid_margins());
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn validate_real_world_margins_negative_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut m = valid_margins();
        m.position_margin = -0.01;
        profile.real_world_margins = Some(m);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::RealWorldMarginsInvalid { .. })
        ));
    }

    #[test]
    fn validate_real_world_margins_exactly_one_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut m = valid_margins();
        m.velocity_margin = 1.0;
        profile.real_world_margins = Some(m);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::RealWorldMarginsInvalid { .. })
        ));
    }

    #[test]
    fn validate_real_world_margins_half_passes() {
        let mut profile = validation_test_profile();
        let mut m = valid_margins();
        m.torque_margin = 0.5;
        profile.real_world_margins = Some(m);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn validate_real_world_margins_nan_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut m = valid_margins();
        m.acceleration_margin = f64::NAN;
        profile.real_world_margins = Some(m);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::RealWorldMarginsInvalid { .. })
        ));
    }

    // ── Rule 5: EndEffectorConfigInvalid ─────────────────────────────────────

    fn valid_end_effector() -> super::profile::EndEffectorConfig {
        use super::profile::EndEffectorConfig;
        EndEffectorConfig {
            name: "gripper".into(),
            max_force_n: 100.0,
            max_grasp_force_n: 80.0,
            min_grasp_force_n: 5.0,
            max_force_rate_n_per_s: 500.0,
            max_payload_kg: 10.0,
        }
    }

    #[test]
    fn validate_end_effector_valid_passes() {
        let mut profile = validation_test_profile();
        profile.end_effectors = vec![valid_end_effector()];
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn validate_end_effector_negative_max_force_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut ee = valid_end_effector();
        ee.max_force_n = -1.0;
        profile.end_effectors = vec![ee];
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::EndEffectorConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_end_effector_min_grasp_ge_max_grasp_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut ee = valid_end_effector();
        ee.min_grasp_force_n = 80.0; // equal to max_grasp_force_n
        profile.end_effectors = vec![ee];
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::EndEffectorConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_end_effector_nan_payload_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut ee = valid_end_effector();
        ee.max_payload_kg = f64::NAN;
        profile.end_effectors = vec![ee];
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::EndEffectorConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_end_effector_zero_force_rate_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut ee = valid_end_effector();
        ee.max_force_rate_n_per_s = 0.0;
        profile.end_effectors = vec![ee];
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::EndEffectorConfigInvalid { .. })
        ));
    }

    // ── Rule 7: StabilityConfigInvalid (Step 99) ────────────────────────────

    fn valid_stability() -> super::profile::StabilityConfig {
        super::profile::StabilityConfig {
            support_polygon: vec![[0.0, 0.0], [1.0, 0.0], [0.5, 1.0]],
            com_height_estimate: 0.9,
            enabled: true,
        }
    }

    #[test]
    fn validate_stability_valid_config_accepted() {
        let mut profile = validation_test_profile();
        profile.stability = Some(valid_stability());
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn validate_stability_nan_com_height_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut stab = valid_stability();
        stab.com_height_estimate = f64::NAN;
        profile.stability = Some(stab);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::StabilityConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_stability_zero_com_height_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut stab = valid_stability();
        stab.com_height_estimate = 0.0;
        profile.stability = Some(stab);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::StabilityConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_stability_enabled_fewer_than_3_vertices_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut stab = valid_stability();
        stab.support_polygon = vec![[0.0, 0.0], [1.0, 0.0]]; // only 2
        profile.stability = Some(stab);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::StabilityConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_stability_disabled_fewer_than_3_vertices_accepted() {
        let mut profile = validation_test_profile();
        let mut stab = valid_stability();
        stab.enabled = false;
        stab.support_polygon = vec![[0.0, 0.0]]; // only 1, but disabled
        profile.stability = Some(stab);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn validate_stability_nan_polygon_vertex_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut stab = valid_stability();
        stab.support_polygon = vec![[0.0, 0.0], [f64::NAN, 0.0], [0.5, 1.0]];
        profile.stability = Some(stab);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::StabilityConfigInvalid { .. })
        ));
    }

    #[test]
    fn validate_stability_infinity_polygon_vertex_rejected() {
        use super::error::ValidationError;
        let mut profile = validation_test_profile();
        let mut stab = valid_stability();
        stab.support_polygon = vec![[0.0, 0.0], [1.0, f64::INFINITY], [0.5, 1.0]];
        profile.stability = Some(stab);
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::StabilityConfigInvalid { .. })
        ));
    }
}
