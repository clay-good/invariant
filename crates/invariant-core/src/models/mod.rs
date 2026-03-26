pub mod actuation;
pub mod audit;
pub mod authority;
pub mod command;
pub mod error;
pub mod profile;
pub mod trace;
pub mod verdict;

#[cfg(test)]
mod tests {
    use super::error::Validate;
    use super::profile::{RobotProfile, SafeStopStrategy};

    #[test]
    fn deserialize_humanoid_profile() {
        let json = include_str!("../../../../profiles/humanoid_28dof.json");
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
        };
        assert!(matches!(
            profile.validate(),
            Err(ValidationError::DuplicateJointName { name }) if name == "elbow"
        ));
    }
}
