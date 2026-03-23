pub mod error;
pub mod profile;
pub mod command;
pub mod verdict;
pub mod authority;
pub mod audit;
pub mod trace;
pub mod actuation;

#[cfg(test)]
mod tests {
    use super::profile::{RobotProfile, SafeStopStrategy};
    use super::error::Validate;

    #[test]
    fn deserialize_humanoid_profile() {
        let json = include_str!("../../../../profiles/humanoid_28dof.json");
        let profile: RobotProfile = serde_json::from_str(json).expect("deserialize humanoid profile");
        assert_eq!(profile.name, "humanoid_28dof");
        assert_eq!(profile.joints.len(), 28);
        assert_eq!(profile.safe_stop_profile.strategy, SafeStopStrategy::ControlledCrouch);
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

        let zero_vel = JointDefinition { max_velocity: 0.0, ..bad.clone() };
        // first error is inverted limits, so fix those first
        let ok = JointDefinition { min: -1.0, max: 1.0, max_velocity: 0.0, ..bad };
        assert!(ok.validate().is_err()); // zero velocity
        let _ = zero_vel; // suppress unused
    }
}
