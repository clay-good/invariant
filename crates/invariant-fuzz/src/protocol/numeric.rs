//! PA3–PA4: NaN, Inf, and subnormal value injection.
//!
//! `NumericInjector` takes a base command and returns variants with pathological
//! floating-point values substituted into every numeric field.  The validator
//! must reject all of them (NaN/Inf positions would pass vacuous limit checks
//! in a naive implementation).

use invariant_core::models::command::Command;

/// Pathological floating-point values to inject (PA3–PA4).
const INJECTED_VALUES: &[f64] = &[
    f64::NAN,
    f64::INFINITY,
    f64::NEG_INFINITY,
    -0.0_f64,
    f64::MIN_POSITIVE / 2.0, // subnormal
];

/// Injects pathological floating-point values into command fields.
pub struct NumericInjector;

impl NumericInjector {
    /// Create a new `NumericInjector`.
    pub fn new() -> Self {
        Self
    }

    /// Return a set of commands derived from `base_command` where each numeric
    /// field has been replaced by a pathological value.
    ///
    /// For each injected value the following fields are probed independently:
    ///
    /// - `joint_states[i].position`  for every joint *i*
    /// - `joint_states[i].velocity`  for every joint *i*
    /// - `joint_states[i].effort`    for every joint *i*
    /// - `delta_time`
    ///
    /// The base command is cloned for each injection; all other fields are left
    /// unchanged so that the only difference between variants is the injected
    /// value.
    pub fn inject_all(base_command: &Command) -> Vec<Command> {
        let mut results = Vec::new();

        for &value in INJECTED_VALUES {
            // Inject into each joint's position, velocity, and effort.
            for joint_idx in 0..base_command.joint_states.len() {
                results.push(inject_joint_position(base_command, joint_idx, value));
                results.push(inject_joint_velocity(base_command, joint_idx, value));
                results.push(inject_joint_effort(base_command, joint_idx, value));
            }

            // Inject into delta_time.
            results.push(inject_delta_time(base_command, value));
        }

        results
    }
}

impl Default for NumericInjector {
    fn default() -> Self {
        Self::new()
    }
}

fn inject_joint_position(base: &Command, idx: usize, value: f64) -> Command {
    let mut cmd = base.clone();
    cmd.joint_states[idx].position = value;
    cmd
}

fn inject_joint_velocity(base: &Command, idx: usize, value: f64) -> Command {
    let mut cmd = base.clone();
    cmd.joint_states[idx].velocity = value;
    cmd
}

fn inject_joint_effort(base: &Command, idx: usize, value: f64) -> Command {
    let mut cmd = base.clone();
    cmd.joint_states[idx].effort = value;
    cmd
}

fn inject_delta_time(base: &Command, value: f64) -> Command {
    let mut cmd = base.clone();
    cmd.delta_time = value;
    cmd
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use invariant_core::models::command::{Command, CommandAuthority, JointState};

    fn base_command() -> Command {
        Command {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![
                JointState {
                    name: "j1".into(),
                    position: 0.0,
                    velocity: 0.0,
                    effort: 0.0,
                },
                JointState {
                    name: "j2".into(),
                    position: 0.1,
                    velocity: 0.1,
                    effort: 5.0,
                },
            ],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
        }
    }

    #[test]
    fn inject_all_count() {
        let base = base_command();
        // 2 joints * 3 fields * 5 values + 1 delta_time * 5 values = 35
        let injected = NumericInjector::inject_all(&base);
        assert_eq!(injected.len(), 35);
    }

    #[test]
    fn inject_all_contains_nan_in_position() {
        let base = base_command();
        let injected = NumericInjector::inject_all(&base);
        let has_nan = injected
            .iter()
            .any(|cmd| cmd.joint_states.iter().any(|js| js.position.is_nan()));
        assert!(has_nan, "should have at least one NaN position");
    }

    #[test]
    fn inject_all_contains_inf_in_position() {
        let base = base_command();
        let injected = NumericInjector::inject_all(&base);
        let has_inf = injected
            .iter()
            .any(|cmd| cmd.joint_states.iter().any(|js| js.position.is_infinite()));
        assert!(has_inf, "should have at least one Inf position");
    }

    #[test]
    fn inject_all_contains_nan_in_delta_time() {
        let base = base_command();
        let injected = NumericInjector::inject_all(&base);
        let has_nan_dt = injected.iter().any(|cmd| cmd.delta_time.is_nan());
        assert!(has_nan_dt, "should have at least one NaN delta_time");
    }

    #[test]
    fn inject_all_preserves_source() {
        let base = base_command();
        let injected = NumericInjector::inject_all(&base);
        for cmd in &injected {
            assert_eq!(cmd.source, "test");
        }
    }

    #[test]
    fn inject_all_no_commands_for_empty_joints() {
        let mut base = base_command();
        base.joint_states.clear();
        let injected = NumericInjector::inject_all(&base);
        // Only delta_time injections: 1 field * 5 values = 5
        assert_eq!(injected.len(), 5);
    }

    #[test]
    fn default_constructor_works() {
        let _injector = NumericInjector::default();
    }
}
