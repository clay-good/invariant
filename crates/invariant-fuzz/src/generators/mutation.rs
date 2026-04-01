//! Step 26: Mutation engine — valid-to-invalid command transformer.
//!
//! Takes a known-valid command and applies targeted mutations to produce
//! commands that should be rejected. Each mutation targets a specific check.

use invariant_core::models::command::Command;

/// Targeted mutation strategies for transforming valid commands into invalid ones.
pub struct MutationEngine;

/// A mutation result: the attack ID, the mutated command, and which check
/// category is expected to catch it.
pub struct Mutation {
    pub id: String,
    pub command: Command,
    pub target_check: &'static str,
}

impl MutationEngine {
    /// Apply all mutation strategies to a valid base command.
    ///
    /// Returns a vec of `Mutation` values, each targeting a specific physics or
    /// authority check.
    pub fn mutate_all(base: &Command) -> Vec<Mutation> {
        let mut results = Vec::new();

        // --- Joint position mutations ---
        // Flip sign on all positions.
        let mut cmd = base.clone();
        for js in &mut cmd.joint_states {
            js.position = -js.position - 100.0;
        }
        results.push(Mutation {
            id: "MUT-position-flip".into(),
            command: cmd,
            target_check: "joint_limits",
        });

        // Scale positions by 10x.
        let mut cmd = base.clone();
        for js in &mut cmd.joint_states {
            js.position *= 10.0;
        }
        results.push(Mutation {
            id: "MUT-position-10x".into(),
            command: cmd,
            target_check: "joint_limits",
        });

        // --- Velocity mutations ---
        // Set all velocities to max * 5.
        let mut cmd = base.clone();
        for js in &mut cmd.joint_states {
            js.velocity = 100.0;
        }
        results.push(Mutation {
            id: "MUT-velocity-overshoot".into(),
            command: cmd,
            target_check: "velocity_limits",
        });

        // Negative velocity (should be absolute-valued checked).
        let mut cmd = base.clone();
        for js in &mut cmd.joint_states {
            js.velocity = -100.0;
        }
        results.push(Mutation {
            id: "MUT-velocity-negative".into(),
            command: cmd,
            target_check: "velocity_limits",
        });

        // --- Torque mutations ---
        let mut cmd = base.clone();
        for js in &mut cmd.joint_states {
            js.effort = 9999.0;
        }
        results.push(Mutation {
            id: "MUT-torque-spike".into(),
            command: cmd,
            target_check: "torque_limits",
        });

        // --- Delta time mutations ---
        let mut cmd = base.clone();
        cmd.delta_time = 0.0;
        results.push(Mutation {
            id: "MUT-dt-zero".into(),
            command: cmd,
            target_check: "delta_time",
        });

        let mut cmd = base.clone();
        cmd.delta_time = -1.0;
        results.push(Mutation {
            id: "MUT-dt-negative".into(),
            command: cmd,
            target_check: "delta_time",
        });

        let mut cmd = base.clone();
        cmd.delta_time = 999.0;
        results.push(Mutation {
            id: "MUT-dt-huge".into(),
            command: cmd,
            target_check: "delta_time",
        });

        // --- NaN injection ---
        let mut cmd = base.clone();
        if let Some(js) = cmd.joint_states.first_mut() {
            js.position = f64::NAN;
        }
        results.push(Mutation {
            id: "MUT-nan-position".into(),
            command: cmd,
            target_check: "joint_limits",
        });

        let mut cmd = base.clone();
        cmd.delta_time = f64::NAN;
        results.push(Mutation {
            id: "MUT-nan-dt".into(),
            command: cmd,
            target_check: "delta_time",
        });

        // --- Authority strip ---
        let mut cmd = base.clone();
        cmd.authority.pca_chain = String::new();
        results.push(Mutation {
            id: "MUT-authority-strip".into(),
            command: cmd,
            target_check: "authority",
        });

        // --- Empty joints ---
        let mut cmd = base.clone();
        cmd.joint_states.clear();
        results.push(Mutation {
            id: "MUT-empty-joints".into(),
            command: cmd,
            target_check: "empty_joint_states",
        });

        results
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use invariant_core::models::command::{CommandAuthority, JointState};

    fn base_command() -> Command {
        Command {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: "valid_chain".into(),
                required_ops: vec![],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
        }
    }

    #[test]
    fn mutate_all_returns_expected_count() {
        let mutations = MutationEngine::mutate_all(&base_command());
        assert!(
            mutations.len() >= 12,
            "expected at least 12 mutations, got {}",
            mutations.len()
        );
    }

    #[test]
    fn each_mutation_has_id_and_target() {
        for m in MutationEngine::mutate_all(&base_command()) {
            assert!(!m.id.is_empty(), "mutation ID must not be empty");
            assert!(!m.target_check.is_empty(), "target check must not be empty");
        }
    }

    #[test]
    fn nan_mutation_produces_nan() {
        let mutations = MutationEngine::mutate_all(&base_command());
        let nan_mut = mutations
            .iter()
            .find(|m| m.id == "MUT-nan-position")
            .unwrap();
        assert!(
            nan_mut.command.joint_states[0].position.is_nan(),
            "NaN mutation should produce NaN position"
        );
    }

    #[test]
    fn authority_strip_clears_chain() {
        let mutations = MutationEngine::mutate_all(&base_command());
        let strip = mutations
            .iter()
            .find(|m| m.id == "MUT-authority-strip")
            .unwrap();
        assert!(
            strip.command.authority.pca_chain.is_empty(),
            "authority strip should clear pca_chain"
        );
    }
}
