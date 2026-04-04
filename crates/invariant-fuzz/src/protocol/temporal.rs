//! PA6–PA8: Temporal, replay, and sequence attacks.
//!
//! These attacks manipulate timestamps, PCA expiry windows, and command
//! sequence numbers to probe the validator's temporal enforcement.

use chrono::{Duration, Utc};

use invariant_core::models::command::Command;

/// PA6: Temporal attacks on PCA chains.
///
/// Constructs commands with boundary timestamps relative to PCA expiry/not-before
/// windows. The validator must reject expired or not-yet-valid chains.
pub struct TemporalAttacker;

impl TemporalAttacker {
    /// Generate commands with various temporal anomalies.
    ///
    /// The returned tuples are `(attack_id, command, expected_reject)`.
    /// `expected_reject = true` means the validator should reject this command.
    pub fn temporal_attacks(base: &Command) -> Vec<(String, Command, bool)> {
        let mut results = Vec::new();

        // PA6: Command with timestamp far in the past (stale command).
        let mut cmd = base.clone();
        cmd.timestamp = Utc::now() - Duration::days(365);
        results.push(("PA6-stale-timestamp".into(), cmd, false)); // may or may not reject

        // PA6: Command with timestamp far in the future.
        let mut cmd = base.clone();
        cmd.timestamp = Utc::now() + Duration::days(365);
        results.push(("PA6-future-timestamp".into(), cmd, false));

        // PA8: Sequence number = 0.
        let mut cmd = base.clone();
        cmd.sequence = 0;
        results.push(("PA8-sequence-zero".into(), cmd, false));

        // PA8: Sequence number = MAX.
        let mut cmd = base.clone();
        cmd.sequence = u64::MAX;
        results.push(("PA8-sequence-max".into(), cmd, false));

        // PA8: Delta time = 0 (should fail P8).
        let mut cmd = base.clone();
        cmd.delta_time = 0.0;
        results.push(("PA8-delta-time-zero".into(), cmd, true));

        // PA8: Delta time negative (should fail P8).
        let mut cmd = base.clone();
        cmd.delta_time = -0.001;
        results.push(("PA8-delta-time-negative".into(), cmd, true));

        // PA8: Delta time way too large (should fail P8).
        let mut cmd = base.clone();
        cmd.delta_time = 1000.0;
        results.push(("PA8-delta-time-huge".into(), cmd, true));

        results
    }
}

/// PA7: Replay attacks.
///
/// Returns a pair of identical commands (simulating a replay). The second
/// submission of the same sequence number should be rejected if the validator
/// tracks sequences.
pub struct ReplayAttacker;

impl ReplayAttacker {
    /// Generate a replay pair: two commands identical except one may have an
    /// adjusted sequence number.
    pub fn replay_pair(base: &Command) -> Vec<(String, Command)> {
        let mut results = Vec::new();

        // Exact duplicate (same sequence).
        results.push(("PA7-exact-replay".into(), base.clone()));

        // Replay with decremented sequence.
        let mut cmd = base.clone();
        cmd.sequence = cmd.sequence.saturating_sub(1);
        results.push(("PA7-decremented-sequence".into(), cmd));

        results
    }
}

/// PA10: Contradictory commands (physics consistency).
///
/// Generates commands where position and velocity are physically contradictory
/// within the given delta_time.
pub struct ContradictoryAttacker;

impl ContradictoryAttacker {
    /// Generate commands with self-contradictory physics.
    pub fn contradictory_commands(base: &Command) -> Vec<(String, Command)> {
        let mut results = Vec::new();

        // Position at min but velocity pointing further negative.
        let mut cmd = base.clone();
        for js in &mut cmd.joint_states {
            js.position = -3.0; // near min limit
            js.velocity = -10.0; // negative velocity = going further past limit
        }
        results.push(("PA10-vel-past-limit".into(), cmd));

        // All joints at zero position, but impossibly high velocity.
        let mut cmd = base.clone();
        for js in &mut cmd.joint_states {
            js.position = 0.0;
            js.velocity = 999.0;
        }
        results.push(("PA10-impossible-velocity".into(), cmd));

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
            timestamp: Utc::now(),
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
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: std::collections::HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: std::collections::HashMap::new(),
            environment_state: None,
        }
    }

    #[test]
    fn temporal_attacks_generate_expected_count() {
        let attacks = TemporalAttacker::temporal_attacks(&base_command());
        assert_eq!(attacks.len(), 7);
    }

    #[test]
    fn delta_time_zero_is_marked_reject() {
        let attacks = TemporalAttacker::temporal_attacks(&base_command());
        let dt_zero = attacks
            .iter()
            .find(|(id, _, _)| id == "PA8-delta-time-zero");
        assert!(dt_zero.is_some());
        assert!(dt_zero.unwrap().2, "delta_time=0 should be expected-reject");
    }

    #[test]
    fn replay_pair_generates_two() {
        let pairs = ReplayAttacker::replay_pair(&base_command());
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn contradictory_generates_attacks() {
        let attacks = ContradictoryAttacker::contradictory_commands(&base_command());
        assert_eq!(attacks.len(), 2);
    }
}
