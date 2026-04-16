// Heartbeat monitor and safe-stop trigger.
//
// Enforces the W1 invariant:
//   If no heartbeat from cognitive layer for >N ms, command safe-stop.
//
// The watchdog is deterministic — all time inputs are caller-supplied
// (monotonic millisecond timestamps). No threads, no I/O. The caller
// (CLI/server layer) is responsible for calling `check()` on a timer.

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use thiserror::Error;

use crate::actuator::build_signed_actuation_command;
use crate::models::actuation::SignedActuationCommand;
use crate::models::command::JointState;
use crate::models::profile::{SafeStopProfile, SafeStopStrategy};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by watchdog operations.
#[derive(Debug, Error, PartialEq)]
pub enum WatchdogError {
    /// The watchdog has already triggered; operator reset is required before resuming.
    #[error("watchdog already triggered — operator reset required")]
    AlreadyTriggered,

    /// Signing the safe-stop actuation command failed.
    #[error("failed to sign safe-stop command: {reason}")]
    SigningFailed {
        /// Human-readable reason for the signing failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The watchdog's operational state.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::watchdog::WatchdogState;
///
/// let state = WatchdogState::Armed;
/// assert_eq!(state, WatchdogState::Armed);
/// assert_ne!(state, WatchdogState::Triggered);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogState {
    /// Normal operation. Heartbeats are being received.
    Armed,
    /// Timeout expired. Safe-stop command has been issued.
    /// No further commands accepted until operator reset.
    Triggered,
}

// ---------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------

/// Heartbeat monitor that generates a signed safe-stop command when the
/// cognitive layer stops responding.
///
/// All time parameters are monotonic millisecond timestamps supplied by the
/// caller. The watchdog does no I/O and has no internal clock — the caller
/// drives it by calling `heartbeat()` and `check()` at appropriate intervals.
///
/// Once triggered, the watchdog is a one-way latch: only `reset()` (operator
/// action) can return it to `Armed` state.
pub struct Watchdog {
    timeout_ms: u64,
    safe_stop_profile: SafeStopProfile,
    signing_key: SigningKey,
    signer_kid: String,
    state: WatchdogState,
    last_heartbeat_ms: u64,
}

impl Watchdog {
    /// Create a new watchdog in `Armed` state.
    ///
    /// `now_ms` is the monotonic time at construction (establishes the first
    /// heartbeat baseline).
    ///
    /// `timeout_ms = 0` is a valid construction argument but has no practical
    /// use — the watchdog would trigger on the first `check()` call. Callers
    /// that treat 0 as "watchdog disabled" must gate on that value themselves
    /// and skip constructing a `Watchdog` entirely (see `serve.rs`).
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_core::watchdog::{Watchdog, WatchdogState};
    /// use invariant_robotics_core::models::profile::{SafeStopProfile, SafeStopStrategy};
    /// use ed25519_dalek::SigningKey;
    /// use std::collections::HashMap;
    ///
    /// let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    /// let safe_stop = SafeStopProfile {
    ///     strategy: SafeStopStrategy::ImmediateStop,
    ///     max_deceleration: 5.0,
    ///     target_joint_positions: HashMap::new(),
    /// };
    ///
    /// let wd = Watchdog::new(500, safe_stop, signing_key, "kid-1".to_string(), 0);
    /// assert_eq!(wd.state(), WatchdogState::Armed);
    /// assert_eq!(wd.timeout_ms(), 500);
    /// ```
    pub fn new(
        timeout_ms: u64,
        safe_stop_profile: SafeStopProfile,
        signing_key: SigningKey,
        signer_kid: String,
        now_ms: u64,
    ) -> Self {
        Self {
            timeout_ms,
            safe_stop_profile,
            signing_key,
            signer_kid,
            state: WatchdogState::Armed,
            last_heartbeat_ms: now_ms,
        }
    }

    /// Current watchdog state.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_core::watchdog::{Watchdog, WatchdogState};
    /// use invariant_robotics_core::models::profile::{SafeStopProfile, SafeStopStrategy};
    /// use ed25519_dalek::SigningKey;
    /// use std::collections::HashMap;
    ///
    /// let signing_key = SigningKey::from_bytes(&[4u8; 32]);
    /// let safe_stop = SafeStopProfile {
    ///     strategy: SafeStopStrategy::ImmediateStop,
    ///     max_deceleration: 5.0,
    ///     target_joint_positions: HashMap::new(),
    /// };
    /// let wd = Watchdog::new(500, safe_stop, signing_key, "kid".to_string(), 0);
    /// assert_eq!(wd.state(), WatchdogState::Armed);
    /// ```
    pub fn state(&self) -> WatchdogState {
        self.state
    }

    /// Configured timeout in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Record a heartbeat from the cognitive layer.
    ///
    /// Resets the watchdog timer. Returns an error if the watchdog has
    /// already been triggered (one-way transition — operator reset required).
    ///
    /// Non-monotonic timestamps (now_ms < last_heartbeat_ms) are silently
    /// ignored: the timer is not advanced backward, preventing a clock
    /// regression from artificially extending the deadline.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_core::watchdog::{Watchdog, WatchdogState};
    /// use invariant_robotics_core::models::profile::{SafeStopProfile, SafeStopStrategy};
    /// use ed25519_dalek::SigningKey;
    /// use std::collections::HashMap;
    /// use chrono::Utc;
    ///
    /// let signing_key = SigningKey::from_bytes(&[2u8; 32]);
    /// let safe_stop = SafeStopProfile {
    ///     strategy: SafeStopStrategy::ImmediateStop,
    ///     max_deceleration: 5.0,
    ///     target_joint_positions: HashMap::new(),
    /// };
    /// let mut wd = Watchdog::new(100, safe_stop, signing_key, "kid".to_string(), 0);
    ///
    /// // Heartbeat at t=50 resets the timer.
    /// wd.heartbeat(50).unwrap();
    ///
    /// // Checking at t=120 — only 70 ms since heartbeat — should NOT trigger.
    /// let result = wd.check(120, Utc::now()).unwrap();
    /// assert!(result.is_none());
    /// assert_eq!(wd.state(), WatchdogState::Armed);
    /// ```
    pub fn heartbeat(&mut self, now_ms: u64) -> Result<(), WatchdogError> {
        if self.state == WatchdogState::Triggered {
            return Err(WatchdogError::AlreadyTriggered);
        }
        self.last_heartbeat_ms = now_ms.max(self.last_heartbeat_ms);
        Ok(())
    }

    /// Check whether the heartbeat timeout has expired.
    ///
    /// If the timeout has elapsed and the watchdog is still armed, transitions
    /// to `Triggered` state and returns a signed safe-stop actuation command.
    ///
    /// If already triggered or not yet expired, returns `Ok(None)`.
    ///
    /// - `now_ms`: current monotonic time in milliseconds.
    /// - `now_utc`: wall-clock time for the actuation command timestamp.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_core::watchdog::{Watchdog, WatchdogState};
    /// use invariant_robotics_core::models::profile::{SafeStopProfile, SafeStopStrategy};
    /// use ed25519_dalek::SigningKey;
    /// use std::collections::HashMap;
    /// use chrono::Utc;
    ///
    /// let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    /// let safe_stop = SafeStopProfile {
    ///     strategy: SafeStopStrategy::ImmediateStop,
    ///     max_deceleration: 5.0,
    ///     target_joint_positions: HashMap::new(),
    /// };
    /// let mut wd = Watchdog::new(50, safe_stop, signing_key, "kid".to_string(), 0);
    ///
    /// // No timeout yet — returns None.
    /// let no_trigger = wd.check(30, Utc::now()).unwrap();
    /// assert!(no_trigger.is_none());
    ///
    /// // Timeout elapsed — returns a signed safe-stop command.
    /// let triggered = wd.check(60, Utc::now()).unwrap();
    /// assert!(triggered.is_some());
    /// assert_eq!(wd.state(), WatchdogState::Triggered);
    /// ```
    pub fn check(
        &mut self,
        now_ms: u64,
        now_utc: DateTime<Utc>,
    ) -> Result<Option<SignedActuationCommand>, WatchdogError> {
        if self.state == WatchdogState::Triggered {
            return Ok(None);
        }

        let elapsed = now_ms.saturating_sub(self.last_heartbeat_ms);
        if elapsed <= self.timeout_ms {
            return Ok(None);
        }

        // Timeout expired — trigger safe-stop (W1).
        self.state = WatchdogState::Triggered;

        let joint_states = build_safe_stop_joints(&self.safe_stop_profile);

        let cmd = build_signed_actuation_command(
            "watchdog:safe-stop",
            0,
            &joint_states,
            now_utc,
            &self.signing_key,
            &self.signer_kid,
        )
        .map_err(|e| WatchdogError::SigningFailed {
            reason: e.to_string(),
        })?;

        Ok(Some(cmd))
    }

    /// Operator reset: return to `Armed` state.
    ///
    /// This is the only way to recover from `Triggered` state. The operator
    /// must manually confirm it is safe to resume operations.
    ///
    /// Applies the same monotonicity guard as `heartbeat()`: if `now_ms` is
    /// less than the last heartbeat, the baseline is not regressed. This
    /// prevents a buggy caller from setting a stale baseline that would
    /// cause immediate re-trigger on the next `check()`.
    pub fn reset(&mut self, now_ms: u64) {
        self.state = WatchdogState::Armed;
        self.last_heartbeat_ms = now_ms.max(self.last_heartbeat_ms);
    }
}

// ---------------------------------------------------------------------------
// Safe-stop joint generation
// ---------------------------------------------------------------------------

/// Build JointState entries from the safe-stop profile's target positions.
///
/// For `ControlledCrouch` and `ParkPosition`, each target position becomes a
/// JointState with zero velocity and zero effort (decelerate to target).
/// For `ImmediateStop`, an empty joint list is returned (motor controller
/// holds current position with no further motion).
///
/// Joints are sorted by name for deterministic ordering (the profile's
/// `target_joint_positions` is a HashMap with non-deterministic iteration).
fn build_safe_stop_joints(profile: &SafeStopProfile) -> Vec<JointState> {
    match profile.strategy {
        SafeStopStrategy::ImmediateStop => vec![],
        SafeStopStrategy::ControlledCrouch | SafeStopStrategy::ParkPosition => {
            let mut joints: Vec<JointState> = profile
                .target_joint_positions
                .iter()
                .map(|(name, &position)| JointState {
                    name: name.clone(),
                    position,
                    velocity: 0.0,
                    effort: 0.0,
                })
                .collect();
            joints.sort_by(|a, b| a.name.cmp(&b.name));
            joints
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::crypto::generate_keypair;
    use crate::models::profile::SafeStopStrategy;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::Utc;
    use ed25519_dalek::Verifier;
    use rand::rngs::OsRng;
    use serde::Serialize;
    use std::collections::HashMap;

    fn make_signing_key() -> SigningKey {
        generate_keypair(&mut OsRng)
    }

    fn default_safe_stop() -> SafeStopProfile {
        let mut targets = HashMap::new();
        targets.insert("left_hip".into(), -0.5);
        targets.insert("right_hip".into(), -0.5);
        targets.insert("left_knee".into(), 1.0);
        targets.insert("right_knee".into(), 1.0);
        SafeStopProfile {
            strategy: SafeStopStrategy::ControlledCrouch,
            max_deceleration: 5.0,
            target_joint_positions: targets,
        }
    }

    fn make_watchdog(timeout_ms: u64, now_ms: u64) -> Watchdog {
        Watchdog::new(
            timeout_ms,
            default_safe_stop(),
            make_signing_key(),
            "watchdog-kid".into(),
            now_ms,
        )
    }

    // -----------------------------------------------------------------------
    // Construction and state
    // -----------------------------------------------------------------------

    #[test]
    fn new_watchdog_is_armed() {
        let wd = make_watchdog(50, 0);
        assert_eq!(wd.state(), WatchdogState::Armed);
        assert_eq!(wd.timeout_ms(), 50);
    }

    // -----------------------------------------------------------------------
    // Heartbeat
    // -----------------------------------------------------------------------

    #[test]
    fn heartbeat_resets_timer() {
        let mut wd = make_watchdog(50, 0);

        // Heartbeat at t=30 resets timer.
        wd.heartbeat(30).unwrap();

        // Check at t=60 — only 30ms since last heartbeat, should NOT trigger.
        let result = wd.check(60, Utc::now()).unwrap();
        assert!(result.is_none());
        assert_eq!(wd.state(), WatchdogState::Armed);
    }

    #[test]
    fn heartbeat_rejected_after_trigger() {
        let mut wd = make_watchdog(50, 0);

        // Force trigger by checking after timeout.
        let cmd = wd.check(100, Utc::now()).unwrap();
        assert!(cmd.is_some());
        assert_eq!(wd.state(), WatchdogState::Triggered);

        // Heartbeat must fail.
        let err = wd.heartbeat(100).unwrap_err();
        assert_eq!(err, WatchdogError::AlreadyTriggered);
    }

    // -----------------------------------------------------------------------
    // Timeout and trigger
    // -----------------------------------------------------------------------

    #[test]
    fn no_trigger_within_timeout() {
        let mut wd = make_watchdog(50, 0);

        // Check at exactly the timeout boundary — should NOT trigger.
        let result = wd.check(50, Utc::now()).unwrap();
        assert!(result.is_none());
        assert_eq!(wd.state(), WatchdogState::Armed);
    }

    #[test]
    fn triggers_after_timeout_expires() {
        let mut wd = make_watchdog(50, 0);

        // Check at t=51 — 51ms since last heartbeat, exceeds 50ms timeout.
        let result = wd.check(51, Utc::now()).unwrap();
        assert!(result.is_some());
        assert_eq!(wd.state(), WatchdogState::Triggered);
    }

    #[test]
    fn second_check_after_trigger_returns_none() {
        let mut wd = make_watchdog(50, 0);

        let first = wd.check(100, Utc::now()).unwrap();
        assert!(first.is_some());

        // Subsequent checks return None (already triggered).
        let second = wd.check(200, Utc::now()).unwrap();
        assert!(second.is_none());
    }

    // -----------------------------------------------------------------------
    // Operator reset
    // -----------------------------------------------------------------------

    #[test]
    fn reset_returns_to_armed() {
        let mut wd = make_watchdog(50, 0);

        // Trigger.
        wd.check(100, Utc::now()).unwrap();
        assert_eq!(wd.state(), WatchdogState::Triggered);

        // Operator reset.
        wd.reset(200);
        assert_eq!(wd.state(), WatchdogState::Armed);

        // Heartbeat should work again.
        wd.heartbeat(210).unwrap();
        assert_eq!(wd.state(), WatchdogState::Armed);
    }

    #[test]
    fn reset_establishes_new_baseline() {
        let mut wd = make_watchdog(50, 0);

        // Trigger and reset at t=200.
        wd.check(100, Utc::now()).unwrap();
        wd.reset(200);

        // Check at t=230 — only 30ms since reset, should NOT trigger.
        let result = wd.check(230, Utc::now()).unwrap();
        assert!(result.is_none());
        assert_eq!(wd.state(), WatchdogState::Armed);

        // Check at t=260 — 60ms since reset, SHOULD trigger.
        let result = wd.check(260, Utc::now()).unwrap();
        assert!(result.is_some());
        assert_eq!(wd.state(), WatchdogState::Triggered);
    }

    // -----------------------------------------------------------------------
    // Safe-stop command correctness
    // -----------------------------------------------------------------------

    #[test]
    fn safe_stop_command_has_watchdog_hash() {
        let mut wd = make_watchdog(50, 0);
        let cmd = wd.check(100, Utc::now()).unwrap().unwrap();
        assert_eq!(cmd.command_hash, "watchdog:safe-stop");
    }

    #[test]
    fn safe_stop_command_signature_is_valid() {
        let sk = make_signing_key();
        let vk = sk.verifying_key();

        let mut wd = Watchdog::new(50, default_safe_stop(), sk, "test-kid".into(), 0);

        let now_utc = Utc::now();
        let cmd = wd.check(100, now_utc).unwrap().unwrap();

        // Reconstruct the payload the actuator would have signed.
        #[derive(Serialize)]
        struct ActuationPayload<'a> {
            command_hash: &'a str,
            command_sequence: u64,
            joint_states: &'a [JointState],
            timestamp: DateTime<Utc>,
            signer_kid: &'a str,
        }

        let payload = ActuationPayload {
            command_hash: &cmd.command_hash,
            command_sequence: cmd.command_sequence,
            joint_states: &cmd.joint_states,
            timestamp: cmd.timestamp,
            signer_kid: &cmd.signer_kid,
        };
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let sig_bytes = STANDARD.decode(&cmd.actuation_signature).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();

        assert!(vk.verify(&payload_json, &signature).is_ok());
    }

    #[test]
    fn controlled_crouch_generates_sorted_joints() {
        let mut wd = make_watchdog(50, 0);
        let cmd = wd.check(100, Utc::now()).unwrap().unwrap();

        // Should have 4 joints, sorted alphabetically.
        assert_eq!(cmd.joint_states.len(), 4);
        assert_eq!(cmd.joint_states[0].name, "left_hip");
        assert_eq!(cmd.joint_states[1].name, "left_knee");
        assert_eq!(cmd.joint_states[2].name, "right_hip");
        assert_eq!(cmd.joint_states[3].name, "right_knee");

        // All velocities and efforts should be zero.
        for js in &cmd.joint_states {
            assert_eq!(js.velocity, 0.0);
            assert_eq!(js.effort, 0.0);
        }

        // Check target positions match profile.
        assert_eq!(cmd.joint_states[0].position, -0.5); // left_hip
        assert_eq!(cmd.joint_states[1].position, 1.0); // left_knee
        assert_eq!(cmd.joint_states[2].position, -0.5); // right_hip
        assert_eq!(cmd.joint_states[3].position, 1.0); // right_knee
    }

    #[test]
    fn immediate_stop_generates_empty_joints() {
        let profile = SafeStopProfile {
            strategy: SafeStopStrategy::ImmediateStop,
            max_deceleration: 10.0,
            target_joint_positions: HashMap::new(),
        };

        let mut wd = Watchdog::new(50, profile, make_signing_key(), "kid".into(), 0);

        let cmd = wd.check(100, Utc::now()).unwrap().unwrap();
        assert!(cmd.joint_states.is_empty());
    }

    // -----------------------------------------------------------------------
    // Finding 19: clock regression (now_ms < last_heartbeat_ms)
    // -----------------------------------------------------------------------

    #[test]
    fn check_with_clock_regression_does_not_trigger() {
        // The watchdog uses saturating_sub to compute elapsed time.
        // If the caller supplies now_ms < last_heartbeat_ms (e.g. due to a
        // monotonic clock reset or a test misconfiguration), saturating_sub
        // clamps the elapsed time to 0, which is <= any timeout.
        // Defined behavior: the watchdog remains Armed and returns None.
        // This prevents a spurious safe-stop on clock regression.
        let mut wd = make_watchdog(50, /*now_ms=*/ 100);

        // Simulate a clock regression: check at t=50, which is before the
        // heartbeat baseline of t=100.
        let result = wd.check(50, Utc::now()).unwrap();
        assert!(
            result.is_none(),
            "clock regression must not trigger the watchdog"
        );
        assert_eq!(
            wd.state(),
            WatchdogState::Armed,
            "watchdog must remain Armed after clock regression"
        );
    }

    // -----------------------------------------------------------------------
    // Finding 49 + 75: timeout_ms=0 triggers on first check() call
    // -----------------------------------------------------------------------

    #[test]
    fn timeout_zero_triggers_on_first_check() {
        // timeout_ms=0 is a valid construction argument (not rejected at the
        // library level) but has no practical use: elapsed = now_ms - 0 = any
        // positive value, which is immediately > 0, so check() fires on the
        // very first call.
        //
        // Callers that want "watchdog disabled" semantics must gate on
        // timeout_ms=0 themselves and skip constructing a Watchdog entirely
        // (see serve.rs). The library does not validate this because the
        // caller context determines whether 0 is a programming error.
        let mut wd = make_watchdog(0, 0);
        assert_eq!(wd.state(), WatchdogState::Armed);

        // Even at now_ms=0 (no elapsed time), elapsed = 0, which is NOT > 0
        // (the check is strict: elapsed > timeout_ms), so the watchdog does
        // NOT trigger at exactly t=0 with timeout_ms=0.
        let result = wd.check(0, Utc::now()).unwrap();
        assert!(
            result.is_none(),
            "at t=0 with timeout_ms=0 elapsed==0 which is NOT > 0, so no trigger"
        );
        assert_eq!(wd.state(), WatchdogState::Armed);

        // At t=1 (elapsed=1 > timeout_ms=0), it must trigger.
        let result = wd.check(1, Utc::now()).unwrap();
        assert!(
            result.is_some(),
            "timeout_ms=0 must trigger on first check with now_ms=1 (elapsed=1 > 0)"
        );
        assert_eq!(wd.state(), WatchdogState::Triggered);
    }

    #[test]
    fn park_position_uses_target_joints() {
        let mut targets = HashMap::new();
        targets.insert("j1".into(), 0.0);
        targets.insert("j2".into(), 1.5);

        let profile = SafeStopProfile {
            strategy: SafeStopStrategy::ParkPosition,
            max_deceleration: 3.0,
            target_joint_positions: targets,
        };

        let mut wd = Watchdog::new(100, profile, make_signing_key(), "kid".into(), 0);

        let cmd = wd.check(200, Utc::now()).unwrap().unwrap();
        assert_eq!(cmd.joint_states.len(), 2);
        assert_eq!(cmd.joint_states[0].name, "j1");
        assert_eq!(cmd.joint_states[0].position, 0.0);
        assert_eq!(cmd.joint_states[1].name, "j2");
        assert_eq!(cmd.joint_states[1].position, 1.5);
    }

    // ── Watchdog edge case tests ────────────────────────────

    #[test]
    fn latch_is_truly_one_way_heartbeat_cannot_clear() {
        // The safe-stop latch must be one-way: once Triggered, heartbeat()
        // must return AlreadyTriggered and state must remain Triggered.
        let mut wd = make_watchdog(50, 0);
        wd.check(100, Utc::now()).unwrap(); // trigger
        assert_eq!(wd.state(), WatchdogState::Triggered);

        // Multiple heartbeat attempts must all fail.
        for t in [100, 200, 300, u64::MAX] {
            assert_eq!(wd.heartbeat(t), Err(WatchdogError::AlreadyTriggered));
            assert_eq!(wd.state(), WatchdogState::Triggered);
        }
    }

    #[test]
    fn reset_with_stale_timestamp_does_not_regress_baseline() {
        let mut wd = make_watchdog(50, 0);

        // Heartbeat at t=200 establishes a baseline.
        wd.heartbeat(200).unwrap();

        // Trigger at t=300.
        wd.check(300, Utc::now()).unwrap();
        assert_eq!(wd.state(), WatchdogState::Triggered);

        // Reset with stale timestamp t=100 (before the last heartbeat).
        // The monotonicity guard must keep the baseline at 200, not 100.
        wd.reset(100);
        assert_eq!(wd.state(), WatchdogState::Armed);

        // Check at t=210: only 10ms since baseline(200), should NOT trigger.
        let result = wd.check(210, Utc::now()).unwrap();
        assert!(
            result.is_none(),
            "stale reset must not regress baseline — should NOT trigger at t=210"
        );
    }

    #[test]
    fn heartbeat_with_backwards_timestamp_does_not_regress() {
        let mut wd = make_watchdog(50, 0);

        // Heartbeat at t=100, then at t=50 (backwards clock).
        wd.heartbeat(100).unwrap();
        wd.heartbeat(50).unwrap(); // should be silently ignored

        // Check at t=120: only 20ms since last real heartbeat(100).
        let result = wd.check(120, Utc::now()).unwrap();
        assert!(
            result.is_none(),
            "backwards heartbeat must not regress timer"
        );
    }

    #[test]
    fn large_timeout_no_overflow() {
        // u64::MAX timeout should not cause overflow in check().
        let mut wd = make_watchdog(u64::MAX, 0);
        wd.heartbeat(1000).unwrap();

        // saturating_sub(1000, 1000) = 0, which is <= u64::MAX. No trigger.
        let result = wd.check(1000, Utc::now()).unwrap();
        assert!(result.is_none());
        assert_eq!(wd.state(), WatchdogState::Armed);
    }

    #[test]
    fn check_with_backwards_clock_does_not_false_trigger() {
        // If the check clock goes backwards (now_ms < last_heartbeat_ms),
        // saturating_sub returns 0, which is <= timeout. The watchdog must
        // NOT false-trigger — backwards clocks are a timing anomaly, not a
        // missed heartbeat.
        let mut wd = make_watchdog(50, 0);
        wd.heartbeat(200).unwrap();

        // Check at t=100 — earlier than the heartbeat at t=200.
        let result = wd.check(100, Utc::now()).unwrap();
        assert!(
            result.is_none(),
            "backwards check clock must NOT trigger watchdog"
        );
        assert_eq!(wd.state(), WatchdogState::Armed);
    }

    #[test]
    fn check_at_exact_heartbeat_time_does_not_trigger() {
        // Elapsed = 0 when check time == heartbeat time. Must not trigger.
        let mut wd = make_watchdog(50, 0);
        wd.heartbeat(100).unwrap();

        let result = wd.check(100, Utc::now()).unwrap();
        assert!(
            result.is_none(),
            "check at exact heartbeat time (elapsed=0) must not trigger"
        );
        assert_eq!(wd.state(), WatchdogState::Armed);
    }

    #[test]
    fn safe_stop_command_has_sentinel_hash_not_content_hash() {
        // Documents that the watchdog uses a sentinel string "watchdog:safe-stop"
        // as command_hash, not a SHA-256 of the payload. This is intentional:
        // the motor controller identifies watchdog-originated commands by this
        // sentinel.
        let mut wd = make_watchdog(50, 0);
        let cmd = wd.check(100, Utc::now()).unwrap().unwrap();
        assert_eq!(cmd.command_hash, "watchdog:safe-stop");
        assert!(!cmd.command_hash.starts_with("sha256:"));
    }
}
