// Heartbeat monitor and safe-stop trigger.
//
// Implements the W1 invariant: if no heartbeat from the cognitive layer for
// >N ms (from the robot profile's `watchdog_timeout_ms`), command a safe-stop.
//
// Design notes:
// - NOT thread-safe by design — called from the validation hot path.
// - Safe-stop is a one-way transition until operator explicitly resets (CE7).
// - The `check()` method must be called regularly; no background thread.
// - All state transitions are explicit and deterministic.
// - `_at` variants accept an injected `Instant` for deterministic testing.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use thiserror::Error;

use crate::actuator::build_signed_actuation_command;
use crate::models::actuation::SignedActuationCommand;
use crate::models::command::JointState;
use crate::models::profile::SafeStopProfile;
use crate::validator::ValidatorError;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq)]
pub enum WatchdogError {
    #[error("watchdog is not in SafeStopTriggered state; cannot reset")]
    NotTriggered,

    #[error("watchdog is already active; cannot reset")]
    AlreadyActive,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The current operational state of the watchdog.
///
/// Safe-stop is a **one-way transition** until operator manually resets (CE7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchdogState {
    /// Heartbeats are being received within the configured timeout.
    Active,
    /// Timeout elapsed — safe-stop has been commanded. No further heartbeats
    /// are accepted until an operator explicitly resets.
    SafeStopTriggered,
    /// Operator has manually reset after a safe-stop. The watchdog returns to
    /// `Active` on the next call to `reset()`.
    ManuallyReset,
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Returned by `check()` / `check_at()`.
#[derive(Debug, Clone)]
pub enum WatchdogStatus {
    /// Heartbeat is within timeout; all clear.
    Ok,
    /// Timeout just expired. The caller must issue a safe-stop command using
    /// the enclosed profile.
    SafeStopRequired {
        safe_stop_profile: SafeStopProfile,
    },
    /// Watchdog already triggered; safe-stop was already commanded.
    AlreadyTriggered,
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for a `Watchdog` instance.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// How long to wait for a heartbeat before triggering safe-stop.
    pub timeout: Duration,
    /// What to do when safe-stop triggers.
    pub safe_stop_profile: SafeStopProfile,
}

// ---------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------

/// Heartbeat monitor that enforces the W1 invariant.
///
/// Call `heartbeat()` whenever a valid command is received from the cognitive
/// layer. Call `check()` on every validation cycle; it returns
/// `WatchdogStatus::SafeStopRequired` the first time the timeout is exceeded.
pub struct Watchdog {
    config: WatchdogConfig,
    state: WatchdogState,
    last_heartbeat: Instant,
    trigger_count: u64,
}

impl Watchdog {
    /// Create a new watchdog in `Active` state. `last_heartbeat` is set to
    /// `Instant::now()`.
    pub fn new(config: WatchdogConfig) -> Self {
        Self::new_with_instant(config, Instant::now())
    }

    /// Create a new watchdog with an injected starting instant. Used for
    /// deterministic testing.
    pub fn new_with_instant(config: WatchdogConfig, now: Instant) -> Self {
        Self {
            config,
            state: WatchdogState::Active,
            last_heartbeat: now,
            trigger_count: 0,
        }
    }

    /// Record a heartbeat at `Instant::now()`.
    ///
    /// If the watchdog has already triggered, this is a no-op (CE7 defense —
    /// the cognitive layer cannot talk its way out of a triggered safe-stop).
    pub fn heartbeat(&mut self) {
        self.heartbeat_at(Instant::now());
    }

    /// Record a heartbeat at the given instant. Injected for testing.
    pub fn heartbeat_at(&mut self, now: Instant) {
        if self.state == WatchdogState::Active {
            self.last_heartbeat = now;
        }
        // In SafeStopTriggered or ManuallyReset: no-op (one-way transition).
    }

    /// Check whether the watchdog timeout has expired.
    ///
    /// Returns:
    /// - `WatchdogStatus::Ok` — heartbeat is within timeout.
    /// - `WatchdogStatus::SafeStopRequired` — timeout just exceeded; also
    ///   transitions state to `SafeStopTriggered` and increments `trigger_count`.
    /// - `WatchdogStatus::AlreadyTriggered` — already in safe-stop state.
    pub fn check(&mut self) -> WatchdogStatus {
        self.check_at(Instant::now())
    }

    /// Check at the given instant. Injected for testing.
    pub fn check_at(&mut self, now: Instant) -> WatchdogStatus {
        match self.state {
            WatchdogState::Active => {
                let elapsed = now.saturating_duration_since(self.last_heartbeat);
                if elapsed > self.config.timeout {
                    self.state = WatchdogState::SafeStopTriggered;
                    self.trigger_count += 1;
                    WatchdogStatus::SafeStopRequired {
                        safe_stop_profile: self.config.safe_stop_profile.clone(),
                    }
                } else {
                    WatchdogStatus::Ok
                }
            }
            WatchdogState::SafeStopTriggered | WatchdogState::ManuallyReset => {
                WatchdogStatus::AlreadyTriggered
            }
        }
    }

    /// Operator-initiated reset after a safe-stop.
    ///
    /// Only valid when the watchdog is in `SafeStopTriggered` state. Returns
    /// an error if already active or in `ManuallyReset`.
    pub fn reset(&mut self) -> Result<(), WatchdogError> {
        self.reset_at(Instant::now())
    }

    /// Reset with an injected instant. Used for testing.
    pub fn reset_at(&mut self, now: Instant) -> Result<(), WatchdogError> {
        match self.state {
            WatchdogState::Active => Err(WatchdogError::AlreadyActive),
            WatchdogState::ManuallyReset => Err(WatchdogError::AlreadyActive),
            WatchdogState::SafeStopTriggered => {
                self.state = WatchdogState::Active;
                self.last_heartbeat = now;
                Ok(())
            }
        }
    }

    /// Current state of the watchdog.
    pub fn state(&self) -> &WatchdogState {
        &self.state
    }

    /// Number of times the watchdog has triggered (for audit).
    pub fn trigger_count(&self) -> u64 {
        self.trigger_count
    }

    /// How much time remains before the watchdog triggers.
    ///
    /// Returns `None` if not in `Active` state.
    pub fn time_remaining(&self) -> Option<Duration> {
        self.time_remaining_at(Instant::now())
    }

    /// How much time remains as of the given instant.
    ///
    /// Returns `None` if not in `Active` state.
    pub fn time_remaining_at(&self, now: Instant) -> Option<Duration> {
        if self.state != WatchdogState::Active {
            return None;
        }
        let elapsed = now.saturating_duration_since(self.last_heartbeat);
        Some(self.config.timeout.saturating_sub(elapsed))
    }
}

// ---------------------------------------------------------------------------
// Safe-stop command builder
// ---------------------------------------------------------------------------

/// Build a signed safe-stop actuation command from a `SafeStopProfile`.
///
/// The resulting `SignedActuationCommand` uses the sentinel
/// `command_hash = "safe-stop:watchdog"` to distinguish it from normal
/// validated commands. `sequence` should be set to the watchdog's current
/// `trigger_count` so the motor controller can detect duplicates.
pub fn build_safe_stop_command(
    safe_stop_profile: &SafeStopProfile,
    sequence: u64,
    signing_key: &SigningKey,
    signer_kid: &str,
    timestamp: DateTime<Utc>,
) -> Result<SignedActuationCommand, ValidatorError> {
    // Convert HashMap<String, f64> to Vec<JointState> with velocity=0 and effort=0.
    // Sort by joint name for determinism.
    let mut joint_states: Vec<JointState> = safe_stop_profile
        .target_joint_positions
        .iter()
        .map(|(name, &position)| JointState {
            name: name.clone(),
            position,
            velocity: 0.0,
            effort: 0.0,
        })
        .collect();
    joint_states.sort_by(|a, b| a.name.cmp(&b.name));

    build_signed_actuation_command(
        "safe-stop:watchdog",
        sequence,
        &joint_states,
        timestamp,
        signing_key,
        signer_kid,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::authority::crypto::generate_keypair;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::Utc;
    use ed25519_dalek::Verifier;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn make_config(timeout_ms: u64) -> WatchdogConfig {
        WatchdogConfig {
            timeout: Duration::from_millis(timeout_ms),
            safe_stop_profile: SafeStopProfile::default(),
        }
    }

    fn make_config_with_joints(timeout_ms: u64) -> WatchdogConfig {
        let mut positions = HashMap::new();
        positions.insert("j1".to_string(), 0.5);
        positions.insert("j2".to_string(), -0.5);
        WatchdogConfig {
            timeout: Duration::from_millis(timeout_ms),
            safe_stop_profile: SafeStopProfile {
                strategy: crate::models::profile::SafeStopStrategy::ParkPosition,
                max_deceleration: 5.0,
                target_joint_positions: positions,
            },
        }
    }

    // -----------------------------------------------------------------------
    // 1. Initial state
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_watchdog_is_active() {
        let wd = Watchdog::new(make_config(100));
        assert_eq!(wd.state(), &WatchdogState::Active);
        assert_eq!(wd.trigger_count(), 0);
    }

    // -----------------------------------------------------------------------
    // 2. Heartbeat resets timer
    // -----------------------------------------------------------------------

    #[test]
    fn test_heartbeat_resets_timer() {
        let t0 = Instant::now();
        let mut wd = Watchdog::new_with_instant(make_config(100), t0);

        // Advance 80 ms (within timeout).
        let t1 = t0 + Duration::from_millis(80);
        // Heartbeat at t1.
        wd.heartbeat_at(t1);

        // Check at t1 + 80 ms = 160 ms from t0, but only 80 ms from last heartbeat.
        let t2 = t1 + Duration::from_millis(80);
        match wd.check_at(t2) {
            WatchdogStatus::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // 3. Timeout triggers safe-stop
    // -----------------------------------------------------------------------

    #[test]
    fn test_timeout_triggers_safe_stop() {
        let t0 = Instant::now();
        let mut wd = Watchdog::new_with_instant(make_config(100), t0);

        // Advance past timeout.
        let t1 = t0 + Duration::from_millis(101);
        match wd.check_at(t1) {
            WatchdogStatus::SafeStopRequired { .. } => {}
            other => panic!("expected SafeStopRequired, got {other:?}"),
        }
        assert_eq!(wd.state(), &WatchdogState::SafeStopTriggered);
        assert_eq!(wd.trigger_count(), 1);
    }

    // -----------------------------------------------------------------------
    // 4. Safe-stop is one-way — heartbeat after trigger is no-op
    // -----------------------------------------------------------------------

    #[test]
    fn test_safe_stop_is_one_way() {
        let t0 = Instant::now();
        let mut wd = Watchdog::new_with_instant(make_config(100), t0);

        // Trigger.
        let t1 = t0 + Duration::from_millis(101);
        wd.check_at(t1);

        // Heartbeat is ignored.
        wd.heartbeat_at(t1 + Duration::from_millis(1));

        // Still triggered.
        match wd.check_at(t1 + Duration::from_millis(2)) {
            WatchdogStatus::AlreadyTriggered => {}
            other => panic!("expected AlreadyTriggered, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // 5. Manual reset
    // -----------------------------------------------------------------------

    #[test]
    fn test_manual_reset() {
        let t0 = Instant::now();
        let mut wd = Watchdog::new_with_instant(make_config(100), t0);

        // Trigger.
        let t1 = t0 + Duration::from_millis(101);
        wd.check_at(t1);
        assert_eq!(wd.state(), &WatchdogState::SafeStopTriggered);

        // Operator resets.
        let t2 = t1 + Duration::from_millis(10);
        wd.reset_at(t2).expect("reset should succeed");
        assert_eq!(wd.state(), &WatchdogState::Active);

        // Now a check within timeout should be Ok.
        let t3 = t2 + Duration::from_millis(50);
        match wd.check_at(t3) {
            WatchdogStatus::Ok => {}
            other => panic!("expected Ok after reset, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // 6. Reset when active returns AlreadyActive
    // -----------------------------------------------------------------------

    #[test]
    fn test_reset_when_active_is_noop() {
        let mut wd = Watchdog::new(make_config(100));
        let err = wd.reset().expect_err("should error when active");
        assert_eq!(err, WatchdogError::AlreadyActive);
        assert_eq!(wd.state(), &WatchdogState::Active);
    }

    // -----------------------------------------------------------------------
    // 7. Trigger count increments
    // -----------------------------------------------------------------------

    #[test]
    fn test_trigger_count_increments() {
        let t0 = Instant::now();
        let mut wd = Watchdog::new_with_instant(make_config(100), t0);

        // First trigger.
        wd.check_at(t0 + Duration::from_millis(101));
        assert_eq!(wd.trigger_count(), 1);

        // Reset and re-trigger.
        let t1 = t0 + Duration::from_millis(200);
        wd.reset_at(t1).unwrap();
        wd.check_at(t1 + Duration::from_millis(101));
        assert_eq!(wd.trigger_count(), 2);
    }

    // -----------------------------------------------------------------------
    // 8. time_remaining returns correct value
    // -----------------------------------------------------------------------

    #[test]
    fn test_time_remaining() {
        let t0 = Instant::now();
        let wd = Watchdog::new_with_instant(make_config(100), t0);

        let t1 = t0 + Duration::from_millis(40);
        let remaining = wd.time_remaining_at(t1).expect("should be Some when active");

        // Should be approximately 60 ms remaining (100 - 40).
        assert_eq!(remaining, Duration::from_millis(60));
    }

    // -----------------------------------------------------------------------
    // 9. time_remaining is None when triggered
    // -----------------------------------------------------------------------

    #[test]
    fn test_time_remaining_none_when_triggered() {
        let t0 = Instant::now();
        let mut wd = Watchdog::new_with_instant(make_config(100), t0);

        wd.check_at(t0 + Duration::from_millis(101));
        assert!(wd.time_remaining_at(t0 + Duration::from_millis(102)).is_none());
    }

    // -----------------------------------------------------------------------
    // 10. build_safe_stop_command fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_safe_stop_command() {
        let sk = generate_keypair(&mut OsRng);
        let cfg = make_config_with_joints(100);
        let now = Utc::now();

        let cmd = build_safe_stop_command(&cfg.safe_stop_profile, 1, &sk, "watchdog-key", now)
            .expect("build_safe_stop_command should succeed");

        assert_eq!(cmd.command_hash, "safe-stop:watchdog");
        assert_eq!(cmd.command_sequence, 1);
        assert_eq!(cmd.signer_kid, "watchdog-key");
        assert_eq!(cmd.timestamp, now);

        // Two joint states with velocity=0 and effort=0, sorted by name.
        assert_eq!(cmd.joint_states.len(), 2);
        assert_eq!(cmd.joint_states[0].name, "j1");
        assert_eq!(cmd.joint_states[0].position, 0.5);
        assert_eq!(cmd.joint_states[0].velocity, 0.0);
        assert_eq!(cmd.joint_states[0].effort, 0.0);
        assert_eq!(cmd.joint_states[1].name, "j2");
        assert_eq!(cmd.joint_states[1].position, -0.5);
    }

    // -----------------------------------------------------------------------
    // 11. build_safe_stop_command signature verifiable
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_safe_stop_command_signature_verifiable() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        let cfg = make_config_with_joints(100);
        let now = Utc::now();

        let cmd = build_safe_stop_command(&cfg.safe_stop_profile, 7, &sk, "wd-key", now)
            .expect("build should succeed");

        // Reconstruct the payload the same way actuator.rs does internally.
        // We verify via the actuator's own signing contract: re-sign the same
        // payload with a known good key and confirm signatures match.
        //
        // A cleaner approach: rebuild the payload and verify the raw signature.
        #[derive(serde::Serialize)]
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

    // -----------------------------------------------------------------------
    // 12. Check just before timeout returns Ok
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_just_before_timeout() {
        let t0 = Instant::now();
        let mut wd = Watchdog::new_with_instant(make_config(100), t0);

        // Exactly timeout - 1 ns: should be within timeout (elapsed == 99_999_999 ns).
        let t1 = t0 + Duration::from_nanos(99_999_999);
        match wd.check_at(t1) {
            WatchdogStatus::Ok => {}
            other => panic!("expected Ok at timeout-1ns, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // 13. Check at exactly timeout duration returns Ok (must exceed, not equal)
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_at_exact_timeout() {
        let t0 = Instant::now();
        let mut wd = Watchdog::new_with_instant(make_config(100), t0);

        // Elapsed == timeout exactly: should NOT trigger (must be strictly greater).
        let t1 = t0 + Duration::from_millis(100);
        match wd.check_at(t1) {
            WatchdogStatus::Ok => {}
            other => panic!("expected Ok at exact timeout, got {other:?}"),
        }
    }
}
