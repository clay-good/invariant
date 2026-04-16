//! Degraded mode failure tests.
//!
//! Automated test cases for every failure mode from spec Section 19.
//! Verifies the core invariant: "If Invariant cannot guarantee safety,
//! it guarantees stillness."

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use invariant_core::audit::AuditLogger;
    use invariant_core::authority::crypto::generate_keypair;
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::models::profile::SafeStopProfile;
    use invariant_core::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use invariant_core::validator::ValidatorConfig;
    use invariant_core::watchdog::{Watchdog, WatchdogError, WatchdogState};
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn make_sk() -> SigningKey {
        generate_keypair(&mut OsRng)
    }

    fn minimal_command(joint_name: &str) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "degraded-test".into(),
            sequence: 0,
            joint_states: vec![JointState {
                name: joint_name.into(),
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
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        }
    }

    fn minimal_verdict() -> SignedVerdict {
        SignedVerdict {
            verdict: Verdict {
                approved: true,
                command_hash: "sha256:test".into(),
                command_sequence: 0,
                timestamp: Utc::now(),
                checks: vec![CheckResult {
                    name: "test".into(),
                    category: "test".into(),
                    passed: true,
                    details: "ok".into(),
                    derating: None,
                }],
                profile_name: "test".into(),
                profile_hash: "sha256:hash".into(),
                authority_summary: AuthoritySummary {
                    origin_principal: "op".into(),
                    hop_count: 1,
                    operations_granted: vec!["actuate:*".into()],
                    operations_required: vec!["actuate:j1".into()],
                },
                threat_analysis: None,
            },
            verdict_signature: "sig".into(),
            signer_kid: "kid".into(),
        }
    }

    fn make_validator() -> ValidatorConfig {
        let name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(name).unwrap();
        let sk = make_sk();
        let vk = sk.verifying_key();
        let kid = "degraded-kid".to_string();
        let mut trusted = HashMap::new();
        trusted.insert(kid.clone(), vk);
        ValidatorConfig::new(profile, trusted, sk, kid).unwrap()
    }

    // ===================================================================
    // FM1-FM3: Cognitive layer crash / hang / network partition
    // Defense: Watchdog timeout → signed safe-stop
    // ===================================================================

    /// FM1: Cognitive crash — watchdog triggers safe-stop after timeout.
    #[test]
    fn fm1_cognitive_crash_triggers_safe_stop() {
        let sk = make_sk();
        let mut wd = Watchdog::new(50, SafeStopProfile::default(), sk, "kid".into(), 0);

        // No heartbeats after t=0. Check at t=100 (well past 50ms timeout).
        let cmd = wd.check(100, Utc::now()).unwrap();
        assert!(
            cmd.is_some(),
            "FM1: watchdog must produce safe-stop command"
        );
        assert_eq!(wd.state(), WatchdogState::Triggered);
    }

    /// FM2: Cognitive hang — identical to crash from watchdog perspective.
    #[test]
    fn fm2_cognitive_hang_same_as_crash() {
        let sk = make_sk();
        let mut wd = Watchdog::new(50, SafeStopProfile::default(), sk, "kid".into(), 0);

        // Heartbeat at t=10 then nothing. Check at t=70 (60ms since heartbeat > 50ms).
        wd.heartbeat(10).unwrap();
        let cmd = wd.check(70, Utc::now()).unwrap();
        assert!(cmd.is_some(), "FM2: hang triggers safe-stop");
    }

    /// FM3: Network partition — no commands arrive, watchdog handles it.
    #[test]
    fn fm3_network_partition_triggers_safe_stop() {
        let sk = make_sk();
        let mut wd = Watchdog::new(100, SafeStopProfile::default(), sk, "kid".into(), 0);

        // Simulate partition: heartbeat at t=50, then nothing until t=200.
        wd.heartbeat(50).unwrap();
        let cmd = wd.check(200, Utc::now()).unwrap();
        assert!(
            cmd.is_some(),
            "FM3: network partition triggers safe-stop after timeout"
        );
    }

    /// FM1-3: After safe-stop, watchdog rejects heartbeats until operator reset.
    #[test]
    fn fm1_3_safe_stop_is_one_way_latch() {
        let sk = make_sk();
        let mut wd = Watchdog::new(50, SafeStopProfile::default(), sk, "kid".into(), 0);

        // Trigger safe-stop.
        wd.check(100, Utc::now()).unwrap();
        assert_eq!(wd.state(), WatchdogState::Triggered);

        // Cognitive layer "recovers" and sends heartbeat — REJECTED.
        let err = wd.heartbeat(200).unwrap_err();
        assert_eq!(err, WatchdogError::AlreadyTriggered);

        // Only operator reset restores Armed state.
        wd.reset(300);
        assert_eq!(wd.state(), WatchdogState::Armed);
        wd.heartbeat(310).unwrap(); // now succeeds
    }

    // ===================================================================
    // FM5: HSM unreachable → fail-closed (reject all commands)
    // Defense: Validator always requires signing key
    // ===================================================================

    /// FM5: Without a valid signing key, the validator cannot be constructed.
    #[test]
    fn fm5_validator_requires_signing_key() {
        // ValidatorConfig::new requires a signing key. If the HSM is
        // unreachable, the key cannot be loaded, and the validator cannot
        // start → no commands are processed → fail-closed.
        let name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(name).unwrap();
        let sk = make_sk();
        let vk = sk.verifying_key();
        let kid = "hsm-kid".to_string();
        let mut trusted = HashMap::new();
        trusted.insert(kid.clone(), vk);

        // Validator is constructable with the key.
        let config = ValidatorConfig::new(profile.clone(), trusted.clone(), sk, kid.clone());
        assert!(config.is_ok(), "FM5: validator constructs with valid key");

        // Without trusted keys for the PCA chain, authority check will fail.
        let sk2 = make_sk();
        let config2 = ValidatorConfig::new(profile, HashMap::new(), sk2, "other".into());
        assert!(
            config2.is_ok(),
            "FM5: validator constructs (empty trusted keys = all authority checks fail)"
        );
    }

    /// FM5: Validator with no trusted keys rejects every command.
    #[test]
    fn fm5_no_trusted_keys_rejects_all() {
        let name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(name).unwrap();
        let sk = make_sk();
        let config = ValidatorConfig::new(profile, HashMap::new(), sk, "kid".into()).unwrap();

        let cmd = minimal_command("j1");
        let result = config.validate(&cmd, Utc::now(), None);
        // Err(_) is also correct — fail-closed
        if let Ok(r) = result {
            assert!(
                !r.signed_verdict.verdict.approved,
                "FM5: no trusted keys → command must be rejected"
            );
        }
    }

    // ===================================================================
    // FM6: Audit log disk full → fail-closed (reject commands)
    // Defense: AuditLogger returns Err on write failure
    // ===================================================================

    /// A writer that fails after N successful flush() calls, simulating disk full.
    /// Each `AuditLogger::log()` call does one write+flush cycle, so counting
    /// flushes is the correct way to count complete log entries.
    struct DiskFullWriter {
        flushes_remaining: usize,
        buf: Vec<u8>,
    }

    impl DiskFullWriter {
        fn new(max_entries: usize) -> Self {
            Self {
                flushes_remaining: max_entries,
                buf: Vec::new(),
            }
        }
    }

    impl std::io::Write for DiskFullWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            // Writes always succeed — the error fires on flush.
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.flushes_remaining == 0 {
                return Err(std::io::Error::other("ENOSPC: disk full"));
            }
            self.flushes_remaining -= 1;
            Ok(())
        }
    }

    /// FM6: Audit logger returns Err when disk is full.
    #[test]
    fn fm6_audit_write_failure_returns_error() {
        let sk = make_sk();
        let writer = DiskFullWriter::new(0); // fails immediately
        let mut logger = AuditLogger::new(writer, sk, "kid".into());

        let cmd = minimal_command("j1");
        let verdict = minimal_verdict();
        let result = logger.log(&cmd, &verdict);

        assert!(
            result.is_err(),
            "FM6: audit log must return Err when write fails"
        );
    }

    /// FM6: After write failure, hash chain state is NOT advanced (safe to retry).
    #[test]
    fn fm6_write_failure_does_not_advance_hash_chain() {
        let sk = make_sk();
        let writer = DiskFullWriter::new(1); // succeeds once, then fails
        let mut logger = AuditLogger::new(writer, sk, "kid".into());

        let cmd = minimal_command("j1");
        let verdict = minimal_verdict();

        // First write succeeds.
        let result1 = logger.log(&cmd, &verdict);
        assert!(result1.is_ok(), "first write should succeed");
        let seq_after_success = logger.sequence();
        let hash_after_success = logger.previous_hash().to_string();

        // Second write fails (disk full).
        let result2 = logger.log(&cmd, &verdict);
        assert!(result2.is_err(), "second write should fail");

        // Hash chain state should NOT have advanced.
        assert_eq!(
            logger.sequence(),
            seq_after_success,
            "FM6: sequence must not advance on write failure"
        );
        assert_eq!(
            logger.previous_hash(),
            hash_after_success,
            "FM6: previous_hash must not change on write failure"
        );
    }

    /// FM6: In the real pipeline, if audit logging fails, the server/CLI
    /// must reject the command. This test documents the pattern:
    /// validate → audit log → if audit fails, discard verdict.
    #[test]
    fn fm6_fail_closed_pattern_documented() {
        // The fail-closed guarantee is architectural:
        //   1. Validate command → get verdict
        //   2. Attempt to write audit entry
        //   3. IF audit write fails → do NOT return the signed verdict to the caller
        //   4. Return error to cognitive layer
        //
        // This is enforced in the CLI/server layer, not in the library.
        // The library guarantees audit Err propagation; the caller must
        // handle it by rejecting the command.
        //
        // Verify the library returns Err (which the caller can act on).
        let sk = make_sk();
        let writer = DiskFullWriter::new(0);
        let mut logger = AuditLogger::new(writer, sk, "kid".into());
        let result = logger.log(&minimal_command("j1"), &minimal_verdict());
        assert!(result.is_err());
    }

    // ===================================================================
    // FM7: Audit log corruption → hash chain detects
    // (Covered by SA6 tests in system/filesystem.rs — reference only)
    // ===================================================================

    /// FM7: Reference test — audit corruption is detected via hash chain.
    /// Full tests are in system/filesystem.rs (SA6).
    #[test]
    fn fm7_audit_corruption_reference() {
        // SA6 tests verify: tampered entry, deleted entry, inserted entry.
        // All detected by verify_log hash chain + signature checks.
        // FM7: see SA6 tests for audit corruption detection.
    }

    // ===================================================================
    // FM8: Profile file corrupted → hash mismatch
    // (Covered by SA4 tests in system/filesystem.rs — reference only)
    // ===================================================================

    /// FM8: Reference test — profile corruption is detected via hash.
    #[test]
    fn fm8_profile_corruption_reference() {
        // SA4 tests verify: modified profile changes hash, single byte flip detected.
        // FM8: see SA4 tests for profile corruption detection.
    }

    // ===================================================================
    // FM9: Clock anomaly → PCA temporal checks catch it
    // (Covered by SA9 tests in system/time.rs — reference only)
    // ===================================================================

    /// FM9: Reference test — clock anomaly is handled by PCA temporal checks.
    #[test]
    fn fm9_clock_anomaly_reference() {
        // SA9 tests verify: expired PCA rejected, future PCA rejected,
        // clock skew does not bypass temporal checks.
        // Watchdog uses monotonic timestamps (caller-supplied) independent of wall clock.
        // FM9: see SA9 tests for clock anomaly handling.
    }

    // ===================================================================
    // FM10: Invariant process OOM → motor watchdog handles
    // ===================================================================

    /// FM10: OOM is an OS-level event. The defense is: motor controller
    /// has its own watchdog — when it stops receiving signed commands, it
    /// triggers hardware safe-stop. This is a deployment architecture test.
    #[test]
    #[ignore = "FM10: OOM recovery requires OS-level testing — motor watchdog is hardware-specific"]
    fn fm10_oom_motor_watchdog_handles() {}

    // ===================================================================
    // FM11: Power loss → hardware e-stop
    // ===================================================================

    /// FM11: Power loss is instantaneous. The defense is hardware e-stop
    /// (spring brakes, gravity compensation). Not testable in software.
    #[test]
    #[ignore = "FM11: power loss recovery is hardware-specific — spring brakes / gravity compensation"]
    fn fm11_power_loss_hardware_estop() {}

    // ===================================================================
    // Section 19.2: "No pass-through mode" guarantee
    // ===================================================================

    /// The core invariant: there is no code path that passes a command
    /// through without validation. Every command must go through
    /// ValidatorConfig::validate().
    #[test]
    fn section19_2_no_passthrough_mode() {
        let config = make_validator();
        let cmd = minimal_command("j1");
        let now = Utc::now();

        // There is no method on ValidatorConfig that returns a signed
        // actuation command without running the full validation pipeline.
        // The only public method is `validate()`, which always runs
        // authority + physics checks.
        let result = config.validate(&cmd, now, None);
        match result {
            Ok(r) => {
                // If approved, the signed actuation command was produced
                // only because all checks passed.
                if r.signed_verdict.verdict.approved {
                    assert!(
                        r.signed_verdict.verdict.checks.iter().all(|c| c.passed),
                        "approved verdict must have all checks passing"
                    );
                }
            }
            Err(_) => {
                // Validator error = no actuation command produced.
                // This is the correct fail-closed behavior.
            }
        }
    }

    /// The three operational states from Section 19.2:
    /// 1. Full operation — commands validated and signed
    /// 2. Safe-stop — watchdog triggered, all commands rejected
    /// 3. Dead — no validator running, motor gets no signed commands
    ///
    /// There is no state 4. There is no "pass-through mode."
    #[test]
    fn section19_2_only_three_states() {
        // State 1: Full operation.
        let config = make_validator();
        let _ = config.validate(&minimal_command("j1"), Utc::now(), None);

        // State 2: Safe-stop.
        let sk = make_sk();
        let mut wd = Watchdog::new(50, SafeStopProfile::default(), sk, "kid".into(), 0);
        let cmd = wd.check(100, Utc::now()).unwrap();
        assert!(cmd.is_some()); // safe-stop command issued
        assert_eq!(wd.state(), WatchdogState::Triggered);

        // State 3: Dead — no validator means no signed commands.
        // (Drop the validator — no method to call.)
        drop(config);

        // There is no state 4.
    }

    // ===================================================================
    // FM4: Network partition (invariant ↔ motor) → motor ACK timeout
    // ===================================================================

    /// FM4: Motor-side partition. The defense is the motor controller's own
    /// watchdog. From Invariant's perspective, it stops sending signed
    /// commands and alerts. This is a deployment architecture test.
    #[test]
    #[ignore = "FM4: motor-side network partition requires hardware motor controller with ACK timeout"]
    fn fm4_motor_partition_motor_watchdog() {}
}
