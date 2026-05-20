//! Append-only signed JSONL audit logger.
//!
//! Thin robotics shim over [`invariant_core::audit`]. The hash-chain and
//! signature logic now lives in `invariant-core` so it can be shared with
//! the biosynthesis domain (Phase 1b). This module fixes the generic
//! parameters to robotics's [`Command`] and [`SignedVerdict`] so the
//! existing public API surface (and on-disk JSONL format) is unchanged.

use crate::models::command::Command;
use crate::models::verdict::SignedVerdict;

pub use invariant_core::audit::{AuditError, AuditVerifyError};

/// Append-only audit logger for the robotics domain.
///
/// Generic over `W: Write` so it can target a file (with O_APPEND) or an
/// in-memory buffer for testing. The input/verdict types are bound to
/// [`Command`] and [`SignedVerdict`].
pub type AuditLogger<W> = invariant_core::audit::AuditLogger<W, Command, SignedVerdict>;

/// Verify an audit log's integrity: hash chain continuity (L2), entry hash
/// correctness, signature validity (L3), and sequence monotonicity.
///
/// Returns the number of verified entries on success, or the first error.
pub fn verify_log(
    jsonl: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<u64, AuditVerifyError> {
    invariant_core::audit::verify_log::<Command, SignedVerdict>(jsonl, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::crypto::{generate_keypair, sign_pca};
    use crate::models::authority::{Operation, Pca};
    use crate::models::command::{Command, CommandAuthority, JointState};
    use crate::models::profile::*;
    use crate::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use crate::validator::ValidatorConfig;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::{BTreeSet, HashMap};

    fn op(s: &str) -> Operation {
        Operation::new(s).unwrap()
    }

    #[allow(dead_code)]
    fn ops(ss: &[&str]) -> BTreeSet<Operation> {
        ss.iter().map(|s| op(s)).collect()
    }

    fn make_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[allow(dead_code)]
    fn test_profile() -> RobotProfile {
        RobotProfile {
            name: "test_robot".into(),
            version: "1.0.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -3.15,
                max: 3.15,
                max_velocity: 5.0,
                max_torque: 100.0,
                max_acceleration: 50.0,
            }],
            workspace: WorkspaceBounds::Aabb {
                min: [-2.0, -2.0, 0.0],
                max: [2.0, 2.0, 3.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            end_effectors: vec![],
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
        }
    }

    #[allow(dead_code)]
    fn encode_chain(hops: &[crate::models::authority::SignedPca]) -> String {
        let json = serde_json::to_vec(hops).unwrap();
        STANDARD.encode(&json)
    }

    #[allow(dead_code)]
    fn make_command(chain_b64: &str, required_ops: Vec<Operation>) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 1.0,
                effort: 10.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: chain_b64.to_string(),
                required_ops,
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

    #[allow(dead_code)]
    fn make_approved_result(command: &Command) -> (SignedVerdict, ValidatorConfig, SigningKey) {
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _sign_vk) = make_keypair();

        let claim = Pca {
            p_0: "alice".into(),
            ops: ops(&["actuate:*"]),
            kid: "key-1".into(),
            exp: None,
            nbf: None,
            predecessor_digest: [0u8; 32],
        };
        let signed_pca = sign_pca(&claim, &pca_sk).unwrap();
        let chain_b64 = encode_chain(&[signed_pca]);

        let mut trusted = HashMap::new();
        trusted.insert("key-1".to_string(), pca_vk);

        let config = ValidatorConfig::new(
            test_profile(),
            trusted,
            sign_sk.clone(),
            "invariant-test".into(),
        )
        .unwrap();

        let mut cmd = command.clone();
        cmd.authority.pca_chain = chain_b64;

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        (result.signed_verdict, config, sign_sk)
    }

    fn make_simple_signed_verdict() -> (SignedVerdict, SigningKey) {
        let (sign_sk, _) = make_keypair();
        // Use a fixed timestamp so that entry_hash values are deterministic
        // across repeated calls (Finding 49).
        let fixed_ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let verdict = Verdict {
            approved: true,
            command_hash: "sha256:abc123".into(),
            command_sequence: 1,
            timestamp: fixed_ts,
            checks: vec![CheckResult {
                name: "test".into(),
                category: "test".into(),
                passed: true,
                details: "ok".into(),
                derating: None,
            }],
            profile_name: "test_robot".into(),
            profile_hash: "sha256:def456".into(),
            threat_analysis: None,
            authority_summary: AuthoritySummary {
                origin_principal: "alice".into(),
                hop_count: 1,
                operations_granted: vec!["actuate:*".into()],
                operations_required: vec!["actuate:j1".into()],
            },
        };

        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        use ed25519_dalek::Signer;
        let signature = sign_sk.sign(&verdict_json);

        let signed = SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(signature.to_bytes()),
            signer_kid: "invariant-test".into(),
        };

        (signed, sign_sk)
    }

    fn make_simple_command() -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 1.0,
                effort: 10.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![op("actuate:j1")],
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

    // -----------------------------------------------------------------------
    // Core tests
    // -----------------------------------------------------------------------

    #[test]
    fn single_entry_log_and_verify() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        let entry = logger.log(&cmd, &verdict).unwrap();

        assert_eq!(entry.entry.sequence, 0);
        assert!(entry.entry.previous_hash.is_empty());
        assert!(entry.entry.entry_hash.starts_with("sha256:"));
        assert!(!entry.entry_signature.is_empty());
        assert_eq!(entry.signer_kid, "invariant-001");

        // Logger state advanced.
        assert_eq!(logger.sequence(), 1);
        assert_eq!(logger.previous_hash(), &entry.entry.entry_hash);

        // Verify the JSONL output.
        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn multi_entry_hash_chain() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        let e0 = logger.log(&cmd, &verdict).unwrap();
        let e1 = logger.log(&cmd, &verdict).unwrap();
        let e2 = logger.log(&cmd, &verdict).unwrap();

        // Hash chain links.
        assert!(e0.entry.previous_hash.is_empty());
        assert_eq!(e1.entry.previous_hash, e0.entry.entry_hash);
        assert_eq!(e2.entry.previous_hash, e1.entry.entry_hash);

        // Monotonic sequence.
        assert_eq!(e0.entry.sequence, 0);
        assert_eq!(e1.entry.sequence, 1);
        assert_eq!(e2.entry.sequence, 2);

        // All hashes are distinct.
        assert_ne!(e0.entry.entry_hash, e1.entry.entry_hash);
        assert_ne!(e1.entry.entry_hash, e2.entry.entry_hash);

        // Verify full chain.
        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn tampered_entry_hash_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        // Tamper: modify the entry_hash in the JSONL.
        let jsonl = String::from_utf8(buf).unwrap();
        let tampered = jsonl.replace(
            r#""entry_hash":"sha256:"#,
            r#""entry_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000_REPLACED_"#,
        );

        let result = verify_log(&tampered, &sign_vk);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_signature_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        // Tamper: replace signature with zeros.
        let jsonl = String::from_utf8(buf).unwrap();
        let entry: serde_json::Value = serde_json::from_str(jsonl.trim()).unwrap();
        let mut tampered_entry = entry.clone();
        tampered_entry["entry_signature"] = serde_json::Value::String(STANDARD.encode([0u8; 64]));
        let tampered_jsonl = serde_json::to_string(&tampered_entry).unwrap() + "\n";

        let result = verify_log(&tampered_jsonl, &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::SignatureInvalid { sequence } => assert_eq!(sequence, 0),
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let (sign_sk, _) = make_keypair();
        let (_, wrong_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        let jsonl = String::from_utf8(buf).unwrap();
        let result = verify_log(&jsonl, &wrong_vk);
        assert!(result.is_err());
    }

    #[test]
    fn broken_hash_chain_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();
        logger.log(&cmd, &verdict).unwrap();

        // Parse both entries, swap the order so hash chain breaks.
        let jsonl = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);

        // Swapping lines will cause hash chain mismatch at entry 1.
        let swapped = format!("{}\n{}\n", lines[1], lines[0]);
        let result = verify_log(&swapped, &sign_vk);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_gap_detected() {
        let (sign_sk, sign_vk) = make_keypair();

        // Log entry 0.
        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger1.log(&cmd, &verdict).unwrap();

        // Log entry with sequence=2 (skipping 1) via resume.
        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::resume(
            &mut buf2,
            sign_sk,
            "test".into(),
            2, // skip sequence 1
            logger1.previous_hash().to_string(),
        );
        logger2.log(&cmd, &verdict).unwrap();

        let jsonl = format!(
            "{}{}\n",
            String::from_utf8(buf1).unwrap(),
            String::from_utf8(buf2).unwrap().trim()
        );
        let result = verify_log(&jsonl, &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::SequenceGap { expected, got, .. } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("expected SequenceGap, got {other:?}"),
        }
    }

    #[test]
    fn resume_continues_chain() {
        let (sign_sk, sign_vk) = make_keypair();

        // Phase 1: log two entries.
        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger1.log(&cmd, &verdict).unwrap();
        logger1.log(&cmd, &verdict).unwrap();

        let seq = logger1.sequence();
        let prev = logger1.previous_hash().to_string();

        // Phase 2: resume and log one more.
        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::resume(&mut buf2, sign_sk, "test".into(), seq, prev);
        logger2.log(&cmd, &verdict).unwrap();

        // Combine JSONL and verify full chain.
        let jsonl = format!(
            "{}{}",
            String::from_utf8(buf1).unwrap(),
            String::from_utf8(buf2).unwrap(),
        );
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn empty_log_verifies() {
        let (_, sign_vk) = make_keypair();
        let count = verify_log("", &sign_vk).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn entry_hash_is_deterministic() {
        // `cmd` and `verdict` are constructed once and reused for both logger
        // calls.  Because both objects carry identical timestamps (they are the
        // same heap values), the JSON serialisation is byte-identical across
        // both invocations, making the entry_hash and the Ed25519 signature
        // deterministic.  If each call were to use a freshly-constructed
        // command or verdict with Utc::now() inside, clock drift between the
        // two calls could produce different hashes and this assertion would
        // fail non-deterministically.
        let (sign_sk, _) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let e1 = logger1.log(&cmd, &verdict).unwrap();

        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::new(&mut buf2, sign_sk, "test".into());
        let e2 = logger2.log(&cmd, &verdict).unwrap();

        assert_eq!(e1.entry.entry_hash, e2.entry.entry_hash);
        assert_eq!(e1.entry_signature, e2.entry_signature);
    }

    #[test]
    fn rejected_verdict_also_logged() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk.clone(), "test".into());

        // Create a rejection verdict.
        let verdict = Verdict {
            approved: false,
            command_hash: "sha256:rejected".into(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks: vec![CheckResult {
                name: "authority".into(),
                category: "authority".into(),
                passed: false,
                details: "chain verification failed".into(),
                derating: None,
            }],
            profile_name: "test".into(),
            profile_hash: "sha256:profile".into(),
            threat_analysis: None,
            authority_summary: AuthoritySummary {
                origin_principal: String::new(),
                hop_count: 0,
                operations_granted: vec![],
                operations_required: vec!["actuate:j1".into()],
            },
        };
        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        use ed25519_dalek::Signer;
        let sig = sign_sk.sign(&verdict_json);
        let signed_verdict = SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(sig.to_bytes()),
            signer_kid: "test".into(),
        };

        let cmd = make_simple_command();
        let entry = logger.log(&cmd, &signed_verdict).unwrap();
        assert!(!entry.entry.verdict.verdict.approved);

        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn verify_detects_malformed_json() {
        let (_, sign_vk) = make_keypair();
        let result = verify_log("this is not json\n", &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::Deserialization { line, .. } => assert_eq!(line, 1),
            other => panic!("expected Deserialization, got {other:?}"),
        }
    }

    #[test]
    fn verify_skips_blank_lines() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        // Add blank lines around the entry.
        let jsonl = String::from_utf8(buf).unwrap();
        let with_blanks = format!("\n\n{jsonl}\n\n");
        let count = verify_log(&with_blanks, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn open_file_resumes_hash_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");

        let (sign_sk, sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Phase 1: write two entries via open_file.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "kid-1".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
            logger.log(&cmd, &verdict).unwrap();
            // BufWriter is flushed on drop.
        }

        // Phase 2: re-open the same file and append a third entry.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "kid-1".into()).unwrap();
            // The resumed logger must start at sequence 2.
            assert_eq!(logger.sequence(), 2, "resumed sequence should be 2");
            logger.log(&cmd, &verdict).unwrap();
        }

        // The combined file must form a valid 3-entry chain.
        let jsonl = std::fs::read_to_string(&path).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 3, "expected 3 verified entries");
    }

    #[test]
    fn open_file_new_file_starts_at_genesis() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new_audit.jsonl");

        let (sign_sk, sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        {
            let mut logger = AuditLogger::open_file(&path, sign_sk, "kid-1".into()).unwrap();
            assert_eq!(logger.sequence(), 0);
            logger.log(&cmd, &verdict).unwrap();
            // BufWriter is flushed on drop at end of this block.
        }

        let jsonl = std::fs::read_to_string(&path).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn entry_contains_full_command_and_verdict() {
        let (sign_sk, _) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let entry = logger.log(&cmd, &verdict).unwrap();

        // L1: entry contains the full command and signed verdict.
        assert_eq!(entry.entry.command.source, "test");
        assert_eq!(entry.entry.command.sequence, 1);
        assert_eq!(entry.entry.verdict.verdict.command_hash, "sha256:abc123");
        assert!(entry.entry.verdict.verdict.approved);
    }

    // -----------------------------------------------------------------------
    // Finding 16: open_file tests
    // -----------------------------------------------------------------------

    #[test]
    fn open_file_succeeds_and_entry_is_verifiable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit_f16.jsonl");

        let (sign_sk, sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Open a brand-new file, log one entry, then verify it.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "f16-kid".into()).unwrap();
            assert_eq!(logger.sequence(), 0, "new file must start at genesis");
            let entry = logger.log(&cmd, &verdict).unwrap();
            assert_eq!(entry.entry.sequence, 0);
            assert!(entry.entry.entry_hash.starts_with("sha256:"));
        }

        let jsonl = std::fs::read_to_string(&path).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1, "exactly one entry must be verifiable");
    }

    #[test]
    fn open_file_missing_parent_returns_io_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Construct a path whose parent does not exist.
        let path = dir.path().join("nonexistent_dir").join("audit.jsonl");

        let (sign_sk, _) = make_keypair();
        let result = AuditLogger::open_file(&path, sign_sk, "kid".into());

        match result {
            Err(AuditError::Io { .. }) => {}
            Err(other) => panic!("expected AuditError::Io, got {other:?}"),
            Ok(_) => panic!("expected an error but got Ok"),
        }
    }

    // -----------------------------------------------------------------------
    // Finding 17: verify_log NonEmptyGenesisPreviousHash
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Finding 53: truncated final entry is detected
    // -----------------------------------------------------------------------

    #[test]
    fn verify_log_rejects_truncated_final_entry() {
        // Build a two-entry log, then truncate the second JSONL line mid-way.
        // verify_log must return a Deserialization error for the truncated line.
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();
        logger.log(&cmd, &verdict).unwrap();

        let jsonl = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 log lines");

        // Truncate the second line to roughly half its length.
        let truncated_line = &lines[1][..lines[1].len() / 2];
        let truncated_jsonl = format!("{}\n{}\n", lines[0], truncated_line);

        let result = verify_log(&truncated_jsonl, &sign_vk);
        assert!(
            result.is_err(),
            "truncated entry must cause verify_log to fail"
        );
        match result.unwrap_err() {
            AuditVerifyError::Deserialization { line, .. } => {
                assert_eq!(line, 2, "error should be on line 2 (the truncated entry)");
            }
            other => panic!("expected Deserialization error, got {other:?}"),
        }
    }

    #[test]
    fn verify_log_rejects_genesis_with_non_empty_previous_hash() {
        let (sign_sk, sign_vk) = make_keypair();

        // Build a legitimate entry via the logger to get the correct JSON shape.
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "f17-kid".into());
        let signed_entry = logger.log(&cmd, &verdict).unwrap();

        // Surgically inject a non-empty previous_hash on sequence 0.
        // verify_log checks previous_hash before it verifies entry_hash or
        // the Ed25519 signature, so the patch will hit the right error first.
        let mut entry_json: serde_json::Value = serde_json::to_value(&signed_entry).unwrap();
        entry_json["previous_hash"] = serde_json::Value::String("sha256:not_empty_genesis".into());
        let tampered_line = serde_json::to_string(&entry_json).unwrap();

        let result = verify_log(&tampered_line, &sign_vk);
        assert!(result.is_err(), "expected an error, got {:?}", result);
        assert_eq!(
            result.unwrap_err(),
            AuditVerifyError::NonEmptyGenesisPreviousHash,
        );
    }

    // -----------------------------------------------------------------------
    // Finding 43: open_file resumes from tampered log without re-verifying
    // -----------------------------------------------------------------------

    #[test]
    fn open_file_tampered_log_verify_fails_after_resume() {
        // Write a valid 2-entry log, corrupt the last entry_hash on disk, then
        // call open_file to resume (which reads but does NOT verify the chain).
        // After logging one more entry, verify_log on the combined file must
        // fail with HashChainBroken because the corrupted hash was chained into
        // the new entry's previous_hash field.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tampered_audit.jsonl");

        let (sign_sk, sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Phase 1: write a valid 2-entry log.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "kid-tamper".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
            logger.log(&cmd, &verdict).unwrap();
        }

        // Phase 2: corrupt the last entry_hash field in the file.
        let original = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = original.lines().collect();
        assert_eq!(lines.len(), 2);
        // Replace the entry_hash value in the last line with zeroes.
        let corrupted_last = {
            let mut val: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
            val["entry_hash"] = serde_json::Value::String(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            );
            serde_json::to_string(&val).unwrap()
        };
        let tampered_content = format!("{}\n{}\n", lines[0], corrupted_last);
        std::fs::write(&path, &tampered_content).unwrap();

        // Phase 3: open_file resumes from the tampered log and appends a third entry.
        // This should succeed — open_file does not verify the chain on resume.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "kid-tamper".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
        }

        // Phase 4: verify_log must fail because the chain is broken.
        let combined = std::fs::read_to_string(&path).unwrap();
        let result = verify_log(&combined, &sign_vk);
        assert!(
            result.is_err(),
            "verify_log must fail on a log that resumes from a tampered entry"
        );
        // The error should be about the hash chain or entry hash mismatch.
        match result.unwrap_err() {
            AuditVerifyError::HashChainBroken { .. }
            | AuditVerifyError::EntryHashMismatch { .. } => {}
            other => panic!("expected HashChainBroken or EntryHashMismatch, got {other:?}"),
        }
    }

    // ── Audit log corruption resilience ─────────────────────

    #[test]
    fn open_file_with_truncated_last_line_returns_error() {
        // Simulates a power failure mid-write: file ends with a partial JSON line.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("truncated_audit.jsonl");

        let (sign_sk, _) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Write a valid 1-entry log.
        {
            let mut logger = AuditLogger::open_file(&path, sign_sk.clone(), "kid".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
        }

        // Append a truncated JSON line (simulating crash mid-write).
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"\n{\"entry\":{\"seq").unwrap();
        file.flush().unwrap();
        drop(file);

        // Re-opening should fail because the last line is not valid JSON.
        let result = AuditLogger::open_file(&path, sign_sk, "kid".into());
        assert!(
            result.is_err(),
            "truncated last line must cause open_file to fail"
        );
    }

    #[test]
    fn open_file_with_only_blank_lines_starts_at_genesis() {
        // A file containing only newlines should be treated as empty.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blank_audit.jsonl");

        use std::io::Write;
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"\n\n\n").unwrap();
        drop(file);

        let (sign_sk, _) = make_keypair();
        let result = AuditLogger::open_file(&path, sign_sk, "kid".into());
        // An all-blank file should either start at genesis (sequence 0) or
        // error. Both are acceptable — the important thing is no panic.
        match result {
            Ok(logger) => {
                assert_eq!(logger.sequence(), 0, "blank file must start at genesis");
            }
            Err(_) => {
                // Also acceptable — the file is corrupt (no valid entries).
            }
        }
    }

    #[test]
    fn verify_log_catches_single_bit_flip_in_signature() {
        // Write a valid 1-entry log, then flip a bit in the entry_signature.
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();
        drop(logger);

        let jsonl = String::from_utf8(buf).unwrap();
        // Flip one character in the base64 signature.
        let corrupted = jsonl.replacen("entry_signature\":\"", "entry_signature\":\"X", 1);

        let result = verify_log(&corrupted, &sign_vk);
        assert!(
            result.is_err(),
            "single bit flip in signature must be detected"
        );
    }

    // -----------------------------------------------------------------------
    // max_file_bytes / LogFull tests (spec-v3 §3.3)
    // -----------------------------------------------------------------------

    #[test]
    fn log_full_rejects_when_entry_exceeds_limit() {
        let (sign_sk, _) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        // Set a very small limit — first entry will exceed it.
        logger.set_max_file_bytes(Some(10));

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let result = logger.log(&cmd, &verdict);

        assert!(
            result.is_err(),
            "write must fail when it would exceed limit"
        );
        match result.unwrap_err() {
            AuditError::LogFull {
                current_bytes,
                entry_bytes,
                max_bytes,
            } => {
                assert_eq!(current_bytes, 0);
                assert!(entry_bytes > 10);
                assert_eq!(max_bytes, 10);
            }
            other => panic!("expected LogFull, got: {other}"),
        }
        // Buffer must remain empty — entry was NOT written.
        assert!(buf.is_empty(), "no data must be written on LogFull");
    }

    #[test]
    fn log_full_allows_entries_within_limit() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        // Set a generous limit.
        logger.set_max_file_bytes(Some(1_000_000));

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let entry = logger.log(&cmd, &verdict);
        assert!(entry.is_ok(), "entry within limit must succeed");
        assert!(!buf.is_empty());

        // Verify the log is valid.
        let log_str = String::from_utf8(buf).unwrap();
        assert!(verify_log(&log_str, &sign_vk).is_ok());
    }

    #[test]
    fn log_full_triggers_after_multiple_entries() {
        let (sign_sk, _) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Write one entry to a scratch buffer to measure its size.
        let entry_size = {
            let mut scratch = Vec::new();
            let mut scratch_logger = AuditLogger::new(&mut scratch, sign_sk.clone(), "test".into());
            scratch_logger.log(&cmd, &verdict).unwrap();
            scratch.len() as u64
        };

        // Now create the real logger with a limit that fits 2 entries
        // (add a small margin for timestamp/sequence variation).
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());
        logger.set_max_file_bytes(Some(entry_size * 2 + 256));

        // First and second entries should fit.
        assert!(logger.log(&cmd, &verdict).is_ok(), "first entry must fit");
        assert!(logger.log(&cmd, &verdict).is_ok(), "second entry must fit");

        // Third entry should be rejected.
        let result = logger.log(&cmd, &verdict);
        assert!(result.is_err(), "third entry must be rejected");
        assert!(
            matches!(result.unwrap_err(), AuditError::LogFull { .. }),
            "error must be LogFull"
        );
    }

    #[test]
    fn log_full_disabled_by_default() {
        let (sign_sk, _) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Without max_file_bytes, writes should always succeed.
        for _ in 0..100 {
            assert!(logger.log(&cmd, &verdict).is_ok());
        }
    }

    #[test]
    fn set_initial_bytes_affects_limit_check() {
        let (sign_sk, _) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        // Pretend the file already has 999,990 bytes.
        logger.set_initial_bytes(999_990);
        logger.set_max_file_bytes(Some(1_000_000));

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // A typical audit entry is far larger than 10 bytes, so this should fail.
        let result = logger.log(&cmd, &verdict);
        assert!(
            matches!(result.unwrap_err(), AuditError::LogFull { .. }),
            "entry must be rejected when initial_bytes + entry > max"
        );
    }

    // -----------------------------------------------------------------------
    // read_last_line O(1) syscalls test (spec-v3 §5.2)
    // -----------------------------------------------------------------------

    #[test]
    fn read_last_line_large_audit_log() {
        // Write many entries to a temp file, then verify open_file recovers
        // the correct chain state from the last entry using the O(1) reader.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large_audit.jsonl");

        let (sign_sk, _sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Write 200 entries (produces a file of roughly 0.5-1 MB).
        let expected_sequence;
        let expected_hash;
        {
            let mut logger = AuditLogger::open_file(&path, sign_sk.clone(), "test".into()).unwrap();
            for _ in 0..200 {
                logger.log(&cmd, &verdict).unwrap();
            }
            expected_sequence = logger.sequence();
            expected_hash = logger.previous_hash().to_string();
        }

        // Re-open and verify chain state is recovered correctly.
        let start = std::time::Instant::now();
        let logger = AuditLogger::open_file(&path, sign_sk, "test".into()).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(
            logger.sequence(),
            expected_sequence,
            "sequence must match after re-open"
        );
        assert_eq!(
            logger.previous_hash(),
            expected_hash,
            "previous_hash must match after re-open"
        );

        // The O(1) reader should complete in well under 100ms even on slow
        // CI disks. The old per-byte reader would take proportionally longer
        // on large entries.
        assert!(
            elapsed.as_millis() < 500,
            "read_last_line must be fast: took {}ms",
            elapsed.as_millis()
        );

        // Verify the file is non-trivial in size.
        let file_size = std::fs::metadata(&path).unwrap().len();
        assert!(
            file_size > 50_000,
            "audit log must be substantial: {} bytes",
            file_size
        );
    }

    #[test]
    fn read_last_line_with_trailing_newlines() {
        // Audit logs end with a newline after each entry. Verify the reader
        // handles trailing newlines correctly (doesn't return an empty line).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trailing.jsonl");

        let (sign_sk, _) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        {
            let mut logger = AuditLogger::open_file(&path, sign_sk.clone(), "test".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
            logger.log(&cmd, &verdict).unwrap();
        }

        // Re-open — must resume at sequence 2.
        let logger = AuditLogger::open_file(&path, sign_sk, "test".into()).unwrap();
        assert_eq!(logger.sequence(), 2);
    }

    #[test]
    fn read_last_line_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.jsonl");

        let (sign_sk, _) = make_keypair();
        let logger = AuditLogger::open_file(&path, sign_sk, "test".into()).unwrap();
        assert_eq!(logger.sequence(), 0);
        assert_eq!(logger.previous_hash(), "");
    }

    // -----------------------------------------------------------------------
    // v12 N-4: audit JSONL schema_version
    // -----------------------------------------------------------------------

    #[test]
    fn v2_record_round_trips_with_schema_version_field() {
        use invariant_core::models::audit::{CURRENT_SCHEMA_VERSION, SCHEMA_VERSION_V2};

        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let entry = logger.log(&cmd, &verdict).unwrap();

        // The logger writes the current schema version.
        assert_eq!(CURRENT_SCHEMA_VERSION, SCHEMA_VERSION_V2);
        assert_eq!(entry.entry.schema_version, CURRENT_SCHEMA_VERSION);

        let jsonl = String::from_utf8(buf).unwrap();
        // The serialized form must include the new field at v2.
        assert!(
            jsonl.contains(r#""schema_version":2"#),
            "v2 record must serialize schema_version: {jsonl}",
        );

        // And it must still verify end-to-end (hash + signature).
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn legacy_v1_record_deserializes_as_v1_and_verifies() {
        use invariant_core::models::audit::{SignedAuditEntry, SCHEMA_VERSION_V1};

        // Simulate a pre-v12 on-disk record (no `schema_version` field).
        // We construct it by writing a v2 record, then stripping the field —
        // because skip_serializing_if(v1) omits the field, the resulting JSON
        // is byte-identical to what the pre-v12 code would have produced, so
        // the stored entry_hash and signature remain valid.
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk.clone(), "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();
        let jsonl = String::from_utf8(buf).unwrap();

        // Reach into the serialized form and patch the entry to look like v1:
        // re-hash and re-sign after deleting the field so we exercise the
        // *deserializer's* default-to-v1 path on a clean v1 record.
        let mut value: serde_json::Value = serde_json::from_str(jsonl.trim()).unwrap();
        // Strip the field on disk.
        value
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        // Recompute entry_hash over a struct that has no schema_version. Since
        // the in-memory struct *does* carry the field, we set it to 1 so
        // skip_serializing_if omits it from the canonical bytes.
        let mut parsed: SignedAuditEntry<Command, SignedVerdict> =
            serde_json::from_value(value).unwrap();
        assert_eq!(
            parsed.entry.schema_version, SCHEMA_VERSION_V1,
            "missing field must default to v1",
        );

        // Re-canonicalise (hash + signature) so the test exercises a *valid*
        // legacy entry rather than a tampered one.
        parsed.entry.entry_hash = String::new();
        let pre_hash =
            serde_json::to_vec(&parsed.entry).expect("entry must serialize");
        // Match the hash format used by the logger (no `sha256:` prefix here —
        // see invariant_core::audit::build_entry).
        parsed.entry.entry_hash = invariant_core::util::sha256_hex(&pre_hash);
        let entry_bytes = serde_json::to_vec(&parsed.entry).unwrap();
        use ed25519_dalek::Signer;
        let sig = sign_sk.sign(&entry_bytes);
        parsed.entry_signature = STANDARD.encode(sig.to_bytes());

        let v1_jsonl = serde_json::to_string(&parsed).unwrap() + "\n";
        // The canonical v1 form has no schema_version key on disk.
        assert!(
            !v1_jsonl.contains("schema_version"),
            "v1 record must omit schema_version from JSON: {v1_jsonl}",
        );

        // verify_log accepts the v1 record end-to-end.
        let count = verify_log(&v1_jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }
}
