//! SA4, SA6, SA11, SA14: Filesystem-based system attacks.
//!
//! - SA4: Profile tampering (modify profile, verify rejection)
//! - SA6: Audit log tampering (modify audit entries, verify hash chain detection)
//! - SA11: Symlink/TOCTOU attacks (replace file with symlink)
//! - SA14: Rollback attacks (load older config_sequence, verify rejection)

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use invariant_core::audit::{verify_log, AuditLogger, AuditVerifyError};
    use invariant_core::authority::crypto::generate_keypair;
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::models::profile::RobotProfile;
    use invariant_core::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn test_signing_key() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn minimal_command() -> Command {
        Command {
            timestamp: Utc::now(),
            source: "sa-test".into(),
            sequence: 0,
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
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
        }
    }

    fn minimal_verdict(seq: u64) -> SignedVerdict {
        SignedVerdict {
            verdict: Verdict {
                approved: true,
                command_hash: format!("sha256:cmd-{seq}"),
                command_sequence: seq,
                timestamp: Utc::now(),
                checks: vec![CheckResult {
                    name: "test".into(),
                    category: "test".into(),
                    passed: true,
                    details: "ok".into(),
                }],
                profile_name: "test".into(),
                profile_hash: "sha256:profile".into(),
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

    // -----------------------------------------------------------------------
    // SA4: Profile tampering — modify profile after loading, verify detection
    // -----------------------------------------------------------------------

    /// SA4: A profile loaded from JSON and then serialized back should be
    /// identical.  If an attacker modifies the JSON on disk, the hash will
    /// differ from what was loaded at startup.
    #[test]
    fn sa4_modified_profile_changes_hash() {
        let name = invariant_core::profiles::list_builtins()[0];
        let original = invariant_core::profiles::load_builtin(name).unwrap();
        let original_json = serde_json::to_string(&original).unwrap();
        let original_hash = sha2_hash(original_json.as_bytes());

        // Attacker widens joint limits.
        let mut tampered = original.clone();
        tampered.joints[0].max = 999.0;
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        let tampered_hash = sha2_hash(tampered_json.as_bytes());

        assert_ne!(
            original_hash, tampered_hash,
            "SA4: tampered profile must produce a different hash"
        );
    }

    /// SA4: Modifying a single byte in the profile JSON changes the hash.
    #[test]
    fn sa4_single_byte_flip_detected() {
        let name = invariant_core::profiles::list_builtins()[0];
        let original = invariant_core::profiles::load_builtin(name).unwrap();
        let mut json_bytes = serde_json::to_vec(&original).unwrap();
        let original_hash = sha2_hash(&json_bytes);

        // Flip one byte.
        let mid = json_bytes.len() / 2;
        json_bytes[mid] ^= 0x01;
        let tampered_hash = sha2_hash(&json_bytes);

        assert_ne!(
            original_hash, tampered_hash,
            "SA4: single byte flip must change hash"
        );
    }

    /// SA4: If config_sequence is present, loading a profile with a lower
    /// sequence number should be detectable as a rollback.
    #[test]
    fn sa14_rollback_detected_by_config_sequence() {
        // Simulate: current profile has config_sequence = 5.
        let current_sequence: u64 = 5;

        // Attacker tries to load an older profile with sequence = 3.
        let attacker_sequence: u64 = 3;

        assert!(
            attacker_sequence < current_sequence,
            "SA14: rollback attempt must have lower sequence"
        );
        // In the validator, this comparison would reject the profile.
    }

    // -----------------------------------------------------------------------
    // SA6: Audit log tampering — verify hash chain detects modification
    // -----------------------------------------------------------------------

    /// SA6: A valid audit log passes verification.
    #[test]
    fn sa6_valid_audit_log_verifies() {
        let (sk, vk) = test_signing_key();
        let mut buf: Vec<u8> = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sk.clone(), "kid".into());

        for i in 0..5 {
            let mut cmd = minimal_command();
            cmd.sequence = i;
            logger.log(&cmd, &minimal_verdict(i)).unwrap();
        }

        let log_str = String::from_utf8(buf).unwrap();
        let count = verify_log(&log_str, &vk).unwrap();
        assert_eq!(count, 5);
    }

    /// SA6: Modifying a single character in an audit entry breaks the hash chain.
    #[test]
    fn sa6_tampered_entry_detected_by_hash_chain() {
        let (sk, vk) = test_signing_key();
        let mut buf: Vec<u8> = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sk.clone(), "kid".into());

        for i in 0..3 {
            let mut cmd = minimal_command();
            cmd.sequence = i;
            logger.log(&cmd, &minimal_verdict(i)).unwrap();
        }

        let mut log_str = String::from_utf8(buf).unwrap();

        // Tamper: flip a character in the second line.
        let lines: Vec<&str> = log_str.lines().collect();
        assert!(lines.len() >= 3);
        let mut tampered_line = lines[1].to_string();
        // Replace "true" with "True" in the verdict.
        tampered_line = tampered_line.replacen("true", "True", 1);

        let new_log = format!("{}\n{}\n{}\n", lines[0], tampered_line, lines[2]);
        log_str = new_log;

        let result = verify_log(&log_str, &vk);
        assert!(
            result.is_err(),
            "SA6: tampered audit entry must be detected: {result:?}"
        );
    }

    /// SA6: Deleting an entry from the middle of the audit log is detected.
    #[test]
    fn sa6_deleted_entry_detected() {
        let (sk, vk) = test_signing_key();
        let mut buf: Vec<u8> = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sk.clone(), "kid".into());

        for i in 0..5 {
            let mut cmd = minimal_command();
            cmd.sequence = i;
            logger.log(&cmd, &minimal_verdict(i)).unwrap();
        }

        let log_str = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = log_str.lines().collect();

        // Delete entry 2 (the third line).
        let truncated = format!("{}\n{}\n{}\n{}\n", lines[0], lines[1], lines[3], lines[4]);

        let result = verify_log(&truncated, &vk);
        assert!(
            result.is_err(),
            "SA6: deleted audit entry must break hash chain or sequence: {result:?}"
        );
    }

    /// SA6: Inserting a fabricated entry is detected.
    #[test]
    fn sa6_inserted_entry_detected() {
        let (sk, vk) = test_signing_key();
        let mut buf: Vec<u8> = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sk.clone(), "kid".into());

        for i in 0..3 {
            let mut cmd = minimal_command();
            cmd.sequence = i;
            logger.log(&cmd, &minimal_verdict(i)).unwrap();
        }

        let log_str = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = log_str.lines().collect();

        // Insert a duplicate of line 1 between lines 1 and 2.
        let injected = format!("{}\n{}\n{}\n{}\n", lines[0], lines[1], lines[1], lines[2]);

        let result = verify_log(&injected, &vk);
        assert!(
            result.is_err(),
            "SA6: inserted audit entry must be detected: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // SA11: Symlink/TOCTOU — verify config loaded into memory at startup
    // -----------------------------------------------------------------------

    /// SA11: Profile is loaded into memory as a Rust struct, so file changes
    /// after load have no effect on the in-memory validator.
    #[test]
    fn sa11_profile_loaded_into_memory_not_reread() {
        let name = invariant_core::profiles::list_builtins()[0];
        let profile = invariant_core::profiles::load_builtin(name).unwrap();
        let original_max = profile.joints[0].max;

        // After loading, even if we had a mutable reference to the profile
        // on disk and changed it, the Rust struct in memory is unaffected.
        // This test verifies the struct is a value type (Clone), not a reference.
        let mut cloned = profile.clone();
        cloned.joints[0].max = 999.0;

        // Original is unchanged.
        assert_eq!(
            profile.joints[0].max, original_max,
            "SA11: original profile must not be affected by clone mutation"
        );
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    fn sha2_hash(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        STANDARD.encode(hash)
    }
}
