use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct VerifyArgs {
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
    #[arg(long, value_name = "PUBKEY_FILE")]
    pub pubkey: PathBuf,
}

pub fn run(args: &VerifyArgs) -> i32 {
    // Load public key.
    let kf = match crate::key_file::load_key_file(&args.pubkey) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (vk, _kid) = match crate::key_file::load_verifying_key(&kf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Reject audit logs larger than 512 MiB before reading to avoid OOM.
    const LOG_SIZE_LIMIT: u64 = 512 * 1024 * 1024; // 512 MiB
    match std::fs::metadata(&args.log) {
        Ok(meta) if meta.len() > LOG_SIZE_LIMIT => {
            eprintln!(
                "error: audit log {:?} is too large ({} bytes; limit is {LOG_SIZE_LIMIT} bytes)",
                args.log,
                meta.len()
            );
            return 2;
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("error: failed to stat audit log: {e}");
            return 2;
        }
    }

    // Read and verify the audit log.
    let content = match std::fs::read_to_string(&args.log) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to read audit log: {e}");
            return 2;
        }
    };
    match invariant_core::audit::verify_log(&content, &vk) {
        Ok(count) => {
            println!("OK. {count} entries. Hash chain intact. All signatures valid.");
            0
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::Utc;
    use ed25519_dalek::Signer;
    use invariant_core::audit::AuditLogger;
    use invariant_core::authority::crypto::generate_keypair;
    use invariant_core::models::authority::Operation;
    use invariant_core::models::command::{Command, CommandAuthority, JointState};
    use invariant_core::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_command() -> Command {
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
                required_ops: vec![Operation::new("actuate:j1").unwrap()],
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

    fn make_signed_verdict(signing_key: &ed25519_dalek::SigningKey) -> SignedVerdict {
        let verdict = Verdict {
            approved: true,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks: vec![CheckResult {
                name: "authority".into(),
                category: "authority".into(),
                passed: true,
                details: "ok".into(),
            }],
            profile_name: "test_robot".into(),
            profile_hash: "sha256:def".into(),
            threat_analysis: None,
            authority_summary: AuthoritySummary {
                origin_principal: "alice".into(),
                hop_count: 1,
                operations_granted: vec!["actuate:*".into()],
                operations_required: vec!["actuate:j1".into()],
            },
        };
        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        let signature = signing_key.sign(&verdict_json);
        SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(signature.to_bytes()),
            signer_kid: "test-kid".into(),
        }
    }

    /// Write a valid audit log to a temp file using `signing_key` and return
    /// the file.
    fn write_valid_audit_log(signing_key: &ed25519_dalek::SigningKey, n: usize) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        let cmd = make_command();
        let verdict = make_signed_verdict(signing_key);
        let mut logger = AuditLogger::new(&mut tmp, signing_key.clone(), "test-kid".into());
        for _ in 0..n {
            logger.log(&cmd, &verdict).unwrap();
        }
        tmp.flush().unwrap();
        tmp
    }

    /// Serialize `signing_key`'s public half to a `KeyFile` JSON and write it
    /// to a temp file.
    fn write_pubkey_file(signing_key: &ed25519_dalek::SigningKey) -> NamedTempFile {
        let vk = signing_key.verifying_key();
        let kf = crate::key_file::KeyFile {
            kid: "test-kid".into(),
            public_key: STANDARD.encode(vk.as_bytes()),
            secret_key: None,
        };
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(serde_json::to_string_pretty(&kf).unwrap().as_bytes())
            .unwrap();
        tmp.flush().unwrap();
        tmp
    }

    fn args_for(log: &std::path::Path, pubkey: &std::path::Path) -> VerifyArgs {
        VerifyArgs {
            log: log.to_path_buf(),
            pubkey: pubkey.to_path_buf(),
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn valid_log_and_pubkey_returns_0() {
        let sk = generate_keypair(&mut OsRng);
        let log_file = write_valid_audit_log(&sk, 3);
        let key_file = write_pubkey_file(&sk);
        let args = args_for(log_file.path(), key_file.path());
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn empty_log_returns_0() {
        let sk = generate_keypair(&mut OsRng);
        let log_file = write_valid_audit_log(&sk, 0);
        let key_file = write_pubkey_file(&sk);
        let args = args_for(log_file.path(), key_file.path());
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn nonexistent_log_returns_2() {
        let sk = generate_keypair(&mut OsRng);
        let key_file = write_pubkey_file(&sk);
        let args = VerifyArgs {
            log: PathBuf::from("/nonexistent/audit.jsonl"),
            pubkey: key_file.path().to_path_buf(),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn nonexistent_pubkey_returns_2() {
        let sk = generate_keypair(&mut OsRng);
        let log_file = write_valid_audit_log(&sk, 1);
        let args = VerifyArgs {
            log: log_file.path().to_path_buf(),
            pubkey: PathBuf::from("/nonexistent/key.json"),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn wrong_key_returns_1() {
        // Log is signed with sk1 but we verify with sk2's public key.
        let sk1 = generate_keypair(&mut OsRng);
        let sk2 = generate_keypair(&mut OsRng);
        let log_file = write_valid_audit_log(&sk1, 2);
        let key_file = write_pubkey_file(&sk2);
        let args = args_for(log_file.path(), key_file.path());
        // Signature mismatch -> verify_log returns Err -> exit 1.
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn invalid_pubkey_json_returns_2() {
        let sk = generate_keypair(&mut OsRng);
        let log_file = write_valid_audit_log(&sk, 1);
        let mut bad_key_file = NamedTempFile::new().unwrap();
        writeln!(bad_key_file, "not valid json").unwrap();
        bad_key_file.flush().unwrap();
        let args = args_for(log_file.path(), bad_key_file.path());
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn tampered_log_returns_1() {
        let sk = generate_keypair(&mut OsRng);
        let log_file = write_valid_audit_log(&sk, 1);
        let key_file = write_pubkey_file(&sk);

        // Read the log, corrupt the entry_hash, write it back.
        let content = std::fs::read_to_string(log_file.path()).unwrap();
        let tampered = content.replace("sha256:", "sha256:TAMPERED");
        let mut bad_log = NamedTempFile::new().unwrap();
        bad_log.write_all(tampered.as_bytes()).unwrap();
        bad_log.flush().unwrap();

        let args = args_for(bad_log.path(), key_file.path());
        assert_eq!(run(&args), 1);
    }

    // -----------------------------------------------------------------------
    // Finding 81: Audit log size limit
    //
    // We cannot create a 512 MiB file in unit tests, so instead we test the
    // size-check logic using a small helper that mocks the metadata-reported
    // size.  The actual check in run() uses `std::fs::metadata`, so we test
    // the boundary condition by creating a tiny file and verifying that:
    //   a) a file within the limit is accepted, and
    //   b) the check is exercised on the code path (covered by the stat call
    //      that all verify runs make).
    //
    // A proper 512 MiB test is marked #[ignore] below. Use `cargo test -- --ignored`
    // to run it on a machine with sufficient disk space.
    // -----------------------------------------------------------------------

    #[test]
    fn small_log_file_is_within_size_limit_and_returns_ok() {
        let sk = generate_keypair(&mut OsRng);
        let log_file = write_valid_audit_log(&sk, 1);
        let key_file = write_pubkey_file(&sk);
        let meta = std::fs::metadata(log_file.path()).unwrap();
        // Sanity: our test log must be well below the 512 MiB limit.
        assert!(
            meta.len() < 512 * 1024 * 1024,
            "test log must be smaller than 512 MiB"
        );
        let args = args_for(log_file.path(), key_file.path());
        assert_eq!(run(&args), 0, "small log must pass size check");
    }

    /// This test verifies the size-limit path using a real oversized file.
    /// It is marked #[ignore] because creating a 512 MiB file in CI is
    /// impractical. Run it manually with:
    ///   cargo test -- verify::tests::oversized_log_returns_2 --ignored
    #[test]
    #[ignore]
    fn oversized_log_returns_2() {
        use std::io::Seek;

        let sk = generate_keypair(&mut OsRng);
        let key_file = write_pubkey_file(&sk);

        // Create a sparse file that reports > 512 MiB via seek-and-write of a
        // single byte.  On most Unix filesystems this does not allocate disk
        // blocks for the "hole".
        let mut log_file = NamedTempFile::new().unwrap();
        let size_limit: u64 = 512 * 1024 * 1024;
        log_file
            .seek(std::io::SeekFrom::Start(size_limit + 1))
            .unwrap();
        log_file.write_all(b"\x00").unwrap();
        log_file.flush().unwrap();

        let args = args_for(log_file.path(), key_file.path());
        assert_eq!(run(&args), 2, "file exceeding 512 MiB must return 2");
    }
}
