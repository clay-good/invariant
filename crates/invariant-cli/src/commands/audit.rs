use clap::Args;
use std::collections::VecDeque;
use std::io::BufRead;
use std::path::PathBuf;

use invariant_core::models::audit::SignedAuditEntry;

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
    #[arg(long)]
    pub last: Option<usize>,
}

pub fn run(args: &AuditArgs) -> i32 {
    let file = match std::fs::File::open(&args.log) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: failed to open {:?}: {e}", args.log);
            return 2;
        }
    };
    let reader = std::io::BufReader::new(file);

    if let Some(last_n) = args.last {
        // Ring-buffer approach: keep only the last N entries so we never
        // hold the full file in memory.
        let mut ring: VecDeque<SignedAuditEntry> = VecDeque::with_capacity(last_n);
        for (i, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: I/O error at line {}: {e}", i + 1);
                    return 2;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<SignedAuditEntry>(trimmed) {
                Ok(entry) => {
                    if ring.len() == last_n {
                        ring.pop_front();
                    }
                    ring.push_back(entry);
                }
                Err(e) => {
                    eprintln!("error: parse error at line {}: {e}", i + 1);
                    return 2;
                }
            }
        }
        for entry in &ring {
            match serde_json::to_string_pretty(entry) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("error: serialization failed: {e}");
                    return 2;
                }
            }
        }
    } else {
        // Stream all entries; never accumulate the full log.
        for (i, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: I/O error at line {}: {e}", i + 1);
                    return 2;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<SignedAuditEntry>(trimmed) {
                Ok(entry) => match serde_json::to_string_pretty(&entry) {
                    Ok(json) => println!("{json}"),
                    Err(e) => {
                        eprintln!("error: serialization failed: {e}");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("error: parse error at line {}: {e}", i + 1);
                    return 2;
                }
            }
        }
    }

    0
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

    fn make_test_command() -> Command {
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
        }
    }

    fn make_test_signed_verdict(signing_key: &ed25519_dalek::SigningKey) -> SignedVerdict {
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

    /// Write `n` valid audit JSONL entries to `file` using `AuditLogger`.
    fn write_audit_entries(file: &mut NamedTempFile, n: usize) {
        let signing_key = generate_keypair(&mut OsRng);
        let cmd = make_test_command();
        let verdict = make_test_signed_verdict(&signing_key);

        let mut logger = AuditLogger::new(&mut *file, signing_key, "test-kid".into());
        for _ in 0..n {
            logger.log(&cmd, &verdict).unwrap();
        }
        file.flush().unwrap();
    }

    fn args_for(path: &std::path::Path, last: Option<usize>) -> AuditArgs {
        AuditArgs {
            log: path.to_path_buf(),
            last,
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn valid_multi_entry_no_last_returns_0() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_audit_entries(&mut tmp, 3);
        let args = args_for(tmp.path(), None);
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn last_1_returns_0() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_audit_entries(&mut tmp, 3);
        let args = args_for(tmp.path(), Some(1));
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn last_0_returns_0() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_audit_entries(&mut tmp, 3);
        // last=0 means keep zero entries in the ring buffer; nothing is printed
        // but the file still parses successfully.
        let args = args_for(tmp.path(), Some(0));
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn nonexistent_path_returns_2() {
        let args = AuditArgs {
            log: PathBuf::from("/nonexistent/path/audit.jsonl"),
            last: None,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn invalid_json_line_returns_2() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "this is not valid json").unwrap();
        tmp.flush().unwrap();
        let args = args_for(tmp.path(), None);
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn empty_file_returns_0() {
        let tmp = NamedTempFile::new().unwrap();
        let args = args_for(tmp.path(), None);
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn invalid_json_line_with_last_returns_2() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "not json").unwrap();
        tmp.flush().unwrap();
        let args = args_for(tmp.path(), Some(5));
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn last_larger_than_entry_count_returns_0() {
        // last > actual entries — ring never fills; all entries are returned.
        let mut tmp = NamedTempFile::new().unwrap();
        write_audit_entries(&mut tmp, 2);
        let args = args_for(tmp.path(), Some(10));
        assert_eq!(run(&args), 0);
    }

    // -----------------------------------------------------------------------
    // Finding 58: Output content assertions
    //
    // We test output content by parsing the JSONL log file directly and
    // verifying that the entries contain the expected fields rather than
    // capturing stdout (which would require refactoring the run() function).
    // -----------------------------------------------------------------------

    /// Parse all audit entries from a JSONL temp file and return them.
    fn parse_entries(file: &NamedTempFile) -> Vec<SignedAuditEntry> {
        use std::io::BufRead;
        let f = std::fs::File::open(file.path()).unwrap();
        let reader = std::io::BufReader::new(f);
        reader
            .lines()
            .filter_map(|l| {
                let line = l.unwrap();
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(serde_json::from_str::<SignedAuditEntry>(&trimmed).unwrap())
                }
            })
            .collect()
    }

    #[test]
    fn audit_entries_contain_expected_profile_name() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_audit_entries(&mut tmp, 2);

        let entries = parse_entries(&tmp);
        assert_eq!(entries.len(), 2, "should have 2 entries");
        for entry in &entries {
            // Each entry wraps a SignedVerdict; verify the profile_name field.
            assert_eq!(
                entry.entry.verdict.verdict.profile_name, "test_robot",
                "entry profile_name must equal the test verdict profile_name"
            );
        }
    }

    #[test]
    fn audit_entries_contain_signer_kid() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_audit_entries(&mut tmp, 1);

        let entries = parse_entries(&tmp);
        assert_eq!(entries.len(), 1);
        // signer_kid on the SignedAuditEntry is the audit logger's kid.
        assert_eq!(
            entries[0].signer_kid, "test-kid",
            "SignedAuditEntry signer_kid must be 'test-kid'"
        );
    }

    #[test]
    fn audit_entries_have_non_empty_entry_hash() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_audit_entries(&mut tmp, 1);

        let entries = parse_entries(&tmp);
        assert_eq!(entries.len(), 1);
        // entry_hash is on the AuditEntry (inside .entry).
        assert!(
            !entries[0].entry.entry_hash.is_empty(),
            "entry_hash must not be empty"
        );
        assert!(
            entries[0].entry.entry_hash.starts_with("sha256:"),
            "entry_hash must start with 'sha256:'"
        );
    }

    #[test]
    fn audit_entries_have_non_empty_entry_signature() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_audit_entries(&mut tmp, 1);

        let entries = parse_entries(&tmp);
        assert_eq!(entries.len(), 1);
        assert!(
            !entries[0].entry_signature.is_empty(),
            "entry_signature must not be empty"
        );
    }

    #[test]
    fn audit_entries_approved_flag_matches_verdict() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_audit_entries(&mut tmp, 1);

        let entries = parse_entries(&tmp);
        assert_eq!(entries.len(), 1);
        // The test verdict is always approved=true.
        assert!(
            entries[0].entry.verdict.verdict.approved,
            "test verdict must be approved"
        );
    }
}
