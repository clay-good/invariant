//! `invariant verify-package` — deep proof package verification (Section 20.2).
//!
//! Verifies the integrity of a proof package by:
//! 1. Parsing the manifest and validating its schema
//! 2. Verifying SHA-256 hashes of every file listed in the manifest
//! 3. Checking directory structure completeness
//! 4. Validating summary statistics consistency
//! 5. Computing Merkle root from audit log if present

use clap::Args;
use std::path::PathBuf;

use invariant_core::proof_package::ProofPackageManifest;
use invariant_core::util::sha256_hex;

#[derive(Args)]
pub struct VerifyPackageArgs {
    /// Path to the proof package directory.
    #[arg(long, value_name = "PACKAGE_DIR")]
    pub path: PathBuf,
}

/// Result of a single verification check.
struct Check {
    name: String,
    passed: bool,
    detail: String,
}

impl Check {
    fn pass(name: &str, detail: impl std::fmt::Display) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            detail: detail.to_string(),
        }
    }
    fn fail(name: &str, detail: impl std::fmt::Display) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            detail: detail.to_string(),
        }
    }
}

pub fn run(args: &VerifyPackageArgs) -> i32 {
    if !args.path.is_dir() {
        eprintln!("error: package directory {:?} does not exist", args.path);
        return 2;
    }

    let mut checks: Vec<Check> = Vec::new();

    // 1. Parse manifest.
    let manifest_path = args.path.join("manifest.json");
    let manifest = match std::fs::read_to_string(&manifest_path) {
        Ok(data) => match serde_json::from_str::<ProofPackageManifest>(&data) {
            Ok(m) => {
                checks.push(Check::pass(
                    "Manifest",
                    format!(
                        "valid (campaign: {}, profile: {})",
                        m.campaign_name, m.profile_name
                    ),
                ));
                Some(m)
            }
            Err(e) => {
                checks.push(Check::fail("Manifest", format!("parse error: {e}")));
                None
            }
        },
        Err(_) => {
            checks.push(Check::fail("Manifest", "manifest.json missing"));
            None
        }
    };

    // 2. Verify file hashes from manifest.
    if let Some(ref m) = manifest {
        let (hash_ok, hash_fail) = verify_file_hashes(&args.path, m);
        if hash_fail == 0 {
            checks.push(Check::pass(
                "File integrity",
                format!("{hash_ok} files verified, 0 mismatches"),
            ));
        } else {
            checks.push(Check::fail(
                "File integrity",
                format!(
                    "{hash_fail} of {} files have hash mismatches",
                    hash_ok + hash_fail
                ),
            ));
        }
    } else {
        checks.push(Check::fail("File integrity", "skipped (no manifest)"));
    }

    // 3. Directory structure completeness.
    let required_dirs = ["campaign", "results", "adversarial", "integrity"];
    let mut dirs_present = 0;
    for dir_name in &required_dirs {
        if args.path.join(dir_name).is_dir() {
            dirs_present += 1;
        }
    }
    if dirs_present == required_dirs.len() {
        checks.push(Check::pass(
            "Directory structure",
            format!(
                "{dirs_present}/{} required directories present",
                required_dirs.len()
            ),
        ));
    } else {
        checks.push(Check::fail(
            "Directory structure",
            format!(
                "{dirs_present}/{} required directories present",
                required_dirs.len()
            ),
        ));
    }

    // 4. Audit log presence.
    let audit_path = args.path.join("results").join("audit.jsonl");
    if audit_path.exists() {
        let size = std::fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);
        let lines = std::fs::read_to_string(&audit_path)
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
        checks.push(Check::pass(
            "Audit log",
            format!("{lines} entries, {size} bytes"),
        ));
    } else {
        checks.push(Check::fail("Audit log", "results/audit.jsonl missing"));
    }

    // 5. Summary statistics consistency.
    let summary_path = args.path.join("results").join("summary.json");
    if let Some(ref m) = manifest {
        let s = &m.summary;
        let total_ok = s.total_commands == s.commands_approved + s.commands_rejected;
        let escape_ok = s.violation_escapes == 0;
        if total_ok && escape_ok {
            checks.push(Check::pass(
                "Summary statistics",
                format!(
                    "{} commands ({} approved, {} rejected), 0 escapes",
                    s.total_commands, s.commands_approved, s.commands_rejected,
                ),
            ));
        } else if !total_ok {
            checks.push(Check::fail(
                "Summary statistics",
                format!(
                    "total {} != approved {} + rejected {}",
                    s.total_commands, s.commands_approved, s.commands_rejected,
                ),
            ));
        } else {
            checks.push(Check::fail(
                "Summary statistics",
                format!("{} violation escapes detected", s.violation_escapes),
            ));
        }
    } else if summary_path.exists() {
        checks.push(Check::pass(
            "Summary statistics",
            "present (no manifest to cross-check)",
        ));
    } else {
        checks.push(Check::fail(
            "Summary statistics",
            "results/summary.json missing",
        ));
    }

    // 6. Adversarial reports.
    let adversarial_dir = args.path.join("adversarial");
    if adversarial_dir.is_dir() {
        let count = std::fs::read_dir(&adversarial_dir)
            .map(|d| d.filter(|e| e.is_ok()).count())
            .unwrap_or(0);
        if count > 0 {
            checks.push(Check::pass(
                "Adversarial reports",
                format!("{count} report files"),
            ));
        } else {
            checks.push(Check::fail("Adversarial reports", "directory empty"));
        }
    } else {
        checks.push(Check::fail("Adversarial reports", "directory missing"));
    }

    // 7. Public keys.
    let keys_path = args.path.join("integrity").join("public_keys.json");
    if keys_path.exists() {
        checks.push(Check::pass("Public keys", "present"));
    } else {
        checks.push(Check::fail(
            "Public keys",
            "integrity/public_keys.json missing",
        ));
    }

    // 8. Binary hash.
    let binary_hash_path = args.path.join("integrity").join("binary_hash.txt");
    if let Some(ref m) = manifest {
        if binary_hash_path.exists() {
            let on_disk = std::fs::read_to_string(&binary_hash_path).unwrap_or_default();
            if on_disk.trim() == m.binary_hash {
                checks.push(Check::pass(
                    "Binary hash",
                    format!(
                        "matches manifest ({})",
                        &m.binary_hash[..20.min(m.binary_hash.len())]
                    ),
                ));
            } else {
                checks.push(Check::fail(
                    "Binary hash",
                    "integrity/binary_hash.txt does not match manifest",
                ));
            }
        } else {
            checks.push(Check::fail(
                "Binary hash",
                "integrity/binary_hash.txt missing",
            ));
        }
    } else if binary_hash_path.exists() {
        checks.push(Check::pass(
            "Binary hash",
            "present (no manifest to cross-check)",
        ));
    } else {
        checks.push(Check::fail(
            "Binary hash",
            "integrity/binary_hash.txt missing",
        ));
    }

    // 9. Merkle root from audit log.
    if audit_path.exists() {
        match std::fs::read_to_string(&audit_path) {
            Ok(content) if !content.trim().is_empty() => {
                if let Some(root) = invariant_core::replication::merkle_root_from_log(&content) {
                    let merkle_path = args.path.join("integrity").join("merkle_root.txt");
                    if merkle_path.exists() {
                        let on_disk = std::fs::read_to_string(&merkle_path).unwrap_or_default();
                        if on_disk.trim() == root {
                            checks.push(Check::pass(
                                "Merkle root",
                                "computed root matches integrity/merkle_root.txt",
                            ));
                        } else {
                            checks.push(Check::fail(
                                "Merkle root",
                                "computed root does NOT match integrity/merkle_root.txt",
                            ));
                        }
                    } else {
                        checks.push(Check::pass(
                            "Merkle root",
                            format!("computed: {}...", &root[..20.min(root.len())]),
                        ));
                    }
                } else {
                    checks.push(Check::pass("Merkle root", "no entries to hash"));
                }
            }
            _ => {
                checks.push(Check::pass("Merkle root", "audit log empty, skipped"));
            }
        }
    }

    // Print results.
    println!();
    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();

    for check in &checks {
        let symbol = if check.passed { "\u{2713}" } else { "\u{2717}" };
        println!("  {symbol} {}: {}", check.name, check.detail);
    }

    println!();
    if passed == total {
        println!("PACKAGE VERIFIED. {passed}/{total} checks passed.");
        0
    } else {
        let failed = total - passed;
        println!("PACKAGE VERIFICATION FAILED. {passed}/{total} checks passed, {failed} failed.");
        1
    }
}

/// Verify SHA-256 hashes of all files listed in the manifest.
/// Returns (files_ok, files_failed).
fn verify_file_hashes(base: &std::path::Path, manifest: &ProofPackageManifest) -> (usize, usize) {
    let mut ok = 0usize;
    let mut failed = 0usize;

    for (rel_path, expected_hash) in &manifest.file_hashes {
        let full_path = base.join(rel_path);
        match std::fs::read(&full_path) {
            Ok(bytes) => {
                let actual = sha256_hex(&bytes);
                if actual == *expected_hash {
                    ok += 1;
                } else {
                    eprintln!(
                        "  hash mismatch: {rel_path} (expected {}, got {})",
                        &expected_hash[..20.min(expected_hash.len())],
                        &actual[..20.min(actual.len())]
                    );
                    failed += 1;
                }
            }
            Err(_) => {
                eprintln!("  missing file: {rel_path}");
                failed += 1;
            }
        }
    }

    (ok, failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use invariant_core::proof_package::{assemble, CampaignSummary, PackageInputs};
    use std::collections::HashMap;

    #[test]
    fn nonexistent_dir_returns_2() {
        let args = VerifyPackageArgs {
            path: PathBuf::from("/nonexistent/package"),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn empty_dir_returns_1() {
        let dir = tempfile::tempdir().unwrap();
        let args = VerifyPackageArgs {
            path: dir.path().to_path_buf(),
        };
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn assembled_package_verifies_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("proof-package");

        // Create a fake audit log.
        let audit_path = dir.path().join("audit.jsonl");
        std::fs::write(&audit_path, "{\"entry\":1}\n{\"entry\":2}\n").unwrap();

        // Create a fake adversarial report.
        let adv_path = dir.path().join("protocol_report.json");
        std::fs::write(&adv_path, r#"{"attacks":100,"escapes":0}"#).unwrap();

        // Create fake public keys.
        let keys_path = dir.path().join("public_keys.json");
        std::fs::write(&keys_path, r#"{"keys":[]}"#).unwrap();

        let summary = CampaignSummary::compute(1000, 950, 50, 0, 100, 0, 100.0);

        let mut adversarial = HashMap::new();
        adversarial.insert("protocol_report.json".into(), adv_path);

        let inputs = PackageInputs {
            campaign_config: None,
            profile: None,
            audit_log: Some(audit_path),
            adversarial_reports: adversarial,
            compliance_mappings: HashMap::new(),
            public_keys: Some(keys_path),
            campaign_name: "verify_test".into(),
            profile_name: "test_robot".into(),
            binary_hash: "sha256:abc123".into(),
            summary,
        };

        assemble(&inputs, &output).unwrap();

        let args = VerifyPackageArgs {
            path: output.clone(),
        };
        assert_eq!(
            run(&args),
            0,
            "assembled package should verify successfully"
        );
    }

    #[test]
    fn tampered_file_fails_hash_check() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("proof-package");

        let summary = CampaignSummary::compute(100, 90, 10, 0, 0, 0, 100.0);

        let inputs = PackageInputs {
            campaign_config: None,
            profile: None,
            audit_log: None,
            adversarial_reports: HashMap::new(),
            compliance_mappings: HashMap::new(),
            public_keys: None,
            campaign_name: "tamper_test".into(),
            profile_name: "test".into(),
            binary_hash: "sha256:original".into(),
            summary,
        };

        assemble(&inputs, &output).unwrap();

        // Tamper with the summary file.
        let summary_path = output.join("results/summary.json");
        std::fs::write(&summary_path, r#"{"tampered": true}"#).unwrap();

        let args = VerifyPackageArgs {
            path: output.clone(),
        };
        // Should fail because summary.json hash no longer matches manifest.
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn package_with_escapes_fails_summary_check() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("proof-package");

        // Summary with escapes.
        let summary = CampaignSummary::compute(1000, 950, 50, 3, 100, 2, 100.0);

        let inputs = PackageInputs {
            campaign_config: None,
            profile: None,
            audit_log: None,
            adversarial_reports: HashMap::new(),
            compliance_mappings: HashMap::new(),
            public_keys: None,
            campaign_name: "escape_test".into(),
            profile_name: "test".into(),
            binary_hash: "sha256:abc".into(),
            summary,
        };

        assemble(&inputs, &output).unwrap();

        let args = VerifyPackageArgs {
            path: output.clone(),
        };
        // Should fail because violation_escapes > 0.
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn verify_file_hashes_detects_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        std::fs::create_dir_all(base.join("results")).unwrap();
        std::fs::write(base.join("results/test.txt"), "original").unwrap();

        let correct_hash = sha256_hex(b"original");
        let mut file_hashes = HashMap::new();
        file_hashes.insert("results/test.txt".into(), correct_hash);

        let manifest = ProofPackageManifest {
            version: "1.0.0".into(),
            generated_at: chrono::Utc::now(),
            campaign_name: "test".into(),
            profile_name: "test".into(),
            profile_hash: String::new(),
            binary_hash: String::new(),
            invariant_version: "0.1.0".into(),
            summary: CampaignSummary::compute(0, 0, 0, 0, 0, 0, 100.0),
            file_hashes,
        };

        // Before tampering: should pass.
        let (ok, fail) = verify_file_hashes(base, &manifest);
        assert_eq!(ok, 1);
        assert_eq!(fail, 0);

        // After tampering: should fail.
        std::fs::write(base.join("results/test.txt"), "tampered").unwrap();
        let (ok, fail) = verify_file_hashes(base, &manifest);
        assert_eq!(ok, 0);
        assert_eq!(fail, 1);
    }
}
