//! `differential` subcommand: compare two signed verdicts and surface any
//! divergence in approval status or per-check pass/fail.
//!
//! This delegates the heavy lifting to
//! [`invariant_biosynthesis::differential::compare_verdicts`]. Two
//! verdict-file paths must agree on `command_hash` (otherwise the inputs
//! refer to different bundles and a comparison is meaningless).
//!
//! Exit codes:
//! - 0 — both verdicts fully agree
//! - 1 — divergence detected (approval mismatch or check disagreement)
//! - 2 — usage error
//! - 3 — internal error (I/O, parse, hash mismatch)

use std::fs;
use std::path::PathBuf;

use clap::Args;

use invariant_biosynthesis::differential::compare_verdicts;
use invariant_biosynthesis::models::verdict::SignedVerdict;

#[derive(Args, Debug)]
pub struct DifferentialArgs {
    /// First signed verdict JSON.
    #[arg(long, value_name = "VERDICT_A")]
    pub a: PathBuf,
    /// Second signed verdict JSON.
    #[arg(long, value_name = "VERDICT_B")]
    pub b: PathBuf,
    /// Optional output path for the differential report JSON. When omitted
    /// the report is written to stdout.
    #[arg(long, value_name = "REPORT")]
    pub output: Option<PathBuf>,
}

pub fn run(args: &DifferentialArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            3
        }
    }
}

fn run_inner(args: &DifferentialArgs) -> Result<i32, String> {
    let a: SignedVerdict = load_verdict(&args.a)?;
    let b: SignedVerdict = load_verdict(&args.b)?;

    if a.verdict.command_hash != b.verdict.command_hash {
        return Err(format!(
            "command_hash mismatch: a={} b={} — refusing to compare",
            a.verdict.command_hash, b.verdict.command_hash
        ));
    }

    let result = compare_verdicts(&a.verdict, &b.verdict);

    eprintln!(
        "differential: approval_agrees={} a_approved={} b_approved={} agreeing_checks={}/{} disagreements={}",
        result.approval_agrees,
        result.instance_a_approved,
        result.instance_b_approved,
        result.agreeing_checks,
        result.total_checks,
        result.check_disagreements.len()
    );
    for d in &result.check_disagreements {
        eprintln!(
            "  - [{}] {}: a={} b={} | a_details={:?} b_details={:?}",
            d.category,
            d.check_name,
            if d.instance_a_passed { "PASS" } else { "FAIL" },
            if d.instance_b_passed { "PASS" } else { "FAIL" },
            d.instance_a_details,
            d.instance_b_details,
        );
    }

    let json =
        serde_json::to_string_pretty(&result).map_err(|e| format!("serialize report: {e}"))?;
    match &args.output {
        Some(path) => {
            fs::write(path, &json).map_err(|e| format!("write report {}: {e}", path.display()))?
        }
        None => println!("{json}"),
    }

    if result.fully_agrees() {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn load_verdict(path: &PathBuf) -> Result<SignedVerdict, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use invariant_biosynthesis::models::verdict::{
        AuthoritySummary, CheckResult, SignedVerdict, Verdict,
    };
    use tempfile::TempDir;

    fn signed(checks: Vec<CheckResult>, approved: bool, hash: &str) -> SignedVerdict {
        let v = Verdict {
            approved,
            command_hash: hash.to_string(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks,
            profile_name: "p".into(),
            profile_hash: "sha256:p".into(),
            authority_summary: AuthoritySummary {
                origin_principal: "x".into(),
                hop_count: 0,
                operations_granted: vec![],
                operations_required: vec![],
            },
            threat_analysis: None,
        };
        SignedVerdict {
            verdict: v,
            verdict_signature: String::new(),
            signer_kid: "kid".into(),
        }
    }

    fn write(dir: &TempDir, name: &str, sv: &SignedVerdict) -> PathBuf {
        let p = dir.path().join(name);
        fs::write(&p, serde_json::to_vec_pretty(sv).unwrap()).unwrap();
        p
    }

    #[test]
    fn agreeing_verdicts_exit_zero() {
        let dir = TempDir::new().unwrap();
        let v = signed(
            vec![CheckResult::new("authority", "authority", true, "ok")],
            true,
            "sha256:abc",
        );
        let a = write(&dir, "a.json", &v);
        let b = write(&dir, "b.json", &v);
        let args = DifferentialArgs { a, b, output: None };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn approval_divergence_exits_one() {
        let dir = TempDir::new().unwrap();
        let va = signed(vec![], true, "sha256:abc");
        let vb = signed(vec![], false, "sha256:abc");
        let a = write(&dir, "a.json", &va);
        let b = write(&dir, "b.json", &vb);
        let out = dir.path().join("report.json");
        let args = DifferentialArgs {
            a,
            b,
            output: Some(out.clone()),
        };
        assert_eq!(run(&args), 1);
        let raw = fs::read_to_string(&out).unwrap();
        assert!(raw.contains("\"approval_agrees\": false"));
    }

    #[test]
    fn check_divergence_exits_one() {
        let dir = TempDir::new().unwrap();
        let va = signed(
            vec![CheckResult::new(
                "d1_select_agent",
                "invariant.dna",
                true,
                "ok",
            )],
            true,
            "sha256:abc",
        );
        let vb = signed(
            vec![CheckResult::new(
                "d1_select_agent",
                "invariant.dna",
                false,
                "matched X",
            )],
            true,
            "sha256:abc",
        );
        let a = write(&dir, "a.json", &va);
        let b = write(&dir, "b.json", &vb);
        let args = DifferentialArgs { a, b, output: None };
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn hash_mismatch_returns_internal_error() {
        let dir = TempDir::new().unwrap();
        let va = signed(vec![], true, "sha256:aaa");
        let vb = signed(vec![], true, "sha256:bbb");
        let a = write(&dir, "a.json", &va);
        let b = write(&dir, "b.json", &vb);
        let args = DifferentialArgs { a, b, output: None };
        assert_eq!(run(&args), 3);
    }

    #[test]
    fn missing_file_returns_internal_error() {
        let args = DifferentialArgs {
            a: PathBuf::from("/nonexistent/a.json"),
            b: PathBuf::from("/nonexistent/b.json"),
            output: None,
        };
        assert_eq!(run(&args), 3);
    }
}
