//! `campaign` subcommand: run a YAML campaign through the sim harness.
//!
//! Loads the campaign, executes every scenario via
//! [`invariant_sim::biosynthesis::run_campaign`], and emits a structured
//! report.
//!
//! Exit codes:
//! - 0 — all scenarios matched expected outcome (no errors)
//! - 1 — one or more mismatches (expected != actual)
//! - 2 — one or more scenarios errored before producing a verdict
//! - 3 — internal error (campaign load / parse / write)

use std::fs;
use std::path::PathBuf;

use clap::Args;

use invariant_sim::biosynthesis::{load_campaign, run_campaign as sim_run, CampaignReport};

#[derive(Args, Debug)]
pub struct CampaignArgs {
    /// Path to the campaign YAML file.
    #[arg(long, value_name = "CAMPAIGN")]
    pub campaign: PathBuf,
    /// Output path for the JSON report. Stdout when omitted.
    #[arg(long, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,
    /// Render output as plain text instead of JSON.
    #[arg(long, default_value_t = false)]
    pub text: bool,
}

pub fn run(args: &CampaignArgs) -> i32 {
    let campaign = match load_campaign(&args.campaign) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 3;
        }
    };
    let base = args
        .campaign
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let report = sim_run(&campaign, &base);

    eprintln!(
        "campaign {}: {}/{} matched, {} mismatches, {} errors, {} ms",
        report.name,
        report.matches,
        report.scenarios.len(),
        report.mismatches,
        report.errors,
        report.total_duration_ms
    );
    for s in &report.scenarios {
        let tag = if s.error.is_some() {
            "ERROR"
        } else if s.matched {
            "OK"
        } else {
            "MISMATCH"
        };
        eprintln!(
            "  [{tag}] {} expected={:?} approved={} ({} ms){}",
            s.name,
            s.expected,
            s.approved,
            s.duration_ms,
            s.error
                .as_deref()
                .map(|e| format!(" — {e}"))
                .unwrap_or_default()
        );
    }

    let body = if args.text {
        render_text(&report)
    } else {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: serialize report: {e}");
                return 3;
            }
        }
    };
    match &args.output {
        Some(p) => {
            if let Err(e) = fs::write(p, &body) {
                eprintln!("error: write {}: {e}", p.display());
                return 3;
            }
        }
        None => println!("{body}"),
    }

    if report.errors > 0 {
        2
    } else if report.mismatches > 0 {
        1
    } else {
        0
    }
}

fn render_text(r: &CampaignReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("campaign {}\n", r.name));
    out.push_str(&format!(
        "  totals: matches={} mismatches={} errors={} duration_ms={}\n",
        r.matches, r.mismatches, r.errors, r.total_duration_ms
    ));
    for s in &r.scenarios {
        out.push_str(&format!(
            "  - {}: matched={} expected={:?} approved={}\n",
            s.name, s.matched, s.expected, s.approved
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::SigningKey;
    use invariant_biosynthesis::screening::{sign_body_for_tests, HazardDatabaseBody, HazardEntry};
    use rand::rngs::OsRng;
    use std::path::Path;
    use tempfile::TempDir;

    fn write_db(dir: &Path, dna_pattern: &str) {
        let sk = SigningKey::generate(&mut OsRng);
        let body = HazardDatabaseBody {
            schema_version: 1,
            db_version: 1,
            dna_signatures: if dna_pattern.is_empty() {
                vec![]
            } else {
                vec![HazardEntry {
                    id: "x".into(),
                    label: "x".into(),
                    hazard_class: "select-agent".into(),
                    pattern: dna_pattern.into(),
                }]
            },
            peptide_signatures: vec![],
            chemical_signatures: vec![],
        };
        let signed = sign_body_for_tests(&body, "issuer-cli", &sk);
        fs::write(
            dir.join("db.json"),
            serde_json::to_vec_pretty(&signed).unwrap(),
        )
        .unwrap();
        let pub_kf = serde_json::json!({
            "kid": "issuer-cli",
            "public_key": STANDARD.encode(sk.verifying_key().as_bytes()),
        });
        fs::write(
            dir.join("issuer.json"),
            serde_json::to_vec_pretty(&pub_kf).unwrap(),
        )
        .unwrap();
    }

    fn write_dna_bundle(path: &Path, sequence: &str) {
        let bundle = serde_json::json!({
            "timestamp": "2026-04-25T12:00:00Z",
            "source": "cli-test",
            "sequence": 1,
            "payload": {"kind": "dna", "sequence": sequence},
            "delta_time": 0.0,
            "authority": {"pca_chain": "", "required_ops": []},
            "metadata": {}
        });
        fs::write(path, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
    }

    fn write_yaml(dir: &Path, name: &str, expect: &str) {
        let yaml = format!(
            "name: t\nscenarios:\n  - name: {name}\n    bundle: bundle.json\n    hazard_db: db.json\n    hazard_db_issuer_pub: issuer.json\n    expect: {expect}\n"
        );
        fs::write(dir.join("campaign.yaml"), yaml).unwrap();
    }

    #[test]
    fn campaign_match_returns_zero() {
        let dir = TempDir::new().unwrap();
        write_db(dir.path(), "");
        write_dna_bundle(&dir.path().join("bundle.json"), "ATGAAA");
        write_yaml(dir.path(), "rejected-by-empty-pca", "rejected");
        let args = CampaignArgs {
            campaign: dir.path().join("campaign.yaml"),
            output: None,
            text: false,
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn campaign_mismatch_returns_one() {
        let dir = TempDir::new().unwrap();
        write_db(dir.path(), "");
        write_dna_bundle(&dir.path().join("bundle.json"), "ATGAAA");
        write_yaml(dir.path(), "expects-approval", "approved");
        let args = CampaignArgs {
            campaign: dir.path().join("campaign.yaml"),
            output: None,
            text: false,
        };
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn campaign_error_returns_two() {
        let dir = TempDir::new().unwrap();
        write_db(dir.path(), "");
        // Missing bundle file -> scenario errors.
        write_yaml(dir.path(), "missing-bundle", "rejected");
        let args = CampaignArgs {
            campaign: dir.path().join("campaign.yaml"),
            output: None,
            text: false,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn campaign_missing_yaml_returns_three() {
        let args = CampaignArgs {
            campaign: PathBuf::from("/nonexistent/campaign.yaml"),
            output: None,
            text: false,
        };
        assert_eq!(run(&args), 3);
    }

    #[test]
    fn campaign_text_output_writes_file() {
        let dir = TempDir::new().unwrap();
        write_db(dir.path(), "");
        write_dna_bundle(&dir.path().join("bundle.json"), "ATGAAA");
        write_yaml(dir.path(), "ok", "rejected");
        let out = dir.path().join("report.txt");
        let args = CampaignArgs {
            campaign: dir.path().join("campaign.yaml"),
            output: Some(out.clone()),
            text: true,
        };
        assert_eq!(run(&args), 0);
        let raw = fs::read_to_string(&out).unwrap();
        assert!(raw.contains("matches=1"));
    }
}
