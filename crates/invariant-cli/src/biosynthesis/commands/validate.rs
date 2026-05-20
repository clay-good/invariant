//! `validate` subcommand: validate a synthesis bundle against a profile.
//!
//! Loads the bundle, the optional profile (default profile used when
//! omitted), and the required hazard-database file (signed JSON), runs the
//! validator, prints a structured summary, and writes the signed verdict
//! JSON to the chosen sink. Exit codes:
//!
//! - 0 — verdict approved
//! - 1 — verdict rejected (Fail)
//! - 2 — verdict carried only Advisory non-Pass (no Fail / DbStale)
//! - 3 — internal error (I/O, parse, signature, etc.)

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use clap::Args;
use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;

use invariant_biosynthesis::authority::crypto::generate_keypair;
use invariant_biosynthesis::invariants::InvariantStatus;
use invariant_biosynthesis::models::bundle::SynthesisBundle;
use invariant_biosynthesis::models::profile::BioProfile;
use invariant_biosynthesis::screening::{
    ConsensusHazardScreener, FileBackedHazardDatabase, HazardScreener, QuorumPolicy,
};
use invariant_biosynthesis::threat::ThreatScorer;
use invariant_biosynthesis::validator::ValidatorConfig;

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Path to the synthesis bundle JSON.
    #[arg(long, value_name = "BUNDLE")]
    pub bundle: PathBuf,
    /// Path to the bio profile JSON. If omitted, a permissive default
    /// profile is used.
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<PathBuf>,
    /// Path to the signed hazard-database JSON. May be specified multiple
    /// times for multi-source consensus screening.
    #[arg(long, value_name = "HAZARD_DB")]
    pub hazard_db: Vec<PathBuf>,
    /// Path to the issuer's public-key file (the kid that signed the
    /// hazard DB). The kid is read from the file.
    #[arg(long, value_name = "ISSUER_PUB")]
    pub hazard_db_issuer_pub: PathBuf,
    /// Optional output path for the signed verdict JSON. When omitted the
    /// verdict is written to stdout.
    #[arg(long, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,
    /// Disable the stateful fragmentation-bypass detector (S1). On by
    /// default.
    #[arg(long)]
    pub no_stateful: bool,
    /// Quorum policy for multi-source consensus screening. Only relevant
    /// when multiple --hazard-db paths are given. Values: "any", "all",
    /// "k:N" (at least N sources must agree).
    #[arg(long, value_name = "POLICY", default_value = "all")]
    pub quorum: String,
    /// Composite threat-score threshold (0.0–1.0). When set, enables the
    /// threat scorer and blocks approval if the composite score meets or
    /// exceeds this value.
    #[arg(long, value_name = "THRESHOLD")]
    pub threat_threshold: Option<f64>,
    /// Path to a persistent nonce log (JSONL) for attestation replay
    /// protection across restarts.
    #[arg(long, value_name = "PATH")]
    pub nonce_log: Option<PathBuf>,
}

pub fn run(args: &ValidateArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            3
        }
    }
}

fn run_inner(args: &ValidateArgs) -> Result<i32, String> {
    // ---- Load bundle ----
    let bundle_raw = fs::read_to_string(&args.bundle)
        .map_err(|e| format!("read bundle {}: {e}", args.bundle.display()))?;
    let bundle: SynthesisBundle =
        serde_json::from_str(&bundle_raw).map_err(|e| format!("parse bundle: {e}"))?;

    // ---- Load profile ----
    let profile = match &args.profile {
        Some(path) => {
            let raw = fs::read_to_string(path)
                .map_err(|e| format!("read profile {}: {e}", path.display()))?;
            serde_json::from_str::<BioProfile>(&raw).map_err(|e| format!("parse profile: {e}"))?
        }
        None => default_profile(),
    };

    // ---- Load issuer public key ----
    let issuer_kf = crate::key_file::load_key_file(&args.hazard_db_issuer_pub)
        .map_err(|e| format!("load issuer pub key: {e}"))?;
    let (issuer_vk, issuer_kid) = crate::key_file::load_verifying_key(&issuer_kf)
        .map_err(|e| format!("decode issuer pub key: {e}"))?;
    let mut trusted = HashMap::new();
    trusted.insert(issuer_kid, issuer_vk);

    // ---- Load hazard DB(s) ----
    if args.hazard_db.is_empty() {
        return Err("at least one --hazard-db path is required".into());
    }
    let dbs: Vec<Arc<dyn HazardScreener>> = args
        .hazard_db
        .iter()
        .map(|path| {
            let db = FileBackedHazardDatabase::load(path, &trusted)
                .map_err(|e| format!("load hazard DB {}: {e}", path.display()))?;
            Ok(Arc::new(db) as Arc<dyn HazardScreener>)
        })
        .collect::<Result<Vec<_>, String>>()?;

    let db_arc: Arc<dyn HazardScreener> = if dbs.len() == 1 {
        dbs.into_iter().next().unwrap()
    } else {
        let policy = parse_quorum(&args.quorum)?;
        Arc::new(
            ConsensusHazardScreener::new(dbs, policy)
                .map_err(|e| format!("consensus screener: {e}"))?,
        )
    };

    // ---- Build validator ----
    let signing_key = generate_keypair(&mut OsRng);
    let mut cfg = ValidatorConfig::new(
        profile,
        HashMap::<String, VerifyingKey>::new(),
        signing_key,
        "invariant-bio-validate-cli".to_string(),
    )
    .map_err(|e| format!("validator config: {e}"))?
    .with_hazard_db(db_arc);

    if args.no_stateful {
        cfg = cfg
            .without_stateful_detector()
            .map_err(|e| format!("--no-stateful rejected: {e}"))?;
    }

    if let Some(threshold) = args.threat_threshold {
        let scorer = Arc::new(Mutex::new(ThreatScorer::with_defaults()));
        cfg = cfg
            .with_threat_scorer(scorer)
            .with_threat_alert_threshold(threshold);
    }

    // ---- Run validator ----
    let out = cfg
        .validate(&bundle, Utc::now(), None)
        .map_err(|e| format!("validate: {e}"))?;

    // ---- Render summary to stderr ----
    let v = &out.signed_verdict.verdict;
    eprintln!(
        "verdict approved={} command_hash={} checks={}",
        v.approved,
        v.command_hash,
        v.checks.len()
    );
    for c in &v.checks {
        eprintln!(
            "  [{}] {} {}: {}",
            category_tag(&c.category),
            if c.passed { "PASS" } else { "FAIL" },
            c.name,
            c.details
        );
    }
    if !out.screening_hits.is_empty() {
        eprintln!("screening_hits ({}):", out.screening_hits.len());
        for h in &out.screening_hits {
            eprintln!(
                "  {} ({}) -> {}",
                h.entry.id, h.entry.hazard_class, h.matched_text
            );
        }
    }

    // ---- Emit verdict JSON ----
    let json = serde_json::to_string_pretty(&out.signed_verdict)
        .map_err(|e| format!("serialize verdict: {e}"))?;
    match &args.output {
        Some(path) => {
            fs::write(path, &json).map_err(|e| format!("write verdict {}: {e}", path.display()))?
        }
        None => println!("{json}"),
    }

    // ---- Exit code ----
    if v.approved {
        return Ok(0);
    }
    let any_fail = out.invariant_results.iter().any(|r| {
        matches!(
            r.status,
            InvariantStatus::Fail { .. } | InvariantStatus::DbStale { .. }
        )
    });
    let advisory_only = !any_fail
        && out
            .invariant_results
            .iter()
            .any(|r| matches!(r.status, InvariantStatus::Advisory { .. }));
    if any_fail {
        Ok(1)
    } else if advisory_only {
        Ok(2)
    } else {
        // Approval blocked by authority/screening but no invariant Fail.
        Ok(1)
    }
}

fn default_profile() -> BioProfile {
    BioProfile {
        name: "cli-default".to_string(),
        version: "0.1.0".to_string(),
        bsl_level: 2,
        allowed_substrates: vec![
            "dna".into(),
            "peptide".into(),
            "chemical".into(),
            "protocol".into(),
        ],
        max_synthesis_volume_ml: 1.0,
        export_controlled: false,
        profile_signature: None,
        profile_signer_kid: None,
        codon_usage_organism: None,
        codon_entropy_band: None,
        protein_kmer_k: None,
        protein_kmer_threshold: None,
        allowed_protocol_steps: None,
        allow_stale_screening: false,
        stale_screening_max_days: None,
        max_authority_chain_depth: 5,
        max_dna_length_bp: None,
        max_peptide_length_aa: None,
        max_smiles_length_chars: None,
    }
}

fn parse_quorum(s: &str) -> Result<QuorumPolicy, String> {
    match s {
        "any" => Ok(QuorumPolicy::Any),
        "all" => Ok(QuorumPolicy::All),
        other => {
            if let Some(n_str) = other.strip_prefix("k:") {
                let n: usize = n_str
                    .parse()
                    .map_err(|_| format!("invalid quorum k value: {n_str:?}"))?;
                if n == 0 {
                    return Err("quorum k must be >= 1".into());
                }
                Ok(QuorumPolicy::AtLeast(n))
            } else {
                Err(format!(
                    "unknown quorum policy {other:?}; expected \"any\", \"all\", or \"k:N\""
                ))
            }
        }
    }
}

fn category_tag(category: &str) -> &str {
    if let Some(rest) = category.strip_prefix("invariant.") {
        rest
    } else {
        category
    }
}

// ---------------------------------------------------------------------------
// Test helpers (used by the integration test below).
// ---------------------------------------------------------------------------

#[cfg(test)]
fn write_test_hazard_db(
    path: &std::path::Path,
    issuer_pub_path: &std::path::Path,
    dna_pattern: &str,
) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::SigningKey;
    use invariant_biosynthesis::screening::{sign_body_for_tests, HazardDatabaseBody, HazardEntry};
    let sk = SigningKey::generate(&mut OsRng);
    let body = HazardDatabaseBody {
        schema_version: 1,
        db_version: 1,
        dna_signatures: if dna_pattern.is_empty() {
            vec![]
        } else {
            vec![HazardEntry {
                id: "dna-1".into(),
                label: "test".into(),
                hazard_class: "select-agent".into(),
                pattern: dna_pattern.into(),
            }]
        },
        peptide_signatures: vec![],
        chemical_signatures: vec![],
    };
    let signed = sign_body_for_tests(&body, "issuer-cli", &sk);
    fs::write(path, serde_json::to_vec_pretty(&signed).unwrap()).unwrap();
    let pub_kf = crate::key_file::KeyFile {
        kid: "issuer-cli".into(),
        public_key: STANDARD.encode(sk.verifying_key().as_bytes()),
        secret_key: None,
    };
    fs::write(issuer_pub_path, serde_json::to_vec_pretty(&pub_kf).unwrap()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn safe_bundle_path() -> PathBuf {
        // examples/biosynthesis/safe-bundle.json relative to the repo
        // root. The CLI crate sits at crates/invariant-cli/, so go up two.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/biosynthesis/safe-bundle.json")
    }

    #[test]
    fn validate_safe_bundle_no_hits_returns_approval_or_screening_block() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("hazard-db.json");
        let pub_path = dir.path().join("issuer.pub.json");
        // No DNA pattern -> no hits. Authority chain in the example is empty,
        // so approval will still be blocked by authority. Exit 1 is the
        // expected outcome here.
        write_test_hazard_db(&db_path, &pub_path, "");
        let out_path = dir.path().join("verdict.json");
        let args = ValidateArgs {
            bundle: safe_bundle_path(),
            profile: None,
            hazard_db: vec![db_path],
            hazard_db_issuer_pub: pub_path,
            output: Some(out_path.clone()),
            no_stateful: false,
            quorum: "all".into(),
            threat_threshold: None,
            nonce_log: None,
        };
        let code = run(&args);
        assert!(code == 0 || code == 1, "got code {code}");
        assert!(out_path.exists());
        let raw = fs::read_to_string(&out_path).unwrap();
        assert!(raw.contains("verdict"));
    }

    #[test]
    fn validate_with_dna_hit_blocks_approval() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("hazard-db.json");
        let pub_path = dir.path().join("issuer.pub.json");
        // Pattern matches the safe-bundle DNA: ATGAAA prefix.
        write_test_hazard_db(&db_path, &pub_path, "ATGAAA");
        let out_path = dir.path().join("verdict.json");
        let args = ValidateArgs {
            bundle: safe_bundle_path(),
            profile: None,
            hazard_db: vec![db_path],
            hazard_db_issuer_pub: pub_path,
            output: Some(out_path.clone()),
            no_stateful: false,
            quorum: "all".into(),
            threat_threshold: None,
            nonce_log: None,
        };
        let code = run(&args);
        // Hits trip D1 SelectAgentScreen -> Fail -> exit 1.
        assert_eq!(code, 1);
    }

    #[test]
    fn validate_missing_bundle_returns_internal_error() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("hazard-db.json");
        let pub_path = dir.path().join("issuer.pub.json");
        write_test_hazard_db(&db_path, &pub_path, "");
        let args = ValidateArgs {
            bundle: dir.path().join("does-not-exist.json"),
            profile: None,
            hazard_db: vec![db_path],
            hazard_db_issuer_pub: pub_path,
            output: None,
            no_stateful: false,
            quorum: "all".into(),
            threat_threshold: None,
            nonce_log: None,
        };
        assert_eq!(run(&args), 3);
    }
}
