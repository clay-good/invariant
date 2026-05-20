//! Dry-run simulation harness for biosynthesis firewall campaigns.
//!
//! A *campaign* is a YAML file describing one or more scenarios. Each
//! scenario points at a synthesis-bundle JSON, a hazard-database file (and
//! its issuer pub key), an optional profile, and an expected outcome. The
//! runner loads each scenario, runs the validator, compares the actual
//! verdict against the expected outcome, and returns a structured report.
//!
//! Real scenario libraries (large adversarial corpora, parametric sweeps)
//! land in later steps; this module ships the runner shape so the CLI and
//! tests can drive end-to-end smoke runs.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use invariant_biosynthesis::authority::crypto::generate_keypair;
use invariant_biosynthesis::models::bundle::SynthesisBundle;
use invariant_biosynthesis::models::profile::BioProfile;
use invariant_biosynthesis::screening::{FileBackedHazardDatabase, HazardScreener};
use invariant_biosynthesis::validator::ValidatorConfig;

// ---------------------------------------------------------------------------
// Scenario / campaign types
// ---------------------------------------------------------------------------

/// Expected outcome of a scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    /// Bundle should be approved.
    Approved,
    /// Bundle should be rejected.
    Rejected,
}

/// One scenario entry in a campaign YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignScenario {
    /// Human-readable id.
    pub name: String,
    /// Optional description (for the report).
    #[serde(default)]
    pub description: String,
    /// Path to the bundle JSON.
    pub bundle: PathBuf,
    /// Path to the signed hazard-database JSON. Required because the
    /// validator is fail-closed when no DB is configured.
    pub hazard_db: PathBuf,
    /// Path to the issuer public-key JSON for the hazard DB.
    pub hazard_db_issuer_pub: PathBuf,
    /// Optional profile JSON. When omitted, a permissive default is used.
    #[serde(default)]
    pub profile: Option<PathBuf>,
    /// Expected outcome.
    pub expect: ExpectedOutcome,
}

/// Top-level campaign file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignFile {
    /// Campaign name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: String,
    /// Scenarios to run.
    pub scenarios: Vec<CampaignScenario>,
}

/// One scenario's evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Scenario name.
    pub name: String,
    /// Whether the actual outcome matched the expected one.
    pub matched: bool,
    /// Expected outcome.
    pub expected: ExpectedOutcome,
    /// Actual approval flag from the verdict.
    pub approved: bool,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u128,
    /// Optional error string (when scenario load / validation failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Aggregated campaign report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    /// Campaign name.
    pub name: String,
    /// Per-scenario results.
    pub scenarios: Vec<ScenarioResult>,
    /// Number of scenarios where the actual outcome matched the expected one.
    pub matches: usize,
    /// Number of scenarios where it did not.
    pub mismatches: usize,
    /// Number of scenarios that errored before producing a verdict.
    pub errors: usize,
    /// Total wall-clock duration in milliseconds.
    pub total_duration_ms: u128,
}

impl CampaignReport {
    /// Whether every scenario matched its expected outcome (no errors).
    pub fn fully_matches(&self) -> bool {
        self.mismatches == 0 && self.errors == 0
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the campaign runner.
#[derive(Debug, Error)]
pub enum CampaignError {
    /// Could not read the campaign YAML.
    #[error("read campaign file {path:?}: {reason}")]
    Io {
        /// Offending path.
        path: PathBuf,
        /// Underlying io error message.
        reason: String,
    },
    /// YAML parse error.
    #[error("parse campaign YAML: {0}")]
    Yaml(String),
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load a campaign YAML file from disk.
pub fn load_campaign(path: &Path) -> Result<CampaignFile, CampaignError> {
    let raw = fs::read_to_string(path).map_err(|e| CampaignError::Io {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    serde_yaml::from_str(&raw).map_err(|e| CampaignError::Yaml(e.to_string()))
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Execute every scenario in a campaign file and return a structured report.
///
/// `base_dir` is prepended to every relative path in the campaign so that
/// scenarios can refer to fixtures by paths relative to the campaign YAML
/// itself (the typical layout). Absolute paths in the YAML are honoured
/// as-is.
pub fn run_campaign(campaign: &CampaignFile, base_dir: &Path) -> CampaignReport {
    let started = Instant::now();
    let mut results: Vec<ScenarioResult> = Vec::with_capacity(campaign.scenarios.len());
    let mut matches = 0usize;
    let mut mismatches = 0usize;
    let mut errors = 0usize;
    for s in &campaign.scenarios {
        let r = run_one(s, base_dir);
        if r.error.is_some() {
            errors += 1;
        } else if r.matched {
            matches += 1;
        } else {
            mismatches += 1;
        }
        results.push(r);
    }
    CampaignReport {
        name: campaign.name.clone(),
        scenarios: results,
        matches,
        mismatches,
        errors,
        total_duration_ms: started.elapsed().as_millis(),
    }
}

fn run_one(s: &CampaignScenario, base_dir: &Path) -> ScenarioResult {
    let started = Instant::now();
    match run_one_inner(s, base_dir) {
        Ok(approved) => {
            let matched = match s.expect {
                ExpectedOutcome::Approved => approved,
                ExpectedOutcome::Rejected => !approved,
            };
            ScenarioResult {
                name: s.name.clone(),
                matched,
                expected: s.expect,
                approved,
                duration_ms: started.elapsed().as_millis(),
                error: None,
            }
        }
        Err(e) => ScenarioResult {
            name: s.name.clone(),
            matched: false,
            expected: s.expect,
            approved: false,
            duration_ms: started.elapsed().as_millis(),
            error: Some(e),
        },
    }
}

fn run_one_inner(s: &CampaignScenario, base_dir: &Path) -> Result<bool, String> {
    let bundle_path = resolve(base_dir, &s.bundle);
    let bundle_raw = fs::read_to_string(&bundle_path)
        .map_err(|e| format!("read bundle {}: {e}", bundle_path.display()))?;
    let bundle: SynthesisBundle =
        serde_json::from_str(&bundle_raw).map_err(|e| format!("parse bundle: {e}"))?;

    let profile = match &s.profile {
        Some(p) => {
            let path = resolve(base_dir, p);
            let raw = fs::read_to_string(&path)
                .map_err(|e| format!("read profile {}: {e}", path.display()))?;
            serde_json::from_str::<BioProfile>(&raw).map_err(|e| format!("parse profile: {e}"))?
        }
        None => default_profile(),
    };

    let issuer_path = resolve(base_dir, &s.hazard_db_issuer_pub);
    let issuer_raw = fs::read_to_string(&issuer_path)
        .map_err(|e| format!("read issuer pub {}: {e}", issuer_path.display()))?;
    let issuer_kf: PubKeyFile =
        serde_json::from_str(&issuer_raw).map_err(|e| format!("parse issuer pub: {e}"))?;
    let mut trusted = HashMap::new();
    let vk = decode_vk(&issuer_kf.public_key)?;
    trusted.insert(issuer_kf.kid, vk);

    let db_path = resolve(base_dir, &s.hazard_db);
    let db = FileBackedHazardDatabase::load(&db_path, &trusted)
        .map_err(|e| format!("load hazard DB {}: {e}", db_path.display()))?;
    let db_arc: Arc<dyn HazardScreener> = Arc::new(db);

    let signing_key = generate_keypair(&mut rand::rngs::OsRng);
    let cfg = ValidatorConfig::new(
        profile,
        HashMap::<String, VerifyingKey>::new(),
        signing_key,
        "invariant-bio-sim".into(),
    )
    .map_err(|e| format!("validator config: {e}"))?
    .with_hazard_db(db_arc);

    let out = cfg
        .validate(&bundle, Utc::now(), None)
        .map_err(|e| format!("validate: {e}"))?;
    Ok(out.signed_verdict.verdict.approved)
}

#[derive(Deserialize)]
struct PubKeyFile {
    kid: String,
    public_key: String,
}

fn decode_vk(b64: &str) -> Result<VerifyingKey, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("base64 pub key: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "expected 32-byte public key".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("decode pub key: {e}"))
}

fn resolve(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

fn default_profile() -> BioProfile {
    BioProfile {
        name: "sim-default".into(),
        version: "0.1.0".into(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::SigningKey;
    use invariant_biosynthesis::screening::{sign_body_for_tests, HazardDatabaseBody, HazardEntry};
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn write_db(dir: &Path, name: &str, dna_pattern: &str) -> (PathBuf, PathBuf) {
        let sk = SigningKey::generate(&mut OsRng);
        let body = HazardDatabaseBody {
            schema_version: 1,
            db_version: 1,
            dna_signatures: if dna_pattern.is_empty() {
                vec![]
            } else {
                vec![HazardEntry {
                    id: format!("{name}-1"),
                    label: name.into(),
                    hazard_class: "select-agent".into(),
                    pattern: dna_pattern.into(),
                }]
            },
            peptide_signatures: vec![],
            chemical_signatures: vec![],
        };
        let signed = sign_body_for_tests(&body, &format!("{name}-issuer"), &sk);
        let db_path = dir.join(format!("{name}-db.json"));
        fs::write(&db_path, serde_json::to_vec_pretty(&signed).unwrap()).unwrap();
        let pub_path = dir.join(format!("{name}-issuer.json"));
        let pub_kf = serde_json::json!({
            "kid": format!("{name}-issuer"),
            "public_key": STANDARD.encode(sk.verifying_key().as_bytes()),
        });
        fs::write(&pub_path, serde_json::to_vec_pretty(&pub_kf).unwrap()).unwrap();
        (db_path, pub_path)
    }

    fn write_dna_bundle(dir: &Path, name: &str, sequence: &str) -> PathBuf {
        let bundle = serde_json::json!({
            "timestamp": "2026-04-25T12:00:00Z",
            "source": "sim-test",
            "sequence": 1,
            "payload": {"kind": "dna", "sequence": sequence},
            "delta_time": 0.0,
            "authority": {"pca_chain": "", "required_ops": []},
            "metadata": {}
        });
        let p = dir.join(format!("{name}.json"));
        fs::write(&p, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
        p
    }

    #[test]
    fn load_campaign_roundtrips_minimal_yaml() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("c.yaml");
        fs::write(
            &p,
            r#"
name: t
scenarios:
  - name: a
    bundle: a.json
    hazard_db: db.json
    hazard_db_issuer_pub: issuer.json
    expect: approved
"#,
        )
        .unwrap();
        let c = load_campaign(&p).unwrap();
        assert_eq!(c.name, "t");
        assert_eq!(c.scenarios.len(), 1);
        assert_eq!(c.scenarios[0].expect, ExpectedOutcome::Approved);
    }

    #[test]
    fn load_campaign_rejects_unknown_scenario_field() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("c.yaml");
        fs::write(
            &p,
            r#"
name: t
scenarios:
  - name: a
    bundle: a.json
    hazard_db: db.json
    hazard_db_issuer_pub: issuer.json
    expect: approved
    junk: 1
"#,
        )
        .unwrap();
        assert!(load_campaign(&p).is_err());
    }

    #[test]
    fn run_campaign_aggregates_matches_and_mismatches() {
        let dir = TempDir::new().unwrap();
        let (db_path, issuer_path) = write_db(dir.path(), "t", "");
        // Bundle approval is gated by authority+screening. With empty PCA
        // chain authority fails -> rejected. So expect=rejected matches.
        let safe = write_dna_bundle(dir.path(), "safe", "ATGAAAGCTGGC");
        let scenarios = vec![
            CampaignScenario {
                name: "matches".into(),
                description: String::new(),
                bundle: safe.clone(),
                hazard_db: db_path.clone(),
                hazard_db_issuer_pub: issuer_path.clone(),
                profile: None,
                expect: ExpectedOutcome::Rejected,
            },
            CampaignScenario {
                name: "mismatches".into(),
                description: String::new(),
                bundle: safe,
                hazard_db: db_path,
                hazard_db_issuer_pub: issuer_path,
                profile: None,
                expect: ExpectedOutcome::Approved,
            },
        ];
        let campaign = CampaignFile {
            name: "t".into(),
            description: String::new(),
            scenarios,
        };
        let report = run_campaign(&campaign, dir.path());
        assert_eq!(report.matches, 1);
        assert_eq!(report.mismatches, 1);
        assert_eq!(report.errors, 0);
        assert!(!report.fully_matches());
    }

    #[test]
    fn run_campaign_records_load_error_per_scenario() {
        let dir = TempDir::new().unwrap();
        let (db_path, issuer_path) = write_db(dir.path(), "t", "");
        let scenarios = vec![CampaignScenario {
            name: "broken".into(),
            description: String::new(),
            bundle: dir.path().join("nope.json"),
            hazard_db: db_path,
            hazard_db_issuer_pub: issuer_path,
            profile: None,
            expect: ExpectedOutcome::Rejected,
        }];
        let campaign = CampaignFile {
            name: "t".into(),
            description: String::new(),
            scenarios,
        };
        let report = run_campaign(&campaign, dir.path());
        assert_eq!(report.errors, 1);
        assert!(report.scenarios[0].error.is_some());
    }

    #[test]
    fn run_campaign_dna_hit_blocks_approval_matches_rejected() {
        let dir = TempDir::new().unwrap();
        // Hazard DB hits any DNA starting with ATGAAA.
        let (db_path, issuer_path) = write_db(dir.path(), "hit", "ATGAAA");
        let bundle = write_dna_bundle(dir.path(), "b", "ATGAAACCC");
        let scenarios = vec![CampaignScenario {
            name: "hit".into(),
            description: String::new(),
            bundle,
            hazard_db: db_path,
            hazard_db_issuer_pub: issuer_path,
            profile: None,
            expect: ExpectedOutcome::Rejected,
        }];
        let campaign = CampaignFile {
            name: "t".into(),
            description: String::new(),
            scenarios,
        };
        let report = run_campaign(&campaign, dir.path());
        assert_eq!(report.matches, 1);
        assert_eq!(report.mismatches, 0);
        assert_eq!(report.errors, 0);
        assert!(report.fully_matches());
    }
}
