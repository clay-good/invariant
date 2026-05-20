//! Per-shard determinism fixture (v12 prompt N-3).
//!
//! Regenerates a fixed 1 000-episode `Baseline` shard on the built-in
//! `ur10e_haas_cell` profile with seed `0xCAFE_BABE_DEAD_BEEF` and asserts the
//! SHA-256 of the canonicalised `CampaignReport` matches the committed
//! fixture at `tests/fixtures/baseline_ur10e_seed_cafebabe.sha256`.
//!
//! ## Deviations from the prompt body
//!
//! * **Profile.** The prompt names `ur10e_safety_v1`, which doesn't exist in
//!   the built-in registry; `ur10e_haas_cell` is the closest peer (UR10e
//!   physics, real cell envelope) and is already covered by the campaign
//!   doctests.
//! * **Hash target.** The prompt names "the JSONL output." `run_dry_campaign`
//!   doesn't emit JSONL today — it returns a `CampaignReport`. Per-`Verdict`
//!   `Utc::now()` inside `dry_run.rs` means the JSONL form is wall-clock-
//!   dependent and *cannot* be byte-deterministic with today's code. The
//!   `CampaignReport` itself is timestamp-free; we hash its canonicalised
//!   JSON (HashMaps re-sorted into BTreeMap to neutralise hasher state,
//!   matching `tests/determinism.rs`). When v11 follow-up work introduces
//!   a seeded clock and a JSONL writer, this test should be re-pointed at
//!   that artifact and the fixture digest regenerated.
//!
//! ## Regeneration
//!
//! When the campaign generator output changes *intentionally* (new
//! scenario, modified weighting, profile rev), regenerate the fixture:
//!
//! ```text
//! REGENERATE_DETERMINISM_FIXTURE=1 cargo test -p invariant-sim \
//!     --test determinism_fixture
//! ```
//!
//! That writes the new digest to the fixture file and exits 0. Commit the
//! fixture change in the same PR as the generator change so CI gates
//! against silent drift.

use std::fs;
use std::path::PathBuf;

use invariant_sim::robotics::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
use invariant_sim::robotics::isaac::dry_run::run_dry_campaign;
use invariant_sim::robotics::reporter::CampaignReport;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// 32-byte seed expanded from the spec-named u64 `0xCAFE_BABE_DEAD_BEEF`.
/// We splat the 8-byte value across the 32-byte slot four times so the
/// seed is recoverable from the fixture file's name by hand.
const SEED: [u8; 32] = [
    0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
    0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
];

const FIXTURE_REL_PATH: &str = "tests/fixtures/baseline_ur10e_seed_cafebabe.sha256";

fn fixture_config() -> CampaignConfig {
    CampaignConfig {
        name: "baseline_ur10e_haas_cell_n3".to_string(),
        profile: "ur10e_haas_cell".to_string(),
        // 1 env × 1000 episodes × 4 steps = 4 000 commands. The prompt
        // says "1 000-episode shard"; we hold steps small so the test
        // runs under a couple of seconds on CI while still pinning every
        // per-episode generator and selection deterministically.
        environments: 1,
        episodes_per_env: 1000,
        steps_per_episode: 4,
        scenarios: vec![ScenarioConfig {
            scenario_type: "baseline".to_string(),
            weight: 1.0,
            injections: vec![],
        }],
        success_criteria: SuccessCriteria::default(),
    }
}

fn canonicalize(r: &CampaignReport) -> serde_json::Value {
    let per_profile: BTreeMap<_, _> = r
        .per_profile
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap()))
        .collect();
    let per_scenario: BTreeMap<_, _> = r
        .per_scenario
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap()))
        .collect();
    let per_check: BTreeMap<_, _> = r
        .per_check
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap()))
        .collect();

    serde_json::json!({
        "campaign_name": r.campaign_name,
        "total_commands": r.total_commands,
        "total_approved": r.total_approved,
        "total_rejected": r.total_rejected,
        "approval_rate": r.approval_rate,
        "rejection_rate": r.rejection_rate,
        "legitimate_pass_rate": r.legitimate_pass_rate,
        "violation_escape_count": r.violation_escape_count,
        "violation_escape_rate": r.violation_escape_rate,
        "false_rejection_count": r.false_rejection_count,
        "false_rejection_rate": r.false_rejection_rate,
        "criteria_met": r.criteria_met,
        "confidence": serde_json::to_value(&r.confidence).unwrap(),
        "per_profile": per_profile,
        "per_scenario": per_scenario,
        "per_check": per_check,
    })
}

fn compute_digest() -> String {
    let config = fixture_config();
    let report = run_dry_campaign(&config, Some(SEED)).expect("campaign must succeed");
    assert_eq!(report.total_commands, 4_000, "fixture scale drifted");
    let bytes = serde_json::to_vec(&canonicalize(&report)).expect("canonical JSON");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        write!(hex, "{:02x}", b).expect("hex write");
    }
    hex
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_REL_PATH)
}

#[test]
fn baseline_ur10e_shard_digest_matches_fixture() {
    let computed = compute_digest();
    let path = fixture_path();

    if std::env::var("REGENERATE_DETERMINISM_FIXTURE").is_ok() {
        fs::write(&path, format!("{computed}\n")).expect("write fixture");
        eprintln!(
            "wrote regenerated digest to {} — commit this change\n  digest: {}",
            path.display(),
            computed
        );
        return;
    }

    let expected_raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
    let expected = expected_raw.trim();

    assert_eq!(
        computed, expected,
        "campaign generator output drifted (or wall-clock state crept in).\n\
         expected: {expected}\n\
         computed: {computed}\n\
         If the change is intentional, re-run with\n\
         REGENERATE_DETERMINISM_FIXTURE=1 cargo test -p invariant-sim --test determinism_fixture\n\
         and commit the new {} alongside the generator change.",
        path.display(),
    );
}
