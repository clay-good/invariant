//! Determinism contract test.
//!
//! Spec: `docs/robotics/spec-v11.md` §2.0. Two `run_dry_campaign` invocations
//! with the same `(config, seed)` must produce identical counted outputs.
//!
//! What we compare:
//!   * Every scalar count and rate in `CampaignReport`.
//!   * Per-profile / per-scenario / per-check stats (after sorting into
//!     `BTreeMap` so insertion-order / hasher-state cannot perturb the
//!     comparison).
//!
//! What we *don't* compare (yet):
//!   * Wall-clock timestamps inside individual `Verdict` records: the
//!     validator stamps `Utc::now()` per command (`dry_run.rs:330`), which
//!     by design varies. v11 §2.0 will tighten this to a seeded clock in a
//!     follow-up; the public `CampaignReport` already has no timestamps,
//!     so this test is the meaningful one operators care about.
//!
//! This test gates against silent generator / selection / weight drift —
//! the failure modes that make the 15M campaign claim unverifiable.

use std::collections::BTreeMap;

use invariant_sim::robotics::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
use invariant_sim::robotics::isaac::dry_run::run_dry_campaign;
use invariant_sim::robotics::reporter::CampaignReport;

const SEED: [u8; 32] = [
    0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
    0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
];

fn fixture_config() -> CampaignConfig {
    CampaignConfig {
        name: "determinism_smoke".to_string(),
        profile: "franka_panda".to_string(),
        environments: 2,
        episodes_per_env: 50,
        steps_per_episode: 4,
        scenarios: vec![
            ScenarioConfig {
                scenario_type: "baseline".to_string(),
                weight: 4.0,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "aggressive".to_string(),
                weight: 1.0,
                injections: vec![],
            },
            ScenarioConfig {
                scenario_type: "exclusion_zone".to_string(),
                weight: 1.0,
                injections: vec![],
            },
        ],
        success_criteria: SuccessCriteria::default(),
    }
}

/// Reduce a `CampaignReport` to a value that has no map-ordering or
/// hasher-state ambiguity.
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

#[test]
fn same_seed_yields_byte_identical_canonical_report() {
    let config = fixture_config();

    let run_a = run_dry_campaign(&config, Some(SEED)).expect("campaign a must succeed");
    let run_b = run_dry_campaign(&config, Some(SEED)).expect("campaign b must succeed");

    // 2 envs × 50 episodes × 4 steps = 400 commands.  Sanity-check the
    // scale so a future refactor doesn't silently shrink this fixture.
    assert_eq!(run_a.total_commands, 400, "fixture size drifted");
    assert_eq!(run_a.total_commands, run_b.total_commands);

    let canon_a = serde_json::to_vec(&canonicalize(&run_a)).unwrap();
    let canon_b = serde_json::to_vec(&canonicalize(&run_b)).unwrap();

    if canon_a != canon_b {
        let pretty_a = serde_json::to_string_pretty(&canonicalize(&run_a)).unwrap();
        let pretty_b = serde_json::to_string_pretty(&canonicalize(&run_b)).unwrap();
        panic!(
            "determinism contract violated: same seed produced different \
             canonical reports.\n\n--- run A ---\n{pretty_a}\n\n--- run B ---\n{pretty_b}",
        );
    }
}

#[test]
fn different_seeds_produce_same_aggregate_shape() {
    // Different seeds yield byte-identical reports for the dry-run path
    // today because no generator currently consumes the keypair seed for
    // anything other than Ed25519 key material (which doesn't surface
    // in CampaignReport).  This test pins that property: if a future
    // generator threads `CampaignRng` into its sequence and a seed bit
    // changes a verdict, totals will drift — and that's a real signal,
    // not a regression.  We assert the *aggregate-shape* invariants
    // (totals add up, rates are in [0,1], confidence bound exists)
    // without asserting byte equality across seeds.
    let config = fixture_config();
    let alt_seed = {
        let mut s = SEED;
        s[0] ^= 0xFF;
        s
    };

    let report = run_dry_campaign(&config, Some(alt_seed)).expect("alt-seed campaign must succeed");
    assert_eq!(report.total_commands, 400);
    assert_eq!(
        report.total_commands,
        report.total_approved + report.total_rejected,
        "approved + rejected must sum to total_commands"
    );
    assert!((0.0..=1.0).contains(&report.approval_rate));
    assert!((0.0..=1.0).contains(&report.rejection_rate));
    assert!(report.confidence.upper_bound_95 >= 0.0);
}
