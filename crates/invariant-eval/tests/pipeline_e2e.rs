//! End-to-end pipeline coverage for `invariant-eval` (v12-N-16).
//!
//! Drives the `safety-check` preset against two hand-crafted trace fixtures
//! committed alongside this test:
//!
//! * [`fixtures/good_trace.jsonl`] — every step approved, every check passing.
//! * [`fixtures/bad_trace.jsonl`] — step 1 rejected by the physics check
//!   `joint_limits` (a typical motion violation).
//!
//! The fixtures are constructed by [`build_good_trace`] and [`build_bad_trace`]
//! below. An ignored `regenerate_fixtures` test (run with
//! `cargo test --test pipeline_e2e -- --ignored regenerate_fixtures`) writes
//! the canonical JSON into the fixtures directory; the regular tests only
//! read those files and never write.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, TimeZone, Utc};
use invariant_eval::robotics::presets::{run_preset, EvalReport, Severity};
use invariant_robotics::models::authority::Operation;
use invariant_robotics::models::command::{Command, CommandAuthority, JointState};
use invariant_robotics::models::trace::{Trace, TraceStep};
use invariant_robotics::models::verdict::{
    AuthoritySummary, CheckResult, SignedVerdict, Verdict,
};

const GOOD_FIXTURE: &str = "good_trace.jsonl";
const BAD_FIXTURE: &str = "bad_trace.jsonl";

const PROFILE_NAME: &str = "test-arm";
const PROFILE_HASH: &str = "sha256:test-profile";
const SIGNER_KID: &str = "kid-test";
const PRINCIPAL: &str = "op@example.com";
const FAILING_CHECK_NAME: &str = "joint_limits";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn fixed_timestamp(step: u64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .unwrap()
        .checked_add_signed(chrono::Duration::milliseconds(step as i64 * 20))
        .unwrap()
}

fn make_command(seq: u64) -> Command {
    Command {
        timestamp: fixed_timestamp(seq),
        source: "test-agent".into(),
        sequence: seq,
        joint_states: vec![JointState {
            name: "j1".into(),
            position: 0.0,
            velocity: 0.0,
            effort: 0.0,
        }],
        delta_time: 0.02,
        end_effector_positions: vec![],
        center_of_mass: None,
        authority: CommandAuthority {
            pca_chain: String::new(),
            required_ops: vec![Operation::new("actuate:j1:position").unwrap()],
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

fn make_good_step(seq: u64) -> TraceStep {
    let cmd = make_command(seq);
    let verdict = SignedVerdict {
        verdict: Verdict {
            approved: true,
            command_hash: format!("sha256:cmd-{seq}"),
            command_sequence: seq,
            timestamp: fixed_timestamp(seq),
            checks: vec![
                CheckResult::new("authority", "authority", true, "chain ok"),
                CheckResult::new(FAILING_CHECK_NAME, "physics", true, "within limits"),
            ],
            profile_name: PROFILE_NAME.into(),
            profile_hash: PROFILE_HASH.into(),
            threat_analysis: None,
            authority_summary: AuthoritySummary {
                origin_principal: PRINCIPAL.into(),
                hop_count: 1,
                operations_granted: vec!["actuate:j1:position".into()],
                operations_required: vec!["actuate:j1:position".into()],
            },
        },
        verdict_signature: format!("sig-{seq}"),
        signer_kid: SIGNER_KID.into(),
    };
    TraceStep {
        step: seq,
        timestamp: fixed_timestamp(seq),
        command: cmd,
        verdict,
        simulation_state: None,
    }
}

fn make_bad_step(seq: u64, fail_check: bool) -> TraceStep {
    let cmd = make_command(seq);
    let approved = !fail_check;
    let checks = if fail_check {
        vec![
            CheckResult::new("authority", "authority", true, "chain ok"),
            CheckResult::new(
                FAILING_CHECK_NAME,
                "physics",
                false,
                "j1 at 1.500 rad exceeds max 1.200 rad",
            ),
        ]
    } else {
        vec![
            CheckResult::new("authority", "authority", true, "chain ok"),
            CheckResult::new(FAILING_CHECK_NAME, "physics", true, "within limits"),
        ]
    };
    let verdict = SignedVerdict {
        verdict: Verdict {
            approved,
            command_hash: format!("sha256:cmd-{seq}"),
            command_sequence: seq,
            timestamp: fixed_timestamp(seq),
            checks,
            profile_name: PROFILE_NAME.into(),
            profile_hash: PROFILE_HASH.into(),
            threat_analysis: None,
            authority_summary: AuthoritySummary {
                origin_principal: PRINCIPAL.into(),
                hop_count: 1,
                operations_granted: vec!["actuate:j1:position".into()],
                operations_required: vec!["actuate:j1:position".into()],
            },
        },
        verdict_signature: format!("sig-{seq}"),
        signer_kid: SIGNER_KID.into(),
    };
    TraceStep {
        step: seq,
        timestamp: fixed_timestamp(seq),
        command: cmd,
        verdict,
        simulation_state: None,
    }
}

fn build_good_trace() -> Trace {
    Trace {
        id: "good-episode-001".into(),
        episode: 1,
        environment_id: 0,
        scenario: "pick_and_place".into(),
        profile_name: PROFILE_NAME.into(),
        steps: vec![make_good_step(0), make_good_step(1), make_good_step(2)],
        metadata: HashMap::new(),
    }
}

fn build_bad_trace() -> Trace {
    // Step 1 violates the physics `joint_limits` check; steps 0 and 2 are
    // clean. This shape makes the report deterministic and small.
    Trace {
        id: "bad-episode-047".into(),
        episode: 47,
        environment_id: 0,
        scenario: "pick_and_place".into(),
        profile_name: PROFILE_NAME.into(),
        steps: vec![
            make_bad_step(0, false),
            make_bad_step(1, true),
            make_bad_step(2, false),
        ],
        metadata: HashMap::new(),
    }
}

fn load_trace(name: &str) -> Trace {
    let path = fixtures_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    // The fixtures are a single canonical Trace JSON per file (one trace per
    // shard), serialised pretty-printed for readability. The `.jsonl`
    // extension mirrors the convention used elsewhere in the campaign.
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

#[test]
fn good_trace_passes_safety_check() {
    let trace = load_trace(GOOD_FIXTURE);
    assert_eq!(trace, build_good_trace(), "fixture must match builder");

    let report: EvalReport =
        run_preset("safety-check", &trace).expect("safety-check is a known preset");

    assert!(
        report.passed,
        "good trace must pass safety-check, got findings: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.severity != Severity::Error),
        "no error-severity findings allowed on the good trace"
    );
    assert_eq!(report.preset, "safety-check");
    assert_eq!(report.trace_id, "good-episode-001");
}

#[test]
fn bad_trace_fails_safety_check_with_expected_guardrail() {
    let trace = load_trace(BAD_FIXTURE);
    assert_eq!(trace, build_bad_trace(), "fixture must match builder");

    let report: EvalReport =
        run_preset("safety-check", &trace).expect("safety-check is a known preset");

    assert!(!report.passed, "bad trace must fail safety-check");

    let error_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .collect();
    assert!(
        !error_findings.is_empty(),
        "expected at least one Error finding; got: {:?}",
        report.findings
    );

    // The expected guardrail is the failing physics check on step 1.
    let hit = error_findings.iter().find(|f| {
        f.step == 1 && f.message.contains(FAILING_CHECK_NAME) && f.message.contains("physics")
    });
    assert!(
        hit.is_some(),
        "no finding names the expected `{FAILING_CHECK_NAME}` failure on step 1; \
         got: {:?}",
        error_findings
    );
}

#[test]
fn bad_trace_summary_counts_one_rejection() {
    let trace = load_trace(BAD_FIXTURE);
    let report = run_preset("safety-check", &trace).unwrap();
    assert!(
        report.summary.contains("1 rejected"),
        "expected summary to count one rejection, got: {}",
        report.summary
    );
}

#[test]
fn fixture_files_are_under_two_hundred_lines_each() {
    // Acceptance criterion from the v12-N-16 prompt: each fixture < 200
    // lines. The cap is a guard against a future "just dump the whole
    // shard" temptation that would obscure intent.
    for name in [GOOD_FIXTURE, BAD_FIXTURE] {
        let path = fixtures_dir().join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let lines = text.lines().count();
        assert!(
            lines < 200,
            "{name}: expected < 200 lines, got {lines}"
        );
    }
}

/// Regenerate the committed fixtures from the in-Rust builders. Run with
/// `cargo test --test pipeline_e2e -- --ignored regenerate_fixtures`
/// whenever the upstream `Trace`/`Command`/`Verdict` shape changes.
#[test]
#[ignore]
fn regenerate_fixtures() {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).unwrap();
    // Compact JSON: one trace per file, one line, no pretty-printing.
    // Keeps each fixture comfortably under 200 lines and avoids
    // whitespace-sensitive diffs on regeneration.
    let good = serde_json::to_string(&build_good_trace()).unwrap();
    let bad = serde_json::to_string(&build_bad_trace()).unwrap();
    std::fs::write(dir.join(GOOD_FIXTURE), good).unwrap();
    std::fs::write(dir.join(BAD_FIXTURE), bad).unwrap();
    eprintln!("regenerated fixtures in {}", dir.display());
}
