//! Intent tests for the Category G batch:
//! G-01 `ValidAuthorityChain`, G-03 `ForgedSignature`,
//! G-05 `PrivilegeEscalation`, G-08 `ExpiredChain`.
//!
//! Validator semantics for these failure modes live with the
//! authority/chain modules in `invariant-core` and `invariant-robotics`;
//! these tests only assert the deterministic shape each generator
//! emits so harness wiring catches drift.
//!
//! v11 prompt 2.6 — see `docs/robotics/spec-v11.md` and
//! `docs/robotics/spec-15m-campaign.md` §3.

use chrono::Utc;
use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

fn ops() -> Vec<Operation> {
    vec![Operation::new("actuate:*").unwrap()]
}

fn load_ur10() -> invariant_robotics::models::profile::RobotProfile {
    load_builtin("ur10").expect("ur10 profile must be available")
}

#[test]
fn g_01_valid_authority_chain_passes_through() {
    let profile = load_ur10();
    let count = 12;
    let pca = "harness_supplied_chain_b64";
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::ValidAuthorityChain)
        .generate_commands(count, pca, &ops());
    assert_eq!(cmds.len(), count);

    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(
            c.authority.pca_chain, pca,
            "cmd {i}: pca_chain pass-through"
        );
        assert_eq!(
            c.metadata.get("chain_class").map(String::as_str),
            Some("valid"),
            "cmd {i}: chain_class metadata"
        );
        assert_eq!(c.source, "valid_authority_agent");
        // Baseline-safe physics: every joint position is finite.
        for js in &c.joint_states {
            assert!(js.position.is_finite(), "cmd {i}: joint position finite");
        }
        // Strictly +1 monotonic sequence starting at 1.
        assert_eq!(c.sequence, i as u64 + 1);
    }
}

#[test]
fn g_03_forged_signature_produces_distinct_tampered_envelopes() {
    let profile = load_ur10();
    let count = 8;
    let pca = "valid_envelope_b64";
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::ForgedSignature).generate_commands(
        count,
        pca,
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    let mut seen = std::collections::HashSet::new();
    for (i, c) in cmds.iter().enumerate() {
        assert_ne!(
            c.authority.pca_chain, pca,
            "cmd {i}: forged chain must differ from input"
        );
        assert!(
            c.authority.pca_chain.starts_with(pca),
            "cmd {i}: forged chain must start with input prefix (suffix-flip)"
        );
        assert!(
            c.authority.pca_chain.contains("SIGFLIP"),
            "cmd {i}: tampered chain carries SIGFLIP marker"
        );
        assert_eq!(
            c.metadata.get("chain_class").map(String::as_str),
            Some("forged_signature")
        );
        // Every command must produce a distinct tampered envelope.
        assert!(
            seen.insert(c.authority.pca_chain.clone()),
            "cmd {i}: tampered envelope collides with an earlier one"
        );
    }

    // Empty input fallback: sentinel pattern, still unique per command.
    let cmds_empty = ScenarioGenerator::new(&profile, ScenarioType::ForgedSignature)
        .generate_commands(4, "", &ops());
    let mut seen_empty = std::collections::HashSet::new();
    for (i, c) in cmds_empty.iter().enumerate() {
        assert!(
            c.authority.pca_chain.starts_with("FORGEDSIG"),
            "cmd {i}: empty-input fallback must use FORGEDSIG sentinel"
        );
        assert!(
            seen_empty.insert(c.authority.pca_chain.clone()),
            "cmd {i}: sentinel envelope collides"
        );
    }
}

#[test]
fn g_05_privilege_escalation_widens_required_ops() {
    let profile = load_ur10();
    let count = 12;
    let pca = "harness_supplied_chain_b64";
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::PrivilegeEscalation)
        .generate_commands(count, pca, &ops());
    assert_eq!(cmds.len(), count);

    let tier_ladder = ["actuate:joint:0", "actuate:joint:*", "actuate:*", "*"];
    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(
            c.authority.pca_chain, pca,
            "cmd {i}: pca_chain passes through"
        );
        // Breadth grows by index % 4 — narrowest to widest.
        let breadth = (i % tier_ladder.len()) + 1;
        let got: Vec<&str> = c
            .authority
            .required_ops
            .iter()
            .map(|o| o.as_str())
            .collect();
        let expected: Vec<&str> = tier_ladder.iter().take(breadth).copied().collect();
        assert_eq!(got, expected, "cmd {i}: required_ops widening pattern");
        assert_eq!(
            c.metadata.get("chain_class").map(String::as_str),
            Some("privilege_escalation")
        );
        assert_eq!(
            c.metadata.get("escalation_index").map(String::as_str),
            Some(i.to_string().as_str())
        );
    }
    // Every tier breadth (1..=4) must appear in a 12-command run.
    for breadth in 1..=tier_ladder.len() {
        assert!(
            cmds.iter()
                .any(|c| c.authority.required_ops.len() == breadth),
            "breadth {breadth} never appears"
        );
    }
}

#[test]
fn g_08_expired_chain_timestamps_are_one_year_in_past() {
    let profile = load_ur10();
    let count = 6;
    let pca = "harness_supplied_chain_b64";
    let now = Utc::now();
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::ExpiredChain).generate_commands(
        count,
        pca,
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    const ONE_YEAR_SECONDS: i64 = 365 * 24 * 3600;
    for (i, c) in cmds.iter().enumerate() {
        let age = (now - c.timestamp).num_seconds();
        // Allow a small wall-clock band for test-execution latency, but
        // every command must be at least ~1 year old.
        assert!(
            age >= ONE_YEAR_SECONDS - 60,
            "cmd {i}: age {age}s, expected >= ~{ONE_YEAR_SECONDS}s"
        );
        assert!(
            age <= ONE_YEAR_SECONDS + 60,
            "cmd {i}: age {age}s, expected <= ~{ONE_YEAR_SECONDS}s"
        );
        assert_eq!(c.authority.pca_chain, pca);
        assert_eq!(
            c.metadata.get("chain_class").map(String::as_str),
            Some("expired")
        );
        assert_eq!(
            c.metadata.get("seconds_in_past").map(String::as_str),
            Some(ONE_YEAR_SECONDS.to_string().as_str())
        );
    }
}

#[test]
fn spec_id_bindings_match_doc_table() {
    assert_eq!(ScenarioType::ValidAuthorityChain.spec_id(), "G-01");
    assert_eq!(ScenarioType::ForgedSignature.spec_id(), "G-03");
    assert_eq!(ScenarioType::PrivilegeEscalation.spec_id(), "G-05");
    assert_eq!(ScenarioType::ExpiredChain.spec_id(), "G-08");
}
