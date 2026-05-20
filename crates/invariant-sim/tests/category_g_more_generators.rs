//! Intent tests for the second Category G batch:
//! G-04 `KeySubstitution`, G-06 `ProvenanceMutation`, G-07 `WildcardExploit`.
//!
//! These three close every Category G spec row except G-09
//! (cross-chain splice) which blocks on v11 1.2 predecessor digest.
//!
//! v11 prompt 2.6 — see `docs/robotics/spec-v11.md` and
//! `docs/robotics/spec-15m-campaign.md` §3.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
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
fn g_04_key_substitution_emits_untrusted_kid_envelope() {
    let profile = load_ur10();
    let count = 8;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::KeySubstitution)
        .generate_commands(count, "harness_chain_b64", &ops());
    assert_eq!(cmds.len(), count);

    let mut seen = std::collections::HashSet::new();
    for (i, c) in cmds.iter().enumerate() {
        let expected_kid = format!("untrusted_kid_{i:08}");
        assert_eq!(
            c.metadata.get("chain_class").map(String::as_str),
            Some("key_substitution"),
            "cmd {i}: chain_class metadata"
        );
        assert_eq!(
            c.metadata.get("untrusted_kid").cloned(),
            Some(expected_kid.clone()),
            "cmd {i}: untrusted_kid metadata"
        );
        assert_eq!(c.source, "key_substitution_agent");
        // Envelope must decode as base64; the JSON inside must carry
        // the per-command untrusted kid.
        let decoded = STANDARD
            .decode(c.authority.pca_chain.as_bytes())
            .expect("envelope decodes as base64");
        let text = std::str::from_utf8(&decoded).expect("envelope is utf-8 JSON");
        assert!(
            text.contains(&expected_kid),
            "cmd {i}: envelope embeds untrusted kid"
        );
        // Every command's envelope must be distinct.
        assert!(
            seen.insert(c.authority.pca_chain.clone()),
            "cmd {i}: envelope collides with an earlier one"
        );
        assert_eq!(c.sequence, i as u64 + 1);
    }
}

#[test]
fn g_06_provenance_mutation_emits_two_hop_chain_with_p0_drift() {
    let profile = load_ur10();
    let count = 6;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::ProvenanceMutation)
        .generate_commands(count, "harness_chain_b64", &ops());
    assert_eq!(cmds.len(), count);

    for (i, c) in cmds.iter().enumerate() {
        let expected_p0 = format!("agent_beta_{i:08}");
        assert_eq!(
            c.metadata.get("chain_class").map(String::as_str),
            Some("provenance_mutation"),
            "cmd {i}: chain_class metadata"
        );
        assert_eq!(
            c.metadata.get("mutated_p0").cloned(),
            Some(expected_p0.clone()),
            "cmd {i}: mutated_p0 metadata"
        );
        assert_eq!(c.source, "provenance_mutation_agent");
        let decoded = STANDARD
            .decode(c.authority.pca_chain.as_bytes())
            .expect("envelope decodes as base64");
        let text = std::str::from_utf8(&decoded).expect("envelope is utf-8 JSON");
        // Hop 0 names agent_alpha; hop 1 mutates p_0 to agent_beta_<i>.
        assert!(text.contains("agent_alpha"), "cmd {i}: hop 0 p_0 present");
        assert!(
            text.contains(&expected_p0),
            "cmd {i}: hop 1 mutated p_0 present"
        );
        // Two distinct hop payload tags.
        assert!(text.contains(&format!("hop0_{i}")), "cmd {i}: hop0 tag");
        assert!(text.contains(&format!("hop1_{i}")), "cmd {i}: hop1 tag");
    }
}

#[test]
fn g_07_wildcard_exploit_required_ops_outside_actuate_scope() {
    let profile = load_ur10();
    let count = 12;
    let pca = "harness_chain_b64";
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::WildcardExploit)
        .generate_commands(count, pca, &ops());
    assert_eq!(cmds.len(), count);

    let rotation = [
        "sensor.read:imu",
        "read:sensor",
        "admin:profile.reload",
        "debug:trace.export",
    ];
    let mut seen_rotation = std::collections::HashSet::new();
    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(
            c.authority.pca_chain, pca,
            "cmd {i}: pca_chain passes through"
        );
        assert_eq!(
            c.authority.required_ops.len(),
            1,
            "cmd {i}: exactly one outside-scope op claimed"
        );
        let expected = rotation[i % rotation.len()];
        let claimed = c.authority.required_ops[0].as_str();
        assert_eq!(claimed, expected, "cmd {i}: op rotation");
        // Sanity: none of the claimed ops sit under the actuate tree.
        assert!(
            !claimed.starts_with("actuate:"),
            "cmd {i}: op {claimed} must lie outside actuate scope"
        );
        assert_eq!(
            c.metadata.get("chain_class").map(String::as_str),
            Some("wildcard_exploit")
        );
        assert_eq!(
            c.metadata.get("outside_scope_op").map(String::as_str),
            Some(expected)
        );
        seen_rotation.insert(expected);
    }
    // All four rotation slots must appear in a 12-command run.
    assert_eq!(
        seen_rotation.len(),
        rotation.len(),
        "every rotation slot must appear at least once"
    );
}

#[test]
fn spec_id_bindings_match_doc_table() {
    assert_eq!(ScenarioType::KeySubstitution.spec_id(), "G-04");
    assert_eq!(ScenarioType::ProvenanceMutation.spec_id(), "G-06");
    assert_eq!(ScenarioType::WildcardExploit.spec_id(), "G-07");
}
