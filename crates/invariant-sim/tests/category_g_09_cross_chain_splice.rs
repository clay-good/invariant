//! Intent test for G-09 cross-chain splice (v11 2.6 closure).
//!
//! Mirrors the in-tree `g09_splice_replaces_middle_hop_with_different_parent`
//! unit test at the scenario layer: emits commands whose embedded
//! authority chain encodes a two-hop synthetic envelope with hop 1's
//! `predecessor_digest` deliberately disagreeing with
//! `sha256(canonical_bytes(hop 0))`. The validator running in v11 1.2
//! opt-in detection mode must reject every command with
//! `PredecessorDigestMismatch { hop: 1 }`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
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
fn g_09_cross_chain_splice_envelope_shape() {
    let profile = load_ur10();
    let count = 8;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::CrossChainSplice).generate_commands(
        count,
        "harness_chain_b64",
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    let mut seen = std::collections::HashSet::new();
    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(c.source, "cross_chain_splice_agent");
        assert_eq!(
            c.metadata.get("chain_class").map(String::as_str),
            Some("cross_chain_splice"),
            "cmd {i}: chain_class metadata"
        );
        // Per-index mismatched-digest byte = 0xAB ^ i.
        let expected_byte = 0xABu8 ^ (i as u8);
        let expected_label = format!("{:#04x}", expected_byte);
        assert_eq!(
            c.metadata.get("mismatched_digest_byte").map(String::as_str),
            Some(expected_label.as_str()),
            "cmd {i}: mismatched_digest_byte metadata"
        );
        // Envelope decodes as base64 and as UTF-8 JSON; hop 1 carries
        // the per-index mismatched digest 32 times.
        let decoded = STANDARD
            .decode(c.authority.pca_chain.as_bytes())
            .expect("envelope decodes as base64");
        let text = std::str::from_utf8(&decoded).expect("envelope is utf-8 JSON");
        let expected_digest: String = (0..32).map(|_| format!("{:02x}", expected_byte)).collect();
        assert!(
            text.contains(&expected_digest),
            "cmd {i}: envelope must embed the mismatched digest {expected_digest}: {text}"
        );
        // Hop 0 always carries the zero-digest sentinel.
        assert!(
            text.contains(
                "\"predecessor_digest\":\"0000000000000000000000000000000000000000000000000000000000000000\""
            ),
            "cmd {i}: hop 0 must carry the zero digest sentinel"
        );
        // Envelopes must be per-index distinct so the spliced state isn't
        // accidentally cached.
        assert!(
            seen.insert(c.authority.pca_chain.clone()),
            "cmd {i}: envelope collides with an earlier one"
        );
        // Joint state stays baseline-safe so the failure mode is
        // isolated to the authority binding.
        for js in &c.joint_states {
            assert!(js.position.is_finite(), "cmd {i}: position is finite");
        }
    }
}

#[test]
fn g_09_spec_id_binding_is_stable() {
    assert_eq!(ScenarioType::CrossChainSplice.spec_id(), "G-09");
}
