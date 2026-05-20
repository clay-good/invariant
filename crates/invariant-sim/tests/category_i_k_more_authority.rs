//! Intent tests for the next batch of scenario generators:
//! I-04 `AuthorityLaundering`, I-06 `WatchdogManipulation`,
//! I-08 `MultiAgentCollusion`, K-06 `ValidatorRestart`.
//!
//! Each test asserts the deterministic shape its generator must produce;
//! validator behaviour for these failure modes is covered by the per-check
//! unit tests under `crates/invariant-robotics`.
//!
//! v11 prompts 2.8 (Category I closure) and 2.9 (Category K closure) —
//! see `docs/robotics/spec-v11.md` and `docs/robotics/spec-15m-campaign.md` §3.

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
fn i_04_authority_laundering_cycles_scope_tiers() {
    let profile = load_ur10();
    let count = 16;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::AuthorityLaundering)
        .generate_commands(count, "ignored_chain", &ops());
    assert_eq!(cmds.len(), count);

    let expected = ["actuate:joint:0", "actuate:joint:*", "actuate:*", "*"];
    for (i, c) in cmds.iter().enumerate() {
        // Every command carries an empty PCA chain — the failure mode is
        // unambiguously authority, even though the laundering attempt
        // cycles wider ops scopes.
        assert!(
            c.authority.pca_chain.is_empty(),
            "cmd {i}: pca_chain should be empty for I-04, got {:?}",
            c.authority.pca_chain
        );
        let tier = i % expected.len();
        let ops_strs: Vec<&str> = c
            .authority
            .required_ops
            .iter()
            .map(|o| o.as_str())
            .collect();
        assert_eq!(
            ops_strs,
            vec![expected[tier]],
            "cmd {i}: expected scope tier {tier} -> {:?}",
            expected[tier]
        );
        assert_eq!(
            c.metadata.get("scope_breadth").map(String::as_str),
            Some((tier + 1).to_string().as_str()),
            "cmd {i}: scope_breadth metadata must match tier index"
        );
        // Joint state stays baseline-safe so the failure mode is isolated.
        for js in &c.joint_states {
            assert!(js.position.is_finite(), "cmd {i}: joint position finite");
        }
    }
    // All four tiers must appear at least once in a 16-command run.
    for (tier, &name) in expected.iter().enumerate() {
        assert!(
            cmds.iter()
                .any(|c| { c.authority.required_ops.iter().any(|o| o.as_str() == name) }),
            "scope tier {tier} ({name}) never appears"
        );
    }
}

#[test]
fn i_06_watchdog_manipulation_three_phase_pattern() {
    let profile = load_ur10();
    let count = 30;
    let pca = "fresh_chain_b64";
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::WatchdogManipulation)
        .generate_commands(count, pca, &ops());
    assert_eq!(cmds.len(), count);

    let third = count / 3;
    let two_thirds = third * 2;
    let normal_dt = profile.max_delta_time * 0.5;
    let missed_dt = profile.max_delta_time * 5.0;

    for (i, c) in cmds.iter().enumerate() {
        let phase = c
            .metadata
            .get("phase")
            .expect("phase metadata required for I-06");
        if i < third {
            assert_eq!(phase, "A", "cmd {i}: phase A expected");
            assert!(
                (c.delta_time - missed_dt).abs() < 1e-12,
                "cmd {i}: phase A delta_time should be 5× max"
            );
            assert_eq!(
                c.authority.pca_chain, pca,
                "cmd {i}: phase A keeps authority"
            );
        } else if i < two_thirds {
            assert_eq!(phase, "B", "cmd {i}: phase B expected");
            assert!(
                (c.delta_time - missed_dt).abs() < 1e-12,
                "cmd {i}: phase B delta_time still 5× max"
            );
            assert!(
                c.authority.pca_chain.is_empty(),
                "cmd {i}: phase B drops authority"
            );
        } else {
            assert_eq!(phase, "C", "cmd {i}: phase C expected");
            assert!(
                (c.delta_time - normal_dt).abs() < 1e-12,
                "cmd {i}: phase C delta_time normal"
            );
            assert_eq!(
                c.authority.pca_chain, pca,
                "cmd {i}: phase C re-establishes authority"
            );
        }
        // Joint state stays baseline-safe across all phases.
        for js in &c.joint_states {
            assert!(js.position.is_finite(), "cmd {i}: joint position finite");
        }
    }
}

#[test]
fn i_08_multi_agent_collusion_alternates_with_per_source_monotonicity() {
    let profile = load_ur10();
    let count = 20;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::MultiAgentCollusion)
        .generate_commands(count, "ignored_chain", &ops());
    assert_eq!(cmds.len(), count);

    // Per-source sequence trackers — both must observe a strictly +1
    // monotonic stream so the failure mode is isolated to authority.
    let mut last_seq_a: Option<u64> = None;
    let mut last_seq_b: Option<u64> = None;
    let mut saw_a = false;
    let mut saw_b = false;

    for (i, c) in cmds.iter().enumerate() {
        // Empty authority on every command.
        assert!(
            c.authority.pca_chain.is_empty(),
            "cmd {i}: pca_chain must be empty"
        );
        assert_eq!(
            c.metadata.get("coordinated_attack").map(String::as_str),
            Some("true"),
            "cmd {i}: coordinated_attack metadata must be set"
        );

        let agent = c
            .metadata
            .get("colluding_agent")
            .expect("colluding_agent metadata required");

        match (i % 2, c.source.as_str(), agent.as_str()) {
            (0, "cognitive_agent_a", "a") => {
                saw_a = true;
                let ops_strs: Vec<&str> = c
                    .authority
                    .required_ops
                    .iter()
                    .map(|o| o.as_str())
                    .collect();
                assert_eq!(ops_strs, vec!["actuate:joint_0"]);
                if let Some(prev) = last_seq_a {
                    assert_eq!(c.sequence, prev + 1, "cmd {i}: agent A sequence must be +1");
                }
                last_seq_a = Some(c.sequence);
            }
            (1, "cognitive_agent_b", "b") => {
                saw_b = true;
                let ops_strs: Vec<&str> = c
                    .authority
                    .required_ops
                    .iter()
                    .map(|o| o.as_str())
                    .collect();
                assert_eq!(ops_strs, vec!["sensor.read:imu"]);
                if let Some(prev) = last_seq_b {
                    assert_eq!(c.sequence, prev + 1, "cmd {i}: agent B sequence must be +1");
                }
                last_seq_b = Some(c.sequence);
            }
            other => panic!("cmd {i}: unexpected parity/source/agent triple {other:?}"),
        }
    }
    assert!(saw_a && saw_b, "both colluding agents must appear");
}

#[test]
fn k_06_validator_restart_resets_per_source_sequence() {
    let profile = load_ur10();
    let count = 20;
    let pca = "harness_chain";
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::ValidatorRestart).generate_commands(
        count,
        pca,
        &ops(),
    );
    assert_eq!(cmds.len(), count);

    let half = count / 2;
    let mut saw_pre = false;
    let mut saw_post = false;
    let mut saw_restart_marker = false;

    for (i, c) in cmds.iter().enumerate() {
        // Baseline-safe physics + harness's pca_chain throughout.
        assert_eq!(c.authority.pca_chain, pca, "cmd {i}: pca_chain unchanged");
        for js in &c.joint_states {
            assert!(js.position.is_finite(), "cmd {i}: joint position finite");
        }

        if i < half {
            assert_eq!(c.source, "pre_restart", "cmd {i}: pre-restart source");
            assert_eq!(c.sequence, i as u64 + 1, "cmd {i}: pre-restart sequence");
            saw_pre = true;
        } else {
            assert_eq!(c.source, "post_restart", "cmd {i}: post-restart source");
            assert_eq!(
                c.sequence,
                (i - half) as u64 + 1,
                "cmd {i}: post-restart sequence resets"
            );
            saw_post = true;
        }

        // The boundary command stamps restart_event="true" exactly once.
        if c.metadata.get("restart_event").map(String::as_str) == Some("true") {
            assert_eq!(i, half, "restart_event must be stamped on boundary index");
            assert!(
                !saw_restart_marker,
                "restart_event must appear exactly once"
            );
            saw_restart_marker = true;
        }
    }
    assert!(saw_pre, "must observe pre-restart segment");
    assert!(saw_post, "must observe post-restart segment");
    assert!(saw_restart_marker, "must observe restart_event marker");
}

#[test]
fn spec_id_bindings_match_doc_table() {
    assert_eq!(ScenarioType::AuthorityLaundering.spec_id(), "I-04");
    assert_eq!(ScenarioType::WatchdogManipulation.spec_id(), "I-06");
    assert_eq!(ScenarioType::MultiAgentCollusion.spec_id(), "I-08");
    assert_eq!(ScenarioType::ValidatorRestart.spec_id(), "K-06");
}
