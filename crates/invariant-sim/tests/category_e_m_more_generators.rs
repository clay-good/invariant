//! Intent tests for Category E (E-05 / E-06) and Category M (M-06) — the
//! ISO 15066 human-proximity force, bimanual coordination, and
//! mixed-profile audit scenarios.
//!
//! Each test asserts the deterministic shape its generator must produce; it
//! does not exercise the validator. Validator behaviour for these failure
//! modes is covered by the per-check unit tests under
//! `crates/invariant-robotics`.
//!
//! v11 prompts 2.4 (Category E tail) / 2.10 (Category M tail) — see
//! `docs/robotics/spec-v11.md` and `docs/robotics/spec-15m-campaign.md` §3.

use invariant_robotics::models::authority::Operation;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

fn ops() -> Vec<Operation> {
    vec![Operation::new("actuate:*").unwrap()]
}

#[test]
fn e_05_iso_15066_places_ee_in_zone_with_overforce() {
    // ur10 declares two proximity zones (human_warning + human_critical).
    let profile = load_builtin("ur10").expect("ur10 profile available");
    let zone_centre = match profile.proximity_zones.first().unwrap() {
        invariant_robotics::models::profile::ProximityZone::Sphere { center, .. } => *center,
        _ => unreachable!("ur10 proximity zones are spheres"),
    };
    let count = 12;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::Iso15066HumanProximityForce)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    for c in &cmds {
        // EE placed at the human-zone centre.
        assert_eq!(c.end_effector_positions.len(), 1);
        assert_eq!(c.end_effector_positions[0].position, zone_centre);

        // 200 N applied on +x — above the ISO 15066 face limit (65 N)
        // and (for ur10) above the per-EE `max_force_n = 150 N`.
        assert_eq!(c.end_effector_forces.len(), 1);
        let fx = c.end_effector_forces[0].force[0];
        assert!(fx > 65.0, "force {fx} N must exceed the 65 N face limit");
        assert!(
            fx > profile.end_effectors[0].max_force_n,
            "for ur10 the force must also exceed per-EE max_force_n",
        );

        assert_eq!(
            c.metadata.get("iso_15066").map(String::as_str),
            Some("true"),
        );
        assert_eq!(c.source, "iso_15066_human_proximity_force");
    }
}

#[test]
fn e_06_bimanual_emits_two_arms_with_combined_overforce() {
    let profile = load_builtin("ur10").expect("ur10 profile available");
    let max_force = profile.end_effectors[0].max_force_n;
    let per_arm_expected = 0.6 * max_force;
    let count = 8;
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::BimanualCoordination)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    for c in &cmds {
        assert_eq!(c.end_effector_forces.len(), 2);
        let names: Vec<&str> = c
            .end_effector_forces
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(names.contains(&"bimanual_left"));
        assert!(names.contains(&"bimanual_right"));

        for f in &c.end_effector_forces {
            assert!(
                (f.force[0] - per_arm_expected).abs() < 1e-9,
                "per-arm force must be 0.6× max_force_n, got {}",
                f.force[0],
            );
            // Individually each is *below* the per-EE limit …
            assert!(f.force[0] < max_force);
        }

        // … but combined is above.
        let combined: f64 = c.end_effector_forces.iter().map(|f| f.force[0]).sum();
        assert!(
            combined > max_force,
            "combined bimanual force {combined} must exceed max_force_n {max_force}",
        );

        assert_eq!(c.metadata.get("bimanual").map(String::as_str), Some("true"));
        assert_eq!(c.source, "bimanual_coordination");
    }
}

#[test]
fn m_06_mixed_profiles_rotates_source_with_per_source_monotonic_sequence() {
    let profile = load_builtin("ur10").expect("ur10 profile available");
    let count = 30; // 10 commands per source
    let cmds = ScenarioGenerator::new(&profile, ScenarioType::MixedProfilesAudit)
        .generate_commands(count, "", &ops());
    assert_eq!(cmds.len(), count);

    let sources = ["robot_alpha", "robot_beta", "robot_gamma"];

    // Source rotation tracks the index modulus exactly.
    for (i, c) in cmds.iter().enumerate() {
        assert_eq!(c.source.as_str(), sources[i % sources.len()]);
    }

    // Per-source sequences are strictly monotonic starting at 1.
    for s in sources {
        let seqs: Vec<u64> = cmds
            .iter()
            .filter(|c| c.source == s)
            .map(|c| c.sequence)
            .collect();
        assert_eq!(seqs.len(), count / sources.len());
        assert_eq!(seqs[0], 1, "first sequence for {s} must be 1");
        for w in seqs.windows(2) {
            assert!(w[1] > w[0], "per-source sequence must be monotonic for {s}");
        }
    }
}
