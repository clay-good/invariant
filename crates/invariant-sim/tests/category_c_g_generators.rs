//! Intent tests for the Category C / G scenarios that already ship in
//! `crates/invariant-sim/src/robotics/scenario.rs` (v11 prompts 2.2 + 2.6
//! — implemented subset).
//!
//! Spec: `docs/robotics/spec-15m-campaign.md` §3 (categories C, G).
//!
//! Scope: pin the *intent* of the four already-shipped variants whose
//! spec IDs were promoted on 2026-05-17 (see `docs/scenario-id-map.md`).
//! Mirrors the Category B pattern in [`category_b_generators.rs`].
//!
//! | Spec ID | Variant                | What this file asserts                              |
//! |---------|------------------------|------------------------------------------------------|
//! | C-02    | `ExclusionZone`        | Every EE position lies inside ≥1 exclusion zone.    |
//! | C-03    | `CncTending`           | Loading phase overrides `conditional` zone off; cutting phase on. |
//! | G-02    | `AuthorityEscalation`  | `pca_chain` is the empty string on every command.    |
//! | G-10    | `ChainForgery`         | `pca_chain` is non-empty but rejects base64 decode.  |
//!
//! The remaining Category C / G spec IDs (C-01, C-04..C-06, G-01,
//! G-03..G-09) still need generators — tracked under v11 prompts 2.2 / 2.6.

use base64::Engine;
use invariant_robotics::models::authority::Operation;
use invariant_robotics::models::profile::ExclusionZone;
use invariant_robotics::profiles::load_builtin;
use invariant_sim::robotics::scenario::{ScenarioGenerator, ScenarioType};

const COUNT: usize = 20;
const PCA_PLACEHOLDER: &str = "AAAA"; // valid base64, irrelevant to these tests

fn ops() -> [Operation; 1] {
    [Operation::new("actuate:*").expect("valid op")]
}

fn point_in_aabb(p: [f64; 3], min: [f64; 3], max: [f64; 3]) -> bool {
    (0..3).all(|i| p[i] >= min[i] && p[i] <= max[i])
}

fn point_in_sphere(p: [f64; 3], center: [f64; 3], radius: f64) -> bool {
    let dx = p[0] - center[0];
    let dy = p[1] - center[1];
    let dz = p[2] - center[2];
    (dx * dx + dy * dy + dz * dz).sqrt() <= radius
}

#[test]
fn c02_exclusion_zone_places_ee_inside_some_zone() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::ExclusionZone);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert!(!cmds.is_empty(), "generator should produce commands");

    for (i, cmd) in cmds.iter().enumerate() {
        let ee_pos = cmd
            .end_effector_positions
            .first()
            .map(|e| e.position)
            .unwrap_or_else(|| panic!("cmd {i} missing EE position"));

        let inside_any = profile.exclusion_zones.iter().any(|z| match z {
            ExclusionZone::Aabb { min, max, .. } => point_in_aabb(ee_pos, *min, *max),
            ExclusionZone::Sphere { center, radius, .. } => {
                point_in_sphere(ee_pos, *center, *radius)
            }
            // ExclusionZone is `#[non_exhaustive]` (P3-5 forward-compat for
            // Cylinder etc.). Future variants we don't know about can't
            // satisfy this assertion — fail closed by returning false.
            _ => false,
        });
        assert!(
            inside_any,
            "C-02 cmd {i}: EE at {ee_pos:?} should lie inside some exclusion zone"
        );
    }
}

#[test]
fn c03_cnc_tending_toggles_conditional_zone_between_loading_and_cutting() {
    let profile = load_builtin("ur10e_haas_cell").expect("ur10e_haas_cell builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::CncTending);
    let cmds = gen.generate_commands(COUNT, PCA_PLACEHOLDER, &ops());
    assert_eq!(cmds.len(), COUNT);

    // The generator looks for the first `conditional: true` exclusion
    // zone. ur10e_haas_cell has exactly one (`haas_spindle_zone`).
    let conditional_zone_name = profile
        .exclusion_zones
        .iter()
        .find(|z| {
            matches!(
                z,
                ExclusionZone::Aabb {
                    conditional: true,
                    ..
                } | ExclusionZone::Sphere {
                    conditional: true,
                    ..
                }
            )
        })
        .map(|z| match z {
            ExclusionZone::Aabb { name, .. } => name.clone(),
            ExclusionZone::Sphere { name, .. } => name.clone(),
            _ => String::new(),
        })
        .expect("ur10e_haas_cell must define a conditional exclusion zone");

    let half = COUNT / 2;
    for (i, cmd) in cmds.iter().enumerate() {
        let expected_active = i >= half; // loading phase = off, cutting = on
        let actual = cmd
            .zone_overrides
            .get(&conditional_zone_name)
            .copied()
            .unwrap_or_else(|| panic!("cmd {i} missing override for `{conditional_zone_name}`"));
        assert_eq!(
            actual,
            expected_active,
            "C-03 cmd {i} (phase={}): conditional zone override should be {expected_active}",
            if expected_active {
                "cutting"
            } else {
                "loading"
            }
        );
    }
}

#[test]
fn g02_authority_escalation_emits_empty_pca_chain() {
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::AuthorityEscalation);
    let cmds = gen.generate_commands(8, PCA_PLACEHOLDER, &ops());
    assert!(!cmds.is_empty());

    for (i, cmd) in cmds.iter().enumerate() {
        assert!(
            cmd.authority.pca_chain.is_empty(),
            "G-02 cmd {i}: expected empty pca_chain, got {:?}",
            cmd.authority.pca_chain
        );
    }
}

#[test]
fn g10_chain_forgery_emits_non_empty_pca_chain_that_fails_base64_decode() {
    let profile = load_builtin("franka_panda").expect("franka_panda builtin");
    let gen = ScenarioGenerator::new(&profile, ScenarioType::ChainForgery);
    let cmds = gen.generate_commands(8, PCA_PLACEHOLDER, &ops());
    assert!(!cmds.is_empty());

    let engine = base64::engine::general_purpose::STANDARD;
    for (i, cmd) in cmds.iter().enumerate() {
        assert!(
            !cmd.authority.pca_chain.is_empty(),
            "G-10 cmd {i}: pca_chain must be non-empty (the forgery payload)"
        );
        let decode = engine.decode(&cmd.authority.pca_chain);
        assert!(
            decode.is_err(),
            "G-10 cmd {i}: pca_chain `{}` unexpectedly decodes as valid base64",
            cmd.authority.pca_chain
        );
    }
}
