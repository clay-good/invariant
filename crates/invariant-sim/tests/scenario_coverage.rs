//! Spec-ID coverage report for `ScenarioType` variants (v12-N-1).
//!
//! Today the gap report is non-failing — adversarial scenarios that pre-date
//! the §3 ID system are still "unassigned". Once v11 Phase 2 lands a generator
//! for every spec ID, flip the eprintln-style report below into a hard
//! `assert!` so silent regressions stop being possible.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

use invariant_sim::robotics::scenario::ScenarioType;

/// Step 1: `Scenario::all()` enumerates the full variant set with no duplicates.
///
/// We do not pull `strum::IntoEnumIterator` in just for the count. Instead,
/// `ScenarioType::spec_id` is an exhaustive match (no `_` arm), so any
/// new variant is a compile error until it is bound in `spec_id` AND added
/// to `all()`. This test asserts the second half of that contract — every
/// item in `all()` is distinct and `spec_id` is callable on every one.
#[test]
fn all_is_distinct_and_spec_id_callable() {
    let variants = ScenarioType::all();
    assert!(
        !variants.is_empty(),
        "ScenarioType::all() must not be empty"
    );

    let mut seen = HashSet::new();
    for v in variants {
        let inserted = seen.insert(format!("{v:?}"));
        assert!(
            inserted,
            "ScenarioType::all() contains a duplicate: {v:?}"
        );
        // spec_id must not panic on any variant.
        let _ = v.spec_id();
    }
    assert_eq!(seen.len(), variants.len());
}

/// Step 2: every spec_id is either "unassigned" or matches `^[A-N]-\d{2}$`.
#[test]
fn every_spec_id_is_unassigned_or_well_formed() {
    for v in ScenarioType::all() {
        let id = v.spec_id();
        if id == "unassigned" {
            continue;
        }
        assert!(
            is_well_formed_spec_id(id),
            "ScenarioType::{v:?} returned malformed spec_id {id:?}; \
             expected 'unassigned' or `[A-N]-\\d{{2}}`"
        );
    }
}

/// Step 3: report which spec IDs in `docs/spec-15m-campaign.md` have no
/// implementing variant yet. Non-failing today; promote to a hard assert
/// once v11 Phase 2 closes (see N-1 prompt).
#[test]
fn spec_id_gap_report() {
    let spec_ids = extract_spec_ids_from_campaign_doc();
    assert!(
        spec_ids.len() >= 100,
        "expected ≥100 spec IDs in docs/robotics/spec-15m-campaign.md, found {}",
        spec_ids.len()
    );

    let mut implemented: BTreeSet<&'static str> = BTreeSet::new();
    for v in ScenarioType::all() {
        let id = v.spec_id();
        if id != "unassigned" {
            implemented.insert(id);
        }
    }

    let missing: Vec<String> = spec_ids
        .iter()
        .filter(|id| !implemented.contains(id.as_str()))
        .cloned()
        .collect();

    eprintln!(
        "spec_id coverage: {}/{} ids implemented; {} gaps",
        implemented.len(),
        spec_ids.len(),
        missing.len()
    );
    if !missing.is_empty() {
        eprintln!("missing spec IDs (non-failing; tracked by v11 Phase 2):");
        for id in &missing {
            eprintln!("  - {id}");
        }
    }

    // TODO(spec-v11 Phase 2): replace this with `assert!(missing.is_empty())`
    // once generators for every category land.
}

// ---- helpers ---------------------------------------------------------------

fn is_well_formed_spec_id(s: &str) -> bool {
    // `^[A-N]-\d{2}$` without pulling in `regex`.
    let bytes = s.as_bytes();
    bytes.len() == 4
        && (bytes[0] >= b'A' && bytes[0] <= b'N')
        && bytes[1] == b'-'
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
}

fn extract_spec_ids_from_campaign_doc() -> BTreeSet<String> {
    let path = workspace_root()
        .join("docs")
        .join("robotics")
        .join("spec-15m-campaign.md");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

    let mut ids = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let b = bytes[i];
        if (b'A'..=b'N').contains(&b)
            && bytes.get(i + 1) == Some(&b'-')
            && bytes.get(i + 2).map(|c| c.is_ascii_digit()).unwrap_or(false)
            && bytes.get(i + 3).map(|c| c.is_ascii_digit()).unwrap_or(false)
        {
            // Reject if the character before is alphanumeric (avoid matching
            // mid-word like `bA-01`).
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            // Reject if the character after is alphanumeric.
            let after = bytes.get(i + 4);
            let after_ok = after.is_none() || !after.unwrap().is_ascii_alphanumeric();
            if prev_ok && after_ok {
                ids.insert(std::str::from_utf8(&bytes[i..i + 4]).unwrap().to_string());
                i += 4;
                continue;
            }
        }
        i += 1;
    }
    ids
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/invariant-sim/.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root must be two levels above the crate manifest")
        .to_path_buf()
}

#[test]
fn well_formed_helper_matches_only_expected_shape() {
    assert!(is_well_formed_spec_id("A-01"));
    assert!(is_well_formed_spec_id("N-10"));
    assert!(!is_well_formed_spec_id("a-01"));
    assert!(!is_well_formed_spec_id("O-01")); // O is past N
    assert!(!is_well_formed_spec_id("A-1"));
    assert!(!is_well_formed_spec_id("A-001"));
    assert!(!is_well_formed_spec_id("unassigned"));
}
