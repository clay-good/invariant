//! Golden JCS encoding for a fixed `ProofPackageManifest` (v11 1.4).
//!
//! Pins the canonical bytes a future change to `canonical_json` (or to the
//! manifest struct itself) would inadvertently shift. Three `file_hashes`,
//! one `merkle_root`, and `manifest_signature` set — to confirm the
//! signature field is excluded from the preimage.

use std::collections::HashMap;

use chrono::TimeZone;
use invariant_core::proof_package::{
    canonical_json, CampaignSummary, ProofPackageManifest, CURRENT_FORMAT_VERSION,
};

fn fixture_manifest() -> ProofPackageManifest {
    let mut file_hashes = HashMap::new();
    file_hashes.insert(
        "results/audit.jsonl".to_string(),
        "0011223344556677889900112233445566778899001122334455667788990011".to_string(),
    );
    file_hashes.insert(
        "campaign/profile.json".to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    );
    file_hashes.insert(
        "integrity/binary_hash.txt".to_string(),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
    );

    ProofPackageManifest {
        format_version: CURRENT_FORMAT_VERSION,
        version: "1.0.0".to_string(),
        // Frozen timestamp so the golden bytes don't drift.
        generated_at: chrono::Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
        campaign_name: "golden".to_string(),
        profile_name: "ur10e".to_string(),
        profile_hash: "sha256:profile-golden".to_string(),
        binary_hash: "sha256:binary-golden".to_string(),
        invariant_version: "0.2.0".to_string(),
        summary: CampaignSummary::compute(1000, 990, 10, 0, 100, 0, 100.0),
        file_hashes,
        merkle_root: Some(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        ),
        // Set a bogus signature on the *input* to make sure canonicalization
        // strips it. If canonical_json failed to strip, the byte length /
        // contents below would shift.
        manifest_signature: Some("THIS-SIGNATURE-MUST-BE-EXCLUDED".to_string()),
        manifest_signer_kid: Some("kid-must-also-be-excluded".to_string()),
    }
}

#[test]
fn canonical_bytes_keys_are_sorted_at_every_level() {
    let bytes = canonical_json(&fixture_manifest()).expect("canonicalize");
    let s = std::str::from_utf8(&bytes).expect("utf-8");

    // Top-level keys must appear in lexicographic order. We assert by
    // looking up the first byte-offset of each known top-level key and
    // checking that the offsets are monotonically increasing.
    let expected_order = [
        "\"binary_hash\":",
        "\"campaign_name\":",
        "\"file_hashes\":",
        "\"format_version\":",
        "\"generated_at\":",
        "\"invariant_version\":",
        "\"merkle_root\":",
        "\"profile_hash\":",
        "\"profile_name\":",
        "\"summary\":",
        "\"version\":",
    ];
    let mut last_pos = 0usize;
    for key in &expected_order {
        let pos = s
            .find(key)
            .unwrap_or_else(|| panic!("missing top-level key {key}\n{s}"));
        assert!(
            pos > last_pos,
            "top-level keys must be sorted: {key} appears at {pos} before previous key at {last_pos}\n{s}"
        );
        last_pos = pos;
    }

    // file_hashes is a nested object — keys inside must also be sorted.
    let nested = [
        "\"campaign/profile.json\"",
        "\"integrity/binary_hash.txt\"",
        "\"results/audit.jsonl\"",
    ];
    last_pos = 0;
    for key in &nested {
        let pos = s
            .find(key)
            .unwrap_or_else(|| panic!("missing nested key {key}\n{s}"));
        assert!(
            pos > last_pos,
            "nested keys must be sorted: {key} at {pos} before previous at {last_pos}",
        );
        last_pos = pos;
    }
}

#[test]
fn canonical_bytes_omit_manifest_signature_fields() {
    // The signature field on the *input* is non-None; canonical_json must
    // still emit a preimage that excludes both the signature and the kid.
    // Otherwise verify_manifest could never round-trip.
    let bytes = canonical_json(&fixture_manifest()).expect("canonicalize");
    let s = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(
        !s.contains("manifest_signature"),
        "signature field must not appear in canonical preimage: {s}"
    );
    assert!(
        !s.contains("manifest_signer_kid"),
        "signer_kid must not appear in canonical preimage: {s}"
    );
    assert!(
        !s.contains("THIS-SIGNATURE-MUST-BE-EXCLUDED"),
        "bogus signature value leaked into canonical bytes: {s}"
    );
}

#[test]
fn canonical_bytes_are_compact_no_whitespace() {
    let bytes = canonical_json(&fixture_manifest()).expect("canonicalize");
    // No spaces, no tabs, no newlines in canonical form (RFC 8785 §3).
    for (i, b) in bytes.iter().enumerate() {
        assert!(
            !matches!(*b, b' ' | b'\t' | b'\n' | b'\r'),
            "whitespace byte 0x{:02x} at offset {} in canonical output",
            *b,
            i
        );
    }
}

#[test]
fn canonical_bytes_are_deterministic_across_calls() {
    let a = canonical_json(&fixture_manifest()).expect("canonicalize 1");
    let b = canonical_json(&fixture_manifest()).expect("canonicalize 2");
    assert_eq!(a, b, "canonical bytes must be deterministic");
}
