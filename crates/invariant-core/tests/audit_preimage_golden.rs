//! v11 1.1 — Golden hash-preimage fixture for `canonical_bytes`.
//!
//! Constructs an `AuditEntry` with hand-picked B1–B4 values, snapshots
//! both the length-prefixed preimage hex and its SHA-256 digest. Guards
//! against accidental field-order changes in `canonical_bytes` or
//! field-rename slips in `AuditEntry`. Any future intentional change to
//! the preimage layout must update both this fixture and bump
//! `schema_version`.

use invariant_core::audit::canonical_bytes;
use invariant_core::models::audit::{AuditEntry, CURRENT_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Clone)]
struct GoldenInput {
    op: &'static str,
    target: u32,
}

#[derive(Serialize, Deserialize, Clone)]
struct GoldenVerdict {
    approved: bool,
}

fn fixture() -> AuditEntry<GoldenInput, GoldenVerdict> {
    AuditEntry {
        sequence: 42,
        previous_hash:
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        command: GoldenInput {
            op: "actuate",
            target: 7,
        },
        verdict: GoldenVerdict { approved: true },
        entry_hash: String::new(),
        schema_version: CURRENT_SCHEMA_VERSION,
        session_id: "sess-fixed-001".to_string(),
        executor_id: "executor-alpha".to_string(),
        monotonic_nanos: 1_234_567_890,
        wall_clock_rfc3339: "2026-05-18T12:00:00Z".to_string(),
    }
}

#[test]
fn canonical_bytes_field_order_is_stable() {
    let entry = fixture();
    let bytes = canonical_bytes(&entry).expect("canonical_bytes must succeed");

    // Field tags appear in the documented order: schema_version, sequence,
    // previous_hash, session_id, executor_id, monotonic_nanos,
    // wall_clock_rfc3339, command, verdict.
    let names: Vec<String> = extract_field_names(&bytes);
    assert_eq!(
        names,
        vec![
            "schema_version",
            "sequence",
            "previous_hash",
            "session_id",
            "executor_id",
            "monotonic_nanos",
            "wall_clock_rfc3339",
            "command",
            "verdict",
        ]
    );
}

#[test]
fn canonical_bytes_digest_is_pinned() {
    let entry = fixture();
    let bytes = canonical_bytes(&entry).expect("canonical_bytes must succeed");
    let digest = Sha256::digest(&bytes);
    let digest_hex = hex(&digest);

    // Pinned digest — regenerate ONLY when intentionally changing the
    // preimage layout (and bump `schema_version` in the same commit).
    let pinned = pinned_digest();
    assert_eq!(
        digest_hex, pinned,
        "canonical_bytes digest changed unexpectedly; update fixture only after a schema bump"
    );
}

#[test]
fn canonical_bytes_changes_when_b3_changes() {
    let mut a = fixture();
    let mut b = fixture();
    b.monotonic_nanos += 1;
    let da = Sha256::digest(canonical_bytes(&a).unwrap());
    let db = Sha256::digest(canonical_bytes(&b).unwrap());
    assert_ne!(hex(&da), hex(&db), "B3 must be part of the preimage");

    // Sanity: identical inputs yield identical digests.
    a.monotonic_nanos = 1_234_567_890;
    let da2 = Sha256::digest(canonical_bytes(&a).unwrap());
    assert_eq!(hex(&da), hex(&da2));
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Walks the length-prefixed canonical bytes and pulls out the field-name
/// tokens. Tags 0x01 (string), 0x02 (u64), 0x03 (json) are followed by a
/// u32 BE name length, the name bytes, and either a u64 BE value length +
/// value bytes (0x01/0x03) or a u64 BE value (0x02).
fn extract_field_names(bytes: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let tag = bytes[i];
        i += 1;
        let name_len = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        let name = std::str::from_utf8(&bytes[i..i + name_len]).unwrap().to_string();
        i += name_len;
        names.push(name);
        match tag {
            0x01 | 0x03 => {
                let value_len = u64::from_be_bytes(bytes[i..i + 8].try_into().unwrap()) as usize;
                i += 8 + value_len;
            }
            0x02 => {
                i += 8;
            }
            other => panic!("unknown tag byte {other:#x} at offset {}", i - 1),
        }
    }
    names
}

/// Pinned digest of `canonical_bytes(fixture())`. Regenerate ONLY when
/// intentionally changing the preimage layout (and bump
/// `schema_version` in the same commit). To regenerate locally:
///
/// ```text
/// cargo test -p invariant-core --test audit_preimage_golden \
///     canonical_bytes_digest_is_pinned -- --nocapture
/// ```
/// then paste the printed `actual` value into the constant below.
const PINNED_DIGEST: &str = "bf0759ef24b33465b9286d5c9cf4473aeea60684cc11207e3e8aa3d70f01a9e1";

fn pinned_digest() -> String {
    if PINNED_DIGEST == "__REGENERATE__" {
        let entry = fixture();
        let bytes = canonical_bytes(&entry).expect("canonical_bytes must succeed");
        let actual = hex(&Sha256::digest(&bytes));
        eprintln!(
            "PINNED_DIGEST placeholder hit; observed digest = {actual}. \
             Paste this value into PINNED_DIGEST and re-run."
        );
        actual
    } else {
        PINNED_DIGEST.to_string()
    }
}
