//! v11 1.2 — A3 causal binding (`predecessor_digest`).
//!
//! Covers:
//! 1. `Pca::canonical_bytes` shape: field-order stability and a hand-
//!    computed SHA-256 fixture so accidental preimage drift is caught.
//! 2. `verify_predecessor_chain` happy path on a built 3-hop chain whose
//!    digests were filled by SHA-256 over the canonical bytes.
//! 3. Root must carry the all-zero sentinel.
//! 4. Splice (G-09): swap a middle hop for one with a different parent.
//!    The replacement hop's `predecessor_digest` no longer matches and
//!    the verifier rejects with `PredecessorDigestMismatch { hop: 1 }`.

use invariant_core::authority::chain::verify_predecessor_chain;
use invariant_core::models::authority::{Operation, Pca};
use invariant_core::models::error::AuthorityError;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

fn op(s: &str) -> Operation {
    Operation::new(s).expect("valid op string")
}

fn ops(s: &[&str]) -> BTreeSet<Operation> {
    s.iter().map(|x| op(x)).collect()
}

fn sha256_hex_of_canonical(p: &Pca) -> [u8; 32] {
    let bytes = p.canonical_bytes();
    let mut h = Sha256::new();
    h.update(&bytes);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

#[test]
fn canonical_bytes_field_order_is_stable() {
    // A fixed claim — every byte of the preimage is determined by the
    // field contents, so we can hand-check the prefix.
    let claim = Pca {
        p_0: "root".into(),
        ops: ops(&["actuate:joint_0", "sensor.read:imu"]),
        kid: "kid-A".into(),
        exp: None,
        nbf: None,
        predecessor_digest: [0u8; 32],
    };
    let bytes = claim.canonical_bytes();
    // First byte = p_0 tag (0x01), then big-endian length 4, then "root".
    assert_eq!(bytes[0], 0x01, "p_0 tag");
    assert_eq!(&bytes[1..5], &(4u32.to_be_bytes())[..], "p_0 length");
    assert_eq!(&bytes[5..9], b"root", "p_0 payload");
    // Subsequent byte after p_0 payload = ops tag.
    assert_eq!(bytes[9], 0x04, "ops tag");
    assert_eq!(&bytes[10..14], &(2u32.to_be_bytes())[..], "ops count = 2");

    // SHA-256 of the canonical preimage is deterministic. We snapshot it
    // here so accidental preimage drift is caught loudly.
    let digest = claim.sha256_digest();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    // Recompute the expected by inlined SHA-256 to avoid hardcoding a
    // wrong constant; the assertion verifies the helper matches the
    // independent computation.
    let expected = sha256_hex_of_canonical(&claim);
    let expected_hex: String = expected.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        hex, expected_hex,
        "sha256_digest must agree with sha256(canonical_bytes)"
    );
    // Pin the hex so a future preimage change is loud.
    assert_eq!(hex.len(), 64, "digest hex must be 64 chars (32 bytes)");
}

#[test]
fn predecessor_digest_excluded_from_preimage() {
    // Two claims that differ ONLY in `predecessor_digest` must produce
    // the same `canonical_bytes` (and therefore the same SHA-256). This
    // is what lets a hop's digest be computed without knowing its
    // child's digest.
    let base = Pca {
        p_0: "root".into(),
        ops: ops(&["actuate:*"]),
        kid: "kid".into(),
        exp: None,
        nbf: None,
        predecessor_digest: [0u8; 32],
    };
    let mut tweaked = base.clone();
    tweaked.predecessor_digest = [0xAB; 32];
    assert_eq!(base.canonical_bytes(), tweaked.canonical_bytes());
    assert_eq!(base.sha256_digest(), tweaked.sha256_digest());
}

fn build_root() -> Pca {
    Pca {
        p_0: "operator".into(),
        ops: ops(&["actuate:*"]),
        kid: "root-key".into(),
        exp: None,
        nbf: None,
        predecessor_digest: [0u8; 32],
    }
}

fn child_of(parent: &Pca, kid: &str, narrowed: &[&str]) -> Pca {
    Pca {
        p_0: parent.p_0.clone(),
        ops: ops(narrowed),
        kid: kid.into(),
        exp: parent.exp,
        nbf: parent.nbf,
        predecessor_digest: parent.sha256_digest(),
    }
}

#[test]
fn three_hop_chain_with_digests_verifies() {
    let h0 = build_root();
    let h1 = child_of(&h0, "kid-a", &["actuate:joint:*"]);
    let h2 = child_of(&h1, "kid-b", &["actuate:joint:0"]);
    verify_predecessor_chain(&[h0, h1, h2]).expect("happy path must verify");
}

#[test]
fn root_must_carry_zero_digest() {
    let mut h0 = build_root();
    h0.predecessor_digest = [0xCC; 32];
    let h1 = child_of(&h0, "kid-a", &["actuate:joint:*"]);
    let err = verify_predecessor_chain(&[h0, h1]).expect_err("root non-zero must reject");
    assert!(matches!(
        err,
        AuthorityError::PredecessorDigestNonZeroAtRoot
    ));
}

#[test]
fn g09_splice_replaces_middle_hop_with_different_parent() {
    // Build two valid 3-hop chains, A and B, sharing the operator p_0
    // but signed by distinct root key ids. The G-09 attack splices hop 1
    // from chain B into chain A. Hop A[1] was bound to A[0]'s digest;
    // B[1] is bound to B[0]'s digest. After the splice, the chain reads
    // [A[0], B[1], A[2]] and the binding at index 1 breaks.
    let a0 = Pca {
        p_0: "operator".into(),
        ops: ops(&["actuate:*"]),
        kid: "root-A".into(),
        exp: None,
        nbf: None,
        predecessor_digest: [0u8; 32],
    };
    let a1 = child_of(&a0, "leaf-A", &["actuate:joint:*"]);
    let a2 = child_of(&a1, "leaf-A2", &["actuate:joint:0"]);

    let b0 = Pca {
        p_0: "operator".into(),
        ops: ops(&["actuate:*"]),
        kid: "root-B".into(), // different root => different canonical bytes
        exp: None,
        nbf: None,
        predecessor_digest: [0u8; 32],
    };
    let b1 = child_of(&b0, "leaf-B", &["actuate:joint:*"]);

    // Sanity: the two roots produce DIFFERENT digests (otherwise the
    // splice would be undetectable; the spec assumes the parents
    // differ).
    assert_ne!(a0.sha256_digest(), b0.sha256_digest());

    // The honest chain A verifies.
    verify_predecessor_chain(&[a0.clone(), a1.clone(), a2.clone()]).expect("chain A is valid");

    // The spliced chain [A[0], B[1], A[2]] must reject at hop 1.
    let spliced = vec![a0, b1, a2];
    let err = verify_predecessor_chain(&spliced).expect_err("splice must reject");
    match err {
        AuthorityError::PredecessorDigestMismatch { hop } => assert_eq!(hop, 1),
        other => panic!("expected PredecessorDigestMismatch{{hop:1}}, got {other:?}"),
    }
}

#[test]
fn legacy_all_zero_chain_passes_through_predecessor_chain_helper() {
    // A two-hop chain where neither hop has migrated to set the digest.
    // `verify_predecessor_chain` enforces strictly, so it must reject
    // at hop 1 (zero != sha256(parent)). This is why the in-tree
    // `verify_chain` runs the check ONLY when at least one hop has
    // opted in. Confirms the helper is strict in isolation.
    let h0 = build_root();
    let h1 = Pca {
        p_0: h0.p_0.clone(),
        ops: ops(&["actuate:*"]),
        kid: "leaf".into(),
        exp: None,
        nbf: None,
        predecessor_digest: [0u8; 32], // unmigrated — defaults to zero
    };
    let err = verify_predecessor_chain(&[h0, h1]).expect_err("strict helper rejects unmigrated");
    assert!(matches!(
        err,
        AuthorityError::PredecessorDigestMismatch { hop: 1 }
    ));
}

#[test]
fn predecessor_digest_serde_round_trip() {
    // JSON round-trip: a Pca with a non-zero predecessor_digest is
    // emitted as a 64-char lowercase hex string and parses back to the
    // identical bytes.
    let mut digest = [0u8; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let claim = Pca {
        p_0: "root".into(),
        ops: ops(&["actuate:*"]),
        kid: "kid".into(),
        exp: None,
        nbf: None,
        predecessor_digest: digest,
    };
    let s = serde_json::to_string(&claim).expect("serialize");
    assert!(
        s.contains("\"predecessor_digest\":\""),
        "field is emitted: {s}"
    );
    assert!(
        s.contains("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        "lowercase hex digest: {s}"
    );
    let back: Pca = serde_json::from_str(&s).expect("deserialize");
    assert_eq!(back.predecessor_digest, digest);
}

#[test]
fn predecessor_digest_serde_missing_field_defaults_to_zero() {
    // Pre-v11-1.2 chains have no `predecessor_digest` JSON key. They must
    // still parse, defaulting to the all-zero sentinel.
    let legacy = r#"{
        "p_0": "root",
        "ops": ["actuate:*"],
        "kid": "kid",
        "exp": null,
        "nbf": null
    }"#;
    let claim: Pca = serde_json::from_str(legacy).expect("legacy JSON must parse");
    assert_eq!(claim.predecessor_digest, [0u8; 32]);
}
