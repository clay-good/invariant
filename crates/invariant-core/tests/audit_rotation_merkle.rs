//! v12 N-11 — Audit-rotation Merkle continuity.
//!
//! Models external log rotation (logrotate-style: rename the active file
//! aside, open a fresh one at the original path) and asserts that an
//! offline RFC 6962 Merkle tree built over the *concatenated* entry-hash
//! stream produces a root distinct from each per-segment root, and that
//! inclusion proofs for leaves drawn from either segment verify against
//! the cross-segment root.
//!
//! The in-process [`MerkleAccumulator`] resets on resume by design (see
//! the doc on `AuditLogger::merkle_root` in `invariant-core::audit`); the
//! cross-segment root is reconstructed off-line from the JSONL using the
//! public [`invariant_core::merkle::tree_root`] oracle.
//!
//! `invariant-core` exposes no explicit rotation API — `AuditLogger` is
//! generic over the file backing and external tools own the file
//! lifecycle. This test exercises the supported pattern: capture
//! `previous_hash` + `sequence` from the soon-to-be-rotated logger, then
//! resume a new logger from that state against a new file. The L2 hash
//! chain continues unbroken across the cut point even though the segment
//! files are physically separate.

use ed25519_dalek::SigningKey;
use invariant_core::audit::AuditLogger;
use invariant_core::merkle::{
    inclusion_proof, leaf_hash, tree_root, verify_inclusion, Hash,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Input(String);

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Verdict(bool);

const SEGMENT_A_LEN: usize = 1000;
const SEGMENT_B_LEN: usize = 1000;

/// `Vec<u8>` sink that can be reclaimed without consuming the logger.
struct SharedSink(Rc<RefCell<Vec<u8>>>);

impl std::io::Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Write `n` audit entries through a fresh logger and return the captured
/// JSONL bytes, the live accumulator's root, the final `previous_hash`,
/// and the next sequence number. The logger is created with `new` when
/// `start_seq == 0` (genesis) and `resume` otherwise.
fn write_segment(
    sk: SigningKey,
    kid: &str,
    start_seq: u64,
    start_prev: String,
    n: usize,
    label: &str,
) -> (Vec<u8>, Hash, String, u64) {
    let buf = Rc::new(RefCell::new(Vec::new()));
    let sink = SharedSink(buf.clone());
    let mut logger: AuditLogger<SharedSink, Input, Verdict> = if start_seq == 0 {
        AuditLogger::new(sink, sk, kid.to_string())
    } else {
        AuditLogger::resume(sink, sk, kid.to_string(), start_seq, start_prev)
    };
    for i in 0..n {
        let input = Input(format!("{label}/cmd-{i}"));
        let verdict = Verdict(true);
        logger.log(&input, &verdict).expect("in-memory log()");
    }
    let live_root = logger.merkle_root();
    let last_prev = logger.previous_hash().to_string();
    let next_seq = logger.sequence();
    drop(logger);
    let bytes = buf.borrow().clone();
    (bytes, live_root, last_prev, next_seq)
}

/// Extract every `entry_hash` from a JSONL byte slice and pre-hash each
/// for use as a Merkle leaf (matches `AuditLogger`'s `push_leaf_hash`
/// call site exactly: `leaf_hash(entry_hash_bytes)`).
fn jsonl_to_leaves(jsonl: &[u8]) -> Vec<Hash> {
    let s = std::str::from_utf8(jsonl).expect("audit jsonl is valid UTF-8");
    let mut out = Vec::new();
    for line in s.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(line).expect("each audit line is valid JSON");
        // `SignedAuditEntry` uses `#[serde(flatten)]` on its `entry` field,
        // so `entry_hash` and `previous_hash` are top-level keys.
        let h = v["entry_hash"]
            .as_str()
            .expect("audit line carries an entry_hash field");
        out.push(leaf_hash(h.as_bytes()));
    }
    out
}

fn fresh_key() -> SigningKey {
    invariant_core::authority::crypto::generate_keypair(&mut OsRng)
}

#[test]
fn cross_segment_root_differs_from_each_segment_and_proves_inclusion() {
    let kid = "rotation-test";

    // Segment A: fresh genesis, 1000 entries.
    let (jsonl_a, root_a_live, last_prev, next_seq) =
        write_segment(fresh_key(), kid, 0, String::new(), SEGMENT_A_LEN, "segA");
    assert_eq!(next_seq, SEGMENT_A_LEN as u64);
    assert!(!last_prev.is_empty(), "last hash must be set after writes");

    // External rotation: new logger resumes from segment A's terminal state.
    let (jsonl_b, root_b_live, _, next_seq_b) = write_segment(
        fresh_key(),
        kid,
        next_seq,
        last_prev.clone(),
        SEGMENT_B_LEN,
        "segB",
    );
    assert_eq!(next_seq_b, (SEGMENT_A_LEN + SEGMENT_B_LEN) as u64);

    let leaves_a = jsonl_to_leaves(&jsonl_a);
    let leaves_b = jsonl_to_leaves(&jsonl_b);
    assert_eq!(leaves_a.len(), SEGMENT_A_LEN);
    assert_eq!(leaves_b.len(), SEGMENT_B_LEN);

    // Live and offline roots must agree per segment (sanity).
    let offline_a = tree_root(&leaves_a);
    let offline_b = tree_root(&leaves_b);
    assert_eq!(offline_a, root_a_live, "offline/live root mismatch (A)");
    assert_eq!(offline_b, root_b_live, "offline/live root mismatch (B)");

    // L2 continuity check at the cut: the first segment-B entry's
    // previous_hash must equal segment A's last entry_hash.
    let b_text = std::str::from_utf8(&jsonl_b).unwrap();
    let first_b: serde_json::Value =
        serde_json::from_str(b_text.lines().next().unwrap()).unwrap();
    assert_eq!(
        first_b["previous_hash"].as_str().unwrap(),
        last_prev,
        "L2 chain must continue across rotation"
    );

    // Cross-segment root.
    let mut leaves_all = leaves_a.clone();
    leaves_all.extend_from_slice(&leaves_b);
    let root_cross = tree_root(&leaves_all);

    // (a) cross-segment root differs from each per-segment root.
    assert_ne!(root_cross, offline_a, "cross root must differ from A");
    assert_ne!(root_cross, offline_b, "cross root must differ from B");

    // (b) inclusion proofs for one pre-rotation index and one post-
    // rotation index both verify against the cross-segment root.
    for &idx in &[500usize, 1500usize] {
        let proof = inclusion_proof(&leaves_all, idx);
        assert!(
            verify_inclusion(&root_cross, &leaves_all[idx], idx, leaves_all.len(), &proof),
            "inclusion proof for cross-segment index {idx} must verify"
        );
        // A single bit flip in the leaf must invalidate the proof.
        let mut bad = leaves_all[idx];
        bad[0] ^= 0x80;
        assert!(
            !verify_inclusion(&root_cross, &bad, idx, leaves_all.len(), &proof),
            "tampered leaf at index {idx} must not verify"
        );
    }
}

#[test]
fn corrupting_post_rotation_segment_breaks_cross_segment_proof() {
    let kid = "rotation-corrupt";
    let (jsonl_a, _, last_prev, next_seq) =
        write_segment(fresh_key(), kid, 0, String::new(), SEGMENT_A_LEN, "segA");
    let (jsonl_b, _, _, _) = write_segment(
        fresh_key(),
        kid,
        next_seq,
        last_prev,
        SEGMENT_B_LEN,
        "segB",
    );

    let leaves_a = jsonl_to_leaves(&jsonl_a);
    let leaves_b_honest = jsonl_to_leaves(&jsonl_b);

    let mut leaves_b_tampered = leaves_b_honest.clone();
    leaves_b_tampered[123][0] ^= 0x01;

    let mut honest = leaves_a.clone();
    honest.extend_from_slice(&leaves_b_honest);
    let mut tampered = leaves_a;
    tampered.extend_from_slice(&leaves_b_tampered);

    let honest_root = tree_root(&honest);
    let tampered_root = tree_root(&tampered);
    assert_ne!(
        honest_root, tampered_root,
        "any single-bit perturbation must change the cross-segment root"
    );

    // The honest proof for the corrupted index does not verify against
    // the tampered root.
    let idx = SEGMENT_A_LEN + 123;
    let honest_proof = inclusion_proof(&honest, idx);
    assert!(
        !verify_inclusion(&tampered_root, &honest[idx], idx, honest.len(), &honest_proof),
        "tampered root must reject the honest inclusion proof"
    );
}
