//! Audit-path tamper test (v11 1.3 acceptance criterion).
//!
//! Build a 1024-leaf RFC 6962 Merkle tree, generate inclusion proofs for
//! every index, then for one fixed index iterate over every byte of the
//! proof, flip a single bit, and assert `verify_inclusion` returns false.
//!
//! This is the "every byte matters" property — a Merkle proof has no slack
//! bits, so a single-bit perturbation anywhere must invalidate the proof.

use invariant_core::merkle::{
    inclusion_proof, leaf_hash, tree_root, verify_inclusion, Hash,
};

const N: usize = 1024;

fn build_leaves() -> Vec<Hash> {
    (0..N as u32)
        .map(|i| leaf_hash(&i.to_be_bytes()))
        .collect()
}

#[test]
fn every_index_round_trips_in_1024_leaf_tree() {
    let leaves = build_leaves();
    let root = tree_root(&leaves);
    for i in 0..N {
        let proof = inclusion_proof(&leaves, i);
        assert!(
            verify_inclusion(&root, &leaves[i], i, N, &proof),
            "round-trip failed at i={i}",
        );
    }
}

#[test]
fn flipping_every_byte_of_proof_invalidates_verification() {
    let leaves = build_leaves();
    let root = tree_root(&leaves);
    // Use an index in the middle of the tree so every level of the audit
    // path is exercised (i=337 sits in the left half of the right half of
    // the left subtree, etc.).
    let target = 337usize;
    let proof = inclusion_proof(&leaves, target);
    assert!(!proof.is_empty(), "1024-leaf tree must have a non-empty proof");

    let mut total_byte_flips_tested = 0usize;
    for (h_idx, hash) in proof.iter().enumerate() {
        for byte_idx in 0..hash.len() {
            for bit in 0..8u8 {
                let mut tampered = proof.clone();
                tampered[h_idx][byte_idx] ^= 1 << bit;
                let ok = verify_inclusion(&root, &leaves[target], target, N, &tampered);
                assert!(
                    !ok,
                    "single bit flip at proof[{h_idx}][{byte_idx}] bit {bit} \
                     was not detected — Merkle proof has slack",
                );
                total_byte_flips_tested += 1;
            }
        }
    }
    // Sanity: confirm we actually exercised the whole proof body
    // (`32 bytes * 8 bits` per hash, summed across all proof hashes).
    assert_eq!(total_byte_flips_tested, proof.len() * 32 * 8);
}

#[test]
fn flipping_root_byte_invalidates_verification() {
    let leaves = build_leaves();
    let mut root = tree_root(&leaves);
    let proof = inclusion_proof(&leaves, 0);
    assert!(verify_inclusion(&root, &leaves[0], 0, N, &proof));
    // Flip one bit of the *root* — verification must fail.
    root[0] ^= 0x01;
    assert!(!verify_inclusion(&root, &leaves[0], 0, N, &proof));
}

#[test]
fn flipping_leaf_byte_invalidates_verification() {
    let leaves = build_leaves();
    let root = tree_root(&leaves);
    let proof = inclusion_proof(&leaves, 500);
    let mut tampered_leaf = leaves[500];
    tampered_leaf[31] ^= 0x80;
    assert!(!verify_inclusion(&root, &tampered_leaf, 500, N, &proof));
}
