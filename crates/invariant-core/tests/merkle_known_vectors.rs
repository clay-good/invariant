//! Hand-computed RFC 6962 Merkle roots for trees of size 1, 2, 3, 4, and 7.
//!
//! Each test spells out the leaf and inner-hash steps inline so a reviewer
//! can verify the expected root by eye against the RFC 6962 §2 definition:
//!
//! ```text
//! MTH({d_0})         = SHA-256(0x00 || d_0)
//! MTH(D[0:n]) (n>1)  = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//!     where k = largest power of two < n
//! ```
//!
//! These vectors are the regression oracle for `MerkleAccumulator` and
//! `tree_root`. Hand-computing the steps inline keeps the test maintainable
//! without pulling in a separate vector file.

use invariant_core::merkle::{
    inner_hash, leaf_hash, tree_root, Hash, MerkleAccumulator,
};

fn leaf(b: &[u8]) -> Hash {
    leaf_hash(b)
}

/// Helper: assert the accumulator's running root matches the closed-form
/// `tree_root`, then compare both to the supplied expected hash.
fn assert_root(leaves: &[Hash], expected: Hash) {
    let mut acc = MerkleAccumulator::new();
    for h in leaves {
        acc.push_leaf_hash(*h);
    }
    let oracle = tree_root(leaves);
    assert_eq!(oracle, expected, "tree_root oracle mismatch");
    assert_eq!(acc.root(), expected, "MerkleAccumulator root mismatch");
    assert_eq!(acc.leaf_count() as usize, leaves.len());
}

#[test]
fn n_eq_1_root_is_leaf_hash_of_only_entry() {
    // Tree: just leaf(d_0). RFC 6962 says MTH({d_0}) = leaf(d_0).
    let d0 = b"entry-0".to_vec();
    let expected = leaf(&d0);
    assert_root(&[leaf(&d0)], expected);
}

#[test]
fn n_eq_2_root_is_inner_hash_of_two_leaves() {
    // Layer 0: [leaf(d_0), leaf(d_1)]
    // Layer 1: [inner(leaf(d_0), leaf(d_1))]  ← root
    let d0 = leaf(b"a");
    let d1 = leaf(b"b");
    let expected = inner_hash(&d0, &d1);
    assert_root(&[d0, d1], expected);
}

#[test]
fn n_eq_3_promotes_unpaired_third_leaf() {
    // Largest power of two below 3 is 2, so the split is (2, 1).
    // Layer 0: [leaf(d_0), leaf(d_1), leaf(d_2)]
    // Layer 1: [inner(leaf(d_0), leaf(d_1)), leaf(d_2)]  ← d_2 promoted
    // Layer 2: [inner(layer1[0], layer1[1])]             ← root
    let d0 = leaf(b"a");
    let d1 = leaf(b"b");
    let d2 = leaf(b"c");
    let pair01 = inner_hash(&d0, &d1);
    let expected = inner_hash(&pair01, &d2);
    assert_root(&[d0, d1, d2], expected);
}

#[test]
fn n_eq_4_is_balanced_two_level_tree() {
    // Layer 0: [leaf(d_0), leaf(d_1), leaf(d_2), leaf(d_3)]
    // Layer 1: [inner(d_0, d_1), inner(d_2, d_3)]
    // Layer 2: [inner(layer1[0], layer1[1])]    ← root
    let d0 = leaf(b"a");
    let d1 = leaf(b"b");
    let d2 = leaf(b"c");
    let d3 = leaf(b"d");
    let pair01 = inner_hash(&d0, &d1);
    let pair23 = inner_hash(&d2, &d3);
    let expected = inner_hash(&pair01, &pair23);
    assert_root(&[d0, d1, d2, d3], expected);
}

#[test]
fn n_eq_7_split_is_4_plus_3() {
    // Largest power of two below 7 is 4, so split is (4, 3).
    // Left subtree (4 leaves): standard balanced — same as n_eq_4 above.
    // Right subtree (3 leaves): split (2, 1), so:
    //   inner(inner(d_4, d_5), d_6)
    // Root: inner(left, right)
    let d0 = leaf(b"a");
    let d1 = leaf(b"b");
    let d2 = leaf(b"c");
    let d3 = leaf(b"d");
    let d4 = leaf(b"e");
    let d5 = leaf(b"f");
    let d6 = leaf(b"g");

    let left_top = inner_hash(&inner_hash(&d0, &d1), &inner_hash(&d2, &d3));
    let right_top = inner_hash(&inner_hash(&d4, &d5), &d6);
    let expected = inner_hash(&left_top, &right_top);

    assert_root(&[d0, d1, d2, d3, d4, d5, d6], expected);
}
