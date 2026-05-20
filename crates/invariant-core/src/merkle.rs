//! RFC 6962 Merkle tree over the audit log (v11 1.3).
//!
//! RFC 6962 §2 prescribes the canonical leaf and inner-node hash forms:
//!
//! ```text
//! MTH({})                = SHA-256()                              # empty tree
//! MTH({d_0})             = SHA-256(0x00 || d_0)                   # single leaf
//! MTH(D[0:n]) (n > 1)    = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//!     where k = largest power of two < n
//! ```
//!
//! The 0x00 / 0x01 domain-separator bytes are what prevent leaf/inner
//! collisions and what make this a Merkle tree rather than a Patricia trie.
//!
//! This module exposes:
//! - [`leaf_hash`] / [`inner_hash`] — the two RFC 6962 primitives.
//! - [`MerkleAccumulator`] — a streaming builder that ingests leaves one
//!   at a time and keeps the running root in O(log n) memory.
//! - [`inclusion_proof`] / [`verify_inclusion`] — RFC 6962 §2.1.1 audit
//!   path generation and verification.

use sha2::{Digest, Sha256};

/// 32-byte SHA-256 output.
pub type Hash = [u8; 32];

/// RFC 6962 §2 leaf hash: `H(0x00 || entry)`.
pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(entry);
    h.finalize().into()
}

/// RFC 6962 §2 inner-node hash: `H(0x01 || left || right)`.
pub fn inner_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Hash of the empty tree: SHA-256 of the empty byte string (RFC 6962 §2).
pub fn empty_tree_hash() -> Hash {
    Sha256::new().finalize().into()
}

/// Streaming Merkle accumulator (RFC 6962 §2.1.1, Crosby/Wallach 2009 "stack"
/// construction). Maintains exactly one hash per set bit in the leaf count,
/// so memory usage is `O(log n)` regardless of how many leaves are appended.
///
/// `stack[i]` is occupied iff bit `i` of the current leaf count is set —
/// it holds the root of a complete subtree of 2^i leaves. Appending a new
/// leaf cascades from level 0 upward: at each level where there is already
/// a pending hash, the two are combined into the next level (mirroring a
/// binary increment with carries).
#[derive(Debug, Clone, Default)]
pub struct MerkleAccumulator {
    stack: Vec<Option<Hash>>,
    leaf_count: u64,
}

impl MerkleAccumulator {
    /// Create a fresh empty accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves ingested so far.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Append a pre-hashed leaf to the tree.
    ///
    /// Caller must use [`leaf_hash`] on the raw leaf bytes first — this lets
    /// the accumulator be reused across already-hashed inputs (e.g. when
    /// resuming from an existing log).
    pub fn push_leaf_hash(&mut self, leaf: Hash) {
        let mut carry = leaf;
        let mut level = 0;
        loop {
            if level >= self.stack.len() {
                self.stack.push(Some(carry));
                break;
            }
            match self.stack[level].take() {
                Some(left) => {
                    carry = inner_hash(&left, &carry);
                    level += 1;
                }
                None => {
                    self.stack[level] = Some(carry);
                    break;
                }
            }
        }
        self.leaf_count += 1;
    }

    /// Convenience: hash `entry` with [`leaf_hash`] and append it.
    pub fn push(&mut self, entry: &[u8]) {
        self.push_leaf_hash(leaf_hash(entry));
    }

    /// Compute the current Merkle root.
    ///
    /// For an empty accumulator returns [`empty_tree_hash`]. Otherwise
    /// collapses the right-leaning spine of pending subtree hashes from
    /// the bottom up using `inner_hash` — this matches the RFC 6962
    /// recursive definition for non-power-of-two leaf counts.
    pub fn root(&self) -> Hash {
        if self.leaf_count == 0 {
            return empty_tree_hash();
        }
        let mut current: Option<Hash> = None;
        for h in self.stack.iter().flatten() {
            current = Some(match current {
                None => *h,
                Some(c) => inner_hash(h, &c),
            });
        }
        current.expect("non-empty accumulator must have at least one occupied level")
    }
}

/// Build an RFC 6962 audit path for the leaf at `index` in the slice
/// `leaves` (which must already contain the per-leaf hashes from
/// [`leaf_hash`]).
///
/// The proof is the list of sibling hashes encountered while walking from
/// the target leaf up to the tree root, in bottom-to-top order. For a
/// tree whose leaf count is not a power of two the proof skips the
/// "phantom" siblings at levels where the target leaf's subtree is the
/// only child — this matches RFC 6962 §2.1.1.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Vec<Hash> {
    assert!(
        index < leaves.len(),
        "index {} out of range for {} leaves",
        index,
        leaves.len()
    );
    let mut proof = Vec::new();
    let mut layer: Vec<Hash> = leaves.to_vec();
    let mut idx = index;
    while layer.len() > 1 {
        let sibling = idx ^ 1;
        if sibling < layer.len() {
            proof.push(layer[sibling]);
        }
        layer = next_layer(&layer);
        idx /= 2;
    }
    proof
}

/// Verify an RFC 6962 audit path. Reconstructs the root from `leaf`,
/// `index`, `n`, and `proof` and checks for byte equality with `root`.
pub fn verify_inclusion(
    root: &Hash,
    leaf: &Hash,
    index: usize,
    n: usize,
    proof: &[Hash],
) -> bool {
    if index >= n {
        return false;
    }
    let mut computed = *leaf;
    let mut idx = index;
    let mut layer_size = n;
    let mut proof_iter = proof.iter();
    while layer_size > 1 {
        let sibling_idx = idx ^ 1;
        if sibling_idx < layer_size {
            let Some(sibling) = proof_iter.next() else {
                return false;
            };
            computed = if idx.is_multiple_of(2) {
                inner_hash(&computed, sibling)
            } else {
                inner_hash(sibling, &computed)
            };
        }
        // Walk to the parent layer.
        idx /= 2;
        layer_size = layer_size.div_ceil(2);
    }
    // Any leftover proof bytes indicate the proof is over-long.
    proof_iter.next().is_none() && computed == *root
}

/// Compute one parent layer from a child layer. Odd-numbered children are
/// promoted directly (RFC 6962 §2.1: an unbalanced subtree promotes its
/// last leaf rather than hashing with a phantom zero sibling).
fn next_layer(layer: &[Hash]) -> Vec<Hash> {
    let mut out = Vec::with_capacity(layer.len().div_ceil(2));
    let mut i = 0;
    while i + 1 < layer.len() {
        out.push(inner_hash(&layer[i], &layer[i + 1]));
        i += 2;
    }
    if i < layer.len() {
        out.push(layer[i]);
    }
    out
}

/// Compute the canonical RFC 6962 Merkle tree hash over the in-order
/// sequence of pre-hashed leaves. Useful for offline verification and as
/// an oracle for [`MerkleAccumulator::root`].
pub fn tree_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return empty_tree_hash();
    }
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        layer = next_layer(&layer);
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lh(b: &[u8]) -> Hash {
        leaf_hash(b)
    }

    #[test]
    fn empty_accumulator_root_matches_rfc6962() {
        let acc = MerkleAccumulator::new();
        assert_eq!(acc.root(), empty_tree_hash());
    }

    #[test]
    fn single_leaf_accumulator_equals_streaming_oracle() {
        let mut acc = MerkleAccumulator::new();
        acc.push(b"a");
        let oracle = tree_root(&[lh(b"a")]);
        assert_eq!(acc.root(), oracle);
    }

    #[test]
    fn accumulator_matches_oracle_up_to_17_leaves() {
        for n in 1..=17 {
            let leaves: Vec<Hash> = (0..n).map(|i| lh(format!("e{i}").as_bytes())).collect();
            let mut acc = MerkleAccumulator::new();
            for leaf in &leaves {
                acc.push_leaf_hash(*leaf);
            }
            assert_eq!(acc.root(), tree_root(&leaves), "mismatch at n={n}");
            assert_eq!(acc.leaf_count(), n);
        }
    }

    #[test]
    fn inclusion_proof_round_trips_for_every_index() {
        for n in 1..=17 {
            let leaves: Vec<Hash> = (0..n).map(|i| lh(format!("e{i}").as_bytes())).collect();
            let root = tree_root(&leaves);
            for i in 0..n {
                let proof = inclusion_proof(&leaves, i);
                assert!(
                    verify_inclusion(&root, &leaves[i], i, n, &proof),
                    "verify failed: n={n}, i={i}",
                );
            }
        }
    }

    #[test]
    fn verify_inclusion_rejects_wrong_index() {
        let leaves: Vec<Hash> = (0..8).map(|i| lh(&[i as u8])).collect();
        let root = tree_root(&leaves);
        let proof = inclusion_proof(&leaves, 3);
        assert!(verify_inclusion(&root, &leaves[3], 3, 8, &proof));
        // A different index with the same proof must fail.
        assert!(!verify_inclusion(&root, &leaves[3], 2, 8, &proof));
    }

    #[test]
    fn verify_inclusion_rejects_overlong_proof() {
        let leaves: Vec<Hash> = (0..4).map(|i| lh(&[i as u8])).collect();
        let root = tree_root(&leaves);
        let mut proof = inclusion_proof(&leaves, 0);
        // Tack on an extra hash that wouldn't be part of a real audit path.
        proof.push([0xAA; 32]);
        assert!(!verify_inclusion(&root, &leaves[0], 0, 4, &proof));
    }

    #[test]
    fn leaf_and_inner_have_distinct_domain_bytes() {
        // RFC 6962 §2: leaf prefix 0x00, inner prefix 0x01. A second-pre-image
        // attack would otherwise let an attacker pass an inner-node hash off
        // as a leaf.
        let lh_zero = leaf_hash(&[0u8; 32]);
        let ih_zero = inner_hash(&[0u8; 32], &[0u8; 32]);
        assert_ne!(lh_zero, ih_zero);
    }
}
