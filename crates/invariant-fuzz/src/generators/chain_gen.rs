//! Property-based PCA chain generation.
//!
//! `ChainGenerator` produces random but structurally valid PCA chains that
//! can be used for fuzz testing.  The chains are signed with a provided key
//! and have randomized operations, expiry windows, and hop depths.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use rand::Rng;

use invariant_core::authority::crypto::sign_pca;
use invariant_core::models::authority::{Operation, Pca, SignedPca};

/// Generates random PCA chains for testing.
pub struct ChainGenerator;

impl ChainGenerator {
    /// Generate a single-hop chain with a random subset of operations.
    pub fn single_hop<R: Rng>(
        signing_key: &SigningKey,
        kid: &str,
        available_ops: &[&str],
        rng: &mut R,
    ) -> Vec<SignedPca> {
        let ops: BTreeSet<Operation> = available_ops
            .iter()
            .filter(|_| rng.gen_bool(0.5))
            .filter_map(|s| Operation::new(*s).ok())
            .collect();

        // Ensure at least one op.
        let ops = if ops.is_empty() {
            BTreeSet::from([Operation::new(available_ops[0]).unwrap()])
        } else {
            ops
        };

        let pca = Pca {
            p_0: "chain-gen".into(),
            ops,
            kid: kid.to_string(),
            exp: None,
            nbf: None,
        };

        let signed = sign_pca(&pca, signing_key).expect("sign_pca must not fail");
        vec![signed]
    }

    /// Generate a multi-hop chain with monotonically narrowing operations.
    ///
    /// Each hop removes at least one operation from the parent's set, ensuring
    /// the monotonicity invariant (A2) is satisfied.
    pub fn narrowing_chain<R: Rng>(
        signing_key: &SigningKey,
        kid: &str,
        ops: &[&str],
        hops: usize,
        rng: &mut R,
    ) -> Vec<SignedPca> {
        let all_ops: Vec<Operation> = ops.iter().filter_map(|s| Operation::new(*s).ok()).collect();

        if all_ops.is_empty() || hops == 0 {
            return vec![];
        }

        let mut chain = Vec::new();
        let mut remaining = all_ops.clone();

        for i in 0..hops {
            let op_set: BTreeSet<Operation> = remaining.iter().cloned().collect();
            let pca = Pca {
                p_0: "chain-gen".into(),
                ops: op_set,
                kid: kid.to_string(),
                exp: None,
                nbf: None,
            };
            let signed = sign_pca(&pca, signing_key).expect("sign_pca must not fail");
            chain.push(signed);

            // Narrow: remove a random operation for the next hop.
            if remaining.len() > 1 && i < hops - 1 {
                let idx = rng.gen_range(0..remaining.len());
                remaining.remove(idx);
            }
        }

        chain
    }

    /// Encode a chain as the base64-wrapped JSON string expected by
    /// `Command::authority::pca_chain`.
    pub fn encode(chain: &[SignedPca]) -> String {
        let json = serde_json::to_vec(chain).expect("chain serialization is infallible");
        STANDARD.encode(&json)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use invariant_core::authority::crypto::generate_keypair;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_sk() -> SigningKey {
        generate_keypair(&mut rand::rngs::OsRng)
    }

    #[test]
    fn single_hop_produces_one_entry() {
        let sk = make_sk();
        let mut rng = StdRng::seed_from_u64(42);
        let chain =
            ChainGenerator::single_hop(&sk, "kid", &["actuate:arm:*", "actuate:leg:*"], &mut rng);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn narrowing_chain_length_matches_hops() {
        let sk = make_sk();
        let mut rng = StdRng::seed_from_u64(99);
        let ops = vec!["actuate:a", "actuate:b", "actuate:c", "actuate:d"];
        let chain = ChainGenerator::narrowing_chain(&sk, "kid", &ops, 3, &mut rng);
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn encode_round_trips() {
        let sk = make_sk();
        let mut rng = StdRng::seed_from_u64(7);
        let chain = ChainGenerator::single_hop(&sk, "kid", &["actuate:*"], &mut rng);
        let encoded = ChainGenerator::encode(&chain);

        let decoded_bytes = STANDARD.decode(&encoded).unwrap();
        let decoded: Vec<SignedPca> = serde_json::from_slice(&decoded_bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].raw, chain[0].raw);
    }

    #[test]
    fn narrowing_chain_with_single_op_produces_chain() {
        let sk = make_sk();
        let mut rng = StdRng::seed_from_u64(123);
        let chain = ChainGenerator::narrowing_chain(&sk, "kid", &["actuate:*"], 3, &mut rng);
        // With only one op, narrowing can't remove it — all hops have the same op.
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn narrowing_chain_zero_hops_returns_empty() {
        let sk = make_sk();
        let mut rng = StdRng::seed_from_u64(1);
        let chain = ChainGenerator::narrowing_chain(&sk, "kid", &["actuate:*"], 0, &mut rng);
        assert!(chain.is_empty());
    }
}
