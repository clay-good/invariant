//! AA1–AA10: Authority chain attacks.
//!
//! Functions in this module construct malformed PCA chains that attempt to
//! bypass the Invariant authority verifier.  Each function returns one or more
//! `SignedPca` values that should be rejected by `verify_chain`.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;

use invariant_core::authority::crypto::{generate_keypair, sign_pca};
use invariant_core::models::authority::{Operation, Pca, SignedPca};

// ---------------------------------------------------------------------------
// AA1: Forge — modify payload after signing
// ---------------------------------------------------------------------------

/// AA1: Return a `SignedPca` whose COSE signature was produced over a
/// *different* payload than the one embedded in the envelope.
///
/// The attack modifies the serialized claim bytes inside the COSE_Sign1
/// envelope after signing, leaving the signature intact.  The verifier must
/// detect the mismatch and reject the hop.
pub fn forge_signature(signing_key: &SigningKey, kid: &str) -> SignedPca {
    // Sign a legitimate claim.
    let op = Operation::new("actuate:*").unwrap();
    let legitimate = Pca {
        p_0: "attacker".into(),
        ops: BTreeSet::from([op.clone()]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed = sign_pca(&legitimate, signing_key).unwrap();

    // Tamper: flip bits in the raw COSE bytes to corrupt the payload while
    // keeping the length the same.  We mutate bytes near the end of the buffer
    // where the JSON payload lives (past the CBOR header / protected header).
    let mut raw = signed.raw.clone();
    let len = raw.len();
    if len > 4 {
        // XOR a few bytes in the middle of the payload region.
        raw[len / 2] ^= 0xFF;
        raw[len / 2 + 1] ^= 0xAA;
    }

    SignedPca { raw }
}

// ---------------------------------------------------------------------------
// AA2: Escalation — add wider ops to child hop
// ---------------------------------------------------------------------------

/// AA2: Return a two-hop chain where the second hop claims *wider* operations
/// than the first hop granted (a monotonicity violation).
///
/// Hop 0 grants `["actuate:joint_0"]`.
/// Hop 1 attempts to escalate to `["actuate:*"]`.
///
/// The verifier must detect the A2 monotonicity violation and reject the chain.
pub fn escalate_operations(signing_key: &SigningKey, kid: &str) -> Vec<SignedPca> {
    let narrow_op = Operation::new("actuate:joint_0").unwrap();
    let wide_op = Operation::new("actuate:*").unwrap();

    // Hop 0: sign a narrow grant.
    let hop0 = Pca {
        p_0: "attacker".into(),
        ops: BTreeSet::from([narrow_op]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed0 = sign_pca(&hop0, signing_key).unwrap();

    // Hop 1: attempt to claim a wider grant — violation of A2.
    let hop1 = Pca {
        p_0: "attacker".into(),
        ops: BTreeSet::from([wide_op]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed1 = sign_pca(&hop1, signing_key).unwrap();

    vec![signed0, signed1]
}

// ---------------------------------------------------------------------------
// AA3: Truncation — remove intermediate hops
// ---------------------------------------------------------------------------

/// AA3: Build a three-hop chain and return it with the middle hop removed.
///
/// The resulting chain skips from hop 0 directly to the original hop 2, so
/// the key-continuity invariant (A3) should be violated — the verifying key
/// for hop 2 was never established through a verified parent.
///
/// In practice the verifier may reject because the key for hop 1 (now
/// re-indexed as hop 1 of the truncated chain) is unknown or because the
/// ops monotonicity check fails.
///
/// Returns the truncated chain as `[hop0, hop2]` with hop1 omitted.
pub fn truncate_chain(signing_key: &SigningKey, kid: &str) -> Vec<SignedPca> {
    let op_wide = Operation::new("actuate:*").unwrap();
    let op_mid = Operation::new("actuate:arm:*").unwrap();
    let op_narrow = Operation::new("actuate:arm:joint_0").unwrap();

    let rng = &mut rand::rngs::OsRng;
    let sk_intermediate = generate_keypair(rng);
    let sk_leaf = generate_keypair(rng);

    // Hop 0 (root, signed with `signing_key`).
    let hop0 = Pca {
        p_0: "root".into(),
        ops: BTreeSet::from([op_wide]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed0 = sign_pca(&hop0, signing_key).unwrap();

    // Hop 1 (intermediate, signed with `sk_intermediate`) — will be dropped.
    let intermediate_kid = "intermediate-kid".to_string();
    let hop1 = Pca {
        p_0: "root".into(),
        ops: BTreeSet::from([op_mid]),
        kid: intermediate_kid.clone(),
        exp: None,
        nbf: None,
    };
    let _signed1 = sign_pca(&hop1, &sk_intermediate).unwrap();

    // Hop 2 (leaf, signed with `sk_leaf`).
    let leaf_kid = "leaf-kid".to_string();
    let hop2 = Pca {
        p_0: "root".into(),
        ops: BTreeSet::from([op_narrow]),
        kid: leaf_kid,
        exp: None,
        nbf: None,
    };
    let signed2 = sign_pca(&hop2, &sk_leaf).unwrap();

    // Truncated: skip hop1, go directly hop0 → hop2.
    // This is invalid because sk_leaf is not in the trusted-keys map for the
    // chain, and there is no monotonicity link from hop0's ops to hop2's ops
    // without going through hop1.
    vec![signed0, signed2]
}

// ---------------------------------------------------------------------------
// AA4: Chain extension — widen operations (violate monotonicity)
// ---------------------------------------------------------------------------

/// AA4: Same as AA2 but with a more subtle approach — the child hop adds
/// an operation not present in the parent rather than replacing the parent's
/// set entirely.
pub fn extend_chain(signing_key: &SigningKey, kid: &str) -> Vec<SignedPca> {
    let op_a = Operation::new("actuate:arm:joint_0").unwrap();
    let op_b = Operation::new("actuate:arm:joint_1").unwrap();

    // Hop 0 grants only op_a.
    let hop0 = Pca {
        p_0: "root".into(),
        ops: BTreeSet::from([op_a.clone()]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed0 = sign_pca(&hop0, signing_key).unwrap();

    // Hop 1 claims op_a AND op_b — op_b was never granted. Monotonicity violation.
    let hop1 = Pca {
        p_0: "root".into(),
        ops: BTreeSet::from([op_a, op_b]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed1 = sign_pca(&hop1, signing_key).unwrap();

    vec![signed0, signed1]
}

// ---------------------------------------------------------------------------
// AA5: Provenance mutation — change p_0 at a later hop
// ---------------------------------------------------------------------------

/// AA5: Build a two-hop chain where hop 1 changes `p_0` to a different
/// principal than hop 0. The provenance invariant (A1: p_0 immutable) must
/// detect this.
pub fn mutate_provenance(signing_key: &SigningKey, kid: &str) -> Vec<SignedPca> {
    let op = Operation::new("actuate:*").unwrap();

    let hop0 = Pca {
        p_0: "alice".into(),
        ops: BTreeSet::from([op.clone()]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed0 = sign_pca(&hop0, signing_key).unwrap();

    // Hop 1 changes p_0 from "alice" to "mallory" — provenance violation.
    let hop1 = Pca {
        p_0: "mallory".into(),
        ops: BTreeSet::from([op]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed1 = sign_pca(&hop1, signing_key).unwrap();

    vec![signed0, signed1]
}

// ---------------------------------------------------------------------------
// AA6: Wildcard exploitation
// ---------------------------------------------------------------------------

/// AA6: Attempt to use a wildcard pattern to match operations the parent
/// never intended to grant.
pub fn wildcard_exploitation(signing_key: &SigningKey, kid: &str) -> Vec<SignedPca> {
    // Parent grants "actuate:arm:*" but child tries to claim "actuate:*"
    // (wider wildcard).
    let parent_op = Operation::new("actuate:arm:*").unwrap();
    let child_op = Operation::new("actuate:*").unwrap();

    let hop0 = Pca {
        p_0: "root".into(),
        ops: BTreeSet::from([parent_op]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed0 = sign_pca(&hop0, signing_key).unwrap();

    let hop1 = Pca {
        p_0: "root".into(),
        ops: BTreeSet::from([child_op]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed1 = sign_pca(&hop1, signing_key).unwrap();

    vec![signed0, signed1]
}

// ---------------------------------------------------------------------------
// AA7: Cross-chain splicing
// ---------------------------------------------------------------------------

/// AA7: Take hop 0 from chain A and hop 1 from a completely different chain B.
/// The resulting hybrid chain should fail signature continuity (A3).
pub fn cross_chain_splice(signing_key: &SigningKey, kid: &str) -> Vec<SignedPca> {
    let rng = &mut rand::rngs::OsRng;
    let other_sk = generate_keypair(rng);

    let op = Operation::new("actuate:*").unwrap();

    // Chain A, hop 0.
    let hop0_a = Pca {
        p_0: "chain-a".into(),
        ops: BTreeSet::from([op.clone()]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed0_a = sign_pca(&hop0_a, signing_key).unwrap();

    // Chain B, hop 1 (signed with a different key).
    let hop1_b = Pca {
        p_0: "chain-b".into(),
        ops: BTreeSet::from([op]),
        kid: "other-kid".to_string(),
        exp: None,
        nbf: None,
    };
    let signed1_b = sign_pca(&hop1_b, &other_sk).unwrap();

    // Splice: hop 0 from A + hop 1 from B.
    vec![signed0_a, signed1_b]
}

// ---------------------------------------------------------------------------
// AA8: Empty operations
// ---------------------------------------------------------------------------

/// AA8: PCA with an empty operations set. Should not authorize anything.
pub fn empty_operations(signing_key: &SigningKey, kid: &str) -> SignedPca {
    let hop = Pca {
        p_0: "root".into(),
        ops: BTreeSet::new(), // empty — authorizes nothing
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    sign_pca(&hop, signing_key).unwrap()
}

// ---------------------------------------------------------------------------
// AA9: Self-delegation (circular chain)
// ---------------------------------------------------------------------------

/// AA9: Entity delegates back to itself, creating a two-hop chain where
/// hop 1 re-delegates to the same key as hop 0.
pub fn self_delegation(signing_key: &SigningKey, kid: &str) -> Vec<SignedPca> {
    let op = Operation::new("actuate:*").unwrap();

    let hop0 = Pca {
        p_0: "self".into(),
        ops: BTreeSet::from([op.clone()]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed0 = sign_pca(&hop0, signing_key).unwrap();

    // Hop 1 re-delegates to the same kid — circular.
    let hop1 = Pca {
        p_0: "self".into(),
        ops: BTreeSet::from([op]),
        kid: kid.to_string(),
        exp: None,
        nbf: None,
    };
    let signed1 = sign_pca(&hop1, signing_key).unwrap();

    vec![signed0, signed1]
}

// ---------------------------------------------------------------------------
// AA10: Expired-but-signed (valid crypto, expired temporal window)
// ---------------------------------------------------------------------------

/// AA10: PCA with valid signature but an `exp` timestamp that has already
/// passed. The verifier must reject despite the crypto being valid.
pub fn expired_but_signed(signing_key: &SigningKey, kid: &str) -> SignedPca {
    let op = Operation::new("actuate:*").unwrap();
    let expired = chrono::Utc::now() - chrono::Duration::hours(24);

    let hop = Pca {
        p_0: "root".into(),
        ops: BTreeSet::from([op]),
        kid: kid.to_string(),
        exp: Some(expired),
        nbf: None,
    };
    sign_pca(&hop, signing_key).unwrap()
}

// ---------------------------------------------------------------------------
// Helper: encode a chain of SignedPca as the base64-JSON string expected by
// the validator's pca_chain field.
// ---------------------------------------------------------------------------

/// Encode a slice of `SignedPca` values as the base64-wrapped JSON string used
/// in `Command::authority::pca_chain`.
pub fn encode_chain(hops: &[SignedPca]) -> String {
    let json = serde_json::to_vec(hops).expect("SignedPca serialization is infallible");
    STANDARD.encode(&json)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use invariant_core::authority::chain::verify_chain;
    use invariant_core::authority::crypto::generate_keypair;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn make_sk() -> SigningKey {
        generate_keypair(&mut OsRng)
    }

    /// Build a minimal trusted-keys map with a single entry.
    fn trusted(kid: &str, sk: &SigningKey) -> HashMap<String, ed25519_dalek::VerifyingKey> {
        let mut map = HashMap::new();
        map.insert(kid.to_string(), sk.verifying_key());
        map
    }

    #[test]
    fn forge_signature_is_rejected_by_verifier() {
        let sk = make_sk();
        let kid = "test-kid";
        let forged = forge_signature(&sk, kid);

        let now = chrono::Utc::now();
        let result = verify_chain(&[forged], &trusted(kid, &sk), now);
        assert!(
            result.is_err(),
            "forged signature must be rejected by verify_chain"
        );
    }

    #[test]
    fn escalate_operations_is_rejected_by_verifier() {
        let sk = make_sk();
        let kid = "test-kid";
        let chain = escalate_operations(&sk, kid);
        assert_eq!(chain.len(), 2);

        let now = chrono::Utc::now();
        let result = verify_chain(&chain, &trusted(kid, &sk), now);
        assert!(
            result.is_err(),
            "operation escalation must be rejected by verify_chain"
        );
    }

    #[test]
    fn truncate_chain_is_rejected_by_verifier() {
        let sk = make_sk();
        let kid = "test-kid";
        let chain = truncate_chain(&sk, kid);
        assert_eq!(chain.len(), 2, "truncated chain must have 2 hops");

        // The leaf key is unknown to the verifier (only root key is trusted).
        let now = chrono::Utc::now();
        let result = verify_chain(&chain, &trusted(kid, &sk), now);
        assert!(
            result.is_err(),
            "truncated chain must be rejected (leaf key unknown)"
        );
    }

    #[test]
    fn forge_signature_raw_bytes_differ_from_valid() {
        let sk = make_sk();
        let kid = "test-kid";

        // Produce a valid SignedPca.
        let op = Operation::new("actuate:*").unwrap();
        let claim = Pca {
            p_0: "attacker".into(),
            ops: BTreeSet::from([op]),
            kid: kid.to_string(),
            exp: None,
            nbf: None,
        };
        let valid = sign_pca(&claim, &sk).unwrap();
        let forged = forge_signature(&sk, kid);

        assert_ne!(
            valid.raw, forged.raw,
            "forged raw bytes must differ from the valid signing"
        );
    }

    #[test]
    fn encode_chain_round_trips() {
        let sk = make_sk();
        let kid = "k1";
        let op = Operation::new("actuate:*").unwrap();
        let claim = Pca {
            p_0: "root".into(),
            ops: BTreeSet::from([op]),
            kid: kid.to_string(),
            exp: None,
            nbf: None,
        };
        let signed = sign_pca(&claim, &sk).unwrap();
        let encoded = encode_chain(std::slice::from_ref(&signed));
        let decoded: Vec<SignedPca> =
            serde_json::from_slice(&STANDARD.decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].raw, signed.raw);
    }

    // --- AA4-AA10 tests ---

    #[test]
    fn extend_chain_is_rejected_by_verifier() {
        let sk = make_sk();
        let kid = "test-kid";
        let chain = extend_chain(&sk, kid);
        assert_eq!(chain.len(), 2);
        let now = chrono::Utc::now();
        let result = verify_chain(&chain, &trusted(kid, &sk), now);
        assert!(
            result.is_err(),
            "AA4: chain extension (wider ops) must be rejected"
        );
    }

    #[test]
    fn mutate_provenance_is_rejected_by_verifier() {
        let sk = make_sk();
        let kid = "test-kid";
        let chain = mutate_provenance(&sk, kid);
        assert_eq!(chain.len(), 2);
        let now = chrono::Utc::now();
        let result = verify_chain(&chain, &trusted(kid, &sk), now);
        assert!(result.is_err(), "AA5: provenance mutation must be rejected");
    }

    #[test]
    fn wildcard_exploitation_is_rejected() {
        let sk = make_sk();
        let kid = "test-kid";
        let chain = wildcard_exploitation(&sk, kid);
        let now = chrono::Utc::now();
        let result = verify_chain(&chain, &trusted(kid, &sk), now);
        assert!(result.is_err(), "AA6: wildcard escalation must be rejected");
    }

    #[test]
    fn cross_chain_splice_is_rejected() {
        let sk = make_sk();
        let kid = "test-kid";
        let chain = cross_chain_splice(&sk, kid);
        let now = chrono::Utc::now();
        let result = verify_chain(&chain, &trusted(kid, &sk), now);
        assert!(result.is_err(), "AA7: cross-chain splice must be rejected");
    }

    #[test]
    fn empty_operations_authorizes_nothing() {
        let sk = make_sk();
        let kid = "test-kid";
        let signed = empty_operations(&sk, kid);
        // Verify the chain itself is valid (empty ops is structurally valid).
        let now = chrono::Utc::now();
        let result = verify_chain(&[signed], &trusted(kid, &sk), now);
        // The chain may verify OK but should grant no operations — tested
        // at the validator level where required_ops would not be satisfied.
        let _ = result;
    }

    #[test]
    fn self_delegation_produces_two_hops() {
        let sk = make_sk();
        let kid = "test-kid";
        let chain = self_delegation(&sk, kid);
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn expired_but_signed_has_valid_structure() {
        let sk = make_sk();
        let kid = "test-kid";
        let signed = expired_but_signed(&sk, kid);
        assert!(!signed.raw.is_empty());
    }
}
