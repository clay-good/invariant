#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use chrono::{Duration, Utc};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use crate::authority::chain::{check_required_ops, verify_chain};
    use crate::authority::crypto::{generate_keypair, sign_pca, verify_signed_pca};
    use crate::authority::operations::{
        first_uncovered_op, operation_matches, ops_are_subset, ops_cover_required,
    };
    use crate::models::authority::{Operation, Pca};
    use crate::models::error::AuthorityError;

    // ───── Helpers ─────

    fn op(s: &str) -> Operation {
        Operation::new(s).unwrap()
    }

    fn ops(ss: &[&str]) -> BTreeSet<Operation> {
        ss.iter().map(|s| op(s)).collect()
    }

    fn make_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn make_pca(p_0: &str, kid: &str, op_strs: &[&str]) -> Pca {
        Pca {
            p_0: p_0.into(),
            ops: ops(op_strs),
            kid: kid.into(),
            exp: None,
            nbf: None,
        }
    }

    fn trusted_keys(pairs: &[(&str, &ed25519_dalek::VerifyingKey)]) -> HashMap<String, ed25519_dalek::VerifyingKey> {
        pairs.iter().map(|(k, v)| (k.to_string(), **v)).collect()
    }

    // ───── operations::operation_matches ─────

    #[test]
    fn exact_match() {
        assert!(operation_matches(&op("actuate:arm:shoulder"), &op("actuate:arm:shoulder")));
    }

    #[test]
    fn no_match_different() {
        assert!(!operation_matches(&op("actuate:arm:shoulder"), &op("actuate:arm:elbow")));
    }

    #[test]
    fn wildcard_trailing_star() {
        let granted = op("actuate:arm:*");
        assert!(operation_matches(&granted, &op("actuate:arm:shoulder")));
        assert!(operation_matches(&granted, &op("actuate:arm:elbow")));
        assert!(!operation_matches(&granted, &op("actuate:leg:knee")));
    }

    #[test]
    fn bare_wildcard_covers_everything() {
        let granted = op("*");
        assert!(operation_matches(&granted, &op("actuate:arm:shoulder")));
        assert!(operation_matches(&granted, &op("anything")));
    }

    #[test]
    fn wildcard_prefix_match_boundary() {
        let granted = op("actuate:*");
        assert!(operation_matches(&granted, &op("actuate:arm")));
        assert!(operation_matches(&granted, &op("actuate:arm:shoulder")));
        assert!(!operation_matches(&granted, &op("read:sensor")));
    }

    #[test]
    fn wildcard_does_not_match_partial_prefix() {
        let granted = op("actuate:arm:*");
        // "actuate:armX:foo" should NOT match "actuate:arm:*"
        assert!(!operation_matches(&granted, &op("actuate:armX:foo")));
    }

    #[test]
    fn mid_wildcard_is_literal() {
        // Wildcard in the middle is NOT expanded — treated as literal.
        let granted = op("actuate:*:shoulder");
        assert!(!operation_matches(&granted, &op("actuate:arm:shoulder")));
        // But exact match still works.
        assert!(operation_matches(&granted, &op("actuate:*:shoulder")));
    }

    // ───── operations::ops_are_subset ─────

    #[test]
    fn subset_exact() {
        let parent = ops(&["actuate:arm:shoulder", "actuate:arm:elbow"]);
        let child = ops(&["actuate:arm:shoulder"]);
        assert!(ops_are_subset(&child, &parent));
    }

    #[test]
    fn subset_via_wildcard() {
        let parent = ops(&["actuate:arm:*"]);
        let child = ops(&["actuate:arm:shoulder", "actuate:arm:elbow"]);
        assert!(ops_are_subset(&child, &parent));
    }

    #[test]
    fn not_subset_escalation() {
        let parent = ops(&["actuate:arm:shoulder"]);
        let child = ops(&["actuate:arm:shoulder", "actuate:arm:elbow"]);
        assert!(!ops_are_subset(&child, &parent));
    }

    #[test]
    fn empty_child_is_always_subset() {
        let parent = ops(&["actuate:arm:shoulder"]);
        let child: BTreeSet<Operation> = BTreeSet::new();
        assert!(ops_are_subset(&child, &parent));
    }

    // ───── operations::ops_cover_required ─────

    #[test]
    fn cover_all_required() {
        let granted = ops(&["actuate:arm:*"]);
        let required = vec![op("actuate:arm:shoulder"), op("actuate:arm:elbow")];
        assert!(ops_cover_required(&granted, &required));
    }

    #[test]
    fn not_cover_missing_op() {
        let granted = ops(&["actuate:arm:shoulder"]);
        let required = vec![op("actuate:arm:shoulder"), op("actuate:arm:elbow")];
        assert!(!ops_cover_required(&granted, &required));
    }

    #[test]
    fn first_uncovered() {
        let granted = ops(&["actuate:arm:shoulder"]);
        let required = vec![op("actuate:arm:elbow"), op("actuate:arm:wrist")];
        let uncovered = first_uncovered_op(&granted, &required);
        assert!(uncovered.is_some());
        assert_eq!(uncovered.unwrap().as_str(), "actuate:arm:elbow");
    }

    // ───── crypto::sign_pca + verify_signed_pca ─────

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, vk) = make_keypair();
        let claim = make_pca("alice", "key-1", &["actuate:arm:*"]);
        let signed = sign_pca(&claim, &sk);

        assert_eq!(signed.claim, claim);
        assert!(!signed.raw.is_empty());
        assert!(verify_signed_pca(&signed, &vk, 0).is_ok());
    }

    #[test]
    fn verify_fails_wrong_key() {
        let (sk, _vk) = make_keypair();
        let (_sk2, vk2) = make_keypair();
        let claim = make_pca("alice", "key-1", &["actuate:arm:*"]);
        let signed = sign_pca(&claim, &sk);

        let result = verify_signed_pca(&signed, &vk2, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthorityError::SignatureInvalid { hop, .. } => assert_eq!(hop, 0),
            other => panic!("expected SignatureInvalid, got: {other}"),
        }
    }

    #[test]
    fn verify_fails_tampered_payload() {
        let (sk, vk) = make_keypair();
        let claim = make_pca("alice", "key-1", &["actuate:arm:*"]);
        let mut signed = sign_pca(&claim, &sk);

        // Tamper with the raw COSE bytes — flip a byte near the end.
        if let Some(last) = signed.raw.last_mut() {
            *last ^= 0xFF;
        }

        let result = verify_signed_pca(&signed, &vk, 0);
        assert!(result.is_err());
    }

    #[test]
    fn decode_payload_roundtrip() {
        let (sk, _vk) = make_keypair();
        let claim = make_pca("alice", "key-1", &["actuate:arm:*"]);
        let signed = sign_pca(&claim, &sk);

        let decoded = crate::authority::crypto::decode_pca_payload(&signed.raw, 0).unwrap();
        assert_eq!(decoded, claim);
    }

    // ───── chain::verify_chain ─────

    #[test]
    fn valid_single_hop_chain() {
        let (sk, vk) = make_keypair();
        let claim = make_pca("alice", "key-1", &["actuate:arm:*"]);
        let signed = sign_pca(&claim, &sk);

        let keys = trusted_keys(&[("key-1", &vk)]);
        let chain = verify_chain(&[signed], &keys, Utc::now()).unwrap();

        assert_eq!(chain.origin_principal, "alice");
        assert_eq!(chain.final_ops, ops(&["actuate:arm:*"]));
        assert_eq!(chain.hops.len(), 1);
    }

    #[test]
    fn valid_two_hop_chain_narrowing() {
        let (sk1, vk1) = make_keypair();
        let (sk2, vk2) = make_keypair();

        let claim0 = make_pca("alice", "key-1", &["actuate:arm:*", "actuate:leg:*"]);
        let claim1 = make_pca("alice", "key-2", &["actuate:arm:shoulder", "actuate:arm:elbow"]);

        let signed0 = sign_pca(&claim0, &sk1);
        let signed1 = sign_pca(&claim1, &sk2);

        let keys = trusted_keys(&[("key-1", &vk1), ("key-2", &vk2)]);
        let chain = verify_chain(&[signed0, signed1], &keys, Utc::now()).unwrap();

        assert_eq!(chain.origin_principal, "alice");
        assert_eq!(chain.final_ops, ops(&["actuate:arm:shoulder", "actuate:arm:elbow"]));
        assert_eq!(chain.hops.len(), 2);
    }

    #[test]
    fn valid_three_hop_chain() {
        let (sk1, vk1) = make_keypair();
        let (sk2, vk2) = make_keypair();
        let (sk3, vk3) = make_keypair();

        let claim0 = make_pca("alice", "key-1", &["actuate:*"]);
        let claim1 = make_pca("alice", "key-2", &["actuate:arm:*"]);
        let claim2 = make_pca("alice", "key-3", &["actuate:arm:shoulder"]);

        let signed0 = sign_pca(&claim0, &sk1);
        let signed1 = sign_pca(&claim1, &sk2);
        let signed2 = sign_pca(&claim2, &sk3);

        let keys = trusted_keys(&[("key-1", &vk1), ("key-2", &vk2), ("key-3", &vk3)]);
        let chain = verify_chain(&[signed0, signed1, signed2], &keys, Utc::now()).unwrap();

        assert_eq!(chain.final_ops, ops(&["actuate:arm:shoulder"]));
    }

    #[test]
    fn empty_chain_rejected() {
        let keys: HashMap<String, ed25519_dalek::VerifyingKey> = HashMap::new();
        let result = verify_chain(&[], &keys, Utc::now());
        assert!(matches!(result, Err(AuthorityError::EmptyChain)));
    }

    #[test]
    fn a1_provenance_mismatch() {
        let (sk1, vk1) = make_keypair();
        let (sk2, vk2) = make_keypair();

        let claim0 = make_pca("alice", "key-1", &["actuate:arm:*"]);
        let claim1 = make_pca("bob", "key-2", &["actuate:arm:shoulder"]); // different p_0!

        let signed0 = sign_pca(&claim0, &sk1);
        let signed1 = sign_pca(&claim1, &sk2);

        let keys = trusted_keys(&[("key-1", &vk1), ("key-2", &vk2)]);
        let result = verify_chain(&[signed0, signed1], &keys, Utc::now());

        match result {
            Err(AuthorityError::ProvenanceMismatch { hop: 1, expected, got }) => {
                assert_eq!(expected, "alice");
                assert_eq!(got, "bob");
            }
            other => panic!("expected ProvenanceMismatch at hop 1, got: {other:?}"),
        }
    }

    #[test]
    fn a2_monotonicity_violation_escalation() {
        let (sk1, vk1) = make_keypair();
        let (sk2, vk2) = make_keypair();

        let claim0 = make_pca("alice", "key-1", &["actuate:arm:shoulder"]);
        let claim1 = make_pca("alice", "key-2", &["actuate:arm:shoulder", "actuate:arm:elbow"]); // escalation!

        let signed0 = sign_pca(&claim0, &sk1);
        let signed1 = sign_pca(&claim1, &sk2);

        let keys = trusted_keys(&[("key-1", &vk1), ("key-2", &vk2)]);
        let result = verify_chain(&[signed0, signed1], &keys, Utc::now());

        match result {
            Err(AuthorityError::MonotonicityViolation { hop: 1, op }) => {
                assert_eq!(op, "actuate:arm:elbow");
            }
            other => panic!("expected MonotonicityViolation, got: {other:?}"),
        }
    }

    #[test]
    fn a3_unknown_key_id() {
        let (sk, _vk) = make_keypair();
        let claim = make_pca("alice", "unknown-key", &["actuate:arm:*"]);
        let signed = sign_pca(&claim, &sk);

        let keys: HashMap<String, ed25519_dalek::VerifyingKey> = HashMap::new();
        let result = verify_chain(&[signed], &keys, Utc::now());

        match result {
            Err(AuthorityError::UnknownKeyId { hop: 0, kid }) => {
                assert_eq!(kid, "unknown-key");
            }
            other => panic!("expected UnknownKeyId, got: {other:?}"),
        }
    }

    #[test]
    fn a3_wrong_signature_key() {
        let (sk1, _vk1) = make_keypair();
        let (_sk2, vk2) = make_keypair();

        let claim = make_pca("alice", "key-1", &["actuate:arm:*"]);
        let signed = sign_pca(&claim, &sk1);

        // Register a different key under the same kid.
        let keys = trusted_keys(&[("key-1", &vk2)]);
        let result = verify_chain(&[signed], &keys, Utc::now());

        assert!(matches!(result, Err(AuthorityError::SignatureInvalid { hop: 0, .. })));
    }

    #[test]
    fn temporal_expired() {
        let (sk, vk) = make_keypair();
        let claim = Pca {
            p_0: "alice".into(),
            ops: ops(&["actuate:arm:*"]),
            kid: "key-1".into(),
            exp: Some(Utc::now() - Duration::seconds(10)),
            nbf: None,
        };
        let signed = sign_pca(&claim, &sk);

        let keys = trusted_keys(&[("key-1", &vk)]);
        let result = verify_chain(&[signed], &keys, Utc::now());

        assert!(matches!(result, Err(AuthorityError::Expired { hop: 0, .. })));
    }

    #[test]
    fn temporal_not_yet_valid() {
        let (sk, vk) = make_keypair();
        let claim = Pca {
            p_0: "alice".into(),
            ops: ops(&["actuate:arm:*"]),
            kid: "key-1".into(),
            exp: None,
            nbf: Some(Utc::now() + Duration::seconds(3600)),
        };
        let signed = sign_pca(&claim, &sk);

        let keys = trusted_keys(&[("key-1", &vk)]);
        let result = verify_chain(&[signed], &keys, Utc::now());

        assert!(matches!(result, Err(AuthorityError::NotYetValid { hop: 0, .. })));
    }

    #[test]
    fn temporal_valid_window() {
        let (sk, vk) = make_keypair();
        let now = Utc::now();
        let claim = Pca {
            p_0: "alice".into(),
            ops: ops(&["actuate:arm:*"]),
            kid: "key-1".into(),
            exp: Some(now + Duration::seconds(3600)),
            nbf: Some(now - Duration::seconds(60)),
        };
        let signed = sign_pca(&claim, &sk);

        let keys = trusted_keys(&[("key-1", &vk)]);
        assert!(verify_chain(&[signed], &keys, now).is_ok());
    }

    // ───── chain::check_required_ops ─────

    #[test]
    fn required_ops_covered() {
        let (sk, vk) = make_keypair();
        let claim = make_pca("alice", "key-1", &["actuate:arm:*"]);
        let signed = sign_pca(&claim, &sk);

        let keys = trusted_keys(&[("key-1", &vk)]);
        let chain = verify_chain(&[signed], &keys, Utc::now()).unwrap();

        let required = vec![op("actuate:arm:shoulder")];
        assert!(check_required_ops(&chain, &required).is_ok());
    }

    #[test]
    fn required_ops_not_covered() {
        let (sk, vk) = make_keypair();
        let claim = make_pca("alice", "key-1", &["actuate:arm:shoulder"]);
        let signed = sign_pca(&claim, &sk);

        let keys = trusted_keys(&[("key-1", &vk)]);
        let chain = verify_chain(&[signed], &keys, Utc::now()).unwrap();

        let required = vec![op("actuate:arm:shoulder"), op("actuate:arm:elbow")];
        let result = check_required_ops(&chain, &required);
        match result {
            Err(AuthorityError::InsufficientOps { op }) => {
                assert_eq!(op, "actuate:arm:elbow");
            }
            other => panic!("expected InsufficientOps, got: {other:?}"),
        }
    }

    // ───── Edge cases ─────

    #[test]
    fn chain_same_ops_no_narrowing_is_valid() {
        let (sk1, vk1) = make_keypair();
        let (sk2, vk2) = make_keypair();

        let claim0 = make_pca("alice", "key-1", &["actuate:arm:shoulder"]);
        let claim1 = make_pca("alice", "key-2", &["actuate:arm:shoulder"]); // same ops = valid subset

        let signed0 = sign_pca(&claim0, &sk1);
        let signed1 = sign_pca(&claim1, &sk2);

        let keys = trusted_keys(&[("key-1", &vk1), ("key-2", &vk2)]);
        assert!(verify_chain(&[signed0, signed1], &keys, Utc::now()).is_ok());
    }

    #[test]
    fn chain_empty_ops_at_leaf_is_valid() {
        let (sk1, vk1) = make_keypair();
        let (sk2, vk2) = make_keypair();

        let claim0 = make_pca("alice", "key-1", &["actuate:arm:*"]);
        let claim1 = Pca {
            p_0: "alice".into(),
            ops: BTreeSet::new(), // empty set is a subset of anything
            kid: "key-2".into(),
            exp: None,
            nbf: None,
        };

        let signed0 = sign_pca(&claim0, &sk1);
        let signed1 = sign_pca(&claim1, &sk2);

        let keys = trusted_keys(&[("key-1", &vk1), ("key-2", &vk2)]);
        let chain = verify_chain(&[signed0, signed1], &keys, Utc::now()).unwrap();
        assert!(chain.final_ops.is_empty());
    }

    #[test]
    fn keypair_generation_produces_valid_keys() {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();

        let claim = make_pca("test", "k", &["op:a"]);
        let signed = sign_pca(&claim, &sk);
        assert!(verify_signed_pca(&signed, &vk, 0).is_ok());
    }

    #[test]
    fn operation_matches_prefix_without_colon() {
        // "actuate:arm:*" should match "actuate:arm" (the prefix itself)
        let granted = op("actuate:arm:*");
        assert!(operation_matches(&granted, &op("actuate:arm")));
    }

    #[test]
    fn wildcard_multi_level_narrowing() {
        // actuate:* covers actuate:arm:shoulder (multi-level under prefix)
        let parent = ops(&["actuate:*"]);
        let child = ops(&["actuate:arm:shoulder"]);
        assert!(ops_are_subset(&child, &parent));
    }

    #[test]
    fn cose_serialization_deterministic() {
        let (sk, _vk) = make_keypair();
        let claim = make_pca("alice", "key-1", &["actuate:arm:shoulder"]);

        let s1 = sign_pca(&claim, &sk);
        let s2 = sign_pca(&claim, &sk);

        // Ed25519 signatures are deterministic (RFC 8032), so the COSE envelopes
        // should be byte-identical when signing the same data with the same key.
        assert_eq!(s1.raw, s2.raw);
    }

    #[test]
    fn max_hops_exceeded() {
        let (sk, vk) = make_keypair();
        let mut hops = Vec::new();
        for _ in 0..17 {
            let claim = make_pca("alice", "key-1", &["actuate:arm:*"]);
            hops.push(sign_pca(&claim, &sk));
        }

        let keys = trusted_keys(&[("key-1", &vk)]);
        let result = verify_chain(&hops, &keys, Utc::now());
        assert!(result.is_err());
    }
}
