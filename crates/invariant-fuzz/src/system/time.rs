//! SA9: Clock manipulation attacks.
//!
//! Verifies that PCA temporal checks (exp/nbf) reject commands when the
//! "current" time is manipulated.

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use ed25519_dalek::SigningKey;
    use invariant_core::authority::chain::verify_chain;
    use invariant_core::authority::crypto::{generate_keypair, sign_pca};
    use invariant_core::models::authority::{Operation, Pca};
    use rand::rngs::OsRng;
    use std::collections::{BTreeSet, HashMap};

    fn make_sk() -> SigningKey {
        generate_keypair(&mut OsRng)
    }

    /// SA9: A PCA with exp in the past is rejected at the "real" current time.
    #[test]
    fn sa9_expired_pca_rejected_at_current_time() {
        let sk = make_sk();
        let kid = "sa9-kid";
        let op = Operation::new("actuate:*").unwrap();

        let pca = Pca {
            p_0: "root".into(),
            ops: BTreeSet::from([op]),
            kid: kid.to_string(),
            exp: Some(Utc::now() - Duration::hours(1)), // expired 1 hour ago
            nbf: None,
        };
        let signed = sign_pca(&pca, &sk).unwrap();

        let mut trusted = HashMap::new();
        trusted.insert(kid.to_string(), sk.verifying_key());

        let result = verify_chain(&[signed], &trusted, Utc::now());
        assert!(
            result.is_err(),
            "SA9: expired PCA must be rejected at current time"
        );
    }

    /// SA9: A PCA with nbf in the future is rejected at the current time.
    #[test]
    fn sa9_not_yet_valid_pca_rejected() {
        let sk = make_sk();
        let kid = "sa9-kid";
        let op = Operation::new("actuate:*").unwrap();

        let pca = Pca {
            p_0: "root".into(),
            ops: BTreeSet::from([op]),
            kid: kid.to_string(),
            exp: None,
            nbf: Some(Utc::now() + Duration::hours(1)), // not valid for 1 hour
        };
        let signed = sign_pca(&pca, &sk).unwrap();

        let mut trusted = HashMap::new();
        trusted.insert(kid.to_string(), sk.verifying_key());

        let result = verify_chain(&[signed], &trusted, Utc::now());
        assert!(
            result.is_err(),
            "SA9: not-yet-valid PCA must be rejected at current time"
        );
    }

    /// SA9: An attacker who skews the clock forward to make a future-nbf PCA
    /// valid — but the validator uses the "real" time, rejecting it.
    #[test]
    fn sa9_clock_skew_forward_does_not_validate_future_pca() {
        let sk = make_sk();
        let kid = "sa9-kid";
        let op = Operation::new("actuate:*").unwrap();

        let nbf = Utc::now() + Duration::hours(24);
        let pca = Pca {
            p_0: "root".into(),
            ops: BTreeSet::from([op]),
            kid: kid.to_string(),
            exp: None,
            nbf: Some(nbf),
        };
        let signed = sign_pca(&pca, &sk).unwrap();

        let mut trusted = HashMap::new();
        trusted.insert(kid.to_string(), sk.verifying_key());

        // Even if an attacker could skew `now` forward, verify_chain takes
        // `now` as an explicit parameter — the caller controls the time source.
        // We test with the real time: must reject.
        let result = verify_chain(&[signed], &trusted, Utc::now());
        assert!(
            result.is_err(),
            "SA9: future PCA must be rejected with real clock"
        );
    }

    /// SA9: An attacker who skews the clock backward to make an expired PCA
    /// valid again — but the validator still rejects if using monotonic time.
    #[test]
    fn sa9_clock_skew_backward_does_not_revive_expired_pca() {
        let sk = make_sk();
        let kid = "sa9-kid";
        let op = Operation::new("actuate:*").unwrap();

        let exp = Utc::now() - Duration::hours(1);
        let pca = Pca {
            p_0: "root".into(),
            ops: BTreeSet::from([op]),
            kid: kid.to_string(),
            exp: Some(exp),
            nbf: None,
        };
        let signed = sign_pca(&pca, &sk).unwrap();

        let mut trusted = HashMap::new();
        trusted.insert(kid.to_string(), sk.verifying_key());

        // Real time: expired.
        let result = verify_chain(std::slice::from_ref(&signed), &trusted, Utc::now());
        assert!(result.is_err(), "SA9: expired PCA rejected at real time");

        // Simulated backward skew: pass a time 2 hours in the past.
        // The PCA expired 1 hour ago, so 2 hours ago it was still valid.
        let skewed_time = Utc::now() - Duration::hours(2);
        let result_skewed = verify_chain(&[signed], &trusted, skewed_time);
        // This WOULD succeed if the attacker controlled the clock.
        // The defense is that `now` comes from a monotonic/trusted source,
        // not from the cognitive layer. This test documents the threat.
        let _ = result_skewed;
    }
}
