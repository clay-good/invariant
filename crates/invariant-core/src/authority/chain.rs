// PCA chain validation: A1 provenance, A2 monotonicity, A3 continuity.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;

use crate::models::authority::{AuthorityChain, Operation, Pca, SignedPca};
use crate::models::error::AuthorityError;

use super::crypto::{decode_pca_payload, extract_kid, verify_signed_pca};
use super::operations::ops_are_subset;

/// Maximum number of hops allowed in a chain (DoS guard).
const MAX_HOPS: usize = 16;

/// Verify a PCA chain and produce a validated `AuthorityChain`.
///
/// Checks performed (in order for each hop):
///
/// 1. **A3 — Continuity**: Ed25519 signature over COSE_Sign1 envelope is valid
///    for the key identified by `kid` (extracted from the COSE protected header).
/// 2. **A1 — Provenance**: `p_0` is identical across all hops (decoded from
///    the verified COSE payload, not from any unverified sidecar field).
/// 3. **A2 — Monotonicity**: `ops` at hop *i+1* is a subset of `ops` at hop *i*.
/// 4. **Temporal**: `now` is within `[nbf, exp)` for each hop (if present).
///
/// `trusted_keys` maps `kid` strings to their Ed25519 verifying keys.
pub fn verify_chain(
    hops: &[SignedPca],
    trusted_keys: &HashMap<String, VerifyingKey>,
    now: DateTime<Utc>,
) -> Result<AuthorityChain, AuthorityError> {
    if hops.is_empty() {
        return Err(AuthorityError::EmptyChain);
    }

    if hops.len() > MAX_HOPS {
        return Err(AuthorityError::ChainTooLong {
            len: hops.len(),
            max: MAX_HOPS,
        });
    }

    // Decode origin from the first hop's COSE payload (pre-verification decode
    // for the origin principal; the signature is verified inside the loop).
    let origin_claim = decode_pca_payload(&hops[0].raw, 0)?;
    let origin = origin_claim.p_0.clone();

    let mut decoded_claims: Vec<Pca> = Vec::with_capacity(hops.len());

    for (i, signed) in hops.iter().enumerate() {
        // Extract kid from the COSE protected header (covered by signature).
        let kid = extract_kid(&signed.raw, i)?;

        // A3: Signature verification.
        let key = trusted_keys.get(&kid).ok_or_else(|| {
            AuthorityError::UnknownKeyId {
                hop: i,
                kid: kid.clone(),
            }
        })?;
        verify_signed_pca(signed, key, i)?;

        // Decode the verified COSE payload — this is the trusted claim.
        let claim = decode_pca_payload(&signed.raw, i)?;

        // A1: Provenance — p_0 must be immutable across all hops.
        if claim.p_0 != origin {
            return Err(AuthorityError::ProvenanceMismatch {
                hop: i,
                expected: origin.clone(),
                got: claim.p_0.clone(),
            });
        }

        // A2: Monotonicity — ops must narrow (be a subset of parent).
        if i > 0 {
            let parent_ops = &decoded_claims[i - 1].ops;
            if !ops_are_subset(&claim.ops, parent_ops) {
                let bad = claim
                    .ops
                    .iter()
                    .find(|op| {
                        !parent_ops
                            .iter()
                            .any(|p| super::operations::operation_matches(p, op))
                    })
                    .map(|op| op.as_str().to_owned())
                    .unwrap_or_default();
                return Err(AuthorityError::MonotonicityViolation { hop: i, op: bad });
            }
        }

        // Temporal constraints.
        if let Some(exp) = claim.exp {
            if now >= exp {
                return Err(AuthorityError::Expired {
                    hop: i,
                    exp: exp.to_rfc3339(),
                });
            }
        }
        if let Some(nbf) = claim.nbf {
            if now < nbf {
                return Err(AuthorityError::NotYetValid {
                    hop: i,
                    nbf: nbf.to_rfc3339(),
                });
            }
        }

        decoded_claims.push(claim);
    }

    let final_ops = decoded_claims.last().unwrap().ops.clone();

    Ok(AuthorityChain::new(
        hops.to_vec(),
        origin,
        final_ops,
    ))
}

/// Verify that the chain's final ops cover all required operations.
pub fn check_required_ops(
    chain: &AuthorityChain,
    required: &[Operation],
) -> Result<(), AuthorityError> {
    if let Some(uncovered) = super::operations::first_uncovered_op(chain.final_ops(), required) {
        return Err(AuthorityError::InsufficientOps {
            op: uncovered.as_str().to_owned(),
        });
    }
    Ok(())
}
