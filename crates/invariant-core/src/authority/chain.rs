// PCA chain validation: A1 provenance, A2 monotonicity, A3 continuity.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;

use crate::models::authority::{AuthorityChain, Operation, SignedPca};
use crate::models::error::AuthorityError;

use super::crypto::verify_signed_pca;
use super::operations::ops_are_subset;

/// Maximum number of hops allowed in a chain (DoS guard).
const MAX_HOPS: usize = 16;

/// Verify a PCA chain and produce a validated `AuthorityChain`.
///
/// Checks performed (in order for each hop):
///
/// 1. **A3 — Continuity**: Ed25519 signature over COSE_Sign1 envelope is valid
///    for the key identified by `kid`.
/// 2. **A1 — Provenance**: `p_0` is identical across all hops.
/// 3. **A2 — Monotonicity**: `ops` at hop *i+1* is a subset of `ops` at hop *i*.
/// 4. **Temporal**: `now` is within `[nbf, exp]` for each hop (if present).
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
        return Err(AuthorityError::CoseError {
            hop: hops.len() - 1,
            reason: format!("chain has {} hops, exceeding maximum of {MAX_HOPS}", hops.len()),
        });
    }

    let origin = &hops[0].claim.p_0;

    for (i, signed) in hops.iter().enumerate() {
        let claim = &signed.claim;

        // A3: Signature verification.
        let key = trusted_keys.get(&claim.kid).ok_or_else(|| {
            AuthorityError::UnknownKeyId {
                hop: i,
                kid: claim.kid.clone(),
            }
        })?;
        verify_signed_pca(signed, key, i)?;

        // A1: Provenance — p_0 must be immutable.
        if &claim.p_0 != origin {
            return Err(AuthorityError::ProvenanceMismatch {
                hop: i,
                expected: origin.clone(),
                got: claim.p_0.clone(),
            });
        }

        // A2: Monotonicity — ops must narrow (be a subset of parent).
        if i > 0 {
            let parent_ops = &hops[i - 1].claim.ops;
            if !ops_are_subset(&claim.ops, parent_ops) {
                // Find the first offending op for the error message.
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
    }

    let final_hop = hops.last().unwrap();

    Ok(AuthorityChain {
        hops: hops.to_vec(),
        origin_principal: origin.clone(),
        final_ops: final_hop.claim.ops.clone(),
    })
}

/// Verify that the chain's final ops cover all required operations.
pub fn check_required_ops(
    chain: &AuthorityChain,
    required: &[Operation],
) -> Result<(), AuthorityError> {
    if let Some(uncovered) = super::operations::first_uncovered_op(&chain.final_ops, required) {
        return Err(AuthorityError::InsufficientOps {
            op: uncovered.as_str().to_owned(),
        });
    }
    Ok(())
}
