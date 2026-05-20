// PCA chain validation: A1 provenance, A2 monotonicity, A3 continuity.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;

use crate::models::authority::{AuthorityChain, Operation, Pca, SignedPca};
use crate::models::error::AuthorityError;

use super::crypto::{
    decode_pca_payload_from_parsed, extract_kid_from_parsed, parse_cose, verify_signed_pca_parsed,
};
use super::operations::ops_are_subset;

/// Maximum number of hops allowed in a chain (DoS guard).
const MAX_HOPS: usize = 16;

/// Public alias for [`MAX_HOPS`] — used by domain crates that expose a
/// configurable `max_authority_chain_depth` on their profile.
pub const DEFAULT_MAX_HOPS: usize = MAX_HOPS;

/// Like [`verify_chain`] but with a configurable maximum chain depth.
/// The effective depth is `min(max_depth, DEFAULT_MAX_HOPS)`.
pub fn verify_chain_with_max_depth(
    hops: &[SignedPca],
    trusted_keys: &std::collections::HashMap<String, ed25519_dalek::VerifyingKey>,
    now: chrono::DateTime<chrono::Utc>,
    max_depth: usize,
) -> Result<AuthorityChain, AuthorityError> {
    if hops.is_empty() {
        return Err(AuthorityError::EmptyChain);
    }
    let effective = max_depth.min(DEFAULT_MAX_HOPS);
    if hops.len() > effective {
        return Err(AuthorityError::ChainTooLong {
            len: hops.len(),
            max: effective,
        });
    }
    verify_chain(hops, trusted_keys, now)
}

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

    let mut decoded_claims: Vec<Pca> = Vec::with_capacity(hops.len());
    let mut origin: Option<String> = None;

    for (i, signed) in hops.iter().enumerate() {
        // Parse the COSE_Sign1 envelope once; all subsequent operations reuse
        // the same parsed struct to avoid redundant CBOR decoding (Finding 26).
        let cose = parse_cose(&signed.raw, i)?;

        // Extract kid from the COSE protected header (covered by signature).
        let kid = extract_kid_from_parsed(&cose, i)?;

        // A3: Signature verification — must complete before we trust the payload.
        let key = trusted_keys
            .get(&kid)
            .ok_or_else(|| AuthorityError::UnknownKeyId {
                hop: i,
                kid: kid.clone(),
            })?;
        verify_signed_pca_parsed(&cose, key, i)?;

        // Decode the verified COSE payload — this is the trusted claim.
        let claim = decode_pca_payload_from_parsed(&cose, i)?;

        // A1: Provenance — p_0 must be immutable across all hops.
        // Extract origin from the first verified hop.
        match &origin {
            None => {
                origin = Some(claim.p_0.clone());
            }
            Some(expected) => {
                if claim.p_0 != *expected {
                    return Err(AuthorityError::ProvenanceMismatch {
                        hop: i,
                        expected: expected.clone(),
                        got: claim.p_0.clone(),
                    });
                }
            }
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

    // v11 1.2 — A3 causal binding (predecessor_digest), mandatory.
    //
    // Promoted from opt-in detection mode to mandatory enforcement on
    // 2026-05-19 once every multi-hop chain producer in the workspace
    // was migrated to call `link_chain_digests` (or set the field by
    // hand) before signing. Root hop must carry `[0u8; 32]`; each
    // child hop must carry `sha256(canonical_bytes(parent))`.
    //
    // Single-hop chains (one root only) pass trivially because the
    // root sentinel is `[0u8; 32]` and there are no children.
    verify_predecessor_chain(&decoded_claims)?;

    // origin and final_ops are guaranteed to be Some/non-empty because hops is
    // non-empty (checked above) and we set origin on the first iteration. We
    // use ok_or instead of unwrap so that a logic regression produces a clear
    // AuthorityError rather than a panic.
    let origin = origin.ok_or(AuthorityError::EmptyChain)?;
    let final_ops = decoded_claims
        .last()
        .ok_or(AuthorityError::EmptyChain)?
        .ops
        .clone();

    Ok(AuthorityChain::new(hops.to_vec(), origin, final_ops))
}

/// v11 1.2 — Link the A3 predecessor digests across a sequence of `Pca`
/// claims, in place. Sets `claims[0].predecessor_digest = [0u8; 32]`
/// (root sentinel) and, for each `i ≥ 1`,
/// `claims[i].predecessor_digest = sha256(canonical_bytes(claims[i-1]))`.
///
/// This is the production-ready chain builder: callers that construct a
/// multi-hop chain should call this before signing each claim so the
/// resulting `SignedPca` sequence verifies under the **mandatory**
/// `verify_chain` predecessor enforcement that landed in v11 1.2.
pub fn link_chain_digests(claims: &mut [Pca]) {
    if claims.is_empty() {
        return;
    }
    claims[0].predecessor_digest = [0u8; 32];
    for i in 1..claims.len() {
        let parent_digest = claims[i - 1].sha256_digest();
        claims[i].predecessor_digest = parent_digest;
    }
}

/// v11 1.2 — Verify the per-hop A3 causal binding (`predecessor_digest`)
/// across a sequence of decoded claims. Root hop (index 0) must carry the
/// all-zero sentinel; for each `i ≥ 1`,
/// `hop[i].predecessor_digest == sha256(canonical_bytes(hop[i-1]))`.
///
/// Public so callers (e.g. the `audit verify --predecessor-digest` flag,
/// or a future opt-in `verify_chain_strict_predecessor`) can drive the
/// check directly when they know every hop has set the field.
pub fn verify_predecessor_chain(claims: &[Pca]) -> Result<(), AuthorityError> {
    if claims.is_empty() {
        return Err(AuthorityError::EmptyChain);
    }
    if claims[0].predecessor_digest != [0u8; 32] {
        return Err(AuthorityError::PredecessorDigestNonZeroAtRoot);
    }
    for i in 1..claims.len() {
        let expected = claims[i - 1].sha256_digest();
        if claims[i].predecessor_digest != expected {
            return Err(AuthorityError::PredecessorDigestMismatch { hop: i });
        }
    }
    Ok(())
}

/// v11 1.2 — Like [`verify_chain`] but mandatorily enforces the A3 causal
/// binding on every hop. Use this from CLI surfaces (e.g.
/// `audit verify --predecessor-digest`) that have a contract with the
/// operator to require the binding be set.
pub fn verify_chain_strict_predecessor(
    hops: &[SignedPca],
    trusted_keys: &HashMap<String, VerifyingKey>,
    now: DateTime<Utc>,
) -> Result<AuthorityChain, AuthorityError> {
    let chain = verify_chain(hops, trusted_keys, now)?;
    // Decode each hop's claim again to feed `verify_predecessor_chain`.
    // The signature path in `verify_chain` already ran, so re-decoding is
    // safe; we just need the typed `Pca` projection.
    let mut claims: Vec<Pca> = Vec::with_capacity(hops.len());
    for (i, signed) in hops.iter().enumerate() {
        let cose = parse_cose(&signed.raw, i)?;
        let claim = decode_pca_payload_from_parsed(&cose, i)?;
        claims.push(claim);
    }
    verify_predecessor_chain(&claims)?;
    Ok(chain)
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
