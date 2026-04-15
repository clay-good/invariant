// Ed25519 + COSE_Sign1 operations for PCA signing and verification.

use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::models::authority::{Pca, SignedPca};
use crate::models::error::AuthorityError;

/// Empty AAD — we don't use additional authenticated data.
const AAD: &[u8] = b"";

/// Sign a PCA claim with Ed25519, producing a COSE_Sign1 envelope.
///
/// The protected header contains the algorithm (EdDSA) and the key id.
/// The payload is the canonical JSON-serialized PCA claim.
pub fn sign_pca(claim: &Pca, signing_key: &SigningKey) -> Result<SignedPca, AuthorityError> {
    let payload = serde_json::to_vec(claim).map_err(|e| AuthorityError::SerializationError {
        reason: e.to_string(),
    })?;

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(claim.kid.as_bytes().to_vec())
        .build();

    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(AAD, |data| {
            use ed25519_dalek::Signer;
            signing_key.sign(data).to_bytes().to_vec()
        })
        .build();

    let raw = cose
        .to_vec()
        .map_err(|e| AuthorityError::SerializationError {
            reason: e.to_string(),
        })?;

    Ok(SignedPca { raw })
}

/// Parse a raw COSE_Sign1 envelope once, returning the parsed struct.
///
/// Centralises the single parse per hop so that `extract_kid_from_parsed`,
/// `verify_signed_pca_parsed`, and `decode_pca_payload_parsed` can all operate
/// on the same already-parsed value, avoiding redundant CBOR decoding.
pub(crate) fn parse_cose(raw: &[u8], hop: usize) -> Result<CoseSign1, AuthorityError> {
    CoseSign1::from_slice(raw).map_err(|e| AuthorityError::CoseError {
        hop,
        reason: e.to_string(),
    })
}

/// Verify the COSE_Sign1 signature on a `SignedPca` against the given public key.
///
/// Uses `verify_strict` to reject small-order and non-canonical points/signatures.
/// Returns `Ok(())` if the signature is valid, or an `AuthorityError` describing
/// the failure.  `hop` is the zero-based index into the chain for error messages.
///
/// Prefer `verify_signed_pca_parsed` when you have already parsed the COSE
/// struct via `parse_cose`.
pub fn verify_signed_pca(
    signed: &SignedPca,
    verifying_key: &VerifyingKey,
    hop: usize,
) -> Result<(), AuthorityError> {
    let cose = parse_cose(&signed.raw, hop)?;
    verify_signed_pca_parsed(&cose, verifying_key, hop)
}

/// Verify a pre-parsed COSE_Sign1 envelope, reusing an already-parsed struct.
pub(crate) fn verify_signed_pca_parsed(
    cose: &CoseSign1,
    verifying_key: &VerifyingKey,
    hop: usize,
) -> Result<(), AuthorityError> {
    cose.verify_signature(AAD, |sig, data| {
        let sig = Signature::from_slice(sig).map_err(|e| e.to_string())?;
        verifying_key
            .verify_strict(data, &sig)
            .map_err(|e| e.to_string())
    })
    .map_err(|e| AuthorityError::SignatureInvalid {
        hop,
        reason: e.to_string(),
    })
}

/// Extract the key ID from a pre-parsed COSE_Sign1 protected header.
///
/// Does NOT verify the signature — call [`verify_signed_pca_parsed`] for that.
pub(crate) fn extract_kid_from_parsed(
    cose: &CoseSign1,
    hop: usize,
) -> Result<String, AuthorityError> {
    let kid_bytes = &cose.protected.header.key_id;
    if kid_bytes.is_empty() {
        return Err(AuthorityError::CoseError {
            hop,
            reason: "missing key id in protected header".into(),
        });
    }
    String::from_utf8(kid_bytes.clone()).map_err(|e| AuthorityError::CoseError {
        hop,
        reason: format!("invalid key id encoding: {e}"),
    })
}

/// Decode the payload of a pre-parsed COSE_Sign1 envelope into a `Pca` claim.
///
/// Does NOT verify the signature — call [`verify_signed_pca_parsed`] first.
pub(crate) fn decode_pca_payload_from_parsed(
    cose: &CoseSign1,
    hop: usize,
) -> Result<Pca, AuthorityError> {
    let payload = cose
        .payload
        .as_deref()
        .ok_or_else(|| AuthorityError::CoseError {
            hop,
            reason: "missing payload".into(),
        })?;
    serde_json::from_slice(payload).map_err(|e| AuthorityError::CoseError {
        hop,
        reason: format!("payload deserialization failed: {e}"),
    })
}

/// Decode the payload of a COSE_Sign1 envelope back into a `Pca` claim.
///
/// This does NOT verify the signature — call `verify_signed_pca` first.
///
/// Prefer [`decode_pca_payload_from_parsed`] when you have already parsed the
/// COSE struct via [`parse_cose`].
#[allow(dead_code)] // Convenience wrapper kept for future callers; prefer decode_pca_payload_from_parsed.
pub(crate) fn decode_pca_payload(raw: &[u8], hop: usize) -> Result<Pca, AuthorityError> {
    let cose = parse_cose(raw, hop)?;
    decode_pca_payload_from_parsed(&cose, hop)
}

/// Generate a new Ed25519 keypair from the provided RNG.
pub fn generate_keypair<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> SigningKey {
    SigningKey::generate(rng)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::authority::Operation;
    use coset::{CoseSign1Builder, HeaderBuilder};
    use rand::rngs::OsRng;
    use std::collections::BTreeSet;

    fn gen_sk() -> SigningKey {
        generate_keypair(&mut OsRng)
    }

    fn make_pca(kid: &str) -> Pca {
        Pca {
            p_0: "test".into(),
            ops: {
                let mut s = BTreeSet::new();
                s.insert(Operation::new("actuate:*").unwrap());
                s
            },
            kid: kid.into(),
            exp: None,
            nbf: None,
        }
    }

    // ── Finding 45: missing payload branch in decode_pca_payload_from_parsed ──

    #[test]
    fn decode_pca_payload_from_parsed_missing_payload_returns_error() {
        // Build a COSE_Sign1 with no payload (payload set to None after creation).
        let sk = gen_sk();
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .key_id(b"test-kid".to_vec())
            .build();

        // Build with an empty payload, then manually clear it to None.
        let mut cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(b"placeholder".to_vec())
            .create_signature(AAD, |data| {
                use ed25519_dalek::Signer;
                sk.sign(data).to_bytes().to_vec()
            })
            .build();

        // Clear the payload after building to simulate a detached-payload envelope.
        cose.payload = None;

        let result = decode_pca_payload_from_parsed(&cose, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthorityError::CoseError { reason, .. } => {
                assert!(
                    reason.contains("missing payload"),
                    "expected 'missing payload' in reason, got: {reason}"
                );
            }
            other => panic!("expected CoseError, got {other:?}"),
        }
    }

    // ── Finding 46: non-UTF8 key_id in extract_kid_from_parsed ──────────────

    #[test]
    fn extract_kid_from_parsed_invalid_utf8_returns_error() {
        // Build a COSE_Sign1 whose protected header key_id contains invalid UTF-8.
        let sk = gen_sk();
        // 0xFF bytes are never valid in UTF-8.
        let invalid_utf8_kid = vec![0xFF, 0xFE, 0xFD];

        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .key_id(invalid_utf8_kid)
            .build();

        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(b"test".to_vec())
            .create_signature(AAD, |data| {
                use ed25519_dalek::Signer;
                sk.sign(data).to_bytes().to_vec()
            })
            .build();

        let result = extract_kid_from_parsed(&cose, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthorityError::CoseError { reason, .. } => {
                assert!(
                    reason.contains("invalid key id encoding"),
                    "expected 'invalid key id encoding' in reason, got: {reason}"
                );
            }
            other => panic!("expected CoseError, got {other:?}"),
        }
    }

    // ── Smoke test: sign_pca + verify_signed_pca roundtrip ───────────────────

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = gen_sk();
        let vk = sk.verifying_key();
        let claim = make_pca("k1");
        let signed = sign_pca(&claim, &sk).unwrap();
        assert!(verify_signed_pca(&signed, &vk, 0).is_ok());
    }

    #[test]
    fn decode_pca_payload_roundtrip() {
        let sk = gen_sk();
        let claim = make_pca("k2");
        let signed = sign_pca(&claim, &sk).unwrap();
        let decoded = decode_pca_payload(&signed.raw, 0).unwrap();
        assert_eq!(decoded.p_0, "test");
        assert_eq!(decoded.kid, "k2");
    }
}
