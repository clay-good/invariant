// Ed25519 + COSE_Sign1 operations for PCA signing and verification.

use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Verifier};

use crate::models::authority::{Pca, SignedPca};
use crate::models::error::AuthorityError;

/// Empty AAD — we don't use additional authenticated data.
const AAD: &[u8] = b"";

/// Sign a PCA claim with Ed25519, producing a COSE_Sign1 envelope.
///
/// The protected header contains the algorithm (EdDSA) and the key id.
/// The payload is the canonical JSON-serialized PCA claim.
pub fn sign_pca(claim: &Pca, signing_key: &SigningKey) -> SignedPca {
    let payload = serde_json::to_vec(claim).expect("PCA serialization is infallible");

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

    let raw = cose.to_vec().expect("COSE serialization is infallible");

    SignedPca {
        raw,
        claim: claim.clone(),
    }
}

/// Verify the COSE_Sign1 signature on a `SignedPca` against the given public key.
///
/// Returns `Ok(())` if the signature is valid, or an `AuthorityError` describing
/// the failure.  `hop` is the zero-based index into the chain for error messages.
pub fn verify_signed_pca(
    signed: &SignedPca,
    verifying_key: &VerifyingKey,
    hop: usize,
) -> Result<(), AuthorityError> {
    let cose = CoseSign1::from_slice(&signed.raw).map_err(|e| {
        AuthorityError::CoseError {
            hop,
            reason: e.to_string(),
        }
    })?;

    cose.verify_signature(AAD, |sig, data| {
        let sig = Signature::from_slice(sig).map_err(|e| e.to_string())?;
        verifying_key
            .verify(data, &sig)
            .map_err(|e| e.to_string())
    })
    .map_err(|e| AuthorityError::SignatureInvalid {
        hop,
        reason: e.to_string(),
    })
}

/// Decode the payload of a COSE_Sign1 envelope back into a `Pca` claim.
///
/// This does NOT verify the signature — call `verify_signed_pca` first.
pub fn decode_pca_payload(raw: &[u8], hop: usize) -> Result<Pca, AuthorityError> {
    let cose = CoseSign1::from_slice(raw).map_err(|e| AuthorityError::CoseError {
        hop,
        reason: e.to_string(),
    })?;
    let payload = cose.payload.as_deref().ok_or_else(|| AuthorityError::CoseError {
        hop,
        reason: "missing payload".into(),
    })?;
    serde_json::from_slice(payload).map_err(|e| AuthorityError::CoseError {
        hop,
        reason: format!("payload deserialization failed: {e}"),
    })
}

/// Generate a new Ed25519 keypair from the provided RNG.
pub fn generate_keypair<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> SigningKey {
    SigningKey::generate(rng)
}
