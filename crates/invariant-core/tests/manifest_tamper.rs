//! Tamper detection for signed proof-package manifests (v11 1.4).
//!
//! Sign a manifest, then flip one byte in (a) a file_hash entry, (b) the
//! merkle_root, (c) the signature itself. Each case must cause
//! `verify_manifest` to return `ProofPackageError::SignatureInvalid`.

use std::collections::HashMap;

use chrono::TimeZone;
use ed25519_dalek::{SigningKey, VerifyingKey};
use invariant_core::proof_package::{
    sign_manifest, verify_manifest, CampaignSummary, ProofPackageError, ProofPackageManifest,
    CURRENT_FORMAT_VERSION,
};

fn deterministic_keypair() -> (SigningKey, VerifyingKey) {
    // Deterministic key — test is reproducible across CI runs.
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn fixture_manifest() -> ProofPackageManifest {
    let mut file_hashes = HashMap::new();
    file_hashes.insert(
        "results/audit.jsonl".into(),
        "0011223344556677889900112233445566778899001122334455667788990011".into(),
    );
    file_hashes.insert(
        "campaign/profile.json".into(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
    );

    ProofPackageManifest {
        format_version: CURRENT_FORMAT_VERSION,
        version: "1.0.0".into(),
        generated_at: chrono::Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
        campaign_name: "tamper_test".into(),
        profile_name: "ur10e".into(),
        profile_hash: "sha256:profile".into(),
        binary_hash: "sha256:binary".into(),
        invariant_version: "0.2.0".into(),
        summary: CampaignSummary::compute(1000, 990, 10, 0, 100, 0, 100.0),
        file_hashes,
        merkle_root: Some(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        ),
        manifest_signature: None,
        manifest_signer_kid: None,
    }
}

#[test]
fn signed_manifest_round_trips() {
    let (sk, vk) = deterministic_keypair();
    let mut manifest = fixture_manifest();
    sign_manifest(&mut manifest, &sk, "fixture-kid".into()).expect("sign");
    assert!(manifest.manifest_signature.is_some());
    assert_eq!(manifest.manifest_signer_kid.as_deref(), Some("fixture-kid"));
    verify_manifest(&manifest, &vk).expect("verify round-trip");
}

#[test]
fn flipping_byte_in_file_hash_invalidates_signature() {
    let (sk, vk) = deterministic_keypair();
    let mut manifest = fixture_manifest();
    sign_manifest(&mut manifest, &sk, "fixture-kid".into()).expect("sign");

    // Mutate one byte of one file_hash entry.
    let hash = manifest
        .file_hashes
        .get_mut("results/audit.jsonl")
        .expect("entry present");
    let mut bytes = hash.clone().into_bytes();
    bytes[0] ^= 0x01;
    *hash = String::from_utf8(bytes).expect("utf-8");

    let err = verify_manifest(&manifest, &vk).expect_err("must fail");
    assert!(matches!(err, ProofPackageError::SignatureInvalid { .. }));
}

#[test]
fn flipping_byte_in_merkle_root_invalidates_signature() {
    let (sk, vk) = deterministic_keypair();
    let mut manifest = fixture_manifest();
    sign_manifest(&mut manifest, &sk, "fixture-kid".into()).expect("sign");

    let mut root = manifest.merkle_root.clone().unwrap().into_bytes();
    root[0] = if root[0] == b'd' { b'e' } else { b'd' };
    manifest.merkle_root = Some(String::from_utf8(root).expect("utf-8"));

    let err = verify_manifest(&manifest, &vk).expect_err("must fail");
    assert!(matches!(err, ProofPackageError::SignatureInvalid { .. }));
}

#[test]
fn flipping_byte_in_signature_invalidates_verification() {
    let (sk, vk) = deterministic_keypair();
    let mut manifest = fixture_manifest();
    sign_manifest(&mut manifest, &sk, "fixture-kid".into()).expect("sign");

    let mut sig = manifest.manifest_signature.clone().unwrap().into_bytes();
    // Flip the first byte to something base64-valid but different. Many
    // base64 chars are valid, so just rotate within the alphabet.
    sig[0] = match sig[0] {
        b'A'..=b'Y' | b'a'..=b'y' | b'0'..=b'8' => sig[0] + 1,
        _ => b'A',
    };
    manifest.manifest_signature = Some(String::from_utf8(sig).expect("utf-8"));

    let err = verify_manifest(&manifest, &vk).expect_err("must fail");
    assert!(matches!(err, ProofPackageError::SignatureInvalid { .. }));
}

#[test]
fn missing_signature_field_is_rejected() {
    let (_, vk) = deterministic_keypair();
    // Build a manifest with no signature attached and confirm verify_manifest
    // refuses it rather than e.g. defaulting to "accept unsigned".
    let manifest = fixture_manifest();
    let err = verify_manifest(&manifest, &vk).expect_err("must fail");
    assert!(matches!(err, ProofPackageError::SignatureInvalid { .. }));
}

#[test]
fn wrong_key_rejects_signature() {
    let (sk, _) = deterministic_keypair();
    let mut manifest = fixture_manifest();
    sign_manifest(&mut manifest, &sk, "fixture-kid".into()).expect("sign");

    // Verify with a different key.
    let other_sk = SigningKey::from_bytes(&[7u8; 32]);
    let other_vk = other_sk.verifying_key();
    let err = verify_manifest(&manifest, &other_vk).expect_err("must fail");
    assert!(matches!(err, ProofPackageError::SignatureInvalid { .. }));
}
