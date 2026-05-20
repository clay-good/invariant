//! V10-17 — synthesizer-side verdict signature self-verification round-trip.
//!
//! This test stands in for the (still-absent) synthesizer-platform adapter:
//! the eventual adapter will load a serialized `SignedVerdict` off disk,
//! reconstruct the canonical JSON of the verdict body the same way the
//! validator did, and verify the Ed25519 signature against the firewall's
//! published verifying key. Until that adapter lands, this integration test
//! is the regression guard.
//!
//! Two assertions:
//!   * a clean round-trip (validator signs → write JSON → load JSON →
//!     reconstruct canonical preimage → `verify_strict`) succeeds.
//!   * mutating a single byte of the loaded verdict body causes the
//!     reconstructed preimage to change and `verify_strict` to reject.
//!
//! The reconstruction must match `validator.rs::validate`'s preimage exactly
//! (sha256-hex of `serde_json::to_vec(&verdict)`, signed bytes are the hex
//! ASCII). If the validator ever switches preimage shape, this test fails
//! loudly — exactly the regression we want.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use invariant_biosynthesis::models::bundle::{
    BundleAuthority, SynthesisBundle, SynthesisPayload,
};
use invariant_biosynthesis::models::profile::BioProfile;
use invariant_biosynthesis::models::verdict::{SignedVerdict, Verdict};
use invariant_biosynthesis::validator::ValidatorConfig;

/// 32-byte deterministic seed — gives a stable signing key across runs so
/// failures are reproducible. Treat as test-only; never use a fixed seed in
/// production code.
const SEED: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

fn make_profile() -> BioProfile {
    BioProfile {
        name: "v10_17_test".into(),
        version: "0.1.0".into(),
        bsl_level: 2,
        allowed_substrates: vec!["dna".into()],
        max_synthesis_volume_ml: 5.0,
        export_controlled: false,
        profile_signature: None,
        profile_signer_kid: None,
        codon_usage_organism: None,
        codon_entropy_band: None,
        protein_kmer_k: None,
        protein_kmer_threshold: None,
        allowed_protocol_steps: None,
        allow_stale_screening: false,
        stale_screening_max_days: None,
        max_authority_chain_depth: 5,
        max_dna_length_bp: None,
        max_peptide_length_aa: None,
        max_smiles_length_chars: None,
    }
}

fn make_bundle() -> SynthesisBundle {
    SynthesisBundle {
        timestamp: Utc::now(),
        source: "v10_17_test".into(),
        sequence: 1,
        payload: SynthesisPayload::Dna {
            sequence: "ATGCGT".into(),
        },
        delta_time: 0.0,
        authority: BundleAuthority {
            pca_chain: String::new(),
            required_ops: vec![],
        },
        metadata: Default::default(),
    }
}

/// Reconstruct the canonical preimage exactly the way `validator.rs::validate`
/// does: it calls `sha256_hex_json(&verdict)`, which returns a
/// `"sha256:<hex>"` string, then signs/verifies the ASCII bytes of that
/// string. The leading `sha256:` prefix is part of the preimage — dropping
/// it would invalidate every signature.
fn canonical_preimage(verdict: &Verdict) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let canon = serde_json::to_vec(verdict).expect("verdict serializes");
    let mut hasher = Sha256::new();
    hasher.update(&canon);
    let digest = hasher.finalize();
    let mut tagged = String::with_capacity(7 + 64);
    tagged.push_str("sha256:");
    for byte in digest {
        tagged.push_str(&format!("{byte:02x}"));
    }
    tagged.into_bytes()
}

fn verify_signed(signed: &SignedVerdict, vk: &VerifyingKey) -> Result<(), String> {
    let preimage = canonical_preimage(&signed.verdict);
    let sig_bytes = STANDARD
        .decode(&signed.verdict_signature)
        .map_err(|e| format!("base64: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| format!("sig parse: {e}"))?;
    vk.verify_strict(&preimage, &sig)
        .map_err(|e| format!("verify: {e}"))
}

#[test]
fn signed_verdict_round_trips_through_disk_and_verifies() {
    let sk = SigningKey::from_bytes(&SEED);
    let vk = sk.verifying_key();

    let cfg = ValidatorConfig::new(
        make_profile(),
        HashMap::new(),
        sk,
        "v10_17_validator".into(),
    )
    .expect("validator config");
    let out = cfg
        .validate(&make_bundle(), Utc::now(), None)
        .expect("validation");

    // Sanity: the in-memory signature already verifies against the matching
    // pubkey before any disk I/O happens.
    verify_signed(&out.signed_verdict, &vk).expect("in-memory verdict must verify");

    // Write the signed verdict to a temp file as a synthesizer would.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("verdict.json");
    let payload = serde_json::to_vec(&out.signed_verdict).expect("serialize");
    std::fs::write(&path, &payload).expect("write");

    // Load it back with no shared state and verify.
    let on_disk = std::fs::read(&path).expect("read");
    let parsed: SignedVerdict = serde_json::from_slice(&on_disk).expect("parse");
    verify_signed(&parsed, &vk).expect("on-disk verdict must verify against firewall pubkey");
}

#[test]
fn mutating_loaded_verdict_body_invalidates_signature() {
    let sk = SigningKey::from_bytes(&SEED);
    let vk = sk.verifying_key();

    let cfg = ValidatorConfig::new(
        make_profile(),
        HashMap::new(),
        sk,
        "v10_17_validator".into(),
    )
    .expect("validator config");
    let out = cfg
        .validate(&make_bundle(), Utc::now(), None)
        .expect("validation");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("verdict.json");
    std::fs::write(&path, serde_json::to_vec(&out.signed_verdict).expect("serialize"))
        .expect("write");

    let mut parsed: SignedVerdict =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");

    // Mutate one bit of the verdict body — flip `approved` if it was set, or
    // bump the `command_sequence` otherwise. Either change rewrites the
    // canonical preimage and must invalidate the signature.
    parsed.verdict.command_sequence = parsed.verdict.command_sequence.wrapping_add(1);

    let err = verify_signed(&parsed, &vk).expect_err("mutated verdict must NOT verify");
    assert!(
        err.contains("verify"),
        "expected signature-verification error, got: {err}"
    );
}
