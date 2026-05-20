//! Fuzz target: arbitrary bytes → COSE_Sign1 envelope parser.
//!
//! v11 2.11 N-07 (COSE-CBOR wire format). Feeds raw bytes directly to a
//! single-hop `Vec<SignedPca>` and invokes `verify_chain`, exercising the
//! `parse_cose` → `extract_kid_from_parsed` → `decode_pca_payload_from_parsed`
//! → `verify_signed_pca_parsed` path on un-base64-wrapped CBOR. Where
//! `fuzz_pca_chain` exercises the *outer* JSON-array-of-SignedPca framing,
//! this target exercises just the *inner* COSE_Sign1 CBOR encoding.
//!
//! The fuzzer won't have the right signing key, so signature verification
//! will almost always fail — the goal is to ensure no byte sequence panics
//! the CBOR decoder, the protected-header parser, the kid extractor, the
//! JSON payload decoder, or the Ed25519 path.

#![no_main]

use libfuzzer_sys::fuzz_target;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use invariant_robotics::authority::chain::verify_chain;
use invariant_robotics::models::authority::SignedPca;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Bound the input so libFuzzer doesn't get bogged down on multi-MiB
    // garbage that the workspace's `MAX_HOPS = 16` would short-circuit
    // anyway.
    if data.len() > 16384 {
        return;
    }

    // Wrap the raw bytes as a single-hop chain and feed it to verify_chain.
    // This is the tightest path through `parse_cose` →
    // `extract_kid_from_parsed` → `decode_pca_payload_from_parsed` →
    // `verify_signed_pca_parsed` that we can stress without re-exposing
    // crate-private helpers.
    let hops = vec![SignedPca { raw: data.to_vec() }];
    let sk = SigningKey::from_bytes(&[0x42; 32]);
    let mut trusted = HashMap::new();
    trusted.insert("fuzz-kid".to_string(), sk.verifying_key());

    let _ = verify_chain(&hops, &trusted, Utc::now());
});
