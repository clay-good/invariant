//! Fuzz target: arbitrary bytes → PCA chain verification.
//!
//! Exercises the full PCA chain parsing and Ed25519 verification path with
//! random input.  The chain is first base64-decoded, then JSON-parsed as
//! `Vec<SignedPca>`, then verified via `verify_chain`.  This target ensures
//! no byte sequence causes a panic in the authority verification pipeline.

#![no_main]

use libfuzzer_sys::fuzz_target;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use invariant_core::authority::chain::verify_chain;
use invariant_core::models::authority::SignedPca;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16384 {
        return;
    }

    // Strategy 1: Treat raw bytes as a base64-encoded PCA chain (mimics real input).
    if let Ok(decoded) = STANDARD.decode(data) {
        if let Ok(hops) = serde_json::from_slice::<Vec<SignedPca>>(&decoded) {
            // Build a dummy trusted-keys map.  The fuzzer won't know the
            // right key, so verification will almost always fail on the
            // crypto check — but we want to ensure no panic on the way there.
            let sk = SigningKey::from_bytes(&[0x42; 32]);
            let mut trusted = HashMap::new();
            trusted.insert("fuzz-kid".to_string(), sk.verifying_key());

            let _ = verify_chain(&hops, &trusted, Utc::now());
        }
    }

    // Strategy 2: Treat raw bytes directly as JSON (skipping base64).
    if let Ok(hops) = serde_json::from_slice::<Vec<SignedPca>>(data) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let mut trusted = HashMap::new();
        trusted.insert("fuzz-kid".to_string(), sk.verifying_key());

        let _ = verify_chain(&hops, &trusted, Utc::now());
    }
});
