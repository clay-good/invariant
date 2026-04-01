//! Fuzz target: arbitrary bytes → full validation pipeline.
//!
//! This is the most important fuzz target.  It exercises the complete
//! Command → ValidatorConfig::validate path including:
//! - JSON deserialization
//! - Input sanitization (NaN/Inf/subnormal rejection)
//! - Authority chain verification (PCA decode + Ed25519 verify)
//! - All 20 physics checks (P1-P20)
//! - Verdict signing
//!
//! The fuzzer uses a fixed profile (franka_panda) and a fixed keypair so
//! that the coverage-guided engine can explore deeply into the validation
//! logic rather than being stopped at the JSON parsing boundary.

#![no_main]

use libfuzzer_sys::fuzz_target;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use invariant_core::models::command::Command;
use invariant_core::validator::ValidatorConfig;
use std::collections::HashMap;

/// Build a validator config once.  `cargo-fuzz` calls the fuzz target
/// in a tight loop — we want to avoid re-loading the profile every time.
///
/// Uses `std::sync::LazyLock` (stable since Rust 1.80) to initialize once.
static VALIDATOR: std::sync::LazyLock<ValidatorConfig> = std::sync::LazyLock::new(|| {
    let profile_name = invariant_core::profiles::list_builtins()[0];
    let profile = invariant_core::profiles::load_builtin(profile_name).unwrap();

    let sk = SigningKey::from_bytes(&[0x42; 32]);
    let vk = sk.verifying_key();
    let kid = "fuzz-kid".to_string();

    let mut trusted = HashMap::new();
    trusted.insert(kid.clone(), vk);

    ValidatorConfig::new(profile, trusted, sk, kid).unwrap()
});

fuzz_target!(|data: &[u8]| {
    // Cap input size to match the real pipeline's limits.
    if data.len() > 8192 {
        return;
    }

    // Parse the fuzz input as a Command.
    let command: Command = match serde_json::from_slice(data) {
        Ok(cmd) => cmd,
        Err(_) => return, // Malformed JSON — not interesting for this target.
    };

    // Run the full validation pipeline.  We don't care about the result —
    // we care that it doesn't panic, hang, or corrupt memory.
    let _ = VALIDATOR.validate(&command, Utc::now(), None);
});
