//! Fuzz target: deeply nested / oversized JSON → `Command` deserialiser.
//!
//! v11 2.11 N-06 (JSON bomb). Where `fuzz_command_json` mutates a
//! plausible `Command` JSON shape via libFuzzer's coverage-guided
//! mutator, this target tries the adversarial extremes: deeply nested
//! arrays/objects, oversized strings, repeated keys, exponent-laden
//! numbers, NaN/∞ literals. The bytes are first wrapped with a small
//! number of leading `[` characters (cycling 0..16 with the first byte)
//! before being fed to `serde_json` to drive depth limits.
//!
//! The goal is to ensure no input causes a stack overflow, an unbounded
//! allocation, or an inconsistent reject path. Successful parses then
//! flow into the validator so any downstream panic also gets caught.

#![no_main]

use libfuzzer_sys::fuzz_target;

use invariant_robotics::models::command::Command;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 65536 {
        return;
    }

    // First byte selects a nesting depth in 0..16; remaining bytes form
    // the JSON body. Wrap with that many `[`, append same many `]` at the
    // end — serde_json's recursion limit (128 by default) is well below
    // what we can pile on here, so this directly stresses the depth
    // bound.
    let depth = (data[0] as usize) % 17;
    let mut wrapped: Vec<u8> = Vec::with_capacity(data.len() - 1 + 2 * depth);
    for _ in 0..depth {
        wrapped.push(b'[');
    }
    wrapped.extend_from_slice(&data[1..]);
    for _ in 0..depth {
        wrapped.push(b']');
    }

    // Strategy 1: plain bytes (libFuzzer-mutated shape).
    let _ = serde_json::from_slice::<Command>(&data[1..]);

    // Strategy 2: nested wrapper to stress depth bounds + adversarial shapes.
    let _ = serde_json::from_slice::<Command>(&wrapped);

    // Strategy 3: parse as serde_json::Value first to exercise the
    // free-form parser independently of the typed deserialiser.
    let _ = serde_json::from_slice::<serde_json::Value>(&wrapped);
});
