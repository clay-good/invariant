//! Fuzz target: arbitrary bytes → Command JSON deserialization.
//!
//! Exercises serde_json's parsing of Command structs with arbitrary input.
//! The validator's first line of defense is rejecting malformed JSON before
//! it reaches any physics or authority checks.  This target ensures that
//! no byte sequence causes a panic, stack overflow, or infinite loop in
//! the deserialization path.

#![no_main]

use libfuzzer_sys::fuzz_target;

use invariant_core::models::command::Command;

fuzz_target!(|data: &[u8]| {
    // Reject extremely large inputs early (mirrors the real pipeline's 4 KB limit).
    if data.len() > 8192 {
        return;
    }

    // Attempt to deserialize as a Command.  We don't care whether it
    // succeeds or fails — we care that it doesn't panic or hang.
    let _ = serde_json::from_slice::<Command>(data);
});
