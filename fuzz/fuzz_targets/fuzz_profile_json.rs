//! Fuzz target: arbitrary bytes → RobotProfile JSON deserialization + validation.
//!
//! Exercises the profile loading and validation pipeline.  Malformed profiles
//! must be rejected without panicking or hanging.

#![no_main]

use libfuzzer_sys::fuzz_target;

use invariant_core::models::error::Validate;
use invariant_core::models::profile::RobotProfile;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }

    // Attempt to deserialize as a RobotProfile.
    if let Ok(profile) = serde_json::from_slice::<RobotProfile>(data) {
        // If parsing succeeds, also run validation — this exercises the
        // Validate impl that checks joint limits, workspace bounds, etc.
        let _ = profile.validate();
    }
});
