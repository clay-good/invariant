//! Fuzz target: arbitrary bytes → bridge line handler.
//!
//! The Isaac Lab bridge reads newline-framed JSON over a Unix socket. After
//! four bridge security commits (bounded reads, framing limits, parser
//! hardening) we lock in the parse path with a fuzzer: take arbitrary
//! bytes, split on `\n` to simulate framed input, and feed each line to
//! the bridge's sync handler. Assert no panic, no unbounded allocation.
//!
//! The handler lives in `invariant_sim::robotics::isaac::bridge` as
//! `fuzz_bridge_handle_multiline` — a synchronous, panic-free counterpart
//! to the async `handle_message` that exercises the JSON layer and the
//! untagged-enum dispatch without touching the validator.
//!
//! v12-N-12.

#![no_main]

use libfuzzer_sys::fuzz_target;

use invariant_sim::robotics::isaac::bridge::{
    fuzz_bridge_handle_multiline, FUZZ_BRIDGE_MAX_LINE_BYTES,
};

fuzz_target!(|data: &[u8]| {
    // Reject inputs larger than 1 MiB up front. cargo-fuzz tends to grow
    // inputs over time; this matches the real bridge's per-connection
    // buffer ceiling and keeps RSS predictable on long fuzz runs.
    if data.len() > 1024 * 1024 {
        return;
    }

    let results = fuzz_bridge_handle_multiline(data);

    // Invariant 1: the handler always produces one result per `\n`-split
    // line. `bytes.split(b'\n')` yields N+1 items for N newlines (or 1
    // for empty input), so this is a tight bound, not a sanity-check.
    let expected = data.split(|&b| b == b'\n').count();
    assert_eq!(results.len(), expected);

    // Invariant 2: any line strictly longer than the bounded-read limit
    // must produce the `Oversize` variant. This guards against the
    // bounded-read invariant regressing without notice — the real bridge
    // enforces the same limit at the I/O layer.
    for line in data.split(|&b| b == b'\n') {
        if line.len() > FUZZ_BRIDGE_MAX_LINE_BYTES {
            let kind = invariant_sim::robotics::isaac::bridge::fuzz_bridge_handle_line(line)
                .expect("oversize lines short-circuit before UTF-8 decoding");
            assert!(
                matches!(
                    kind,
                    invariant_sim::robotics::isaac::bridge::FuzzBridgeFrameKind::Oversize
                ),
                "line of {} bytes must classify as Oversize",
                line.len()
            );
        }
    }
});
