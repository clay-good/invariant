//! Cognitive escape testing (CE1–CE10).
//!
//! Simulates a worst-case adversarial cognitive layer that actively tries
//! to bypass the Invariant firewall using multi-step strategies.
//!
//! Each CE class is a deterministic attack generator that produces a
//! sequence of commands implementing a specific escape strategy.  The
//! validator must reject every unauthorized command with 0 escapes.
//!
//! An adaptive LLM mode (where a real language model generates novel
//! strategies) can be layered on top by driving the same validator with
//! LLM-generated commands.  The structured CE1-CE10 tests form the
//! baseline that any adaptive mode must also pass.

#[allow(clippy::cloned_ref_to_slice_refs)]
pub mod escape;
