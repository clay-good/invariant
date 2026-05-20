//! System-level adversarial tests (SA1–SA15).
//!
//! These tests verify that a compromised cognitive layer cannot circumvent,
//! disable, modify, or subvert the Invariant process.
//!
//! Tests are split into two categories:
//! - **In-process tests**: Run as normal `cargo test` — exercise defenses that
//!   can be verified without OS-level privileges (SA4, SA6, SA8, SA9, SA13, SA14, SA15).
//! - **Container-only tests**: Marked `#[ignore]` — require a dedicated
//!   containerized environment with root (SA1-SA3, SA5, SA7, SA10-SA12).
//!   Un-ignore in CI with `cargo test -- --ignored`.

pub mod degraded;
pub mod filesystem;
pub mod network;
pub mod process;
pub mod resource;
pub mod side_channel;
pub mod time;
