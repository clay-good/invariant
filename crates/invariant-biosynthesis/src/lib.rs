//! Invariant — biosynthesis domain crate.
//!
//! Synthesis bundles, DNA/peptide/chemical/homology/molecule/protocol/stateful
//! invariants, hazard screening, and the biosynthesis validator pipeline.
//! Layered on top of [`invariant_core`].

#![forbid(unsafe_code)]

pub mod attestation;
pub mod audit;
pub mod bundle;
pub mod differential;
/// Bio-specific intent templates (overrides the robotics templates in
/// `invariant_core::intent`).
pub mod intent;
pub mod invariants;
pub mod models;
pub mod profiles;
pub mod screening;
pub mod threat;
pub mod validator;
pub mod watchdog;

// Re-export protocol modules from invariant-core so downstream code that
// imports `invariant_biosynthesis::authority` keeps working with one
// rename to `invariant_biosynthesis`. `intent` is intentionally NOT
// re-exported — bio has its own templates above.
pub use invariant_core::{authority, incident, keys, monitors, proof_package, replication, util};
