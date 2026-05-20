//! Core data models for the biosynthesis firewall.

/// Audit log entry types.
pub mod audit;
/// Synthesis bundle (the bio analog of a motion command).
pub mod bundle;
/// Bio-firewall ValidationError taxonomy (distinct from robotics; kept local).
pub mod error;
/// Signed execution token produced for approved bundles.
pub mod execution_token;
/// Bio profile schema.
pub mod profile;
/// Safety verdict types.
pub mod verdict;

// Re-export the shared authority data types from invariant-core.
pub use invariant_core::models::authority;
