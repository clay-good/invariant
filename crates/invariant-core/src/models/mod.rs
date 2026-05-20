//! Core data models — domain-agnostic.
//!
//! Robotics-specific models (`command`, `profile`, `verdict`, `trace`, `actuation`)
//! live in the `invariant-robotics` crate.

/// Generic audit log entry types: `AuditEntry<I, V>`, `SignedAuditEntry<I, V>`.
pub mod audit;
/// PIC authority chain data types: `Pca`, `SignedPca`, `Operation`, `AuthorityChain`.
pub mod authority;
/// Validation error types and the `Validate` trait.
pub mod error;
