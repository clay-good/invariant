//! Core safety engine for the Invariant PIC/PCA protocol — domain-agnostic.
//!
//! Domain crates (`invariant-robotics`, `invariant-biosynthesis`) implement
//! the [`traits::ValidationInput`] / [`traits::DomainCheck`] /
//! [`traits::DomainProfile`] traits and plug into the generic
//! [`validator::Validator`] pipeline.
//!
//! # Architecture
//!
//! See `INVARIANT_UNIFICATION_SPEC.md` Section 2 for the trait design
//! rationale.

#![forbid(unsafe_code)]

/// Append-only signed JSONL audit logger (generic over input/verdict types).
pub mod audit;
/// PIC chain validation logic (chain.rs, operations.rs, crypto.rs).
pub mod authority;
/// Differential validation comparison logic (generic over a `VerdictView` trait).
pub mod differential;
/// Incident response automation (Section 10.6).
pub mod incident;
/// Intent-to-operations pipeline (Section 15).
pub mod intent;
/// Key file management and abstract key storage.
pub mod keys;
/// RFC 6962 Merkle tree (leaf/inner hash, streaming accumulator, audit-path
/// inclusion proofs). Backs the audit-log root and the proof-package
/// `merkle_root.txt` artifact.
pub mod merkle;
/// Core data models: authority, audit, error.
pub mod models;
/// Runtime integrity monitors (Section 10.5).
pub mod monitors;
/// Generic profile loading trait.
pub mod profiles;
/// Proof package generation (Section 20).
pub mod proof_package;
/// Audit log replication and Merkle root witness (Section 10.4).
pub mod replication;
/// Domain abstraction traits — the keystone of the unified design.
pub mod traits;
/// Miscellaneous utilities (SHA-256, etc.).
pub mod util;
/// Generic validator pipeline (skeleton; full envelope/audit wiring lands in Phase 1b).
pub mod validator;

pub use traits::{CheckContext, CheckResult, DomainCheck, DomainProfile, ValidationInput};
pub use validator::{NamedCheckResult, ValidationVerdict, Validator};
