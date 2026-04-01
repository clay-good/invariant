#![allow(dead_code)]

pub mod actuator;
pub mod audit;
/// PIC chain validation logic (chain.rs, operations.rs, crypto.rs).
///
/// Re-exports the `models::authority` data types so that
/// `invariant_core::authority::Pca` works without ambiguity (P1-5).
pub mod authority;
/// Incident response automation (Section 10.6, Step 36).
pub mod incident;
/// Key file management and abstract key storage (Step 32).
pub mod keys;
pub mod models;
/// Runtime integrity monitors (Section 10.5, Step 34).
pub mod monitors;
pub mod physics;
pub mod profiles;
/// Audit log replication and Merkle root witness (Section 10.4, Step 35).
pub mod replication;
pub mod util;
pub mod validator;
pub mod watchdog;
