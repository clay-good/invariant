#![allow(dead_code)]

pub mod models;
pub mod physics;
/// PIC chain validation logic (chain.rs, operations.rs, crypto.rs).
///
/// Re-exports the `models::authority` data types so that
/// `invariant_core::authority::Pca` works without ambiguity (P1-5).
pub mod authority;
pub mod validator;
pub mod actuator;
pub mod audit;
pub mod watchdog;
pub mod profiles;
