#![allow(dead_code)]

pub mod actuator;
pub mod audit;
/// PIC chain validation logic (chain.rs, operations.rs, crypto.rs).
///
/// Re-exports the `models::authority` data types so that
/// `invariant_core::authority::Pca` works without ambiguity (P1-5).
pub mod authority;
pub mod models;
pub mod physics;
pub mod profiles;
pub mod util;
pub mod validator;
pub mod watchdog;
