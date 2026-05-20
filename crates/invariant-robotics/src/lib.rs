//! Invariant — robotics domain crate.
//!
//! Robot motion commands, physics checks (P1–P25), URDF kinematics, sensor
//! attestation, safety profiles, and the robotics validator pipeline. Layered
//! on top of the domain-agnostic [`invariant_core`] crate which provides the
//! PIC/PCA chain, audit log primitives, key management, and the
//! `ValidationInput` trait.

#![forbid(unsafe_code)]

pub mod actuator;
pub mod audit;
pub mod cycle;
pub mod differential;
pub mod digital_twin;
pub mod envelopes;
pub mod models;
pub mod physics;
pub mod profiles;
pub mod sensor;
pub mod threat;
pub mod urdf;
pub mod validator;
pub mod watchdog;

// Re-export the protocol-level modules from invariant-core under their
// historical names so downstream code (CLI, sim, eval, fuzz) that imports
// from `invariant_robotics::authority` etc. keeps working with a
// single rename to `invariant_robotics`.
pub use invariant_core::{
    authority, incident, intent, keys, monitors, proof_package, replication, util,
};
