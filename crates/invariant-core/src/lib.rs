#![allow(dead_code)]

pub mod actuator;
pub mod audit;
/// PIC chain validation logic (chain.rs, operations.rs, crypto.rs).
///
/// Re-exports the `models::authority` data types so that
/// `invariant_core::authority::Pca` works without ambiguity (P1-5).
pub mod authority;
/// CNC tending cycle state machine (Step 67).
pub mod cycle;
/// Differential validation: dual-instance verdict comparison (Step 37).
pub mod differential;
/// Real-time digital twin divergence detection (Section 18.3).
pub mod digital_twin;
/// Built-in standard task envelopes (Section 17.3, Step 76).
pub mod envelopes;
/// Incident response automation (Section 10.6, Step 36).
pub mod incident;
/// Intent-to-operations pipeline (Section 15, Step 53).
pub mod intent;
/// Key file management and abstract key storage (Step 32).
pub mod keys;
pub mod models;
/// Runtime integrity monitors (Section 10.5, Step 34).
pub mod monitors;
pub mod physics;
pub mod profiles;
/// Proof package generation (Section 20, Step 70).
pub mod proof_package;
/// Audit log replication and Merkle root witness (Section 10.4, Step 35).
pub mod replication;
/// Signed sensor data for zero-trust sensor integrity (Step 64).
pub mod sensor;
/// Runtime threat scoring engine (Section 11.3, Step 68).
pub mod threat;
/// URDF parser and forward kinematics solver for zero-trust self-collision.
pub mod urdf;
pub mod util;
pub mod validator;
pub mod watchdog;
