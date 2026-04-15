//! Core safety engine for the Invariant command-validation firewall.
//!
//! This crate contains all safety-critical logic: 25 physics checks (P1–P25),
//! the PIC authority chain verifier, Ed25519 cryptographic signing, the
//! validator pipeline, audit logger, watchdog, differential validation,
//! threat scoring, sensor attestation, and robot profile management.
//!
//! # Architecture
//!
//! The central entry point is [`validator::ValidatorConfig`], which takes a
//! [`models::command::Command`] and produces a [`models::verdict::SignedVerdict`].
//! Every check is deterministic, fail-closed, and produces a signed audit trail.
//!
//! # Quick Start
//!
//! ```rust
//! use invariant_robotics_core::profiles;
//!
//! // Load a built-in robot profile
//! let profile = profiles::load_builtin("ur10").unwrap();
//! assert_eq!(profile.joints.len(), 6);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Signed actuation command generator for approved commands.
pub mod actuator;
/// Append-only signed JSONL audit logger with hash-chain integrity.
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
/// Core data models: command, verdict, audit, profile, trace, authority, actuation.
pub mod models;
/// Runtime integrity monitors (Section 10.5, Step 34).
pub mod monitors;
/// Physics safety checks (P1–P25).
pub mod physics;
/// Built-in robot profile library embedded at compile time.
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
/// Miscellaneous utilities (SHA-256, etc.).
pub mod util;
/// Validator pipeline: authority + physics -> signed verdict.
pub mod validator;
/// Heartbeat monitor and safe-stop trigger (W1 invariant).
pub mod watchdog;
