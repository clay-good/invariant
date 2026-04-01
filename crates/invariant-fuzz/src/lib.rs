//! Adversarial testing framework for Invariant.
//!
//! Provides structured fuzzing and attack simulation for the Invariant
//! robotics safety system. Attack classes are organised by the layer they
//! target:
//!
//! - `protocol` — command-level attacks (boundary probing, numeric injection)
//! - `generators` — random but valid test-data generators used by attacks and
//!   benchmarks

pub mod cognitive;
pub mod generators;
pub mod protocol;
pub mod report;
pub mod system;
