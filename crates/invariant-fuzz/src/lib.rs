//! Adversarial testing framework for the Invariant safety system.
//!
//! Provides structured fuzzing and attack simulation across four layers:
//!
//! - [`protocol`] — command-level attacks (boundary probing, numeric injection,
//!   authority forgery, schema manipulation, temporal replay)
//! - [`cognitive`] — cognitive escape strategies (CE1–CE10) that mimic an
//!   adversarial AI trying to subvert safety checks
//! - [`system`] — system-level attacks (resource exhaustion, filesystem,
//!   network, process, side-channel, timing)
//! - [`generators`] — random but valid test-data generators used by attacks
//!   and benchmarks
//!
//! # Quick Start
//!
//! ```rust
//! use invariant_robotics_fuzz::report::AdversarialReport;
//!
//! let mut report = AdversarialReport::new("boundary_probing");
//! report.record("BP-1", "joint at max + epsilon", "rejected", false);
//! assert!(report.all_detected());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cognitive;
pub mod generators;
pub mod protocol;
pub mod report;
pub mod system;
