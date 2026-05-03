//! Simulation harness for the Invariant safety system.
//!
//! Provides campaign orchestration, scenario generation, fault injection,
//! and dry-run execution for testing robot safety invariants at scale.
//! Includes an Isaac Lab Unix-socket bridge for hardware-in-the-loop
//! simulation.
//!
//! # Quick Start
//!
//! ```rust
//! use invariant_robotics_sim::campaign::load_config;
//!
//! let yaml = r#"
//! name: smoke-test
//! profile: ur10
//! environments: 1
//! episodes_per_env: 1
//! steps_per_episode: 10
//! scenarios:
//!   - scenario_type: baseline
//!     weight: 1.0
//! "#;
//! let config = load_config(yaml).unwrap();
//! assert_eq!(config.name, "smoke-test");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Campaign configuration loader and data types.
pub mod campaign;
/// Result collector for per-command verdicts.
pub mod collector;
/// Per-episode data outputs: signed verdict chain, seed, and trace bundle.
pub mod episode;
/// Fault injection engine for generating adversarial commands.
pub mod injector;
/// Isaac Lab Unix-socket bridge and dry-run orchestrator.
pub mod isaac;
/// High-level campaign orchestrator (async runtime wrapper).
pub mod orchestrator;
/// Campaign result aggregation and SIL-rated reporting.
pub mod reporter;
/// Scenario type definitions and command generators.
pub mod scenario;
