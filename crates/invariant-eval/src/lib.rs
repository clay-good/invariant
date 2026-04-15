//! Trace evaluation engine for the Invariant safety system.
//!
//! Provides preset safety/completeness/regression checks, custom rubrics,
//! guardrail rules, and step-by-step trace diffing. Used by
//! `invariant eval` and `invariant diff` CLI commands.
//!
//! # Presets
//!
//! ```rust
//! use invariant_robotics_eval::presets::list_presets;
//!
//! let presets = list_presets();
//! assert!(presets.contains(&"safety-check"));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Step-by-step trace diffing with divergence detection.
pub mod differ;
/// Policy-based guardrail engine for check filtering.
pub mod guardrails;
/// Built-in eval presets: safety-check, completeness-check, regression-check.
pub mod presets;
/// Custom YAML/JSON rubric loader and evaluator.
pub mod rubric;
