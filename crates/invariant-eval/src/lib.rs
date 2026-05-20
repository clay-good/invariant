//! Unified trace evaluation engine — split per domain.
//!
//! - [`robotics`]: presets, guardrails, rubric loader, trace differ for
//!   robotics motion-command traces.
//! - [`biosynthesis`]: preset rubric set for biosynthesis-bundle traces.

#![forbid(unsafe_code)]

pub mod biosynthesis;
pub mod robotics;
