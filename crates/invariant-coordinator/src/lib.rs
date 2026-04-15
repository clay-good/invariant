//! Multi-robot coordination safety monitor.
//!
//! When multiple robots share a workspace, individual Invariant instances
//! validate each robot's commands against its own profile but cannot detect
//! cross-robot hazards (collisions, overlapping exclusion zones, workspace
//! conflicts).
//!
//! The [`CoordinationMonitor`] sits above individual Invariant instances and
//! adds cross-robot safety checks. It receives periodic state updates from
//! each robot and produces [`CoordinationVerdict`]s.
//!
//! # Design
//!
//! - **Stateful**: tracks each robot's last-known position and velocity.
//! - **Deterministic**: no I/O, no randomness — pure geometry.
//! - **Fail-closed**: stale robot state is treated as unsafe.
//! - **Additive**: does not replace individual Invariant instances.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Cross-robot coordination monitor with separation and stale-state checks.
pub mod monitor;
/// Workspace partitioning for static non-overlapping robot zones.
pub mod partition;

pub use monitor::{
    CoordinationMonitor, CoordinationVerdict, CrossRobotCheck, RobotState, StaleRobotPolicy,
};
pub use partition::{WorkspacePartition, WorkspacePartitionConfig};
