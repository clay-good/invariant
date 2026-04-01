// Multi-robot coordination safety monitor (Step 39).
//
// When multiple robots share a workspace (e.g., two UR10e cobots tending
// adjacent CNC machines, or a humanoid fleet in a warehouse), individual
// Invariant instances validate each robot's commands against its own profile.
// But they cannot detect cross-robot hazards:
//
// - Robot A's gripper is about to collide with Robot B's arm
// - Robot A and B both enter the same exclusion zone simultaneously
// - Robot A's workspace overlaps with Robot B's during a task change
//
// The CoordinationMonitor sits above individual Invariant instances and adds
// cross-robot safety checks. It receives periodic state updates from each
// robot and produces CoordinationVerdicts.
//
// Design principles:
// - Stateful: tracks each robot's last-known position + velocity.
// - Deterministic: no I/O, no randomness. Pure geometry.
// - Fail-closed: if a robot's state is stale (no update within timeout),
//   it is treated as unsafe and all commands near it are rejected.
// - Does NOT replace individual Invariant instances — it augments them.

pub mod monitor;
pub mod partition;

pub use monitor::{
    CoordinationMonitor, CoordinationVerdict, CrossRobotCheck, RobotState, StaleRobotPolicy,
};
pub use partition::{WorkspacePartition, WorkspacePartitionConfig};
