// Workspace partitioning for multi-robot cells.
//
// Divides a shared workspace into non-overlapping partitions, one per robot.
// Each robot is restricted to its own partition. This provides a static
// guarantee that robots cannot collide, without needing real-time separation
// checks.
//
// Partitioning is the preferred approach when robots have predictable,
// non-overlapping work zones (e.g., two cobots tending adjacent CNC machines).
// Dynamic separation checks (in monitor.rs) are for robots that share
// overlapping work zones.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PartitionError {
    #[error("partition {name:?} overlaps with {other:?}")]
    Overlap { name: String, other: String },

    #[error(
        "point [{x:.3}, {y:.3}, {z:.3}] is outside partition {partition:?} for robot {robot_id:?}"
    )]
    OutsidePartition {
        robot_id: String,
        partition: String,
        x: f64,
        y: f64,
        z: f64,
    },

    #[error("robot {robot_id:?} has no assigned partition")]
    NoPartition { robot_id: String },
}

// ---------------------------------------------------------------------------
// Partition definition
// ---------------------------------------------------------------------------

/// An axis-aligned bounding box partition of the workspace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspacePartition {
    /// Human-readable name for this partition (e.g. "cell-1-zone").
    pub name: String,
    /// The robot assigned to this partition.
    pub robot_id: String,
    /// Minimum corner [x, y, z] in world frame.
    pub min: [f64; 3],
    /// Maximum corner [x, y, z] in world frame.
    pub max: [f64; 3],
}

impl WorkspacePartition {
    /// Check whether a 3D point is inside this partition (inclusive bounds).
    pub fn contains(&self, point: &[f64; 3]) -> bool {
        point[0] >= self.min[0]
            && point[0] <= self.max[0]
            && point[1] >= self.min[1]
            && point[1] <= self.max[1]
            && point[2] >= self.min[2]
            && point[2] <= self.max[2]
    }

    /// Check whether this partition overlaps with another.
    fn overlaps(&self, other: &WorkspacePartition) -> bool {
        // Two AABBs overlap iff they overlap on all three axes.
        self.min[0] < other.max[0]
            && self.max[0] > other.min[0]
            && self.min[1] < other.max[1]
            && self.max[1] > other.min[1]
            && self.min[2] < other.max[2]
            && self.max[2] > other.min[2]
    }
}

// ---------------------------------------------------------------------------
// Partition config
// ---------------------------------------------------------------------------

/// A set of workspace partitions for a multi-robot cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePartitionConfig {
    partitions: Vec<WorkspacePartition>,
}

impl WorkspacePartitionConfig {
    /// Create a new partition config. Validates that no partitions overlap.
    pub fn new(partitions: Vec<WorkspacePartition>) -> Result<Self, PartitionError> {
        // Check all pairs for overlap.
        for i in 0..partitions.len() {
            for j in (i + 1)..partitions.len() {
                if partitions[i].overlaps(&partitions[j]) {
                    return Err(PartitionError::Overlap {
                        name: partitions[i].name.clone(),
                        other: partitions[j].name.clone(),
                    });
                }
            }
        }
        Ok(Self { partitions })
    }

    /// Check whether a robot's end-effector position is within its assigned
    /// partition.
    pub fn check_position(&self, robot_id: &str, point: &[f64; 3]) -> Result<(), PartitionError> {
        let partition = self
            .partitions
            .iter()
            .find(|p| p.robot_id == robot_id)
            .ok_or_else(|| PartitionError::NoPartition {
                robot_id: robot_id.into(),
            })?;

        if partition.contains(point) {
            Ok(())
        } else {
            Err(PartitionError::OutsidePartition {
                robot_id: robot_id.into(),
                partition: partition.name.clone(),
                x: point[0],
                y: point[1],
                z: point[2],
            })
        }
    }

    /// Check all end-effector positions for a robot.
    pub fn check_all_positions(
        &self,
        robot_id: &str,
        positions: &[[f64; 3]],
    ) -> Result<(), PartitionError> {
        for pos in positions {
            self.check_position(robot_id, pos)?;
        }
        Ok(())
    }

    /// Get the partition assigned to a robot, if any.
    pub fn get_partition(&self, robot_id: &str) -> Option<&WorkspacePartition> {
        self.partitions.iter().find(|p| p.robot_id == robot_id)
    }

    /// Number of partitions.
    pub fn len(&self) -> usize {
        self.partitions.len()
    }

    /// Whether the partition set is empty.
    pub fn is_empty(&self) -> bool {
        self.partitions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn partition(name: &str, robot: &str, min: [f64; 3], max: [f64; 3]) -> WorkspacePartition {
        WorkspacePartition {
            name: name.into(),
            robot_id: robot.into(),
            min,
            max,
        }
    }

    #[test]
    fn non_overlapping_partitions_accepted() {
        let config = WorkspacePartitionConfig::new(vec![
            partition("cell-1", "r1", [0.0, 0.0, 0.0], [2.0, 2.0, 2.0]),
            partition("cell-2", "r2", [3.0, 0.0, 0.0], [5.0, 2.0, 2.0]),
        ]);
        assert!(config.is_ok());
        assert_eq!(config.unwrap().len(), 2);
    }

    #[test]
    fn overlapping_partitions_rejected() {
        let result = WorkspacePartitionConfig::new(vec![
            partition("cell-1", "r1", [0.0, 0.0, 0.0], [2.0, 2.0, 2.0]),
            partition("cell-2", "r2", [1.0, 0.0, 0.0], [3.0, 2.0, 2.0]),
        ]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("overlaps"));
    }

    #[test]
    fn touching_partitions_not_overlapping() {
        // Partitions that share a face (edge-touching) do NOT overlap.
        let config = WorkspacePartitionConfig::new(vec![
            partition("cell-1", "r1", [0.0, 0.0, 0.0], [2.0, 2.0, 2.0]),
            partition("cell-2", "r2", [2.0, 0.0, 0.0], [4.0, 2.0, 2.0]),
        ]);
        assert!(config.is_ok());
    }

    #[test]
    fn point_inside_partition() {
        let config = WorkspacePartitionConfig::new(vec![partition(
            "cell-1",
            "r1",
            [0.0, 0.0, 0.0],
            [2.0, 2.0, 2.0],
        )])
        .unwrap();

        assert!(config.check_position("r1", &[1.0, 1.0, 1.0]).is_ok());
    }

    #[test]
    fn point_outside_partition() {
        let config = WorkspacePartitionConfig::new(vec![partition(
            "cell-1",
            "r1",
            [0.0, 0.0, 0.0],
            [2.0, 2.0, 2.0],
        )])
        .unwrap();

        let result = config.check_position("r1", &[3.0, 1.0, 1.0]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("outside partition"));
    }

    #[test]
    fn point_on_boundary_is_inside() {
        let config = WorkspacePartitionConfig::new(vec![partition(
            "cell-1",
            "r1",
            [0.0, 0.0, 0.0],
            [2.0, 2.0, 2.0],
        )])
        .unwrap();

        // Points on the boundary are inside (inclusive).
        assert!(config.check_position("r1", &[0.0, 0.0, 0.0]).is_ok());
        assert!(config.check_position("r1", &[2.0, 2.0, 2.0]).is_ok());
    }

    #[test]
    fn unknown_robot_returns_no_partition() {
        let config = WorkspacePartitionConfig::new(vec![partition(
            "cell-1",
            "r1",
            [0.0, 0.0, 0.0],
            [2.0, 2.0, 2.0],
        )])
        .unwrap();

        let result = config.check_position("r_unknown", &[1.0, 1.0, 1.0]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no assigned partition"));
    }

    #[test]
    fn check_all_positions_all_inside() {
        let config = WorkspacePartitionConfig::new(vec![partition(
            "cell-1",
            "r1",
            [0.0, 0.0, 0.0],
            [5.0, 5.0, 5.0],
        )])
        .unwrap();

        let positions = [[1.0, 1.0, 1.0], [2.0, 2.0, 2.0], [3.0, 3.0, 3.0]];
        assert!(config.check_all_positions("r1", &positions).is_ok());
    }

    #[test]
    fn check_all_positions_one_outside() {
        let config = WorkspacePartitionConfig::new(vec![partition(
            "cell-1",
            "r1",
            [0.0, 0.0, 0.0],
            [2.0, 2.0, 2.0],
        )])
        .unwrap();

        let positions = [[1.0, 1.0, 1.0], [5.0, 5.0, 5.0]];
        assert!(config.check_all_positions("r1", &positions).is_err());
    }

    #[test]
    fn get_partition_returns_correct() {
        let config = WorkspacePartitionConfig::new(vec![
            partition("cell-1", "r1", [0.0, 0.0, 0.0], [2.0, 2.0, 2.0]),
            partition("cell-2", "r2", [3.0, 0.0, 0.0], [5.0, 2.0, 2.0]),
        ])
        .unwrap();

        assert_eq!(config.get_partition("r1").unwrap().name, "cell-1");
        assert_eq!(config.get_partition("r2").unwrap().name, "cell-2");
        assert!(config.get_partition("r3").is_none());
    }

    #[test]
    fn empty_partitions_accepted() {
        let config = WorkspacePartitionConfig::new(vec![]);
        assert!(config.is_ok());
        assert!(config.unwrap().is_empty());
    }

    #[test]
    fn three_partitions_no_overlap() {
        let config = WorkspacePartitionConfig::new(vec![
            partition("cell-1", "r1", [0.0, 0.0, 0.0], [2.0, 4.0, 3.0]),
            partition("cell-2", "r2", [2.5, 0.0, 0.0], [4.5, 4.0, 3.0]),
            partition("cell-3", "r3", [5.0, 0.0, 0.0], [7.0, 4.0, 3.0]),
        ]);
        assert!(config.is_ok());
        assert_eq!(config.unwrap().len(), 3);
    }
}
