//! Audit log entry types — re-exported from `invariant-core` with concrete
//! input/verdict types bound for the robotics domain.
//!
//! The hash-chain + signed-entry shape lives in
//! [`invariant_core::models::audit`]; this module only fixes the generic
//! parameters to robotics's [`Command`] and [`SignedVerdict`] so callers can
//! continue to write `AuditEntry { ... }` literals and access fields without
//! ever seeing the generics.
//!
//! # Examples
//!
//! ```
//! use std::collections::HashMap;
//! use invariant_robotics::models::audit::AuditEntry;
//! use invariant_robotics::models::command::{Command, CommandAuthority, JointState};
//! use invariant_robotics::models::verdict::{SignedVerdict, Verdict, CheckResult, AuthoritySummary};
//! use invariant_robotics::models::authority::Operation;
//!
//! let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
//!     .unwrap()
//!     .with_timezone(&chrono::Utc);
//!
//! let cmd = Command {
//!     timestamp: ts,
//!     source: "motion_planner".into(),
//!     sequence: 5,
//!     joint_states: vec![JointState { name: "shoulder_pan".into(), position: 0.5, velocity: 0.1, effort: 10.0 }],
//!     delta_time: 0.02,
//!     end_effector_positions: vec![],
//!     center_of_mass: None,
//!     authority: CommandAuthority {
//!         pca_chain: "chain".into(),
//!         required_ops: vec![Operation::new("actuate:arm:*").unwrap()],
//!     },
//!     metadata: HashMap::new(),
//!     locomotion_state: None,
//!     end_effector_forces: vec![],
//!     estimated_payload_kg: None,
//!     signed_sensor_readings: vec![],
//!     zone_overrides: HashMap::new(),
//!     environment_state: None,
//! };
//!
//! let verdict = SignedVerdict {
//!     verdict: Verdict {
//!         approved: true,
//!         command_hash: "sha256:cmd_hash".into(),
//!         command_sequence: 5,
//!         timestamp: ts,
//!         checks: vec![CheckResult::new("velocity", "physics", true, "ok")],
//!         profile_name: "ur10e".into(),
//!         profile_hash: "sha256:profile".into(),
//!         authority_summary: AuthoritySummary {
//!             origin_principal: "op@example.com".into(),
//!             hop_count: 1,
//!             operations_granted: vec!["actuate:arm:*".into()],
//!             operations_required: vec!["actuate:arm:*".into()],
//!         },
//!         threat_analysis: None,
//!     },
//!     verdict_signature: "sig".into(),
//!     signer_kid: "kid".into(),
//! };
//!
//! let entry = AuditEntry {
//!     sequence: 5,
//!     previous_hash: "sha256:prev_hash".into(),
//!     command: cmd,
//!     verdict,
//!     entry_hash: "sha256:entry_hash".into(),
//!     schema_version: invariant_core::models::audit::CURRENT_SCHEMA_VERSION,
//!     session_id: String::new(),
//!     executor_id: String::new(),
//!     monotonic_nanos: 0,
//!     wall_clock_rfc3339: String::new(),
//! };
//!
//! assert_eq!(entry.sequence, 5);
//! assert!(entry.verdict.verdict.approved);
//! ```

use super::command::Command;
use super::verdict::SignedVerdict;

/// Robotics audit entry: stores the full [`Command`] plus the [`SignedVerdict`].
pub type AuditEntry = invariant_core::models::audit::AuditEntry<Command, SignedVerdict>;

/// Signed robotics audit entry — an [`AuditEntry`] plus an Ed25519 entry signature.
pub type SignedAuditEntry = invariant_core::models::audit::SignedAuditEntry<Command, SignedVerdict>;
