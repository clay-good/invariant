use serde::{Deserialize, Serialize};

use super::{command::Command, verdict::SignedVerdict};

/// An audit log entry. Stores the full command and the *signed* verdict so
/// that the cryptographic link between the decision and the signed proof is
/// preserved (L1, L3) (P1-4).
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use invariant_robotics_core::models::audit::AuditEntry;
/// use invariant_robotics_core::models::command::{Command, CommandAuthority, JointState};
/// use invariant_robotics_core::models::verdict::{SignedVerdict, Verdict, CheckResult, AuthoritySummary};
/// use invariant_robotics_core::models::authority::Operation;
///
/// let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
///     .unwrap()
///     .with_timezone(&chrono::Utc);
///
/// let cmd = Command {
///     timestamp: ts,
///     source: "motion_planner".into(),
///     sequence: 5,
///     joint_states: vec![JointState { name: "shoulder_pan".into(), position: 0.5, velocity: 0.1, effort: 10.0 }],
///     delta_time: 0.02,
///     end_effector_positions: vec![],
///     center_of_mass: None,
///     authority: CommandAuthority {
///         pca_chain: "chain".into(),
///         required_ops: vec![Operation::new("actuate:arm:*").unwrap()],
///     },
///     metadata: HashMap::new(),
///     locomotion_state: None,
///     end_effector_forces: vec![],
///     estimated_payload_kg: None,
///     signed_sensor_readings: vec![],
///     zone_overrides: HashMap::new(),
///     environment_state: None,
/// };
///
/// let verdict = SignedVerdict {
///     verdict: Verdict {
///         approved: true,
///         command_hash: "sha256:cmd_hash".into(),
///         command_sequence: 5,
///         timestamp: ts,
///         checks: vec![CheckResult::new("velocity", "physics", true, "ok")],
///         profile_name: "ur10e".into(),
///         profile_hash: "sha256:profile".into(),
///         authority_summary: AuthoritySummary {
///             origin_principal: "op@example.com".into(),
///             hop_count: 1,
///             operations_granted: vec!["actuate:arm:*".into()],
///             operations_required: vec!["actuate:arm:*".into()],
///         },
///         threat_analysis: None,
///     },
///     verdict_signature: "sig".into(),
///     signer_kid: "kid".into(),
/// };
///
/// let entry = AuditEntry {
///     sequence: 5,
///     previous_hash: "sha256:prev_hash".into(),
///     command: cmd,
///     verdict,
///     entry_hash: "sha256:entry_hash".into(),
/// };
///
/// assert_eq!(entry.sequence, 5);
/// assert!(entry.verdict.verdict.approved);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing entry number starting at 0.
    pub sequence: u64,
    /// SHA-256 hex digest of the previous entry, or empty string for the genesis entry.
    pub previous_hash: String,
    /// The command that was submitted for validation.
    pub command: Command,
    /// Stores the signed verdict, not the bare verdict, to maintain L3 authenticity.
    pub verdict: SignedVerdict,
    /// SHA-256 hex digest of this entry's canonical JSON (with `entry_hash` set to `""`).
    pub entry_hash: String,
}

/// An [`AuditEntry`] paired with an Ed25519 signature for tamper detection.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use invariant_robotics_core::models::audit::{AuditEntry, SignedAuditEntry};
/// use invariant_robotics_core::models::command::{Command, CommandAuthority, JointState};
/// use invariant_robotics_core::models::verdict::{SignedVerdict, Verdict, CheckResult, AuthoritySummary};
/// use invariant_robotics_core::models::authority::Operation;
///
/// let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
///     .unwrap()
///     .with_timezone(&chrono::Utc);
///
/// let entry = AuditEntry {
///     sequence: 1,
///     previous_hash: "sha256:genesis".into(),
///     command: Command {
///         timestamp: ts,
///         source: "sim".into(),
///         sequence: 1,
///         joint_states: vec![],
///         delta_time: 0.02,
///         end_effector_positions: vec![],
///         center_of_mass: None,
///         authority: CommandAuthority {
///             pca_chain: "chain".into(),
///             required_ops: vec![Operation::new("actuate:arm:*").unwrap()],
///         },
///         metadata: HashMap::new(),
///         locomotion_state: None,
///         end_effector_forces: vec![],
///         estimated_payload_kg: None,
///         signed_sensor_readings: vec![],
///         zone_overrides: HashMap::new(),
///         environment_state: None,
///     },
///     verdict: SignedVerdict {
///         verdict: Verdict {
///             approved: false,
///             command_hash: "sha256:cmd".into(),
///             command_sequence: 1,
///             timestamp: ts,
///             checks: vec![CheckResult::new("workspace", "physics", false, "out of bounds")],
///             profile_name: "ur10e".into(),
///             profile_hash: "sha256:p".into(),
///             authority_summary: AuthoritySummary {
///                 origin_principal: "op@example.com".into(),
///                 hop_count: 1,
///                 operations_granted: vec!["actuate:arm:*".into()],
///                 operations_required: vec!["actuate:arm:*".into()],
///             },
///             threat_analysis: None,
///         },
///         verdict_signature: "sig".into(),
///         signer_kid: "kid".into(),
///     },
///     entry_hash: "sha256:entry".into(),
/// };
///
/// let signed = SignedAuditEntry {
///     entry,
///     entry_signature: "entry-sig-base64".into(),
///     signer_kid: "audit-key-001".into(),
/// };
///
/// assert_eq!(signed.signer_kid, "audit-key-001");
/// assert!(!signed.entry.verdict.verdict.approved);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedAuditEntry {
    /// The audit entry body (flattened into the enclosing JSON object).
    #[serde(flatten)]
    pub entry: AuditEntry,
    /// Base64-encoded Ed25519 signature over the canonical JSON of `entry`.
    pub entry_signature: String,
    /// Key identifier of the key used to produce `entry_signature`.
    pub signer_kid: String,
}
