//! Generic audit log entry types.
//!
//! Hoisted from the per-domain `audit.rs` modules in Phase 1b. The hash-chain
//! and signed-entry shapes are substrate-agnostic; the only thing the entry
//! parameterizes over is the input type `I` (e.g. `Command`,
//! `SynthesisBundle`) and the verdict type `V` (e.g. each domain's
//! `SignedVerdict`). Domain crates re-export these with concrete type
//! aliases so callers do not see the generics.

use serde::{Deserialize, Serialize};

/// Legacy unversioned audit record format. Records written before the
/// `schema_version` field was introduced (v12 N-4) deserialize as this version
/// because the field defaults to `1` when absent.
pub const SCHEMA_VERSION_V1: u32 = 1;

/// First explicitly-versioned audit record format. Adds the
/// `schema_version` field to the on-disk JSONL. Once v11 1.1 (B1–B4 binding
/// fields) and v11 1.2 (predecessor digest) land they ship under this same
/// schema version unless a further bump is required.
pub const SCHEMA_VERSION_V2: u32 = 2;

/// Schema version that new audit entries are written with.
pub const CURRENT_SCHEMA_VERSION: u32 = SCHEMA_VERSION_V2;

/// Default value when deserializing a record that omits `schema_version`.
/// The pre-v12 on-disk format had no such field, so missing → `1`.
pub fn default_schema_version() -> u32 {
    SCHEMA_VERSION_V1
}

/// `serde` skip-predicate: omit `schema_version` from the serialized JSON when
/// the value is `1` so that legacy v1 records round-trip byte-for-byte (and
/// their stored `entry_hash` still verifies against the recomputed hash).
pub fn schema_version_is_v1(v: &u32) -> bool {
    *v == SCHEMA_VERSION_V1
}

/// `serde` skip-predicate: omit a `u64` field from the serialized JSON when
/// the value is zero. Used to keep B1–B4 binding fields (v11 1.1) absent from
/// records produced by call sites that have not yet been migrated to supply
/// a `BindingContext`, so existing entry-hash preimages stay byte-identical.
pub fn u64_is_zero(v: &u64) -> bool {
    *v == 0
}

/// Execution-binding context (spec.md §3.3 B1–B4). When non-empty, these
/// fields are serialized into the `AuditEntry` (and become part of the entry
/// hash preimage), cryptographically binding each record to its session,
/// executor, monotonic-clock reading, and wall-clock timestamp.
///
/// `Default` produces the empty context — entries written against the empty
/// context omit the B1–B4 fields entirely (via `skip_serializing_if`), which
/// preserves byte-for-byte compatibility with pre-v11-1.1 on-disk records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BindingContext {
    /// B1 — opaque session identifier (e.g. a UUID). Must remain constant for
    /// the lifetime of a single validator process; new sessions get new IDs.
    pub session_id: String,
    /// B2 — identifier of the executor that produced the input. Per-executor
    /// monotonicity (B3) is enforced against this string.
    pub executor_id: String,
    /// B3 — monotonic-clock nanoseconds. Strictly non-decreasing per
    /// `executor_id`. Drives the `AuditError::ClockRegression` check.
    pub monotonic_nanos: u64,
    /// B4 — wall-clock timestamp as RFC 3339 (informational; the binding
    /// integrity check uses B3, not this field).
    pub wall_clock_rfc3339: String,
}

impl BindingContext {
    /// Returns true when no binding fields are set. The default-constructed
    /// context returns true; legacy call sites use this to opt out of B1–B4
    /// serialization and per-executor clock checks.
    pub fn is_empty(&self) -> bool {
        self.session_id.is_empty()
            && self.executor_id.is_empty()
            && self.monotonic_nanos == 0
            && self.wall_clock_rfc3339.is_empty()
    }
}

/// An audit log entry. Stores the full input and the *signed* verdict so
/// that the cryptographic link between the decision and the signed proof is
/// preserved (L1, L3).
///
/// The input field is serialized under the legacy key `command` for on-disk
/// JSONL compatibility — both domains write entries in the same schema.
///
/// `schema_version` discriminates the on-disk record format. Records written
/// before v12 N-4 have no such field and deserialize as version `1`; new
/// records write `2`. Re-serialization skips the field when its value is `1`
/// so legacy entry hashes verify unchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry<I, V> {
    /// Monotonically increasing entry number starting at 0.
    pub sequence: u64,
    /// SHA-256 hex digest of the previous entry, or empty string for the genesis entry.
    pub previous_hash: String,
    /// The input that was submitted for validation.
    #[serde(rename = "command")]
    pub command: I,
    /// Signed verdict, not the bare verdict, to maintain L3 authenticity.
    pub verdict: V,
    /// SHA-256 hex digest of this entry's canonical JSON (with `entry_hash` set to `""`).
    pub entry_hash: String,
    /// On-disk record-format version. Missing on-disk field → `1` (legacy).
    #[serde(
        default = "default_schema_version",
        skip_serializing_if = "schema_version_is_v1"
    )]
    pub schema_version: u32,
    /// B1 — opaque session identifier (spec.md §3.3). Empty when the writer
    /// did not configure a [`BindingContext`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    /// B2 — executor identifier. Empty when unset.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub executor_id: String,
    /// B3 — monotonic-clock nanoseconds at the moment the entry was logged.
    /// Zero when unset.
    #[serde(default, skip_serializing_if = "u64_is_zero")]
    pub monotonic_nanos: u64,
    /// B4 — wall-clock timestamp (RFC 3339). Empty when unset.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wall_clock_rfc3339: String,
}

/// An [`AuditEntry`] paired with an Ed25519 signature for tamper detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedAuditEntry<I, V> {
    /// The audit entry body (flattened into the enclosing JSON object).
    #[serde(flatten)]
    pub entry: AuditEntry<I, V>,
    /// Base64-encoded Ed25519 signature over the canonical JSON of `entry`.
    pub entry_signature: String,
    /// Key identifier of the key used to produce `entry_signature`.
    pub signer_kid: String,
}
