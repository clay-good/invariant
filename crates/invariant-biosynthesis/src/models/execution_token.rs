//! Execution token — the signed "go" token a synthesis platform verifies
//! before executing a synthesis bundle. Replaces `models/actuation.rs` from
//! the sibling robotics project.
//!
//! The cryptographic shape is identical: a bundle hash, a verdict reference,
//! and an Ed25519 signature over the canonical bytes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An Ed25519-signed token permitting a synthesis platform to execute a bundle.
///
/// The payload semantics are filled in at Step 3 once platform integration
/// contracts are drafted; for now the token only carries the bundle hash,
/// verdict reference, and signature envelope so downstream crates can
/// type-check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionToken {
    /// SHA-256 hash of the bundle that this token authorizes.
    pub bundle_hash: String,
    /// SHA-256 hash of the signed verdict that approved the bundle.
    pub verdict_hash: String,
    /// Issuance timestamp.
    pub issued_at: DateTime<Utc>,
    /// Monotonic sequence number from the approving verdict.
    pub sequence: u64,
    /// Base64-encoded Ed25519 signature over the canonical JSON of this token
    /// (with `signature` set to the empty string during signing).
    pub signature: String,
    /// Key identifier of the issuing validator.
    pub signer_kid: String,
}
