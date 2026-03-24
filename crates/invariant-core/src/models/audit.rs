use serde::{Deserialize, Serialize};

use super::{command::Command, verdict::SignedVerdict};

/// An audit log entry. Stores the full command and the *signed* verdict so
/// that the cryptographic link between the decision and the signed proof is
/// preserved (L1, L3) (P1-4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub previous_hash: String,
    pub command: Command,
    /// Stores the signed verdict, not the bare verdict, to maintain L3 authenticity.
    pub verdict: SignedVerdict,
    pub entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedAuditEntry {
    #[serde(flatten)]
    pub entry: AuditEntry,
    pub entry_signature: String,
    pub signer_kid: String,
}
