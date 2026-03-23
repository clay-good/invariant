use serde::{Deserialize, Serialize};

use super::{command::Command, verdict::Verdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub previous_hash: String,
    pub command: Command,
    pub verdict: Verdict,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuditEntry {
    #[serde(flatten)]
    pub entry: AuditEntry,
    pub entry_signature: String,
    pub signer_kid: String,
}
