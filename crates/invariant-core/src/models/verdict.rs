use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub approved: bool,
    pub command_hash: String,
    pub command_sequence: u64,
    /// Typed timestamp for precise ordering and replay-prevention (P1-3).
    pub timestamp: DateTime<Utc>,
    pub checks: Vec<CheckResult>,
    pub profile_name: String,
    pub profile_hash: String,
    pub authority_summary: AuthoritySummary,
}

/// Result of a single named check (physical or authority). Usable as a `HashMap`
/// key and in `HashSet` for deduplication (P3-2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub category: String,
    pub passed: bool,
    pub details: String,
}

/// Summary of authority evaluation. Usable as a `HashMap` key (P3-2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthoritySummary {
    pub origin_principal: String,
    pub hop_count: usize,
    pub operations_granted: Vec<String>,
    pub operations_required: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedVerdict {
    #[serde(flatten)]
    pub verdict: Verdict,
    pub verdict_signature: String,
    pub signer_kid: String,
}
