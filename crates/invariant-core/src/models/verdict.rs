use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub approved: bool,
    pub command_hash: String,
    pub command_sequence: u64,
    pub timestamp: String,
    pub checks: Vec<CheckResult>,
    pub profile_name: String,
    pub profile_hash: String,
    pub authority_summary: AuthoritySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub category: String,
    pub passed: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthoritySummary {
    pub origin_principal: String,
    pub hop_count: usize,
    pub operations_granted: Vec<String>,
    pub operations_required: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVerdict {
    #[serde(flatten)]
    pub verdict: Verdict,
    pub verdict_signature: String,
    pub signer_kid: String,
}
