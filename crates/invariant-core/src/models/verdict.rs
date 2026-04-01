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
    /// Continuous adversarial monitoring scores (Section 11.3).
    /// Present in Guardian mode when behavioral analysis is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_analysis: Option<ThreatAnalysis>,
}

/// Behavioral threat scoring for continuous adversarial monitoring (Section 11.3).
///
/// Each score is in [0.0, 1.0] where 0.0 = no threat detected and 1.0 = maximum threat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatAnalysis {
    /// Commands consistently near rejection thresholds.
    pub boundary_clustering_score: f64,
    /// Repeated requests with slightly different operation scopes.
    pub authority_probing_score: f64,
    /// Similarity to previously-rejected commands.
    pub replay_similarity_score: f64,
    /// Gradual shift in command patterns indicating slow escalation.
    pub drift_score: f64,
    /// Technically valid but statistically unusual commands.
    pub anomaly_score: f64,
    /// Weighted composite of all individual scores.
    pub composite_threat_score: f64,
    /// Whether the composite score exceeds the configured alert threshold.
    pub alert: bool,
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
