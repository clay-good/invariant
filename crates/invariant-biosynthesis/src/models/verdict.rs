use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A safety decision produced by the validator for a single synthesis bundle.
///
/// # Examples
///
/// ```
/// use invariant_biosynthesis::models::verdict::{Verdict, CheckResult, AuthoritySummary};
///
/// let verdict = Verdict {
///     approved: true,
///     command_hash: "sha256:abcdef1234567890".into(),
///     command_sequence: 42,
///     timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
///         .unwrap()
///         .with_timezone(&chrono::Utc),
///     checks: vec![
///         CheckResult::new("dna_screening", "invariant", true, "no hazardous motifs"),
///         CheckResult::new("authority", "authority", true, "PCA chain valid"),
///     ],
///     profile_name: "university_bsl2_dna".into(),
///     profile_hash: "sha256:profile_hash_here".into(),
///     authority_summary: AuthoritySummary {
///         origin_principal: "pi@example.edu".into(),
///         hop_count: 1,
///         operations_granted: vec!["synthesize:dna:*".into()],
///         operations_required: vec!["synthesize:dna:fragment".into()],
///     },
///     threat_analysis: None,
/// };
///
/// assert!(verdict.approved);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// Whether the bundle was approved (true) or rejected (false).
    pub approved: bool,
    /// SHA-256 hash of the canonical bundle JSON (for tamper detection).
    /// Named `command_hash` for audit-schema compatibility.
    pub command_hash: String,
    /// Monotonic sequence number copied from the bundle.
    pub command_sequence: u64,
    /// Typed timestamp for precise ordering and replay-prevention.
    pub timestamp: DateTime<Utc>,
    /// Results of all individual safety checks (invariants + authority).
    pub checks: Vec<CheckResult>,
    /// Name of the bio profile used for validation.
    pub profile_name: String,
    /// SHA-256 hash of the bio profile JSON used for validation.
    pub profile_hash: String,
    /// Summary of the authority chain evaluation.
    pub authority_summary: AuthoritySummary,
    /// Continuous adversarial monitoring scores.
    /// Present in Guardian mode when behavioral analysis is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_analysis: Option<ThreatAnalysis>,
}

/// Behavioral threat scoring for continuous adversarial monitoring.
///
/// Each score is in [0.0, 1.0] where 0.0 = no threat detected and 1.0 = maximum threat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatAnalysis {
    /// Bundles consistently near rejection thresholds.
    pub boundary_clustering_score: f64,
    /// Repeated requests with slightly different operation scopes.
    pub authority_probing_score: f64,
    /// Similarity to previously-rejected bundles.
    pub replay_similarity_score: f64,
    /// Gradual shift in request patterns indicating slow escalation.
    pub drift_score: f64,
    /// Technically valid but statistically unusual requests.
    pub anomaly_score: f64,
    /// Weighted composite of all individual scores.
    pub composite_threat_score: f64,
    /// Whether the composite score exceeds the configured alert threshold.
    pub alert: bool,
}

/// Result of a single named check.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckResult {
    /// Name of the check (e.g. "dna_screening", "authority").
    pub name: String,
    /// Category of the check (e.g. "invariant", "authority", "safety").
    pub category: String,
    /// Whether this check passed.
    pub passed: bool,
    /// Human-readable details explaining the pass or fail reason.
    pub details: String,
    /// Advisory derating recommendation from environmental checks.
    ///
    /// When a sensor value is between the warning threshold and the absolute
    /// limit, the check PASSES but recommends reducing operational scale by
    /// this factor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derating: Option<DeratingAdvice>,
}

impl CheckResult {
    /// Create a CheckResult with no derating advice (the common case).
    pub fn new(
        name: impl Into<String>,
        category: impl Into<String>,
        passed: bool,
        details: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            category: category.into(),
            passed,
            details: details.into(),
            derating: None,
        }
    }
}

/// Advisory recommendation to reduce operational limits.
///
/// This does NOT cause rejection — the request still passes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeratingAdvice {
    /// Recommended velocity / throughput scale factor in (0.0, 1.0].
    pub velocity_scale: f64,
    /// Recommended intensity scale factor in (0.0, 1.0].
    pub intensity_scale: f64,
    /// Human-readable reason for the derating.
    pub reason: String,
}

impl Eq for DeratingAdvice {}
impl std::hash::Hash for DeratingAdvice {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.reason.hash(state);
    }
}

/// Summary of authority evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthoritySummary {
    /// Identity of the root principal (PCA_0 `p_0` field).
    pub origin_principal: String,
    /// Number of delegation hops in the chain.
    pub hop_count: usize,
    /// Operations granted by the final link in the chain.
    pub operations_granted: Vec<String>,
    /// Operations claimed as required by the bundle.
    pub operations_required: Vec<String>,
}

/// A [`Verdict`] paired with a cryptographic signature from the validator key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedVerdict {
    #[serde(flatten)]
    /// The unsigned verdict payload.
    pub verdict: Verdict,
    /// Base64-encoded Ed25519 signature over the canonical verdict JSON.
    pub verdict_signature: String,
    /// Key identifier of the validator signing key.
    pub signer_kid: String,
}
