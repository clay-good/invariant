use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A safety decision produced by the validator for a single command.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::verdict::{Verdict, CheckResult, AuthoritySummary};
///
/// let verdict = Verdict {
///     approved: true,
///     command_hash: "sha256:abcdef1234567890".into(),
///     command_sequence: 42,
///     timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
///         .unwrap()
///         .with_timezone(&chrono::Utc),
///     checks: vec![
///         CheckResult::new("joint_limits", "physics", true, "all joints within bounds"),
///         CheckResult::new("workspace", "physics", true, "end-effector inside workspace"),
///     ],
///     profile_name: "ur10e".into(),
///     profile_hash: "sha256:profile_hash_here".into(),
///     authority_summary: AuthoritySummary {
///         origin_principal: "operator@example.com".into(),
///         hop_count: 1,
///         operations_granted: vec!["actuate:arm:*".into()],
///         operations_required: vec!["actuate:arm:joints".into()],
///     },
///     threat_analysis: None,
/// };
///
/// assert!(verdict.approved);
/// assert_eq!(verdict.checks.len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// Whether the command was approved (true) or rejected (false).
    pub approved: bool,
    /// SHA-256 hash of the canonical command JSON (for tamper detection).
    pub command_hash: String,
    /// Monotonic sequence number copied from the command.
    pub command_sequence: u64,
    /// Typed timestamp for precise ordering and replay-prevention (P1-3).
    pub timestamp: DateTime<Utc>,
    /// Results of all individual safety checks (physics + authority).
    pub checks: Vec<CheckResult>,
    /// Name of the robot profile used for validation.
    pub profile_name: String,
    /// SHA-256 hash of the robot profile JSON used for validation.
    pub profile_hash: String,
    /// Summary of the authority chain evaluation.
    pub authority_summary: AuthoritySummary,
    /// Continuous adversarial monitoring scores (Section 11.3).
    /// Present in Guardian mode when behavioral analysis is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_analysis: Option<ThreatAnalysis>,
}

/// Behavioral threat scoring for continuous adversarial monitoring (Section 11.3).
///
/// Each score is in [0.0, 1.0] where 0.0 = no threat detected and 1.0 = maximum threat.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::verdict::ThreatAnalysis;
///
/// let analysis = ThreatAnalysis {
///     boundary_clustering_score: 0.1,
///     authority_probing_score: 0.0,
///     replay_similarity_score: 0.05,
///     drift_score: 0.02,
///     anomaly_score: 0.08,
///     composite_threat_score: 0.05,
///     alert: false,
/// };
///
/// assert!(!analysis.alert);
/// assert!(analysis.composite_threat_score < 0.5);
/// ```
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
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::verdict::CheckResult;
///
/// let pass = CheckResult::new("velocity", "physics", true, "within 3.14 rad/s limit");
/// assert!(pass.passed);
/// assert_eq!(pass.name, "velocity");
/// assert!(pass.derating.is_none());
///
/// let fail = CheckResult::new("exclusion_zone", "safety", false, "end-effector inside zone");
/// assert!(!fail.passed);
/// assert_eq!(fail.category, "safety");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckResult {
    /// Name of the check (e.g. "joint_limits", "workspace", "authority").
    pub name: String,
    /// Category of the check (e.g. "physics", "authority", "safety").
    pub category: String,
    /// Whether this check passed.
    pub passed: bool,
    /// Human-readable details explaining the pass or fail reason.
    pub details: String,
    /// Advisory derating recommendation from environmental checks (P21-P24).
    ///
    /// When a sensor value is between the warning threshold and the absolute
    /// limit, the check PASSES but recommends reducing velocity/torque by
    /// this factor. The cognitive layer SHOULD respect this advice.
    /// A value of `None` means no derating is recommended.
    /// A value of `Some(0.5)` means "reduce to 50% of normal limits."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derating: Option<DeratingAdvice>,
}

impl CheckResult {
    /// Create a CheckResult with no derating advice (the common case).
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_core::models::verdict::CheckResult;
    ///
    /// let pass = CheckResult::new("joint_limits", "physics", true, "shoulder_pitch at 0.5 rad");
    /// assert!(pass.passed);
    /// assert!(pass.derating.is_none());
    ///
    /// let fail = CheckResult::new("torque", "physics", false, "exceeds 150.0 N·m limit");
    /// assert!(!fail.passed);
    /// assert_eq!(fail.details, "exceeds 150.0 N·m limit");
    /// ```
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

/// Advisory recommendation to reduce operational limits when a sensor value
/// is in the warning zone (between warning threshold and absolute limit).
///
/// This does NOT cause rejection — the command still passes. The cognitive
/// layer should use these factors to voluntarily reduce its next commands.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::verdict::DeratingAdvice;
///
/// let advice = DeratingAdvice {
///     velocity_scale: 0.5,
///     torque_scale: 0.7,
///     reason: "actuator temperature approaching limit (72°C / 80°C max)".into(),
/// };
///
/// assert_eq!(advice.velocity_scale, 0.5);
/// assert_eq!(advice.torque_scale, 0.7);
/// assert!(advice.reason.contains("72°C"));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeratingAdvice {
    /// Recommended velocity scale factor in (0.0, 1.0].
    /// Multiply max velocity limits by this factor.
    pub velocity_scale: f64,
    /// Recommended torque scale factor in (0.0, 1.0].
    /// Multiply max torque limits by this factor.
    pub torque_scale: f64,
    /// Human-readable reason for the derating.
    pub reason: String,
}

// Manual Eq/Hash for DeratingAdvice (f64 doesn't implement Eq/Hash, but
// CheckResult needs them for dedup. We compare the reason string only for
// Hash/Eq purposes since derating is advisory.)
impl Eq for DeratingAdvice {}
impl std::hash::Hash for DeratingAdvice {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.reason.hash(state);
    }
}

/// Summary of authority evaluation. Usable as a `HashMap` key (P3-2).
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::verdict::AuthoritySummary;
///
/// let summary = AuthoritySummary {
///     origin_principal: "safety-officer@example.com".into(),
///     hop_count: 2,
///     operations_granted: vec!["actuate:arm:*".into(), "actuate:gripper:*".into()],
///     operations_required: vec!["actuate:arm:joints".into()],
/// };
///
/// assert_eq!(summary.hop_count, 2);
/// assert_eq!(summary.operations_granted.len(), 2);
/// assert!(summary.operations_granted.contains(&"actuate:arm:*".into()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthoritySummary {
    /// Identity of the root principal (PCA_0 `p_0` field).
    pub origin_principal: String,
    /// Number of delegation hops in the chain.
    pub hop_count: usize,
    /// Operations granted by the final link in the chain.
    pub operations_granted: Vec<String>,
    /// Operations claimed as required by the command.
    pub operations_required: Vec<String>,
}

/// A [`Verdict`] paired with a cryptographic signature from the validator key.
///
/// The motor controller requires a valid `verdict_signature` before executing
/// any approved command (M1).
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::verdict::{SignedVerdict, Verdict, CheckResult, AuthoritySummary};
///
/// let verdict = Verdict {
///     approved: true,
///     command_hash: "sha256:deadbeef".into(),
///     command_sequence: 1,
///     timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
///         .unwrap()
///         .with_timezone(&chrono::Utc),
///     checks: vec![CheckResult::new("velocity", "physics", true, "ok")],
///     profile_name: "ur10e".into(),
///     profile_hash: "sha256:profile".into(),
///     authority_summary: AuthoritySummary {
///         origin_principal: "operator@example.com".into(),
///         hop_count: 1,
///         operations_granted: vec!["actuate:arm:*".into()],
///         operations_required: vec!["actuate:arm:joints".into()],
///     },
///     threat_analysis: None,
/// };
///
/// let signed = SignedVerdict {
///     verdict,
///     verdict_signature: "base64-ed25519-signature".into(),
///     signer_kid: "validator-key-001".into(),
/// };
///
/// assert!(signed.verdict.approved);
/// assert_eq!(signed.signer_kid, "validator-key-001");
/// ```
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
