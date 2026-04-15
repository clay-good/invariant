//! Adversarial test report types.
//!
//! `AdversarialReport` aggregates the results of one attack class run.
//! It is serialised as JSON for machine consumption and human review.

use serde::{Deserialize, Serialize};

/// A single finding where an attack was not detected (an "escape").
///
/// # Examples
///
/// ```
/// use invariant_robotics_fuzz::report::AdversarialFinding;
///
/// // Construct a finding for an attack that was correctly detected (not escaped).
/// let detected = AdversarialFinding {
///     attack_id: "PA1-j1-min".into(),
///     description: "Boundary probe at joint j1 minimum limit".into(),
///     validator_outcome: "rejected".into(),
///     escaped: false,
/// };
///
/// assert_eq!(detected.attack_id, "PA1-j1-min");
/// assert!(!detected.escaped, "attack was detected, not escaped");
///
/// // Construct a finding for an attack that slipped through (escaped).
/// let escaped = AdversarialFinding {
///     attack_id: "CE1-drift-step-42".into(),
///     description: "Gradual drift — unauthorized joint moved to midpoint".into(),
///     validator_outcome: "approved".into(),
///     escaped: true,
/// };
///
/// assert!(escaped.escaped, "this attack bypassed the validator");
/// assert_eq!(escaped.validator_outcome, "approved");
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdversarialFinding {
    /// Short identifier for the specific attack variant.
    pub attack_id: String,
    /// Human-readable description of what the attack attempted.
    pub description: String,
    /// The verdict that the validator produced (e.g. `"approved"`, `"rejected"`).
    pub validator_outcome: String,
    /// Whether the outcome was unexpected (i.e. the attack succeeded).
    pub escaped: bool,
}

/// Aggregated results for one attack class.
///
/// # Examples
///
/// ```
/// use invariant_robotics_fuzz::report::AdversarialReport;
///
/// // Create an empty report for a new attack campaign.
/// let report = AdversarialReport::new("protocol");
/// assert_eq!(report.attack_class, "protocol");
/// assert_eq!(report.total_attacks, 0);
/// assert_eq!(report.escapes, 0);
/// assert!(report.findings.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdversarialReport {
    /// Attack class name, e.g. `"protocol"`, `"authority"`, `"all"`.
    pub attack_class: String,
    /// Total number of attack variants attempted.
    pub total_attacks: u64,
    /// Number of attacks that were not detected (escaped).
    pub escapes: u64,
    /// Detailed findings (populated only for escaped attacks by convention,
    /// though callers may include all findings).
    pub findings: Vec<AdversarialFinding>,
}

impl AdversarialReport {
    /// Create a new empty report for the given attack class.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_fuzz::report::AdversarialReport;
    ///
    /// let report = AdversarialReport::new("authority");
    /// assert_eq!(report.attack_class, "authority");
    /// assert_eq!(report.total_attacks, 0);
    /// assert!(report.all_detected(), "empty report has nothing that escaped");
    /// ```
    pub fn new(attack_class: impl Into<String>) -> Self {
        Self {
            attack_class: attack_class.into(),
            total_attacks: 0,
            escapes: 0,
            findings: Vec::new(),
        }
    }

    /// Record a single attack attempt.
    ///
    /// `escaped` should be `true` when the validator failed to detect the
    /// attack (i.e., approved a command it should have rejected, or vice
    /// versa).
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_fuzz::report::AdversarialReport;
    ///
    /// let mut report = AdversarialReport::new("protocol");
    ///
    /// // Record an attack that the validator correctly rejected.
    /// report.record("PA1-j1-min", "Probe j1 at exact minimum limit", "rejected", false);
    /// assert_eq!(report.total_attacks, 1);
    /// assert_eq!(report.escapes, 0);
    /// assert!(report.all_detected());
    ///
    /// // Record an attack that slipped through (escaped detection).
    /// report.record("PA2-j2-overflow", "Probe j2 just above max limit", "approved", true);
    /// assert_eq!(report.total_attacks, 2);
    /// assert_eq!(report.escapes, 1);
    /// assert!(!report.all_detected(), "one attack escaped");
    ///
    /// // Findings are accumulated in order.
    /// assert_eq!(report.findings[0].attack_id, "PA1-j1-min");
    /// assert!(!report.findings[0].escaped);
    /// assert_eq!(report.findings[1].attack_id, "PA2-j2-overflow");
    /// assert!(report.findings[1].escaped);
    /// ```
    pub fn record(
        &mut self,
        attack_id: impl Into<String>,
        description: impl Into<String>,
        validator_outcome: impl Into<String>,
        escaped: bool,
    ) {
        self.total_attacks += 1;
        if escaped {
            self.escapes += 1;
        }
        self.findings.push(AdversarialFinding {
            attack_id: attack_id.into(),
            description: description.into(),
            validator_outcome: validator_outcome.into(),
            escaped,
        });
    }

    /// Return `true` if no attacks escaped detection.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_fuzz::report::AdversarialReport;
    ///
    /// let mut report = AdversarialReport::new("cognitive");
    ///
    /// // A fresh report with no attacks trivially has all detected.
    /// assert!(report.all_detected());
    ///
    /// // After recording only detected attacks, still all detected.
    /// report.record("CE1", "Gradual drift attempt", "rejected", false);
    /// report.record("CE3", "Semantic confusion attempt", "rejected", false);
    /// assert!(report.all_detected());
    ///
    /// // One escaped attack flips the result.
    /// report.record("CE7", "Watchdog manipulation", "approved", true);
    /// assert!(!report.all_detected());
    /// ```
    pub fn all_detected(&self) -> bool {
        self.escapes == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_report_is_empty() {
        let report = AdversarialReport::new("protocol");
        assert_eq!(report.attack_class, "protocol");
        assert_eq!(report.total_attacks, 0);
        assert_eq!(report.escapes, 0);
        assert!(report.findings.is_empty());
        assert!(report.all_detected());
    }

    #[test]
    fn record_detected_attack() {
        let mut report = AdversarialReport::new("authority");
        report.record("AA1", "Forged signature", "rejected", false);
        assert_eq!(report.total_attacks, 1);
        assert_eq!(report.escapes, 0);
        assert!(report.all_detected());
        assert_eq!(report.findings.len(), 1);
        assert!(!report.findings[0].escaped);
    }

    #[test]
    fn record_escaped_attack() {
        let mut report = AdversarialReport::new("protocol");
        report.record("PA1", "Boundary at min", "approved", true);
        assert_eq!(report.total_attacks, 1);
        assert_eq!(report.escapes, 1);
        assert!(!report.all_detected());
        assert!(report.findings[0].escaped);
    }

    #[test]
    fn multiple_records_accumulate() {
        let mut report = AdversarialReport::new("all");
        report.record("AA1", "Forge", "rejected", false);
        report.record("AA2", "Escalate", "rejected", false);
        report.record("PA3", "NaN injection", "approved", true); // escaped
        assert_eq!(report.total_attacks, 3);
        assert_eq!(report.escapes, 1);
        assert!(!report.all_detected());
    }

    #[test]
    fn round_trip_serialization() {
        let mut report = AdversarialReport::new("protocol");
        report.record("PA1", "min boundary", "rejected", false);
        report.record("PA3", "NaN position", "approved", true);

        let json = serde_json::to_string(&report).expect("serialize");
        let deserialized: AdversarialReport = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(report, deserialized);
    }

    #[test]
    fn finding_fields_are_correct() {
        let mut report = AdversarialReport::new("auth");
        report.record("AA3", "Truncated chain", "rejected", false);
        let f = &report.findings[0];
        assert_eq!(f.attack_id, "AA3");
        assert_eq!(f.description, "Truncated chain");
        assert_eq!(f.validator_outcome, "rejected");
        assert!(!f.escaped);
    }
}
