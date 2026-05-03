// Campaign reporter: aggregates per-command results into a CampaignReport.
//
// The reporter tracks pass/fail counts split by profile, scenario, and check
// name. After all commands have been recorded, `finalize()` computes derived
// rates and a Clopper-Pearson upper confidence bound on the violation-escape
// rate for IEC 61508 SIL mapping.

use invariant_core::models::verdict::SignedVerdict;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::campaign::SuccessCriteria;

// ---------------------------------------------------------------------------
// Per-dimension statistics
// ---------------------------------------------------------------------------

/// Aggregated counts for a single robot profile.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::reporter::ProfileStats;
///
/// let stats = ProfileStats {
///     total: 1000,
///     approved: 982,
///     rejected: 18,
/// };
/// assert_eq!(stats.total, 1000);
/// assert_eq!(stats.approved + stats.rejected, stats.total);
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileStats {
    /// Total number of commands evaluated for this profile.
    pub total: u64,
    /// Number of commands approved by the validator.
    pub approved: u64,
    /// Number of commands rejected by the validator.
    pub rejected: u64,
}

/// Aggregated counts for a single scenario type.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::reporter::ScenarioStats;
///
/// // A perfect adversarial scenario: all violations caught, no escapes.
/// let stats = ScenarioStats {
///     total: 200,
///     approved: 0,
///     rejected: 200,
///     expected_reject: 200,
///     escaped: 0,
///     false_rejections: 0,
/// };
/// assert_eq!(stats.escaped, 0);
/// assert_eq!(stats.total, 200);
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScenarioStats {
    /// Total number of commands evaluated for this scenario type.
    pub total: u64,
    /// Number of commands approved by the validator.
    pub approved: u64,
    /// Number of commands rejected by the validator.
    pub rejected: u64,
    /// Commands where rejection was expected (scenario generates violations).
    pub expected_reject: u64,
    /// Violation commands that were incorrectly approved (escaped).
    pub escaped: u64,
    /// Legitimate commands that were incorrectly rejected.
    pub false_rejections: u64,
}

/// Aggregated pass/fail counts for a single named check.
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::reporter::CheckStats;
///
/// let stats = CheckStats {
///     total: 500,
///     passed: 498,
///     failed: 2,
/// };
/// assert_eq!(stats.passed + stats.failed, stats.total);
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckStats {
    /// Number of times this check was evaluated.
    pub total: u64,
    /// Number of times it passed.
    pub passed: u64,
    /// Number of times it failed.
    pub failed: u64,
}

/// Confidence statistics for the violation-escape rate.
///
/// Uses the Clopper-Pearson (exact) method.  For the common case of zero
/// observed escapes in *n* trials the upper bound simplifies to:
///
///   upper_95 ≈ 1 − (α/2)^(1/n)  where α = 0.05
///   upper_99 ≈ 1 − (α/2)^(1/n)  where α = 0.01
///
/// The MTBF is then computed assuming a 100 Hz control-loop rate:
///   mtbf_hours = (1 / upper_bound_rate) / (100 × 3600)
///
/// # Examples
///
/// ```
/// use invariant_robotics_sim::reporter::ConfidenceStats;
///
/// // A SIL-3 result: zero escapes in 10 000 violation trials.
/// let stats = ConfidenceStats {
///     n_trials: 10_000,
///     n_escapes: 0,
///     upper_bound_95: 2.996e-4,
///     upper_bound_99: 4.604e-4,
///     upper_bound_999: 6.905e-4,
///     mtbf_hours_95: 9.26,
///     mtbf_hours_99: 6.03,
///     sil_rating: 3,
///     sil_rating_approximate: false,
/// };
/// assert_eq!(stats.n_escapes, 0);
/// assert_eq!(stats.sil_rating, 3);
/// assert!(!stats.sil_rating_approximate);
/// // Upper bounds must be finite and in (0, 1].
/// assert!(stats.upper_bound_95 > 0.0 && stats.upper_bound_95 < 1.0);
/// assert!(stats.upper_bound_99 > 0.0 && stats.upper_bound_99 < 1.0);
/// assert!(stats.upper_bound_999 > 0.0 && stats.upper_bound_999 < 1.0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceStats {
    /// Total violation commands evaluated.
    pub n_trials: u64,
    /// Observed escape count.
    pub n_escapes: u64,
    /// Clopper-Pearson 95% upper bound on escape rate.
    pub upper_bound_95: f64,
    /// Clopper-Pearson 99% upper bound on escape rate.
    pub upper_bound_99: f64,
    /// Clopper-Pearson 99.9% upper bound on escape rate.
    pub upper_bound_999: f64,
    /// MTBF at 100 Hz based on 95% upper bound (hours).
    pub mtbf_hours_95: f64,
    /// MTBF at 100 Hz based on 99% upper bound (hours).
    pub mtbf_hours_99: f64,
    /// IEC 61508 SIL rating inferred from the 99% upper bound on PFH.
    ///
    /// Based on IEC 61508 PFH thresholds for high-demand mode:
    ///   SIL 4: PFH < 1e-8
    ///   SIL 3: PFH < 1e-7
    ///   SIL 2: PFH < 1e-6
    ///   SIL 1: PFH < 1e-5
    pub sil_rating: u8,
    /// `true` when `n_escapes > 0`, indicating that the SIL rating was derived
    /// from the Wald (normal approximation) interval rather than the exact
    /// Clopper-Pearson interval.
    ///
    /// The Wald interval is known to be anti-conservative — it under-covers the
    /// true escape rate when the sample proportion is near 0 or 1, or when
    /// `n_trials` is small (below ~1000).  The rating should be treated with
    /// caution when this field is `true`, particularly when `n_escapes` is
    /// small relative to `n_trials`.
    pub sil_rating_approximate: bool,
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Complete campaign results.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use invariant_robotics_sim::reporter::{
///     CampaignReport, CheckStats, ConfidenceStats, ProfileStats, ScenarioStats,
/// };
///
/// // A minimal report that passes all criteria.
/// let report = CampaignReport {
///     campaign_name: "franka_sil3_campaign".to_string(),
///     total_commands: 1000,
///     total_approved: 800,
///     total_rejected: 200,
///     approval_rate: 0.8,
///     rejection_rate: 0.2,
///     legitimate_pass_rate: 0.99,
///     violation_escape_count: 0,
///     violation_escape_rate: 0.0,
///     false_rejection_count: 8,
///     false_rejection_rate: 0.01,
///     per_profile: HashMap::new(),
///     per_scenario: HashMap::new(),
///     per_check: HashMap::new(),
///     criteria_met: true,
///     confidence: ConfidenceStats {
///         n_trials: 200,
///         n_escapes: 0,
///         upper_bound_95: 1.49e-2,
///         upper_bound_99: 2.30e-2,
///         upper_bound_999: 3.44e-2,
///         mtbf_hours_95: 1.86,
///         mtbf_hours_99: 1.21,
///         sil_rating: 1,
///         sil_rating_approximate: false,
///     },
/// };
///
/// assert_eq!(report.campaign_name, "franka_sil3_campaign");
/// assert_eq!(report.total_commands, 1000);
/// assert_eq!(report.violation_escape_count, 0);
/// assert!(report.criteria_met);
/// assert!(report.approval_rate > 0.0 && report.approval_rate < 1.0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    /// Human-readable name of the campaign that produced this report.
    pub campaign_name: String,
    /// Total number of commands evaluated across all environments and episodes.
    pub total_commands: u64,
    /// Total number of commands approved by the validator.
    pub total_approved: u64,
    /// Total number of commands rejected by the validator.
    pub total_rejected: u64,
    /// Fraction of commands approved (total_approved / total_commands).
    pub approval_rate: f64,
    /// Fraction of commands rejected (total_rejected / total_commands).
    pub rejection_rate: f64,
    /// Fraction of legitimate commands correctly approved.
    pub legitimate_pass_rate: f64,
    /// Absolute count of violation commands that were incorrectly approved.
    pub violation_escape_count: u64,
    /// Fraction of violation commands that escaped detection.
    pub violation_escape_rate: f64,
    /// Absolute count of legitimate commands incorrectly rejected.
    pub false_rejection_count: u64,
    /// Fraction of legitimate commands incorrectly rejected.
    pub false_rejection_rate: f64,
    /// Per-profile breakdown of approval and rejection counts.
    pub per_profile: HashMap<String, ProfileStats>,
    /// Per-scenario breakdown of approval, rejection, and escape counts.
    pub per_scenario: HashMap<String, ScenarioStats>,
    /// Per-check breakdown of pass/fail counts.
    pub per_check: HashMap<String, CheckStats>,
    /// Whether all success-criteria thresholds were met.
    pub criteria_met: bool,
    /// Statistical confidence bounds on the violation-escape rate.
    pub confidence: ConfidenceStats,
}

// ---------------------------------------------------------------------------
// Reporter (mutable accumulator)
// ---------------------------------------------------------------------------

/// Accumulates per-command results and produces a `CampaignReport`.
pub struct CampaignReporter {
    campaign_name: String,
    criteria: SuccessCriteria,

    total_commands: u64,
    total_approved: u64,
    total_rejected: u64,

    // Counts for rate computation.
    legitimate_total: u64,
    legitimate_approved: u64,
    violation_total: u64,
    violation_escaped: u64,
    false_rejections: u64,

    per_profile: HashMap<String, ProfileStats>,
    per_scenario: HashMap<String, ScenarioStats>,
    per_check: HashMap<String, CheckStats>,
}

impl CampaignReporter {
    /// Create a new reporter for a named campaign.
    pub fn new(campaign_name: String, criteria: SuccessCriteria) -> Self {
        CampaignReporter {
            campaign_name,
            criteria,
            total_commands: 0,
            total_approved: 0,
            total_rejected: 0,
            legitimate_total: 0,
            legitimate_approved: 0,
            violation_total: 0,
            violation_escaped: 0,
            false_rejections: 0,
            per_profile: HashMap::new(),
            per_scenario: HashMap::new(),
            per_check: HashMap::new(),
        }
    }

    /// Record a single validation result.
    ///
    /// * `profile` -- name of the robot profile used.
    /// * `scenario` -- name of the scenario type.
    /// * `expected_reject` -- `true` if this command was generated by a
    ///   violation scenario and should have been rejected.
    /// * `verdict` -- the signed verdict returned by the validator.
    pub fn record_result(
        &mut self,
        profile: &str,
        scenario: &str,
        expected_reject: bool,
        verdict: &SignedVerdict,
    ) {
        let approved = verdict.verdict.approved;

        self.total_commands += 1;
        if approved {
            self.total_approved += 1;
        } else {
            self.total_rejected += 1;
        }

        // Legitimate vs. violation tracking.
        if expected_reject {
            self.violation_total += 1;
            if approved {
                // Violation escaped detection.
                self.violation_escaped += 1;
            }
        } else {
            self.legitimate_total += 1;
            if approved {
                self.legitimate_approved += 1;
            } else {
                // Legitimate command incorrectly rejected.
                self.false_rejections += 1;
            }
        }

        // Per-profile.  Avoid a String allocation on cache hit by checking
        // for an existing entry before inserting.
        let ps = if let Some(ps) = self.per_profile.get_mut(profile) {
            ps
        } else {
            self.per_profile.entry(profile.to_owned()).or_default()
        };
        ps.total += 1;
        if approved {
            ps.approved += 1;
        } else {
            ps.rejected += 1;
        }

        // Per-scenario.  Same cache-miss-only allocation pattern.
        let ss = if let Some(ss) = self.per_scenario.get_mut(scenario) {
            ss
        } else {
            self.per_scenario.entry(scenario.to_owned()).or_default()
        };
        ss.total += 1;
        if approved {
            ss.approved += 1;
        } else {
            ss.rejected += 1;
        }
        if expected_reject {
            ss.expected_reject += 1;
            if approved {
                ss.escaped += 1;
            }
        } else if !approved {
            ss.false_rejections += 1;
        }

        // Per-check.  Allocate a new key only on first observation.
        for check in &verdict.verdict.checks {
            let cs = if let Some(cs) = self.per_check.get_mut(&check.name) {
                cs
            } else {
                self.per_check.entry(check.name.clone()).or_default()
            };
            cs.total += 1;
            if check.passed {
                cs.passed += 1;
            } else {
                cs.failed += 1;
            }
        }
    }

    /// Consume the reporter and compute the final `CampaignReport`.
    pub fn finalize(self) -> CampaignReport {
        let total = self.total_commands;
        let approval_rate = if total > 0 {
            self.total_approved as f64 / total as f64
        } else {
            0.0
        };
        let rejection_rate = if total > 0 {
            self.total_rejected as f64 / total as f64
        } else {
            0.0
        };
        let legitimate_pass_rate = if self.legitimate_total > 0 {
            self.legitimate_approved as f64 / self.legitimate_total as f64
        } else {
            1.0 // vacuously true — no legitimate commands to fail
        };
        let violation_escape_rate = if self.violation_total > 0 {
            self.violation_escaped as f64 / self.violation_total as f64
        } else {
            0.0
        };
        let false_rejection_rate = if self.legitimate_total > 0 {
            self.false_rejections as f64 / self.legitimate_total as f64
        } else {
            0.0
        };

        let confidence = compute_confidence(self.violation_total, self.violation_escaped);

        let criteria_met = legitimate_pass_rate >= self.criteria.min_legitimate_pass_rate
            && violation_escape_rate <= self.criteria.max_violation_escape_rate
            && false_rejection_rate <= self.criteria.max_false_rejection_rate;

        CampaignReport {
            campaign_name: self.campaign_name,
            total_commands: total,
            total_approved: self.total_approved,
            total_rejected: self.total_rejected,
            approval_rate,
            rejection_rate,
            legitimate_pass_rate,
            violation_escape_count: self.violation_escaped,
            violation_escape_rate,
            false_rejection_count: self.false_rejections,
            false_rejection_rate,
            per_profile: self.per_profile,
            per_scenario: self.per_scenario,
            per_check: self.per_check,
            criteria_met,
            confidence,
        }
    }
}

// ---------------------------------------------------------------------------
// Confidence computation (Clopper-Pearson)
// ---------------------------------------------------------------------------

/// Compute Clopper-Pearson upper bounds and derived metrics.
///
/// For zero observed escapes in *n* trials the exact upper bound is:
///   upper_bound = 1 − (α/2)^(1/n)
///
/// For non-zero escapes we use the normal approximation, which is conservative
/// (over-estimates the true upper bound):
///   upper_bound ≈ p_hat + z * sqrt(p_hat*(1-p_hat)/n)
/// where z = 1.96 for 95% and z = 2.576 for 99%.
///
/// If n == 0 we return 1.0 (worst-case — no information).
fn compute_confidence(n_trials: u64, n_escapes: u64) -> ConfidenceStats {
    const HZ: f64 = 100.0;
    const SECS_PER_HOUR: f64 = 3600.0;

    let (upper_95, upper_99, upper_999) = if n_trials == 0 {
        (1.0_f64, 1.0_f64, 1.0_f64)
    } else if n_escapes == 0 {
        // Clopper-Pearson exact one-sided upper bound for zero failures:
        //   upper = 1 - α^(1/n)
        // where α is the significance level (0.05 for 95%, 0.01 for 99%, 0.001 for 99.9%).
        let n = n_trials as f64;
        let ub95 = 1.0 - (0.05_f64).powf(1.0 / n);
        let ub99 = 1.0 - (0.01_f64).powf(1.0 / n);
        let ub999 = 1.0 - (0.001_f64).powf(1.0 / n);
        (
            ub95.clamp(0.0, 1.0),
            ub99.clamp(0.0, 1.0),
            ub999.clamp(0.0, 1.0),
        )
    } else {
        // Wilson score interval — more conservative than the Wald (normal)
        // approximation for small p and large n, which is the regime we
        // operate in during safety certification campaigns.
        //
        // Formula: (p + z²/(2n) + z·√(p(1-p)/n + z²/(4n²))) / (1 + z²/n)
        let n = n_trials as f64;
        let p = n_escapes as f64 / n;

        let z95 = 1.645_f64; // one-sided 95%
        let z99 = 2.326_f64; // one-sided 99%
        let z999 = 3.090_f64; // one-sided 99.9%

        let wilson_upper = |z: f64| -> f64 {
            let z2 = z * z;
            let denom = 1.0 + z2 / n;
            let center = p + z2 / (2.0 * n);
            let margin = z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
            ((center + margin) / denom).clamp(0.0, 1.0)
        };

        (wilson_upper(z95), wilson_upper(z99), wilson_upper(z999))
    };

    // MTBF: mean time between failures at 100 Hz.
    // upper_bound is the per-command failure probability (PFH per step).
    // Expected failures per second = upper_bound * HZ.
    // MTBF (seconds) = 1 / (upper_bound * HZ), then convert to hours.
    let mtbf_hours_95 = if upper_95 > 0.0 {
        1.0 / (upper_95 * HZ * SECS_PER_HOUR)
    } else {
        f64::INFINITY
    };
    let mtbf_hours_99 = if upper_99 > 0.0 {
        1.0 / (upper_99 * HZ * SECS_PER_HOUR)
    } else {
        f64::INFINITY
    };

    // Per-command failure probability thresholds (analogous to SIL but at
    // the per-decision level, not per-hour).  These are useful for comparing
    // across campaigns of different sizes.
    //   Level 4: per-command < 1e-8  (requires ~530M+ violation trials)
    //   Level 3: per-command < 1e-7  (requires ~53M+ violation trials)
    //   Level 2: per-command < 1e-6  (requires ~5.3M+ violation trials)
    //   Level 1: per-command < 1e-5  (requires ~530K+ violation trials)
    //   Level 0: per-command >= 1e-5
    let sil_rating = if upper_99 < 1e-8 {
        4
    } else if upper_99 < 1e-7 {
        3
    } else if upper_99 < 1e-6 {
        2
    } else if upper_99 < 1e-5 {
        1
    } else {
        0
    };

    ConfidenceStats {
        n_trials,
        n_escapes,
        upper_bound_95: upper_95,
        upper_bound_99: upper_99,
        upper_bound_999: upper_999,
        mtbf_hours_95,
        mtbf_hours_99,
        sil_rating,
        sil_rating_approximate: n_escapes > 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use invariant_core::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};

    fn make_verdict(approved: bool, check_names: &[(&str, bool)]) -> SignedVerdict {
        let checks = check_names
            .iter()
            .map(|(name, passed)| CheckResult {
                name: name.to_string(),
                category: "test".into(),
                passed: *passed,
                details: "".into(),
                derating: None,
            })
            .collect();
        SignedVerdict {
            verdict: Verdict {
                approved,
                command_hash: "sha256:abc".into(),
                command_sequence: 1,
                timestamp: Utc::now(),
                checks,
                profile_name: "franka_panda".into(),
                profile_hash: "sha256:def".into(),
                threat_analysis: None,
                authority_summary: AuthoritySummary {
                    origin_principal: "alice".into(),
                    hop_count: 1,
                    operations_granted: vec![],
                    operations_required: vec![],
                },
            },
            verdict_signature: "sig".into(),
            signer_kid: "kid-1".into(),
        }
    }

    fn default_criteria() -> SuccessCriteria {
        SuccessCriteria::default()
    }

    // --- Basic counting ---

    #[test]
    fn empty_reporter_produces_zero_counts() {
        let reporter = CampaignReporter::new("test".into(), default_criteria());
        let report = reporter.finalize();
        assert_eq!(report.total_commands, 0);
        assert_eq!(report.total_approved, 0);
        assert_eq!(report.total_rejected, 0);
        assert!((report.approval_rate).abs() < f64::EPSILON);
        assert!((report.rejection_rate).abs() < f64::EPSILON);
        // Vacuous: no legitimate commands => pass rate = 1.0
        assert!((report.legitimate_pass_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.violation_escape_count, 0);
        assert!((report.violation_escape_rate).abs() < f64::EPSILON);
        assert_eq!(report.false_rejection_count, 0);
    }

    #[test]
    fn all_legitimate_approved_100pct_pass() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        for _ in 0..10 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        let report = reporter.finalize();
        assert_eq!(report.total_commands, 10);
        assert_eq!(report.total_approved, 10);
        assert_eq!(report.total_rejected, 0);
        assert!((report.approval_rate - 1.0).abs() < f64::EPSILON);
        assert!((report.legitimate_pass_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.false_rejection_count, 0);
        assert_eq!(report.violation_escape_count, 0);
    }

    #[test]
    fn all_violations_correctly_rejected() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        for _ in 0..20 {
            reporter.record_result(
                "franka_panda",
                "PositionViolation",
                true,
                &make_verdict(false, &[]),
            );
        }
        let report = reporter.finalize();
        assert_eq!(report.total_rejected, 20);
        assert_eq!(report.violation_escape_count, 0);
        assert!((report.violation_escape_rate).abs() < f64::EPSILON);
    }

    #[test]
    fn escaped_violation_counted() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        // 9 correctly rejected + 1 escape
        for _ in 0..9 {
            reporter.record_result("franka_panda", "Spoofed", true, &make_verdict(false, &[]));
        }
        reporter.record_result("franka_panda", "Spoofed", true, &make_verdict(true, &[]));

        let report = reporter.finalize();
        assert_eq!(report.violation_escape_count, 1);
        assert!((report.violation_escape_rate - 0.1).abs() < 1e-10);
    }

    #[test]
    fn false_rejection_counted() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        for _ in 0..9 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        reporter.record_result("franka_panda", "Baseline", false, &make_verdict(false, &[]));

        let report = reporter.finalize();
        assert_eq!(report.false_rejection_count, 1);
        assert!((report.false_rejection_rate - 0.1).abs() < 1e-10);
    }

    // --- Per-dimension aggregation ---

    #[test]
    fn per_profile_stats() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        for _ in 0..5 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..3 {
            reporter.record_result("ur10", "Baseline", false, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        let fp = &report.per_profile["franka_panda"];
        assert_eq!(fp.total, 5);
        assert_eq!(fp.approved, 5);
        assert_eq!(fp.rejected, 0);
        let ur = &report.per_profile["ur10"];
        assert_eq!(ur.total, 3);
        assert_eq!(ur.approved, 0);
        assert_eq!(ur.rejected, 3);
    }

    #[test]
    fn per_scenario_stats() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        reporter.record_result(
            "franka_panda",
            "PositionViolation",
            true,
            &make_verdict(false, &[]),
        );
        reporter.record_result(
            "franka_panda",
            "PositionViolation",
            true,
            &make_verdict(true, &[]), // escaped
        );

        let report = reporter.finalize();
        let sc = &report.per_scenario["PositionViolation"];
        assert_eq!(sc.total, 2);
        assert_eq!(sc.expected_reject, 2);
        assert_eq!(sc.escaped, 1);
        assert_eq!(sc.false_rejections, 0);
    }

    #[test]
    fn per_check_stats() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        reporter.record_result(
            "franka_panda",
            "Baseline",
            false,
            &make_verdict(true, &[("authority", true), ("joint_limits", true)]),
        );
        reporter.record_result(
            "franka_panda",
            "VelocityViolation",
            true,
            &make_verdict(false, &[("authority", true), ("joint_limits", false)]),
        );

        let report = reporter.finalize();
        let auth = &report.per_check["authority"];
        assert_eq!(auth.total, 2);
        assert_eq!(auth.passed, 2);
        assert_eq!(auth.failed, 0);
        let jl = &report.per_check["joint_limits"];
        assert_eq!(jl.total, 2);
        assert_eq!(jl.passed, 1);
        assert_eq!(jl.failed, 1);
    }

    // --- Criteria evaluation ---

    #[test]
    fn criteria_met_when_thresholds_satisfied() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        for _ in 0..100 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..100 {
            reporter.record_result("franka_panda", "Violation", true, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        assert!(report.criteria_met);
    }

    #[test]
    fn criteria_not_met_on_escape() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        for _ in 0..100 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        // One escape fails max_violation_escape_rate = 0.0
        reporter.record_result("franka_panda", "Violation", true, &make_verdict(true, &[]));

        let report = reporter.finalize();
        assert!(!report.criteria_met);
    }

    #[test]
    fn criteria_not_met_on_high_false_rejection() {
        let criteria = SuccessCriteria {
            min_legitimate_pass_rate: 0.98,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 0.02,
        };
        let mut reporter = CampaignReporter::new("test".into(), criteria);
        // 5% false rejection rate
        for _ in 0..95 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..5 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        assert!(!report.criteria_met);
    }

    // criteria_met boundary: legitimate_pass_rate exactly at threshold (passes)
    #[test]
    fn criteria_met_at_exact_legitimate_pass_rate_boundary() {
        // 50 approved out of 50 legitimate = 1.0, threshold 0.98 => met
        // Use 98 approved + 2 rejected out of 100 to hit exactly 0.98.
        let criteria = SuccessCriteria {
            min_legitimate_pass_rate: 0.98,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 1.0, // not under test here
        };
        let mut reporter = CampaignReporter::new("test".into(), criteria);
        for _ in 0..98 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..2 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        // legitimate_pass_rate = 98/100 = 0.98, which is >= 0.98
        assert!(
            (report.legitimate_pass_rate - 0.98).abs() < f64::EPSILON,
            "expected 0.98, got {}",
            report.legitimate_pass_rate
        );
        assert!(report.criteria_met);
    }

    // criteria_met boundary: legitimate_pass_rate one unit below threshold (fails)
    #[test]
    fn criteria_not_met_just_below_legitimate_pass_rate_boundary() {
        let criteria = SuccessCriteria {
            min_legitimate_pass_rate: 0.98,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 1.0,
        };
        let mut reporter = CampaignReporter::new("test".into(), criteria);
        for _ in 0..97 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..3 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        // legitimate_pass_rate = 97/100 = 0.97, which is < 0.98
        assert!(report.legitimate_pass_rate < 0.98);
        assert!(!report.criteria_met);
    }

    // criteria_met boundary: violation_escape_rate exactly at threshold (passes, max=0.0)
    #[test]
    fn criteria_met_at_zero_escape_rate_boundary() {
        // max_violation_escape_rate = 0.0; zero escapes => 0.0 <= 0.0 passes
        let criteria = SuccessCriteria {
            min_legitimate_pass_rate: 0.0,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 1.0,
        };
        let mut reporter = CampaignReporter::new("test".into(), criteria);
        for _ in 0..10 {
            reporter.record_result("franka_panda", "Violation", true, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        assert!((report.violation_escape_rate).abs() < f64::EPSILON);
        assert!(report.criteria_met);
    }

    // criteria_met boundary: violation_escape_rate exceeds threshold by one escape
    #[test]
    fn criteria_not_met_one_escape_above_zero_threshold() {
        let criteria = SuccessCriteria {
            min_legitimate_pass_rate: 0.0,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 1.0,
        };
        let mut reporter = CampaignReporter::new("test".into(), criteria);
        for _ in 0..9 {
            reporter.record_result("franka_panda", "Violation", true, &make_verdict(false, &[]));
        }
        // One escape
        reporter.record_result("franka_panda", "Violation", true, &make_verdict(true, &[]));
        let report = reporter.finalize();
        assert!(report.violation_escape_rate > 0.0);
        assert!(!report.criteria_met);
    }

    // criteria_met boundary: false_rejection_rate exactly at max threshold (passes)
    #[test]
    fn criteria_met_at_exact_false_rejection_boundary() {
        // max_false_rejection_rate = 0.02; exactly 2/100 => 0.02 <= 0.02 passes
        let criteria = SuccessCriteria {
            min_legitimate_pass_rate: 0.0,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 0.02,
        };
        let mut reporter = CampaignReporter::new("test".into(), criteria);
        for _ in 0..98 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..2 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        assert!(
            (report.false_rejection_rate - 0.02).abs() < f64::EPSILON,
            "expected 0.02, got {}",
            report.false_rejection_rate
        );
        assert!(report.criteria_met);
    }

    // criteria_met boundary: false_rejection_rate one unit above max threshold (fails)
    #[test]
    fn criteria_not_met_just_above_false_rejection_boundary() {
        let criteria = SuccessCriteria {
            min_legitimate_pass_rate: 0.0,
            max_violation_escape_rate: 0.0,
            max_false_rejection_rate: 0.02,
        };
        let mut reporter = CampaignReporter::new("test".into(), criteria);
        for _ in 0..97 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..3 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        // false_rejection_rate = 3/100 = 0.03, which is > 0.02
        assert!(report.false_rejection_rate > 0.02);
        assert!(!report.criteria_met);
    }

    // --- Finding 76: legitimate_pass_rate vacuous-true when zero legitimate commands ---

    /// When only violation commands are recorded, `legitimate_total` is 0.
    /// The reporter returns 1.0 as a vacuous truth — there are no legitimate
    /// commands to fail, so the pass rate is trivially 100%.
    /// Callers should check the total counts before interpreting this value.
    #[test]
    fn legitimate_pass_rate_is_vacuously_one_for_zero_legitimate() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        // Record only violation commands (expected_reject = true).
        for _ in 0..10 {
            reporter.record_result("franka_panda", "Violation", true, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        // No legitimate commands were recorded.
        assert_eq!(report.false_rejection_count, 0);
        // legitimate_pass_rate is vacuously 1.0.
        assert!(
            (report.legitimate_pass_rate - 1.0).abs() < f64::EPSILON,
            "expected vacuous 1.0, got {}",
            report.legitimate_pass_rate
        );
    }

    // --- Finding 78: approval_rate + rejection_rate == 1.0 ---

    #[test]
    fn approval_rate_plus_rejection_rate_equals_one() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        // 7 approved + 3 rejected = 10 total.
        for _ in 0..7 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..3 {
            reporter.record_result("franka_panda", "Violation", true, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        let sum = report.approval_rate + report.rejection_rate;
        assert!(
            (sum - 1.0).abs() < 1e-12,
            "approval_rate ({}) + rejection_rate ({}) must sum to 1.0, got {}",
            report.approval_rate,
            report.rejection_rate,
            sum
        );
    }

    #[test]
    fn approval_rate_plus_rejection_rate_equals_one_all_approved() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        for _ in 0..20 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        let report = reporter.finalize();
        let sum = report.approval_rate + report.rejection_rate;
        assert!(
            (sum - 1.0).abs() < 1e-12,
            "sum must be 1.0 when all approved, got {}",
            sum
        );
    }

    #[test]
    fn approval_rate_plus_rejection_rate_equals_one_all_rejected() {
        let mut reporter = CampaignReporter::new("test".into(), default_criteria());
        for _ in 0..15 {
            reporter.record_result("franka_panda", "Violation", true, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        let sum = report.approval_rate + report.rejection_rate;
        assert!(
            (sum - 1.0).abs() < 1e-12,
            "sum must be 1.0 when all rejected, got {}",
            sum
        );
    }

    // --- Confidence stats ---

    #[test]
    fn zero_trials_confidence_is_worst_case() {
        let conf = compute_confidence(0, 0);
        assert!((conf.upper_bound_95 - 1.0).abs() < f64::EPSILON);
        assert!((conf.upper_bound_99 - 1.0).abs() < f64::EPSILON);
        assert!((conf.upper_bound_999 - 1.0).abs() < f64::EPSILON);
        assert_eq!(conf.n_trials, 0);
        assert_eq!(conf.n_escapes, 0);
    }

    #[test]
    fn confidence_999_bound_15m_spec_claim() {
        // Spec Purpose section: at 15M episodes with 0 bypasses,
        // 99.9% CI upper bound < 0.0000461% (4.61e-7).
        let conf = compute_confidence(15_000_000, 0);
        assert!(
            conf.upper_bound_999 < 4.61e-7,
            "99.9% bound at 15M must be < 4.61e-7, got {:.3e}",
            conf.upper_bound_999
        );
        assert!(
            conf.upper_bound_999 > conf.upper_bound_99,
            "99.9% bound must be wider than 99%"
        );
    }

    #[test]
    fn zero_escapes_in_1000_trials() {
        let conf = compute_confidence(1000, 0);
        // Upper bound should be small but positive.
        assert!(conf.upper_bound_95 > 0.0);
        assert!(conf.upper_bound_95 < 0.01);
        assert!(conf.upper_bound_99 > conf.upper_bound_95);
        assert_eq!(conf.n_escapes, 0);
        assert_eq!(conf.n_trials, 1000);
        // MTBF at 1000 trials is small — only ~2.7 seconds at 100Hz.
        // Just verify it's positive and finite.
        assert!(conf.mtbf_hours_95 > 0.0);
        assert!(conf.mtbf_hours_95.is_finite());
    }

    #[test]
    fn ten_million_trials_achieves_sil2_or_higher() {
        // With 10M violation trials and 0 escapes we cross into SIL 2+.
        // PFH = upper_99 * 100Hz * 3600s ≈ 1.91e-7 for 10M => SIL 2.
        let conf = compute_confidence(10_000_000, 0);
        assert!(conf.sil_rating >= 2, "sil={}", conf.sil_rating);
        // MTBF at this scale should be substantial (> 1 hour).
        assert!(conf.mtbf_hours_95 > 1.0);
    }

    #[test]
    fn nonzero_escapes_normal_approx() {
        let conf = compute_confidence(1000, 10);
        assert!(conf.upper_bound_95 > 0.01);
        assert!(conf.upper_bound_99 > conf.upper_bound_95);
        assert_eq!(conf.sil_rating, 0); // escape rate too high for any SIL
    }

    // --- Findings 11 / 39: sil_rating_approximate flag ---

    #[test]
    fn sil_rating_not_approximate_when_zero_escapes() {
        let conf = compute_confidence(1000, 0);
        assert!(
            !conf.sil_rating_approximate,
            "sil_rating_approximate must be false when n_escapes == 0 (exact Clopper-Pearson)"
        );
    }

    #[test]
    fn sil_rating_approximate_when_nonzero_escapes() {
        let conf = compute_confidence(1000, 1);
        assert!(
            conf.sil_rating_approximate,
            "sil_rating_approximate must be true when n_escapes > 0 (Wald approximation)"
        );
    }

    #[test]
    fn sil_rating_not_approximate_for_zero_trials() {
        // n_trials == 0 → worst-case bound, no escapes recorded, not Wald.
        let conf = compute_confidence(0, 0);
        assert!(
            !conf.sil_rating_approximate,
            "sil_rating_approximate must be false when n_trials == 0"
        );
    }

    /// Verify the Wald upper bound is >= the raw observed rate for small n.
    ///
    /// For n=10, k=1: p_hat = 0.1. The Wald 99% bound = p_hat + 2.576*se.
    /// This must exceed 0.1 (the observed rate) to be at all useful.
    #[test]
    fn wald_upper_bound_exceeds_observed_rate_for_small_n() {
        let conf = compute_confidence(10, 1);
        let observed_rate = 1.0_f64 / 10.0;
        assert!(
            conf.upper_bound_99 > observed_rate,
            "Wald 99% upper bound {:.6} must exceed observed rate {:.6}",
            conf.upper_bound_99,
            observed_rate
        );
        assert!(
            conf.upper_bound_95 > observed_rate,
            "Wald 95% upper bound {:.6} must exceed observed rate {:.6}",
            conf.upper_bound_95,
            observed_rate
        );
    }

    /// For n=5, k=1 the Wald bound must be at least as large as the known
    /// conservative Wilson score bound, demonstrating it does not systematically
    /// under-cover for this extreme-small-n case.
    ///
    /// NOTE: The Wald interval is known to be anti-conservative for small n
    /// and proportions near 0 or 1. This test documents that the bound is
    /// positive and non-trivially above 0.2 (the observed rate) — it does NOT
    /// guarantee Clopper-Pearson coverage.  See `sil_rating_approximate` field.
    #[test]
    fn wald_bound_positive_and_nonzero_for_small_n() {
        let conf = compute_confidence(5, 1);
        assert!(conf.upper_bound_99 > 0.0, "bound must be positive");
        assert!(conf.upper_bound_95 > 0.0, "bound must be positive");
        // Wald bound for n=5, k=1: p=0.2, se=sqrt(0.16/5)≈0.179
        // upper_95 ≈ 0.2 + 1.96*0.179 ≈ 0.55
        // upper_99 ≈ 0.2 + 2.576*0.179 ≈ 0.66
        assert!(
            conf.upper_bound_99 > 0.2,
            "Wald 99% bound for n=5,k=1 must exceed observed rate 0.2"
        );
        assert!(
            conf.sil_rating_approximate,
            "must be marked approximate when n_escapes > 0"
        );
    }

    #[test]
    fn sil_rating_boundaries() {
        // Per-command thresholds: level uses upper_bound_99 directly.
        // One-sided Clopper-Pearson: upper_99 = 1 - 0.01^(1/n).
        //
        // 5M trials, 0 escapes: upper_99 ≈ 9.2e-7 => level 2.
        let conf = compute_confidence(5_000_000, 0);
        assert_eq!(conf.sil_rating, 2);

        // 10M trials: upper_99 ≈ 4.6e-7 => level 2.
        let conf = compute_confidence(10_000_000, 0);
        assert_eq!(conf.sil_rating, 2);

        // 100M trials: upper_99 ≈ 4.6e-8 => level 3.
        let conf = compute_confidence(100_000_000, 0);
        assert_eq!(conf.sil_rating, 3);

        // 1B trials: upper_99 ≈ 4.6e-9 => level 4.
        let conf = compute_confidence(1_000_000_000, 0);
        assert_eq!(conf.sil_rating, 4);
    }

    // =========================================================================
    // Multi-profile reporting tests
    // =========================================================================

    #[test]
    fn multi_profile_per_profile_stats_independent() {
        let mut reporter = CampaignReporter::new("multi".into(), default_criteria());
        // Franka Panda: 10 approved
        for _ in 0..10 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        // UR10: 8 approved, 2 rejected
        for _ in 0..8 {
            reporter.record_result("ur10", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..2 {
            reporter.record_result("ur10", "Baseline", false, &make_verdict(false, &[]));
        }
        // Quadruped: 5 all rejected (violations)
        for _ in 0..5 {
            reporter.record_result(
                "quadruped_12dof",
                "AuthEsc",
                true,
                &make_verdict(false, &[]),
            );
        }
        // Humanoid: 3 approved
        for _ in 0..3 {
            reporter.record_result(
                "humanoid_28dof",
                "Baseline",
                false,
                &make_verdict(true, &[]),
            );
        }
        let report = reporter.finalize();

        assert_eq!(report.total_commands, 28);
        assert_eq!(report.per_profile.len(), 4);
        let fp = &report.per_profile["franka_panda"];
        assert_eq!(fp.total, 10);
        assert_eq!(fp.approved, 10);
        assert_eq!(fp.rejected, 0);
        let ur = &report.per_profile["ur10"];
        assert_eq!(ur.total, 10);
        assert_eq!(ur.approved, 8);
        assert_eq!(ur.rejected, 2);
        let qd = &report.per_profile["quadruped_12dof"];
        assert_eq!(qd.total, 5);
        assert_eq!(qd.approved, 0);
        assert_eq!(qd.rejected, 5);
        let hm = &report.per_profile["humanoid_28dof"];
        assert_eq!(hm.total, 3);
        assert_eq!(hm.approved, 3);
        assert_eq!(hm.rejected, 0);
    }

    #[test]
    fn five_profiles_all_accounted_for() {
        let profiles = [
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ];
        let mut reporter = CampaignReporter::new("five".into(), default_criteria());
        for p in &profiles {
            for _ in 0..4 {
                reporter.record_result(p, "Baseline", false, &make_verdict(true, &[]));
            }
        }
        let report = reporter.finalize();
        assert_eq!(report.total_commands, 20);
        assert_eq!(report.total_approved, 20);
        assert_eq!(report.per_profile.len(), 5);
        for p in &profiles {
            let stats = &report.per_profile[*p];
            assert_eq!(stats.total, 4, "profile {p} must have 4 commands");
            assert_eq!(stats.approved, 4);
        }
    }

    #[test]
    fn multi_profile_escapes_tracked_per_scenario() {
        let mut reporter = CampaignReporter::new("esc".into(), default_criteria());
        // Profile A: violation correctly rejected
        reporter.record_result(
            "franka_panda",
            "PositionViolation",
            true,
            &make_verdict(false, &[]),
        );
        // Profile B: same violation escapes!
        reporter.record_result("ur10", "PositionViolation", true, &make_verdict(true, &[]));
        let report = reporter.finalize();
        assert_eq!(report.violation_escape_count, 1);
        let sc = &report.per_scenario["PositionViolation"];
        assert_eq!(sc.total, 2);
        assert_eq!(sc.escaped, 1);
        assert_eq!(sc.expected_reject, 2);
    }

    #[test]
    fn multi_profile_false_rejections_tracked() {
        let mut reporter = CampaignReporter::new("fr".into(), default_criteria());
        // Profile A: legitimate approved
        reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        // Profile B: legitimate wrongly rejected
        reporter.record_result("ur10", "Baseline", false, &make_verdict(false, &[]));
        // Profile C: legitimate approved
        reporter.record_result(
            "quadruped_12dof",
            "Baseline",
            false,
            &make_verdict(true, &[]),
        );
        let report = reporter.finalize();
        assert_eq!(report.false_rejection_count, 1);
        assert!((report.false_rejection_rate - 1.0 / 3.0).abs() < 1e-10);
    }

    // =========================================================================
    // Multi-scenario aggregation tests
    // =========================================================================

    #[test]
    fn multiple_scenarios_tracked_independently() {
        let mut reporter = CampaignReporter::new("sc".into(), default_criteria());
        reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        reporter.record_result(
            "franka_panda",
            "Aggressive",
            false,
            &make_verdict(true, &[]),
        );
        reporter.record_result("franka_panda", "AuthEsc", true, &make_verdict(false, &[]));
        reporter.record_result(
            "franka_panda",
            "ChainForgery",
            true,
            &make_verdict(false, &[]),
        );
        let report = reporter.finalize();
        assert_eq!(report.per_scenario.len(), 4);
        assert_eq!(report.per_scenario["Baseline"].total, 1);
        assert_eq!(report.per_scenario["Aggressive"].total, 1);
        assert_eq!(report.per_scenario["AuthEsc"].total, 1);
        assert_eq!(report.per_scenario["ChainForgery"].total, 1);
    }

    #[test]
    fn per_check_stats_across_profiles() {
        let mut reporter = CampaignReporter::new("chk".into(), default_criteria());
        reporter.record_result(
            "franka_panda",
            "Baseline",
            false,
            &make_verdict(
                true,
                &[
                    ("joint_limits", true),
                    ("velocity", true),
                    ("authority", true),
                ],
            ),
        );
        reporter.record_result(
            "ur10",
            "Violation",
            true,
            &make_verdict(
                false,
                &[
                    ("joint_limits", false),
                    ("velocity", true),
                    ("authority", true),
                ],
            ),
        );
        reporter.record_result(
            "humanoid_28dof",
            "Violation",
            true,
            &make_verdict(
                false,
                &[
                    ("joint_limits", false),
                    ("velocity", false),
                    ("authority", true),
                ],
            ),
        );
        let report = reporter.finalize();
        let jl = &report.per_check["joint_limits"];
        assert_eq!(jl.total, 3);
        assert_eq!(jl.passed, 1);
        assert_eq!(jl.failed, 2);
        let vel = &report.per_check["velocity"];
        assert_eq!(vel.total, 3);
        assert_eq!(vel.passed, 2);
        assert_eq!(vel.failed, 1);
        let auth = &report.per_check["authority"];
        assert_eq!(auth.total, 3);
        assert_eq!(auth.passed, 3);
        assert_eq!(auth.failed, 0);
    }

    // =========================================================================
    // Rate invariant tests across scenarios
    // =========================================================================

    #[test]
    fn approval_rate_invariant_mixed_profiles_and_scenarios() {
        let mut reporter = CampaignReporter::new("inv".into(), default_criteria());
        // Mix of profiles and scenarios
        for _ in 0..20 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..10 {
            reporter.record_result("ur10", "Baseline", false, &make_verdict(false, &[]));
        }
        for _ in 0..15 {
            reporter.record_result(
                "quadruped_12dof",
                "Violation",
                true,
                &make_verdict(false, &[]),
            );
        }
        for _ in 0..5 {
            reporter.record_result(
                "humanoid_28dof",
                "Violation",
                true,
                &make_verdict(true, &[]),
            );
        }
        let report = reporter.finalize();
        assert_eq!(report.total_commands, 50);
        assert_eq!(report.total_approved, 25); // 20 + 5
        assert_eq!(report.total_rejected, 25); // 10 + 15
        let sum = report.approval_rate + report.rejection_rate;
        assert!((sum - 1.0).abs() < 1e-12);
        assert_eq!(report.violation_escape_count, 5);
        assert!((report.violation_escape_rate - 5.0 / 20.0).abs() < 1e-10);
        assert_eq!(report.false_rejection_count, 10);
        assert!((report.false_rejection_rate - 10.0 / 30.0).abs() < 1e-10);
    }

    #[test]
    fn legitimate_pass_rate_across_profiles() {
        let mut reporter = CampaignReporter::new("lpr".into(), default_criteria());
        // 50 legitimate from panda: 48 approved, 2 rejected
        for _ in 0..48 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..2 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(false, &[]));
        }
        // 50 legitimate from ur10: 50 approved
        for _ in 0..50 {
            reporter.record_result("ur10", "Baseline", false, &make_verdict(true, &[]));
        }
        let report = reporter.finalize();
        // 98 out of 100 legitimate approved => 0.98
        assert!((report.legitimate_pass_rate - 0.98).abs() < f64::EPSILON);
    }

    // =========================================================================
    // Confidence stats: scaling and monotonicity
    // =========================================================================

    #[test]
    fn confidence_upper_bound_decreases_with_more_trials() {
        let conf_100 = compute_confidence(100, 0);
        let conf_1000 = compute_confidence(1000, 0);
        let conf_10000 = compute_confidence(10_000, 0);
        assert!(conf_1000.upper_bound_95 < conf_100.upper_bound_95);
        assert!(conf_10000.upper_bound_95 < conf_1000.upper_bound_95);
        assert!(conf_1000.upper_bound_99 < conf_100.upper_bound_99);
        assert!(conf_10000.upper_bound_99 < conf_1000.upper_bound_99);
    }

    #[test]
    fn confidence_bounds_monotonically_widen_with_confidence_level() {
        for &n in &[10u64, 100, 1000, 10_000, 100_000, 1_000_000] {
            let conf = compute_confidence(n, 0);
            assert!(
                conf.upper_bound_99 >= conf.upper_bound_95,
                "99% bound must >= 95% bound for n={n}"
            );
            assert!(
                conf.upper_bound_999 >= conf.upper_bound_99,
                "99.9% bound must >= 99% bound for n={n}"
            );
        }
    }

    #[test]
    fn mtbf_increases_with_more_trials_zero_escapes() {
        let conf_100 = compute_confidence(100, 0);
        let conf_10000 = compute_confidence(10_000, 0);
        assert!(
            conf_10000.mtbf_hours_95 > conf_100.mtbf_hours_95,
            "more trials with 0 escapes should increase MTBF"
        );
    }

    #[test]
    fn mtbf_finite_for_nonzero_escapes() {
        let conf = compute_confidence(1000, 5);
        assert!(conf.mtbf_hours_95.is_finite());
        assert!(conf.mtbf_hours_99.is_finite());
        assert!(conf.mtbf_hours_95 > 0.0);
        assert!(conf.mtbf_hours_99 > 0.0);
    }

    #[test]
    fn sil_rating_monotonically_increases_with_trials() {
        // With 0 escapes, more trials always means same or higher SIL
        let sil_1k = compute_confidence(1_000, 0).sil_rating;
        let sil_1m = compute_confidence(1_000_000, 0).sil_rating;
        let sil_100m = compute_confidence(100_000_000, 0).sil_rating;
        let sil_1b = compute_confidence(1_000_000_000, 0).sil_rating;
        assert!(sil_1m >= sil_1k);
        assert!(sil_100m >= sil_1m);
        assert!(sil_1b >= sil_100m);
    }

    // =========================================================================
    // Edge case: large mixed campaigns
    // =========================================================================

    #[test]
    fn large_mixed_campaign_accounting_invariants() {
        let mut reporter = CampaignReporter::new("big".into(), default_criteria());
        let profiles = ["franka_panda", "ur10", "quadruped_12dof", "humanoid_28dof"];
        let scenarios = ["Baseline", "Aggressive", "AuthEsc", "PromptInj"];

        // 4 profiles × 4 scenarios × 25 commands = 400 total
        for p in &profiles {
            for (i, s) in scenarios.iter().enumerate() {
                let expected_reject = i >= 2; // AuthEsc, PromptInj are adversarial
                let approved = !expected_reject; // Legitimate approved, adversarial rejected
                for _ in 0..25 {
                    reporter.record_result(p, s, expected_reject, &make_verdict(approved, &[]));
                }
            }
        }
        let report = reporter.finalize();
        assert_eq!(report.total_commands, 400);
        assert_eq!(report.total_approved, 200); // 4 profiles × 2 scenarios × 25
        assert_eq!(report.total_rejected, 200);
        assert_eq!(report.violation_escape_count, 0);
        assert_eq!(report.false_rejection_count, 0);
        assert_eq!(report.per_profile.len(), 4);
        assert_eq!(report.per_scenario.len(), 4);
        for p in &profiles {
            assert_eq!(report.per_profile[*p].total, 100);
        }
        for s in &scenarios {
            assert_eq!(report.per_scenario[*s].total, 100);
        }
    }

    #[test]
    fn single_command_per_profile_all_accounted() {
        let profiles = [
            "franka_panda",
            "ur10",
            "quadruped_12dof",
            "humanoid_28dof",
            "ur10e_haas_cell",
        ];
        let mut reporter = CampaignReporter::new("single".into(), default_criteria());
        for p in &profiles {
            reporter.record_result(p, "Baseline", false, &make_verdict(true, &[]));
        }
        let report = reporter.finalize();
        assert_eq!(report.total_commands, 5);
        assert_eq!(report.total_approved, 5);
        assert_eq!(report.per_profile.len(), 5);
    }

    #[test]
    fn scenario_stats_escape_and_false_rejection_exhaustive() {
        let mut reporter = CampaignReporter::new("exhaust".into(), default_criteria());
        // Violation: 3 correctly rejected, 1 escaped
        for _ in 0..3 {
            reporter.record_result("franka_panda", "Vio", true, &make_verdict(false, &[]));
        }
        reporter.record_result("franka_panda", "Vio", true, &make_verdict(true, &[]));
        // Legitimate: 4 approved, 1 false rejection
        for _ in 0..4 {
            reporter.record_result("franka_panda", "Leg", false, &make_verdict(true, &[]));
        }
        reporter.record_result("franka_panda", "Leg", false, &make_verdict(false, &[]));
        let report = reporter.finalize();
        let vio = &report.per_scenario["Vio"];
        assert_eq!(vio.escaped, 1);
        assert_eq!(vio.false_rejections, 0);
        assert_eq!(vio.expected_reject, 4);
        let leg = &report.per_scenario["Leg"];
        assert_eq!(leg.escaped, 0);
        assert_eq!(leg.false_rejections, 1);
        assert_eq!(leg.expected_reject, 0);
    }

    #[test]
    fn criteria_evaluation_with_mixed_profiles() {
        // Default criteria: 98% pass, 0% escape, 2% false rejection
        let mut reporter = CampaignReporter::new("crit".into(), default_criteria());
        // 100 legitimate from various profiles
        for _ in 0..50 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        for _ in 0..50 {
            reporter.record_result("ur10", "Baseline", false, &make_verdict(true, &[]));
        }
        // 50 violations correctly rejected
        for _ in 0..25 {
            reporter.record_result(
                "quadruped_12dof",
                "AuthEsc",
                true,
                &make_verdict(false, &[]),
            );
        }
        for _ in 0..25 {
            reporter.record_result("humanoid_28dof", "AuthEsc", true, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        assert!(
            report.criteria_met,
            "clean mixed campaign should pass criteria"
        );
        assert_eq!(report.violation_escape_count, 0);
        assert_eq!(report.false_rejection_count, 0);
    }

    #[test]
    fn criteria_fails_when_one_profile_has_escapes() {
        let mut reporter = CampaignReporter::new("esc".into(), default_criteria());
        for _ in 0..100 {
            reporter.record_result("franka_panda", "Baseline", false, &make_verdict(true, &[]));
        }
        // ur10 has one escape
        for _ in 0..9 {
            reporter.record_result("ur10", "Vio", true, &make_verdict(false, &[]));
        }
        reporter.record_result("ur10", "Vio", true, &make_verdict(true, &[]));
        let report = reporter.finalize();
        assert!(!report.criteria_met, "one escape should fail criteria");
    }

    #[test]
    fn report_serialization_round_trip() {
        let mut reporter = CampaignReporter::new("serde".into(), default_criteria());
        for _ in 0..10 {
            reporter.record_result(
                "franka_panda",
                "Baseline",
                false,
                &make_verdict(true, &[("check_a", true)]),
            );
        }
        let report = reporter.finalize();
        let json = serde_json::to_string(&report).expect("report must serialize");
        let back: CampaignReport = serde_json::from_str(&json).expect("report must deserialize");
        assert_eq!(back.campaign_name, "serde");
        assert_eq!(back.total_commands, 10);
        assert_eq!(back.total_approved, 10);
    }

    #[test]
    fn confidence_stats_included_in_report() {
        let mut reporter = CampaignReporter::new("conf".into(), default_criteria());
        // Record 100 violation commands, all rejected
        for _ in 0..100 {
            reporter.record_result("franka_panda", "Vio", true, &make_verdict(false, &[]));
        }
        let report = reporter.finalize();
        assert_eq!(report.confidence.n_trials, 100);
        assert_eq!(report.confidence.n_escapes, 0);
        assert!(report.confidence.upper_bound_95 > 0.0);
        assert!(report.confidence.upper_bound_95 < 0.1);
        assert!(!report.confidence.sil_rating_approximate);
    }
}
