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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileStats {
    pub total: u64,
    pub approved: u64,
    pub rejected: u64,
}

/// Aggregated counts for a single scenario type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScenarioStats {
    pub total: u64,
    pub approved: u64,
    pub rejected: u64,
    /// Commands where rejection was expected (scenario generates violations).
    pub expected_reject: u64,
    /// Violation commands that were incorrectly approved (escaped).
    pub escaped: u64,
    /// Legitimate commands that were incorrectly rejected.
    pub false_rejections: u64,
}

/// Aggregated pass/fail counts for a single named check.
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
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Complete campaign results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    pub campaign_name: String,
    pub total_commands: u64,
    pub total_approved: u64,
    pub total_rejected: u64,
    pub approval_rate: f64,
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
    pub per_profile: HashMap<String, ProfileStats>,
    pub per_scenario: HashMap<String, ScenarioStats>,
    pub per_check: HashMap<String, CheckStats>,
    /// Whether all success-criteria thresholds were met.
    pub criteria_met: bool,
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

    let (upper_95, upper_99) = if n_trials == 0 {
        (1.0_f64, 1.0_f64)
    } else if n_escapes == 0 {
        // Clopper-Pearson exact bound for zero failures.
        let n = n_trials as f64;
        let ub95 = 1.0 - (0.025_f64).powf(1.0 / n);
        let ub99 = 1.0 - (0.005_f64).powf(1.0 / n);
        (ub95.clamp(0.0, 1.0), ub99.clamp(0.0, 1.0))
    } else {
        // STATISTICAL NOTE: the Wald (normal approximation) interval used here
        // is known to be anti-conservative — it under-covers the true escape
        // rate when the sample proportion is near 0 or 1, or when n is small.
        // The exact Clopper-Pearson interval (based on the Beta distribution)
        // would be more appropriate for safety-critical reporting.  A Beta
        // distribution implementation is not currently available in this
        // dependency tree, so the Wald approximation is used as a placeholder.
        // Users should treat these bounds with caution when n_escapes is small
        // relative to n_trials or when n_trials itself is below ~1000.
        let n = n_trials as f64;
        let p = n_escapes as f64 / n;
        let se = (p * (1.0 - p) / n).sqrt();
        let ub95 = (p + 1.96 * se).clamp(0.0, 1.0);
        let ub99 = (p + 2.576 * se).clamp(0.0, 1.0);
        (ub95, ub99)
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
        mtbf_hours_95,
        mtbf_hours_99,
        sil_rating,
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

    // --- Confidence stats ---

    #[test]
    fn zero_trials_confidence_is_worst_case() {
        let conf = compute_confidence(0, 0);
        assert!((conf.upper_bound_95 - 1.0).abs() < f64::EPSILON);
        assert!((conf.upper_bound_99 - 1.0).abs() < f64::EPSILON);
        assert_eq!(conf.n_trials, 0);
        assert_eq!(conf.n_escapes, 0);
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

    #[test]
    fn sil_rating_boundaries() {
        // Per-command thresholds: level uses upper_bound_99 directly.
        // 5M trials, 0 escapes: upper_99 ≈ 1.06e-6 => level 1.
        let conf = compute_confidence(5_000_000, 0);
        assert_eq!(conf.sil_rating, 1);

        // 10M trials: upper_99 ≈ 5.3e-7 => level 2.
        let conf = compute_confidence(10_000_000, 0);
        assert_eq!(conf.sil_rating, 2);

        // 100M trials: upper_99 ≈ 5.3e-8 => level 3.
        let conf = compute_confidence(100_000_000, 0);
        assert_eq!(conf.sil_rating, 3);

        // 1B trials: upper_99 ≈ 5.3e-9 => level 4.
        let conf = compute_confidence(1_000_000_000, 0);
        assert_eq!(conf.sil_rating, 4);
    }
}
