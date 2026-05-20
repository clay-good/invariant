//! Differential validation: dual-instance verdict comparison.
//!
//! The comparison logic is domain-agnostic — it inspects only the structural
//! shape of a verdict (approval, command hash + sequence, per-check
//! pass/fail). Domain crates implement [`VerdictView`] / [`CheckView`] on
//! their concrete `Verdict` and `CheckResult` types and call
//! [`compare_verdicts`] from a thin per-domain `DifferentialValidator`
//! wrapper.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Trait surface
// ---------------------------------------------------------------------------

/// Read-only view of a single check result, for use in differential comparison.
pub trait CheckView {
    /// Stable check identifier (e.g. `"joint_limits"`, `"dna_screening"`).
    fn name(&self) -> &str;
    /// Check category (e.g. `"physics"`, `"invariant"`).
    fn category(&self) -> &str;
    /// Whether the check passed.
    fn passed(&self) -> bool;
    /// Free-form details emitted by the check.
    fn details(&self) -> &str;
}

/// Read-only view of a verdict, for use in differential comparison.
pub trait VerdictView {
    /// Concrete check view type.
    type Check: CheckView;
    /// Whether the overall verdict approves the input.
    fn approved(&self) -> bool;
    /// Hex-encoded SHA-256 of the input payload.
    fn command_hash(&self) -> &str;
    /// Monotonic sequence number copied from the input.
    fn command_sequence(&self) -> u64;
    /// Per-check results, in execution order.
    fn checks(&self) -> &[Self::Check];
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// A single check-level disagreement between the two validator instances.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckDisagreement {
    /// Name of the check that disagreed.
    pub check_name: String,
    /// Category of the check (e.g. "authority", "physics").
    pub category: String,
    /// Whether instance A passed this check.
    pub instance_a_passed: bool,
    /// Whether instance B passed this check.
    pub instance_b_passed: bool,
    /// Details from instance A.
    pub instance_a_details: String,
    /// Details from instance B.
    pub instance_b_details: String,
}

/// The result of a differential validation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialResult {
    /// Whether the two instances agree on the approval decision.
    pub approval_agrees: bool,
    /// Instance A's approval decision.
    pub instance_a_approved: bool,
    /// Instance B's approval decision.
    pub instance_b_approved: bool,
    /// Check-level disagreements (empty if all checks agree).
    pub check_disagreements: Vec<CheckDisagreement>,
    /// Number of checks that both instances evaluated.
    pub total_checks: usize,
    /// Number of checks where both instances agree.
    pub agreeing_checks: usize,
    /// The command hash from instance A (should match instance B).
    pub command_hash: String,
    /// The command sequence number.
    pub command_sequence: u64,
}

impl DifferentialResult {
    /// Returns true if both instances fully agree (approval + all checks).
    pub fn fully_agrees(&self) -> bool {
        self.approval_agrees && self.check_disagreements.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Comparison logic
// ---------------------------------------------------------------------------

/// Compare two verdicts and produce a `DifferentialResult`.
///
/// Pure function — no I/O, no signing keys, no side effects. Both verdict
/// types are expected to be the same Rust type (a single `V` parameter), so
/// callers naturally cannot accidentally compare across domains.
pub fn compare_verdicts<V: VerdictView>(a: &V, b: &V) -> DifferentialResult {
    let approval_agrees = a.approved() == b.approved();

    let mut disagreements = Vec::new();
    let mut agreeing = 0usize;

    let a_checks = a.checks();
    let b_checks = b.checks();

    for check_a in a_checks {
        if let Some(check_b) = b_checks.iter().find(|c| c.name() == check_a.name()) {
            if checks_disagree(check_a, check_b) {
                disagreements.push(CheckDisagreement {
                    check_name: check_a.name().to_string(),
                    category: check_a.category().to_string(),
                    instance_a_passed: check_a.passed(),
                    instance_b_passed: check_b.passed(),
                    instance_a_details: check_a.details().to_string(),
                    instance_b_details: check_b.details().to_string(),
                });
            } else {
                agreeing += 1;
            }
        } else {
            disagreements.push(CheckDisagreement {
                check_name: check_a.name().to_string(),
                category: check_a.category().to_string(),
                instance_a_passed: check_a.passed(),
                instance_b_passed: false,
                instance_a_details: check_a.details().to_string(),
                instance_b_details: "check not present in instance B".into(),
            });
        }
    }

    for check_b in b_checks {
        if !a_checks.iter().any(|c| c.name() == check_b.name()) {
            disagreements.push(CheckDisagreement {
                check_name: check_b.name().to_string(),
                category: check_b.category().to_string(),
                instance_a_passed: false,
                instance_a_details: "check not present in instance A".into(),
                instance_b_passed: check_b.passed(),
                instance_b_details: check_b.details().to_string(),
            });
        }
    }

    let total_checks = a_checks.len().max(b_checks.len());

    DifferentialResult {
        approval_agrees,
        instance_a_approved: a.approved(),
        instance_b_approved: b.approved(),
        check_disagreements: disagreements,
        total_checks,
        agreeing_checks: agreeing,
        command_hash: a.command_hash().to_string(),
        command_sequence: a.command_sequence(),
    }
}

/// Two checks disagree if their pass/fail status differs.
fn checks_disagree<C: CheckView + ?Sized>(a: &C, b: &C) -> bool {
    a.passed() != b.passed()
}
