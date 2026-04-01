// Wildcard operation matching and monotonicity checks.

use std::collections::{BTreeSet, HashSet};

use crate::models::authority::Operation;

/// Check whether a single granted operation covers a required operation.
///
/// Matching rules:
/// - Exact match: `"actuate:arm:shoulder"` covers `"actuate:arm:shoulder"`.
/// - Wildcard: `"actuate:arm:*"` covers `"actuate:arm:shoulder"` and
///   `"actuate:arm:elbow"`, but NOT `"actuate:leg:knee"`.
/// - A bare `"*"` covers everything.
/// - Wildcard is only meaningful at the leaf segment (after the last `:`).
///   `"actuate:*:shoulder"` is NOT a valid wildcard and is treated as a
///   literal match only.
pub fn operation_matches(granted: &Operation, required: &Operation) -> bool {
    let g = granted.as_str();
    let r = required.as_str();

    if g == r {
        return true;
    }

    // Bare wildcard covers everything.
    if g == "*" {
        return true;
    }

    // Check trailing wildcard: "prefix:*" covers "prefix:child" and deeper.
    // Does NOT cover the bare prefix itself (e.g., "a:b:*" does not cover "a:b").
    if let Some(prefix) = g.strip_suffix(":*") {
        if let Some(rest) = r.strip_prefix(prefix) {
            return rest.starts_with(':');
        }
    }

    false
}

/// Partition a granted-ops set into an exact-match `HashSet` (for O(1)
/// lookup) and a `Vec` of wildcard patterns (for sequential scan).
///
/// This is the shared building block for `ops_are_subset`,
/// `ops_cover_required`, and `first_uncovered_op`. Instead of scanning the
/// entire granted set for every required op (O(|child| * |parent|)), we first
/// try a constant-time exact lookup and only fall back to the wildcard list
/// when that misses.
fn partition_granted(granted: &BTreeSet<Operation>) -> (HashSet<&str>, Vec<&Operation>) {
    let mut exact: HashSet<&str> = HashSet::with_capacity(granted.len());
    let mut wildcards: Vec<&Operation> = Vec::new();
    for op in granted {
        let s = op.as_str();
        if s == "*" || s.ends_with(":*") {
            wildcards.push(op);
        } else {
            exact.insert(s);
        }
    }
    (exact, wildcards)
}

/// Returns `true` if `required` is covered by the pre-partitioned granted set.
#[inline]
fn is_covered(required: &Operation, exact: &HashSet<&str>, wildcards: &[&Operation]) -> bool {
    let r = required.as_str();
    // O(1) exact hit (also catches the bare "*" case when stored in exact, but
    // bare "*" is moved to wildcards by partition_granted, so it is always
    // checked in the wildcard loop below).
    if exact.contains(r) {
        return true;
    }
    wildcards.iter().any(|g| operation_matches(g, required))
}

/// Check whether every operation in `child` is covered by at least one
/// operation in `parent`.  This is the A2 monotonicity check.
pub fn ops_are_subset(child: &BTreeSet<Operation>, parent: &BTreeSet<Operation>) -> bool {
    let (exact, wildcards) = partition_granted(parent);
    child.iter().all(|c| is_covered(c, &exact, &wildcards))
}

/// Check whether every required operation is covered by at least one
/// granted operation.  Used to verify that a command's required ops are
/// authorized by the chain's final ops.
pub fn ops_cover_required(granted: &BTreeSet<Operation>, required: &[Operation]) -> bool {
    let (exact, wildcards) = partition_granted(granted);
    required.iter().all(|r| is_covered(r, &exact, &wildcards))
}

/// Find the first required operation not covered by granted ops.
/// Returns `None` if all are covered.
pub fn first_uncovered_op<'a>(
    granted: &BTreeSet<Operation>,
    required: &'a [Operation],
) -> Option<&'a Operation> {
    let (exact, wildcards) = partition_granted(granted);
    required.iter().find(|r| !is_covered(r, &exact, &wildcards))
}
