// Wildcard operation matching and monotonicity checks.

use std::collections::BTreeSet;

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

/// Check whether every operation in `child` is covered by at least one
/// operation in `parent`.  This is the A2 monotonicity check.
pub fn ops_are_subset(child: &BTreeSet<Operation>, parent: &BTreeSet<Operation>) -> bool {
    child
        .iter()
        .all(|c| parent.iter().any(|p| operation_matches(p, c)))
}

/// Check whether every required operation is covered by at least one
/// granted operation.  Used to verify that a command's required ops are
/// authorized by the chain's final ops.
pub fn ops_cover_required(granted: &BTreeSet<Operation>, required: &[Operation]) -> bool {
    required
        .iter()
        .all(|r| granted.iter().any(|g| operation_matches(g, r)))
}

/// Find the first required operation not covered by granted ops.
/// Returns `None` if all are covered.
pub fn first_uncovered_op<'a>(
    granted: &BTreeSet<Operation>,
    required: &'a [Operation],
) -> Option<&'a Operation> {
    required
        .iter()
        .find(|r| !granted.iter().any(|g| operation_matches(g, r)))
}
