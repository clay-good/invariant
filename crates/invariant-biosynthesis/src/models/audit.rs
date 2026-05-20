//! Audit log entry types — re-exported from `invariant-core` with concrete
//! input/verdict types bound for the biosynthesis domain.
//!
//! The hash-chain + signed-entry shape lives in
//! [`invariant_core::models::audit`]; this module only fixes the generic
//! parameters to biosynthesis's [`SynthesisBundle`] and [`SignedVerdict`].
//! On-disk JSONL is identical to the robotics audit schema (the bundle is
//! serialized under the legacy field name `command`) — both tools can read
//! each other's logs.

use super::bundle::SynthesisBundle;
use super::verdict::SignedVerdict;

/// Biosynthesis audit entry: stores the full [`SynthesisBundle`] plus the [`SignedVerdict`].
pub type AuditEntry = invariant_core::models::audit::AuditEntry<SynthesisBundle, SignedVerdict>;

/// Signed biosynthesis audit entry — an [`AuditEntry`] plus an Ed25519 entry signature.
pub type SignedAuditEntry =
    invariant_core::models::audit::SignedAuditEntry<SynthesisBundle, SignedVerdict>;
