//! Domain-agnostic traits implemented by domain crates (`invariant-robotics`,
//! `invariant-biosynthesis`).
//!
//! See Section 2 of `INVARIANT_UNIFICATION_SPEC.md` for the design rationale.

use crate::models::authority::Operation;
use serde::{Deserialize, Serialize};

/// Input that can be validated through the PIC/PCA pipeline.
///
/// Implemented by `robotics::Command` and `biosynthesis::SynthesisBundle`.
pub trait ValidationInput: Serialize + for<'de> Deserialize<'de> + Send + Sync {
    /// Stable string identifying the domain (e.g. `"robotics"`, `"biosynthesis"`).
    /// Used in audit log entries and CLI dispatch.
    fn domain(&self) -> &'static str;

    /// The PCA-protected operation(s) this input claims authority for.
    /// Must match against the `AuthorityChain`'s narrowed operation set.
    fn operations(&self) -> Vec<Operation>;

    /// Stable hash of the input payload for audit chaining and replay detection.
    fn content_hash(&self) -> [u8; 32];

    /// Short human-readable summary for audit log / CLI output.
    fn summary(&self) -> String {
        format!("{} input ({} ops)", self.domain(), self.operations().len())
    }
}

/// A domain-specific check that runs after PCA validation succeeds.
///
/// Robotics impls: P1..P25 physics checks.
/// Biosynthesis impls: D1..D10, P1..P10, C1..C10.
pub trait DomainCheck<I: ValidationInput>: Send + Sync {
    /// Stable identifier (e.g. `"P1"`, `"D3"`, `"C7"`).
    fn id(&self) -> &'static str;
    /// Human-readable name.
    fn name(&self) -> &'static str;
    /// Run the check against an input and emit a result.
    fn run(&self, input: &I, ctx: &CheckContext<'_>) -> CheckResult;
}

/// Context passed to every `DomainCheck::run` call.
pub struct CheckContext<'a> {
    /// The PCA chain that gated this input.
    pub chain: &'a crate::models::authority::AuthorityChain,
    /// The domain profile (robot URDF + limits, synthesizer capabilities).
    pub profile: &'a dyn DomainProfile,
}

/// Outcome of a single `DomainCheck`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CheckResult {
    /// The check passed.
    Pass,
    /// The check failed; the input must be rejected.
    Fail {
        /// Why the check failed.
        reason: String,
        /// Structured evidence (numeric thresholds, offending fields, etc.).
        evidence: serde_json::Value,
    },
    /// The check was skipped (e.g. capability not configured on this profile).
    Skip {
        /// Why the check was skipped.
        reason: String,
    },
}

/// Domain-specific profile (robot URDF + limits, synthesizer capabilities).
///
/// `as_any` is the pragmatic escape hatch: domain checks downcast at the
/// boundary to access their concrete profile type. The alternative (an
/// associated type) propagates type parameters everywhere and breaks
/// `dyn`-compatibility.
pub trait DomainProfile: Send + Sync {
    /// Stable profile identifier (e.g. `"ur10e"`, `"dna-synth-v1"`).
    fn id(&self) -> &str;
    /// Domain this profile belongs to.
    fn domain(&self) -> &'static str;
    /// Downcast hook for domain checks to reach the concrete profile type.
    fn as_any(&self) -> &dyn std::any::Any;
}
