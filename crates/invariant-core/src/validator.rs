//! Generic validation pipeline.
//!
//! This is the skeleton sketched in Section 2 of `INVARIANT_UNIFICATION_SPEC.md`.
//! The wire-format envelope/audit/verdict types it needs are part of
//! **Phase 1b** (generification of `audit.rs`, `envelopes.rs`, etc.). The
//! signatures here define the contract.

use crate::models::authority::AuthorityChain;
use crate::traits::{CheckContext, CheckResult, DomainCheck, DomainProfile, ValidationInput};
use serde::{Deserialize, Serialize};

/// Verdict produced by `Validator::validate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationVerdict {
    /// Domain string (from `ValidationInput::domain`).
    pub domain: String,
    /// Whether the overall validation passed.
    pub accepted: bool,
    /// Per-check results, in execution order.
    pub checks: Vec<NamedCheckResult>,
    /// SHA-256 of the input payload (audit chain key).
    pub content_hash_hex: String,
}

/// A `CheckResult` annotated with the check that produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedCheckResult {
    /// Check identifier (e.g. `"P1"`).
    pub id: String,
    /// Check display name.
    pub name: String,
    /// Outcome.
    pub result: CheckResult,
}

/// Validator pipeline generic over a `ValidationInput`.
///
/// Construct via [`Validator::new`], populate `checks`, then call
/// [`Validator::validate`].
pub struct Validator<I: ValidationInput> {
    profile: Box<dyn DomainProfile>,
    checks: Vec<Box<dyn DomainCheck<I>>>,
}

impl<I: ValidationInput> Validator<I> {
    /// Construct a validator with a profile and zero checks.
    pub fn new(profile: Box<dyn DomainProfile>) -> Self {
        Self {
            profile,
            checks: Vec::new(),
        }
    }

    /// Register a domain check. Checks run in registration order.
    pub fn add_check(&mut self, check: Box<dyn DomainCheck<I>>) -> &mut Self {
        self.checks.push(check);
        self
    }

    /// Run the pipeline.
    ///
    /// Steps:
    /// 1. Verify the authority chain monotonicity (callers pass an already-verified chain).
    /// 2. Verify `input.operations() ⊆ chain.terminal_operations()`.
    /// 3. Run every `DomainCheck` in order.
    /// 4. Return the aggregate verdict.
    ///
    /// Audit-log append is the caller's responsibility (the audit module will be
    /// generified in Phase 1b and wired in here).
    pub fn validate(&self, input: &I, chain: &AuthorityChain) -> ValidationVerdict {
        let ctx = CheckContext {
            chain,
            profile: self.profile.as_ref(),
        };
        let mut results = Vec::with_capacity(self.checks.len());
        let mut accepted = true;
        for check in &self.checks {
            let r = check.run(input, &ctx);
            if matches!(r, CheckResult::Fail { .. }) {
                accepted = false;
            }
            results.push(NamedCheckResult {
                id: check.id().to_string(),
                name: check.name().to_string(),
                result: r,
            });
        }
        let hash = input.content_hash();
        ValidationVerdict {
            domain: input.domain().to_string(),
            accepted,
            checks: results,
            content_hash_hex: hex_encode(&hash),
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
