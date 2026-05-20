//! Bio-firewall `ValidationError` taxonomy.
//!
//! `AuthorityError` lives in [`invariant_core::models::error`] and is re-used
//! verbatim. Only the bio-specific `ValidationError` and `Validate` trait
//! are defined here so they can carry bundle/profile-shaped variants without
//! polluting the shared core.

use thiserror::Error;

// Re-export AuthorityError from invariant-core for legacy import paths.
pub use invariant_core::models::error::AuthorityError;

/// Errors produced when validating bio-firewall model types (profiles, bundles,
/// screening inputs, etc.).
#[derive(Debug, Error, PartialEq)]
pub enum ValidationError {
    /// An operation string is empty, all-whitespace, or contains disallowed characters.
    #[error("operation string is invalid (empty, whitespace, or disallowed characters): {0:?}")]
    InvalidOperation(String),

    /// The authority chain is empty (must have at least one hop).
    #[error("authority chain must have at least one hop")]
    EmptyAuthorityChain,

    /// A collection exceeds its maximum allowed size.
    #[error("collection '{name}' has {count} elements, exceeding maximum of {max}")]
    CollectionTooLarge {
        /// Name of the collection that is too large.
        name: &'static str,
        /// Actual number of elements in the collection.
        count: usize,
        /// Maximum permitted number of elements.
        max: usize,
    },

    /// A generic profile-level field is invalid.
    #[error("profile field '{field}' invalid: {reason}")]
    ProfileFieldInvalid {
        /// Name of the offending profile field.
        field: &'static str,
        /// Human-readable description of the specific violation.
        reason: String,
    },

    /// A synthesis bundle field is invalid.
    #[error("bundle field '{field}' invalid: {reason}")]
    BundleFieldInvalid {
        /// Name of the offending bundle field.
        field: &'static str,
        /// Human-readable description of the specific violation.
        reason: String,
    },
}

/// Types that can be checked for semantic correctness after construction.
pub trait Validate {
    /// Checks this value for semantic correctness, returning an error if any constraint is violated.
    fn validate(&self) -> Result<(), ValidationError>;
}
