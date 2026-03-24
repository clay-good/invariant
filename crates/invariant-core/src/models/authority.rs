use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use super::error::ValidationError;

// --- base64 serde helper for raw COSE bytes ---

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

// --- Operation newtype (P1-2) ---

/// A validated operation string (e.g., `"actuate:humanoid:left_arm:*"`).
///
/// Valid characters: alphanumeric, colon (`:`), hyphen (`-`), underscore (`_`),
/// asterisk (`*`), and dot (`.`). Must be non-empty and contain no whitespace.
///
/// Wildcard `*` is only meaningful at the leaf segment — matching is handled
/// by `pic::operations`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Operation(String);

impl Operation {
    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ValidationError::InvalidOperation(s));
        }
        if !s
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ':' | '-' | '_' | '*' | '.'))
        {
            return Err(ValidationError::InvalidOperation(s));
        }
        // Reject consecutive colons
        if s.contains("::") {
            return Err(ValidationError::InvalidOperation(s));
        }
        // Reject leading or trailing colons
        if s.starts_with(':') || s.ends_with(':') {
            return Err(ValidationError::InvalidOperation(s));
        }
        // Wildcard: only valid as bare "*" or trailing ":*"
        if s.contains('*') {
            if s == "*" {
                // bare wildcard OK
            } else if s.ends_with(":*") {
                // trailing wildcard OK, but no * in the prefix
                let prefix = &s[..s.len() - 2];
                if prefix.contains('*') {
                    return Err(ValidationError::InvalidOperation(s));
                }
            } else {
                return Err(ValidationError::InvalidOperation(s));
            }
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Operation {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for Operation {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Operation::new(s).map_err(serde::de::Error::custom)
    }
}

// --- PCA data types (P1-3, P1-4) ---

/// A Principal Capability Assertion (PCA) claim — the decoded payload of a
/// COSE_Sign1 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pca {
    /// Immutable origin principal (p_0). Must be identical across every hop.
    pub p_0: String,
    /// Operations granted at this hop. Must be a subset of the parent's ops (A2).
    pub ops: BTreeSet<Operation>,
    /// Key ID of the issuing signer.
    pub kid: String,
    /// Optional expiry (A3 temporal constraint). Replay is rejected after this time.
    pub exp: Option<DateTime<Utc>>,
    /// Optional not-before (A3 temporal constraint). Rejected before this time.
    pub nbf: Option<DateTime<Utc>>,
}

/// A COSE_Sign1-encoded PCA: raw bytes for signature verification.
///
/// The claim is decoded from the COSE payload during chain verification,
/// not stored alongside the raw bytes (prevents claim/payload mismatch attacks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPca {
    /// Raw COSE_Sign1 bytes (base64-encoded in JSON).
    #[serde(with = "base64_bytes")]
    pub raw: Vec<u8>,
}

/// A validated, decoded PIC authority chain.
///
/// Produced by `authority::chain::verify_chain` after verifying A1 (provenance),
/// A2 (monotonicity), and A3 (continuity) invariants across all hops.
///
/// Fields are private — only `verify_chain` can construct this type, preventing
/// callers from forging a validated chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorityChain {
    hops: Vec<SignedPca>,
    origin_principal: String,
    final_ops: BTreeSet<Operation>,
}

impl AuthorityChain {
    pub(crate) fn new(
        hops: Vec<SignedPca>,
        origin_principal: String,
        final_ops: BTreeSet<Operation>,
    ) -> Self {
        Self {
            hops,
            origin_principal,
            final_ops,
        }
    }

    pub fn hops(&self) -> &[SignedPca] {
        &self.hops
    }

    pub fn origin_principal(&self) -> &str {
        &self.origin_principal
    }

    pub fn final_ops(&self) -> &BTreeSet<Operation> {
        &self.final_ops
    }
}
