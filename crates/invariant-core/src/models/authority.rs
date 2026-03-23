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

/// A COSE_Sign1-encoded PCA: raw bytes for signature verification plus decoded claim.
///
/// Both fields are serialisable so the chain can appear in audit logs and verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPca {
    /// Raw COSE_Sign1 bytes (base64-encoded in JSON).
    #[serde(with = "base64_bytes")]
    pub raw: Vec<u8>,
    /// Decoded PCA claim (used for chain validation logic).
    pub claim: Pca,
}

/// A validated, decoded PIC authority chain.
///
/// Produced by `pic::chain` after verifying A1 (provenance), A2 (monotonicity),
/// and A3 (continuity) invariants across all hops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityChain {
    /// The ordered sequence of verified signed PCAs (at least one hop required).
    pub hops: Vec<SignedPca>,
    /// The origin principal (p_0) — invariant across all hops (A1).
    pub origin_principal: String,
    /// The narrowest set of operations after monotonicity reduction (A2).
    pub final_ops: BTreeSet<Operation>,
}
