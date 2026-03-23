use serde::{Deserialize, Serialize};

/// A Principal Capability Assertion (PCA) in the authority chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pca {
    /// Immutable origin principal (p_0). Must be the same across all hops.
    pub p_0: String,
    /// Operations granted at this hop. Must be a subset of the parent's ops.
    pub ops: Vec<String>,
    /// Key ID of the signer.
    pub kid: String,
    /// Optional expiry (ISO 8601).
    pub exp: Option<String>,
    /// Optional not-before (ISO 8601).
    pub nbf: Option<String>,
}

/// A COSE_Sign1-encoded PCA with its raw bytes and decoded claim.
#[derive(Debug, Clone)]
pub struct SignedPca {
    pub raw: Vec<u8>,
    pub claim: Pca,
}

/// A validated, decoded authority chain.
#[derive(Debug, Clone)]
pub struct AuthorityChain {
    pub hops: Vec<SignedPca>,
    pub origin_principal: String,
    pub final_ops: Vec<String>,
}

/// An operation string (e.g., "actuate:humanoid:left_arm:*").
pub type Operation = String;
