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
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
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
///
/// # Examples
///
/// ```
/// use invariant_core::models::authority::Operation;
/// use invariant_core::models::error::ValidationError;
///
/// // Valid operations
/// let op = Operation::new("actuate:humanoid:left_arm:*").unwrap();
/// assert_eq!(op.as_str(), "actuate:humanoid:left_arm:*");
///
/// let op2 = Operation::new("actuate:arm:joints").unwrap();
/// assert_eq!(op2.as_str(), "actuate:arm:joints");
///
/// // Bare wildcard
/// let wildcard = Operation::new("*").unwrap();
/// assert_eq!(wildcard.as_str(), "*");
///
/// // Invalid operations
/// assert!(matches!(
///     Operation::new(""),
///     Err(ValidationError::InvalidOperation(_))
/// ));
/// assert!(matches!(
///     Operation::new("bad op"),  // whitespace not allowed
///     Err(ValidationError::InvalidOperation(_))
/// ));
/// assert!(matches!(
///     Operation::new("::leading-colon"),
///     Err(ValidationError::InvalidOperation(_))
/// ));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Operation(String);

impl Operation {
    /// Validate and construct an `Operation` from a string.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_core::models::authority::Operation;
    ///
    /// assert!(Operation::new("actuate:arm:*").is_ok());
    /// assert!(Operation::new("sensor.read:imu-1").is_ok());
    /// assert!(Operation::new("").is_err());
    /// assert!(Operation::new("a::b").is_err());  // consecutive colons
    /// assert!(Operation::new("a:*:b").is_err());  // wildcard not at leaf
    /// ```
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

    /// Return the underlying operation string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_core::models::authority::Operation;
    ///
    /// let op = Operation::new("actuate:gripper:close").unwrap();
    /// assert_eq!(op.as_str(), "actuate:gripper:close");
    ///
    /// // Useful for pattern matching and logging
    /// assert!(op.as_str().starts_with("actuate:"));
    /// ```
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
///
/// # Examples
///
/// ```
/// use std::collections::BTreeSet;
/// use invariant_core::models::authority::{Pca, Operation};
///
/// let mut ops = BTreeSet::new();
/// ops.insert(Operation::new("actuate:arm:*").unwrap());
/// ops.insert(Operation::new("actuate:gripper:*").unwrap());
///
/// let pca = Pca {
///     p_0: "safety-officer@example.com".into(),
///     ops,
///     kid: "validator-key-001".into(),
///     exp: Some(
///         chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
///             .unwrap()
///             .with_timezone(&chrono::Utc),
///     ),
///     nbf: None,
///     predecessor_digest: [0u8; 32], // v11 1.2 — all-zero at root.
/// };
///
/// assert_eq!(pca.p_0, "safety-officer@example.com");
/// assert_eq!(pca.ops.len(), 2);
/// assert!(pca.exp.is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    /// v11 1.2 — A3 causal binding. SHA-256 of `canonical_bytes(parent)` for
    /// hops at index ≥ 1; all-zero (the `Default` value) for the root hop or
    /// for legacy chains that have not been migrated to set the digest yet.
    /// `#[serde(default)]` keeps pre-v11-1.2 serialized chains parseable.
    ///
    /// **Phased enforcement:** `verify_chain` enforces this binding only when
    /// at least one hop in the chain has a non-zero digest (opt-in
    /// detection). Once every chain producer in the workspace migrates to
    /// set the field, the cutover to mandatory enforcement is a one-line
    /// change in `verify_chain`.
    #[serde(default, with = "predecessor_digest_serde")]
    pub predecessor_digest: [u8; 32],
}

impl Pca {
    /// Canonical byte representation of the claim for v11 1.2's
    /// per-hop SHA-256 binding. Length-prefixed, big-endian framing —
    /// the same shape as v11 1.1's `audit::canonical_bytes`. The
    /// `predecessor_digest` field is excluded from the preimage so a
    /// hop's digest can be computed without needing its child's digest.
    ///
    /// Field order (each prefixed with a single byte type tag + a
    /// big-endian length):
    ///
    /// 1. `p_0`        — tag `0x01`, UTF-8 bytes
    /// 2. `ops`        — tag `0x04`, count (u32 BE) then per-op tag `0x01` + len + bytes
    /// 3. `kid`        — tag `0x01`, UTF-8 bytes
    /// 4. `exp_ms`     — tag `0x02`, i64 BE Unix milliseconds (0x00…00 when None)
    /// 5. `nbf_ms`     — tag `0x02`, i64 BE Unix milliseconds (0x00…00 when None)
    ///
    /// `exp` / `nbf` are always emitted (sentinel `0x00…00` when absent) so
    /// the preimage shape is stable regardless of which fields are set.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(128);
        // p_0
        out.push(0x01);
        let p0_bytes = self.p_0.as_bytes();
        out.extend_from_slice(&(p0_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(p0_bytes);
        // ops — sorted by BTreeSet's iter order, which is the canonical
        // ordering used everywhere in the protocol.
        out.push(0x04);
        out.extend_from_slice(&(self.ops.len() as u32).to_be_bytes());
        for op in &self.ops {
            out.push(0x01);
            let b = op.as_str().as_bytes();
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        }
        // kid
        out.push(0x01);
        let kid_bytes = self.kid.as_bytes();
        out.extend_from_slice(&(kid_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(kid_bytes);
        // exp / nbf — always emitted as i64 BE; 0 == not present.
        out.push(0x02);
        let exp_ms = self.exp.map(|t| t.timestamp_millis()).unwrap_or(0);
        out.extend_from_slice(&exp_ms.to_be_bytes());
        out.push(0x02);
        let nbf_ms = self.nbf.map(|t| t.timestamp_millis()).unwrap_or(0);
        out.extend_from_slice(&nbf_ms.to_be_bytes());
        out
    }

    /// SHA-256 over `Pca::canonical_bytes` — the digest a child hop
    /// stamps into its own `predecessor_digest` field.
    pub fn sha256_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let bytes = self.canonical_bytes();
        let mut h = Sha256::new();
        h.update(&bytes);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }
}

/// JSON helper: serialize `[u8; 32]` as a 64-char lowercase hex string and
/// deserialize from the same. `#[serde(default)]` handles missing fields
/// (legacy chains) by returning the all-zero array.
mod predecessor_digest_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        ser.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        if s.is_empty() {
            return Ok([0u8; 32]);
        }
        if s.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "predecessor_digest: expected 64 hex chars, got {}",
                s.len()
            )));
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| {
                serde::de::Error::custom(format!("predecessor_digest hex byte {i}: {e}"))
            })?;
        }
        Ok(out)
    }
}

/// A COSE_Sign1-encoded PCA: raw bytes for signature verification.
///
/// The claim is decoded from the COSE payload during chain verification,
/// not stored alongside the raw bytes (prevents claim/payload mismatch attacks).
///
/// # Examples
///
/// ```
/// use invariant_core::models::authority::SignedPca;
///
/// // In production the bytes come from a COSE_Sign1 signing operation.
/// // Here we use a placeholder to illustrate the struct layout.
/// let signed = SignedPca {
///     raw: vec![0xd2, 0x84, 0x40, 0xa0, 0x40, 0x40],  // minimal COSE stub
/// };
///
/// assert!(!signed.raw.is_empty());
/// assert_eq!(signed.raw[0], 0xd2);
/// ```
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
///
/// # Examples
///
/// ```
/// // AuthorityChain is constructed only by verify_chain. This example shows
/// // the accessor methods available on a verified chain.
/// // (Constructing via the public API requires a real signed PCA chain.)
/// use invariant_core::models::authority::Operation;
///
/// // The final_ops set on a chain determines which operations can be authorized.
/// let op = Operation::new("actuate:arm:joints").unwrap();
/// assert_eq!(op.as_str(), "actuate:arm:joints");
/// ```
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

    /// Returns all signed PCA hops in the chain (from root to leaf).
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_core::models::authority::SignedPca;
    ///
    /// // In production, hops() is called on an AuthorityChain returned by verify_chain.
    /// // Here we illustrate that SignedPca carries raw COSE bytes.
    /// let hop = SignedPca { raw: vec![0xd2, 0x84] };
    /// assert_eq!(hop.raw.len(), 2);
    /// ```
    pub fn hops(&self) -> &[SignedPca] {
        &self.hops
    }

    /// Returns the immutable origin principal (p_0) common to all hops.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_core::models::authority::Operation;
    ///
    /// // The origin principal never changes across hops (A1 invariant).
    /// // Illustrating the type used to carry it:
    /// let p0 = "safety-officer@acme.com".to_string();
    /// assert!(p0.contains('@'));
    /// ```
    pub fn origin_principal(&self) -> &str {
        &self.origin_principal
    }

    /// Returns the final (leaf) operation set granted by the chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_core::models::authority::Operation;
    /// use std::collections::BTreeSet;
    ///
    /// // final_ops() is the set used for operation coverage checks.
    /// let mut ops: BTreeSet<Operation> = BTreeSet::new();
    /// ops.insert(Operation::new("actuate:arm:*").unwrap());
    /// assert!(ops.contains(&Operation::new("actuate:arm:*").unwrap()));
    /// ```
    pub fn final_ops(&self) -> &BTreeSet<Operation> {
        &self.final_ops
    }
}
