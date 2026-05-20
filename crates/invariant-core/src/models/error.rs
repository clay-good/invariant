use thiserror::Error;

/// Errors produced during PCA chain verification (A1, A2, A3).
///
/// # Examples
///
/// ```
/// use invariant_core::models::error::AuthorityError;
///
/// let err = AuthorityError::EmptyChain;
/// assert_eq!(err.to_string(), "authority chain must have at least one hop");
///
/// let err = AuthorityError::ChainTooLong { len: 10, max: 4 };
/// assert!(err.to_string().contains("10"));
///
/// let err = AuthorityError::Expired {
///     hop: 0,
///     exp: "2024-01-01T00:00:00Z".into(),
/// };
/// assert!(matches!(err, AuthorityError::Expired { hop: 0, .. }));
/// ```
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum AuthorityError {
    /// The authority chain contains no hops.
    #[error("authority chain must have at least one hop")]
    EmptyChain,

    /// The authority chain exceeds the allowed maximum number of hops.
    #[error("chain has {len} hops, exceeding maximum of {max}")]
    ChainTooLong {
        /// Actual number of hops in the chain.
        len: usize,
        /// Maximum permitted number of hops.
        max: usize,
    },

    /// Serialization of a chain element failed.
    #[error("serialization failed: {reason}")]
    SerializationError {
        /// Human-readable description of the serialization failure.
        reason: String,
    },

    // Principal names are redacted in the Display output to avoid leaking
    // identity information in logs, API responses, or rejection verdicts.
    // The full values are retained in the struct fields for internal
    // diagnostics — access them directly when a detailed audit trail is needed.
    /// A1 provenance violation: the p_0 principal differs between hops.
    #[error(
        "A1 provenance violation: p_0 differs at hop {hop} (expected <redacted>, got <redacted>)"
    )]
    ProvenanceMismatch {
        /// Index of the hop where the mismatch was detected.
        hop: usize,
        /// Expected p_0 principal value (retained for internal diagnostics).
        expected: String,
        /// Actual p_0 principal value found at this hop.
        got: String,
    },

    /// A2 monotonicity violation: a hop grants an operation not covered by its parent.
    #[error("A2 monotonicity violation: hop {hop} operation {op:?} is not covered by parent ops")]
    MonotonicityViolation {
        /// Index of the hop that introduced the uncovered operation.
        hop: usize,
        /// The operation string that violated monotonicity.
        op: String,
    },

    /// A3 causal binding violation (v11 1.2): the `predecessor_digest` at a
    /// hop does not match `sha256(canonical_bytes(parent))`. Defends against
    /// cross-chain splice attacks (G-09) where an attacker stitches a hop
    /// from one valid chain into another with a different parent.
    #[error("A3 causal binding: hop {hop} predecessor_digest does not match parent")]
    PredecessorDigestMismatch {
        /// Index of the hop whose `predecessor_digest` is wrong.
        hop: usize,
    },

    /// A3 causal binding violation (v11 1.2): the root hop (index 0) carries
    /// a non-zero `predecessor_digest`. Roots, by construction, have no
    /// parent and must stamp the all-zero sentinel.
    #[error("A3 causal binding: root hop carries non-zero predecessor_digest")]
    PredecessorDigestNonZeroAtRoot,

    /// A3 continuity violation: the cryptographic signature at a hop failed verification.
    #[error("A3 continuity: signature verification failed at hop {hop}: {reason}")]
    SignatureInvalid {
        /// Index of the hop whose signature was invalid.
        hop: usize,
        /// Reason the signature verification failed.
        reason: String,
    },

    // kid is redacted in the Display output for the same reason as
    // ProvenanceMismatch above.
    /// A3 continuity violation: the key identifier at a hop is not in the trusted key set.
    #[error("A3 continuity: unknown key id <redacted> at hop {hop}")]
    UnknownKeyId {
        /// Index of the hop that referenced the unknown key.
        hop: usize,
        /// Key identifier that was not found in the trusted key set.
        kid: String,
    },

    /// A PCA token at the given hop has passed its expiry timestamp.
    #[error("PCA at hop {hop} has expired (exp={exp})")]
    Expired {
        /// Index of the hop whose token has expired.
        hop: usize,
        /// Expiry timestamp from the token (`exp` claim), as an ISO-8601 string.
        exp: String,
    },

    /// A PCA token at the given hop is not yet valid (before its `nbf` timestamp).
    #[error("PCA at hop {hop} is not yet valid (nbf={nbf})")]
    NotYetValid {
        /// Index of the hop whose token is not yet valid.
        hop: usize,
        /// Not-before timestamp from the token (`nbf` claim), as an ISO-8601 string.
        nbf: String,
    },

    /// COSE decoding of a token at the given hop failed.
    ///
    /// Kept for backwards compatibility with downstream consumers that may
    /// still pattern-match this variant. Internal call sites in
    /// `authority/crypto.rs` were migrated to [`AuthorityError::CoseDecode`]
    /// in v10-14 (2026-05-17) so a forensic auditor can distinguish
    /// "garbage CBOR" from "missing kid" from "wrong COSE tag" etc.
    /// New call sites should prefer `CoseDecode` with a typed
    /// [`CoseDecodeReason`].
    #[error("COSE decoding error at hop {hop}: {reason}")]
    CoseError {
        /// Index of the hop that failed to decode.
        hop: usize,
        /// Reason the COSE decode failed.
        reason: String,
    },

    /// COSE decoding of a token at the given hop failed with a *granular*
    /// typed reason (v10-14). Forensic auditors can match on the inner
    /// [`CoseDecodeReason`] without parsing a free-form string.
    #[error("COSE decoding error at hop {hop}: {reason}")]
    CoseDecode {
        /// Index of the hop that failed to decode.
        hop: usize,
        /// Typed reason describing what specifically went wrong.
        reason: CoseDecodeReason,
    },

    /// The command requests an operation that is not covered by the granted op set.
    #[error("required operation {op:?} is not covered by granted ops")]
    InsufficientOps {
        /// The operation string that was requested but not granted.
        op: String,
    },
}

/// Structured reason for a COSE_Sign1 decode failure (v10-14).
///
/// Used by [`AuthorityError::CoseDecode`]. Each variant pinpoints a
/// specific class of malformation so audit consumers can route failures
/// without parsing free-form strings. The enum is `#[non_exhaustive]` —
/// new reasons can be added without breaking downstream matchers that
/// include a catch-all arm.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum CoseDecodeReason {
    /// The outer CBOR / COSE_Sign1 envelope failed to parse.
    #[error("CBOR/COSE envelope invalid: {0}")]
    CborInvalid(String),
    /// The COSE_Sign1 envelope had no protected header (or it could not be
    /// extracted). Reserved for envelopes whose protected header is
    /// detached or empty — present in the variant set for forensic
    /// completeness even though `coset` currently surfaces this case
    /// through [`CborInvalid`](CoseDecodeReason::CborInvalid).
    #[error("missing COSE protected header")]
    MissingProtectedHeader,
    /// The protected header was present but carried no `kid` (key id).
    #[error("missing key id in protected header")]
    MissingKid,
    /// The `kid` bytes were not valid UTF-8 and cannot be interpreted as
    /// a key identifier string.
    #[error("invalid key id encoding: {0}")]
    InvalidKidEncoding(String),
    /// The COSE_Sign1 envelope carried no inline payload (e.g. detached-
    /// payload mode is not supported by Invariant). Distinct from
    /// `SignatureSlotEmpty` — that refers to the signature slot being
    /// empty, this refers to the payload slot.
    #[error("missing COSE payload")]
    MissingPayload,
    /// The payload was present but did not deserialize as a `Pca` claim.
    #[error("payload deserialization failed: {0}")]
    PayloadDecode(String),
    /// The COSE_Sign1 envelope had an empty signature slot (defence-in-
    /// depth: `coset` should already reject this during outer parsing).
    /// Reserved for completeness so a downstream tool can distinguish
    /// "no signature on the envelope" from "signature did not verify".
    #[error("COSE signature slot is empty")]
    SignatureSlotEmpty,
    /// The envelope carried a CBOR tag other than the expected COSE_Sign1
    /// tag (RFC 9052 §4.2 — tag 18). Reserved for forensic completeness;
    /// `coset` typically surfaces this through `CborInvalid`.
    #[error("wrong COSE tag: expected {expected}, got {got}")]
    WrongTag {
        /// Tag we expected (typically 18 for COSE_Sign1).
        expected: u64,
        /// Tag actually observed in the envelope.
        got: u64,
    },
    /// Catch-all for COSE-decode failures that don't fit the above
    /// variants. Prefer adding a specific variant when a new failure
    /// class emerges.
    #[error("{0}")]
    Other(String),
}

/// Errors produced when validating model types.
///
/// # Examples
///
/// ```
/// use invariant_core::models::error::ValidationError;
///
/// let err = ValidationError::InvalidOperation("bad op".into());
/// assert!(err.to_string().contains("bad op"));
///
/// let err = ValidationError::JointLimitsInverted {
///     name: "shoulder_pitch".into(),
///     min: 1.0,
///     max: -1.0,
/// };
/// assert!(matches!(err, ValidationError::JointLimitsInverted { .. }));
/// assert!(err.to_string().contains("shoulder_pitch"));
///
/// let err = ValidationError::NoJoints;
/// assert_eq!(err.to_string(), "profile must have at least one joint");
/// ```
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum ValidationError {
    /// An operation string is empty, all-whitespace, or contains disallowed characters.
    #[error("operation string is invalid (empty, whitespace, or disallowed characters): {0:?}")]
    InvalidOperation(String),

    /// A joint's minimum position limit is not strictly less than its maximum.
    #[error("joint '{name}': min ({min}) must be strictly less than max ({max})")]
    JointLimitsInverted {
        /// Name of the offending joint.
        name: String,
        /// The min value that was supplied.
        min: f64,
        /// The max value that was supplied.
        max: f64,
    },

    /// A joint limit field (velocity, torque, or acceleration) is not positive.
    #[error("joint '{name}': {field} must be positive, got {value}")]
    JointLimitNotPositive {
        /// Name of the offending joint.
        name: String,
        /// Name of the limit field that was non-positive.
        field: &'static str,
        /// The non-positive value that was supplied.
        value: f64,
    },

    /// The profile-level `global_velocity_scale` is outside the allowed range `(0.0, 1.0]`.
    #[error("global_velocity_scale {0} is out of range — must be in (0.0, 1.0]")]
    VelocityScaleOutOfRange(f64),

    /// A proximity zone's `velocity_scale` is outside the allowed range `(0.0, 1.0]`.
    #[error(
        "proximity zone '{name}': velocity_scale {scale} is out of range — must be in (0.0, 1.0]"
    )]
    ProximityVelocityScaleOutOfRange {
        /// Name of the proximity zone with an invalid velocity scale.
        name: String,
        /// The out-of-range scale value that was supplied.
        scale: f64,
    },

    /// A collection (joints, zones, collision pairs) exceeds its maximum allowed size.
    #[error("collection '{name}' has {count} elements, exceeding maximum of {max}")]
    CollectionTooLarge {
        /// Name of the collection that is too large.
        name: &'static str,
        /// Actual number of elements in the collection.
        count: usize,
        /// Maximum permitted number of elements.
        max: usize,
    },

    /// The authority chain is empty (must have at least one hop).
    #[error("authority chain must have at least one hop")]
    EmptyAuthorityChain,

    /// The workspace AABB `min` is not strictly less than `max` in all dimensions.
    #[error(
        "workspace bounds min ({min:?}) is not strictly less than max ({max:?}) in all dimensions"
    )]
    WorkspaceBoundsInverted {
        /// The min corner that was supplied.
        min: [f64; 3],
        /// The max corner that was supplied.
        max: [f64; 3],
    },

    /// A joint limit field is NaN or infinite.
    #[error("joint '{name}': {field} must be a finite number (not NaN or infinite)")]
    JointLimitNotFinite {
        /// Name of the offending joint.
        name: String,
        /// Name of the limit field that was non-finite.
        field: &'static str,
    },

    /// A workspace bounds coordinate is NaN or infinite.
    #[error(
        "workspace bounds axis {axis}: coordinate must be a finite number (not NaN or infinite)"
    )]
    WorkspaceBoundsNotFinite {
        /// Zero-based axis index (0 = x, 1 = y, 2 = z) of the non-finite coordinate.
        axis: usize,
    },

    /// A proximity zone has a non-finite or non-positive radius.
    #[error("proximity zone '{name}': radius {radius} must be a finite positive number")]
    ProximityRadiusInvalid {
        /// Name of the proximity zone with an invalid radius.
        name: String,
        /// The invalid radius value that was supplied.
        radius: f64,
    },

    /// Two joints in the profile share the same name.
    #[error("profile contains duplicate joint name: '{name}'")]
    DuplicateJointName {
        /// The duplicated joint name.
        name: String,
    },

    /// `min_collision_distance` is not strictly positive when collision pairs are defined.
    #[error(
        "min_collision_distance must be strictly positive when collision_pairs is non-empty, got {value}"
    )]
    InvalidMinCollisionDistance {
        /// The non-positive value that was supplied.
        value: f64,
    },

    /// A task envelope override is invalid (e.g., it tries to loosen a limit).
    #[error("task envelope '{name}': {reason}")]
    TaskEnvelopeInvalid {
        /// Name of the offending task envelope.
        name: String,
        /// Description of the specific constraint that was violated.
        reason: String,
    },

    /// The `environment` config block contains an invalid value.
    #[error("environment config: {reason}")]
    EnvironmentConfigInvalid {
        /// Description of the specific environment config constraint that was violated.
        reason: String,
    },

    /// The `locomotion` config block contains an invalid value.
    #[error("locomotion config: {reason}")]
    LocomotionConfigInvalid {
        /// Description of the specific locomotion config constraint that was violated.
        reason: String,
    },

    /// The `real_world_margins` block contains an invalid value.
    #[error("real-world margins: {reason}")]
    RealWorldMarginsInvalid {
        /// Description of the specific margin constraint that was violated.
        reason: String,
    },

    /// `max_delta_time` is not finite and positive.
    #[error("max_delta_time must be finite and positive, got {0}")]
    InvalidMaxDeltaTime(f64),

    /// An end-effector config block contains an invalid value.
    #[error("end-effector '{name}': {reason}")]
    EndEffectorConfigInvalid {
        /// Name of the offending end-effector.
        name: String,
        /// Description of the specific end-effector constraint that was violated.
        reason: String,
    },

    /// The profile defines no joints (at least one is required).
    #[error("profile must have at least one joint")]
    NoJoints,

    /// The `stability` config block contains an invalid value.
    #[error("stability config: {reason}")]
    StabilityConfigInvalid {
        /// Description of the specific stability config constraint that was violated.
        reason: String,
    },
}

/// Types that can be checked for semantic correctness after construction.
///
/// Concrete implementors live in the domain crates (e.g.
/// `invariant_robotics::profiles::RobotProfile`). The trait itself is
/// domain-agnostic.
pub trait Validate {
    /// Checks this value for semantic correctness, returning an error if any constraint is violated.
    fn validate(&self) -> Result<(), ValidationError>;
}
