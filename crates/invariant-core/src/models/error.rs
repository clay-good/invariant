use thiserror::Error;

/// Errors produced during PCA chain verification (A1, A2, A3).
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::error::AuthorityError;
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
    #[error("COSE decoding error at hop {hop}: {reason}")]
    CoseError {
        /// Index of the hop that failed to decode.
        hop: usize,
        /// Reason the COSE decode failed.
        reason: String,
    },

    /// The command requests an operation that is not covered by the granted op set.
    #[error("required operation {op:?} is not covered by granted ops")]
    InsufficientOps {
        /// The operation string that was requested but not granted.
        op: String,
    },
}

/// Errors produced when validating model types.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::error::ValidationError;
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
/// # Examples
///
/// ```
/// use invariant_robotics_core::models::error::{Validate, ValidationError};
/// use invariant_robotics_core::models::profile::{JointDefinition, JointType};
///
/// let joint = JointDefinition {
///     name: "elbow_flex".into(),
///     joint_type: JointType::Revolute,
///     min: -2.094,  // -120 degrees
///     max:  2.094,  //  120 degrees
///     max_velocity: 3.14,   // rad/s
///     max_torque: 150.0,    // N·m
///     max_acceleration: 10.0, // rad/s²
/// };
/// assert!(joint.validate().is_ok());
///
/// let bad_joint = JointDefinition {
///     name: "bad_joint".into(),
///     joint_type: JointType::Revolute,
///     min: 1.0,
///     max: 0.0,  // inverted limits
///     max_velocity: 1.0,
///     max_torque: 1.0,
///     max_acceleration: 1.0,
/// };
/// assert!(matches!(
///     bad_joint.validate(),
///     Err(ValidationError::JointLimitsInverted { .. })
/// ));
/// ```
pub trait Validate {
    /// Checks this value for semantic correctness, returning an error if any constraint is violated.
    fn validate(&self) -> Result<(), ValidationError>;
}
