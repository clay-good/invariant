use thiserror::Error;

/// Errors produced during PCA chain verification (A1, A2, A3).
#[derive(Debug, Error, PartialEq)]
pub enum AuthorityError {
    #[error("authority chain must have at least one hop")]
    EmptyChain,

    #[error("chain has {len} hops, exceeding maximum of {max}")]
    ChainTooLong { len: usize, max: usize },

    #[error("serialization failed: {reason}")]
    SerializationError { reason: String },

    // Principal names are redacted in the Display output to avoid leaking
    // identity information in logs, API responses, or rejection verdicts.
    // The full values are retained in the struct fields for internal
    // diagnostics — access them directly when a detailed audit trail is needed.
    #[error(
        "A1 provenance violation: p_0 differs at hop {hop} (expected <redacted>, got <redacted>)"
    )]
    ProvenanceMismatch {
        hop: usize,
        expected: String,
        got: String,
    },

    #[error("A2 monotonicity violation: hop {hop} operation {op:?} is not covered by parent ops")]
    MonotonicityViolation { hop: usize, op: String },

    #[error("A3 continuity: signature verification failed at hop {hop}: {reason}")]
    SignatureInvalid { hop: usize, reason: String },

    // kid is redacted in the Display output for the same reason as
    // ProvenanceMismatch above.
    #[error("A3 continuity: unknown key id <redacted> at hop {hop}")]
    UnknownKeyId { hop: usize, kid: String },

    #[error("PCA at hop {hop} has expired (exp={exp})")]
    Expired { hop: usize, exp: String },

    #[error("PCA at hop {hop} is not yet valid (nbf={nbf})")]
    NotYetValid { hop: usize, nbf: String },

    #[error("COSE decoding error at hop {hop}: {reason}")]
    CoseError { hop: usize, reason: String },

    #[error("required operation {op:?} is not covered by granted ops")]
    InsufficientOps { op: String },
}

/// Errors produced when validating model types.
#[derive(Debug, Error, PartialEq)]
pub enum ValidationError {
    #[error("operation string is invalid (empty, whitespace, or disallowed characters): {0:?}")]
    InvalidOperation(String),

    #[error("joint '{name}': min ({min}) must be strictly less than max ({max})")]
    JointLimitsInverted { name: String, min: f64, max: f64 },

    #[error("joint '{name}': {field} must be positive, got {value}")]
    JointLimitNotPositive {
        name: String,
        field: &'static str,
        value: f64,
    },

    #[error("global_velocity_scale {0} is out of range — must be in (0.0, 1.0]")]
    VelocityScaleOutOfRange(f64),

    #[error(
        "proximity zone '{name}': velocity_scale {scale} is out of range — must be in (0.0, 1.0]"
    )]
    ProximityVelocityScaleOutOfRange { name: String, scale: f64 },

    #[error("collection '{name}' has {count} elements, exceeding maximum of {max}")]
    CollectionTooLarge {
        name: &'static str,
        count: usize,
        max: usize,
    },

    #[error("authority chain must have at least one hop")]
    EmptyAuthorityChain,

    #[error(
        "workspace bounds min ({min:?}) is not strictly less than max ({max:?}) in all dimensions"
    )]
    WorkspaceBoundsInverted { min: [f64; 3], max: [f64; 3] },

    #[error("joint '{name}': {field} must be a finite number (not NaN or infinite)")]
    JointLimitNotFinite { name: String, field: &'static str },

    #[error(
        "workspace bounds axis {axis}: coordinate must be a finite number (not NaN or infinite)"
    )]
    WorkspaceBoundsNotFinite { axis: usize },

    #[error("proximity zone '{name}': radius {radius} must be a finite positive number")]
    ProximityRadiusInvalid { name: String, radius: f64 },

    #[error("profile contains duplicate joint name: '{name}'")]
    DuplicateJointName { name: String },

    #[error(
        "min_collision_distance must be strictly positive when collision_pairs is non-empty, got {value}"
    )]
    InvalidMinCollisionDistance { value: f64 },

    #[error("task envelope '{name}': {reason}")]
    TaskEnvelopeInvalid { name: String, reason: String },

    #[error("environment config: {reason}")]
    EnvironmentConfigInvalid { reason: String },
}

/// Types that can be checked for semantic correctness after construction.
pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}
