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

    #[error("A1 provenance violation: p_0 differs at hop {hop} (expected {expected:?}, got {got:?})")]
    ProvenanceMismatch {
        hop: usize,
        expected: String,
        got: String,
    },

    #[error("A2 monotonicity violation: hop {hop} operation {op:?} is not covered by parent ops")]
    MonotonicityViolation { hop: usize, op: String },

    #[error("A3 continuity: signature verification failed at hop {hop}: {reason}")]
    SignatureInvalid { hop: usize, reason: String },

    #[error("A3 continuity: unknown key id {kid:?} at hop {hop}")]
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

    #[error(
        "global_velocity_scale {0} is out of range — must be in (0.0, 1.0]"
    )]
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
}

/// Types that can be checked for semantic correctness after construction.
pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}
