use thiserror::Error;

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
