//! Generic profile-loading trait. Concrete profile loaders live in the
//! domain crates.

use crate::traits::DomainProfile;

/// Loader interface — domain crates implement this to load their concrete
/// profile type from a JSON byte slice.
pub trait ProfileLoader {
    /// Concrete profile type (must implement [`DomainProfile`]).
    type Profile: DomainProfile;
    /// Error returned on load failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load a profile from raw JSON bytes.
    fn load_json(bytes: &[u8]) -> Result<Self::Profile, Self::Error>;
}
