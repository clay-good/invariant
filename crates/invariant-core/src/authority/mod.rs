/// PIC authority chain verification (verify_chain, check_required_ops).
pub mod chain;
/// Ed25519 key generation, PCA signing, and chain verification.
pub mod crypto;
/// Operation string validation and PCA operations logic.
pub mod operations;

// Re-export data types so `use invariant_core::authority::Pca` resolves
// unambiguously (P1-5: resolves module-name collision between the chain-
// validation logic module and the models::authority data-types module).
pub use crate::models::authority::{AuthorityChain, Operation, Pca, SignedPca};
pub use crate::models::error::AuthorityError;

#[cfg(test)]
mod tests;
