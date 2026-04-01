pub mod chain;
pub mod crypto;
pub mod operations;

// Re-export data types so `use invariant_core::authority::Pca` resolves
// unambiguously (P1-5: resolves module-name collision between the chain-
// validation logic module and the models::authority data-types module).
pub use crate::models::authority::{AuthorityChain, Operation, Pca, SignedPca};
pub use crate::models::error::AuthorityError;

#[cfg(test)]
mod tests;
