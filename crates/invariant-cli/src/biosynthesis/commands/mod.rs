//! Subcommand implementations for the `invariant-bio` CLI.
//!
//! All eleven subcommands ship real implementations after gap-closure
//! Steps 11–17: `validate`, `inspect`, `differential`, `intent`, `campaign`,
//! `eval`, `adversarial`, `keygen`, `audit`, `audit-gaps`, `verify` /
//! `verify-self`.

pub mod adversarial;
pub mod audit;
pub mod audit_gaps;
pub mod campaign;
pub mod differential;
pub mod eval;
pub mod inspect;
pub mod intent;
pub mod keygen;
pub mod validate;
pub mod verify;
pub mod verify_self;
