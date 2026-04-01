//! Protocol-level attack modules.
//!
//! Each sub-module targets a specific class of protocol attack:
//!
//! - `boundary` — PA1/PA2: probe exact joint limits and epsilon escalations
//! - `numeric`  — PA3/PA4: inject NaN, Inf, -Inf, -0.0, and subnormal values
//! - `schema`   — PA5/PA9/PA12–PA15: type confusion, missing fields, profile mismatch, unicode, JSON bombs, serde gadgets
//! - `temporal`  — PA6–PA8/PA10: expired PCAs, replay, sequence manipulation, contradictory commands
//! - `authority` — AA1–AA10: forgery, escalation, truncation, extension, provenance mutation, wildcard exploitation, cross-chain splice, empty ops, self-delegation, expired-but-signed

pub mod authority;
pub mod boundary;
pub mod numeric;
pub mod schema;
pub mod temporal;
