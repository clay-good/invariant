//! Deterministic RNG for campaign scenarios.
//!
//! `CampaignRng` is a thin newtype over `ChaCha20Rng` with a single
//! constructor [`CampaignRng::from_episode_seed`]. ChaCha20 is portable,
//! cryptographically strong, and produces identical output across
//! platforms — properties needed to keep the 15M campaign byte-reproducible
//! across operator workstations and RunPod CI runs.
//!
//! Spec: `docs/robotics/spec-v11.md` §2.0 (determinism contract).
//!
//! # Why a newtype?
//!
//! Wrapping the underlying RNG in a domain-named type makes it grep-able
//! and review-able: a reviewer can immediately tell whether a generator
//! reaches for ambient randomness (`thread_rng`, `OsRng`, `SystemTime`)
//! or threads its `&mut CampaignRng` through the call stack. The
//! `tests/no_threadrng.rs` integration test enforces the rule for the
//! load-bearing modules.
//!
//! # Seeding
//!
//! The episode index becomes the 64-bit seed; ChaCha20Rng's `seed_from_u64`
//! expands it into the 32-byte ChaCha key with a well-defined hashing.
//! This means episode `n` is independent of any other episode in the
//! campaign, supporting per-shard re-execution and resume semantics.

#![allow(missing_docs)]

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Deterministic RNG for campaign scenarios.
///
/// See module docs for the determinism contract this type enforces.
#[derive(Debug, Clone)]
pub struct CampaignRng(ChaCha20Rng);

impl CampaignRng {
    /// Seed a fresh RNG from an episode index.
    ///
    /// Distinct episode indices produce distinct, statistically independent
    /// streams; the same index always produces the same stream.
    pub fn from_episode_seed(seed: u64) -> Self {
        Self(ChaCha20Rng::seed_from_u64(seed))
    }

    /// Seed from an explicit 32-byte key (for fixtures that need to pin
    /// the RNG state directly rather than via an episode index).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(ChaCha20Rng::from_seed(seed))
    }
}

impl RngCore for CampaignRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = CampaignRng::from_episode_seed(0xCAFEBABE);
        let mut b = CampaignRng::from_episode_seed(0xCAFEBABE);
        for _ in 0..32 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = CampaignRng::from_episode_seed(1);
        let mut b = CampaignRng::from_episode_seed(2);
        // Vanishingly unlikely that the first 8 u64s of two independent
        // ChaCha20 streams all collide; treat any collision as a bug.
        let mut diverged = false;
        for _ in 0..8 {
            if a.next_u64() != b.next_u64() {
                diverged = true;
                break;
            }
        }
        assert!(diverged);
    }

    #[test]
    fn from_seed_pins_state() {
        let seed = [7u8; 32];
        let mut a = CampaignRng::from_seed(seed);
        let mut b = CampaignRng::from_seed(seed);
        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_eq!(buf_a, buf_b);
    }
}
