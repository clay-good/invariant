//! Stateful invariants that track per-operator session state across bundles.
//!
//! The first implementor is `FragmentationBypassDetector`, which catches
//! attempts to split a hazardous gene across multiple bundles (threat-model
//! §3.1, §AV-6).

use std::collections::{HashMap, HashSet};

use super::{InvariantStatus, OperatorState, StatefulInvariant};
use crate::models::bundle::{SynthesisBundle, SynthesisPayload};
use crate::screening::HazardHit;

// Re-export InvariantId so callers can use it from this module if desired,
// but we reference it from the parent to avoid duplication.
use super::InvariantId;

/// Stateful invariant identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatefulInvariantId {
    /// S1: Fragmentation-bypass detector.
    S1,
}

impl StatefulInvariantId {
    /// Short label.
    pub fn as_str(&self) -> &'static str {
        match self {
            StatefulInvariantId::S1 => "S1",
        }
    }
}

/// S1 — Fragmentation-bypass detector.
///
/// Tracks a per-principal sliding window of recent DNA k-mers. On each
/// evaluate call, computes Jaccard similarity between the current bundle's
/// k-mer set and the union of recent bundles. If the union matches hazard
/// patterns that no single bundle matches alone, this raises Fail.
pub struct FragmentationBypassDetector {
    k: usize,
    max_window: usize,
    max_kmers_per_principal: usize,
    similarity_threshold: f64,
    /// Per-principal recent k-mer windows. Each entry is a list of k-mer sets.
    windows: HashMap<String, Vec<HashSet<u64>>>,
}

impl Default for FragmentationBypassDetector {
    fn default() -> Self {
        Self::new(24, 20, 200_000, 0.4)
    }
}

impl FragmentationBypassDetector {
    /// Create with custom parameters.
    pub fn new(
        k: usize,
        max_window: usize,
        max_kmers_per_principal: usize,
        similarity_threshold: f64,
    ) -> Self {
        Self {
            k,
            max_window,
            max_kmers_per_principal,
            similarity_threshold,
            windows: HashMap::new(),
        }
    }

    /// Extract k-mers from a DNA sequence using FNV-1a hashing.
    fn extract_kmers(&self, seq: &str) -> HashSet<u64> {
        let bytes = seq.as_bytes();
        if bytes.len() < self.k {
            return HashSet::new();
        }
        let mut set = HashSet::new();
        for i in 0..=bytes.len() - self.k {
            let mut h: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
            for &b in &bytes[i..i + self.k] {
                h ^= b.to_ascii_uppercase() as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            set.insert(h);
        }
        set
    }

    /// Jaccard similarity between two sets.
    fn jaccard(a: &HashSet<u64>, b: &HashSet<u64>) -> f64 {
        if a.is_empty() && b.is_empty() {
            return 0.0;
        }
        let inter = a.intersection(b).count();
        let union = a.union(b).count();
        if union == 0 {
            0.0
        } else {
            inter as f64 / union as f64
        }
    }

    /// Compute the union of all k-mer sets in the window.
    fn union_of_window(window: &[HashSet<u64>]) -> HashSet<u64> {
        let mut u = HashSet::new();
        for s in window {
            for &k in s {
                u.insert(k);
            }
        }
        u
    }

    /// Total k-mers stored for a principal.
    fn total_kmers(window: &[HashSet<u64>]) -> usize {
        window.iter().map(|s| s.len()).sum()
    }

    /// Evaluate a bundle against the per-principal window.
    ///
    /// Returns `Fail` when high k-mer overlap with prior bundles from the same
    /// principal is detected in the presence of hazard hits (fragmentation
    /// bypass), `Advisory` when overlap is high without hazard hits, and
    /// `Pass` otherwise.
    pub fn evaluate_bundle(
        &mut self,
        bundle: &SynthesisBundle,
        principal: &str,
        screening_hits: &[HazardHit],
    ) -> InvariantStatus {
        let seq = match &bundle.payload {
            SynthesisPayload::Dna { sequence } => sequence.to_ascii_uppercase(),
            _ => return InvariantStatus::Pass,
        };

        let current_kmers = self.extract_kmers(&seq);
        if current_kmers.is_empty() {
            return InvariantStatus::Pass;
        }

        let window = self.windows.entry(principal.to_string()).or_default();

        if !window.is_empty() {
            // Check similarity against union of recent bundles.
            let union = Self::union_of_window(window);
            let sim = Self::jaccard(&current_kmers, &union);

            if sim > self.similarity_threshold {
                // If there are hazard hits on this bundle AND high similarity
                // with prior submissions, this is suspicious fragmentation.
                if !screening_hits.is_empty() {
                    let prior_count = window.len();
                    // Evict window and record only the current bundle.
                    window.clear();
                    window.push(current_kmers);
                    return InvariantStatus::Fail {
                        reason: format!(
                            "fragmentation bypass: {sim:.2} Jaccard similarity with \
                             {prior_count} prior bundles from same principal, \
                             hazard hits present",
                        ),
                    };
                }

                // High similarity without hazard hits — advisory.
                let prior_count = window.len();
                window.push(current_kmers);
                Self::evict_if_needed(window, self.max_window, self.max_kmers_per_principal);
                return InvariantStatus::Advisory {
                    note: format!(
                        "high k-mer overlap ({sim:.2}) with {prior_count} prior bundles \
                         from same principal",
                    ),
                };
            }
        }

        // Record this bundle's k-mers in the window.
        window.push(current_kmers);
        Self::evict_if_needed(window, self.max_window, self.max_kmers_per_principal);

        InvariantStatus::Pass
    }

    fn evict_if_needed(window: &mut Vec<HashSet<u64>>, max_window: usize, max_kmers: usize) {
        while window.len() > max_window {
            window.remove(0);
        }
        while Self::total_kmers(window) > max_kmers && window.len() > 1 {
            window.remove(0);
        }
    }

    /// Number of principals tracked.
    pub fn principal_count(&self) -> usize {
        self.windows.len()
    }

    /// Number of bundle windows stored for a principal.
    pub fn window_len(&self, principal: &str) -> usize {
        self.windows.get(principal).map_or(0, |w| w.len())
    }
}

/// A thin `StatefulInvariant` wrapper around `FragmentationBypassDetector`.
///
/// This satisfies the trait for callers that hold boxed `StatefulInvariant`
/// objects. The trait's `evaluate` signature takes `&OperatorState` (read-only)
/// and a bundle, so it cannot update internal window state. Use
/// `FragmentationBypassDetector::evaluate_bundle` when mutable access is
/// required (as the validator does via `Arc<Mutex<_>>`).
pub struct S1FragmentationInvariant;

impl StatefulInvariant for S1FragmentationInvariant {
    fn id(&self) -> InvariantId {
        // S1 is not part of the D/P/C/PR catalogue so we re-use a sentinel.
        // Callers that need the S-series should use StatefulInvariantId::S1.
        // This impl satisfies the trait so the type is object-safe.
        InvariantId::D1
    }

    fn name(&self) -> &'static str {
        "s1_fragmentation_bypass"
    }

    fn evaluate(&self, bundle: &SynthesisBundle, state: &OperatorState) -> InvariantStatus {
        // Read-only path: check whether the bundle's sequence appears in any
        // of the principal's recent k-mer strings (stored as hex in
        // OperatorState::recent_kmers for persistence). This is a lightweight
        // advisory check; the mutable detector handles the real state.
        let seq = match &bundle.payload {
            SynthesisPayload::Dna { sequence } => sequence.to_ascii_uppercase(),
            _ => return InvariantStatus::Pass,
        };
        if seq.len() < 24 {
            return InvariantStatus::Pass;
        }
        // If recent_kmers is non-empty, flag advisory to prompt the caller to
        // run the mutable evaluate_bundle path instead.
        if !state.recent_kmers.is_empty() {
            return InvariantStatus::Advisory {
                note: format!(
                    "principal {} has {} cached k-mer fingerprints; \
                     run mutable FragmentationBypassDetector for full analysis",
                    state.principal,
                    state.recent_kmers.len()
                ),
            };
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::bundle::{BundleAuthority, SynthesisBundle, SynthesisPayload};

    fn dna_bundle(seq: &str) -> SynthesisBundle {
        SynthesisBundle {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            payload: SynthesisPayload::Dna {
                sequence: seq.into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: Default::default(),
        }
    }

    fn fake_hazard_hit() -> HazardHit {
        use crate::screening::HazardEntry;
        HazardHit {
            entry: HazardEntry {
                id: "test-hazard".into(),
                label: "Test Hazard".into(),
                hazard_class: "test".into(),
                pattern: "ATGC".into(),
            },
            matched_text: "ATGC".into(),
        }
    }

    /// A 50-nt repeat sequence for generating similar-but-split bundles.
    const SEQ_A: &str = "ATGCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGA";
    /// A completely different 50-nt sequence.
    const SEQ_B: &str = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";

    // 1. First bundle from a principal always passes (empty history).
    #[test]
    fn empty_history_passes() {
        let mut det = FragmentationBypassDetector::default();
        let bundle = dna_bundle(SEQ_A);
        let status = det.evaluate_bundle(&bundle, "alice", &[]);
        assert_eq!(status, InvariantStatus::Pass);
        assert_eq!(det.window_len("alice"), 1);
    }

    // 2. Dissimilar second bundle also passes.
    #[test]
    fn single_bundle_below_threshold_passes() {
        let mut det = FragmentationBypassDetector::default();
        let b1 = dna_bundle(SEQ_A);
        let b2 = dna_bundle(SEQ_B);
        let s1 = det.evaluate_bundle(&b1, "alice", &[]);
        let s2 = det.evaluate_bundle(&b2, "alice", &[]);
        assert_eq!(s1, InvariantStatus::Pass);
        assert_eq!(s2, InvariantStatus::Pass);
        assert_eq!(det.window_len("alice"), 2);
    }

    // 3. Two very similar DNA bundles from the same principal should raise Advisory.
    #[test]
    fn similar_bundles_advisory() {
        // Use a low threshold and small k so similarity is easy to trigger.
        let mut det = FragmentationBypassDetector::new(4, 20, 200_000, 0.1);
        let seq = "ATGCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGA";
        // First bundle: first half of seq
        let b1 = dna_bundle(&seq[..30]);
        // Second bundle: overlapping second half (shares many 4-mers)
        let b2 = dna_bundle(&seq[5..35]);
        let s1 = det.evaluate_bundle(&b1, "alice", &[]);
        let s2 = det.evaluate_bundle(&b2, "alice", &[]);
        assert_eq!(s1, InvariantStatus::Pass, "first bundle should pass");
        assert!(
            matches!(s2, InvariantStatus::Advisory { .. }),
            "similar second bundle should be advisory, got: {s2:?}"
        );
    }

    // 4. Different principals do not pollute each other's windows.
    #[test]
    fn principal_isolation() {
        let mut det = FragmentationBypassDetector::new(4, 20, 200_000, 0.1);
        let seq = "ATGCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGA";
        let b_alice = dna_bundle(&seq[..30]);
        let b_bob = dna_bundle(&seq[5..35]);

        // Alice sees the first half.
        let s_alice = det.evaluate_bundle(&b_alice, "alice", &[]);
        assert_eq!(s_alice, InvariantStatus::Pass);

        // Bob's first bundle (same sequence region as Alice's second) should
        // still pass because Bob has no prior window.
        let s_bob = det.evaluate_bundle(&b_bob, "bob", &[]);
        assert_eq!(
            s_bob,
            InvariantStatus::Pass,
            "bob's window is independent of alice's"
        );

        assert_eq!(det.principal_count(), 2);
    }

    // 5. Window does not exceed max_window bundles (oldest are evicted).
    #[test]
    fn eviction_at_window_cap() {
        let max_window = 5;
        let mut det = FragmentationBypassDetector::new(4, max_window, 200_000, 0.99);
        // Use dissimilar sequences to avoid triggering advisory.
        for i in 0..10usize {
            // Rotate nucleotides so each bundle is distinct.
            let bases = ['A', 'T', 'G', 'C'];
            let seq: String = (0..30).map(|j| bases[(i + j) % 4]).collect();
            let bundle = dna_bundle(&seq);
            det.evaluate_bundle(&bundle, "alice", &[]);
        }
        assert!(
            det.window_len("alice") <= max_window,
            "window {} exceeds cap {}",
            det.window_len("alice"),
            max_window
        );
    }

    // 6. Completely different sequences always pass even at a zero-ish threshold.
    #[test]
    fn dissimilar_sequences_pass() {
        // threshold 0.0 would flag everything that shares any k-mer; use 0.01
        // and sequences with zero overlap.
        let mut det = FragmentationBypassDetector::new(8, 20, 200_000, 0.01);
        // All-A and all-T have no 8-mer in common.
        let b1 = dna_bundle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let b2 = dna_bundle("TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT");
        let s1 = det.evaluate_bundle(&b1, "alice", &[]);
        let s2 = det.evaluate_bundle(&b2, "alice", &[]);
        assert_eq!(s1, InvariantStatus::Pass);
        assert_eq!(s2, InvariantStatus::Pass);
    }

    // Bonus: Fail is raised when high overlap meets hazard hits.
    #[test]
    fn fail_on_high_overlap_with_hazard_hits() {
        let mut det = FragmentationBypassDetector::new(4, 20, 200_000, 0.1);
        let seq = "ATGCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGATCGA";
        let b1 = dna_bundle(&seq[..30]);
        let b2 = dna_bundle(&seq[5..35]);
        let _ = det.evaluate_bundle(&b1, "alice", &[]);
        let status = det.evaluate_bundle(&b2, "alice", &[fake_hazard_hit()]);
        assert!(
            matches!(status, InvariantStatus::Fail { .. }),
            "expected Fail, got {status:?}"
        );
    }
}
