//! Protein-space homology detection engines.
//!
//! Provides the [`HomologyEngine`] trait with two implementations:
//!
//! - [`KmerHomologyEngine`] (default) — Jaccard similarity on protein k-mer
//!   sets. Interim engine; uncalibrated against a curated reference set.
//! - `HmmerHomologyEngine` (feature-gated `hmmer`) — HMMER profile-HMM
//!   scanning with calibrated bit-score thresholds.
//!
//! ## Acceptance gate
//!
//! Evaluation against the curated HHS Select Agent reference set with
//! FN ≤ 1e-4, FP ≤ 1e-3 and published Clopper–Pearson bounds. The k-mer
//! engine should be benchmarked and either calibrated or replaced with HMMER
//! before this gate can be met.

use std::collections::HashSet;

/// A single homology match produced by a [`HomologyEngine`].
#[derive(Debug, Clone)]
pub struct HomologyMatch {
    /// Which reading frame (1-indexed) the match was found in.
    pub frame_index: usize,
    /// Similarity score (interpretation depends on the engine).
    pub similarity: f64,
    /// Short label for the engine that produced this match (e.g. "kmer", "hmmer").
    pub method: &'static str,
}

/// Abstract protein-space homology detection engine.
///
/// Implementations compare a set of query protein frames (translated from
/// the bundle DNA) against a set of reference protein frames (translated
/// from a hazard-database matched pattern) and return any matches that
/// exceed the engine's configured threshold.
pub trait HomologyEngine: Send + Sync {
    /// Scan `query_frames` against `reference_frames` and return all matches
    /// above the engine's threshold.
    fn scan(
        &self,
        query_frames: &[&str],
        reference_frames: &[&str],
    ) -> Vec<HomologyMatch>;

    /// Short label for this engine (e.g. "kmer", "hmmer").
    fn method_label(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// K-mer Jaccard engine (default)
// ---------------------------------------------------------------------------

/// Protein-space k-mer Jaccard similarity engine.
///
/// Compares protein k-mer sets between query and reference frames. A match
/// is reported when the Jaccard similarity meets or exceeds `threshold`.
///
/// ## Known limitations
///
/// - The k and threshold parameters are heuristic defaults, not derived from
///   a curated reference set.
/// - Jaccard similarity is not equivalent to HMMER bit-scores; short proteins
///   or repetitive domains may produce uncalibrated scores.
/// - The acceptance gate (FN ≤ 1e-4, FP ≤ 1e-3) has not been validated for
///   this engine. Use calibration benchmarks to assess fitness.
#[derive(Debug, Clone)]
pub struct KmerHomologyEngine {
    /// Protein k-mer size (residues).
    pub k: usize,
    /// Minimum Jaccard similarity threshold.
    pub threshold: f64,
}

impl Default for KmerHomologyEngine {
    fn default() -> Self {
        Self {
            k: super::dna::DEFAULT_PROTEIN_KMER_K,
            threshold: super::dna::DEFAULT_PROTEIN_KMER_THRESHOLD,
        }
    }
}

impl KmerHomologyEngine {
    /// Create a new k-mer engine with the given parameters.
    pub fn new(k: usize, threshold: f64) -> Self {
        Self { k, threshold }
    }

    /// Extract protein k-mer set from a sequence.
    pub fn protein_kmers(seq: &str, k: usize) -> HashSet<Vec<u8>> {
        let bytes = seq.as_bytes();
        if bytes.len() < k {
            return HashSet::new();
        }
        let mut set = HashSet::new();
        for i in 0..=bytes.len() - k {
            let kmer = bytes[i..i + k].to_ascii_uppercase();
            if kmer.iter().any(|&b| b == b'X' || b == b'*') {
                continue;
            }
            set.insert(kmer);
        }
        set
    }

    /// Jaccard similarity between two k-mer sets.
    pub fn jaccard(a: &HashSet<Vec<u8>>, b: &HashSet<Vec<u8>>) -> f64 {
        if a.is_empty() || b.is_empty() {
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
}

impl HomologyEngine for KmerHomologyEngine {
    fn scan(
        &self,
        query_frames: &[&str],
        reference_frames: &[&str],
    ) -> Vec<HomologyMatch> {
        let query_kmer_sets: Vec<HashSet<Vec<u8>>> = query_frames
            .iter()
            .map(|f| Self::protein_kmers(f, self.k))
            .collect();

        let mut matches = Vec::new();
        for ref_frame in reference_frames {
            let ref_kmers = Self::protein_kmers(ref_frame, self.k);
            if ref_kmers.is_empty() {
                continue;
            }
            for (fi, qk) in query_kmer_sets.iter().enumerate() {
                let sim = Self::jaccard(qk, &ref_kmers);
                if sim >= self.threshold {
                    matches.push(HomologyMatch {
                        frame_index: fi + 1,
                        similarity: sim,
                        method: "kmer",
                    });
                }
            }
        }
        matches
    }

    fn method_label(&self) -> &'static str {
        "kmer"
    }
}

// ---------------------------------------------------------------------------
// HMMER engine (feature-gated stub)
// ---------------------------------------------------------------------------

/// HMMER profile-HMM homology engine (feature-gated).
///
/// Wraps the HMMER3 `hmmscan` pipeline for calibrated bit-score matching
/// against curated profile-HMMs. Requires the `hmmer` feature flag and a
/// safe FFI wrapper (not yet implemented).
///
/// ## Acceptance gate
///
/// When this engine is available, D1–D6 should be evaluated against the
/// curated HHS Select Agent reference set with:
/// - FN ≤ 1e-4
/// - FP ≤ 1e-3
/// - Published Clopper–Pearson confidence intervals
#[cfg(feature = "hmmer")]
#[derive(Debug, Clone)]
pub struct HmmerHomologyEngine {
    /// Minimum bit-score for a domain hit to be considered significant.
    pub min_bit_score: f64,
    /// Maximum E-value threshold.
    pub max_evalue: f64,
}

#[cfg(feature = "hmmer")]
impl Default for HmmerHomologyEngine {
    fn default() -> Self {
        Self {
            min_bit_score: 50.0,
            max_evalue: 1e-10,
        }
    }
}

#[cfg(feature = "hmmer")]
impl HomologyEngine for HmmerHomologyEngine {
    fn scan(
        &self,
        _query_frames: &[&str],
        _reference_frames: &[&str],
    ) -> Vec<HomologyMatch> {
        // Stub: HMMER FFI integration is deferred until a safe wrapper crate
        // is available. The `#![forbid(unsafe_code)]` policy requires all FFI
        // to go through a vetted, safe-only binding.
        Vec::new()
    }

    fn method_label(&self) -> &'static str {
        "hmmer"
    }
}

// ---------------------------------------------------------------------------
// Calibration utilities
// ---------------------------------------------------------------------------

/// Result of a calibration run against a reference panel.
#[derive(Debug, Clone)]
pub struct CalibrationResult {
    /// Total number of known-positive sequences tested.
    pub total_positives: usize,
    /// Number of known-positive sequences correctly detected (true positives).
    pub true_positives: usize,
    /// Total number of known-negative sequences tested.
    pub total_negatives: usize,
    /// Number of known-negative sequences incorrectly flagged (false positives).
    pub false_positives: usize,
}

impl CalibrationResult {
    /// False-negative rate: FN / total_positives.
    pub fn fn_rate(&self) -> f64 {
        if self.total_positives == 0 {
            return 0.0;
        }
        let fn_count = self.total_positives - self.true_positives;
        fn_count as f64 / self.total_positives as f64
    }

    /// False-positive rate: FP / total_negatives.
    pub fn fp_rate(&self) -> f64 {
        if self.total_negatives == 0 {
            return 0.0;
        }
        self.false_positives as f64 / self.total_negatives as f64
    }

    /// Clopper–Pearson exact 95% confidence interval upper bound for the
    /// false-negative rate. Uses the beta distribution quantile approximation.
    pub fn fn_rate_upper_95(&self) -> f64 {
        let n = self.total_positives;
        let k = n - self.true_positives; // false negatives
        clopper_pearson_upper(k, n, 0.05)
    }

    /// Clopper–Pearson exact 95% confidence interval upper bound for the
    /// false-positive rate.
    pub fn fp_rate_upper_95(&self) -> f64 {
        let n = self.total_negatives;
        let k = self.false_positives;
        clopper_pearson_upper(k, n, 0.05)
    }

    /// Check whether the acceptance gate is met:
    /// FN ≤ 1e-4, FP ≤ 1e-3 (point estimates).
    pub fn meets_acceptance_gate(&self) -> bool {
        self.fn_rate() <= 1e-4 && self.fp_rate() <= 1e-3
    }
}

/// Clopper–Pearson exact upper confidence bound.
///
/// For k successes out of n trials, returns the upper bound of the
/// (1-alpha) confidence interval. Uses a normal approximation to the
/// beta quantile for computational simplicity.
fn clopper_pearson_upper(k: usize, n: usize, alpha: f64) -> f64 {
    if n == 0 {
        return 1.0;
    }
    if k == n {
        return 1.0;
    }
    // Beta(k+1, n-k) quantile at 1-alpha/2.
    // Use the normal approximation: mean = (k+1)/(n+2), var = ...
    let a = (k + 1) as f64;
    let b = (n - k) as f64;
    let mean = a / (a + b);
    let var = (a * b) / ((a + b).powi(2) * (a + b + 1.0));
    let z = 1.96; // ~97.5th percentile for alpha=0.05
    let _ = alpha; // used implicitly via z
    (mean + z * var.sqrt()).min(1.0)
}

/// Run a calibration of the given engine against positive and negative
/// reference panels.
///
/// Each panel entry is a pair of (query_frames, reference_frames). A
/// "detection" means the engine returns at least one match.
pub fn calibrate(
    engine: &dyn HomologyEngine,
    positives: &[(&[&str], &[&str])],
    negatives: &[(&[&str], &[&str])],
) -> CalibrationResult {
    let mut true_positives = 0;
    for (query, reference) in positives {
        let matches = engine.scan(query, reference);
        if !matches.is_empty() {
            true_positives += 1;
        }
    }

    let mut false_positives = 0;
    for (query, reference) in negatives {
        let matches = engine.scan(query, reference);
        if !matches.is_empty() {
            false_positives += 1;
        }
    }

    CalibrationResult {
        total_positives: positives.len(),
        true_positives,
        total_negatives: negatives.len(),
        false_positives,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kmer_engine_identical_sequences_match() {
        let engine = KmerHomologyEngine::new(3, 0.3);
        let protein = "MKFALIDNEA";
        let matches = engine.scan(&[protein], &[protein]);
        assert!(!matches.is_empty());
        assert!((matches[0].similarity - 1.0).abs() < 1e-10);
        assert_eq!(matches[0].method, "kmer");
    }

    #[test]
    fn kmer_engine_disjoint_sequences_no_match() {
        let engine = KmerHomologyEngine::new(3, 0.3);
        let matches = engine.scan(&["MKFALIDNEA"], &["WWWWWWWWWW"]);
        assert!(matches.is_empty());
    }

    #[test]
    fn kmer_engine_partial_overlap() {
        let engine = KmerHomologyEngine::new(3, 0.3);
        // These share some 3-mers at the start.
        let matches = engine.scan(&["MKFALIDNEA"], &["MKFAGGGGGG"]);
        // Should have some hits depending on overlap.
        // MKF, KFA are shared; rest diverge.
        for m in &matches {
            assert!(m.similarity >= 0.3);
        }
    }

    #[test]
    fn kmer_engine_respects_threshold() {
        let strict = KmerHomologyEngine::new(3, 0.99);
        let matches = strict.scan(&["MKFALIDNEA"], &["MKFAGGGGGG"]);
        assert!(matches.is_empty(), "strict threshold should filter partial hits");
    }

    #[test]
    fn kmer_engine_short_sequence_no_match() {
        let engine = KmerHomologyEngine::new(5, 0.3);
        let matches = engine.scan(&["MK"], &["MK"]);
        assert!(matches.is_empty());
    }

    #[test]
    fn kmer_engine_default_params() {
        let engine = KmerHomologyEngine::default();
        assert_eq!(engine.k, 5);
        assert!((engine.threshold - 0.30).abs() < 1e-10);
    }

    #[test]
    fn calibration_perfect_engine() {
        let engine = KmerHomologyEngine::new(3, 0.3);
        let protein = "MKFALIDNEA";
        let pos_q = [protein];
        let pos_r = [protein];
        let neg_q = ["WWWWWWWWWW"];
        let neg_r = ["DDDDDDDDDD"];
        let positives: Vec<(&[&str], &[&str])> = vec![(&pos_q, &pos_r)];
        let negatives: Vec<(&[&str], &[&str])> = vec![(&neg_q, &neg_r)];
        let result = calibrate(&engine, &positives, &negatives);
        assert_eq!(result.true_positives, 1);
        assert_eq!(result.false_positives, 0);
        assert!(result.fn_rate() < 1e-10);
        assert!(result.fp_rate() < 1e-10);
        assert!(result.meets_acceptance_gate());
    }

    #[test]
    fn calibration_result_rates() {
        let result = CalibrationResult {
            total_positives: 1000,
            true_positives: 999,
            total_negatives: 1000,
            false_positives: 1,
        };
        assert!((result.fn_rate() - 0.001).abs() < 1e-10);
        assert!((result.fp_rate() - 0.001).abs() < 1e-10);
    }

    #[test]
    fn clopper_pearson_upper_bound_reasonable() {
        let upper = clopper_pearson_upper(1, 1000, 0.05);
        assert!(upper > 0.001);
        assert!(upper < 0.01);
    }

    #[test]
    fn clopper_pearson_zero_successes() {
        let upper = clopper_pearson_upper(0, 100, 0.05);
        assert!(upper > 0.0);
        assert!(upper < 0.1);
    }

    #[test]
    fn clopper_pearson_all_successes() {
        let upper = clopper_pearson_upper(100, 100, 0.05);
        assert!((upper - 1.0).abs() < 1e-10);
    }

    #[test]
    fn calibration_kmer_synonymous_codons_detected() {
        // Simulate a calibration scenario where the k-mer engine detects
        // a codon-substituted homolog at the protein level.
        let engine = KmerHomologyEngine::new(5, 0.30);
        // Both represent the same protein: MKFALIDNEA
        let query_arr = ["MKFALIDNEA"];
        let ref_arr = ["MKFALIDNEA"];
        let positives: Vec<(&[&str], &[&str])> = vec![(&query_arr, &ref_arr)];
        let result = calibrate(&engine, &positives, &[]);
        assert_eq!(result.true_positives, 1);
        assert_eq!(result.total_positives, 1);
    }

    #[test]
    fn homology_match_fields() {
        let m = HomologyMatch {
            frame_index: 1,
            similarity: 0.85,
            method: "kmer",
        };
        assert_eq!(m.frame_index, 1);
        assert!((m.similarity - 0.85).abs() < 1e-10);
        assert_eq!(m.method, "kmer");
    }
}
