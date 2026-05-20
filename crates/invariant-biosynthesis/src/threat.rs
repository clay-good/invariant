//! Runtime threat-scoring engine for biosynthesis.
//!
//! Bio adaptation: the engine framework (sliding window, weighted composite,
//! `ThreatAnalysis` output, alert threshold) is ported verbatim from the
//! sibling robotics project. The five detector heuristics are rewritten to
//! use bio-relevant signals per `docs/threat-model.md` §3.1:
//!
//! 1. **Boundary clustering** — bundles whose payload size sits at the
//!    profile's per-bundle volume cap. Bio-equivalent of the original
//!    near-actuator-limit heuristic from the sibling robotics project.
//! 2. **Authority probing** — repeated authority rejection per principal
//!    (verbatim semantic; signal is per-PCA-leaf rejection rate).
//! 3. **Replay similarity** — k-mer fingerprint distance to previously
//!    rejected bundle payloads (DNA / peptide). Catches near-duplicate
//!    submissions.
//! 4. **Drift detection** — running-mean shift in per-operator cumulative
//!    synthesis volume.
//! 5. **Fragmentation / anomaly** — payload-size z-score across the recent
//!    window, plus k-mer-overlap test against earlier bundles for the
//!    fragmentation-bypass class (threat-model §3.1).

use std::collections::{HashMap, VecDeque};

use crate::models::bundle::{SynthesisBundle, SynthesisPayload};
use crate::models::profile::BioProfile;
use crate::models::verdict::ThreatAnalysis;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the threat scoring engine.
#[derive(Debug, Clone)]
pub struct ThreatScorerConfig {
    /// Maximum number of recent bundles to retain for analysis.
    pub window_size: usize,
    /// Composite threat score above which `alert` is set to `true`.
    pub alert_threshold: f64,
    /// Weights for combining individual scores into the composite.
    pub weights: ThreatWeights,
    /// Fraction of the profile's max payload size that counts as "near
    /// boundary" (0.0–1.0). Default 0.05 = outer 5%.
    pub boundary_band_fraction: f64,
}

/// Weights for combining individual threat scores.
#[derive(Debug, Clone)]
pub struct ThreatWeights {
    /// Weight for the boundary-clustering detector.
    pub boundary_clustering: f64,
    /// Weight for the authority-probing detector.
    pub authority_probing: f64,
    /// Weight for the replay-similarity detector.
    pub replay_similarity: f64,
    /// Weight for the drift detector.
    pub drift: f64,
    /// Weight for the fragmentation / anomaly detector.
    pub anomaly: f64,
}

impl Default for ThreatScorerConfig {
    fn default() -> Self {
        Self {
            window_size: 100,
            alert_threshold: 0.7,
            weights: ThreatWeights {
                boundary_clustering: 0.2,
                authority_probing: 0.25,
                replay_similarity: 0.2,
                drift: 0.2,
                anomaly: 0.15,
            },
            boundary_band_fraction: 0.05,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct BundleFingerprint {
    /// Payload length in bases / residues / atoms (whatever the substrate
    /// reports natively).
    payload_len: usize,
    /// k-mer set of the payload (k=12). Used for replay & fragmentation.
    kmers: Vec<u64>,
    #[allow(dead_code)]
    rejected: bool,
}

#[derive(Debug, Clone, Default)]
struct DriftTracker {
    /// Per-principal running mean cumulative-volume (in bases/residues).
    means: HashMap<String, f64>,
    counts: HashMap<String, u64>,
}

impl DriftTracker {
    fn update(&mut self, principal: &str, volume: f64) -> f64 {
        let count = self.counts.entry(principal.to_string()).or_insert(0);
        *count = count.saturating_add(1);
        let n = *count as f64;
        let old_mean = self.means.get(principal).copied().unwrap_or(volume);
        let new_mean = old_mean + (volume - old_mean) / n;
        self.means.insert(principal.to_string(), new_mean);
        (new_mean - old_mean).abs()
    }
}

// ---------------------------------------------------------------------------
// Scorer
// ---------------------------------------------------------------------------

/// Runtime threat scoring engine.
///
/// Feed bundles via [`ThreatScorer::score`] and receive a [`ThreatAnalysis`]
/// to attach to a verdict. Stateful: tracks a sliding window of recent
/// bundles for statistical analysis.
pub struct ThreatScorer {
    config: ThreatScorerConfig,
    window: VecDeque<BundleFingerprint>,
    rejected_window: VecDeque<BundleFingerprint>,
    authority_rejections: HashMap<String, u64>,
    authority_checks: u64,
    drift: DriftTracker,
}

impl ThreatScorer {
    /// Create a new scorer with the given configuration.
    pub fn new(config: ThreatScorerConfig) -> Self {
        let window_size = config.window_size;
        Self {
            config,
            window: VecDeque::with_capacity(window_size),
            rejected_window: VecDeque::with_capacity(window_size),
            authority_rejections: HashMap::new(),
            authority_checks: 0,
            drift: DriftTracker::default(),
        }
    }

    /// Create a scorer with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ThreatScorerConfig::default())
    }

    /// Score a bundle and return a [`ThreatAnalysis`].
    pub fn score(
        &mut self,
        bundle: &SynthesisBundle,
        profile: &BioProfile,
        authority_passed: bool,
        principal: &str,
        approved: bool,
    ) -> ThreatAnalysis {
        let fp = fingerprint(bundle);

        let boundary_score = self.score_boundary_clustering(&fp, profile);
        let authority_score = self.score_authority_probing(authority_passed, principal);
        let replay_score = self.score_replay_similarity(&fp);
        let drift_score = self.score_drift(principal, fp.payload_len as f64);
        let anomaly_score = self.score_anomaly(&fp);

        // Record in window.
        self.window.push_back(fp.clone());
        if self.window.len() > self.config.window_size {
            self.window.pop_front();
        }
        if !approved {
            self.rejected_window.push_back(fp);
            if self.rejected_window.len() > self.config.window_size {
                self.rejected_window.pop_front();
            }
        }

        let w = &self.config.weights;
        let composite = boundary_score * w.boundary_clustering
            + authority_score * w.authority_probing
            + replay_score * w.replay_similarity
            + drift_score * w.drift
            + anomaly_score * w.anomaly;
        let composite = composite.clamp(0.0, 1.0);

        ThreatAnalysis {
            boundary_clustering_score: boundary_score,
            authority_probing_score: authority_score,
            replay_similarity_score: replay_score,
            drift_score,
            anomaly_score,
            composite_threat_score: composite,
            alert: composite > self.config.alert_threshold,
        }
    }

    // -- Detector 1: Boundary clustering ----------------------------------

    fn score_boundary_clustering(&self, fp: &BundleFingerprint, profile: &BioProfile) -> f64 {
        // Profile cap is in mL; we treat payload_len/100_000 as a rough
        // proxy "volume". This stub is intentionally conservative — Step
        // 3b will replace it with a real per-substrate volume model.
        let cap = profile.max_synthesis_volume_ml.max(1e-9);
        let proxy_volume = fp.payload_len as f64 / 100_000.0;
        let band = self.config.boundary_band_fraction;
        let band_size = cap * band;
        let dist = (cap - proxy_volume).abs();
        if dist < band_size {
            1.0
        } else {
            (1.0 - (dist / cap)).clamp(0.0, 1.0) * 0.5
        }
    }

    // -- Detector 2: Authority probing ------------------------------------

    fn score_authority_probing(&mut self, authority_passed: bool, principal: &str) -> f64 {
        self.authority_checks = self.authority_checks.saturating_add(1);

        if !authority_passed && !principal.is_empty() {
            let entry = self
                .authority_rejections
                .entry(principal.to_string())
                .or_insert(0);
            *entry = entry.saturating_add(1);
        }

        if self.authority_checks < 5 {
            return 0.0;
        }

        let max_rejection_rate = self
            .authority_rejections
            .values()
            .map(|&count| count as f64 / self.authority_checks as f64)
            .fold(0.0f64, f64::max);
        (max_rejection_rate * 2.0).clamp(0.0, 1.0)
    }

    // -- Detector 3: Replay / k-mer similarity ----------------------------

    fn score_replay_similarity(&self, fp: &BundleFingerprint) -> f64 {
        if self.rejected_window.is_empty() || fp.kmers.is_empty() {
            return 0.0;
        }
        let mut max_overlap = 0.0f64;
        for prev in &self.rejected_window {
            let overlap = jaccard(&fp.kmers, &prev.kmers);
            if overlap > max_overlap {
                max_overlap = overlap;
            }
        }
        // Jaccard ≥ 0.7 with a previously rejected bundle is highly
        // suspicious — likely a replay or near-clone.
        max_overlap.clamp(0.0, 1.0)
    }

    // -- Detector 4: Drift in cumulative volume ---------------------------

    fn score_drift(&mut self, principal: &str, volume: f64) -> f64 {
        if principal.is_empty() {
            return 0.0;
        }
        let shift = self.drift.update(principal, volume);
        // A shift of 1000 bases in the running mean is notable.
        (shift / 1000.0).clamp(0.0, 1.0)
    }

    // -- Detector 5: Fragmentation / payload-size anomaly -----------------

    fn score_anomaly(&self, fp: &BundleFingerprint) -> f64 {
        if self.window.len() < 10 {
            return 0.0;
        }
        // 5a. Payload-length z-score.
        let mean: f64 = self
            .window
            .iter()
            .map(|f| f.payload_len as f64)
            .sum::<f64>()
            / self.window.len() as f64;
        let var: f64 = self
            .window
            .iter()
            .map(|f| {
                let d = f.payload_len as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / self.window.len() as f64;
        let std = var.sqrt();
        let z = if std > 1e-9 {
            ((fp.payload_len as f64 - mean) / std).abs()
        } else if (fp.payload_len as f64 - mean).abs() > 1e-9 {
            10.0
        } else {
            0.0
        };
        let z_score = ((z - 1.0) / 3.0).clamp(0.0, 1.0);

        // 5b. Fragmentation: how much does this fingerprint's k-mer set
        // overlap with each prior bundle's? Many small overlaps across the
        // window suggests fragments of a single larger target (§3.1).
        let mut frag_hits = 0u32;
        for prev in &self.window {
            let j = jaccard(&fp.kmers, &prev.kmers);
            if (0.05..0.5).contains(&j) {
                frag_hits += 1;
            }
        }
        let frag_score = (frag_hits as f64 / self.window.len() as f64).clamp(0.0, 1.0);

        (z_score.max(frag_score)).clamp(0.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fingerprint(bundle: &SynthesisBundle) -> BundleFingerprint {
    let (payload_len, kmers) = match &bundle.payload {
        SynthesisPayload::Dna { sequence } => (sequence.len(), kmers(sequence, 12)),
        SynthesisPayload::Peptide { sequence } => (sequence.len(), kmers(sequence, 6)),
        SynthesisPayload::Chemical { smiles } => (smiles.len(), kmers(smiles, 6)),
        SynthesisPayload::Protocol { steps } => {
            let len: usize = steps.iter().map(|s| s.len()).sum();
            let joined = steps.join("\n");
            (len, kmers(&joined, 8))
        }
    };
    BundleFingerprint {
        payload_len,
        kmers,
        rejected: false,
    }
}

/// Compute the set of k-mer hashes for a string.
fn kmers(s: &str, k: usize) -> Vec<u64> {
    if s.len() < k || k == 0 {
        return Vec::new();
    }
    let bytes = s.as_bytes();
    let mut out: Vec<u64> = (0..=bytes.len() - k)
        .map(|i| {
            // FNV-1a hash of the k-mer.
            let mut h: u64 = 0xcbf29ce484222325;
            for &b in &bytes[i..i + k] {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Jaccard similarity between two sorted-deduped k-mer hash lists.
fn jaccard(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let mut i = 0;
    let mut j = 0;
    let mut inter = 0usize;
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => {
                inter += 1;
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
        }
    }
    let union = a.len() + b.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::bundle::{BundleAuthority, SynthesisPayload};
    use chrono::Utc;

    fn profile() -> BioProfile {
        BioProfile {
            name: "test".into(),
            version: "0.1.0".into(),
            bsl_level: 2,
            allowed_substrates: vec!["dna".into()],
            max_synthesis_volume_ml: 5.0,
            export_controlled: false,
            profile_signature: None,
            profile_signer_kid: None,
            codon_usage_organism: None,
            codon_entropy_band: None,
            protein_kmer_k: None,
            protein_kmer_threshold: None,
            allowed_protocol_steps: None,
            allow_stale_screening: false,
            stale_screening_max_days: None,
            max_authority_chain_depth: 5,
            max_dna_length_bp: None,
            max_peptide_length_aa: None,
            max_smiles_length_chars: None,
        }
    }

    fn dna_bundle(seq: &str, sequence_no: u64) -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "t".into(),
            sequence: sequence_no,
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

    #[test]
    fn default_config_window_and_threshold() {
        let cfg = ThreatScorerConfig::default();
        assert_eq!(cfg.window_size, 100);
        assert!((cfg.alert_threshold - 0.7).abs() < 1e-9);
    }

    #[test]
    fn weights_sum_to_one() {
        let w = ThreatScorerConfig::default().weights;
        let s =
            w.boundary_clustering + w.authority_probing + w.replay_similarity + w.drift + w.anomaly;
        assert!((s - 1.0).abs() < 1e-9);
    }

    #[test]
    fn first_bundle_produces_zero_or_low_score() {
        let mut scorer = ThreatScorer::with_defaults();
        let b = dna_bundle("ATGCGTATGCGT", 1);
        let analysis = scorer.score(&b, &profile(), true, "alice", true);
        assert!(analysis.composite_threat_score < 0.5);
        assert!(!analysis.alert);
    }

    #[test]
    fn replay_of_rejected_bundle_increases_score() {
        let mut scorer = ThreatScorer::with_defaults();
        let pf = profile();
        let b = dna_bundle("ATGCGTACGTACGTACGTACGTACGT", 1);
        // First call: rejected.
        let _ = scorer.score(&b, &pf, true, "alice", false);
        // Replay the same bundle.
        let analysis = scorer.score(&b, &pf, true, "alice", true);
        assert!(analysis.replay_similarity_score > 0.5);
    }

    #[test]
    fn authority_probing_after_repeated_rejections() {
        let mut scorer = ThreatScorer::with_defaults();
        let pf = profile();
        for i in 0..10 {
            let b = dna_bundle("ATGCGTATGCGTACGTACGT", i);
            let _ = scorer.score(&b, &pf, false, "mallory", false);
        }
        let b = dna_bundle("ATGCGTATGCGTACGTACGT", 99);
        let a = scorer.score(&b, &pf, false, "mallory", false);
        assert!(a.authority_probing_score > 0.5);
    }

    #[test]
    fn jaccard_is_one_for_identical_sets() {
        let a = vec![1u64, 2, 3];
        let b = vec![1u64, 2, 3];
        assert!((jaccard(&a, &b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn jaccard_is_zero_for_non_overlapping_sets() {
        let a = vec![1u64, 2, 3];
        let b = vec![4u64, 5, 6];
        assert!(jaccard(&a, &b) < 1e-9);
    }

    #[test]
    fn alert_fires_above_threshold() {
        let cfg = ThreatScorerConfig {
            alert_threshold: 0.0, // anything > 0 alerts
            ..Default::default()
        };
        let mut scorer = ThreatScorer::new(cfg);
        let pf = profile();
        for i in 0..6 {
            let b = dna_bundle("AAAAAAAAAAAAAA", i);
            let _ = scorer.score(&b, &pf, false, "mallory", false);
        }
        let b = dna_bundle("AAAAAAAAAAAAAA", 99);
        let a = scorer.score(&b, &pf, false, "mallory", false);
        assert!(a.alert);
    }
}
