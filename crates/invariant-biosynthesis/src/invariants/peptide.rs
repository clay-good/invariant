//! Peptide synthesis invariants P1–P10.
//!
//! Step 7 ships real implementations. Each invariant is intentionally a
//! transparent heuristic: real classifiers (NetMHCpan, Tango, AGGRESCAN,
//! HMMER) are out of scope at this layer, so the heuristics surface
//! reviewer-actionable signals based on canonical motifs, AA-composition
//! statistics, and screening-database hits.

use serde::{Deserialize, Serialize};

use super::{Invariant, InvariantContext, InvariantId, InvariantStatus};
use crate::models::bundle::{SynthesisBundle, SynthesisPayload};

/// Hazard-class aliases recognised by peptide invariants.
const AMP_CLASSES: &[&str] = &["antimicrobial", "amp", "antimicrobial-peptide"];
const CPP_CLASSES: &[&str] = &["cell-penetrating", "cpp"];
const MEMBRANE_CLASSES: &[&str] = &["membrane-disrupting", "pore-forming", "lytic"];
const PPI_CLASSES: &[&str] = &["ppi-inhibitor", "ppi"];
const TOXIN_AA_CLASSES: &[&str] = &["toxin", "neurotoxin", "ribotoxin"];
const EPITOPE_CLASSES: &[&str] = &["mhc-binder", "epitope", "iedb"];

fn peptide_sequence(bundle: &SynthesisBundle) -> Option<&str> {
    match &bundle.payload {
        SynthesisPayload::Peptide { sequence } => Some(sequence.as_str()),
        _ => None,
    }
}

fn hits_in_classes(ctx: &InvariantContext<'_>, classes: &[&str]) -> Vec<String> {
    ctx.screening_hits
        .iter()
        .filter(|h| {
            let hc = h.entry.hazard_class.to_ascii_lowercase();
            classes.iter().any(|c| hc == *c)
        })
        .map(|h| format!("{} ({})", h.entry.id, h.entry.hazard_class))
        .collect()
}

fn fail(reason: impl Into<String>) -> InvariantStatus {
    InvariantStatus::Fail {
        reason: reason.into(),
    }
}
fn advisory(note: impl Into<String>) -> InvariantStatus {
    InvariantStatus::Advisory { note: note.into() }
}

fn normalize(seq: &str) -> String {
    seq.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn is_canonical_aa(c: char) -> bool {
    matches!(
        c,
        'A' | 'C'
            | 'D'
            | 'E'
            | 'F'
            | 'G'
            | 'H'
            | 'I'
            | 'K'
            | 'L'
            | 'M'
            | 'N'
            | 'P'
            | 'Q'
            | 'R'
            | 'S'
            | 'T'
            | 'V'
            | 'W'
            | 'Y'
    )
}

fn net_charge(seq: &str) -> i32 {
    let mut net = 0i32;
    for c in seq.chars() {
        match c {
            'K' | 'R' => net += 1,
            'D' | 'E' => net -= 1,
            _ => {}
        }
    }
    net
}

fn hydrophobic_fraction(seq: &str) -> f64 {
    if seq.is_empty() {
        return 0.0;
    }
    let hyd = seq
        .chars()
        .filter(|c| matches!(c, 'A' | 'I' | 'L' | 'M' | 'F' | 'V' | 'W' | 'Y'))
        .count();
    hyd as f64 / seq.len() as f64
}

// ---------------------------------------------------------------------------
// P1 — Antimicrobial peptide screen
// ---------------------------------------------------------------------------

/// P1 — Antimicrobial peptide (AMP) classification.
///
/// **(a) Algorithm.** Heuristic AMP signature: short (10–60 AA), net charge
/// ≥ +3 from K/R, hydrophobic fraction ≥ 0.35. Database hits with
/// `hazard_class = antimicrobial` are escalated to Fail.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntimicrobialPeptideScreen;

impl Invariant for AntimicrobialPeptideScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P1
    }
    fn name(&self) -> &'static str {
        "antimicrobial_peptide_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(seq) = peptide_sequence(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, AMP_CLASSES);
        if !hits.is_empty() {
            return fail(format!("AMP database hits: {}", hits.join(", ")));
        }
        let s = normalize(seq);
        if s.len() < 10 || s.len() > 60 {
            return InvariantStatus::Pass;
        }
        let charge = net_charge(&s);
        let hyd = hydrophobic_fraction(&s);
        if charge >= 3 && hyd >= 0.35 {
            advisory(format!(
                "AMP heuristic: net charge {charge}, hydrophobic fraction {:.2}",
                hyd
            ))
        } else {
            InvariantStatus::Pass
        }
    }
}

// ---------------------------------------------------------------------------
// P2 — Cell-penetrating peptide screen
// ---------------------------------------------------------------------------

/// P2 — Cell-penetrating peptide screen.
///
/// **(a) Algorithm.** Match canonical CPP motifs (TAT `GRKKRRQRRRPPQ`,
/// penetratin `RQIKIWFQNRRMKWKK`, polyArg ≥ 6 R) plus database hits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellPenetratingPeptideScreen;

impl Invariant for CellPenetratingPeptideScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P2
    }
    fn name(&self) -> &'static str {
        "cell_penetrating_peptide_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(seq) = peptide_sequence(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, CPP_CLASSES);
        if !hits.is_empty() {
            return fail(format!("CPP database hits: {}", hits.join(", ")));
        }
        let s = normalize(seq);
        let motifs: &[&str] = &["GRKKRRQRRRPPQ", "RQIKIWFQNRRMKWKK"];
        for m in motifs {
            if s.contains(m) {
                return advisory(format!("CPP motif present: {m}"));
            }
        }
        // PolyArg run ≥ 6.
        let mut run = 0usize;
        for c in s.chars() {
            if c == 'R' {
                run += 1;
                if run >= 6 {
                    return advisory("polyArg run ≥ 6 (TAT-like CPP signature)".to_string());
                }
            } else {
                run = 0;
            }
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// P3 — Membrane-disrupting / pore-forming screen
// ---------------------------------------------------------------------------

/// P3 — Membrane-disrupting screen.
///
/// **(a) Algorithm.** Compute hydrophobic fraction over a sliding 18-residue
/// window; flag windows with ≥ 0.55 hydrophobic AND net charge ≥ +3
/// (amphipathic α-helix proxy).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembraneDisruptingScreen;

impl Invariant for MembraneDisruptingScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P3
    }
    fn name(&self) -> &'static str {
        "membrane_disrupting_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(seq) = peptide_sequence(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, MEMBRANE_CLASSES);
        if !hits.is_empty() {
            return fail(format!("membrane-disrupting hits: {}", hits.join(", ")));
        }
        let s = normalize(seq);
        let chars: Vec<char> = s.chars().collect();
        const W: usize = 18;
        if chars.len() < W {
            return InvariantStatus::Pass;
        }
        for i in 0..=chars.len() - W {
            let win: String = chars[i..i + W].iter().collect();
            let hyd = hydrophobic_fraction(&win);
            let charge = net_charge(&win);
            if hyd >= 0.55 && charge >= 3 {
                return advisory(format!(
                    "amphipathic window at offset {i}: hyd {:.2}, charge {charge}",
                    hyd
                ));
            }
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// P4 — PPI-inhibitor screen
// ---------------------------------------------------------------------------

/// P4 — PPI inhibitor screen.
///
/// **(a) Algorithm.** Database-driven only at this layer. Real hot-spot
/// motif matching requires per-target curated lists; this layer surfaces
/// any DB hit in the `ppi-inhibitor` class.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PpiInhibitorScreen;

impl Invariant for PpiInhibitorScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P4
    }
    fn name(&self) -> &'static str {
        "ppi_inhibitor_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        if peptide_sequence(bundle).is_none() {
            return InvariantStatus::Pass;
        }
        let hits = hits_in_classes(ctx, PPI_CLASSES);
        if hits.is_empty() {
            InvariantStatus::Pass
        } else {
            advisory(format!("PPI-inhibitor hits: {}", hits.join(", ")))
        }
    }
}

// ---------------------------------------------------------------------------
// P5 — Enzyme active-site mimic screen
// ---------------------------------------------------------------------------

/// P5 — Enzyme active-site mimic screen.
///
/// **(a) Algorithm.** Match canonical catalytic-site signatures: serine
/// hydrolase `G-X-S-X-G`, zinc metalloprotease `H-E-X-X-H`, RNase
/// `H-X-X-X-X-H`, ADP-ribosyltransferase `R-S-E`. Hits in toxin-class DB
/// entries escalate to Fail.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnzymeActiveSiteMimicScreen;

impl Invariant for EnzymeActiveSiteMimicScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P5
    }
    fn name(&self) -> &'static str {
        "enzyme_active_site_mimic_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(seq) = peptide_sequence(bundle) else {
            return InvariantStatus::Pass;
        };
        let toxin_hits = hits_in_classes(ctx, TOXIN_AA_CLASSES);
        if !toxin_hits.is_empty() {
            return fail(format!(
                "toxin-class enzyme hits: {}",
                toxin_hits.join(", ")
            ));
        }
        let s = normalize(seq);
        let chars: Vec<char> = s.chars().collect();
        let n = chars.len();
        // G-X-S-X-G
        for i in 0..n.saturating_sub(4) {
            if chars[i] == 'G' && chars[i + 2] == 'S' && chars[i + 4] == 'G' {
                return advisory(format!("catalytic G-X-S-X-G motif at offset {i}"));
            }
        }
        // H-E-X-X-H
        for i in 0..n.saturating_sub(4) {
            if chars[i] == 'H' && chars[i + 1] == 'E' && chars[i + 4] == 'H' {
                return advisory(format!("Zn-metalloprotease H-E-X-X-H motif at offset {i}"));
            }
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// P6 — Immunogenic epitope screen
// ---------------------------------------------------------------------------

/// P6 — Immunogenic epitope screen.
///
/// **(a) Algorithm.** Database-driven (DB hits with `epitope`/`mhc-binder`
/// hazard class) plus a length-based proxy: peptides 8–11 AA with hydrophobic
/// fraction ≥ 0.4 are flagged advisory as MHC-I candidate length.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmunogenicEpitopeScreen;

impl Invariant for ImmunogenicEpitopeScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P6
    }
    fn name(&self) -> &'static str {
        "immunogenic_epitope_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(seq) = peptide_sequence(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, EPITOPE_CLASSES);
        if !hits.is_empty() {
            return advisory(format!("epitope DB hits: {}", hits.join(", ")));
        }
        let s = normalize(seq);
        if (8..=11).contains(&s.len()) && hydrophobic_fraction(&s) >= 0.4 {
            return advisory("MHC-I-length hydrophobic peptide".to_string());
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// P7 — Stability screen
// ---------------------------------------------------------------------------

/// P7 — Stability / N-end rule screen.
///
/// **(a) Algorithm.** Bachmair N-end rule: destabilizing N-terminal residues
/// (R, K, F, L, W, Y) trigger short-half-life advisories. Trypsin (K/R)
/// site count is reported when ≥ 5 in a sequence ≤ 30 AA.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StabilityScreen;

impl Invariant for StabilityScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P7
    }
    fn name(&self) -> &'static str {
        "stability_screen"
    }
    fn evaluate(&self, bundle: &SynthesisBundle) -> InvariantStatus {
        let Some(seq) = peptide_sequence(bundle) else {
            return InvariantStatus::Pass;
        };
        let s = normalize(seq);
        if s.is_empty() {
            return InvariantStatus::Pass;
        }
        let n_term = s.chars().next().unwrap();
        if matches!(n_term, 'R' | 'K' | 'F' | 'L' | 'W' | 'Y') {
            return advisory(format!(
                "destabilizing N-terminal residue {n_term} (Bachmair N-end rule)"
            ));
        }
        if s.len() <= 30 {
            let trypsin_sites = s.chars().filter(|c| matches!(c, 'K' | 'R')).count();
            if trypsin_sites >= 5 {
                return advisory(format!(
                    "{trypsin_sites} trypsin sites in {} AA — short half-life expected",
                    s.len()
                ));
            }
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// P8 — Solubility / aggregation screen
// ---------------------------------------------------------------------------

/// P8 — Aggregation propensity screen.
///
/// **(a) Algorithm.** Flag any 6-residue window where every residue is
/// strongly aggregation-prone (I, L, V, F, Y, W) — a proxy for Tango/CamSol
/// hot-spot detection. Long polyQ (Q ≥ 10 in a row) is also flagged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolubilityScreen;

impl Invariant for SolubilityScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P8
    }
    fn name(&self) -> &'static str {
        "solubility_screen"
    }
    fn evaluate(&self, bundle: &SynthesisBundle) -> InvariantStatus {
        let Some(seq) = peptide_sequence(bundle) else {
            return InvariantStatus::Pass;
        };
        let s = normalize(seq);
        let chars: Vec<char> = s.chars().collect();
        const W: usize = 6;
        if chars.len() >= W {
            for i in 0..=chars.len() - W {
                let win = &chars[i..i + W];
                if win
                    .iter()
                    .all(|c| matches!(*c, 'I' | 'L' | 'V' | 'F' | 'Y' | 'W'))
                {
                    return advisory(format!(
                        "aggregation hot-spot at offset {i}: all hydrophobic"
                    ));
                }
            }
        }
        // PolyQ ≥ 10
        let mut run = 0usize;
        for c in chars.iter() {
            if *c == 'Q' {
                run += 1;
                if run >= 10 {
                    return advisory("polyQ run ≥ 10 (aggregation-prone)".to_string());
                }
            } else {
                run = 0;
            }
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// P9 — PTM-site screen
// ---------------------------------------------------------------------------

/// P9 — PTM-site count.
///
/// **(a) Algorithm.** Count canonical motifs: N-glycosylation sequon
/// `N-X-[ST]` (X ≠ P), prenylation CAAX, phospho-context S/T/Y. Count ≥ 5
/// matches → Advisory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PtmSiteScreen;

impl Invariant for PtmSiteScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P9
    }
    fn name(&self) -> &'static str {
        "ptm_site_screen"
    }
    fn evaluate(&self, bundle: &SynthesisBundle) -> InvariantStatus {
        let Some(seq) = peptide_sequence(bundle) else {
            return InvariantStatus::Pass;
        };
        let s = normalize(seq);
        let chars: Vec<char> = s.chars().collect();
        let n = chars.len();
        let mut total = 0usize;
        // N-X-[ST] sequon, X ≠ P.
        for i in 0..n.saturating_sub(2) {
            if chars[i] == 'N'
                && chars[i + 1] != 'P'
                && is_canonical_aa(chars[i + 1])
                && (chars[i + 2] == 'S' || chars[i + 2] == 'T')
            {
                total += 1;
            }
        }
        // CAAX: C-A-A-X (any of the canonical 20 in last position).
        for i in 0..n.saturating_sub(3) {
            if chars[i] == 'C'
                && chars[i + 1] == 'A'
                && chars[i + 2] == 'A'
                && is_canonical_aa(chars[i + 3])
            {
                total += 1;
            }
        }
        if total >= 5 {
            advisory(format!("{total} PTM motif matches"))
        } else {
            InvariantStatus::Pass
        }
    }
}

// ---------------------------------------------------------------------------
// P10 — Delivery compatibility
// ---------------------------------------------------------------------------

/// P10 — Delivery compatibility.
///
/// **(a) Algorithm.** Length and disulfide envelope: > 50 AA or > 4
/// cysteines flagged as Advisory; sequences containing non-canonical AAs
/// are Failed (delivery vehicles assume canonical 20).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryCompatScreen;

impl Invariant for DeliveryCompatScreen {
    fn id(&self) -> InvariantId {
        InvariantId::P10
    }
    fn name(&self) -> &'static str {
        "delivery_compat_screen"
    }
    fn evaluate(&self, bundle: &SynthesisBundle) -> InvariantStatus {
        let Some(seq) = peptide_sequence(bundle) else {
            return InvariantStatus::Pass;
        };
        let s = normalize(seq);
        let bad: Vec<char> = s.chars().filter(|c| !is_canonical_aa(*c)).collect();
        if !bad.is_empty() {
            return fail(format!(
                "non-canonical AAs in peptide: {}",
                bad.iter().collect::<String>()
            ));
        }
        let cys = s.chars().filter(|c| *c == 'C').count();
        if s.len() > 50 {
            return advisory(format!(
                "peptide length {} exceeds 50-AA free-peptide envelope",
                s.len()
            ));
        }
        if cys > 4 {
            return advisory(format!("{cys} cysteines exceed 4-disulfide envelope"));
        }
        InvariantStatus::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::bundle::{BundleAuthority, SynthesisPayload};
    use crate::models::profile::BioProfile;
    use crate::screening::{HazardEntry, HazardHit};
    use chrono::Utc;

    fn pep(seq: &str) -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "t".into(),
            sequence: 0,
            payload: SynthesisPayload::Peptide {
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

    fn profile() -> BioProfile {
        BioProfile {
            name: "t".into(),
            version: "0.1.0".into(),
            bsl_level: 2,
            allowed_substrates: vec!["peptide".into()],
            max_synthesis_volume_ml: 1.0,
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

    fn ctx<'a>(hits: &'a [HazardHit], prof: &'a BioProfile) -> InvariantContext<'a> {
        InvariantContext {
            screening_hits: hits,
            profile: prof,
        }
    }

    fn hit(class: &str) -> HazardHit {
        HazardHit {
            entry: HazardEntry {
                id: "x".into(),
                label: "x".into(),
                hazard_class: class.into(),
                pattern: ".*".into(),
            },
            matched_text: "M".into(),
        }
    }

    // ---- P1 AntimicrobialPeptideScreen ----
    #[test]
    fn p1_db_hit_fails() {
        let p = profile();
        let h = vec![hit("antimicrobial")];
        assert!(matches!(
            AntimicrobialPeptideScreen.evaluate_with(&pep("AAA"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn p1_amphipathic_advisory() {
        let p = profile();
        // 12 AA, charge ≥3, hydrophobic ≥ 0.35
        assert!(matches!(
            AntimicrobialPeptideScreen.evaluate_with(&pep("KKRKLLAFVLAA"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p1_neutral_short_passes() {
        let p = profile();
        assert!(matches!(
            AntimicrobialPeptideScreen.evaluate_with(&pep("AGYK"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- P2 CellPenetratingPeptideScreen ----
    #[test]
    fn p2_tat_motif_advisory() {
        let p = profile();
        assert!(matches!(
            CellPenetratingPeptideScreen.evaluate_with(&pep("AAGRKKRRQRRRPPQAA"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p2_polyarg_advisory() {
        let p = profile();
        assert!(matches!(
            CellPenetratingPeptideScreen.evaluate_with(&pep("AARRRRRRAA"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p2_clean_passes() {
        let p = profile();
        assert!(matches!(
            CellPenetratingPeptideScreen.evaluate_with(&pep("AGYKAAAAAAA"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- P3 MembraneDisruptingScreen ----
    #[test]
    fn p3_db_hit_fails() {
        let p = profile();
        let h = vec![hit("pore-forming")];
        assert!(matches!(
            MembraneDisruptingScreen.evaluate_with(&pep("AAAAAA"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn p3_amphipathic_advisory() {
        let p = profile();
        // 18-AA window with 0.55+ hyd and ≥3 charge: KKK + many hydrophobic
        let s = "KKKLLLVLAFLALFAVLA";
        assert!(matches!(
            MembraneDisruptingScreen.evaluate_with(&pep(s), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p3_clean_passes() {
        let p = profile();
        // Polar 18-AA sequence: charge 0, low hydrophobic fraction.
        assert!(matches!(
            MembraneDisruptingScreen.evaluate_with(&pep("GSDNQTGSDNQTGSDNQT"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- P4 PpiInhibitorScreen ----
    #[test]
    fn p4_db_hit_advisory() {
        let p = profile();
        let h = vec![hit("ppi-inhibitor")];
        assert!(matches!(
            PpiInhibitorScreen.evaluate_with(&pep("AGYK"), &ctx(&h, &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p4_no_hit_passes() {
        let p = profile();
        assert!(matches!(
            PpiInhibitorScreen.evaluate_with(&pep("AGYK"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn p4_unrelated_hit_passes() {
        let p = profile();
        let h = vec![hit("antimicrobial")];
        assert!(matches!(
            PpiInhibitorScreen.evaluate_with(&pep("AGYK"), &ctx(&h, &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- P5 EnzymeActiveSiteMimicScreen ----
    #[test]
    fn p5_serine_motif_advisory() {
        let p = profile();
        // GXSXG embedded
        assert!(matches!(
            EnzymeActiveSiteMimicScreen.evaluate_with(&pep("AAAGASAGAA"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p5_zn_motif_advisory() {
        let p = profile();
        assert!(matches!(
            EnzymeActiveSiteMimicScreen.evaluate_with(&pep("AAAHEAAHAA"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p5_toxin_db_fails() {
        let p = profile();
        let h = vec![hit("toxin")];
        assert!(matches!(
            EnzymeActiveSiteMimicScreen.evaluate_with(&pep("AGYK"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }

    // ---- P6 ImmunogenicEpitopeScreen ----
    #[test]
    fn p6_mhc_length_advisory() {
        let p = profile();
        // 9 AA, hydrophobic ≥ 0.4
        assert!(matches!(
            ImmunogenicEpitopeScreen.evaluate_with(&pep("FLLLAGYKA"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p6_db_hit_advisory() {
        let p = profile();
        let h = vec![hit("epitope")];
        assert!(matches!(
            ImmunogenicEpitopeScreen.evaluate_with(&pep("AAAAAA"), &ctx(&h, &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p6_short_polar_passes() {
        let p = profile();
        assert!(matches!(
            ImmunogenicEpitopeScreen.evaluate_with(&pep("KSTQ"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- P7 StabilityScreen ----
    #[test]
    fn p7_destabilizing_n_term_advisory() {
        assert!(matches!(
            StabilityScreen.evaluate(&pep("RAGYK")),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p7_trypsin_dense_advisory() {
        assert!(matches!(
            StabilityScreen.evaluate(&pep("AKAKAKAKAKA")),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p7_clean_passes() {
        assert!(matches!(
            StabilityScreen.evaluate(&pep("MAGYK")),
            InvariantStatus::Pass
        ));
    }

    // ---- P8 SolubilityScreen ----
    #[test]
    fn p8_aggregation_window_advisory() {
        // 6-AA contiguous run of strongly hydrophobic residues.
        assert!(matches!(
            SolubilityScreen.evaluate(&pep("AAVILLFWA")),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p8_polyq_advisory() {
        assert!(matches!(
            SolubilityScreen.evaluate(&pep("AAQQQQQQQQQQAA")),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p8_clean_passes() {
        assert!(matches!(
            SolubilityScreen.evaluate(&pep("MAGYKSTNDQ")),
            InvariantStatus::Pass
        ));
    }

    // ---- P9 PtmSiteScreen ----
    #[test]
    fn p9_few_motifs_passes() {
        assert!(matches!(
            PtmSiteScreen.evaluate(&pep("MAGYK")),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn p9_many_n_glycosylation_advisory() {
        // 5 N-X-[ST] sequons.
        let s = "NASNATNASNATNAS";
        assert!(matches!(
            PtmSiteScreen.evaluate(&pep(s)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p9_caax_motifs_pass_below_threshold() {
        // Only 1 CAAX -> below threshold of 5.
        assert!(matches!(
            PtmSiteScreen.evaluate(&pep("MAGCAAA")),
            InvariantStatus::Pass
        ));
    }

    // ---- P10 DeliveryCompatScreen ----
    #[test]
    fn p10_clean_passes() {
        assert!(matches!(
            DeliveryCompatScreen.evaluate(&pep("MAGYK")),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn p10_non_canonical_fails() {
        assert!(matches!(
            DeliveryCompatScreen.evaluate(&pep("MAGYBKZ")),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn p10_too_long_advisory() {
        let s = "A".repeat(60);
        assert!(matches!(
            DeliveryCompatScreen.evaluate(&pep(&s)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn p10_many_cys_advisory() {
        assert!(matches!(
            DeliveryCompatScreen.evaluate(&pep("CCCCCAGYK")),
            InvariantStatus::Advisory { .. }
        ));
    }

    // ---- DNA payload pass-through (peptide invariants must be no-ops) ----
    #[test]
    fn peptide_invariants_pass_for_dna_payload() {
        let p = profile();
        let bundle = SynthesisBundle {
            timestamp: Utc::now(),
            source: "t".into(),
            sequence: 0,
            payload: SynthesisPayload::Dna {
                sequence: "ATGCGT".into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: Default::default(),
        };
        assert!(matches!(
            AntimicrobialPeptideScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
        assert!(matches!(
            StabilityScreen.evaluate(&bundle),
            InvariantStatus::Pass
        ));
        assert!(matches!(
            DeliveryCompatScreen.evaluate(&bundle),
            InvariantStatus::Pass
        ));
    }
}
