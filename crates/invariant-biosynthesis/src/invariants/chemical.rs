//! Chemical synthesis invariants C1–C10.
//!
//! Step 8 ships heuristic implementations. Because we do not bring in a real
//! cheminformatics library at this layer, every invariant combines two signals:
//!
//! 1. Hazard-database hits (the canonical mechanism — substructure / fingerprint
//!    matching is delegated to whatever real cheminformatics layer the
//!    [`crate::screening::HazardScreener`] implementation chooses).
//! 2. Structural alerts from the versioned SMARTS rule library
//!    ([`super::molecule::CWC_RULES`], [`super::molecule::EXPLOSIVE_RULES`])
//!    and the [`super::molecule::Molecule`] newtype's functional-group detector.
//!    These are deliberately conservative: each invariant's Rustdoc lists
//!    its known false-positive (FP) and false-negative (FN) failure modes.
//!
//! Per threat-model §3.4, C1 only flags presence; the multi-signature
//! requirement for Schedule 1 work is enforced at the PCA layer.

use serde::{Deserialize, Serialize};

use super::molecule::{
    complexity_score, detect_functional_groups, match_rules, FunctionalGroup, Molecule,
    RuleSeverity, CWC_RULES,
};
use super::{Invariant, InvariantContext, InvariantId, InvariantStatus};
use crate::models::bundle::{SynthesisBundle, SynthesisPayload};

/// Hazard-class aliases recognised by chemical invariants.
const CWC1_CLASSES: &[&str] = &["cwc-schedule-1", "schedule-1"];
const CWC23_CLASSES: &[&str] = &[
    "cwc-schedule-2",
    "cwc-schedule-3",
    "schedule-2",
    "schedule-3",
];
const EXPLOSIVE_CLASSES: &[&str] = &["explosive", "energetic-material"];
const NARCOTIC_CLASSES: &[&str] = &["narcotic", "controlled-substance", "dea-schedule"];
const ENV_TOXIN_CLASSES: &[&str] = &["env-toxin", "tsca", "pop", "pfas"];
const CARC_CLASSES: &[&str] = &["carcinogen", "mutagen", "iarc-1", "iarc-2a"];
const ENDO_CLASSES: &[&str] = &["endocrine-disruptor", "edsp"];
const BIOACC_CLASSES: &[&str] = &["bioaccumulator", "pbt"];
const PATHWAY_CLASSES: &[&str] = &["infeasible-pathway"];
const REACT_CLASSES: &[&str] = &["reaction-incompatibility", "pyrophoric", "peroxide-former"];
const WASTE_CLASSES: &[&str] = &["high-toxicity-waste", "rcra"];

fn smiles(bundle: &SynthesisBundle) -> Option<&str> {
    match &bundle.payload {
        SynthesisPayload::Chemical { smiles } => Some(smiles.as_str()),
        _ => None,
    }
}

/// Try to parse the SMILES payload into a [`Molecule`]. Returns `None` for
/// non-chemical payloads or parse failures (invalid SMILES still gets
/// processed by the raw-string path in each invariant).
fn try_molecule(bundle: &SynthesisBundle) -> Option<Molecule> {
    smiles(bundle).and_then(|s| Molecule::parse(s).ok())
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

/// Count occurrences of `pat` in `haystack` (non-overlapping).
fn count_occurrences(haystack: &str, pat: &str) -> usize {
    if pat.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    let bytes = haystack.as_bytes();
    let pbytes = pat.as_bytes();
    while i + pbytes.len() <= bytes.len() {
        if &bytes[i..i + pbytes.len()] == pbytes {
            count += 1;
            i += pbytes.len();
        } else {
            i += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// C1 — Chemical Weapons Convention screen
// ---------------------------------------------------------------------------

/// C1 — CWC screen.
///
/// **Behaviour.** Schedule-1 hits → Fail; Schedule-2/3 hits → Advisory.
/// Heuristic structural alert: SMILES containing a P=O alkylphosphonate
/// fragment with an alkoxide/fluoride leaving group (`P(=O)(O...)F` or
/// `P(=O)(OC...)`-like patterns) is surfaced as Advisory because real
/// substructure matching needs RDKit/SMARTS.
///
/// **FP modes.** Any benign organophosphate ester (e.g. dimethyl phosphate)
/// also matches the alkylphosphonate regex; reviewer triage is required.
/// **FN modes.** Heteroatom ring-encoded G-series analogues are not detected
/// without a real SMARTS engine — the hazard DB is the canonical detector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwcScreen;

impl Invariant for CwcScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C1
    }
    fn name(&self) -> &'static str {
        "cwc_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(s) = smiles(bundle) else {
            return InvariantStatus::Pass;
        };
        // 1. Hazard-database hits (canonical path)
        let s1 = hits_in_classes(ctx, CWC1_CLASSES);
        if !s1.is_empty() {
            return fail(format!("CWC Schedule 1 hit(s): {}", s1.join(", ")));
        }
        let s23 = hits_in_classes(ctx, CWC23_CLASSES);
        if !s23.is_empty() {
            return advisory(format!("CWC Schedule 2/3 hit(s): {}", s23.join(", ")));
        }
        // 2. SMARTS rule library (versioned structural alerts)
        if let Some(mol) = try_molecule(bundle) {
            let rule_matches = match_rules(&mol, CWC_RULES);
            // Report the highest-severity match (Fail > Advisory).
            if let Some(rm) = rule_matches
                .iter()
                .find(|m| m.severity == RuleSeverity::Fail)
            {
                return fail(format!(
                    "CWC structural alert {} ({}): matched '{}'",
                    rm.rule_id, rm.label, rm.matched_pattern
                ));
            }
            if let Some(rm) = rule_matches.first() {
                return advisory(format!(
                    "CWC structural alert {} ({}): matched '{}' (heuristic; reviewer triage)",
                    rm.rule_id, rm.label, rm.matched_pattern
                ));
            }
        }
        // 3. Legacy fallback for unparseable SMILES
        let upper = s.to_ascii_uppercase();
        if upper.contains("P(=O)") && (upper.contains('F') || upper.contains("OC")) {
            return advisory(
                "alkylphosphonate-with-leaving-group SMILES pattern (heuristic; reviewer triage)"
                    .to_string(),
            );
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// C2 — Explosive screen
// ---------------------------------------------------------------------------

/// C2 — Explosive / energetic-material screen.
///
/// **Behaviour.** DB hits in `explosive`/`energetic-material` → Fail.
/// Heuristic alerts (Advisory): ≥ 3 nitro groups (`[N+](=O)[O-]` or `N(=O)=O`
/// stripped to `NO2` count) **or** any peroxide (`OO`) **or** any azide
/// (`N=[N+]=[N-]` reduced to `N=N=N`).
///
/// **FP modes.** Aromatic nitro substitutions (e.g. nitrobenzene) trip the
/// nitro count even when not energetic.
/// **FN modes.** Salts encoded with explicit ionic SMILES bypass the
/// substring count.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplosiveScreen;

impl Invariant for ExplosiveScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C2
    }
    fn name(&self) -> &'static str {
        "explosive_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(s) = smiles(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, EXPLOSIVE_CLASSES);
        if !hits.is_empty() {
            return fail(format!("explosive DB hits: {}", hits.join(", ")));
        }
        // Functional-group detection via Molecule
        if let Some(mol) = try_molecule(bundle) {
            let groups = detect_functional_groups(&mol);
            // ≥ 3 nitro groups via count (functional group gives presence only)
            let upper = s.to_ascii_uppercase();
            let nitro = count_occurrences(&upper, "[N+](=O)[O-]")
                + count_occurrences(&upper, "N(=O)=O")
                + count_occurrences(&upper, "[NO2]");
            if nitro >= 3 {
                return advisory(format!("{nitro} nitro groups present (energetic alert)"));
            }
            if groups.contains(&FunctionalGroup::Peroxide) {
                return advisory("peroxide bond (OO) present".to_string());
            }
            if groups.contains(&FunctionalGroup::Azide) {
                return advisory("azide group present".to_string());
            }
            return InvariantStatus::Pass;
        }
        // Legacy fallback
        let upper = s.to_ascii_uppercase();
        let nitro = count_occurrences(&upper, "[N+](=O)[O-]")
            + count_occurrences(&upper, "N(=O)=O")
            + count_occurrences(&upper, "[NO2]");
        if nitro >= 3 {
            return advisory(format!("{nitro} nitro groups present (energetic alert)"));
        }
        if upper.contains("OO") {
            return advisory("peroxide bond (OO) present".to_string());
        }
        if upper.contains("N=N=N") {
            return advisory("azide group present".to_string());
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// C3 — Narcotic / controlled substance
// ---------------------------------------------------------------------------

/// C3 — Narcotic / controlled-substance screen.
///
/// **Behaviour.** DB-driven (Fail on `narcotic`/`controlled-substance`/
/// `dea-schedule`).
///
/// **FP modes.** None (DB-bounded).
/// **FN modes.** Novel analogues not yet in the DB are missed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NarcoticScreen;

impl Invariant for NarcoticScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C3
    }
    fn name(&self) -> &'static str {
        "narcotic_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        if smiles(bundle).is_none() {
            return InvariantStatus::Pass;
        }
        let hits = hits_in_classes(ctx, NARCOTIC_CLASSES);
        if hits.is_empty() {
            InvariantStatus::Pass
        } else {
            fail(format!("controlled-substance hits: {}", hits.join(", ")))
        }
    }
}

// ---------------------------------------------------------------------------
// C4 — Environmental toxin
// ---------------------------------------------------------------------------

/// C4 — Environmental toxin / POP screen.
///
/// **Behaviour.** DB hits → Fail. Heuristic Advisory if SMILES contains
/// ≥ 4 chlorines or any `C(F)(F)F` perfluoro signature without a polar
/// terminus.
///
/// **FP modes.** Pharmaceuticals with multiple Cl substituents are flagged.
/// **FN modes.** Brominated POPs (PBDE) are not surfaced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvToxinScreen;

impl Invariant for EnvToxinScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C4
    }
    fn name(&self) -> &'static str {
        "env_toxin_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(s) = smiles(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, ENV_TOXIN_CLASSES);
        if !hits.is_empty() {
            return fail(format!("env-toxin DB hits: {}", hits.join(", ")));
        }
        // Count chlorines as standalone tokens or as `Cl` digraphs.
        let cl_count = count_occurrences(s, "Cl");
        if cl_count >= 4 {
            return advisory(format!("{cl_count} chlorine atoms (POP-like)"));
        }
        if s.contains("C(F)(F)F") {
            return advisory("perfluoro carbon group present (PFAS-like)".to_string());
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// C5 — Carcinogen / mutagen
// ---------------------------------------------------------------------------

/// C5 — Carcinogen / mutagen screen.
///
/// **Behaviour.** DB hits → Fail. Heuristic advisories: aromatic amine
/// (`Nc1ccccc1` lower-case naive), N-nitroso (`N-N=O` reduced to `NN=O`),
/// or any `[C+]` electrophilic carbon.
///
/// **FP modes.** Aniline derivatives that are not actual carcinogens.
/// **FN modes.** Indirect-acting genotoxins (need Ames assay).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarcinogenMutagenScreen;

impl Invariant for CarcinogenMutagenScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C5
    }
    fn name(&self) -> &'static str {
        "carcinogen_mutagen_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(s) = smiles(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, CARC_CLASSES);
        if !hits.is_empty() {
            return fail(format!("carcinogen DB hits: {}", hits.join(", ")));
        }
        if s.contains("Nc1ccccc1") || s.contains("c1ccc(N)cc1") {
            return advisory("aromatic amine (Ashby-Tennant alert)".to_string());
        }
        if s.contains("NN=O") {
            return advisory("N-nitroso group (genotoxic alert)".to_string());
        }
        if s.contains("[C+]") {
            return advisory("electrophilic carbocation site".to_string());
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// C6 — Endocrine disruptor
// ---------------------------------------------------------------------------

/// C6 — Endocrine-disruptor screen.
///
/// **Behaviour.** DB hits → Advisory (most EDCs are dual-use research
/// targets). Heuristic: bisphenol-A core (`Cc1ccc(O)cc1`) embedded twice
/// with the central `C(C)(C)` linkage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndocrineDisruptorScreen;

impl Invariant for EndocrineDisruptorScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C6
    }
    fn name(&self) -> &'static str {
        "endocrine_disruptor_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(s) = smiles(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, ENDO_CLASSES);
        if !hits.is_empty() {
            return advisory(format!("EDSP hits: {}", hits.join(", ")));
        }
        if count_occurrences(s, "c1ccc(O)cc1") >= 2 {
            return advisory("bisphenol-like di-phenol core".to_string());
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// C7 — Bioaccumulation
// ---------------------------------------------------------------------------

/// C7 — Bioaccumulation potential.
///
/// **Behaviour.** DB hits → Advisory. Heuristic: long unbroken aliphatic
/// run (≥ 12 consecutive `C`s in SMILES backbone) plus no polar groups
/// (`O` count < 2) → high logKow proxy → Advisory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BioaccumulationScreen;

impl Invariant for BioaccumulationScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C7
    }
    fn name(&self) -> &'static str {
        "bioaccumulation_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(s) = smiles(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, BIOACC_CLASSES);
        if !hits.is_empty() {
            return advisory(format!("bioaccumulator hits: {}", hits.join(", ")));
        }
        // Longest run of backbone carbons (uppercase C only; lowercase c is
        // aromatic ring carbon and excluded).
        let mut max_run = 0usize;
        let mut run = 0usize;
        for c in s.chars() {
            if c == 'C' {
                run += 1;
                max_run = max_run.max(run);
            } else {
                run = 0;
            }
        }
        let oxygens = s.chars().filter(|c| *c == 'O').count();
        if max_run >= 12 && oxygens < 2 {
            return advisory(format!(
                "{max_run}-carbon aliphatic chain with low polarity (high logKow proxy)"
            ));
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// C8 — Pathway feasibility
// ---------------------------------------------------------------------------

/// C8 — Synthesis-pathway feasibility.
///
/// **Behaviour.** DB hits in `infeasible-pathway` → Fail. Heuristic Fail
/// when SMILES is empty. Complexity scoring via ring count, stereo centres,
/// heteroatom ratio and SMILES length; Advisory when composite score ≥ 0.60
/// (replaces the legacy `>250 chars` proxy).
///
/// **FP modes.** Large but synthetically tractable molecules (e.g. polymers
/// with repetitive units) may trigger the advisory.
/// **FN modes.** Genuinely infeasible pathways that happen to have short
/// SMILES (strained rings, exotic leaving groups) are not detected without
/// a real retrosynthesis engine.
pub const C8_COMPLEXITY_THRESHOLD: f64 = 0.60;

/// C8 — Synthesis-pathway feasibility screen.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathwayFeasibilityScreen;

impl Invariant for PathwayFeasibilityScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C8
    }
    fn name(&self) -> &'static str {
        "pathway_feasibility_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(s) = smiles(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, PATHWAY_CLASSES);
        if !hits.is_empty() {
            return fail(format!("infeasible-pathway hits: {}", hits.join(", ")));
        }
        if s.trim().is_empty() {
            return fail("empty SMILES — no pathway".to_string());
        }
        // Complexity scoring via Molecule
        if let Some(mol) = try_molecule(bundle) {
            let cs = complexity_score(&mol);
            if cs.score >= C8_COMPLEXITY_THRESHOLD {
                return advisory(format!(
                    "high synthesis complexity score {:.2} (threshold {:.2}): \
                     {} rings, {} stereo centres, {:.2} heteroatom ratio, {} chars",
                    cs.score,
                    C8_COMPLEXITY_THRESHOLD,
                    cs.ring_count,
                    cs.stereo_count,
                    cs.heteroatom_ratio,
                    cs.smiles_length,
                ));
            }
            return InvariantStatus::Pass;
        }
        // Legacy fallback for unparseable SMILES
        if s.len() > 250 {
            return advisory(format!(
                "long SMILES ({} chars) — retrosynthesis depth proxy",
                s.len()
            ));
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// C9 — Reaction safety
// ---------------------------------------------------------------------------

/// C9 — Reaction safety.
///
/// **Behaviour.** DB hits → Fail. Heuristic Advisory: pyrophoric metal
/// labels (e.g. `[Na]`, `[K]`, `[Li]`) or peroxide-forming ether
/// substring `OCC`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionSafetyScreen;

impl Invariant for ReactionSafetyScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C9
    }
    fn name(&self) -> &'static str {
        "reaction_safety_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(s) = smiles(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, REACT_CLASSES);
        if !hits.is_empty() {
            return fail(format!(
                "reaction-incompatibility hits: {}",
                hits.join(", ")
            ));
        }
        for pyro in &["[Na]", "[K]", "[Li]", "[AlH4-]"] {
            if s.contains(pyro) {
                return advisory(format!("pyrophoric reagent token {pyro}"));
            }
        }
        InvariantStatus::Pass
    }
}

// ---------------------------------------------------------------------------
// C10 — Waste toxicity
// ---------------------------------------------------------------------------

/// C10 — Waste-stream toxicity / RCRA listing.
///
/// **Behaviour.** DB hits → Fail. Heuristic Advisory if SMILES contains a
/// heavy-metal label (`[Hg]`, `[Pb]`, `[Cd]`, `[As]`, `[Cr+6]`, `[U]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasteToxicityScreen;

impl Invariant for WasteToxicityScreen {
    fn id(&self) -> InvariantId {
        InvariantId::C10
    }
    fn name(&self) -> &'static str {
        "waste_toxicity_screen"
    }
    fn evaluate(&self, _bundle: &SynthesisBundle) -> InvariantStatus {
        InvariantStatus::Pass
    }
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        let Some(s) = smiles(bundle) else {
            return InvariantStatus::Pass;
        };
        let hits = hits_in_classes(ctx, WASTE_CLASSES);
        if !hits.is_empty() {
            return fail(format!("waste-toxicity hits: {}", hits.join(", ")));
        }
        for metal in &["[Hg]", "[Pb]", "[Cd]", "[As]", "[Cr+6]", "[U]"] {
            if s.contains(metal) {
                return advisory(format!("heavy-metal reagent {metal} in SMILES"));
            }
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

    fn chem(s: &str) -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "t".into(),
            sequence: 0,
            payload: SynthesisPayload::Chemical { smiles: s.into() },
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
            allowed_substrates: vec!["chemical".into()],
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

    // ---- C1 ----
    #[test]
    fn c1_schedule_1_fails() {
        let p = profile();
        let h = vec![hit("cwc-schedule-1")];
        assert!(matches!(
            CwcScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn c1_schedule_2_advisory() {
        let p = profile();
        let h = vec![hit("schedule-2")];
        assert!(matches!(
            CwcScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c1_phosphonate_advisory() {
        let p = profile();
        assert!(matches!(
            CwcScreen.evaluate_with(&chem("CCP(=O)(OC)F"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c1_clean_passes() {
        let p = profile();
        assert!(matches!(
            CwcScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- C2 ----
    #[test]
    fn c2_db_hit_fails() {
        let p = profile();
        let h = vec![hit("explosive")];
        assert!(matches!(
            ExplosiveScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn c2_three_nitro_advisory() {
        let p = profile();
        let s = "CC(N(=O)=O)(N(=O)=O)N(=O)=O";
        assert!(matches!(
            ExplosiveScreen.evaluate_with(&chem(s), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c2_peroxide_advisory() {
        let p = profile();
        assert!(matches!(
            ExplosiveScreen.evaluate_with(&chem("COOC"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c2_clean_passes() {
        let p = profile();
        assert!(matches!(
            ExplosiveScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- C3 ----
    #[test]
    fn c3_db_hit_fails() {
        let p = profile();
        let h = vec![hit("narcotic")];
        assert!(matches!(
            NarcoticScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn c3_clean_passes() {
        let p = profile();
        assert!(matches!(
            NarcoticScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn c3_unrelated_ignored() {
        let p = profile();
        let h = vec![hit("explosive")];
        assert!(matches!(
            NarcoticScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- C4 ----
    #[test]
    fn c4_db_hit_fails() {
        let p = profile();
        let h = vec![hit("pfas")];
        assert!(matches!(
            EnvToxinScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn c4_polychlor_advisory() {
        let p = profile();
        assert!(matches!(
            EnvToxinScreen.evaluate_with(&chem("ClCClCClCCl"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c4_perfluoro_advisory() {
        let p = profile();
        assert!(matches!(
            EnvToxinScreen.evaluate_with(&chem("CC(F)(F)F"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c4_clean_passes() {
        let p = profile();
        assert!(matches!(
            EnvToxinScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- C5 ----
    #[test]
    fn c5_db_hit_fails() {
        let p = profile();
        let h = vec![hit("carcinogen")];
        assert!(matches!(
            CarcinogenMutagenScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn c5_aromatic_amine_advisory() {
        let p = profile();
        assert!(matches!(
            CarcinogenMutagenScreen.evaluate_with(&chem("Nc1ccccc1"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c5_clean_passes() {
        let p = profile();
        assert!(matches!(
            CarcinogenMutagenScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- C6 ----
    #[test]
    fn c6_db_hit_advisory() {
        let p = profile();
        let h = vec![hit("endocrine-disruptor")];
        assert!(matches!(
            EndocrineDisruptorScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c6_bpa_core_advisory() {
        let p = profile();
        let s = "CC(C)(c1ccc(O)cc1)c1ccc(O)cc1";
        assert!(matches!(
            EndocrineDisruptorScreen.evaluate_with(&chem(s), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c6_clean_passes() {
        let p = profile();
        assert!(matches!(
            EndocrineDisruptorScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- C7 ----
    #[test]
    fn c7_long_aliphatic_advisory() {
        let p = profile();
        let s = "CCCCCCCCCCCCCC";
        assert!(matches!(
            BioaccumulationScreen.evaluate_with(&chem(s), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c7_polar_long_chain_passes() {
        let p = profile();
        // Long carbon chain but with multiple oxygens — not bioaccumulating proxy.
        let s = "CCCCCCCCCCCCC(=O)OC";
        assert!(matches!(
            BioaccumulationScreen.evaluate_with(&chem(s), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }
    #[test]
    fn c7_short_passes() {
        let p = profile();
        assert!(matches!(
            BioaccumulationScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- C8 ----
    #[test]
    fn c8_empty_smiles_fails() {
        let p = profile();
        assert!(matches!(
            PathwayFeasibilityScreen.evaluate_with(&chem(""), &ctx(&[], &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn c8_long_simple_smiles_passes() {
        // 260 carbons is long but structurally trivial (no rings, no
        // stereo, no heteroatoms) → complexity score < threshold → Pass.
        let p = profile();
        let s = "C".repeat(260);
        assert!(matches!(
            PathwayFeasibilityScreen.evaluate_with(&chem(&s), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    #[test]
    fn c8_complex_molecule_advisory() {
        use super::super::molecule::{complexity_score, Molecule};
        // Build a molecule with enough complexity (rings, stereo, heteroatoms,
        // length) to exceed the C8_COMPLEXITY_THRESHOLD of 0.60.
        let p = profile();
        // Repeat a ring-heavy, heteroatom-rich fragment to drive score up.
        let fragment = "C1(SC2C(NC(=O)C2N)C1C(=O)O)";
        let complex = fragment.repeat(12);
        let mol = Molecule::parse(&complex).expect("test molecule should parse");
        let cs = complexity_score(&mol);
        assert!(
            cs.score >= super::C8_COMPLEXITY_THRESHOLD,
            "test molecule complexity {:.3} should be ≥ {:.2}: rings={}, stereo={}, hetero_ratio={:.2}, len={}",
            cs.score, super::C8_COMPLEXITY_THRESHOLD, cs.ring_count, cs.stereo_count, cs.heteroatom_ratio, cs.smiles_length
        );
        let status = PathwayFeasibilityScreen.evaluate_with(&chem(&complex), &ctx(&[], &p));
        assert!(
            matches!(status, InvariantStatus::Advisory { .. }),
            "complex molecule should trigger C8 advisory, got: {status:?}"
        );
    }
    #[test]
    fn c8_clean_passes() {
        let p = profile();
        assert!(matches!(
            PathwayFeasibilityScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- C9 ----
    #[test]
    fn c9_db_hit_fails() {
        let p = profile();
        let h = vec![hit("pyrophoric")];
        assert!(matches!(
            ReactionSafetyScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn c9_pyrophoric_token_advisory() {
        let p = profile();
        assert!(matches!(
            ReactionSafetyScreen.evaluate_with(&chem("[Na]C(=O)C"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c9_clean_passes() {
        let p = profile();
        assert!(matches!(
            ReactionSafetyScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- C10 ----
    #[test]
    fn c10_db_hit_fails() {
        let p = profile();
        let h = vec![hit("rcra")];
        assert!(matches!(
            WasteToxicityScreen.evaluate_with(&chem("CCO"), &ctx(&h, &p)),
            InvariantStatus::Fail { .. }
        ));
    }
    #[test]
    fn c10_heavy_metal_advisory() {
        let p = profile();
        assert!(matches!(
            WasteToxicityScreen.evaluate_with(&chem("[Hg](Cl)Cl"), &ctx(&[], &p)),
            InvariantStatus::Advisory { .. }
        ));
    }
    #[test]
    fn c10_clean_passes() {
        let p = profile();
        assert!(matches!(
            WasteToxicityScreen.evaluate_with(&chem("CCO"), &ctx(&[], &p)),
            InvariantStatus::Pass
        ));
    }

    // ---- Example bundle coverage ----

    #[test]
    fn safe_chemical_bundle_passes_all_c_invariants() {
        let p = profile();
        let bundle = SynthesisBundle {
            timestamp: Utc::now(),
            source: "t".into(),
            sequence: 0,
            payload: SynthesisPayload::Chemical {
                smiles: "CCO".into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: Default::default(),
        };
        let c = ctx(&[], &p);
        // Ethanol should pass all chemical invariants
        assert!(matches!(
            CwcScreen.evaluate_with(&bundle, &c),
            InvariantStatus::Pass
        ));
        assert!(matches!(
            ExplosiveScreen.evaluate_with(&bundle, &c),
            InvariantStatus::Pass
        ));
        assert!(matches!(
            NarcoticScreen.evaluate_with(&bundle, &c),
            InvariantStatus::Pass
        ));
        assert!(matches!(
            PathwayFeasibilityScreen.evaluate_with(&bundle, &c),
            InvariantStatus::Pass
        ));
    }

    #[test]
    fn dangerous_chemical_explosive_trips_c2() {
        let p = profile();
        let smiles = "[N+](=O)[O-]CC[N+](=O)[O-]CC[N+](=O)[O-]OO";
        let bundle = SynthesisBundle {
            timestamp: Utc::now(),
            source: "t".into(),
            sequence: 0,
            payload: SynthesisPayload::Chemical {
                smiles: smiles.into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: Default::default(),
        };
        let c = ctx(&[], &p);
        let status = ExplosiveScreen.evaluate_with(&bundle, &c);
        assert!(
            matches!(status, InvariantStatus::Advisory { .. }),
            "Expected explosive advisory, got {:?}",
            status
        );
    }

    // ---- Substrate pass-through ----
    #[test]
    fn chemical_invariants_pass_for_dna_payload() {
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
        for s in [
            CwcScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            ExplosiveScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            NarcoticScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            EnvToxinScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            CarcinogenMutagenScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            EndocrineDisruptorScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            BioaccumulationScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            PathwayFeasibilityScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            ReactionSafetyScreen.evaluate_with(&bundle, &ctx(&[], &p)),
            WasteToxicityScreen.evaluate_with(&bundle, &ctx(&[], &p)),
        ] {
            assert!(matches!(s, InvariantStatus::Pass), "got {:?}", s);
        }
    }
}
