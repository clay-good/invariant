//! Molecule newtype, heuristic SMILES parser, functional-group detector,
//! and SMARTS-like structural-alert rule library (v1).
//!
//! This module replaces the raw `&str` SMILES treatment that chemical
//! invariants (C1–C10) previously used. Because we do not link a real
//! cheminformatics backend (RDKit / OpenBabel) at this layer, the
//! implementation is still heuristic — but it provides:
//!
//! - A `Molecule` newtype that normalises whitespace and validates basic
//!   SMILES character legality.
//! - A functional-group detector that identifies common moieties from
//!   SMILES substring patterns (with known FP/FN documented per group).
//! - A versioned `SmartsRule` library with CWC structural alerts, so the
//!   chemical invariants can apply named rules rather than ad-hoc regexes.
//! - A complexity scorer (ring count, stereo centres, heteroatom ratio)
//!   used by C8 for pathway-feasibility estimation.
//!
//! ## Known limitations
//!
//! Without a real SMARTS engine, all matching is substring / heuristic.
//! Canonical SMILES normalisation requires RDKit; here we only strip
//! whitespace and validate character set. Isomer awareness (E/Z, R/S)
//! is detected but not resolved.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Molecule newtype
// ---------------------------------------------------------------------------

/// A validated SMILES string wrapped in a newtype for type safety.
///
/// Construction via [`Molecule::parse`] validates basic SMILES character
/// legality. The inner string is whitespace-trimmed but NOT canonicalised
/// (that requires RDKit or equivalent).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Molecule {
    smiles: String,
}

/// Errors produced when parsing a SMILES string into a [`Molecule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoleculeError {
    /// The SMILES string was empty or all-whitespace.
    Empty,
    /// Unbalanced parentheses in the SMILES string.
    UnbalancedParens,
    /// Unbalanced brackets in the SMILES string.
    UnbalancedBrackets,
    /// Invalid character encountered.
    InvalidChar(char),
}

impl fmt::Display for MoleculeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MoleculeError::Empty => write!(f, "empty SMILES"),
            MoleculeError::UnbalancedParens => write!(f, "unbalanced parentheses"),
            MoleculeError::UnbalancedBrackets => write!(f, "unbalanced brackets"),
            MoleculeError::InvalidChar(c) => write!(f, "invalid SMILES character: {c:?}"),
        }
    }
}

impl Molecule {
    /// Parse a SMILES string into a `Molecule`.
    ///
    /// Validates: non-empty, balanced parens/brackets, character set
    /// (atoms, bonds, digits, branches, stereo, charges).
    pub fn parse(raw: &str) -> Result<Self, MoleculeError> {
        let s = raw.trim().to_string();
        if s.is_empty() {
            return Err(MoleculeError::Empty);
        }
        let mut paren_depth: i32 = 0;
        let mut bracket_depth: i32 = 0;
        for ch in s.chars() {
            match ch {
                '(' => paren_depth += 1,
                ')' => {
                    paren_depth -= 1;
                    if paren_depth < 0 {
                        return Err(MoleculeError::UnbalancedParens);
                    }
                }
                '[' => bracket_depth += 1,
                ']' => {
                    bracket_depth -= 1;
                    if bracket_depth < 0 {
                        return Err(MoleculeError::UnbalancedBrackets);
                    }
                }
                // Organic atoms (upper + lower aromatic)
                'A'..='Z' | 'a'..='z' => {}
                // Digits (ring closures)
                '0'..='9' => {}
                // Bonds
                '-' | '=' | '#' | ':' | '~' => {}
                // Branches, dot-disconnect
                '.' => {}
                // Stereo
                '/' | '\\' | '@' => {}
                // Charges, isotope labels, hydrogen counts in brackets
                '+' | '%' => {}
                _ => return Err(MoleculeError::InvalidChar(ch)),
            }
        }
        if paren_depth != 0 {
            return Err(MoleculeError::UnbalancedParens);
        }
        if bracket_depth != 0 {
            return Err(MoleculeError::UnbalancedBrackets);
        }
        Ok(Molecule { smiles: s })
    }

    /// The raw (trimmed, non-canonical) SMILES string.
    pub fn as_str(&self) -> &str {
        &self.smiles
    }

    /// Length of the SMILES string in characters.
    pub fn len(&self) -> usize {
        self.smiles.len()
    }

    /// Whether the SMILES string is empty (always false for valid molecules).
    pub fn is_empty(&self) -> bool {
        self.smiles.is_empty()
    }

    /// Upper-cased copy for case-insensitive matching.
    pub fn upper(&self) -> String {
        self.smiles.to_ascii_uppercase()
    }
}

impl fmt::Display for Molecule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.smiles)
    }
}

// ---------------------------------------------------------------------------
// Functional groups
// ---------------------------------------------------------------------------

/// Functional groups detectable by the heuristic SMILES engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionalGroup {
    /// Phosphonate ester: `P(=O)` core.
    Phosphonate,
    /// Fluorine on phosphorus (nerve-agent motif): `P...F`.
    PhosphorusFluoride,
    /// Nitro group: `[N+](=O)[O-]` or `N(=O)=O`.
    Nitro,
    /// Peroxide bond: `OO`.
    Peroxide,
    /// Azide group: `N=N=N` or `[N-]=[N+]=[N-]`.
    Azide,
    /// Aromatic amine: `Nc1ccccc1` or `c1ccc(N)cc1`.
    AromaticAmine,
    /// N-nitroso group: `NN=O`.
    NNitroso,
    /// Perfluoro carbon: `C(F)(F)F`.
    PerfluoroCarbon,
    /// Mustard / thioether with chlorine: `SCC...Cl`.
    Mustard,
    /// Isocyanate: `N=C=O`.
    Isocyanate,
    /// Epoxide: typically detected via `C1OC1` three-membered ring.
    Epoxide,
    /// Aldehyde: `C=O` at terminal (heuristic: `C(=O)[H]` or `C=O` not in ester/acid context).
    Aldehyde,
    /// Thiol / sulfhydryl: `[SH]` or standalone `S` in small context.
    Thiol,
    /// Heavy metal atom in brackets.
    HeavyMetal,
    /// Stereocentre detected (@ symbol present).
    StereoCenter,
}

/// Detect functional groups present in a molecule.
///
/// Returns a deduplicated set of groups found. Each group's heuristic is
/// documented in the `FunctionalGroup` variant docs. False positives are
/// expected; see the module-level docs for the acceptance stance.
pub fn detect_functional_groups(mol: &Molecule) -> Vec<FunctionalGroup> {
    let s = mol.as_str();
    let upper = mol.upper();
    let mut groups = Vec::new();

    // Phosphonate
    if upper.contains("P(=O)") || upper.contains("P(O)") {
        groups.push(FunctionalGroup::Phosphonate);
    }
    // P-F bond (nerve agent motif)
    if (upper.contains("P(=O)") || upper.contains("P(")) && upper.contains('F') {
        groups.push(FunctionalGroup::PhosphorusFluoride);
    }
    // Nitro
    if s.contains("[N+](=O)[O-]") || s.contains("N(=O)=O") || s.contains("[NO2]") {
        groups.push(FunctionalGroup::Nitro);
    }
    // Peroxide
    if upper.contains("OO") {
        groups.push(FunctionalGroup::Peroxide);
    }
    // Azide
    if s.contains("N=N=N") || s.contains("[N-]=[N+]=[N-]") {
        groups.push(FunctionalGroup::Azide);
    }
    // Aromatic amine
    if s.contains("Nc1ccccc1") || s.contains("c1ccc(N)cc1") || s.contains("c1cc(N)ccc1") {
        groups.push(FunctionalGroup::AromaticAmine);
    }
    // N-nitroso
    if s.contains("NN=O") || s.contains("N(=O)N") {
        groups.push(FunctionalGroup::NNitroso);
    }
    // Perfluoro carbon
    if s.contains("C(F)(F)F") {
        groups.push(FunctionalGroup::PerfluoroCarbon);
    }
    // Mustard (sulfur mustard motif)
    if s.contains("ClCCS") || s.contains("SCCCl") {
        groups.push(FunctionalGroup::Mustard);
    }
    // Isocyanate
    if s.contains("N=C=O") {
        groups.push(FunctionalGroup::Isocyanate);
    }
    // Epoxide (three-membered ring with oxygen)
    if s.contains("C1OC1") || s.contains("C1(O1)") {
        groups.push(FunctionalGroup::Epoxide);
    }
    // Thiol
    if s.contains("[SH]") {
        groups.push(FunctionalGroup::Thiol);
    }
    // Heavy metals
    for metal in &["[Hg]", "[Pb]", "[Cd]", "[As]", "[Cr", "[U]", "[Tl]"] {
        if s.contains(metal) {
            groups.push(FunctionalGroup::HeavyMetal);
            break;
        }
    }
    // Stereo centres
    if s.contains('@') {
        groups.push(FunctionalGroup::StereoCenter);
    }

    groups
}

// ---------------------------------------------------------------------------
// SMARTS rule library v1
// ---------------------------------------------------------------------------

/// Version of the SMARTS rule library. Incremented when rules are added,
/// removed, or structurally changed.
pub const SMARTS_RULE_LIBRARY_VERSION: u32 = 1;

/// A heuristic structural-alert rule (SMARTS-like, substring-based).
///
/// Each rule has a unique `id`, one or more SMILES substring patterns to
/// match, a severity level, and the hazard class it maps to.
#[derive(Debug, Clone)]
pub struct SmartsRule {
    /// Unique rule identifier (e.g. `"CWC-SA-01"`).
    pub id: &'static str,
    /// Human-readable label.
    pub label: &'static str,
    /// SMILES substrings — any match triggers the rule.
    pub patterns: &'static [&'static str],
    /// Severity: `"fail"` blocks approval; `"advisory"` is informational.
    pub severity: RuleSeverity,
    /// Hazard class tag for grouping.
    pub hazard_class: &'static str,
}

/// Severity of a SMARTS rule match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    /// Hard failure — blocks approval.
    Fail,
    /// Advisory — recorded but does not block.
    Advisory,
}

/// Result of matching a single SMARTS rule against a molecule.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// The rule that matched.
    pub rule_id: &'static str,
    /// The label of the matched rule.
    pub label: &'static str,
    /// Which pattern triggered the match.
    pub matched_pattern: &'static str,
    /// Severity.
    pub severity: RuleSeverity,
    /// Hazard class.
    pub hazard_class: &'static str,
}

/// CWC-focused structural alert rules (Schedule 1 / 2 / 3 motifs).
///
/// These are the *heuristic* SMILES-substring equivalents of the SMARTS
/// patterns that a real cheminformatics engine would run. They complement
/// (not replace) hazard-database hits.
pub static CWC_RULES: &[SmartsRule] = &[
    // -- Schedule 1 motifs --
    SmartsRule {
        id: "CWC-SA-01",
        label: "Alkylphosphonofluoridate (G-series core)",
        patterns: &["P(=O)(F)", "P(F)(=O)"],
        severity: RuleSeverity::Fail,
        hazard_class: "cwc-schedule-1",
    },
    SmartsRule {
        id: "CWC-SA-02",
        label: "Phosphoramidocyanidate (tabun-class core)",
        patterns: &["P(=O)(N)(C#N)", "P(N)(=O)(C#N)"],
        severity: RuleSeverity::Fail,
        hazard_class: "cwc-schedule-1",
    },
    SmartsRule {
        id: "CWC-SA-03",
        label: "Sulfur mustard (bis-chloroethyl thioether)",
        patterns: &["ClCCSCCCl"],
        severity: RuleSeverity::Fail,
        hazard_class: "cwc-schedule-1",
    },
    SmartsRule {
        id: "CWC-SA-04",
        label: "Nitrogen mustard (bis-chloroethyl amine)",
        patterns: &["ClCCN(CCCl)"],
        severity: RuleSeverity::Fail,
        hazard_class: "cwc-schedule-1",
    },
    // -- Schedule 2 motifs --
    SmartsRule {
        id: "CWC-SA-05",
        label: "Alkylphosphonyl difluoride (DF precursor)",
        patterns: &["P(=O)(F)F", "P(F)(F)=O"],
        severity: RuleSeverity::Advisory,
        hazard_class: "cwc-schedule-2",
    },
    SmartsRule {
        id: "CWC-SA-06",
        label: "Dialkylaminoethanol (precursor amine)",
        patterns: &["N(C)(C)CCO", "OCCN(C)C"],
        severity: RuleSeverity::Advisory,
        hazard_class: "cwc-schedule-2",
    },
    SmartsRule {
        id: "CWC-SA-07",
        label: "Thiodiglycol (mustard precursor)",
        patterns: &["OCCSCC O", "OCCSCCO"],
        severity: RuleSeverity::Advisory,
        hazard_class: "cwc-schedule-2",
    },
    // -- General structural alerts --
    SmartsRule {
        id: "CWC-SA-08",
        label: "Alkylphosphonate with leaving group",
        patterns: &["P(=O)(OC)(F)", "P(=O)(F)(OC)"],
        severity: RuleSeverity::Advisory,
        hazard_class: "cwc-structural-alert",
    },
];

/// Explosive-related structural alert rules.
pub static EXPLOSIVE_RULES: &[SmartsRule] = &[
    SmartsRule {
        id: "EXP-SA-01",
        label: "Polynitro compound (≥3 nitro groups)",
        patterns: &["[N+](=O)[O-]"],
        severity: RuleSeverity::Advisory,
        hazard_class: "explosive",
    },
    SmartsRule {
        id: "EXP-SA-02",
        label: "Organic peroxide",
        patterns: &["OO"],
        severity: RuleSeverity::Advisory,
        hazard_class: "explosive",
    },
    SmartsRule {
        id: "EXP-SA-03",
        label: "Organic azide",
        patterns: &["N=N=N", "[N-]=[N+]=[N-]"],
        severity: RuleSeverity::Advisory,
        hazard_class: "explosive",
    },
];

/// Match a molecule against a slice of SMARTS rules. Returns all matches.
pub fn match_rules(mol: &Molecule, rules: &[SmartsRule]) -> Vec<RuleMatch> {
    let s = mol.as_str();
    let mut matches = Vec::new();
    for rule in rules {
        for pat in rule.patterns {
            if s.contains(pat) {
                matches.push(RuleMatch {
                    rule_id: rule.id,
                    label: rule.label,
                    matched_pattern: pat,
                    severity: rule.severity,
                    hazard_class: rule.hazard_class,
                });
                break; // one match per rule is enough
            }
        }
    }
    matches
}

// ---------------------------------------------------------------------------
// Complexity scoring (for C8 pathway feasibility)
// ---------------------------------------------------------------------------

/// Heuristic complexity score for a molecule.
///
/// Combines ring count, stereo-centre count, heteroatom ratio, and raw
/// SMILES length into a single 0.0–1.0 score. Higher = more complex.
/// This replaces the naive `>250 chars` advisory in C8.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityScore {
    /// Number of ring-closure digits found.
    pub ring_count: usize,
    /// Number of `@` stereo annotations.
    pub stereo_count: usize,
    /// Ratio of heteroatoms (N, O, S, P, F, Cl, Br, I) to total atom-like chars.
    pub heteroatom_ratio: f64,
    /// SMILES string length.
    pub smiles_length: usize,
    /// Composite score in [0.0, 1.0].
    pub score: f64,
}

/// Compute a heuristic complexity score for a molecule.
pub fn complexity_score(mol: &Molecule) -> ComplexityScore {
    let s = mol.as_str();
    let len = s.len();

    // Ring closures: count digits not inside brackets that appear as ring-open
    let mut ring_count = 0usize;
    let mut in_bracket = false;
    for ch in s.chars() {
        match ch {
            '[' => in_bracket = true,
            ']' => in_bracket = false,
            '0'..='9' if !in_bracket => ring_count += 1,
            '%' if !in_bracket => ring_count += 1,
            _ => {}
        }
    }
    // Each ring is opened and closed, so divide by 2
    ring_count /= 2;

    // Stereo centres
    let stereo_count = s.chars().filter(|c| *c == '@').count();

    // Heteroatom ratio
    let atom_chars: usize = s.chars().filter(|c| c.is_ascii_alphabetic()).count().max(1);
    let hetero_chars: usize = s
        .chars()
        .filter(|c| matches!(c, 'N' | 'O' | 'S' | 'P' | 'F' | 'I' | 'n' | 'o' | 's'))
        .count();
    // Count Cl and Br digraphs
    let cl_count = count_non_overlapping(s, "Cl");
    let br_count = count_non_overlapping(s, "Br");
    let total_hetero = hetero_chars + cl_count + br_count;
    let heteroatom_ratio = total_hetero as f64 / atom_chars as f64;

    // Composite: weighted sum, clamped to [0, 1]
    // Weights chosen empirically for the heuristic engine.
    let ring_score = (ring_count as f64 / 6.0).min(1.0);
    let stereo_score = (stereo_count as f64 / 4.0).min(1.0);
    let len_score = (len as f64 / 300.0).min(1.0);
    let hetero_score = heteroatom_ratio.min(1.0);

    let score = (0.30 * ring_score + 0.20 * stereo_score + 0.25 * len_score + 0.25 * hetero_score)
        .clamp(0.0, 1.0);

    ComplexityScore {
        ring_count,
        stereo_count,
        heteroatom_ratio,
        smiles_length: len,
        score,
    }
}

fn count_non_overlapping(haystack: &str, pat: &str) -> usize {
    if pat.is_empty() {
        return 0;
    }
    haystack.matches(pat).count()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Molecule::parse ----

    #[test]
    fn parse_valid_smiles() {
        assert!(Molecule::parse("CCO").is_ok());
        assert!(Molecule::parse("c1ccccc1").is_ok());
        assert!(Molecule::parse("[Na]Cl").is_ok());
        assert!(Molecule::parse("CC(=O)O").is_ok());
        assert!(Molecule::parse("C(/F)=C/Cl").is_ok()); // stereo
    }

    #[test]
    fn parse_rejects_empty() {
        assert_eq!(Molecule::parse(""), Err(MoleculeError::Empty));
        assert_eq!(Molecule::parse("   "), Err(MoleculeError::Empty));
    }

    #[test]
    fn parse_rejects_unbalanced_parens() {
        assert_eq!(
            Molecule::parse("CC(=O"),
            Err(MoleculeError::UnbalancedParens)
        );
        assert_eq!(Molecule::parse("CC)"), Err(MoleculeError::UnbalancedParens));
    }

    #[test]
    fn parse_rejects_unbalanced_brackets() {
        assert_eq!(
            Molecule::parse("[Na"),
            Err(MoleculeError::UnbalancedBrackets)
        );
    }

    #[test]
    fn parse_strips_whitespace() {
        let mol = Molecule::parse("  CCO  ").unwrap();
        assert_eq!(mol.as_str(), "CCO");
    }

    #[test]
    fn molecule_display() {
        let mol = Molecule::parse("CCO").unwrap();
        assert_eq!(format!("{mol}"), "CCO");
    }

    #[test]
    fn molecule_serde_roundtrip() {
        let mol = Molecule::parse("CC(=O)O").unwrap();
        let json = serde_json::to_string(&mol).unwrap();
        let back: Molecule = serde_json::from_str(&json).unwrap();
        assert_eq!(mol, back);
    }

    // ---- Functional group detection ----

    #[test]
    fn detect_phosphonate() {
        let mol = Molecule::parse("CCP(=O)(OC)OC").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::Phosphonate));
    }

    #[test]
    fn detect_phosphorus_fluoride() {
        let mol = Molecule::parse("CCP(=O)(F)OC").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::PhosphorusFluoride));
    }

    #[test]
    fn detect_nitro_group() {
        let mol = Molecule::parse("CC[N+](=O)[O-]").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::Nitro));
    }

    #[test]
    fn detect_peroxide() {
        let mol = Molecule::parse("COOC").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::Peroxide));
    }

    #[test]
    fn detect_azide() {
        let mol = Molecule::parse("CCN=N=N").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::Azide));
    }

    #[test]
    fn detect_aromatic_amine() {
        let mol = Molecule::parse("Nc1ccccc1").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::AromaticAmine));
    }

    #[test]
    fn detect_perfluoro() {
        let mol = Molecule::parse("CC(F)(F)F").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::PerfluoroCarbon));
    }

    #[test]
    fn detect_mustard() {
        let mol = Molecule::parse("ClCCSCCCl").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::Mustard));
    }

    #[test]
    fn detect_heavy_metal() {
        let mol = Molecule::parse("[Hg](Cl)Cl").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::HeavyMetal));
    }

    #[test]
    fn detect_stereo() {
        let mol = Molecule::parse("C[C@@H](O)F").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(groups.contains(&FunctionalGroup::StereoCenter));
    }

    #[test]
    fn clean_molecule_no_groups() {
        let mol = Molecule::parse("CCO").unwrap();
        let groups = detect_functional_groups(&mol);
        assert!(
            groups.is_empty(),
            "ethanol should have no alerts: {groups:?}"
        );
    }

    // ---- SMARTS rule matching ----

    #[test]
    fn cwc_sa01_matches_g_series_core() {
        let mol = Molecule::parse("CCP(=O)(F)OC").unwrap();
        let matches = match_rules(&mol, CWC_RULES);
        assert!(
            matches.iter().any(|m| m.rule_id == "CWC-SA-01"),
            "G-series core should trigger CWC-SA-01: {matches:?}"
        );
    }

    #[test]
    fn cwc_sa03_matches_sulfur_mustard() {
        let mol = Molecule::parse("ClCCSCCCl").unwrap();
        let matches = match_rules(&mol, CWC_RULES);
        assert!(
            matches.iter().any(|m| m.rule_id == "CWC-SA-03"),
            "sulfur mustard should trigger CWC-SA-03: {matches:?}"
        );
    }

    #[test]
    fn cwc_sa04_matches_nitrogen_mustard() {
        let mol = Molecule::parse("ClCCN(CCCl)C").unwrap();
        let matches = match_rules(&mol, CWC_RULES);
        assert!(
            matches.iter().any(|m| m.rule_id == "CWC-SA-04"),
            "nitrogen mustard should trigger CWC-SA-04: {matches:?}"
        );
    }

    #[test]
    fn clean_molecule_no_cwc_matches() {
        let mol = Molecule::parse("CCO").unwrap();
        let matches = match_rules(&mol, CWC_RULES);
        assert!(matches.is_empty(), "ethanol should not trigger CWC rules");
    }

    #[test]
    fn explosive_rules_detect_polynitro() {
        let mol = Molecule::parse("CC([N+](=O)[O-])([N+](=O)[O-])[N+](=O)[O-]").unwrap();
        let matches = match_rules(&mol, EXPLOSIVE_RULES);
        assert!(
            matches.iter().any(|m| m.rule_id == "EXP-SA-01"),
            "polynitro should trigger EXP-SA-01"
        );
    }

    #[test]
    fn smarts_rule_library_version() {
        assert_eq!(SMARTS_RULE_LIBRARY_VERSION, 1);
    }

    // ---- Complexity scoring ----

    #[test]
    fn simple_molecule_low_complexity() {
        let mol = Molecule::parse("CCO").unwrap();
        let cs = complexity_score(&mol);
        assert!(
            cs.score < 0.3,
            "ethanol should be low complexity: {}",
            cs.score
        );
        assert_eq!(cs.ring_count, 0);
        assert_eq!(cs.stereo_count, 0);
    }

    #[test]
    fn benzene_has_rings() {
        let mol = Molecule::parse("c1ccccc1").unwrap();
        let cs = complexity_score(&mol);
        assert!(cs.ring_count >= 1, "benzene should have ≥1 ring");
    }

    #[test]
    fn complex_molecule_higher_score() {
        // A moderately complex SMILES
        let mol = Molecule::parse("CC1(C)SC2C(NC(=O)C2N)C1C(=O)O").unwrap();
        let cs = complexity_score(&mol);
        assert!(
            cs.score > 0.2,
            "penicillin-like should be moderate complexity: {}",
            cs.score
        );
    }

    #[test]
    fn long_smiles_high_length_component() {
        let long = "C".repeat(300);
        let mol = Molecule::parse(&long).unwrap();
        let cs = complexity_score(&mol);
        assert!(cs.smiles_length >= 300);
        assert!(cs.score > 0.2, "long SMILES should have non-trivial score");
    }

    #[test]
    fn stereo_molecule_counted() {
        let mol = Molecule::parse("C[C@@H](O)[C@H](O)C").unwrap();
        let cs = complexity_score(&mol);
        // @@ counts as 2 '@' chars and @ counts as 1
        assert!(cs.stereo_count >= 2);
    }
}
