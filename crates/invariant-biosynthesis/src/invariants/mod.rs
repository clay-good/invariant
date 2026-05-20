//! Biological + chemical safety invariants (D/P/C families).
//!
//! Step 3a establishes the *skeleton* of all 30 invariants — D1–D10 (DNA),
//! P1–P10 (peptide), and C1–C10 (chemical). Each invariant is a concrete
//! struct implementing the `Invariant` trait (or `StatefulInvariant` for
//! per-operator stateful checks). All bodies currently return
//! `InvariantStatus::Unimplemented`; Step 3b fills in the real logic.
//!
//! ## Threat-model alignment (`docs/threat-model.md` §2, §3)
//!
//! - D1 (`SelectAgentScreen`) accepts both DNA and translated AA so it can
//!   match at the protein level (§3.1 codon-substituted-homolog mitigation).
//! - The `StatefulInvariant` trait variant handles per-operator aggregate
//!   state for fragmentation and rate-of-rejection scoring (§3.1, §AV-6).
//! - The `HazardDatabase` trait exposes a `freshness()` method;
//!   `InvariantStatus::DbStale` is the fail-closed response when the
//!   configured freshness window is exceeded (§AV-5).
//! - Every new struct in this module uses
//!   `#[serde(deny_unknown_fields)]` to close the covert-channel side
//!   channel (§AV-8).
//!
//! ## Wiring
//!
//! `run_all` iterates every invariant, calls its `evaluate`, and aggregates
//! `InvariantResult`s into a vector that the validator consumes. A profile
//! may suppress a subset by id via `InvariantSelection`.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::models::bundle::SynthesisBundle;
use crate::models::profile::BioProfile;
use crate::screening::HazardHit;

/// Chemical synthesis invariants C1-C10.
pub mod chemical;
/// DNA synthesis invariants D1-D10.
pub mod dna;
/// Protein-space homology detection engines.
pub mod homology;
/// Molecule newtype, SMILES parser, functional-group detector, SMARTS rules.
pub mod molecule;
/// Peptide synthesis invariants P1-P10.
pub mod peptide;
/// Protocol-payload invariants PR1-PR4.
pub mod protocol;
/// Stateful invariants (cross-bundle fragmentation detection).
pub mod stateful;

// ---------------------------------------------------------------------------
// Invariant id catalogue
// ---------------------------------------------------------------------------

/// Stable identifier for each of the 30 invariants in the D/P/C families.
///
/// IDs are intentionally short and stable: they are used in audit logs,
/// profile configuration files, and verdict `CheckResult.name` strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[allow(missing_docs)]
pub enum InvariantId {
    // DNA family.
    D1,
    D2,
    D3,
    D4,
    D5,
    D6,
    D7,
    D8,
    D9,
    D10,
    // Peptide family.
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
    P7,
    P8,
    P9,
    P10,
    // Chemical family.
    C1,
    C2,
    C3,
    C4,
    C5,
    C6,
    C7,
    C8,
    C9,
    C10,
    // Protocol family.
    Pr1,
    Pr2,
    Pr3,
    Pr4,
}

impl InvariantId {
    /// Short string label (e.g. `"D1"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            InvariantId::D1 => "D1",
            InvariantId::D2 => "D2",
            InvariantId::D3 => "D3",
            InvariantId::D4 => "D4",
            InvariantId::D5 => "D5",
            InvariantId::D6 => "D6",
            InvariantId::D7 => "D7",
            InvariantId::D8 => "D8",
            InvariantId::D9 => "D9",
            InvariantId::D10 => "D10",
            InvariantId::P1 => "P1",
            InvariantId::P2 => "P2",
            InvariantId::P3 => "P3",
            InvariantId::P4 => "P4",
            InvariantId::P5 => "P5",
            InvariantId::P6 => "P6",
            InvariantId::P7 => "P7",
            InvariantId::P8 => "P8",
            InvariantId::P9 => "P9",
            InvariantId::P10 => "P10",
            InvariantId::C1 => "C1",
            InvariantId::C2 => "C2",
            InvariantId::C3 => "C3",
            InvariantId::C4 => "C4",
            InvariantId::C5 => "C5",
            InvariantId::C6 => "C6",
            InvariantId::C7 => "C7",
            InvariantId::C8 => "C8",
            InvariantId::C9 => "C9",
            InvariantId::C10 => "C10",
            InvariantId::Pr1 => "PR1",
            InvariantId::Pr2 => "PR2",
            InvariantId::Pr3 => "PR3",
            InvariantId::Pr4 => "PR4",
        }
    }

    /// Family of the invariant (DNA, peptide, chemical).
    pub fn family(&self) -> InvariantFamily {
        match self {
            InvariantId::D1
            | InvariantId::D2
            | InvariantId::D3
            | InvariantId::D4
            | InvariantId::D5
            | InvariantId::D6
            | InvariantId::D7
            | InvariantId::D8
            | InvariantId::D9
            | InvariantId::D10 => InvariantFamily::Dna,
            InvariantId::P1
            | InvariantId::P2
            | InvariantId::P3
            | InvariantId::P4
            | InvariantId::P5
            | InvariantId::P6
            | InvariantId::P7
            | InvariantId::P8
            | InvariantId::P9
            | InvariantId::P10 => InvariantFamily::Peptide,
            InvariantId::C1
            | InvariantId::C2
            | InvariantId::C3
            | InvariantId::C4
            | InvariantId::C5
            | InvariantId::C6
            | InvariantId::C7
            | InvariantId::C8
            | InvariantId::C9
            | InvariantId::C10 => InvariantFamily::Chemical,
            InvariantId::Pr1 | InvariantId::Pr2 | InvariantId::Pr3 | InvariantId::Pr4 => {
                InvariantFamily::Protocol
            }
        }
    }

    /// All 30 ids in canonical order.
    pub fn all() -> &'static [InvariantId] {
        &[
            InvariantId::D1,
            InvariantId::D2,
            InvariantId::D3,
            InvariantId::D4,
            InvariantId::D5,
            InvariantId::D6,
            InvariantId::D7,
            InvariantId::D8,
            InvariantId::D9,
            InvariantId::D10,
            InvariantId::P1,
            InvariantId::P2,
            InvariantId::P3,
            InvariantId::P4,
            InvariantId::P5,
            InvariantId::P6,
            InvariantId::P7,
            InvariantId::P8,
            InvariantId::P9,
            InvariantId::P10,
            InvariantId::C1,
            InvariantId::C2,
            InvariantId::C3,
            InvariantId::C4,
            InvariantId::C5,
            InvariantId::C6,
            InvariantId::C7,
            InvariantId::C8,
            InvariantId::C9,
            InvariantId::C10,
            InvariantId::Pr1,
            InvariantId::Pr2,
            InvariantId::Pr3,
            InvariantId::Pr4,
        ]
    }
}

/// Invariant family / substrate group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvariantFamily {
    /// DNA substrate (D-series).
    Dna,
    /// Peptide substrate (P-series).
    Peptide,
    /// Chemical / small-molecule substrate (C-series).
    Chemical,
    /// Protocol payload (PR-series): assembly-program checks rather than
    /// substrate-specific molecule checks.
    Protocol,
}

// ---------------------------------------------------------------------------
// Status & result
// ---------------------------------------------------------------------------

/// Outcome of running a single invariant.
///
/// `Unimplemented` is the Step 3a default. `DbStale` is the explicit
/// fail-closed response per `docs/threat-model.md` §AV-5 when a
/// [`HazardDatabase`] dependency is older than the configured freshness
/// window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum InvariantStatus {
    /// The invariant evaluated and the bundle is acceptable under it.
    Pass,
    /// The invariant rejects the bundle with a human-readable reason.
    Fail {
        /// Human-readable rejection reason.
        reason: String,
    },
    /// The invariant evaluated and produced a non-blocking advisory note.
    /// Advisory results are recorded in the verdict but do NOT gate
    /// approval — they are intended for dual-use research findings, weak
    /// hits that warrant reviewer attention, and synthesis-feasibility
    /// concerns that are not safety violations.
    Advisory {
        /// Human-readable advisory note.
        note: String,
    },
    /// The invariant is a Step 3a stub; real logic lands in Step 3b.
    Unimplemented,
    /// The invariant's hazard database is older than its freshness window;
    /// fail-closed per threat-model §AV-5.
    DbStale {
        /// Human-readable description of the staleness.
        reason: String,
    },
}

impl InvariantStatus {
    /// Whether this status counts as a pass for verdict aggregation.
    /// `Unimplemented` is treated as *not* a pass — it is advisory while the
    /// implementation is incomplete.
    pub fn is_pass(&self) -> bool {
        matches!(self, InvariantStatus::Pass)
    }

    /// Whether this status is a hard fail (`Fail` or `DbStale`).
    pub fn is_fail(&self) -> bool {
        matches!(
            self,
            InvariantStatus::Fail { .. } | InvariantStatus::DbStale { .. }
        )
    }

    /// Whether this status is a non-blocking advisory.
    pub fn is_advisory(&self) -> bool {
        matches!(self, InvariantStatus::Advisory { .. })
    }
}

/// A single invariant evaluation, suitable for inclusion in a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantResult {
    /// Stable identifier of the invariant that produced this result.
    pub id: InvariantId,
    /// Human-readable name (e.g. `"select_agent_screen"`).
    pub name: String,
    /// Family / category (dna / peptide / chemical).
    pub family: InvariantFamily,
    /// Outcome of the evaluation.
    pub status: InvariantStatus,
}

// ---------------------------------------------------------------------------
// Hazard database trait (threat-model §AV-5)
// ---------------------------------------------------------------------------

/// Abstract handle on a signed, versioned hazard database.
///
/// Real implementations (Step 6) wrap the SecureDNA federation, HHS Select
/// Agent updates, CWC schedule lists, etc. The runtime contract is just:
/// expose how stale the local snapshot is, expose its version, and let the
/// invariant decide whether to fail-closed.
pub trait HazardDatabase: Send + Sync {
    /// Time elapsed since the local snapshot was last successfully refreshed.
    fn freshness(&self) -> Duration;

    /// Monotonic version of the local snapshot.
    fn version(&self) -> u64;

    /// Configured maximum age before invariants depending on this DB must
    /// fail-closed. Default: 30 days, per threat-model §AV-5.
    fn freshness_window(&self) -> Duration {
        Duration::from_secs(30 * 24 * 60 * 60)
    }

    /// Convenience: is the local snapshot older than the freshness window?
    fn is_stale(&self) -> bool {
        self.freshness() > self.freshness_window()
    }
}

// ---------------------------------------------------------------------------
// Invariant traits
// ---------------------------------------------------------------------------

/// Read-only context made available to invariants alongside the bundle.
///
/// The validator constructs this once per call to `validate()` and passes
/// it into [`Invariant::evaluate_with`]. Invariants that don't need the
/// extra context can stay on the simpler [`Invariant::evaluate`] entry
/// point — the default implementation of `evaluate_with` forwards to it.
#[derive(Debug, Clone, Copy)]
pub struct InvariantContext<'a> {
    /// Hazard-database hits produced by the screening phase. Empty if no
    /// database was configured (advisory mode) or no patterns matched.
    pub screening_hits: &'a [HazardHit],
    /// The validation profile under which this bundle is being evaluated.
    pub profile: &'a BioProfile,
}

/// A pure invariant: input is a synthesis bundle; output is a status.
///
/// Bio invariants whose outcome depends only on the current bundle implement
/// this trait. Stateful invariants (cumulative volume, fragmentation) use
/// [`StatefulInvariant`] instead.
pub trait Invariant: Send + Sync {
    /// Stable id of this invariant (one of D1–D10, P1–P10, C1–C10).
    fn id(&self) -> InvariantId;

    /// Short human name used in `CheckResult.name`.
    fn name(&self) -> &'static str;

    /// Evaluate this invariant against `bundle` without contextual inputs.
    /// Most stubs implement this; context-aware invariants override
    /// [`Self::evaluate_with`] instead.
    fn evaluate(&self, bundle: &SynthesisBundle) -> InvariantStatus;

    /// Evaluate this invariant against `bundle` with screening hits + profile.
    /// Default implementation forwards to [`Self::evaluate`].
    fn evaluate_with(
        &self,
        bundle: &SynthesisBundle,
        _ctx: &InvariantContext<'_>,
    ) -> InvariantStatus {
        self.evaluate(bundle)
    }
}

/// Per-operator aggregate state shared across invariant evaluations.
///
/// Stateful invariants (e.g. fragmentation detection per threat-model §3.1,
/// rate-of-rejected bundles for AV-6) read from and update this aggregate.
/// Mutable access is the caller's responsibility — this struct is the
/// canonical shape, not a thread-safety primitive.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OperatorState {
    /// Origin principal whose state this is.
    pub principal: String,
    /// Cumulative number of approved bundles since aggregate start.
    #[serde(default)]
    pub approved_count: u64,
    /// Cumulative number of rejected bundles since aggregate start.
    #[serde(default)]
    pub rejected_count: u64,
    /// Cumulative DNA bases requested.
    #[serde(default)]
    pub cumulative_dna_bases: u64,
    /// Cumulative peptide residues requested.
    #[serde(default)]
    pub cumulative_peptide_residues: u64,
    /// Recent k-mer fingerprints, used for fragmentation detection (§3.1).
    /// Step 3b will populate this; Step 3a leaves it empty.
    #[serde(default)]
    pub recent_kmers: Vec<String>,
}

/// Stateful invariant variant that takes operator-scoped aggregate state in
/// addition to the bundle.
pub trait StatefulInvariant: Send + Sync {
    /// Stable id of this invariant.
    fn id(&self) -> InvariantId;

    /// Short human name.
    fn name(&self) -> &'static str;

    /// Evaluate against `bundle` with the operator's aggregate state.
    fn evaluate(&self, bundle: &SynthesisBundle, state: &OperatorState) -> InvariantStatus;
}

// ---------------------------------------------------------------------------
// Selection / orchestration
// ---------------------------------------------------------------------------

/// Subset of invariants to execute. Profiles can opt out of irrelevant
/// substrates (a peptide-only lab does not need C1–C10).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InvariantSelection {
    /// Invariants to *exclude* from the canonical 30. Empty = run all.
    #[serde(default)]
    pub disabled: BTreeSet<InvariantId>,
}

impl InvariantSelection {
    /// Whether `id` should be evaluated under this selection.
    pub fn includes(&self, id: InvariantId) -> bool {
        !self.disabled.contains(&id)
    }
}

/// Run every invariant in the canonical 30 (subject to `selection`) against
/// `bundle` and return their results in canonical id order.
pub fn run_all(
    bundle: &SynthesisBundle,
    selection: &InvariantSelection,
    ctx: &InvariantContext<'_>,
) -> Vec<InvariantResult> {
    let mut out = Vec::with_capacity(34);
    for id in InvariantId::all() {
        if !selection.includes(*id) {
            continue;
        }
        let (name, family, status) = evaluate_by_id(*id, bundle, ctx);
        out.push(InvariantResult {
            id: *id,
            name: name.into(),
            family,
            status,
        });
    }
    out
}

fn evaluate_by_id(
    id: InvariantId,
    bundle: &SynthesisBundle,
    ctx: &InvariantContext<'_>,
) -> (&'static str, InvariantFamily, InvariantStatus) {
    use chemical::*;
    use dna::*;
    use peptide::*;
    use protocol::*;
    match id {
        InvariantId::D1 => {
            let inv = SelectAgentScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::D2 => {
            let inv = PandemicPathogenScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::D3 => {
            let inv = ToxinGeneScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::D4 => {
            let inv = VirulenceFactorScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::D5 => {
            let inv = AntibioticResistanceScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::D6 => {
            let inv = SynbioPartScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::D7 => {
            let inv = CodonEntropyScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::D8 => {
            let inv = GcContentScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::D9 => {
            let inv = SecondaryStructureScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::D10 => {
            let inv = AssemblyCompatibilityScreen;
            (
                inv.name(),
                InvariantFamily::Dna,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P1 => {
            let inv = AntimicrobialPeptideScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P2 => {
            let inv = CellPenetratingPeptideScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P3 => {
            let inv = MembraneDisruptingScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P4 => {
            let inv = PpiInhibitorScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P5 => {
            let inv = EnzymeActiveSiteMimicScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P6 => {
            let inv = ImmunogenicEpitopeScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P7 => {
            let inv = StabilityScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P8 => {
            let inv = SolubilityScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P9 => {
            let inv = PtmSiteScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::P10 => {
            let inv = DeliveryCompatScreen;
            (
                inv.name(),
                InvariantFamily::Peptide,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C1 => {
            let inv = CwcScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C2 => {
            let inv = ExplosiveScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C3 => {
            let inv = NarcoticScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C4 => {
            let inv = EnvToxinScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C5 => {
            let inv = CarcinogenMutagenScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C6 => {
            let inv = EndocrineDisruptorScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C7 => {
            let inv = BioaccumulationScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C8 => {
            let inv = PathwayFeasibilityScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C9 => {
            let inv = ReactionSafetyScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::C10 => {
            let inv = WasteToxicityScreen;
            (
                inv.name(),
                InvariantFamily::Chemical,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::Pr1 => {
            let inv = ProtocolStepCount;
            (
                inv.name(),
                InvariantFamily::Protocol,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::Pr2 => {
            let inv = ProtocolAllowedVocabulary;
            (
                inv.name(),
                InvariantFamily::Protocol,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::Pr3 => {
            let inv = ProtocolNoNested;
            (
                inv.name(),
                InvariantFamily::Protocol,
                inv.evaluate_with(bundle, ctx),
            )
        }
        InvariantId::Pr4 => {
            let inv = ProtocolAggregateVolume;
            (
                inv.name(),
                InvariantFamily::Protocol,
                inv.evaluate_with(bundle, ctx),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariant_id_all_has_thirty_four_unique_entries() {
        let all = InvariantId::all();
        assert_eq!(all.len(), 34);
        let unique: BTreeSet<_> = all.iter().collect();
        assert_eq!(unique.len(), 34);
    }

    #[test]
    fn invariant_id_family_classifies_correctly() {
        assert_eq!(InvariantId::D5.family(), InvariantFamily::Dna);
        assert_eq!(InvariantId::P5.family(), InvariantFamily::Peptide);
        assert_eq!(InvariantId::C5.family(), InvariantFamily::Chemical);
    }

    #[test]
    fn invariant_status_classifications() {
        assert!(InvariantStatus::Pass.is_pass());
        assert!(InvariantStatus::Fail { reason: "x".into() }.is_fail());
        assert!(InvariantStatus::DbStale { reason: "x".into() }.is_fail());
        assert!(!InvariantStatus::Unimplemented.is_pass());
        assert!(!InvariantStatus::Unimplemented.is_fail());
        assert!(InvariantStatus::Advisory { note: "x".into() }.is_advisory());
        assert!(!InvariantStatus::Advisory { note: "x".into() }.is_pass());
        assert!(!InvariantStatus::Advisory { note: "x".into() }.is_fail());
    }

    #[test]
    fn selection_round_trips_disabled() {
        let mut sel = InvariantSelection::default();
        sel.disabled.insert(InvariantId::D7);
        assert!(!sel.includes(InvariantId::D7));
        assert!(sel.includes(InvariantId::D1));

        let json = serde_json::to_string(&sel).unwrap();
        let back: InvariantSelection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sel);
    }

    #[test]
    fn selection_rejects_unknown_fields() {
        let bad = r#"{"disabled":["D1"],"unknown":42}"#;
        assert!(serde_json::from_str::<InvariantSelection>(bad).is_err());
    }

    #[test]
    fn run_all_with_dna_bundle_returns_thirty_four_results() {
        let bundle = sample_dna_bundle();
        let profile = sample_profile();
        let ctx = InvariantContext {
            screening_hits: &[],
            profile: &profile,
        };
        let results = run_all(&bundle, &InvariantSelection::default(), &ctx);
        assert_eq!(results.len(), 34);
    }

    #[test]
    fn run_all_honours_selection() {
        let mut sel = InvariantSelection::default();
        sel.disabled.insert(InvariantId::D1);
        sel.disabled.insert(InvariantId::C10);
        sel.disabled.insert(InvariantId::Pr1);
        let profile = sample_profile();
        let ctx = InvariantContext {
            screening_hits: &[],
            profile: &profile,
        };
        let results = run_all(&sample_dna_bundle(), &sel, &ctx);
        assert_eq!(results.len(), 31);
        assert!(!results.iter().any(|r| r.id == InvariantId::D1));
        assert!(!results.iter().any(|r| r.id == InvariantId::C10));
        assert!(!results.iter().any(|r| r.id == InvariantId::Pr1));
    }

    #[test]
    fn protocol_bundle_runs_pr_pipeline() {
        use crate::models::bundle::{BundleAuthority, SynthesisPayload};
        let bundle = SynthesisBundle {
            timestamp: chrono::Utc::now(),
            source: "t".into(),
            sequence: 0,
            payload: SynthesisPayload::Protocol {
                steps: vec!["aspirate 10uL".into(), "dispense 10uL".into()],
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: Default::default(),
        };
        let profile = sample_profile();
        let ctx = InvariantContext {
            screening_hits: &[],
            profile: &profile,
        };
        let results = run_all(&bundle, &InvariantSelection::default(), &ctx);
        assert_eq!(results.len(), 34);
        // PR1–PR4 must be present and must not be Unimplemented for a
        // protocol payload — at minimum PR1 (step count) returns Pass.
        let pr1 = results.iter().find(|r| r.id == InvariantId::Pr1).unwrap();
        assert!(matches!(pr1.status, InvariantStatus::Pass));
    }

    fn sample_dna_bundle() -> SynthesisBundle {
        use crate::models::bundle::{BundleAuthority, SynthesisPayload};
        SynthesisBundle {
            timestamp: chrono::Utc::now(),
            source: "test".into(),
            sequence: 1,
            payload: SynthesisPayload::Dna {
                sequence: "ATGAAAGCTGGCGTTTTTTGCCTG".into(),
            },
            delta_time: 0.0,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: Vec::new(),
            },
            metadata: Default::default(),
        }
    }

    pub(crate) fn sample_profile() -> BioProfile {
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
}
