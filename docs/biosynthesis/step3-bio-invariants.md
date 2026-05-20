# Step 3 — Biological Invariant Set Definition

**Status:** v0.1 design + executed. Implements `docs/spec.md` Step 3.
**Prereqs:** `invariants/mod.rs` trait + `InvariantContext`, `screening::HazardScreener`, `models::bundle::SynthesisPayload` (all shipping; see gap-closure `spec.md` Steps 6–9).

This document is the formal specification for the deterministic invariant set the firewall evaluates on every `SynthesisBundle`. It is the bio analog of the P1–P20 physics invariants in `invariant-robotics`. The contract is: **every invariant is a total function of `(bundle, context)` returning one of `Pass`, `Fail { reason }`, `Advisory { note }`, or `Unimplemented`.** No invariant performs I/O at evaluation time — all hazard data is pre-fetched into `InvariantContext::screening_hits` by the screening phase.

The catalogue is **34 invariants in four families**: ten DNA (D1–D10), ten peptide (P1–P10), ten chemical (C1–C10), and four protocol (PR1–PR4). Code lives under `crates/invariant-biosynthesis-core/src/invariants/`. Each invariant has unit tests covering its pass / fail / advisory paths plus one cross-family pass-through smoke test.

---

## 1. Common Contract

### 1.1 Trait

```rust
pub trait Invariant {
    fn id(&self) -> InvariantId;
    fn evaluate(&self, bundle: &SynthesisBundle) -> InvariantStatus;
    fn evaluate_with(&self, bundle: &SynthesisBundle, ctx: &InvariantContext)
        -> InvariantStatus { self.evaluate(bundle) }
}
```

`InvariantContext` carries `screening_hits: &[HazardHit]` (output of the file-backed hazard DB) and `profile: &BioProfile` (BSL level, allowed substrates, volume cap, export-control flags). The validator builds the context once per bundle and threads it through `run_all`.

### 1.2 Status semantics

| Variant | Meaning | Effect on verdict |
|---|---|---|
| `Pass` | Predicate holds. | Contributes to approval. |
| `Fail { reason }` | Predicate violated. | Blocks approval. |
| `Advisory { note }` | Dual-use signal worth a reviewer note; not a hard violation. | Recorded as `passed=true` with `advisory:` prefix. |
| `Unimplemented` | Stub; treated per `ValidatorConfig::allow_unimplemented_invariants` (default fail-closed). | Blocks approval unless explicitly allowed. |

### 1.3 Complexity bound

Every invariant must run in `O(L · k)` worst case where `L` is the payload length (DNA bases / peptide residues / SMILES characters / protocol step bytes) and `k` is the number of compiled regex patterns or motif rules. No invariant performs an unbounded search, network fetch, or BLAST-style alignment at evaluate time. Sub-linear lookups (`HashSet::contains`, `Regex::find`) are preferred where possible. The screening phase amortises hazard-DB work into a single pass before invariants run.

### 1.4 Failure-mode taxonomy

Every invariant's Rustdoc must document its known false-positive (FP) and false-negative (FN) modes. Heuristic invariants (codon-entropy, GC window, hydrophobic-fraction, motif regex) are explicitly conservative on the safety-critical side: they prefer `Advisory` over `Pass` when ambiguous. DB-driven invariants are bound by the freshness window of the signed hazard DB (default 30 days, threat-model §AV-5).

---

## 2. DNA Family — D1 through D10

Substrate: `SynthesisPayload::Dna { sequence }`. Non-DNA payloads pass through (`Pass`).

### D1 — Select Agent Screen
**Predicate:** No screening hit carries `hazard_class ∈ {select-agent, sap}`.
**Algorithm:** linear scan of `ctx.screening_hits`.
**FP:** false hit on a homologous but benign housekeeping ortholog (mitigated by curated DB labels).
**FN:** novel agent not yet in the signed DB; addressed at the screening layer (Step 6 freshness gate).
**References:** HHS Select Agent Program, NSABB DURC framework.

### D2 — Pandemic Pathogen Screen
**Predicate:** No hit with class `∈ {pandemic-pathogen, pandemic, pheic}`.
**FP:** as D1.
**FN:** lab-leak-relevant gain-of-function variants not yet curated; covered by D3/D4 motif overlap.

### D3 — Toxin Gene Screen
**Predicate:** No hit with class `∈ {toxin, toxin-gene}`.
**FP:** Cry-like Bt toxin in agricultural research → mitigated by profile-level allow-listing (Step 4 PCA scope).
**FN:** novel toxin homologs without DB entries.

### D4 — Virulence Factor Screen *(advisory)*
**Predicate:** Advisory if any hit has class `∈ {virulence, virulence-factor}`; else Pass.
**Rationale:** virulence factors are heavily dual-use; reviewer triage rather than auto-block.

### D5 — Antibiotic Resistance Screen
**Predicate:** No hit with class `∈ {antibiotic-resistance, card, amr}`.
**Reference:** CARD, ResFinder. `card` is the canonical class label emitted by curated CARD-derived DBs.

### D6 — Synbio Part Screen *(advisory)*
**Predicate:** Advisory on hits in `{synbio-part, igem, addgene}`. Common parts (RBS, terminators, marker genes) are inherently dual-use; we record but don't block.

### D7 — Codon Entropy Screen *(advisory)*
**Predicate:** Shannon entropy `H(c)` over frame-1 codon distribution must lie in `[2.5, 5.8]` bits. Sequences shorter than 10 codons pass without scoring.
**Math:** `H(c) = -Σ_i p_i log₂ p_i` over the 64-codon alphabet (with `N` mapping to a 65th symbol).
**Rationale:** very low entropy → suspicious repeat / repetitive codon-optimization artefact; very high entropy → near-random sequence not consistent with any real ORF.
**FP/FN:** highly host-optimised but legitimate sequences may dip toward the lower bound; an attacker can also pad entropy with junk. Hence advisory only.

### D8 — GC Content Screen
**Predicate:** Every 100 nt sliding window has `GC ∈ [0.25, 0.75]`. Whole-sequence single window for inputs shorter than 100 nt.
**Algorithm:** rolling counter, `O(L)`.
**Rationale:** windows outside this range often correspond to synthesis-infeasible homopolymers or assembly-incompatible regions.
**FP:** legitimate AT-rich (e.g. *Plasmodium*) or GC-rich (some *Streptomyces*) genomes. Profile-level overrides are out-of-scope for v0.1.

### D9 — Secondary Structure Screen
**Predicate:** No 20 nt window has its reverse complement appearing later in the sequence with ≥4 nt spacer (hairpin candidate).
**Algorithm:** hash-of-window forward pass, `O(L)`. Real ΔG estimation (e.g. ViennaRNA) deferred — see Known Gaps.
**FN:** thermodynamically stable structures with mismatched / bulged stems are missed by the perfect-rev-comp heuristic.

### D10 — Assembly Compatibility Screen *(advisory)*
**Predicate:** Advisory when the fragment terminus exposes BsaI / BbsI / SapI Golden-Gate sites that would interfere with downstream assembly.
**Note:** cross-bundle fragmentation (an attacker splitting a hazardous gene across multiple bundles) is handled by the `StatefulInvariant` pathway in `threat.rs` and is **out of scope** for the per-bundle D-family.

---

## 3. Peptide Family — P1 through P10

Substrate: `SynthesisPayload::Peptide { sequence }` (single-letter AA, optional modifications). Non-peptide payloads pass through.

### P1 — Antimicrobial Peptide Screen
**Predicate:** Fail on DB hits in `{antimicrobial, amp}`. Advisory for sequences of length 10–60 AA with **net charge ≥ +3** *and* **hydrophobic fraction ≥ 0.35**.
**Hydrophobic set:** `{A, V, L, I, F, W, Y, M}`.
**Net charge:** `#{K,R,H} − #{D,E}` at neutral pH (H counted at +1 here for screening conservatism).

### P2 — Cell-Penetrating Peptide Screen
**Predicate:** Fail on DB `{cpp, cell-penetrating}`. Advisory on TAT (`GRKKRRQRRRPPQ`), penetratin (`RQIKIWFQNRRMKWKK`), or polyArg-`R{6,}`.

### P3 — Membrane-Disrupting Screen
**Predicate:** Fail on DB `{pore-forming, lytic, membrane-disrupting}`. Advisory if any 18-AA sliding window simultaneously has hydrophobic fraction ≥ 0.55 *and* net charge ≥ +3 (amphipathic α-helix proxy).

### P4 — PPI Inhibitor Screen *(advisory)*
**Predicate:** Advisory on DB `{ppi-inhibitor, ppi}`. Pure DB-driven at this layer; structural inference is deferred.

### P5 — Enzyme Active-Site Mimic Screen
**Predicate:** Fail on DB `{toxin, neurotoxin, ribotoxin}`. Advisory on serine-hydrolase `G-X-S-X-G` or zinc-metalloprotease `H-E-X-X-H` motifs.

### P6 — Immunogenic Epitope Screen *(advisory)*
**Predicate:** Advisory on DB `{epitope, mhc-binder}` or any 8–11 AA window with hydrophobic fraction ≥ 0.4 (MHC-I length proxy).

### P7 — Stability Screen *(advisory)*
**Predicate:** Advisory if N-terminal residue ∈ `{R, K, F, L, W, Y}` (Bachmair N-end rule destabilising) **or** trypsin sites (K|R) ≥ 5 in ≤30 AA.

### P8 — Solubility Screen *(advisory)*
**Predicate:** Advisory on any 6-residue window of strongly aggregation-prone AAs `{I, L, V, F, Y, W}` or polyQ stretch ≥ 10.

### P9 — PTM Site Screen *(advisory)*
**Predicate:** Advisory when ≥5 PTM motifs match: N-glycosylation sequon `N-X-[ST]` (X ≠ P) plus C-terminal CAAX prenylation.

### P10 — Delivery Compatibility Screen
**Predicate:** Fail on non-canonical AA characters outside the 20-letter alphabet (free-peptide envelope is the assumption; modified/protected AAs require explicit profile opt-in). Advisory if length > 50 AA or > 4 cysteines (folding/disulfide complications).

**Test fixtures:** `examples/safe-peptide-bundle.json` (pass-through), `examples/dangerous-peptide-bundle.json` (melittin-like amphipath that trips P1 + P3 advisories).

---

## 4. Chemical Family — C1 through C10

Substrate: `SynthesisPayload::Chemical { smiles }`. Non-chemical payloads pass through. SMILES is treated as an **opaque string** with regex-level structural heuristics — there is no built-in cheminformatics library in v0.1 (see Known Gaps).

### C1 — CWC Screen
**Predicate:** Fail on Schedule-1 DB hits. Advisory on Schedule-2/3 hits **or** alkylphosphonate-with-leaving-group SMILES heuristic (`P(=O)(O…)(F)` / similar regex tokens).
**Reference:** Chemical Weapons Convention Annex on Chemicals.

### C2 — Explosive Screen
**Predicate:** Fail on DB `{explosive, energetic-material}`. Advisory for ≥3 nitro groups, peroxide token `OO`, or azide `N=N=N`.

### C3 — Narcotic Screen
**Predicate:** Fail on DB `{narcotic, controlled-substance, dea-schedule}`.

### C4 — Environmental Toxin Screen
**Predicate:** Fail on DB `{tsca, pop, pfas}`. Advisory for ≥4 chlorine atoms or perfluoro-carbon group regex.

### C5 — Carcinogen / Mutagen Screen
**Predicate:** Fail on DB `{carcinogen, mutagen, iarc-1, iarc-2a}`. Advisory on aromatic amines, N-nitroso, or carbocation `[C+]`.

### C6 — Endocrine Disruptor Screen *(advisory)*
**Predicate:** Advisory on DB `{endocrine-disruptor, edsp}` or bisphenol-like di-phenol core.

### C7 — Bioaccumulation Screen *(advisory)*
**Predicate:** Advisory on DB `{bioaccumulator, pbt}` or ≥12-carbon aliphatic chain with O count <2 (logKow proxy).

### C8 — Pathway Feasibility Screen
**Predicate:** Fail on empty SMILES or DB `infeasible-pathway`. Advisory when SMILES > 250 chars (synthesis-infeasibility proxy).

### C9 — Reaction Safety Screen
**Predicate:** Fail on DB `{reaction-incompatibility, pyrophoric, peroxide-former}`. Advisory on `[Na]` / `[K]` / `[Li]` / `[AlH4-]` reagent tokens.

### C10 — Waste Toxicity Screen
**Predicate:** Fail on DB `{high-toxicity-waste, rcra}`. Advisory on `[Hg]` / `[Pb]` / `[Cd]` / `[As]` / `[Cr+6]` / `[U]` heavy-metal tokens.

**FP/FN policy:** every C-family invariant has a Rustdoc block enumerating known false-positive and false-negative modes (e.g. C7's logKow proxy is blind to branched but lipophilic species; C5's regex misses planar polycyclic aromatics not flagged by the DB). The `Advisory` tier is preferred whenever the heuristic is structural-only.

---

## 5. Protocol Family — PR1 through PR4

Substrate: `SynthesisPayload::Protocol { steps }`. Non-protocol payloads pass through.

### PR1 — Step Count
**Predicate:** Fail on empty `steps`. Fail when `steps.len() > 256`.

### PR2 — Allowed Vocabulary
**Predicate:** Each step's first token must be in the built-in allowed-verb set: `{aspirate, dispense, mix, incubate, centrifuge, transfer, wash, elute, heat, cool, shake, vortex, ligate, digest, amplify, anneal, denature, extend, couple, deprotect, cleave, wait, measure, image, log}`. Empty steps fail with a sentinel `<empty>` token.
**Future:** per-profile vocabularies (Known Gaps).

### PR3 — No Nested Protocols
**Predicate:** Fail on any step containing `protocol:` / `include:` / `subprotocol:` / `run-protocol`.
**Rationale:** prevents an attacker from smuggling a protocol-as-string through a single bundle to bypass the step-count cap.

### PR4 — Aggregate Volume vs Profile Cap
**Predicate:** Sum explicit `<n>(uL|mL|L)` volume tokens across all steps; Fail when total > `profile.synthesis_volume_cap_l`; Advisory when total > `0.5 × cap`.
**Algorithm:** `O(total_step_chars)` regex scan with unit normalization to litres.

---

## 6. Validator Wiring

`validate(bundle, now, attested_inputs)` runs:

1. **Authority** (PCA chain) — must verify, scopes must subset down to declared ops.
2. **Attestation** (optional) — verify Ed25519 + freshness + replay on each `AttestedInput`.
3. **Screening** — `HazardScreener::screen_payload(payload)` → `Vec<HazardHit>`. Fail-closed if no DB and `allow_missing_hazard_db = false`.
4. **Invariants** — `run_all(bundle, &InvariantContext { screening_hits, profile })`. All 34 invariants execute regardless of family; the non-substrate ones pass through cheaply.
5. **Verdict aggregation** — approval iff `authority_passed && attestation_passed && screening_passed && all_invariants_passed`. Verdict is signed with the validator's Ed25519 key and emits a `screening_hits: Vec<HazardHit>` field for downstream rendering.

`InvariantStatus::Unimplemented` is a hard fail unless `ValidatorConfig::allow_unimplemented_invariants` is set (gap-closure Step 2 policy). After Steps 6–9 of the gap-closure plan landed, **no shipping invariant returns `Unimplemented`** — the variant is retained only for forward-compatibility with future families.

---

## 7. Test Coverage

Every invariant ships with at minimum:

- One `Pass` path on a representative non-violating fixture.
- One `Fail` path (or `Advisory` for tier-2 invariants) on a representative violating fixture.
- One cross-family pass-through (e.g. peptide payload through a DNA invariant returns `Pass`).
- One alias coverage check (DB hazard-class string variants — `amp` vs `antimicrobial`, `cpp` vs `cell-penetrating`, etc.).

Aggregate counts as of the last gap-closure sweep: **core crate 403 unit tests**, including ~32 D-family, ~31 P-family, ~30 C-family, ~18 PR-family, plus the validator pipeline / context-threading tests. See gap-closure `spec.md` Steps 6–9 for the per-step delta.

---

## 8. Known Gaps (deferred)

Items intentionally out of scope for v0.1 of the invariant set, recorded so reviewers know what is *not* in the shipping firewall:

1. **Real cheminformatics.** SMILES is regex-only; no canonicalisation, no SMARTS matching, no fingerprint similarity, no logP/logKow calculation, no ring/stereo perception. Replacing the C-family heuristics with an RDKit (or pure-Rust equivalent) layer is the principal v0.2 follow-up.
2. **Real homology engines.** D1/D2/D3 rely on the curated signed DB; there is no BLAST, no HMMER, no DIAMOND. Homology is therefore as good as the DB's curators.
3. **Codon-usage host hints.** D7 uses a substrate-agnostic Shannon entropy bound; a real host-aware codon-adaptation index (CAI) per organism is deferred.
4. **Cross-bundle fragmentation.** Per-bundle invariants don't see history; the `threat.rs` k-mer-overlap detector handles fragmentation across bundles. A first-class `StatefulInvariant` family is on the v0.2 roadmap.
5. **Per-profile step vocabularies.** PR2's allowed-verb list is hard-coded; profile-level overrides (e.g. allow `transduce` for a virology BSL-3 profile) are deferred.
6. **ΔG-based RNA secondary-structure scoring.** D9 uses perfect reverse-complement matching; ViennaRNA-style minimum-free-energy folding is out of scope for v0.1.

These gaps are also reflected in the README's "Known gaps" section and in the gap-closure PR body.

---

## 9. References

- HHS Select Agent Program — 42 CFR Part 73.
- Australia Group control list — common control list of dual-use biological equipment and related technology.
- Chemical Weapons Convention — Annex on Chemicals (Schedule 1/2/3).
- IARC Monographs — Group 1 and 2A carcinogen classifications.
- CARD — Comprehensive Antibiotic Resistance Database.
- Bachmair, Finley & Varshavsky (1986) — N-end rule of protein degradation.
- IGSC — International Gene Synthesis Consortium harmonized screening protocol.
- SecureDNA — cryptographic hazard-screening protocol (referenced from Step 6 doc).
- NCBI Genetic Code Table 1 — standard codon translation used by `naive_translate` (gap-closure Step 3).
- Threat model (`docs/threat-model.md`) — the upstream attack-vector taxonomy this invariant set defends against.
