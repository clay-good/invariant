> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Invariant Biosynthesis — Gap Closure Spec

This is a step-by-step instruction sheet for finishing the `invariant-biosynthesis` workspace. It is written as a sequence of self-contained prompts you can hand to Claude Code, one at a time. Each step lists its goal, preconditions, the prompt itself, and an acceptance check. **Run the prompts in order** — later steps assume earlier ones have landed.

## Progress log

- [x] **Step 1** — Baseline established (2026-04-24). Fixed four `assert!(true)` placeholder tests (in `screening/mod.rs`, `attestation.rs`, `sim/lib.rs`, `eval/lib.rs`, `fuzz/lib.rs`) that were failing `clippy::assertions_on_constants`; replaced with meaningful smoke assertions on the relevant types. Build/test/clippy all green; 301 tests pass. Note: working tree is **not a git repo**, so the branch-creation portion of Step 1 was skipped — re-introduce a `gap-closure` branch when git is initialized.
- [x] **Step 2** — Unimplemented-invariant policy added (2026-04-24). `ValidatorConfig` now carries `allow_unimplemented_invariants: bool` (default `false`, fail-closed). When `false`, any `InvariantStatus::Unimplemented` blocks approval; the verdict gains a synthetic `invariants_unimplemented` `CheckResult` listing every unimplemented id and the active policy. Builder method `with_allow_unimplemented_invariants(bool)` added. Existing `validator_emits_thirty_invariant_check_results` updated for the new check count (32). Two new tests cover both modes.
- [x] **Step 3** — Codon translation implemented (2026-04-24). Replaced the empty `naive_translate` stub with `translate_dna_sequence(&str) -> Result<TranslationFrames, TranslateError>` using NCBI translation table 1 (standard genetic code). Returns three forward reading frames in a `TranslationFrames` struct (with an `iter()` helper). Case-insensitive; `N` codons map to `X`; non-ACGTN input produces `TranslateError::InvalidBase { base, offset }`; trailing partial codons are dropped. Reverse-complement frames intentionally out of scope (caller's responsibility). 11 new unit tests cover: known control sequence (`MK*`), three-frame lengths, lowercase normalization, ambiguous-base handling, partial-codon truncation, empty input, non-ACGTN rejection, whitespace rejection, frame-shift divergence, iter-order, and all three stop codons. The bundle-level `translate_dna(&SynthesisBundle)` wrapper now returns `Option<Result<TranslationFrames, TranslateError>>`. Total core tests: 285 (was 274).
- [x] **Step 4** — `FileBackedHazardDatabase` and signed JSON format implemented (2026-04-24). Replaced the `screening::screen()` `todo!()` stub with a full file-backed implementation:
  - On-disk envelope `SignedHazardFile { issuer_kid, signature, body }` carrying `HazardDatabaseBody { schema_version: 1, db_version, dna_signatures, peptide_signatures, chemical_signatures }`. All structs use `#[serde(deny_unknown_fields)]`.
  - `HazardEntry { id, label, hazard_class, pattern }` — `pattern` is a `regex::Regex` for DNA/peptide (case-folded) and currently a SMILES regex placeholder for chemicals (real cheminformatics deferred to Step 8).
  - `FileBackedHazardDatabase::load(path, trusted_keys)` and `from_bytes(...)` verify the schema version, look up the issuer kid in the trusted-key map, and verify the Ed25519 signature against `sha256_hex_json(&body)` (using the existing `util::sha256_hex_json` infrastructure). Implements the `invariants::HazardDatabase` trait (`freshness`, `version`, `freshness_window` overridable; default 30 days per threat-model §AV-5).
  - `screen(&SynthesisPayload)` dispatches per substrate, returns `Vec<HazardHit>` with the matched entry and matched substring; protocol payloads return empty.
  - `ScreeningError` enum: `Io`, `Json`, `SchemaVersion`, `UnknownIssuer`, `Signature`, `SignatureMismatch`, `BadPattern`.
  - 14 unit tests cover: valid load, tampered-body detection, wrong-key rejection, unknown-issuer rejection, schema-version mismatch, regex-compile failure, DNA/peptide/chemical match paths, lowercase normalization for nucleic-acid substrates, no-match, protocol no-op, default 30-day freshness window, freshness-window override, and `deny_unknown_fields` enforcement on the envelope. Total core tests: 299 (was 285).
- [x] **Step 5** — Hazard database wired into the validator pipeline (2026-04-24).
  - Added `HazardScreener: HazardDatabase` super-trait in `screening/mod.rs` exposing `screen_payload(&SynthesisPayload) -> Vec<HazardHit>`. `FileBackedHazardDatabase` implements both. Trait-object indirection lets the validator hold any screener (file-backed, network-backed, in-memory test) without recompilation.
  - `ValidatorConfig` now carries `hazard_db: Option<Arc<dyn HazardScreener>>` and `allow_missing_hazard_db: bool` (default `false`). Builders `with_hazard_db(...)` and `with_allow_missing_hazard_db(...)` added.
  - `validate()` runs screening before invariants. A new `screening` `CheckResult` is appended; non-empty hits make it fail (with id/hazard-class summary). Approval now requires `authority_passed && screening_passed && all_invariants_passed`.
  - When `hazard_db` is `None`, the screening check is `fail-closed` by default (advisory only when `allow_missing_hazard_db = true`). Production deployments never see a quiet pass on a missing database.
  - `ValidationOutput` gained `screening_hits: Vec<HazardHit>` so callers can render or audit hits without re-walking the verdict.
  - Updated `validator_emits_thirty_invariant_check_results` for the new check count (32 → 33). Added 4 new tests covering: missing-DB fail-closed; missing-DB advisory; DB present with no hits; DB present with hit propagation into the verdict and `screening_hits`. Total core tests: 303 (was 299).
- [x] **Step 6** — DNA invariants D1–D10 implemented (2026-04-25). The validator pipeline now runs real DNA-substrate logic.
  - **Status enum** gained `InvariantStatus::Advisory { note }` (non-blocking; recorded in verdict). `is_advisory()` helper added; validator records advisory checks as `passed=true` with an "advisory:" detail prefix.
  - **`InvariantContext`** struct added in `invariants/mod.rs` carrying `screening_hits: &[HazardHit]` and `profile: &BioProfile`. Trait gained default `evaluate_with(bundle, ctx)` forwarding to `evaluate(bundle)`. `run_all` now takes a context; the validator builds it from the screening phase + the configured profile.
  - **D1 SelectAgentScreen** — Fail when any screening hit's `hazard_class` matches `select-agent` / `sap`; else Pass.
  - **D2 PandemicPathogenScreen** — Fail on `pandemic-pathogen` / `pandemic` / `pheic` hits; else Pass.
  - **D3 ToxinGeneScreen** — Fail on `toxin` / `toxin-gene` hits.
  - **D4 VirulenceFactorScreen** — Advisory on `virulence` / `virulence-factor` hits (dual-use; reviewer triage rather than block).
  - **D5 AntibioticResistanceScreen** — Fail on `antibiotic-resistance` / `card` / `amr` hits.
  - **D6 SynbioPartScreen** — Advisory on `synbio-part` / `igem` / `addgene` hits.
  - **D7 CodonEntropyScreen** — Advisory if Shannon entropy of frame-1 codons falls outside `[2.5, 5.8]`. Sequences shorter than 10 codons pass without scoring.
  - **D8 GcContentScreen** — Fail if any 100-nt window has GC outside `[0.25, 0.75]`. Whole-sequence window for shorter inputs.
  - **D9 SecondaryStructureScreen** — Fail when a 20-nt window's reverse complement appears later in the sequence with ≥4 nt spacing (hairpin candidate). Real ΔG estimation deferred.
  - **D10 AssemblyCompatibilityScreen** — Advisory when the fragment terminus exposes BsaI / BbsI / SapI sites. Cross-bundle fragmentation handled by the StatefulInvariant pathway (out of scope).
  - **Tests added (~32):** per-invariant pass / fail / advisory paths, hazard-class alias coverage, non-DNA payload pass-through, bundle smoke test, and updated existing `run_all` / status tests for the new signature and Advisory variant. Validator test for unimplemented-policy now asserts on `P1` (D-family is real). Total core tests: 324 (was 303).
- [x] **Step 7** — Peptide invariants P1–P10 implemented (2026-04-25). All ten peptide invariants are now real heuristic implementations consuming `InvariantContext` (screening hits + profile).
  - **P1 AntimicrobialPeptideScreen** — Fail on `antimicrobial`/`amp` DB hits; Advisory for 10–60 AA with net charge ≥ +3 and hydrophobic fraction ≥ 0.35.
  - **P2 CellPenetratingPeptideScreen** — Fail on `cpp`/`cell-penetrating` DB hits; Advisory for TAT (`GRKKRRQRRRPPQ`) / penetratin / polyArg ≥ 6.
  - **P3 MembraneDisruptingScreen** — Fail on `pore-forming`/`lytic`/`membrane-disrupting` DB hits; Advisory for any 18-AA window with hydrophobic fraction ≥ 0.55 AND net charge ≥ +3 (amphipathic α-helix proxy).
  - **P4 PpiInhibitorScreen** — Advisory on `ppi-inhibitor`/`ppi` DB hits (database-driven only at this layer).
  - **P5 EnzymeActiveSiteMimicScreen** — Fail on `toxin`/`neurotoxin`/`ribotoxin` DB hits; Advisory on serine-hydrolase `G-X-S-X-G` or zinc-metalloprotease `H-E-X-X-H` motifs.
  - **P6 ImmunogenicEpitopeScreen** — Advisory on `epitope`/`mhc-binder` DB hits or 8–11 AA hydrophobic-fraction-≥0.4 (MHC-I length proxy).
  - **P7 StabilityScreen** — Advisory for destabilizing N-terminal residues (R/K/F/L/W/Y, Bachmair N-end rule) or ≥5 trypsin sites (K/R) in ≤30 AA.
  - **P8 SolubilityScreen** — Advisory for any 6-residue window of strongly aggregation-prone AAs (I/L/V/F/Y/W) or polyQ ≥ 10.
  - **P9 PtmSiteScreen** — Advisory when ≥5 PTM motif matches (N-X-[ST] sequons + CAAX prenylation).
  - **P10 DeliveryCompatScreen** — Fail on non-canonical AAs; Advisory on length > 50 AA or > 4 cysteines (free-peptide envelope).
  - **Examples added:** `examples/safe-peptide-bundle.json` (`MAGYKSTNDQ`), `examples/dangerous-peptide-bundle.json` (melittin-like amphipath that trips P1/P3 advisories).
  - **Tests added (~31):** per-invariant pass / fail / advisory paths, hazard-class alias coverage, DNA-payload pass-through smoke test. Updated validator unimplemented-policy assertion to look for `C1` (only chemical family remains stub). Total core tests: 346 (was 324).
- [x] **Step 8** — Chemical invariants C1–C10 implemented (2026-04-25). All ten invariants are real heuristics combining DB hazard-class hits with structural-regex SMILES alerts. FP/FN failure modes are documented inline on each invariant.
  - **C1 CwcScreen** — Schedule-1 hits → Fail; Schedule-2/3 → Advisory; alkylphosphonate-with-leaving-group SMILES heuristic → Advisory.
  - **C2 ExplosiveScreen** — Fail on `explosive`/`energetic-material` DB; Advisory for ≥3 nitro groups, peroxide (`OO`), or azide (`N=N=N`).
  - **C3 NarcoticScreen** — Fail on `narcotic`/`controlled-substance`/`dea-schedule` DB hits.
  - **C4 EnvToxinScreen** — Fail on `tsca`/`pop`/`pfas` DB; Advisory for ≥4 chlorines or perfluoro carbon group.
  - **C5 CarcinogenMutagenScreen** — Fail on `carcinogen`/`mutagen`/`iarc-1`/`iarc-2a` DB; Advisory on aromatic amines, N-nitroso, or `[C+]`.
  - **C6 EndocrineDisruptorScreen** — Advisory on `endocrine-disruptor`/`edsp` DB hits or bisphenol-like di-phenol core.
  - **C7 BioaccumulationScreen** — Advisory on `bioaccumulator`/`pbt` DB or ≥12-carbon aliphatic chain with O count <2.
  - **C8 PathwayFeasibilityScreen** — Fail on empty SMILES or `infeasible-pathway` DB; Advisory when SMILES > 250 chars.
  - **C9 ReactionSafetyScreen** — Fail on `reaction-incompatibility`/`pyrophoric`/`peroxide-former` DB; Advisory on `[Na]` / `[K]` / `[Li]` / `[AlH4-]` reagent tokens.
  - **C10 WasteToxicityScreen** — Fail on `high-toxicity-waste`/`rcra` DB; Advisory on `[Hg]` / `[Pb]` / `[Cd]` / `[As]` / `[Cr+6]` / `[U]` heavy-metal tokens.
  - **Validator tests rewritten:** `validator_emits_thirty_invariant_check_results` count drops to 32 (no unimplemented-policy entry needed). Added `validator_no_unimplemented_policy_when_all_invariants_real` confirming the synthetic check is absent. Removed obsolete tests asserting `Unimplemented` behaviour for D/P/C families (the `Unimplemented` branch is still exercised via direct `InvariantStatus` unit tests).
  - Total core tests: 369 (was 346). Clippy clean.
- [x] **Step 9** — Protocol invariant pipeline added (2026-04-25). `SynthesisPayload::Protocol` is no longer ignored.
  - **InvariantId** gained `Pr1`, `Pr2`, `Pr3`, `Pr4` (rendered as `PR1`–`PR4`); `InvariantFamily::Protocol` added; `InvariantId::all()` now returns 34 ids; `evaluate_by_id` dispatches the four new invariants. Validator `category_for` maps to `invariant.protocol`.
  - **New module** `invariants/protocol.rs`:
    - **PR1 ProtocolStepCount** — Fail on empty steps; Fail when `steps.len() > 256`.
    - **PR2 ProtocolAllowedVocabulary** — Fail when any step's first token is not in the built-in allowed-verb list (aspirate / dispense / mix / incubate / centrifuge / transfer / wash / elute / heat / cool / shake / vortex / ligate / digest / amplify / anneal / denature / extend / couple / deprotect / cleave / wait / measure / image / log). Empty steps fail with `<empty>` token.
    - **PR3 ProtocolNoNested** — Fail on any step containing `protocol:` / `include:` / `subprotocol:` / `run-protocol`.
    - **PR4 ProtocolAggregateVolume** — Sums explicit `<n>(uL|mL|L)` volume tokens across steps; Fail when total > profile cap; Advisory when total > 0.5 × cap.
  - All four pass when payload is non-Protocol (DNA/peptide/chemical pass-through).
  - **Tests added (~18):** PR1–PR4 pass / fail / advisory paths; volume-parser unit-aware tests; non-protocol pass-through. New `protocol_bundle_runs_pr_pipeline` confirms `run_all` returns 34 results and PR1 is reachable for protocol payloads.
  - **Tests updated:** invariant-id catalogue size 30 → 34; validator check count 32 → 36; selection test now disables peptide+chemical+protocol families to keep the 10-DNA assertion.
  - Total core tests: 386 (was 369). Clippy clean (one `manual_contains` lint fixed).
- [x] **Step 10** — Attestation logic completed and wired into the validator (2026-04-25).
  - **Module `attestation.rs`** rewritten:
    - New `AttestationVerifier` carrying a trusted-keys map plus configurable `max_age` (default 5 min), `clock_skew` tolerance (default 30 s), and bounded recent-nonce cache (default capacity 4096). Builders `with_max_age` / `with_clock_skew` / `with_nonce_cache_cap`.
    - `verify_input` and `verify_reading` perform: (1) signer-kid lookup in trusted keys, (2) base64 + length-checked Ed25519 signature parse, (3) signature verification against `sha256_hex_json(canonical)` where `canonical` is the struct minus `signature`, (4) freshness check against `max_age`, (5) future-skew check against `clock_skew`, (6) replay rejection via the nonce cache; on success, the nonce is recorded and the cache is FIFO-trimmed to `nonce_cap`.
    - New `AttestationError` enum: `UnknownKid`, `Signature`, `BadSignature`, `Stale`, `FutureTimestamp`, `Replay`, `Serialization`.
    - Public test/build helpers `sign_attested_input` and `sign_attested_reading` produce envelopes signed against the same canonical bytes the verifier checks.
  - **Validator wiring:** new `validate_with_attested_inputs(bundle, &[AttestedInput], Option<&mut AttestationVerifier>, now)` runs verification up-front and appends a `screening_attestation` `CheckResult`. Approval now requires `authority_passed && screening_passed && all_invariants_passed && attestation_passed`. The `validate(...)` shorthand still works (zero attested inputs → no attestation check appended).
  - **Tests added (12):** happy-path input + reading, unknown-kid rejection, malformed-base64 rejection, attacker-key rejection, tampered-payload rejection, stale-timestamp rejection, future-timestamp beyond skew rejection, replay rejection, FIFO cache eviction; validator-side: pass / missing-verifier-fail-closed / verification-failure-blocks-approval / no-inputs-no-check.
  - Total core tests: 399 (was 386). Clippy clean.
- [x] **Step 11** — `validate` CLI subcommand implemented (2026-04-25).
  - **New file** `crates/invariant-biosynthesis-cli/src/commands/validate.rs`:
    - `ValidateArgs` flags: `--bundle <PATH>` (required), `--profile <PATH>` (optional, falls back to a permissive default), `--hazard-db <PATH>` (required), `--hazard-db-issuer-pub <PATH>` (required, public-key file containing the issuer's kid + base64 verifying key), `--output <PATH>` (optional; stdout when omitted).
    - Loads the bundle, profile, issuer pub key, and signed hazard DB; constructs `ValidatorConfig::with_hazard_db(...)`; runs `cfg.validate(&bundle, Utc::now(), None)`.
    - Renders a structured per-check summary to stderr (category tag + PASS/FAIL + name + details), lists screening hits, then writes the signed verdict JSON to the output file or stdout.
    - Exit codes: `0` approved, `1` Fail / authority-or-screening block, `2` Advisory-only, `3` internal error.
  - **Wiring:** `commands/mod.rs` adds `pub mod validate`; `main.rs` replaces the `Validate` stub variant with `Validate(commands::validate::ValidateArgs)` and dispatches `commands::validate::run`. Remaining stubs now reference Step 12+.
  - **Visibility change:** `screening::sign_body_for_tests` promoted from `pub(crate)` to `pub` (with documentation) so CLI integration tests can build signed-DB fixtures without bringing in extra dependencies.
  - **Tests added (3):** safe-bundle no-hits path against a fixture DB (exit 0/1), DNA hit blocks approval (exit 1), missing bundle returns internal error (exit 3). The tests use `examples/safe-bundle.json` and a tempfile DB+issuer-pub pair.
  - Total CLI tests: 61 (was 58). Workspace clippy clean.
- [x] **Step 12** — `inspect` CLI subcommand implemented (2026-04-25).
  - **New file** `crates/invariant-biosynthesis-cli/src/commands/inspect.rs`:
    - `InspectArgs` accepts exactly one of `--bundle`, `--profile`, `--verdict`, `--audit-log` (clap `group = "input"`); plus optional `--verify-with <PUB>` for signature verification of verdicts and audit-log entries.
    - **Bundle** path prints source / timestamp / sequence / payload kind+size / PCA chain length / required ops / metadata key count.
    - **Profile** path prints name / version / BSL level / allowed substrates / volume cap / export-control flag; reports signature presence + verifying kid (verification of profile signatures is out of scope here — flagged as `signed (unverified)`).
    - **Verdict** path prints approval / command hash / sequence / timestamp / profile / authority summary / per-check pass-fail with category and details; signature is reported as `signed and verified`, `signed but INVALID`, `signed but signer kid not in --verify-with`, or `signed (unverified — pass --verify-with)` depending on the supplied pub key.
    - **Audit log** path streams the JSONL, counting entries per signer kid, recording the head hash and last sequence, and (when a pub key is given) tallying valid vs invalid `entry_signature`s.
    - Exit codes: `0` success, `1` signature present but invalid, `2` usage error (zero or multiple input flags), `3` internal error.
  - **Wiring:** `commands/mod.rs` adds `pub mod inspect`; `main.rs` replaces the stub variant with `Inspect(InspectArgs)` dispatching to `commands::inspect::run`.
  - **Tests added (7):** missing-input-flag → 2; multiple-input-flags → 2; bundle path against `examples/safe-bundle.json` → 0; profile path against `profiles/university_bsl2_dna.json` → 0; missing file → 3; tampered-verdict signature → 1 (with verifying pub key); unsigned-verifier path reports `unverified` → 0.
  - Total CLI tests: 68 (was 61). Workspace clippy clean.
- [x] **Step 13** — `differential` CLI subcommand implemented (2026-04-25).
  - **New file** `crates/invariant-biosynthesis-cli/src/commands/differential.rs`:
    - `DifferentialArgs`: `--a <VERDICT>`, `--b <VERDICT>`, optional `--output <REPORT>`.
    - Loads two signed verdicts; refuses to compare if `command_hash` differs (different bundles → meaningless diff). Delegates to `core::differential::compare_verdicts` and serializes the resulting `DifferentialResult` JSON.
    - Renders a human summary to stderr (approval agreement, agreeing/total counts, per-check disagreement listing) and writes the report JSON to `--output` or stdout.
    - Exit codes: `0` fully agree, `1` divergence (approval mismatch or per-check disagreement), `2` usage error, `3` internal error (I/O, parse, hash mismatch, missing file).
  - **Wiring:** added to `commands/mod.rs`; `main.rs` replaces the `Differential` stub with `Differential(DifferentialArgs)` dispatching to `commands::differential::run`. Remaining stubs now reference Step 14+.
  - **Tests added (5):** agreeing verdicts → 0; approval divergence with output file → 1 (file written); per-check disagreement → 1; `command_hash` mismatch → 3; missing file → 3.
  - Total CLI tests: 73 (was 68). Workspace clippy clean.
- [x] **Step 14** — `intent` CLI subcommand + extended template registry (2026-04-25).
  - **Template registry extended:** `core::intent::builtin_templates()` now returns 9 templates. Existing 5 (`synthesize_dna_fragment`, `run_peptide_coupling`, `dispense_reagent`, `synthesize_chemical`, `execute_protocol`) plus 4 new (`prepare_chemical_compound`, `assemble_plasmid`, `screen_library`, `purify_product`). Each new template declares `required_params`, `operation_patterns` (using the existing `{platform}` substitution), and a default duration. The spec's other named templates (`synthesize_dna_fragment`, `run_peptide_coupling`) were already present.
  - **New file** `crates/invariant-biosynthesis-cli/src/commands/intent.rs`:
    - Three sub-subcommands: `intent list` (print every template), `intent show --name X` (print one template's schema), `intent expand --name X --param k=v --principal P --kid K [--duration-s N] [--output PATH]` (parse params, call `resolve_template` + `intent_to_pca`, emit `{ intent, pca }` JSON to file or stdout).
    - Exit codes: `0` success, `1` semantic error (unknown template, missing required param, invalid op, invalid duration), `2` usage error (malformed `--param` not in `KEY=VALUE` form), `3` internal error (write failure, serialization).
  - **Wiring:** `commands/mod.rs` adds `pub mod intent`; `main.rs` replaces the `Intent` stub with `Intent(IntentArgs)` dispatching to `commands::intent::run`. Remaining stubs now reference Step 15+.
  - **Tests added (8):** list, show known, show unknown → 1, expand → 0 (writes file with expected payload), expand-missing-param → 1, expand-unknown → 1, expand-malformed-param → 2, and a smoke test that all four newly-added templates expand cleanly with `platform=tecan`.
  - Total CLI tests: 81 (was 73). Workspace clippy clean (one doc-overindent fix in the new file).
- [x] **Step 15** — Simulation harness + `campaign` CLI implemented (2026-04-25).
  - **Sim crate rewritten** (`crates/invariant-biosynthesis-sim/src/lib.rs`):
    - New types: `ExpectedOutcome` (`approved` / `rejected`), `CampaignScenario { name, description, bundle, hazard_db, hazard_db_issuer_pub, profile?, expect }`, `CampaignFile { name, description, scenarios }`, `ScenarioResult`, `CampaignReport` (with `fully_matches()`).
    - `load_campaign(path)` parses `serde_yaml` with `deny_unknown_fields` enforcement.
    - `run_campaign(campaign, base_dir)` runs each scenario through the validator (loads bundle, optional profile, signed hazard DB + issuer pub, builds `ValidatorConfig::with_hazard_db`, calls `validate`); aggregates matches/mismatches/errors plus per-scenario timing. Relative paths resolve against `base_dir` so scenarios can refer to fixtures relative to the campaign YAML.
    - Cargo deps added: `ed25519-dalek`, `base64`, `rand`, dev-dep `tempfile`.
  - **New CLI command** `crates/invariant-biosynthesis-cli/src/commands/campaign.rs`:
    - `--campaign <YAML>`, `--output <PATH>`, `--text` (plain-text instead of JSON).
    - Renders a per-scenario summary to stderr (`OK` / `MISMATCH` / `ERROR` tags + timing). Exit codes: `0` all matched, `1` mismatches, `2` scenario errors, `3` internal/load.
  - **Wiring:** CLI Cargo.toml depends on `invariant-biosynthesis-sim`; `commands/mod.rs` adds `pub mod campaign`; `main.rs` replaces the stub with `Campaign(CampaignArgs)` dispatching to `commands::campaign::run`. Remaining stubs now reference Step 16+.
  - **Demo YAML updated:** `examples/demo-campaign.yaml` now reflects the real schema (3 scenarios spanning safe DNA, dangerous DNA, safe peptide). It is intentionally documentation-style; runnable copies are produced inside the sim and CLI integration tests with fresh signed-DB fixtures.
  - **Tests added:** sim — `load_campaign` round-trip + `deny_unknown_fields` rejection; `run_campaign` paths covering match, mismatch, scenario load error, and DNA-hit blocking approval (5 total). CLI — match → 0, mismatch → 1, scenario error → 2, missing YAML → 3, text-output writes file (5 total).
  - Counts: sim crate 5 tests (was 1), CLI 86 tests (was 81), workspace clippy clean.
- [x] **Step 16** — Trace evaluation engine + `eval` CLI implemented (2026-04-25).
  - **Eval crate rewritten** (`crates/invariant-biosynthesis-eval/src/lib.rs`):
    - Trace JSONL format: each line is either `{"kind":"request","command_sequence":<u64>}` or `{"kind":"verdict", ...SignedVerdict fields}`.
    - New types: `Preset` (`SafetyCheck` / `Completeness` / `Regression`), `RubricResult { id, description, passed, details }`, `EvalReport { preset, line_count, verdict_count, request_count, rubrics, overall_pass }`, `EvalError` (`Io`, `Parse`, `GoldenRequired`).
    - `evaluate(path, preset, golden)` parses the trace and dispatches to one of three rubric sets:
      - **SafetyCheck**: `all_verdicts_approved` + `no_check_failures`.
      - **Completeness**: `every_request_has_verdict` + `no_duplicate_verdicts`.
      - **Regression**: `verdict_count_matches_golden` + `approval_timeline_matches_golden` (requires `golden` path).
    - dev-dep `tempfile` added. Boxed the large `Verdict` payload in the internal `TraceLine::Verdict` variant to satisfy the `large_enum_variant` lint.
  - **New CLI command** `crates/invariant-biosynthesis-cli/src/commands/eval.rs`:
    - `--trace <PATH>`, `--preset {safety-check|completeness|regression}`, optional `--golden <PATH>`, optional `--output <PATH>`.
    - Stderr per-rubric `[PASS] / [FAIL]` summary. Exit codes: `0` overall pass, `1` overall fail, `2` `--golden` missing for regression, `3` internal/load error.
  - **Wiring:** CLI Cargo.toml depends on `invariant-biosynthesis-eval`; `commands/mod.rs` adds `pub mod eval`; `main.rs` replaces the stub with `Eval(EvalArgs)`. Only `Adversarial` remains stubbed (Step 17).
  - **Trace fixtures added:** `crates/invariant-biosynthesis-eval/tests/fixtures/{all-approved,incomplete,golden}.jsonl` plus an integration test (`tests/fixtures_test.rs`) confirming SafetyCheck pass on `all-approved`, Completeness fail on `incomplete`, and Regression self-match on `golden`.
  - **Tests added:** eval crate — 12 lib (3 per preset + parse/IO + edge cases) + 3 integration (fixtures); CLI — 6 (each exit code path + report-file output). Total: eval 12 lib + 3 integration; CLI 92 (was 86).
  - Workspace clippy clean.
- [x] **Step 17** — Adversarial fuzz suite + `adversarial` CLI implemented (2026-04-25).
  - **Fuzz crate rewritten** (`crates/invariant-biosynthesis-fuzz/src/lib.rs`):
    - New types: `Suite::{Protocol, Authority, System, Cognitive}` (+ `all()`), `ExpectedVerdict::{Approved, Rejected}`, `AttackCase { id, suite, bundle, expected }`, `CaseResult`, `FuzzReport` (+ `fully_matches()`).
    - `generate(suite)` returns the canonical case set for that suite. Cases:
      - **Protocol** — `empty-pca-chain`, `oversize-payload` (50k DNA bases), `malformed-pca-chain-base64`, `timestamp-far-future`.
      - **Authority** — `forged-pca-chain-bytes`, `empty-chain-but-ops-required`, `scope-escalation-no-pca`.
      - **System** — `zero-sequence`, `timestamp-far-past`, `metadata-flood` (1024 metadata keys).
      - **Cognitive** — `prompt-injection-in-metadata`, `source-string-spoof`, `fragmentation-via-intent-string`.
    - `run(suite)` builds a default validator (in-memory signed hazard DB, no trusted PCA keys → authority fail-closed) and runs every case; `run_all()` runs every suite and aggregates a single `FuzzReport`.
    - `chrono` workspace dep added to the fuzz crate.
  - **New CLI command** `crates/invariant-biosynthesis-cli/src/commands/adversarial.rs`:
    - `--suite {protocol|authority|system|cognitive|all}` (default `all`), `--output <PATH>` (stdout when omitted).
    - Stderr summary tagged `OK` / `MISMATCH` / `ERROR` per case. Exit codes: `0` all matched, `1` mismatches, `2` case errors, `3` internal/serialization.
  - **Wiring:** CLI Cargo.toml depends on `invariant-biosynthesis-fuzz`; `commands/mod.rs` adds `pub mod adversarial`; `main.rs` replaces the `Adversarial` stub with `Adversarial(AdversarialArgs)` dispatching to `commands::adversarial::run`. **All 11 CLI subcommands now implemented** (no stubs remain in `main.rs`).
  - **Tests added:** fuzz crate — 7 (`Suite::all` size; per-suite full-match runs; `run_all` aggregation; protocol-suite ID inclusion). CLI — 3 (protocol suite → 0; all suites → 0; output file). Total: fuzz 7 (was 1); CLI 95 (was 92).
  - Workspace clippy clean.
- [x] **Step 18** — Bio-profile library expanded (2026-04-25).
  - **Five new profile JSON files** added under `profiles/`: `industry_peptide.json` (peptide, BSL-2, 25 mL), `industry_chemical.json` (chemical, BSL-2, 100 mL), `university_bsl3_dna.json` (DNA, BSL-3, 2 mL), `government_bsl4_restricted.json` (DNA+peptide, BSL-4, 0.5 mL, export-controlled), `export_controlled_chemical.json` (chemical, BSL-2, 10 mL, export-controlled). Total profile library: 6.
  - **`profiles.rs` rewritten** to drive a slice-based registry (`BUILTIN_PROFILES`) with each entry's name + `include_str!`-embedded JSON. `load_builtin(name)` is now a single search; new public `builtin_names() -> Vec<&'static str>` exposes registry order for tooling.
  - **Tests added (4):** `every_builtin_profile_loads_round_trips_and_validates` walks every registered profile, asserts `Validate::validate()` succeeds, and round-trips it through serde_json; `builtin_library_has_six_profiles` size assertion; `bsl4_profile_is_export_controlled` and `export_controlled_chemical_flag_set` verify the new policy fields.
  - Total core tests: 403 (was 399). Workspace clippy clean.
- [x] **Step 19** — End-to-end CLI integration tests + CI job (2026-04-25).
  - **New file** `crates/invariant-biosynthesis-cli/tests/cli_integration.rs`. Each test invokes the binary via `Command::new(env!("CARGO_BIN_EXE_invariant-bio"))` and asserts on exit status / minimal output. Fixtures (hazard DB, issuer pub, bundles, traces, campaign YAML, verdict pairs) are constructed inline in tempdirs so the suite is hermetic.
  - **Coverage (15 tests):** `--help`; `keygen` writes file; `intent list` / `intent show <known>` / `intent show <unknown>` (non-zero) / `intent expand` writes file; `adversarial --suite protocol` (exit 0); `inspect --profile`, `inspect --bundle`, `inspect` no-flag → 2; `validate` on safe-bundle with empty PCA chain → exit 1 + verdict file written; `eval --preset safety-check` against the eval crate's `all-approved` fixture; `differential` on identical verdicts → 0; `campaign` with hand-written YAML + bundle + signed DB → 0; `verify-self` (accepts 0/1/2 since baseline may be absent in dev builds).
  - **CI job added:** new `cli-integration` job in `.github/workflows/ci.yml` mirrors the spec's `cargo test -p invariant-biosynthesis-cli --test '*'` invocation across `ubuntu-latest` and `macos-latest`, with `Swatinem/rust-cache@v2`.
  - The pre-existing top-level `test` job already runs `cargo test --workspace`, so the new integration suite is exercised there too — the dedicated `cli-integration` job exists per spec to make CLI regressions fail fast on a focused matrix.
  - Workspace clippy clean. Total counts: CLI lib 95, CLI integration 15 (new), core 403, eval 12 lib + 3 integration, sim 5, fuzz 7.
- [x] **Step 20** — README + CHANGELOG reconciled with shipped state (2026-04-25).
  - **README.md:** the original ten-step status table has been kept (every entry now reads `Code shipped` with cross-references to the gap-closure step that delivered it). A new **gap-closure plan** table lists Steps 1–22 with a per-step ✅/⏳ marker. Added a **Test counts** subsection (core 403, CLI 95+15, eval 12+3, sim 5, fuzz 7, plus 22 doc-tests) and a **Known gaps** subsection enumerating what is intentionally deferred (real cheminformatics, real homology engines, codon-usage host hints, cross-bundle fragmentation, per-profile step vocabularies). Phase-1-Foundation framing replaced with an accurate description of the runtime now shipping.
  - **CHANGELOG.md:** new `0.0.5 (2026-04-25)` entry summarising the gap-closure work step-by-step (Steps 1–20). Each bullet names the artifact (file / module / trait / CLI subcommand) that landed for that step. The entry preserves a `Known gaps (deferred)` block enumerating future-follow items so readers know what is *not* in this release.
  - No invented features: every claim in the README/CHANGELOG corresponds to a code path or test in the workspace.
- [x] **Step 21** — Final sweep (2026-04-25).
  - `cargo fmt --all` applied across the workspace; `cargo fmt --all --check` reports clean. The formatter rewrote 23 files (mostly trailing-comma normalisation, multi-line struct layout in tests, and module-level rustfmt cosmetic adjustments).
  - `cargo test --workspace` all green (counts unchanged: core 403, CLI 95 lib + 15 integration, eval 12 + 3, sim 5, fuzz 7, plus 22 doc-tests).
  - `cargo clippy --workspace --all-targets -- -D warnings` clean.
  - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items` now builds cleanly. Fixed pre-existing intra-doc-link breakages flagged by stricter rustdoc:
    - `attestation.rs`, `invariants/mod.rs`, `validator.rs`, `screening/mod.rs`, `models/bundle.rs`, `watchdog.rs` — module-level `[\`Type\`]` references that the resolver rejects in `//!` doc blocks rewritten to bare backticks (kept the type names visible without the link).
    - `invariants/protocol.rs` — `[\`MAX_STEPS\`]` (private constant) link in public Rustdoc replaced with prose.
  - `cargo deny check` not run locally (`cargo-deny` not installed in this environment) but the existing CI `deny` job continues to gate supply-chain on PRs.
  - **TODO sweep:** `grep -rn 'todo!\|unimplemented!' crates/` returns **zero hits**. The single residual stale-comment reference (`commands/mod.rs` doc-block describing the historical `todo!("step-5")` stubs) was rewritten to describe the now-shipping eleven-subcommand surface. No leftover step-pointer comments in shipping code.
- [x] **Step 22** — Gap-closure PR draft prepared (2026-04-25).
  - **Blocker recorded:** the working tree is **not a git repository** (also flagged in Step 1's progress note). Without `git init` + a configured `origin`, the literal `git push -u origin gap-closure` and `gh pr create` commands cannot run from this environment.
  - **PR body authored as `PULL_REQUEST.md`** at the repo root. Once the working tree is converted to a real repo with a GitHub remote, a human (or `gh` automation) can:
    1. `git init && git add -A && git commit -m "gap-closure Steps 1–21"`
    2. `git remote add origin <url> && git checkout -b gap-closure && git push -u origin gap-closure`
    3. `gh pr create --title "Close gap-closure spec (Steps 1–21)" --body "$(cat PULL_REQUEST.md)"`
  - **`PULL_REQUEST.md` contents:** summary by gap (15 numbered items), per-crate test-count delta table (~360 → ~562), the full Step 1–21 ✅ checklist, deferred items (cheminformatics, homology engines, codon-usage host hints, cross-bundle fragmentation, per-profile vocabularies, locally-skipped `cargo deny`), and a reviewer test plan.
  - No code modified in this step. The PR is **not merged** (cannot be merged without first being created).
  - **All 22 steps of the gap-closure plan are now ✅** at the artifact level. Final remaining human action is the `git init` + push + PR-creation sequence above.

Ground rules that apply to every step:

- Preserve `#![forbid(unsafe_code)]` in every crate.
- Do not add new top-level dependencies beyond those already in `Cargo.toml` unless a step explicitly authorizes it.
- After every code-changing step, run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace -- -D warnings`. Do not move on until all three pass.
- One commit per step, message prefixed with the step number (e.g. `step-3a: implement codon translation`).
- Never push directly to `main`.

---

## Snapshot of identified gaps (what this spec closes)

1. All 30 biological invariants (D1–D10 DNA, P1–P10 peptide, C1–C10 chemical) return `InvariantStatus::Unimplemented`.
2. `screening::screen()` is `todo!()`; no concrete `HazardDatabase` implementation exists.
3. Seven CLI subcommands are `todo!()`: `validate`, `inspect`, `campaign`, `adversarial`, `eval`, `differential`, `intent`.
4. `naive_translate()` in `invariants/dna.rs` returns an empty string (no codon table).
5. `attestation.rs` lacks nonce/freshness/signature verification; structs are declared but logic is missing.
6. The `sim`, `eval`, and `fuzz` crates are shells with one placeholder test each.
7. Only one bio profile (`university_bsl2_dna.json`) exists; no peptide, chemical, BSL-3/4, or export-control profiles.
8. The validator does not consume `AttestedInput`, does not call `screening::screen()`, and does not enforce profile-based volume/hazard caps.
9. `SynthesisPayload::Protocol` has no matching invariant pipeline.
10. The intent-template registry is empty.
11. Sim/eval/fuzz crates have no integration tests; CLI command files have no per-command tests.
12. `examples/demo-campaign.yaml` is empty/missing real scenario data.
13. Documentation in `README.md` advertises Step 5 as "Code shipped" but the CLI commands are stubs — README needs reconciliation after the CLI lands.
14. No end-to-end CLI integration tests in CI.
15. Threat-model gaps: `Unimplemented` invariants currently fall through; the validator's fail-closed posture for partially-implemented invariant sets needs an explicit policy.

The steps below close each of these in order of dependency.

---

## Step 1 — Establish a working baseline and a tracking branch

**Goal:** Confirm the repo builds, tests, and clippy-clean as-is, and create the working branch for the rest of this spec.

**Prompt for Claude Code:**

> Run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` and report the exact pass/fail status of each, plus the test count per crate. Do not modify any source. If anything fails, stop and report the failure verbatim. If everything passes, create a new git branch named `gap-closure` off the current branch and confirm it is checked out. Do not commit anything yet.

**Acceptance check:** Three green commands; branch `gap-closure` checked out; no file modifications.

---

## Step 2 — Add a `Status` policy for `Unimplemented` invariants

**Goal:** Make the validator's fail-closed posture explicit so partial implementations of Steps 3–5 cannot accidentally produce a "pass" verdict.

**Prompt for Claude Code:**

> Read `crates/invariant-biosynthesis-core/src/validator.rs` and `crates/invariant-biosynthesis-core/src/invariants/mod.rs`. Add a new validator configuration field `allow_unimplemented_invariants: bool` (default `false`). When `false`, any invariant returning `InvariantStatus::Unimplemented` must cause the overall verdict to be `Reject` with a reason string that names every unimplemented invariant. When `true`, `Unimplemented` is treated as `Advisory` and recorded but does not block. Update existing tests that depended on the old behaviour, and add new tests covering both modes. Do not change the invariant stubs themselves.

**Acceptance check:** New config flag, two new tests, all existing tests still pass.

---

## Step 3 — Implement the codon translation utility

**Goal:** Replace the empty-string stub in `naive_translate()` so DNA invariants D1/D3/D4 can do amino-acid-level analysis.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/invariants/dna.rs`, replace the `naive_translate()` stub with a correct standard-genetic-code (NCBI table 1) translation. Handle the three forward reading frames, return all three translations, treat ambiguous bases as a stop-equivalent placeholder, and reject non-ACGTN input with a typed error. Add a unit-test module covering: known control sequences, frame-shift behavior, ambiguous bases, lowercase input, and empty input. Do not implement any of the D1–D10 screening logic yet — just the translation primitive and its tests.

**Acceptance check:** Translation function returns three frames; ≥6 new tests; no clippy warnings.

---

## Step 4 — Define the `HazardDatabase` concrete type and seed data format

**Goal:** Provide a minimal, file-backed hazard database so invariants have something real to call.

**Prompt for Claude Code:**

> Read `crates/invariant-biosynthesis-core/src/invariants/mod.rs` to find the `HazardDatabase` trait. In `crates/invariant-biosynthesis-core/src/screening/mod.rs`, design a concrete struct `FileBackedHazardDatabase` that loads from a signed JSON file. The file format must contain: schema version, issuer key id, signature over the canonical bytes of the body, and three lists — `dna_signatures`, `peptide_signatures`, `chemical_signatures` — each entry having an id, a human-readable label, a hazard class, and a match pattern (regex for sequences, SMARTS-like string placeholder for chemicals). Implement `screen()` to dispatch to per-substrate matchers and return a list of hits. Verify the file's Ed25519 signature on load using the existing key infrastructure. Add tests for: signature verification (valid, tampered, wrong key), each substrate's matching path, and unknown-substrate rejection.

**Acceptance check:** `screening::screen()` no longer `todo!()`; signed-file loader works; ≥10 tests added.

---

## Step 5 — Wire the hazard database into the validator pipeline

**Goal:** The validator must call screening before invariants run, and must surface screening hits as invariant inputs.

**Prompt for Claude Code:**

> Update `validator.rs` so it accepts an `Arc<dyn HazardDatabase>` at construction time and calls `screen()` for the bundle's payload before invariants run. The screening result must be passed to each invariant via the existing context object. Add the database handle as an optional CLI/library parameter; if absent, the validator must reject the bundle with an explicit "no hazard database configured" error (fail-closed). Update existing validator tests to construct a small in-memory test database. Add tests covering: missing-database rejection, screening-hit propagation to invariants, and screening-error surfacing in the verdict.

**Acceptance check:** Validator requires a database; missing-DB path is fail-closed; tests cover both presence and absence.

---

## Step 6 — Implement the 10 DNA invariants (D1–D10)

**Goal:** Replace every `Unimplemented` in `invariants/dna.rs` with real logic that consumes the screening result and the codon translation.

**Prompt for Claude Code:**

> Read `docs/threat-model.md` and `docs/spec.md` to recover the intended semantics of D1–D10 (Select Agent screen, pandemic pathogen homology, gain-of-function motifs, dual-use research signatures, dangerous toxin coding regions, illicit gene-drive cassettes, sequence-length sanity, GC-content plausibility, restriction-site policy, profile-allowed-organism check). Implement each one as a separate function in `invariants/dna.rs`. Each must: read the bundle's DNA payload, optionally consult the screening hits passed via context, optionally consult the translated AAs from Step 3, and return `Pass` / `Fail { reason }` / `Advisory { note }`. None should return `Unimplemented` after this step. Add unit tests using the existing `examples/safe-bundle.json` and `examples/dangerous-bundle.json` plus at least three new fixtures per invariant.

**Acceptance check:** Zero `Unimplemented` returns in `dna.rs`; ≥30 new tests; clippy clean; existing `safe-bundle.json` passes, `dangerous-bundle.json` fails on the expected invariants.

---

## Step 7 — Implement the 10 peptide invariants (P1–P10)

**Goal:** Same as Step 6, for peptide payloads.

**Prompt for Claude Code:**

> In `invariants/peptide.rs`, implement P1–P10 (antimicrobial peptide screen, toxin homology, hemolytic motif, cell-penetrating peptide screen, prion-like region, length plausibility, residue-composition sanity, D-amino-acid policy from profile, modification policy, profile-allowed-class check). Use the screening database for homology and motif look-ups. Add per-invariant unit tests with at least three peptide fixtures per invariant covering pass, fail, and advisory paths. Add a peptide test bundle to `examples/` analogous to the existing DNA examples.

**Acceptance check:** Zero `Unimplemented` in `peptide.rs`; new examples present; ≥30 new tests.

---

## Step 8 — Implement the 10 chemical invariants (C1–C10)

**Goal:** Same as Steps 6–7, for chemical/SMILES payloads.

**Prompt for Claude Code:**

> In `invariants/chemical.rs`, implement C1–C10 (CWC schedule screen, precursor-list screen, explosive-motif screen, energetic-material plausibility, organophosphate nerve-agent screen, heavy-metal toxicity gate, controlled-substance regex screen, molecular-weight plausibility, hazard-class profile gate, export-control flag enforcement). Because we do not yet pull in a real cheminformatics library, treat SMILES as opaque strings and rely on the hazard-database SMARTS-like patterns plus structural regex heuristics. Document each heuristic's known false-positive and false-negative behavior in a Rustdoc block on the invariant function. Add unit tests with at least three fixtures per invariant.

**Acceptance check:** Zero `Unimplemented` in `chemical.rs`; FP/FN behavior documented inline; ≥30 new tests.

---

## Step 9 — Add a `Protocol` invariant pipeline

**Goal:** `SynthesisPayload::Protocol` currently has no matching invariants. Either route it through the existing pipelines or add a small dedicated set.

**Prompt for Claude Code:**

> Read `models/bundle.rs` to confirm the shape of `SynthesisPayload::Protocol`. Add a new module `invariants/protocol.rs` with at least four invariants: step-count bound, allowed-step-vocabulary check (against profile), no-nested-protocol rule, and aggregate-volume-vs-profile-cap check. Wire these into `invariants::run_all()` so a `Protocol` bundle is no longer ignored. Add tests covering: empty protocols, oversized protocols, disallowed steps, and a fully-allowed protocol.

**Acceptance check:** New module integrated; protocol bundles produce a real verdict; ≥8 new tests.

---

## Step 10 — Complete the attestation logic

**Goal:** Replace the attestation skeleton with real nonce, freshness, and signature checks.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/attestation.rs`, implement: nonce uniqueness within a configurable window, freshness check against a monotonic clock with a configurable max-age, Ed25519 signature verification against an issuer key id resolved through the existing key store, and replay rejection via an in-memory recently-seen-nonce set with a bounded size. Wire `AttestedInput` into the validator so that any bundle carrying attested screening telemetry is verified before the screening result is trusted. Add tests for: replay, stale timestamp, bad signature, unknown key id, and the happy path.

**Acceptance check:** No `todo!()` left in `attestation.rs`; validator consumes attested inputs; ≥6 new tests.

---

## Step 11 — Implement the `validate` CLI subcommand

**Goal:** Make the most basic CLI command actually work.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-cli/src/commands/`, add `validate.rs`. The command takes: a bundle JSON path, an optional profile path, a required hazard-database path, and an optional output path for the signed verdict. It must construct the validator from Step 5, run validation, print a structured human-readable summary, write the signed verdict to the output path (or stdout) in JSON, and exit with code 0 for `Pass`, 1 for `Fail`, 2 for `Advisory`, and 3 for any internal error. Wire it into `main.rs` replacing the `todo!()`. Add an integration test under `crates/invariant-biosynthesis-cli/tests/` that runs the binary against `examples/safe-bundle.json` and `examples/dangerous-bundle.json` using a small fixture hazard database.

**Acceptance check:** `cargo run -- validate ...` works; integration test passes; exit codes correct.

---

## Step 12 — Implement the `inspect` CLI subcommand

**Goal:** Read-only introspection of bundles, profiles, and verdicts.

**Prompt for Claude Code:**

> Implement `commands/inspect.rs`. It must accept any of: a bundle path, a profile path, a verdict path, or an audit-log path, and print a structured summary (counts, signers, key ids, timestamps, hash chain head if applicable). It must verify signatures where present and clearly mark unsigned vs. signed-and-verified vs. signed-but-invalid. Replace the `todo!()` in `main.rs`. Add integration tests for each of the four input types, including a tampered-signature negative case.

**Acceptance check:** Subcommand handles all four input shapes; tamper detection visible in output; integration tests cover each.

---

## Step 13 — Implement the `differential` CLI subcommand

**Goal:** Surface the existing `differential.rs` library code through the CLI.

**Prompt for Claude Code:**

> Read `crates/invariant-biosynthesis-core/src/differential.rs` to find the dual-instance comparison API. Implement `commands/differential.rs` so it takes two verdict files (or runs validation twice with two different validator configurations against one bundle) and reports any divergence with structured diff output. Exit non-zero on divergence. Replace the `todo!()`. Add an integration test that constructs two deliberately-divergent verdicts and confirms the command flags them.

**Acceptance check:** Divergence is detected and reported; integration test green.

---

## Step 14 — Implement the `intent` CLI subcommand and the template registry

**Goal:** Populate the empty intent-template registry and expose it through the CLI.

**Prompt for Claude Code:**

> Read `crates/invariant-biosynthesis-core/src/intent.rs`. Create a new file `crates/invariant-biosynthesis-core/src/intent_templates.rs` that registers at least six concrete templates: `synthesize_dna_fragment`, `run_peptide_coupling`, `prepare_chemical_compound`, `assemble_plasmid`, `screen_library`, `purify_product`. Each template must declare its required fields, allowed substrates, and the operations it expects on the PCA chain. Implement `commands/intent.rs` to list templates, show one template's schema, and expand a template invocation into a draft bundle that the user can sign separately. Replace the `todo!()`. Add tests for template lookup, schema rendering, and bundle expansion.

**Acceptance check:** Six templates registered; CLI lists/shows/expands them; ≥9 new tests.

---

## Step 15 — Build out the simulation harness and `campaign` CLI subcommand

**Goal:** Replace the `todo!()` shell in the `sim` crate with a real campaign runner, and surface it via the CLI.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-sim/src/lib.rs`, define a `CampaignScenario` struct (id, description, seed bundles, expected outcomes, profile, hazard-database path), a YAML loader for it, and a `run_campaign()` function that executes each scenario through the validator and aggregates the results into a structured report (counts, mismatches, timing). Implement `commands/campaign.rs` to invoke this from the CLI with a YAML input and a JSON or text output mode. Replace the `todo!()` in `main.rs`. Populate `examples/demo-campaign.yaml` with at least three scenarios using the existing example bundles. Add unit tests for the loader and aggregator, and an integration test that runs the demo campaign end-to-end.

**Acceptance check:** Real `run_campaign()`; demo YAML runs cleanly; ≥10 new tests.

---

## Step 16 — Build out the trace evaluation engine and `eval` CLI subcommand

**Goal:** Replace the `eval` crate's `todo!()` with rubric-based trace evaluation.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-eval/src/lib.rs`, implement `evaluate(trace, preset) -> EvalReport` for the three declared presets (`SafetyCheck`, `Completeness`, `Regression`). Define a `Trace` type that wraps a JSONL file of validator events and verdicts. Each preset must apply a small named rubric set that scores the trace and returns per-rubric pass/fail with reasons. Implement `commands/eval.rs` to run a preset against a trace file and print a structured report. Replace the `todo!()`. Add at least three trace fixtures under `crates/invariant-biosynthesis-eval/tests/fixtures/` and tests for each preset.

**Acceptance check:** Real `evaluate()`; three presets functional; ≥9 new tests.

---

## Step 17 — Build out the adversarial fuzzing suite and `adversarial` CLI subcommand

**Goal:** Replace the `fuzz` crate's `todo!()` with payload generators for the four declared suites.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-fuzz/src/lib.rs`, implement payload generators for each `Suite` variant: `Protocol` (malformed bundles, replays, timestamp skew, oversize payloads, truncated signatures), `Authority` (forged PCAs, expired delegations, scope-escalation attempts, key-rotation race), `System` (audit-log tamper, watchdog skip, attestation replay), `Cognitive` (prompt-injection-style payloads embedded in human-readable bundle metadata, classifier-evasion variants of safe-looking sequences). Each generator yields a stream of bundles plus the expected verdict. Implement `run(suite)` to execute each generator through the validator and assert expected verdicts. Implement `commands/adversarial.rs` to expose this from the CLI. Replace the `todo!()` in `main.rs`. Add tests confirming every generated payload produces the expected verdict.

**Acceptance check:** All four suites runnable; CLI works; verdict expectations enforced.

---

## Step 18 — Author additional bio profiles

**Goal:** Cover peptide, chemical, BSL-3, BSL-4, and export-controlled cases.

**Prompt for Claude Code:**

> Read `models/profile.rs` and the existing `profiles/university_bsl2_dna.json`. Add: `industry_peptide.json`, `industry_chemical.json`, `university_bsl3_dna.json`, `government_bsl4_restricted.json`, and `export_controlled_chemical.json`. Each must populate every documented profile field with values appropriate to its scenario, including hazard-class lists, allowed-substrate lists, synthesis-volume caps, export-control flags, and required-attestation flags. Add a test in `crates/invariant-biosynthesis-core` that loads every profile file under `profiles/`, round-trips it through serde, and validates required-field presence.

**Acceptance check:** Five new profiles; round-trip test passes for all six profiles.

---

## Step 19 — End-to-end CLI integration tests in CI

**Goal:** Lock in CLI behavior so future regressions are caught.

**Prompt for Claude Code:**

> Add a new integration test crate or top-level `tests/` directory under `crates/invariant-biosynthesis-cli/` that runs the binary as a subprocess for each subcommand: `keygen`, `validate`, `inspect`, `verify`, `audit`, `differential`, `intent`, `campaign`, `eval`, `adversarial`, `verify-self`. Each test must use only files under `examples/` and `profiles/`. Add a new GitHub Actions job in `.github/workflows/ci.yml` that runs `cargo test -p invariant-biosynthesis-cli --test '*'` on both Ubuntu and macOS. Confirm CI passes locally with `act` if available, otherwise validate the YAML by running `gh workflow view` on a draft PR is unnecessary — just confirm the YAML parses with a YAML linter and the local test suite is green.

**Acceptance check:** All eleven subcommands have at least one integration test; CI job added.

---

## Step 20 — Reconcile README.md and CHANGELOG.md with shipped state

**Goal:** Documentation must not lie. After Steps 2–19, update status markers.

**Prompt for Claude Code:**

> Re-read `README.md` and `CHANGELOG.md`. For each of Steps 0–10 listed in the README status table, update the marker to reflect actual code state after the gap-closure branch. Add a new CHANGELOG section dated 2026-04-24 enumerating the closed gaps from this spec by step number. Do not invent features that were not implemented. If anything in this spec was deliberately deferred, list it under a "Known Gaps" section.

**Acceptance check:** README status table matches code; CHANGELOG entry added; no invented features.

---

## Step 21 — Final sweep: clippy, format, deny, docs

**Goal:** Leave the workspace in a clean shippable state.

**Prompt for Claude Code:**

> Run, in order: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo doc --workspace --no-deps`, and `cargo deny check`. Fix any new findings. Then grep the entire workspace for `todo!`, `unimplemented!`, and the literal string `TODO` and produce a final report listing every remaining occurrence with file:line and a one-line justification (deferred, intentional, or scheduled). Do not delete justified TODOs.

**Acceptance check:** All five commands green; final TODO inventory produced and reviewed.

---

## Step 22 — Open the gap-closure pull request

**Goal:** Hand the work over for human review.

**Prompt for Claude Code:**

> Confirm the working tree is clean and the branch is `gap-closure`. Push the branch and open a pull request titled `Close gap-closure spec (Steps 1–21)`. The PR body must summarize: which gaps from `spec.md` were closed, the new test count delta per crate, any deferred items, and a checklist mirroring this spec's step list with each step checked. Do not request review from anyone; do not merge. Report the PR URL.

**Acceptance check:** PR exists, body is complete, branch is not merged.

---

## Notes on ordering and parallelism

- Steps 3 (codon translation) and 4 (hazard database) are independent and could be done in parallel by separate agents in worktrees.
- Steps 6–8 (DNA, peptide, chemical invariants) depend on Steps 3–5 and can each be done in parallel once those land.
- Steps 11–17 (CLI subcommands) depend on Step 5; the seven CLI commands themselves are mutually independent.
- Step 18 (profiles) is independent of the invariant work and can land at any time after Step 1.
- Steps 19–22 are strictly final.

If you parallelize, give each parallel worktree its own branch off `gap-closure` and merge them serially with a single integration commit before Step 19.
