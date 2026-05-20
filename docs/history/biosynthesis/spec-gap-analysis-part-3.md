> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Specification: Gap Closure & Remediation — Part 3

**Status:** Draft, 2026-04-27
**Supersedes:** the prior status table in [spec-gap-analysis.md](spec-gap-analysis.md) (2026-04-25), which is preserved as the historical baseline.
**Scope:** Re-runs the spec-vs-code delta after commits `d497f37` (chunk-02 snapshot) and `2716d97` (chunk-03 D-family). Records what closed, what remained open, and what new gaps the recent work surfaced. Severity tags follow `CRITICAL > HIGH > MEDIUM > LOW`.

A short legend per section:

- **Spec promise** — the contract from `spec.md` / `step*-*.md` / `threat-model.md`.
- **Now in code** — what the current `crates/` actually does, with `file:line` evidence.
- **Status** — `CLOSED`, `PARTIALLY CLOSED`, `OPEN`, or `UNCHANGED` since 2026-04-25.
- **Remaining gaps** — what is still missing for the spec promise to hold.

---

## 0. Snapshot of the codebase

- `cargo build --workspace`, `cargo clippy -- -D warnings`: clean.
- `cargo test --workspace`: 562 tests passing (was 547 on 2026-04-25; +15 from new stateful-detector and end-to-end suites). `tests/audit_replication_e2e.rs` and `tests/differential_e2e.rs` are new integration suites.
- All five crates retain `#![forbid(unsafe_code)]`. No `todo!()`, `unimplemented!()`, or `panic!()` on production paths. `unwrap()`/`expect()` remain confined to tests/examples.
- The cryptographic spine (PCA chain, audit, attestation, watchdog) was already complete; this round added attestation persistence and stateful biological state. Biology-, chemistry-, hardware-key-, and platform-integration layers are still the soft underbelly.

---

## 1. Biological invariants (D-family) — CRITICAL

**Spec promise (step3-bio-invariants.md, D1–D10):** profile-HMM scanning at calibrated bit-score thresholds, codon-substituted homolog detection across 3 reading frames (forward and reverse), host-specific codon-usage hints, and cross-bundle fragmentation detection.

**Now in code:**
- 3-frame *and* reverse-complement protein-space rescreen added in [crates/invariant-biosynthesis-core/src/invariants/dna.rs](../crates/invariant-biosynthesis-core/src/invariants/dna.rs):59–173. Translation → protein k-mer set (k=5) → Jaccard ≥ 0.30 against translated hazard patterns. Catches codon-substituted homologs that DNA-level regex misses.
- D7 codon-entropy bounds now read from `BioProfile.codon_entropy_band` and `codon_usage_organism` (precedence: explicit band > organism band > legacy default `[2.5, 5.8]`) — see [dna.rs:716-783](../crates/invariant-biosynthesis-core/src/invariants/dna.rs#L716-L783) and the corresponding tests at [dna.rs:1283-1320](../crates/invariant-biosynthesis-core/src/invariants/dna.rs#L1283).
- D10 cross-bundle fragmentation detector lives in the new file [crates/invariant-biosynthesis-core/src/invariants/stateful.rs](../crates/invariant-biosynthesis-core/src/invariants/stateful.rs) (414 LOC). Per-principal sliding window of 24-mers, capped at 20 windows, Jaccard ≥ 0.4 + hazard-class hit ⇒ Fail; overlap without hazard ⇒ Advisory. Eviction and principal isolation are tested.
- Single-bundle D10 was correspondingly weakened to *Advisory* on assembly-bypass termini ([dna.rs:975-1004](../crates/invariant-biosynthesis-core/src/invariants/dna.rs#L975)) since cross-bundle is now S1's job.

**Status:** PARTIALLY CLOSED.

**Remaining gaps:**

1. **No real homology engine.** Protein k-mer Jaccard is uncalibrated. Spec calls for HMMER bit-scores against curated profile-HMMs with FN ≤ 1e-4, FP ≤ 1e-3 and published Clopper–Pearson bounds. Pattern source is still the regex-derived `HazardDatabase`, not an HMM index. `k=5` and `threshold=0.30` are constants in source — not derived from any reference set.
2. **D7 has no chi-squared / CUTG lookup.** Profile carries `codon_usage_organism` but the validator only whitelists the organism string ([dna.rs:1315-1320](../crates/invariant-biosynthesis-core/src/invariants/dna.rs#L1315)); it does not load a host-specific codon-usage table or run a hypothesis test. Shannon entropy alone cannot tell a deliberately codon-shuffled hazard from a benign exotic-host gene.
3. **D10 / S1 is opt-in.** [validator.rs:109](../crates/invariant-biosynthesis-core/src/validator.rs#L109) carries `stateful_detector: Option<…>`; if `None`, fragmentation attacks pass. There is no CLI flag (`--stateful` / `--cross-bundle`) and no production-profile template that wires it.
4. **Multi-publisher consensus is implemented but not auto-wired** (see §5).

**Acceptance gate:** evaluation against the curated HHS Select Agent reference set with FN ≤ 1e-4, FP ≤ 1e-3 and published Clopper–Pearson bounds. The k-mer engine should be benchmarked first and either calibrated, or replaced with HMMER, before this gate can be met.

---

## 2. Chemical invariants (C-family) — CRITICAL

**Spec promise:** SMILES canonicalisation, SMARTS substructure matching, reaction-feasibility scoring, CWC-schedule cross-reference.

**Now in code:** unchanged. [crates/invariant-biosynthesis-core/src/invariants/chemical.rs](../crates/invariant-biosynthesis-core/src/invariants/chemical.rs) still pattern-matches SMILES strings as opaque text (`[Na]`, `P(=O)(O…)(F)`, etc.). No molecule object, no canonical form, no isomer awareness, no SMARTS engine. C8 reaction feasibility is still a `>250 chars` advisory.

**Status:** UNCHANGED (CRITICAL).

**Remaining gaps:** as in [spec-gap-analysis.md §2](spec-gap-analysis.md). RDKit (FFI or Rust port), `Molecule` type replacing `&str`, signed/versioned SMARTS rule library loaded the way `HazardDatabase` is, canonicalisation as a precondition, and a real synthon/retrosynthesis scorer or honest downgrade of C8 in the spec.

---

## 3. Peptide invariants (P-family) — HIGH

**Spec promise:** MHC-I/II binding prediction (P6), aggregation calibrated against TANGO/Zyggregator (P8), context-aware PTM site prediction (P9).

**Now in code:** unchanged. [peptide.rs](../crates/invariant-biosynthesis-core/src/invariants/peptide.rs) gained only the `mod stateful` plumbing in chunk-02; P5/P6/P8/P9 remain pure regex / sliding-window heuristics.

**Status:** UNCHANGED (HIGH).

**Remaining gaps:**

1. **P6** — wire NetMHCpan via subprocess or bundle a small predictor. Current 8–11mer hydrophobic window is a poor proxy.
2. **P8** — replace 6-residue heuristic with a calibrated aggregation predictor.
3. **P5** — without structural context, downgrade active-site catalytic motif hits to `Advisory` until a real predictor lands.

---

## 4. Protocol invariants (PR-family) — LOW

**Spec promise:** PR1–PR4 fully evaluated; per-profile vocabulary override.

**Now in code:**
- PR1, PR3, PR4 unchanged and complete.
- **PR2 vocabulary moved into the profile.** [models/profile.rs:44-51](../crates/invariant-biosynthesis-core/src/models/profile.rs#L44) adds `allowed_protocol_steps: Option<Vec<String>>`, validated against the built-in 25-verb whitelist on profile load ([profile.rs:107-119](../crates/invariant-biosynthesis-core/src/models/profile.rs#L107)). [protocol.rs:172-214](../crates/invariant-biosynthesis-core/src/invariants/protocol.rs#L172) reads the override in `evaluate_with()`; absence falls back to the built-in list.

**Status:** CLOSED.

**Remaining gap:** the built-in 25-verb list itself is still hard-coded; per-profile *additions* outside the built-ins are rejected by validation. If the spec wants pure per-profile vocabularies (no global gate) this is still a gap; if the built-in is meant as a global ceiling, this is intentional and documentation should say so.

---

## 5. Screening database — HIGH

**Spec promise (step6-screening-databases.md):** signed and versioned hazard DB, multi-source consensus with explicit disagreement surfacing, SecureDNA-style oblivious queries, 30-day fail-closed staleness window.

**Now in code:**
- Single-DB path unchanged: signed JSON, schema v1, Ed25519 verification, 30-day freshness.
- **Consensus screener implemented:** [screening/mod.rs:287-409](../crates/invariant-biosynthesis-core/src/screening/mod.rs#L287) introduces `ConsensusHazardScreener` with `QuorumPolicy::{Any, All, AtLeast(k)}`. Hits from each source are aggregated; class-level disagreement is annotated into the hit label. Source freshness is taken worst-case (stalest source wins).
- New end-to-end test [tests/audit_replication_e2e.rs](../crates/invariant-biosynthesis-core/tests/audit_replication_e2e.rs) exercises the screener in the validator pipeline.

**Status:** PARTIALLY CLOSED.

**Remaining gaps:**

1. **Validator default is still single-DB.** [validator.rs](../crates/invariant-biosynthesis-core/src/validator.rs) holds one `Arc<dyn HazardScreener>`; the consensus screener can be supplied but no CLI subcommand or config schema lets an operator declare *N* DB paths and a quorum policy. Add `--hazard-db <path>` (repeatable) + `--quorum {any|all|k:N}` to `invariant-bio validate`.
2. **SecureDNA / oblivious-query backend.** Still unimplemented. Either build it (cite primary research and pin a protocol version) or remove from `step6-screening-databases.md`.
3. **Fail-closed staleness in production.** Stale DBs can still degrade to advisory if `allow_unimplemented_invariants=true`; that path is reachable from the CLI without a guard. Lock it down by either (a) splitting that knob into `allow_unimplemented` (silence stubs) and `allow_stale_screening` (separate, defaults to `false`, refused in production profiles), or (b) refusing the combination in profile validation.

---

## 6. PCA authority chain — COMPLETE

Unchanged. Ed25519 / COSE_Sign1 / hop-by-hop validation / time-bound checks / operation algebra all tested. No gap.

(Out-of-spec opportunity from the prior doc — institutional reference profiles in `examples/` — is also unchanged. Not a blocker.)

---

## 7. HSM and key management — CRITICAL (for production)

**Spec promise (step7-hsm-key-mgmt.md):** TPM 2.0, FIPS 140-2 L3 HSMs, YubiHSM, OS keyring; multi-party threshold root-key ceremony; secure-boot attestation; key rotation.

**Now in code:** unchanged. `OsKeyringStore`, `TpmKeyStore`, `YubiHsmKeyStore` in `keys.rs` still return `Unavailable`. File-backed keys still the only working path; mode-0o600 enforcement is in place.

**Status:** UNCHANGED (CRITICAL).

**Remaining gaps:** as before — real backends (`tss-esapi`, `yubihsm`, `keyring`); `invariant-bio keygen ceremony …` for multi-party threshold provisioning; key-rotation API with overlap-key support; TPM/SGX remote attestation so a synthesiser can verify the firewall host.

---

## 8. Audit, replication, witnessing — HIGH

**Spec promise (step8 + step9):** L1–L4 (completeness, ordering, authenticity, immutability); off-site replication; Merkle-root witnessing for external notarisation.

**Now in code:**
- Audit log (`audit.rs`): unchanged and complete (append-only JSONL, SHA-256 chain, per-entry signatures, tamper detection, rotation guards). End-to-end coverage now in [tests/audit_replication_e2e.rs](../crates/invariant-biosynthesis-core/tests/audit_replication_e2e.rs).
- **Attestation gained persistence.** [attestation.rs:188-239](../crates/invariant-biosynthesis-core/src/attestation.rs#L188) — `AttestationVerifier::with_persistent_log()` reads/writes a JSONL nonce log so replay protection survives restarts. New `AttestedInput` envelope and verifier wired into the validator (see §9).
- **Replication still split:** `FileReplicator` real, `S3Replicator` and `WebhookWitness` still return `not yet implemented`.

**Status:** PARTIALLY CLOSED — attestation persistence done; remote replication and witnessing still open.

**Remaining gaps:**

1. **`S3Replicator`** — wire to `aws-sdk-s3`; cross-region replication, recovery-on-restart, integrity check on read-back.
2. **`WebhookWitness`** — POST Merkle roots to an external notary (RFC 9162 transparency-log style). Add a verifier client and document what counts as an acceptable witness.
3. **Cross-instance Merkle reconciliation.** Multiple firewalls keep independent logs; need a periodic root-exchange protocol so divergence is detectable and attributable.

---

## 9. Synthesis-platform integration — CRITICAL

**Spec promise (step5-platform-integration.md):** integrations with Twist, IDT, Ansa, Kilobaser (DNA); CEM Liberty / Biotage / CSBio / Gyros (peptide); Chemspeed / Hamilton / Tecan (chemical); Emerald / Strateos / Transcriptic (cloud labs). Execution-token verification at endpoints; post-execution attestation.

**Now in code:**
- Envelope types and verifier expanded in `attestation.rs` (`ExecutionToken`, `AttestedReading`, `AttestedInput`).
- **Validator integration.** [validator.rs:217-267](../crates/invariant-biosynthesis-core/src/validator.rs#L217) — new `validate_with_attested_inputs()` verifies attested inputs up front; failures block approval. Attestation results flow into the verdict.
- No vendor API client. No HTTP transport. No instrument-side library to *produce* attested readings.

**Status:** UNCHANGED — verifier-only side; producer-side and transport still missing.

**Remaining gaps:**

1. **New crate `invariant-biosynthesis-platform`** with a `Platform` trait and one reference vendor implementation (Twist or Emerald — both have public APIs).
2. **Execution-token issuance command.** Verdicts exist; signed execution tokens that synthesisers verify offline do not. Add `invariant-bio issue-token …` and document the verify protocol.
3. **Instrument-side reference library.** Code can verify `AttestedReading`; nothing in the repo produces them. Provide a small device-side example.
4. **Instrument key provisioning.** Ceremony required; couples to §7.

---

## 10. Differential validation — MEDIUM → LOW

**Now in code:**
- [differential.rs](../crates/invariant-biosynthesis-core/src/differential.rs) intact.
- **End-to-end exercised:** [tests/differential_e2e.rs](../crates/invariant-biosynthesis-core/tests/differential_e2e.rs) (155 LOC) constructs two validators with different hazard screeners and asserts disagreement is surfaced.

**Status:** CLOSED for capability; OPEN for default-on policy.

**Remaining gap:** still not part of the standard validate flow. Decide: (a) add `invariant-bio validate --differential <path-to-second-config>` and require it in production profile templates, or (b) drop the IEC 61508 SIL 2 framing from the spec. Pick one.

---

## 11. Testing, simulation, fuzzing — MEDIUM

**Now in code:**
- `invariant-biosynthesis-sim`: dry-run campaign harness (5 tests).
- `invariant-biosynthesis-eval`: rubric scoring (12 lib + 3 integration tests).
- `invariant-biosynthesis-fuzz`: protocol/authority/system/cognitive suites (7 tests).
- New `tests/audit_replication_e2e.rs` and `tests/differential_e2e.rs` integration suites.

**Status:** UNCHANGED in scope; +15 tests overall. Statistical-validation and shadow-mode infrastructure still absent.

**Remaining gaps:**

1. **Synthetic sequence corpora.** Sim still runs against hardcoded bundles. Generate distributions covering legitimate research and known hazard variants for FP/FN measurement.
2. **Statistical validation framework.** Spec demands Clopper–Pearson, power analysis, Bayesian updating. None of this exists. New `eval::stats` module.
3. **Shadow-mode evaluation.** No infrastructure for parallel verdict generation against expert review (spec stage 3). Required before any production claim. Target: >99% agreement on borderline cases.
4. **Hardware-in-the-loop tests.** Stage 2 of step8 needs real-platform-without-real-synthesis tests; blocked by §9.
5. **Calibrate the new D-family k-mer engine.** Specifically benchmark the chunk-03 protein-space screener (k=5, Jaccard 0.30) against a curated set; the constants are guesses today.

---

## 12. Regulatory compliance — CRITICAL (for production)

**Spec promise (step9-regulatory-compliance.md):** automated reports for CDC Select Agent, NIH rDNA, FDA, USDA APHIS, EPA TSCA, CWC / ITAR / Australia Group / Wassenaar; NIST AI RMF and ISO/IEC AI safety mappings; auditor RBAC.

**Now in code:** unchanged. Raw `proof_package` JSON export, no jurisdiction-specific generators, no auditor RBAC, no per-jurisdiction invariant variants.

**Status:** UNCHANGED (CRITICAL).

**Remaining gaps:**

1. **`invariant-biosynthesis-compliance` crate.** Per-jurisdiction generators that map verdicts and audit entries onto agency schemas.
2. **Auditor RBAC.** A read-only audit-accessor role authenticated against a separate keypair. Today any reader of the JSONL file sees everything.
3. **Per-jurisdiction invariant variants.** Profiles cannot today distinguish FDA-pharma from USDA-agriculture; both run identical invariants.

---

## 13. Ecosystem and governance — LOW

Unchanged. `SECURITY.md`, `CONTRIBUTING.md`, `README.md`, `CHANGELOG.md`, `LICENSE` present. No documented RFC process; no responsible-disclosure SLA; no export-control CI check (`deny.toml` covers licensing only). All low priority.

---

## 14. Code-quality observations

- `unwrap()`/`expect()`: still confined to tests and examples.
- `#![forbid(unsafe_code)]`: in every crate.
- `cargo clippy -- -D warnings`: clean.
- Public API has rustdoc; module docs present everywhere; no doc-test gaps.
- The new `stateful.rs` introduces mutable global-ish state (per-principal HashMaps). Eviction is tested but the storage is in-memory only — this is correct for a single firewall process, but multi-instance deployments will need shared state (Redis / DB) before §1 gap 3 can be claimed at fleet scale. Note this for §8 cross-instance reconciliation.

No code-quality blockers found. Gaps remain scope, not hygiene.

---

## 15. Status table — what closed since 2026-04-25

| Topic | Severity | 2026-04-25 | 2026-04-27 | Evidence |
|---|---|---|---|---|
| D1–D6 homology | CRITICAL | open | partially closed (k-mer + 3-frame + RC) | `dna.rs:59-173` |
| D7 host-specific bounds | CRITICAL | open | **closed** | `profile.rs:44-51`, `dna.rs:716-783` |
| D10 stateful orchestrator | CRITICAL | open | **closed (opt-in)** | `stateful.rs` (new), `validator.rs:109` |
| Multi-publisher screening | HIGH | open | partially closed (impl, not auto-wired) | `screening/mod.rs:287-409` |
| PR2 vocabulary in profile | LOW | open | **closed** | `profile.rs:44-51`, `protocol.rs:172-214` |
| Attestation persistence | HIGH | open | **closed** | `attestation.rs:188-239` |
| Differential e2e | MEDIUM | open | **closed (capability)** | `tests/differential_e2e.rs` |
| Chemical RDKit | CRITICAL | open | unchanged | — |
| P6/P8 real predictors | HIGH | open | unchanged | — |
| HSM backends | CRITICAL | open | unchanged | — |
| S3 replicator / webhook witness | HIGH | open | unchanged | `replication.rs` |
| Platform vendor adapters | CRITICAL | open | unchanged | — |
| Compliance reports / RBAC | CRITICAL | open | unchanged | — |
| SecureDNA oblivious queries | HIGH | open | unchanged | — |
| Cross-instance Merkle reconciliation | HIGH | open | unchanged | — |
| Statistical / shadow-mode validation | MEDIUM | open | unchanged | — |

---

## 16. New gaps surfaced by chunk-02/chunk-03

These were not in the prior doc; they exist *because* recent work landed and exposed adjacent obligations.

1. **Calibration debt on the protein-space screener.** k=5, Jaccard 0.30 are constants. The screener now claims to detect codon-substituted homologs; the spec's FN ≤ 1e-4 / FP ≤ 1e-3 cannot be defended without a benchmark. Treat as CRITICAL — claiming detection without calibration is worse than not claiming it.
2. **Stateful-detector storage is process-local.** [stateful.rs](../crates/invariant-biosynthesis-core/src/invariants/stateful.rs) holds state in `HashMap<Principal, …>` inside the validator. Two validators running side by side will not see each other's bundles, defeating fragmentation detection across a fleet. HIGH.
3. **Consensus-screener disagreement is logged into a hit label string.** [screening/mod.rs:397-406](../crates/invariant-biosynthesis-core/src/screening/mod.rs#L397) annotates disagreement textually. Compliance will need this as structured data (separate field on the verdict). MEDIUM.
4. **Attestation persistent-log rotation.** [attestation.rs:216-239](../crates/invariant-biosynthesis-core/src/attestation.rs#L216) writes JSONL but has no rotation/compaction policy. A long-running firewall will grow the nonce log unbounded. MEDIUM.
5. **`allow_unimplemented_invariants` is still a single global knob.** It now governs both stub invariants *and* stale screening fallback. As §5 notes, those should split. LOW–MEDIUM.
6. **No CLI surface for the new capabilities.** Stateful detection, consensus screening, attested-input verification, and persistent attestation logs all exist in the library but are not reachable from the `invariant-bio` binary's flags or config schema. Operators cannot use what was built. HIGH — without CLI exposure these closures count as library-only progress.

---

## 17. Phased remediation plan (revised)

**Phase A — biology and chemistry parity with spec (CRITICAL):**
- §1.1 HMMER (or minimap2) integration to replace k-mer Jaccard for D1–D6.
- §1.2 Host-specific CUTG table + chi-squared D7 test.
- §1 calibrate or remove the k-mer threshold defaults; publish FN/FP on a curated reference set.
- §2 RDKit + signed SMARTS rule library.
- §5 multi-publisher consensus auto-wired in CLI; staleness fail-closed in production.

**Phase B — production trust boundary (CRITICAL):**
- §7 real HSM backends + provisioning ceremony + key rotation.
- §9 first-vendor platform integration + execution-token issuance + device-side example.
- §12 first-jurisdiction compliance report generator + auditor RBAC.
- §8 S3 replication, webhook witness, attestation-log rotation.

**Phase C — operational validation (HIGH/MEDIUM):**
- §3 P6/P8 real predictors (or honest downgrade to Advisory).
- §11 shadow-mode + statistical framework.
- §10 wire `--differential` into production profile templates.
- §8 cross-instance Merkle reconciliation.
- §16.2 shared backing store for stateful detector (HIGH if multi-instance is in scope).
- §16.6 CLI surface for stateful, consensus, attested-input, and persistent-log features.

**Phase D — polish (LOW):**
- §13 governance docs, RFC process, responsible-disclosure SLA, export-control CI.
- §16.3 promote consensus disagreement to a structured verdict field.
- §16.5 split `allow_unimplemented_invariants` into stub-vs-staleness knobs.

---

## 18. Acceptance gates (unchanged)

A future release may claim "production-ready for synthesis" only when *all* of the following hold:

1. Phase A and Phase B closed; CI green on the corresponding suites.
2. Curated select-agent reference set: FN ≤ 1e-4, FP ≤ 1e-3, with published Clopper–Pearson bounds — for the actual screener in production, not a placeholder k-mer engine.
3. Shadow-mode agreement with expert review > 99% on borderline cases over a documented N.
4. At least one HSM backend in production use; file-backed keys disabled in the production config.
5. At least one synthesiser vendor verifying execution tokens end-to-end.
6. At least one jurisdiction's compliance report accepted by counsel.
7. Stateful detection and consensus screening reachable from the CLI and enabled in production profile templates.

The codebase remains a sound reference implementation with a clean integration surface. Chunks 02 and 03 closed several CRITICAL items at the library level, but exposure to operators (CLI flags, default profiles) and external dependencies (HMMER, RDKit, HSM, vendor APIs) are still the gating concerns.
