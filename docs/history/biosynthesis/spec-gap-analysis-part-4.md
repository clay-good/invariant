> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Spec Gap Analysis — Part 4

Date: 2026-04-27
Branch: `codelicious/spec-spec-gap-analysis-part-3`
Scope: deep cross-cut of every spec doc against current code (post-chunk-03, ~562 tests, clean clippy).
Predecessors: `spec-gap-analysis.md` (baseline), `spec-phase1-gap-closure.md` (Steps 0–22 closure), `spec-phase2-operational.md` (forward plan), `spec-gap-analysis-part-3.md` (D-family update).

This document is a **complete inventory of remaining issues and incomplete items**. Each gap carries a severity, file references, and a concrete remediation. Items already covered in parts 1–3 are referenced but not re-derived.

---

## 1. Severity Legend

| Severity | Meaning |
|----------|---------|
| CRITICAL | Blocks any production deployment claim; security or correctness hole. |
| HIGH     | Operationally important; library has the capability but it is unreachable, opt-in by accident, or unvalidated. |
| MEDIUM   | Maturity / observability gap; required for serious operations but not safety-critical. |
| LOW      | Polish; quality-of-life or governance. |

Counts: **7 CRITICAL · 7 HIGH · 7 MEDIUM · 3 LOW** = 24 open gaps.

---

## 2. Critical Gaps (production-blocking)

### C-1. Chemical invariants have no real cheminformatics
- **Files:** [crates/invariant-biosynthesis-core/src/invariants/chemical.rs](../crates/invariant-biosynthesis-core/src/invariants/chemical.rs)
- **Symptom:** C1–C10 treat SMILES as opaque strings. Structural matching is regex tokens (`[Na]`, `P(=O)(O…)(F)`, `[Hg]`). C8 reaction feasibility is a `>250-char SMILES` heuristic. No `Molecule` type, no canonicalisation, no SMARTS engine, no isomer detection. Salts with explicit ionic SMILES bypass.
- **Spec demand:** RDKit (or Rust port) with SMARTS, canonicalisation, retrosynthesis depth.
- **Remediation:** Land `rdkit-cheminformatics` feature (Phase-2 §11). Introduce `Molecule` type. Replace each C-invariant heuristic with calibrated SMARTS pattern set; publish FP/FN bounds against a curated reference set.

### C-2. D-family homology is regex-based; new k-mer screener uncalibrated
- **Files:** [crates/invariant-biosynthesis-core/src/invariants/dna.rs:59-173](../crates/invariant-biosynthesis-core/src/invariants/dna.rs#L59-L173)
- **Symptom:** D1–D6 use regex patterns from `HazardDatabase`. The new 3-frame + reverse-complement protein k-mer Jaccard screener has hardcoded constants (`k=5`, Jaccard ≥ 0.30) with **no published Clopper–Pearson bounds** against the HHS Select-Agent reference set.
- **Spec demand:** FN ≤ 1e-4, FP ≤ 1e-3 with statistical confidence intervals.
- **Remediation:** Build a reference corpus (CRITICAL gap C-12 below). Run grid search over `k ∈ {4..8}` and Jaccard ∈ {0.15..0.45}. Publish ROC curve and lock thresholds. Alternative path: integrate HMMER or `minimap2` behind feature flag.

### C-3. HSM backends are stubs
- **Files:** [crates/invariant-biosynthesis-core/src/keys.rs:289-539](../crates/invariant-biosynthesis-core/src/keys.rs#L289-L539)
- **Symptom:** `OsKeyringStore`, `TpmKeyStore`, `YubiHsmKeyStore` all return `KeyStoreError::Unavailable("…not yet implemented")`. Only file-backed keys (mode 0o600) work. No multi-party threshold ceremony, no key rotation with overlap-key support, no host attestation.
- **Remediation:** Land TPM 2.0 backend behind `tpm2` feature flag using `tss-esapi` (Phase-2 §6). Add `keygen --threshold m-of-n` ceremony command. Document file-backed key disablement in production configs.

### C-4. Replication backends are stubs
- **Files:** [crates/invariant-biosynthesis-core/src/replication.rs:256-294](../crates/invariant-biosynthesis-core/src/replication.rs#L256-L294)
- **Symptom:** `S3Replicator::replicate_entry` and `WebhookWitness::publish` both return `ReplicationError::Unavailable`. Audit log is local-disk-only; loss of disk = loss of trail. No RFC 9162-style transparency-log POST.
- **Remediation:** Implement `S3Replicator` against `aws-sdk-s3` behind `s3-replication` feature. Implement `WebhookWitness` with retry + exponential backoff. Add periodic Merkle-root exchange protocol for cross-instance reconciliation (see C-7 below).

### C-5. Stateful fragmentation detector is opt-in and process-local
- **Files:** [crates/invariant-biosynthesis-core/src/validator.rs:109](../crates/invariant-biosynthesis-core/src/validator.rs#L109), [crates/invariant-biosynthesis-core/src/invariants/stateful.rs](../crates/invariant-biosynthesis-core/src/invariants/stateful.rs)
- **Symptom:** `validator.stateful_detector: Option<…>` — when `None`, **fragmentation attacks pass silently**. No CLI flag to enable. No production profile wires it. Even when wired, state is in-memory only — two firewalls running side-by-side share nothing, defeating fleet-scale fragmentation detection.
- **Remediation:** (a) Make `Some(default detector)` the default in `ValidatorConfig::new`; require explicit opt-out. (b) Add `--stateful` / `--no-stateful` CLI flag on `validate`. (c) Add a `StatefulStore` trait with file-backed and Redis-backed implementations so multi-instance deployments can share the per-principal sliding window.

### C-6. Stale screening-database fallback is reachable from the CLI
- **Files:** [crates/invariant-biosynthesis-core/src/validator.rs:407-410](../crates/invariant-biosynthesis-core/src/validator.rs#L407-L410), [crates/invariant-biosynthesis-core/src/models/profile.rs](../crates/invariant-biosynthesis-core/src/models/profile.rs)
- **Symptom:** `allow_unimplemented_invariants=true` simultaneously silences stub invariants **and** downgrades stale hazard DBs to advisory. Combination is reachable via the CLI without a guard.
- **Remediation:** Split the knob into:
  - `allow_unimplemented_invariants: bool` (stubs only).
  - `allow_stale_screening: bool` (defaults to `false`; when `true` requires staleness window in days).
  - Reject combination at `BioProfile::validate` time when `bsl_level >= 3`.

### C-7. Synthesizer-platform adapters do not exist
- **Files:** [crates/invariant-biosynthesis-core/src/attestation.rs](../crates/invariant-biosynthesis-core/src/attestation.rs) (envelope types only)
- **Symptom:** Zero vendor adapters (Twist, IDT, Ansa, Kilobaser, CEM, Biotage, Chemspeed, Hamilton, Tecan, Emerald, Strateos, Transcriptic). No HTTP transport. No instrument-side library to *produce* attested readings. No `invariant-bio issue-token` command. No sample profiles wiring platform names. Vendor-facing surface is incomplete.
- **Remediation:** Phase-2 §14–15: ship three reference adapters (Twist DNA, CEM peptide, Chemspeed chemical) as separate crates, each pre-verifying execution-token signature before any network call. Ship 5 tests + 1 example profile per adapter.

---

## 3. High-Priority Gaps

### H-1. Library features unreachable from CLI
- **Symptom:** Five capabilities exist in code but have no CLI flag, so operators cannot use them. Catalogued from part-3 §16.6 and re-verified.

| Feature | Library | Missing CLI Flag |
|---|---|---|
| Stateful fragmentation detection | `validator.rs:109`, `stateful.rs` | `--stateful` / `--cross-bundle` |
| Consensus hazard screening | `screening/mod.rs:303-409` | `--hazard-db` (repeatable) + `--quorum {any\|all\|k:N}` |
| Attested-input verification | `attestation.rs:188-239`, `validator.rs:217` | `--attest` / `--verify-with` |
| Threat scoring | `threat.rs`, `validator.rs:166-173` | `--threat-threshold <f64>` |
| Persistent attestation log | `attestation.rs:188-239` | `--nonce-log <PATH>` |

- **Remediation:** Add the flags above to [crates/invariant-biosynthesis-cli/src/commands/validate.rs](../crates/invariant-biosynthesis-cli/src/commands/validate.rs). Wire each to the existing builder method on `ValidatorConfig`. Add integration tests in [crates/invariant-biosynthesis-cli/tests/cli_integration.rs](../crates/invariant-biosynthesis-cli/tests/cli_integration.rs) covering each flag's effect.

### H-2. Threat scorer and runtime monitors are coded but not invoked
- **Files:** [crates/invariant-biosynthesis-core/src/threat.rs](../crates/invariant-biosynthesis-core/src/threat.rs), [crates/invariant-biosynthesis-core/src/monitors.rs](../crates/invariant-biosynthesis-core/src/monitors.rs)
- **Symptom:** `ThreatScorer` (5 detectors) and `MonitorAction` (6 checks) are fully implemented; default `ValidatorConfig` passes `threat_scorer: None`, disabling them. There is no `invariant-bio monitor --interval-s <N>` mode.
- **Remediation:** (a) Default-on threat scorer with conservative threshold for BSL ≥ 3 profiles. (b) Add `monitor` subcommand running the scheduler against a pluggable alert sink.

### H-3. Multi-source hazard-DB consensus not auto-wired
- **Files:** [crates/invariant-biosynthesis-core/src/screening/mod.rs:303-409](../crates/invariant-biosynthesis-core/src/screening/mod.rs#L303-L409)
- **Symptom:** `ConsensusHazardScreener` exists but the validator default holds a single `Arc<dyn HazardScreener>`. Operators get a single-DB pipeline by default.
- **Remediation:** When `--hazard-db` is supplied more than once, build a `ConsensusHazardScreener` automatically with policy from `--quorum` (default `all`).

### H-4. D7 host-specific codon usage uncalibrated
- **Files:** [crates/invariant-biosynthesis-core/src/invariants/dna.rs:716-783](../crates/invariant-biosynthesis-core/src/invariants/dna.rs#L716-L783), [crates/invariant-biosynthesis-core/src/models/profile.rs:44-51](../crates/invariant-biosynthesis-core/src/models/profile.rs#L44-L51)
- **Symptom:** Profile carries `codon_usage_organism`; validator only whitelists the string and uses Shannon entropy. No CUTG table loaded; no chi-squared hypothesis test against host distribution. Codon-shuffled hazards in a benign exotic-host carrier sequence will pass.
- **Remediation:** Embed CUTG tables for `e_coli`, `s_cerevisiae`, `h_sapiens`, `cho_k1` (compile-time `include_str!`). Run chi-squared GoF; verdict path = `Pass | Advisory(p<0.05) | Fail(p<0.001)`.

### H-5. P-family uses heuristics, not calibrated predictors
- **Files:** [crates/invariant-biosynthesis-core/src/invariants/peptide.rs:485-670](../crates/invariant-biosynthesis-core/src/invariants/peptide.rs#L485-L670)
- **Symptom:**
  - P6 MHC binding: 8–11 AA hydrophobic window (no NetMHCpan).
  - P8 aggregation: 6-residue poly-(I/L/V/F/Y/W) window (no TANGO/Zyggregator).
  - P9 PTM motifs: regex only, no structural context.
- **Remediation:** Either (a) integrate a real predictor behind feature flags, or (b) downgrade these invariants to Advisory in the spec and document the limitation in user-facing docs.

### H-6. Attestation nonce log has no rotation policy
- **Files:** [crates/invariant-biosynthesis-core/src/attestation.rs:188-239](../crates/invariant-biosynthesis-core/src/attestation.rs#L188-L239)
- **Symptom:** Persistent JSONL nonce log (added in chunk-03) survives restart but grows unbounded. Long-running firewall will exhaust disk.
- **Remediation:** Time-windowed rotation (e.g. 90 days) with cryptographic compaction: write a checkpoint summarising "all nonces seen before T are rejected" and truncate.

### H-7. No audit-readiness documentation
- **Symptom:** Phase-2 §20 calls for `docs/AUDIT-READINESS.md` walking auditors through build, test inventory, supported features, known limitations, crypto primitives + library versions, supply-chain (SBOM). Not present. Threat-model.md predates chunk-03 stateful detection.
- **Remediation:** Author `docs/AUDIT-READINESS.md` and refresh `docs/threat-model.md` to reflect D10/S1 coverage and k-mer limitations. Generate SBOM with `cargo-sbom` in CI.

---

## 4. Medium-Priority Gaps

### M-1. Consensus disagreement is not structured
- **Files:** [crates/invariant-biosynthesis-core/src/screening/mod.rs:397-406](../crates/invariant-biosynthesis-core/src/screening/mod.rs#L397-L406)
- **Symptom:** Disagreement is a string label on the hit. Compliance auditing needs structured fields (per-source verdict, agreement matrix).
- **Remediation:** Add `ConsensusReport { sources: Vec<SourceVerdict>, policy: QuorumPolicy, agreed: bool }` to verdict.

### M-2. Differential validation not in standard validate flow
- **Files:** [crates/invariant-biosynthesis-core/src/differential.rs](../crates/invariant-biosynthesis-core/src/differential.rs), [crates/invariant-biosynthesis-cli/src/commands/differential.rs](../crates/invariant-biosynthesis-cli/src/commands/differential.rs)
- **Symptom:** Capability exists; CLI accepts pre-computed verdicts only. No `invariant-bio validate --differential <secondary-config>` mode. IEC 61508 SIL-2 framing in the spec is unsupported.
- **Remediation:** Add `--differential <config-path>` to the validate command; on disagreement, escalate verdict to `Fail` and emit a structured divergence record.

### M-3. No statistical validation framework
- **Symptom:** Spec demands Clopper–Pearson confidence bounds, power analysis, Bayesian updating. None of this exists.
- **Remediation:** New module `invariant-biosynthesis-core::statistics` providing CIs for binary classification metrics; use in sim crate for FN/FP estimation.

### M-4. No performance benchmarks
- **Symptom:** Phase-2 §17 calls for `criterion` harnesses on hot paths (validator, screening, k-mer engine). Missing.
- **Remediation:** Add `benches/` to core crate; lock baseline numbers in `docs/PERFORMANCE.md`.

### M-5. D9 secondary-structure check is heuristic
- **Files:** [crates/invariant-biosynthesis-core/src/invariants/dna.rs:937-974](../crates/invariant-biosynthesis-core/src/invariants/dna.rs#L937-L974)
- **Symptom:** 20-nt rolling-hash perfect-complement match. Real ΔG via ViennaRNA deferred.
- **Remediation:** Land `viennarna` feature flag invoking external binary; gate on availability.

### M-6. Incident responder framework not integrated
- **Files:** [crates/invariant-biosynthesis-core/src/incident.rs](../crates/invariant-biosynthesis-core/src/incident.rs)
- **Symptom:** `IncidentResponder`, `IncidentRecord`, `IncidentTrigger` defined and tested but not called from validator or CLI. `AlertSink::Webhook` and `AlertSink::Syslog` return `AlertError::Unavailable`.
- **Remediation:** Wire into validator post-verdict path; implement webhook + syslog sinks behind features.

### M-7. PCA chain hop count is unbounded
- **Symptom:** Deeply nested delegations are accepted; no spec limit on hops.
- **Remediation:** Add `max_authority_chain_depth` to `BioProfile` (default 5); reject longer chains at validation.

---

## 5. Low-Priority Gaps

### L-1. PR2 vocabulary is gated by built-in ceiling
- **Files:** [crates/invariant-biosynthesis-core/src/invariants/protocol.rs:172-214](../crates/invariant-biosynthesis-core/src/invariants/protocol.rs#L172-L214), [crates/invariant-biosynthesis-core/src/models/profile.rs:107-119](../crates/invariant-biosynthesis-core/src/models/profile.rs#L107-L119)
- **Symptom:** Profiles can restrict but not extend the 25-verb whitelist. If spec intends pure per-profile vocabularies, this is a gap; if the built-in is a global ceiling, document it explicitly.
- **Remediation:** Decide policy in spec; either remove built-in ceiling or add `BUILT-IN-VOCAB.md` documentation.

### L-2. No formal RFC/responsible-disclosure SLA
- **Symptom:** `SECURITY.md` lacks SLA timelines; no PR template or RFC process.
- **Remediation:** Add `.github/SECURITY.md` SLA, RFC template under `docs/rfcs/`.

### L-3. No export-control CI check
- **Symptom:** `deny.toml` covers licensing only, not EAR/ITAR. Flagged in part-3 §13.
- **Remediation:** Add a CI step checking for export-controlled crate dependencies; document policy in `docs/EXPORT-CONTROL.md`.

---

## 6. Cross-Cutting: Specification Hygiene

These are not single-line bugs but systemic gaps that require spec text changes alongside code.

### X-1. Severity of the "opt-in" pattern is under-recognised
The codebase has a recurring pattern: a security-critical capability is implemented as `Option<T>` on `ValidatorConfig`, defaulting to `None`. Today this affects:
- Stateful fragmentation detector (C-5).
- Threat scorer (H-2).
- Persistent attestation log (H-1 row 5).
- Consensus screening (H-3).

**Each silently degrades safety when not wired.** The spec should adopt a default-secure posture: profiles with `bsl_level >= 3` MUST set these to `Some(default)` at `BioProfile::validate` time, not at runtime.

### X-2. `allow_unimplemented_invariants` is overloaded
Currently governs stub invariants AND stale-DB fallback. Split (see C-6) and make `allow_stale_screening` independent.

### X-3. Acceptance gates for "production-ready" claim
Restating part-3 §18 with current status against each gate:

| # | Gate | Status |
|---|------|--------|
| 1 | Phase 2 closed | ❌ in progress |
| 2 | Reference set FN ≤ 1e-4 / FP ≤ 1e-3 with CIs | ❌ no reference set |
| 3 | Shadow-mode > 99% agreement | ❌ no infra |
| 4 | At least one HSM backend in production | ❌ all stubs |
| 5 | At least one synthesizer end-to-end | ❌ no adapters |
| 6 | At least one jurisdiction's compliance report accepted | ❌ no compliance crate |
| 7 | Stateful + consensus reachable from CLI, default in production profiles | ❌ no flags |

**Until all seven flip to ✅, the README, marketing, and spec MUST NOT claim "production-ready for synthesis."**

### X-4. README "Known gaps" is incomplete
[README.md](../README.md) lines 133–140 list 5 deferred items; missing from that list:
- Threat scorer not wired (H-2).
- Stateful detector opt-in (C-5).
- Consensus screener no CLI surface (H-1, H-3).
- Platform adapters absent (C-7).
- Attestation persistence rotation (H-6).

Update the README to be honest about the current capability surface.

---

## 7. Compliance Track (separate roadmap)

These belong to a `invariant-biosynthesis-compliance` crate that does not yet exist. Listed here so they appear in the gap inventory but are not weighted into the main severity table because the work is *additive* (new crate) rather than *fixing* existing code.

1. **Per-jurisdiction report generators** (CDC Select Agent, NIH rDNA, FDA, USDA APHIS, EPA TSCA, CWC/ITAR/Australia Group/Wassenaar, NIST AI RMF, ISO/IEC AI safety).
2. **Auditor RBAC** — read-only audit-accessor role authenticated against a separate keypair.
3. **Per-jurisdiction invariant variants** — declare different screening rules per jurisdiction in profiles.

---

## 8. Suggested Work Order

A pragmatic sequence (each item independently shippable):

1. **CLI surface for existing library features** (H-1) — single PR, no new dependencies, immediately reduces silent failure modes. Couples with C-5, C-6, H-2, H-3.
2. **Default-secure validator config** (X-1, C-5, C-6) — flip defaults; tighten profile validation.
3. **Replication backends** (C-4) — `s3-replication` and `webhook-witness` features.
4. **Reference corpora + statistical framework** (C-2, M-3) — enables calibration of the new k-mer screener and any future predictors.
5. **TPM 2.0 backend** (C-3) — single feature flag; document file-backed key disablement.
6. **First synthesizer adapter** (C-7) — Twist DNA reference adapter; sets the pattern for the rest.
7. **Cheminformatics integration** (C-1) — `rdkit-cheminformatics` feature; longest critical-path item.
8. **AUDIT-READINESS.md + threat-model refresh** (H-7) — gates third-party audit.
9. **Compliance crate** (§7) — last; depends on stable verdict + audit schemas.

Estimated effort: ~8 weeks for items 1–5, ~6 months for full production readiness through item 9.

---

## 9. Test Coverage Gaps

Beyond the per-gap remediation tests, the following test categories are missing entirely:

- **Adversarial corpus tests** — known-hazard sequences, codon-shuffled variants, fragmentation chains, replay attacks across reset boundaries.
- **Statistical regression tests** — calibration drift detection on each k-mer engine release.
- **Multi-instance integration tests** — two validators sharing state via Redis-backed `StatefulStore`.
- **End-to-end synthesizer-mock tests** — full token-issuance → bundle-validation → attested-reading → audit chain, against a fake vendor adapter.
- **CLI flag coverage** — each new flag from H-1 needs a happy-path and a refusal-path test.

---

## 10. Files Touched / Referenced

For convenience to reviewers:

- Validator: [validator.rs](../crates/invariant-biosynthesis-core/src/validator.rs)
- Invariants: [dna.rs](../crates/invariant-biosynthesis-core/src/invariants/dna.rs) · [peptide.rs](../crates/invariant-biosynthesis-core/src/invariants/peptide.rs) · [chemical.rs](../crates/invariant-biosynthesis-core/src/invariants/chemical.rs) · [protocol.rs](../crates/invariant-biosynthesis-core/src/invariants/protocol.rs) · [stateful.rs](../crates/invariant-biosynthesis-core/src/invariants/stateful.rs)
- Crypto / keys: [keys.rs](../crates/invariant-biosynthesis-core/src/keys.rs)
- Audit / replication / attestation: [audit.rs](../crates/invariant-biosynthesis-core/src/audit.rs) · [replication.rs](../crates/invariant-biosynthesis-core/src/replication.rs) · [attestation.rs](../crates/invariant-biosynthesis-core/src/attestation.rs)
- Threat / monitors / incident: [threat.rs](../crates/invariant-biosynthesis-core/src/threat.rs) · [monitors.rs](../crates/invariant-biosynthesis-core/src/monitors.rs) · [incident.rs](../crates/invariant-biosynthesis-core/src/incident.rs)
- Screening: [screening/mod.rs](../crates/invariant-biosynthesis-core/src/screening/mod.rs)
- Profile: [models/profile.rs](../crates/invariant-biosynthesis-core/src/models/profile.rs)
- CLI commands: [validate.rs](../crates/invariant-biosynthesis-cli/src/commands/validate.rs) · [differential.rs](../crates/invariant-biosynthesis-cli/src/commands/differential.rs)

— end —
