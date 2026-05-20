> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

---
title: Invariant Biosynthesis — Remediation Spec
status: Draft
date: 2026-04-27
branch: codelicious/spec-spec-gap-analysis-part-3
supersedes: none (companion to docs/spec.md)
predecessors: spec-gap-analysis.md, spec-gap-analysis-part-3.md, spec-gap-analysis-part-4.md, spec-phase1-gap-closure.md, spec-phase2-operational.md
---

# Invariant Biosynthesis — Remediation Spec

This is a **normative, code-targeted specification** for closing the gaps between
[docs/spec.md](spec.md) and the current implementation. It deliberately does not
restate working behavior. Every requirement here is **SHALL/MUST** language with a
test gate and a file pointer. If a section's gates pass, the gap is closed.

The gap inventory is taken from [spec-gap-analysis-part-4.md](spec-gap-analysis-part-4.md)
(7 CRITICAL · 7 HIGH · 7 MEDIUM · 3 LOW = 24 open gaps), verified against code on
2026-04-27. Items still verified-open at write time:

- HSM backends are stubs ([keys.rs:436-540](../crates/invariant-biosynthesis-core/src/keys.rs#L436-L540))
- S3 + Webhook replication return `Unavailable` ([replication.rs:257-294](../crates/invariant-biosynthesis-core/src/replication.rs#L257-L294))
- `threat_scorer` and `stateful_detector` default to `None` ([validator.rs:141-143](../crates/invariant-biosynthesis-core/src/validator.rs#L141-L143))
- `validate` CLI exposes only 5 flags ([validate.rs:33-49](../crates/invariant-biosynthesis-cli/src/commands/validate.rs#L33-L49))

Conformance keywords follow RFC 2119.

---

## 0. Conformance Profiles

This spec defines two conformance profiles. Code MUST self-report its profile via
`invariant-bio verify-self --profile`.

| Profile | Intended use | Required sections |
|---------|-------------|-------------------|
| **Research** | Lab research, dry-run, education. BSL ≤ 2 only. | §1, §2, §6, §11 |
| **Production** | Real synthesis gating at BSL ≥ 3. | All sections |

A binary that cannot satisfy the **Production** gates MUST refuse to load any
profile with `bsl_level >= 3` unless the operator passes
`--accept-research-only-build` and the validator emits a `Verdict::Advisory` with
reason `"build profile is Research; production gating disabled"`.

---

## 1. Default-Secure Validator Configuration  *(closes C-5, X-1)*

### 1.1 Requirements

- **R1.1.** `ValidatorConfig::new` MUST construct with:
  - `stateful_detector = Some(FragmentationBypassDetector::default())`
  - `threat_scorer = Some(Arc::new(Mutex::new(ThreatScorer::default())))`
  - `consensus_required = true` when more than one `HazardScreener` is registered
  - `attestation_log = None` only if profile is Research; required otherwise
- **R1.2.** `BioProfile::validate` MUST reject any profile with `bsl_level >= 3` if
  the resolved `ValidatorConfig` has any of the above set to `None`. The error
  variant SHALL be `ProfileError::DegradedSecurityForBSL3 { missing: Vec<&'static str> }`.
- **R1.3.** Opting *out* MUST require both an explicit method
  (`ValidatorConfig::without_stateful_detector(reason: &str)`) and a non-empty
  reason recorded in audit. CLI MUST surface this as
  `--no-stateful --reason="..."` (mirror for each opt-out).

### 1.2 Acceptance gates

- New unit test: `bsl3_profile_rejects_default_none_after_strip` in [validator.rs](../crates/invariant-biosynthesis-core/src/validator.rs).
- Update tests `threat_scorer_absent_no_check` and similar to reflect new default.
- `cargo test --workspace` passes; `cargo clippy -- -D warnings` clean.

---

## 2. CLI Surface for Existing Library Capabilities  *(closes H-1, H-3)*

### 2.1 Requirements

`invariant-bio validate` MUST accept these flags (in addition to today's 5):

| Flag | Type | Behavior |
|------|------|----------|
| `--stateful` / `--no-stateful --reason=<S>` | bool | Force-on / force-off the fragmentation detector. |
| `--cross-bundle <PATH>` | path | Persistent state file for the detector (enables fleet sharing via shared FS / mount). |
| `--hazard-db <PATH>` | path, **repeatable** | When supplied >1×, validator MUST construct a `ConsensusHazardScreener`. |
| `--quorum <POLICY>` | enum: `any \| all \| k:N` | Default `all`. Used only when `--hazard-db` repeated. |
| `--attest <ENVELOPE>` | path | Verify a COSE_Sign1 attested-input envelope before running invariants. |
| `--verify-with <PUBKEY>` | path, repeatable | Acceptable signer keys for `--attest`. |
| `--threat-threshold <FLOAT>` | f64 in [0,1] | Default 0.65 for BSL ≥ 3, 0.85 for BSL ≤ 2. Below threshold = `Pass`; ≥ = `Fail`. |
| `--nonce-log <PATH>` | path | Persistent attestation nonce log; required for `bsl_level >= 3`. |
| `--differential <CONFIG>` | path | Run a second validator instance with the alternate config; on disagreement, escalate to `Fail`. |

### 2.2 Acceptance gates

- One CLI integration test per flag (happy path + refusal path) in
  [cli_integration.rs](../crates/invariant-biosynthesis-cli/tests/cli_integration.rs).
- `--quorum k:N` parser test for malformed values.
- `validate --help` output snapshot test.

---

## 3. `allow_unimplemented_invariants` Split  *(closes C-6, X-2)*

### 3.1 Requirements

- **R3.1.** Replace the single boolean with two:
  - `allow_unimplemented_invariants: bool`
  - `allow_stale_screening: Option<StaleScreeningPolicy>` where
    `StaleScreeningPolicy { max_age_days: u32, reason: String }`.
- **R3.2.** `BioProfile::validate` MUST reject any profile with `bsl_level >= 3`
  that sets either to a permissive value.
- **R3.3.** Audit emits a `degraded_invariants` field listing which invariants
  were silenced, on every verdict where either knob was permissive.

### 3.2 Acceptance gates

- Migration of existing call sites in [validator.rs:407-410](../crates/invariant-biosynthesis-core/src/validator.rs#L407-L410).
- Snapshot test of audit JSON for permissive case.

---

## 4. Replication Backends  *(closes C-4)*

### 4.1 S3 replicator (`s3-replication` feature)

- **R4.1.** `S3Replicator::replicate_entry` MUST PUT each audit entry as
  `{prefix}/{timestamp}-{hash}.jsonl` using `aws-sdk-s3` v1.x.
- **R4.2.** Object-lock retention MUST be set when `BioProfile::export_controlled = true`.
  Default retention: 7 years.
- **R4.3.** Failures MUST retry with exponential backoff (3 attempts, 1s/4s/16s)
  before returning `ReplicationError::TransientFailure`. Persistent failure MUST
  enqueue to a local `replication_queue/` directory and emit a metric
  `audit_replication_queue_depth`.

### 4.2 Webhook witness (`webhook-witness` feature)

- **R4.4.** `WebhookWitness::publish` MUST POST a COSE_Sign1 envelope of the
  audit entry to the configured URL with `Content-Type: application/cose`.
- **R4.5.** Receiver public-key pinning is REQUIRED; trust-on-first-use is forbidden.
- **R4.6.** Same retry policy as R4.3.

### 4.3 Cross-instance reconciliation

- **R4.7.** Add a `merkle_root` subcommand that prints the current root and a
  `reconcile <peer-url>` command that exchanges roots and identifies divergent
  ranges. Reconciliation algorithm MUST be RFC 9162 §2.1.4 consistent.

### 4.4 Acceptance gates

- `cargo test --features s3-replication` against `localstack`.
- `cargo test --features webhook-witness` against an in-process axum mock.
- Negative tests: invalid pin, expired retention, dropped network mid-PUT.

---

## 5. HSM Backends  *(closes C-3)*

### 5.1 TPM 2.0 (`tpm2` feature, REQUIRED for Production profile)

- **R5.1.** Implement `TpmKeyStore::{generate, sign, public_key}` over `tss-esapi`.
- **R5.2.** Keys MUST be persisted in NV with policy: `PolicyPCR(0,7)` over the
  measured boot state, plus `PolicyAuthValue`.
- **R5.3.** Provide a `keygen --backend tpm` CLI flow that: provisions an SRK,
  derives the signing key, prints the public key + KID, and writes a
  `tpm-attestation.cose` quoting the keys' creation PCRs.

### 5.2 Multi-party threshold

- **R5.4.** Add `keygen --threshold m-of-n` producing FROST-Ed25519 shares (use
  `frost-ed25519` crate). Document share distribution out-of-band.
- **R5.5.** Validator MUST accept signatures produced by an `m-of-n` aggregator
  identified by KID without code path divergence.

### 5.3 File backend in Production

- **R5.6.** `FileKeyStore` MUST refuse to load when the binary self-reports the
  Production profile and `bsl_level >= 3`, unless the operator passes
  `--accept-file-keys --reason=<S>`. Emit a loud audit warning.

### 5.4 Acceptance gates

- TPM tests behind `#[cfg(feature = "tpm2")]` using `swtpm` in CI (Linux only).
- FROST round-trip test producing a valid Ed25519 signature against a known
  public key.

---

## 6. Bio Invariant Calibration  *(closes C-1, C-2, H-4, H-5, M-5)*

### 6.1 Reference corpus (prerequisite)

- **R6.1.** A new repo `invariant-biosynthesis-reference-corpus` (private, hash-pinned)
  MUST contain at minimum:
  - 200 HHS Select Agent positives across DNA, peptide, chemical.
  - 1000 negatives drawn from non-pathogenic homologs and benign small molecules.
  - 50 codon-shuffled positives, 50 fragmented positives (split across 2-5 pieces),
    50 reverse-complement-only positives.
- **R6.2.** A SHA-256 manifest of the corpus is checked into this repo at
  `tests/corpus.manifest`. Calibration runs MUST verify the manifest.

### 6.2 Calibration framework  *(closes M-3)*

- **R6.3.** New module `invariant_biosynthesis_core::statistics` providing
  `clopper_pearson(successes, trials, conf)` and `mcnemar(a, b, c, d)`.
- **R6.4.** A new `invariant-bio calibrate <corpus>` subcommand MUST emit a
  JSON report with FN/FP point estimates and 95% Clopper–Pearson CIs per family.
- **R6.5.** Acceptance gate: D-family achieves **FN ≤ 1e-4 (95% CI upper bound)**
  and **FP ≤ 1e-3 (95% CI upper bound)** at the locked thresholds.

### 6.3 D-family upgrades

- **R6.6.** Replace hardcoded `k=5, jaccard >= 0.30` in
  [dna.rs:59-173](../crates/invariant-biosynthesis-core/src/invariants/dna.rs#L59-L173)
  with profile-tunable thresholds. Default values MUST come from §6.2 calibration.
- **R6.7. (D7)** Embed CUTG tables for `e_coli`, `s_cerevisiae`, `h_sapiens`,
  `cho_k1` via `include_str!`. Replace Shannon entropy with chi-squared GoF;
  verdict path: `Pass | Advisory(p<0.05) | Fail(p<0.001)`.
- **R6.8. (D9)** Behind `viennarna` feature, shell out to `RNAfold -p` and parse
  ΔG. Without the feature, D9 verdict downgrades to `Advisory` with reason
  `"viennarna feature not built"`.

### 6.4 P-family

- **R6.9.** Until calibrated predictors land, P6/P8/P9 verdicts MUST be capped at
  `Advisory`. The spec text in [docs/spec.md](spec.md) sections P6–P9 is updated
  to reflect this; a `KNOWN-LIMITATIONS.md` is added.
- **R6.10.** `netmhcpan-binding` and `tango-aggregation` feature flags are
  reserved (no implementation required this phase) and documented in
  [docs/step3-bio-invariants.md](step3-bio-invariants.md).

### 6.5 C-family (`rdkit-cheminformatics` feature)

- **R6.11.** Introduce a `Molecule` newtype wrapping a canonicalised SMILES.
  All C-invariants MUST take `&Molecule`, not `&str`.
- **R6.12.** Each of C1–C10 MUST have a SMARTS-backed implementation behind
  `rdkit-cheminformatics`. Without the feature: each C-invariant returns
  `Advisory` with reason `"rdkit feature not built"`.
- **R6.13.** Curated SMARTS pattern set (organophosphate G-/V-series, schedule-1
  CWC, opioid analogues, sulfur mustards, etc.) is checked in under
  `crates/invariant-biosynthesis-core/data/smarts/` with provenance citations.

### 6.6 Acceptance gates

- Calibration run produces `docs/CALIBRATION-REPORT.md` with the corpus hash,
  thresholds, and CIs.
- All C/D/P invariants list their dependency state in `verify-self` output.

---

## 7. Synthesizer Platform Adapters  *(closes C-7)*

### 7.1 Adapter contract

A new crate `invariant-biosynthesis-adapter` defines:

```rust
pub trait Synthesizer {
    fn vendor(&self) -> &'static str;
    fn issue_token(&self, intent: &Intent) -> Result<ExecutionToken>;
    fn submit(&self, token: &ExecutionToken, bundle: &Bundle) -> Result<JobId>;
    fn poll(&self, job: &JobId) -> Result<JobState>;
    fn fetch_attestation(&self, job: &JobId) -> Result<CoseSign1>;
}
```

Each adapter MUST pre-verify the execution-token signature before any network
call, and MUST refuse to submit if the bundle's verdict is not `Pass`.

### 7.2 Required first-wave adapters

- `adapter-twist` (DNA): HTTP REST against Twist's order API (mockable).
- `adapter-cem` (peptide): CEM Liberty Blue series control over their HTTP shim.
- `adapter-chemspeed` (chemical): Chemspeed AutoSuite over OPC-UA via `opcua` crate.

### 7.3 CLI

- **R7.1.** `invariant-bio issue-token --vendor=<NAME> --intent=<PATH>` MUST
  produce a signed execution token consumed by adapters.
- **R7.2.** Each adapter ships with one example profile in `profiles/` and 5
  integration tests against a mock vendor server.

---

## 8. Threat Model Refresh + Audit Readiness  *(closes H-7)*

- **R8.1.** Refresh [docs/threat-model.md](threat-model.md) to cover D10, S1, the
  k-mer screener, and the new opt-out flags. Add STRIDE row for "Operator silently
  disables stateful detector with empty reason".
- **R8.2.** Author `docs/AUDIT-READINESS.md` containing: build instructions,
  reproducible-build proof, full test inventory, supported features, known
  limitations, primitive + library versions, CycloneDX SBOM (regenerated in CI).
- **R8.3.** CI step `cargo sbom` produces `sbom.cdx.json`; PRs that change
  dependencies MUST update it.

---

## 9. Threat Scorer + Monitors + Incident Response  *(closes H-2, M-6)*

- **R9.1.** Default-on threat scorer per §1. CLI flag per §2.
- **R9.2.** New subcommand `invariant-bio monitor --interval-s <N> --sink <S>`
  invoking `MonitorAction` checks. Sinks MUST include at least: `stdout`,
  `file:<path>`, `webhook:<url>` (post-§4.2 wiring), `syslog` (Unix only).
- **R9.3.** Wire `IncidentResponder` into `Validator::validate_bundle` after
  verdict computation. Trigger conditions and severity mapping documented in
  [docs/step8-testing-validation.md](step8-testing-validation.md).
- **R9.4.** `AlertSink::Webhook` and `AlertSink::Syslog` MUST be implemented;
  `Unavailable` is no longer acceptable.

---

## 10. Audit, Replication, and PCA Hardening  *(closes M-7, H-6)*

- **R10.1.** New `BioProfile::max_authority_chain_depth: u32` (default 5).
  Validator MUST reject chains longer than this.
- **R10.2.** Persistent attestation nonce log MUST rotate on `--rotate-after-days`
  (default 90). Compaction emits a checkpoint record `{ "before": <ts>, "rejected_until": <ts> }`
  signed by the same KID; truncation deletes nonces older than `before`.
- **R10.3.** PCA chain serialization adds a `not_before` and `not_after` to each
  delegation; validator MUST check both against current time.

---

## 11. Performance Benchmarks  *(closes M-4)*

- **R11.1.** Add `benches/` to `invariant-biosynthesis-core` using `criterion`.
  Required benches: validator hot path (1k bundles), k-mer scan (10k 200-mer
  fragments), audit append (10k entries), PCA verify (1k chains depth-5).
- **R11.2.** Lock baseline numbers in `docs/PERFORMANCE.md` with hardware spec.
  CI MUST fail any bench >25% slower than baseline.

---

## 12. Differential Validation in Standard Flow  *(closes M-2)*

- **R12.1.** When `--differential <config>` is supplied, validator runs both
  configs and emits a `DifferentialReport { primary: Verdict, secondary: Verdict, divergences: Vec<Divergence> }`.
- **R12.2.** Any divergence in `Pass`/`Fail` outcome MUST escalate the final
  verdict to `Fail` with reason `"differential disagreement"`.
- **R12.3.** Divergence record is included in the audit entry.

---

## 13. Consensus Reporting  *(closes M-1)*

- **R13.1.** Replace the unstructured `String` disagreement label with:

```rust
pub struct ConsensusReport {
    pub sources: Vec<SourceVerdict>,   // (kid, verdict, latency_ms)
    pub policy: QuorumPolicy,           // Any | All | KofN(k, n)
    pub agreed: bool,
}
```

- **R13.2.** This report is included verbatim in the verdict's `evidence` field.

---

## 14. Profile Vocabulary Policy  *(closes L-1)*

- **R14.1.** Decide and document: the built-in 25-verb vocabulary in
  [protocol.rs:172-214](../crates/invariant-biosynthesis-core/src/invariants/protocol.rs#L172-L214)
  is a **global ceiling**. Profiles MAY restrict; profiles MAY NOT extend.
- **R14.2.** Add `docs/BUILT-IN-VOCAB.md` listing each verb, its semantics,
  the citation for the verb, and a stability promise (no removal without major
  version bump).

---

## 15. Disclosure / Governance / Export Control  *(closes L-2, L-3)*

- **R15.1.** Update `SECURITY.md` with explicit SLAs: 72h ack, 7d triage,
  30d patch for CRITICAL.
- **R15.2.** Add `docs/rfcs/0000-template.md` and `docs/rfcs/README.md`
  describing the RFC process for spec changes.
- **R15.3.** Add CI step (script in `xtask/export-control.rs`) that flags any
  dependency known to be EAR/ITAR-controlled. Policy documented in
  `docs/EXPORT-CONTROL.md`.

---

## 16. Test Coverage Gaps  *(closes Part-4 §9)*

The following test categories MUST exist (one or more tests per category):

- **Adversarial corpus tests**: fuzz crate gains a corpus driver consuming the
  reference corpus from §6.1.
- **Statistical regression tests**: `tests/statistical_regression.rs` runs
  calibration on a frozen subset and fails if FN/FP CIs widen.
- **Multi-instance integration tests**: two validators sharing a `StatefulStore`
  via Redis or a shared file; fragmentation chain split across them is detected.
- **End-to-end synthesizer-mock**: full token → bundle → submit → attestation
  flow against a per-vendor mock.
- **CLI flag coverage**: every flag added in §2 has both a happy-path and
  refusal-path test.

---

## 17. Acceptance Gates for "Production-Ready" Claim  *(closes X-3)*

The README, marketing, and spec MUST NOT claim "production-ready for synthesis"
until **all** of the following are ✅:

| # | Gate | Section gating it |
|---|------|------|
| 1 | Phase 2 closed | §4, §5, §9 |
| 2 | Reference set FN ≤ 1e-4 / FP ≤ 1e-3 with CIs | §6.1, §6.2 |
| 3 | Shadow-mode > 99% agreement on a real-traffic replay | §12 |
| 4 | At least one HSM backend in production | §5 |
| 5 | At least one synthesizer end-to-end | §7 |
| 6 | At least one jurisdiction's compliance report accepted | §18 |
| 7 | Stateful + consensus reachable from CLI, default-on for BSL ≥ 3 | §1, §2 |

Until all seven flip, the binary's `verify-self` MUST print
`PRODUCTION-READY: NO` with the failing gate list.

---

## 18. Compliance Crate (separate roadmap)

A new crate `invariant-biosynthesis-compliance` SHALL host jurisdiction-specific
report generators. This work is additive and **not** a prerequisite for any
gate above except 17.6.

- Reports: CDC Select Agent, NIH rDNA, FDA, USDA APHIS, EPA TSCA, CWC Schedule-1,
  Australia Group, Wassenaar, NIST AI RMF, ISO/IEC 42001.
- Auditor RBAC: read-only audit-accessor role with separate keypair, enforced at
  `audit query` time.
- Per-jurisdiction invariant variants: profile carries optional `jurisdiction:`
  tag; selected screener variants per jurisdiction.

---

## 19. Suggested Work Order

A pragmatic shippable sequence (dependencies in parentheses):

1. **§1, §2, §3** — single PR, no new deps, removes silent-degrade modes.
2. **§4** S3 + webhook replication, behind features.
3. **§5** TPM backend + threshold keygen.
4. **§6.1, §6.2** Reference corpus + calibration framework. Unblocks §6.3–§6.6.
5. **§6.3** D-family calibration; threshold lock.
6. **§7** First synthesizer adapter (Twist).
7. **§6.5** RDKit C-family integration.
8. **§8** Audit-readiness + threat-model refresh.
9. **§11** Benches + perf gates.
10. **§18** Compliance crate.

Estimated effort: ~8 weeks for items 1–5, ~6 months through item 10 to flip all
seven Production gates.

---

## 20. README Honesty Update  *(closes X-4)*

[README.md](../README.md) "Known gaps" list MUST be updated to include:

- Threat scorer wired but opt-in (until §1 lands).
- Stateful detector opt-in (until §1 lands).
- Consensus screener has no CLI surface (until §2 lands).
- Synthesizer adapters absent (until §7 lands).
- Attestation log unbounded (until §10.2 lands).
- HSM backends are stubs (until §5 lands).
- Replication backends are stubs (until §4 lands).

When a gate flips ✅, the corresponding bullet is removed in the same PR.

---

## 21. Out of Scope for This Spec

The following are intentionally **not** addressed here and remain TODO for a
future spec:

- Formal verification of the validator (TLA+/Coq).
- Hardware-attested measurement of the binary itself (DICE/RIM).
- Browser-based operator UI.
- Multi-tenant SaaS deployment model.

---

## 22. Change Log

- **2026-04-27** — initial draft, derived from Part-4 gap inventory after spot-verification of HSM/replication/validator-default/CLI-flags claims.

— end —
