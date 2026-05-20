> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Spec v6 — Gap Remediation Plan

**Date:** 2026-05-01
**Branch baseline:** `codelicious/spec-spec-gap-analysis-part-3-part-2`
**Test baseline:** 691 passing, `cargo clippy -- -D warnings` clean
**Predecessors:** `spec-gap-analysis-part-4.md` (gap inventory), `spec-v5-gap-closure.md` (D/C-family closure)

---

## How to use this document

Each numbered step below is written as a **standalone Claude Code prompt**. Open a new conversation (or `/clear`), paste the prompt verbatim, and let the agent work. Steps are ordered by priority — earlier steps unblock later ones.

Each step states:

- **Goal** — the outcome that defines success.
- **Context** — what the agent needs to know before starting (file paths, prior state).
- **Prompt** — the literal text to give Claude Code.
- **Acceptance** — what to check before moving on.

Do **not** run more than one step in parallel without reading the dependency notes — several steps touch `validator.rs` or `BioProfile`.

After every step: run `cargo test --workspace` and `cargo clippy -- -D warnings`, commit with a message of the form `[spec-v6 step-NN] <short summary>`.

---

## Tier 1 — Unblock & default-secure (start here)

### Step 1 — Split `allow_unimplemented_invariants` into two narrow knobs

**Goal:** Stop a single profile flag from simultaneously silencing stub invariants AND downgrading stale hazard-DB errors. Make stale-DB tolerance explicit and BSL-gated.

**Context:** [crates/invariant-biosynthesis-core/src/models/profile.rs](crates/invariant-biosynthesis-core/src/models/profile.rs) currently exposes `allow_unimplemented_invariants: bool` and (per memory) already exposes `allow_stale_screening` + `stale_screening_max_days`. The validator at [crates/invariant-biosynthesis-core/src/validator.rs](crates/invariant-biosynthesis-core/src/validator.rs) around lines 400–420 still treats `allow_unimplemented_invariants` as the gate for stale-DB downgrade. Confirm by reading both files first.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/models/profile.rs and crates/invariant-biosynthesis-core/src/validator.rs end to end. The profile field allow_unimplemented_invariants is currently overloaded: it silences stub invariants AND it downgrades a stale hazard database to an advisory. Separate these.

1. Confirm allow_stale_screening and stale_screening_max_days already exist on BioProfile; if not, add them (allow_stale_screening: bool default false; stale_screening_max_days: Option<u32>; required Some when allow_stale_screening is true).
2. In the validator, route stale-DB handling through allow_stale_screening only. Make allow_unimplemented_invariants control ONLY the stub-invariant pathway.
3. In BioProfile::validate, reject any profile where bsl_level >= 3 AND allow_stale_screening is true. Reject any profile where allow_stale_screening is true and stale_screening_max_days is None or > 30.
4. Update all six built-in profile JSON files under profiles/ so each declares allow_stale_screening explicitly (false for BSL>=3, false or true-with-cap for lower).
5. Add tests covering: (a) BSL=3 profile with allow_stale_screening=true is rejected, (b) BSL=2 profile with allow_stale_screening=true and max_days=30 validates, (c) stale DB with allow_stale_screening=false produces a Fail, with =true produces an Advisory.

Run cargo test --workspace and cargo clippy -- -D warnings. Commit as "[spec-v6 step-01] split stale-screening from unimplemented-invariants".
```

**Acceptance:** All six built-in profiles parse; new tests pass; no production profile (BSL>=3) can reach the stale-DB downgrade path.

---

### Step 2 — Surface five existing library features through the CLI

**Goal:** Expose threat-scorer threshold, quorum policy, attestation verification, attestation nonce log, and consensus-disagreement reporting as CLI flags on `invariant-bio validate`.

**Context:** Library code already implements all five features. The CLI in [crates/invariant-biosynthesis-cli/src/commands/validate.rs](crates/invariant-biosynthesis-cli/src/commands/validate.rs) does not expose them, so users silently get less safety than the library can provide.

**Prompt:**
```
Read crates/invariant-biosynthesis-cli/src/commands/validate.rs and the corresponding builder methods on Validator/ValidatorConfig in crates/invariant-biosynthesis-core/src/validator.rs and crates/invariant-biosynthesis-core/src/threat.rs and crates/invariant-biosynthesis-core/src/screening/mod.rs and crates/invariant-biosynthesis-core/src/attestation.rs.

Add these clap arguments to the validate subcommand:

  --threat-threshold <f64>           Enables the threat scorer with this score gate (0.0..=1.0). When omitted, behavior is unchanged for BSL<3 and threat scorer auto-wires for BSL>=3 (already implemented).
  --quorum-policy <all|majority|n:M> Selects the consensus quorum policy when one or more --hazard-db are provided. Default "all".
  --attest <path>                    Path to a signed AttestedInputEnvelope to verify alongside the bundle. May be repeated.
  --nonce-log <path>                 Path to the persistent attestation nonce log (created if absent). When omitted, in-memory only.
  --no-threat-scorer                 Explicit opt-out (overrides the BSL>=3 default-on). Refused for BSL>=3 unless --i-accept-the-risk is also passed; emit a stderr warning either way.

Wire each flag to the matching builder method. For --quorum-policy, parse "n:M" into QuorumPolicy::AtLeast { n, of: M }. For --attest, load and verify each envelope before validation begins; on signature failure abort with a non-zero exit code and a structured JSON error.

Add CLI integration tests under crates/invariant-biosynthesis-cli/tests/ covering: each flag's happy path, invalid quorum string is rejected, --no-threat-scorer without --i-accept-the-risk on a BSL=3 profile is rejected, --attest with a tampered envelope aborts.

Update README.md "CLI usage" section with the new flags. Run cargo test --workspace, cargo clippy -- -D warnings. Commit as "[spec-v6 step-02] expose threat/quorum/attest/nonce-log on validate CLI".
```

**Acceptance:** Five new flags appear in `invariant-bio validate --help`; integration tests pass; README is updated.

---

### Step 3 — Refresh threat model and write audit-readiness doc

**Goal:** Bring `docs/threat-model.md` up to date with the post-chunk-03/chunk-04 codebase (S1 stateful detector, D10, chemistry advisory engine), and create `docs/AUDIT-READINESS.md` describing the build, test inventory, feature matrix, crypto primitives, and known limitations for an external auditor.

**Context:** The current threat model predates the S1 detector and the chemistry advisory pipeline. There is no consolidated audit-readiness document.

**Prompt:**
```
Read these files completely: docs/threat-model.md, docs/spec.md, docs/spec-gap-analysis-part-4.md, docs/spec-v5-gap-closure.md, CLAUDE.md, README.md, crates/invariant-biosynthesis-core/src/lib.rs, crates/invariant-biosynthesis-core/src/invariants/stateful.rs, crates/invariant-biosynthesis-core/src/invariants/dna.rs (top of file + D10), crates/invariant-biosynthesis-core/src/invariants/chemical.rs (top of file).

Task A — refresh docs/threat-model.md:
- Add a section on cross-bundle fragmentation attacks and how the S1 FragmentationBypassDetector defends against them, including its in-memory-state limitation (no fleet coordination yet).
- Add a section on chemistry coverage: the heuristic SMILES engine is advisory-grade only; do not claim CWC-level assurance until a real cheminformatics backend lands.
- Add a section on D10 (uncalibrated k-mer homology screener) describing residual FN/FP risk.
- Add an "Open assumptions" subsection listing every place the system relies on operator discipline (single-firewall deployments, file-based key storage, local-only audit log, etc.).

Task B — create docs/AUDIT-READINESS.md with these sections:
1. Scope and version (commit hash, branch, test count, clippy status)
2. Build instructions (rust-toolchain.toml pin, cargo build/test/clippy commands)
3. Crate inventory and module-level responsibilities
4. Cryptographic primitives inventory (Ed25519, SHA-256, COSE_Sign1) with the crate name and version providing each
5. Invariant coverage matrix (D1..D10, P1..P10, C1..C10, PR1..PR4, S1) — for each: implemented / advisory-only / stubbed, and the file:line where its main logic lives
6. CLI feature matrix (subcommands and flags as of this commit)
7. Known limitations (lift from this gap-remediation spec; group by severity)
8. Sensitive operations checklist (key handling, network calls, file writes, environment variables)
9. Reproducible-build notes (deny.toml, supply-chain considerations)

Do not invent capabilities or numbers — verify each claim against the source. Where the source contradicts a previously-published claim, fix the doc.

No code changes; documentation only. Commit as "[spec-v6 step-03] refresh threat model and add audit-readiness doc".
```

**Acceptance:** `docs/threat-model.md` mentions S1, D10, chemistry advisory; `docs/AUDIT-READINESS.md` exists with all nine sections grounded in current code.

---

## Tier 2 — Core capability completeness

### Step 4 — Build the D-family reference corpus and calibrate D1–D6

**Goal:** Produce a curated reference corpus (HHS Select-Agent positives + known negatives + codon-shuffled variants) under `corpora/dna/`, then publish Clopper–Pearson FN/FP bounds for the D1–D6 k-mer screener at the configured `(k, jaccard_threshold)`.

**Context:** D1–D6 use a 3-frame + reverse-complement protein k-mer engine in [crates/invariant-biosynthesis-core/src/invariants/dna.rs](crates/invariant-biosynthesis-core/src/invariants/dna.rs) with `k=5` and Jaccard >= 0.30. There is no published acceptance gate. Without calibration, no production correctness claim is possible.

**Prompt:**
```
This is a research-style task with three phases.

Phase 1 — corpus construction. Create corpora/dna/ with three subdirectories:
  positives/   sequences (FASTA) drawn from HHS Select-Agent regulated organisms. Use only public sources (NCBI, GenBank); record accession + URL + retrieval date in a manifest.json next to each file.
  negatives/   sequences (FASTA) drawn from common laboratory hosts (E. coli K-12, S. cerevisiae S288C, GFP, lacZ, etc.) plus randomly-generated synthetic DNA matched for length distribution. Same manifest format.
  shuffled/    each positive re-encoded with a synonymous codon shuffle (preserving the protein sequence). Document the shuffler in a tools/codon_shuffle.rs binary (or python script under tools/).

Aim for >= 100 positives, >= 200 negatives, and one shuffled variant per positive. Add a README explaining how the corpus was built and how to regenerate it.

Phase 2 — calibration harness. Add a new bench/integration target crates/invariant-biosynthesis-core/tests/dna_calibration.rs that loads the corpus, runs the existing KmerHomologyEngine over each sequence with current settings, and emits a JSON report containing TP/FP/TN/FN counts plus a 95% Clopper–Pearson confidence interval on FNR and FPR. Use the statrs crate for the binomial CIs. Gate the test behind a #[ignore] attribute so it does not run in default cargo test (it is slow); document the explicit invocation in the README.

Phase 3 — publication. Write docs/calibration/D-family-2026-05.md with: corpus stats, the (k, threshold) grid you swept, the chosen operating point, the resulting CIs, and an honest statement of whether the spec's FN<=1e-4 / FP<=1e-3 acceptance gate is met. If not met, list what would close the gap (larger corpus, different k, alternative engine).

Do not modify the existing engine in this step; only measure it. If you discover the engine is mis-implemented, write up findings in the calibration doc and stop — fixing the engine is a separate step.

Run cargo test --workspace excluding the ignored calibration test. Commit each phase separately: "[spec-v6 step-04a] DNA corpus", "[spec-v6 step-04b] calibration harness", "[spec-v6 step-04c] D-family calibration report".
```

**Acceptance:** `corpora/dna/` populated with manifest; `cargo test --ignored dna_calibration` runs end-to-end; calibration doc reports concrete FN/FP CIs.

---

### Step 5 — Implement D7 chi-squared codon-usage test against CUTG tables

**Goal:** Replace the current Shannon-entropy-only D7 check with a proper goodness-of-fit chi-squared test against host codon-usage tables (per CLAUDE.md, table tables for `e_coli`, `s_cerevisiae`, `h_sapiens`, `cho_k1` are already partially in place; verify and finish).

**Context:** [crates/invariant-biosynthesis-core/src/invariants/dna.rs](crates/invariant-biosynthesis-core/src/invariants/dna.rs) D7. Memory says CUTG tables are already wired; verify and finish if incomplete. Profile field `codon_usage_organism` exists.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/dna.rs (D7 section) and crates/invariant-biosynthesis-core/src/models/profile.rs (codon_usage_organism field). Memory indicates CUTG-based chi-squared is already implemented; verify by reading the code and tests.

If the chi-squared GoF test is fully implemented for all four organisms and gated as Pass/Advisory(p<0.05)/Fail(p<0.001):
  - Confirm with a test pass listing
  - Add a one-line note to docs/AUDIT-READINESS.md confirming D7 calibration source (CUTG release date)
  - Commit nothing if no changes needed; otherwise commit doc-only.

If anything is missing (table not embedded, statistical test absent, verdict thresholds wrong, organism unsupported):
  - Embed CUTG tables for the missing organisms via include_str! from data/codon-usage/<organism>.tsv
  - Implement the chi-squared GoF test using statrs::distribution::ChiSquared
  - Verdict: Pass when p>=0.05; Advisory when 0.001<=p<0.05; Fail when p<0.001
  - Add tests covering each organism: a known-host gene (Pass), a randomly-codon-permuted version (Advisory or Fail), and an obviously-mismatched gene (Fail)
  - Update docs/AUDIT-READINESS.md
  - Commit as "[spec-v6 step-05] D7 CUTG chi-squared GoF".

Run cargo test --workspace and cargo clippy -- -D warnings.
```

**Acceptance:** D7 either is or becomes a real chi-squared GoF check; tests cover all four supported organisms.

---

### Step 6 — Make S1 mandatory at BSL>=3 and add a pluggable StatefulStore

**Goal:** (a) Reject `BioProfile`s with `bsl_level >= 3` that disable the fragmentation detector at validation time, with no escape hatch other than the audited `with_stateful_detector_bypass(reason)` method. (b) Refactor the in-memory state into a `StatefulStore` trait so multi-instance deployments can share state.

**Context:** [crates/invariant-biosynthesis-core/src/invariants/stateful.rs](crates/invariant-biosynthesis-core/src/invariants/stateful.rs) holds in-memory sliding-window state. [crates/invariant-biosynthesis-core/src/validator.rs](crates/invariant-biosynthesis-core/src/validator.rs) `ValidatorConfig::without_stateful_detector` already errors for BSL>=3 (per memory) — verify, and extend coverage.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/stateful.rs and the stateful-related code in crates/invariant-biosynthesis-core/src/validator.rs. Read crates/invariant-biosynthesis-core/src/models/profile.rs.

Task A — defaults audit. Confirm:
  1. ValidatorConfig::new sets stateful_detector to Some(default). If not, fix.
  2. without_stateful_detector returns an Err for any BSL>=3 profile. If not, fix.
  3. with_stateful_detector_bypass(reason) is the only escape hatch and emits a stderr warning at every validate() call. If not, fix.
  4. Add a test asserting that a BSL=4 profile with the bypass set still emits the warning and records the reason in the audit log entry.

Task B — pluggable store. Define a new trait in crates/invariant-biosynthesis-core/src/invariants/stateful.rs:

  pub trait StatefulStore: Send + Sync {
      fn record(&self, key: &str, fragment: FragmentRecord) -> Result<(), StatefulStoreError>;
      fn recent(&self, key: &str, window: Duration) -> Result<Vec<FragmentRecord>, StatefulStoreError>;
      fn purge_expired(&self, older_than: Duration) -> Result<usize, StatefulStoreError>;
  }

Provide two implementations:
  InMemoryStatefulStore (default; what exists today, refactored behind the trait)
  FileStatefulStore (append-only JSONL with periodic compaction; path configurable)

Wire both into FragmentationBypassDetector::with_store(...). Default constructor stays in-memory for backward compatibility. Add a CLI flag --stateful-store <path> on the validate subcommand that selects the file-backed store.

Do NOT add a Redis backend in this step; leave a TODO documenting it as a follow-up.

Add tests for FileStatefulStore: write/read roundtrip, two processes appending concurrently (use a file lock), purge_expired removes only expired entries, corrupted JSONL line is logged-and-skipped not panicked.

Run cargo test --workspace, cargo clippy -- -D warnings. Commit as "[spec-v6 step-06] S1 BSL>=3 enforcement and pluggable StatefulStore".
```

**Acceptance:** No BSL>=3 profile can reach validation with the detector silently disabled; file-backed store passes concurrency tests.

---

### Step 7 — Auto-wire the threat scorer for BSL>=3 and ship a `monitor` subcommand

**Goal:** Per memory, the threat scorer is already auto-wired for BSL>=3. Verify, then add a `monitor` CLI subcommand that runs the existing runtime monitors (defined in [crates/invariant-biosynthesis-core/src/monitors.rs](crates/invariant-biosynthesis-core/src/monitors.rs)) on a schedule.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/threat.rs, crates/invariant-biosynthesis-core/src/monitors.rs, and crates/invariant-biosynthesis-cli/src/main.rs.

Phase 1 — verify threat scorer auto-wiring for BSL>=3 profiles. Add a test in crates/invariant-biosynthesis-core/tests/ asserting that ValidatorConfig::new with a BSL=3 profile yields a non-None threat_scorer and one with BSL=2 yields None unless explicitly enabled. Fix any divergence.

Phase 2 — design the monitor subcommand. It should:
  - Take --interval <duration> (default 60s), --audit-log <path>, --alert-sink <stderr|file:PATH|syslog|webhook:URL> (repeatable).
  - Loop running each MonitorCheck from monitors.rs at the interval, writing structured findings to every alert sink.
  - Exit cleanly on SIGINT/SIGTERM.
  - For sinks not yet implemented (syslog, webhook), abort at startup with a clear "not yet implemented" message rather than silently dropping alerts.

Implement only the stderr and file sinks in this step; leave syslog and webhook returning a startup error (not a runtime failure). Document the unimplemented sinks in the help text.

Add an integration test that runs `invariant-bio monitor --interval 100ms --audit-log <tempfile> --alert-sink file:<tempfile>` for ~500ms in a child process and asserts the alert file contains structured JSON findings.

Update README.md to document the new subcommand. Run cargo test --workspace, cargo clippy -- -D warnings. Commit as "[spec-v6 step-07] threat scorer default-on for BSL>=3 and monitor subcommand".
```

**Acceptance:** `invariant-bio monitor --help` exists; stderr and file sinks work; integration test passes.

---

## Tier 3 — Long-horizon items (each is a multi-week project; treat each as its own milestone)

These steps are written so a single Claude Code conversation can scope them, but the actual implementation will likely span many sessions. Each prompt asks the agent to produce a **design proposal first**, then implement in tracked sub-steps.

### Step 8 — Real cheminformatics backend for the C-family

**Context:** [crates/invariant-biosynthesis-core/src/invariants/chemical.rs](crates/invariant-biosynthesis-core/src/invariants/chemical.rs) is regex-on-SMILES today. Memory notes: heuristic engine, no SMARTS parser, no canonicalization.

**Prompt:**
```
Phase 0 — produce a design doc, do not write production code yet.

Read crates/invariant-biosynthesis-core/src/invariants/chemical.rs end to end. Read crates/invariant-biosynthesis-core/src/invariants/molecule.rs if present. Read docs/step3-bio-invariants.md (C1..C10 sections) and docs/threat-model.md (chemistry sections).

Write docs/design/chemistry-backend.md proposing the integration. The doc must answer:

  1. Library choice. Compare options for Rust integration: (a) RDKit via FFI (rdkit-sys crate, maturity, license), (b) OpenBabel FFI, (c) chemcore / pure-Rust crates, (d) shell out to a sidecar Python process. Recommend one with concrete tradeoffs (license, build complexity, platform support, performance).
  2. Scope of integration. Which C-family invariants need true cheminformatics (canonicalization, SMARTS matching, descriptor calculation) vs. which can stay heuristic? Be explicit about C1, C2, C3, C4, C5, C6, C7, C8, C9, C10 individually.
  3. Feature-flag plan. The chosen library should be optional (cargo feature) so the default build remains pure-Rust and offline-buildable. Define the feature name, the modules that gain functionality when enabled, and the fallback behavior when disabled.
  4. Data assets. Where does the SMARTS rule library live? How is it versioned, signed, and updated? Reuse the existing HazardDatabase signing approach if possible.
  5. Calibration plan. How do we measure FN/FP against a CWC + EPA Toxic Release Inventory reference set? Mirror the dna_calibration harness from step 4.
  6. Phased delivery. Break the work into numbered sub-steps, each <= 1 week, each independently testable.

Stop after the design doc; do not start the implementation. Commit as "[spec-v6 step-08] chemistry backend design doc".

A follow-up conversation will implement the phases listed in the doc.
```

**Acceptance:** A reviewable design doc lands. Implementation happens in subsequent conversations driven by the doc.

---

### Step 9 — TPM 2.0 and YubiHSM key-store backends

**Context:** [crates/invariant-biosynthesis-core/src/keys.rs](crates/invariant-biosynthesis-core/src/keys.rs) `TpmKeyStore` and `YubiHsmKeyStore` return `Unavailable`. File-backed keys work today.

**Prompt:**
```
Phase 0 — produce a design doc, do not write production code yet.

Read crates/invariant-biosynthesis-core/src/keys.rs end to end and docs/step7-hsm-key-mgmt.md.

Write docs/design/hsm-backends.md proposing the implementation. Cover:

  1. Crate selection and licensing. tss-esapi for TPM 2.0; yubihsm crate for YubiHSM 2. Both behind cargo features. Pin minimum versions; check license compatibility (deny.toml).
  2. Key hierarchy mapping. Map the L0..L5 hierarchy from step7-hsm-key-mgmt.md onto TPM persistent handles and YubiHSM key IDs. Be explicit about which levels live in which backend.
  3. Test strategy. TPM tests need either a real device or the swtpm simulator; YubiHSM has yubihsm-connector --inMemory. Document how CI runs each (likely behind a separate test target gated on env var).
  4. Threshold ceremony. Spec out a multi-party signing ceremony for L0/L1 keys (m-of-n using FROST or similar). Identify the smallest acceptable v1 (e.g., 2-of-3 with manual coordination) and defer larger schemes.
  5. Rotation. Design the overlap-key window and the audit-log record format that proves rotation happened.
  6. Phased delivery. Numbered sub-steps, each <= 1 week. Recommend starting with TPM (more widely deployed than YubiHSM).

Stop after the design doc. Commit as "[spec-v6 step-09] HSM backends design doc".
```

---

### Step 10 — Replication backends (S3 + webhook witness + Merkle reconciliation)

**Context:** [crates/invariant-biosynthesis-core/src/replication.rs](crates/invariant-biosynthesis-core/src/replication.rs). FileReplicator works; S3Replicator and WebhookWitness return Unavailable.

**Prompt:**
```
Phase 0 — design doc only.

Read crates/invariant-biosynthesis-core/src/replication.rs and crates/invariant-biosynthesis-core/src/audit.rs.

Write docs/design/replication-backends.md covering:

  1. S3 backend. aws-sdk-s3 vs object_store crate. Authentication options (IAM role, static credentials, OIDC). Object naming scheme for audit log entries. Retry policy and idempotency. Whether to support S3-compatible endpoints (MinIO, R2).
  2. Webhook witness. POST schema, retry/backoff, deduplication, signing of outbound payloads (so a witness can verify the source).
  3. Merkle witness protocol. RFC 9162-style. Define the tree structure, the published-head schema, the cross-instance gossip protocol (or pull-based check) that detects a fork. Specify divergence-detection thresholds and the response (alert, block validation, etc.).
  4. Local-to-remote sync. How does an instance recover after a network partition? Catch-up batching strategy.
  5. Phased delivery. Numbered sub-steps, each <= 1 week.

Stop after the design doc. Commit as "[spec-v6 step-10] replication backends design doc".
```

---

### Step 11 — Synthesizer-platform adapter framework + three reference adapters

**Context:** [docs/step5-platform-integration.md](docs/step5-platform-integration.md) names many vendors. No adapters exist today.

**Prompt:**
```
Phase 0 — design doc only.

Read docs/step5-platform-integration.md, docs/spec.md (platform-integration sections), and crates/invariant-biosynthesis-core/src/attestation.rs.

Write docs/design/platform-adapters.md proposing:

  1. Workspace layout. Should adapters live in a new crate (invariant-biosynthesis-platform) with submodules per vendor, or one crate per vendor? Recommend one and justify (license-segregation? release cadence?).
  2. Platform trait. Define the trait that every adapter implements: at least submit_order, fetch_status, attest_run. Specify how vendor-specific extensions are surfaced.
  3. Reference adapters. Pick three vendors that span DNA / peptide / chemical synthesis. For each, document: API surface, authentication model, attestation hook, known limitations. Recommended starters: Twist (DNA, mature REST API), CEM Liberty Blue (peptide, vendor SDK), Chemspeed (chemistry, OPC UA).
  4. Attestation provisioning. How is the vendor's signing key bound to the platform identity? Reuse the existing PCA chain or a parallel CA?
  5. issue-token CLI subcommand spec.
  6. Phased delivery. One adapter at a time, each <= 4 weeks.

Stop after the design doc. Commit as "[spec-v6 step-11] platform adapters design doc".
```

---

## Tier 4 — Operational maturity

### Step 12 — Structured consensus disagreement reporting

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/screening/mod.rs (consensus path) and the verdict types in crates/invariant-biosynthesis-core/src/models/verdict.rs.

Today, when consensus screening sources disagree, the disagreement is encoded as a string label. Replace this with a structured ConsensusReport:

  pub struct ConsensusReport {
      pub policy: QuorumPolicy,
      pub sources: Vec<SourceVerdict>,
      pub agreed: bool,
      pub majority_verdict: Option<HazardVerdict>,
  }

Embed ConsensusReport on the appropriate hit type. Update serializers, displays, and tests. Confirm the JSON schema change is documented in docs/AUDIT-READINESS.md.

Run cargo test --workspace, cargo clippy -- -D warnings. Commit as "[spec-v6 step-12] structured consensus report".
```

---

### Step 13 — Differential validation as a CLI flag

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/differential.rs and crates/invariant-biosynthesis-cli/src/commands/validate.rs.

Add --differential <secondary-config-path> to the validate subcommand. When set, the validator runs the bundle through both the primary configuration and a secondary configuration loaded from the path; on disagreement, emit a structured DifferentialReport and escalate the verdict to Fail; on agreement, emit DifferentialReport at info level.

Add tests: agreement, value disagreement, secondary-config load failure (must abort, not silently proceed).

Update README.md. Run cargo test --workspace, cargo clippy -- -D warnings. Commit as "[spec-v6 step-13] differential validation CLI flag".
```

---

### Step 14 — Statistics module (Clopper–Pearson, agreement metrics)

**Prompt:**
```
Add a new module crates/invariant-biosynthesis-core/src/statistics.rs exposing:

  pub fn clopper_pearson(successes: u64, trials: u64, confidence: f64) -> (f64, f64)
  pub fn cohen_kappa(...) -> f64
  pub fn fleiss_kappa(...) -> f64

Use the statrs crate (or implement against the regularized incomplete beta function — pick whichever keeps the dependency tree smaller). Add property tests using proptest comparing against scipy reference values (committed as fixtures, not invoked at runtime).

Wire clopper_pearson into the dna_calibration test from step 4 if it is using a hand-rolled formula. Commit as "[spec-v6 step-14] statistics module".
```

---

### Step 15 — Performance benchmarks and baseline

**Prompt:**
```
Add benches/ directories under crates/invariant-biosynthesis-core and configure criterion in the workspace Cargo.toml.

Write benchmarks for:
  - validator end-to-end on a representative bundle (small, medium, large)
  - KmerHomologyEngine on 10kb DNA
  - SMILES screener on 10k-molecule batch
  - audit-log append + verify on 100k entries

Run the benchmarks on the current commit, capture results in docs/PERFORMANCE.md as the v6 baseline (include host CPU, OS, rustc version).

Document the invocation in README.md. Do not gate CI on benchmark times yet. Commit as "[spec-v6 step-15] performance benchmarks and baseline".
```

---

### Step 16 — Attestation nonce-log rotation

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/attestation.rs (persistent nonce log section).

Today the nonce log grows unbounded. Add time-windowed rotation:

  - On each append, if the current segment is older than rotation_window (default 90 days) or larger than max_segment_bytes (default 64 MiB), seal it with a checkpoint summary ("all nonces in segment <id> are rejected") and start a new segment.
  - Verification consults the active segment plus all sealed checkpoints; full rejected-nonce sets in sealed segments may be dropped from memory once the checkpoint is verified.
  - Add tests: rotation triggers at the right thresholds; verification still rejects an old nonce after rotation; corrupted segment is detected at startup.

Run cargo test --workspace, cargo clippy -- -D warnings. Commit as "[spec-v6 step-16] attestation nonce-log rotation".
```

---

### Step 17 — Incident-responder wiring + alert sinks

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/incident.rs.

Wire the incident responder into the validator's post-verdict path: any Fail verdict at BSL>=3, any S1 fragmentation hit, and any consensus disagreement should fire an Incident. Each Incident must include: verdict ID, audit-log entry hash, severity, one-line summary.

Implement two sinks:
  - SyslogSink (using the syslog crate; behind cargo feature "syslog")
  - WebhookSink (using reqwest with rustls; behind cargo feature "webhook")

For tests, provide an InMemorySink. Add tests that simulate a Fail verdict and assert the InMemorySink received the expected Incident. Document the new features in README.md.

Commit as "[spec-v6 step-17] wire incident responder, syslog and webhook sinks".
```

---

### Step 18 — Bound PCA chain depth in profile and validator

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/authority/chain.rs and crates/invariant-biosynthesis-core/src/models/profile.rs.

Memory says max_authority_chain_depth is already on BioProfile (default 5, max 16) and is declared in all six built-in profiles. Verify by reading the code and the JSON files. If true, add an integration test asserting that a chain exceeding the profile's depth is rejected at validate time, and update docs/AUDIT-READINESS.md to mention the bound. If anything is missing, finish the implementation.

Run cargo test --workspace, cargo clippy -- -D warnings. Commit only if changes were needed.
```

---

### Step 19 — D9 secondary structure: ViennaRNA integration (feature-flagged)

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/dna.rs (D9 section).

Add an optional cargo feature "vienna-rna" that, when enabled, calls out to the RNAfold binary (or ViennaRNA Rust bindings if a maintained crate exists) to compute minimum-free-energy ΔG for the candidate sequence. When the feature is disabled, D9 keeps its current rolling-hash heuristic but emits an Advisory check noting that real ΔG was not computed. When the feature is enabled and RNAfold is missing at runtime, the validator must fail closed with a clear error, not silently fall back.

Add tests: feature disabled (heuristic + advisory), feature enabled with mocked RNAfold binary in PATH, feature enabled with binary absent (fail-closed).

Document installation of ViennaRNA in README.md. Commit as "[spec-v6 step-19] D9 ViennaRNA feature".
```

---

### Step 20 — P-family honesty: downgrade or integrate predictors

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/peptide.rs (P6, P8, P9 sections).

P6 (MHC binding), P8 (aggregation), P9 (PTM) currently use heuristics that the spec presents as production-grade checks. Pick one of two paths and update both code and spec accordingly:

PATH A — downgrade. Mark P6/P8/P9 as Advisory-only across the verdict pipeline. Update docs/step3-bio-invariants.md to state explicitly that these are advisory pending real predictor integration. No new dependencies.

PATH B — integrate. Add cargo features "netmhcpan" (P6) and "tango" (P8) wrapping the respective external tools, with the same fail-closed-when-missing pattern as step 19. P9 stays heuristic until a structural-context predictor is added.

The user has not yet chosen a path. In your response, summarize the tradeoffs in 100 words and ASK the user to choose before writing any code.
```

---

### Step 21 — PR2 vocabulary policy decision

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/protocol.rs (PR2 section) and crates/invariant-biosynthesis-core/src/models/profile.rs.

Today profiles can restrict the built-in 25-verb whitelist but not extend it. This is either a deliberate safety ceiling or an artificial limit. Two options:

  A. Keep the ceiling, document explicitly in docs/step3-bio-invariants.md that profiles may only narrow the vocab.
  B. Allow profiles to add custom verbs, with each addition signed by an authority key whose scope includes "protocol-vocab-extension".

The user has not yet chosen. Summarize the tradeoffs in 80 words and ASK before writing any code.
```

---

### Step 22 — Responsible-disclosure SLA and RFC template

**Prompt:**
```
Update SECURITY.md to add explicit triage and fix SLA timelines. Recommended starting values: acknowledge within 3 business days; triage within 7 business days; high-severity fix within 30 days; medium within 90 days. Document the contact channel (security@... — if none exists, use the user's hi@claygood.com noted in user memory, but ASK first before publishing a personal email in a public file).

Create docs/rfcs/0000-template.md with sections: Summary, Motivation, Detailed design, Drawbacks, Alternatives, Unresolved questions, Adoption checklist.

Run no tests. Commit as "[spec-v6 step-22] disclosure SLA and RFC template".
```

---

### Step 23 — Export-control CI guard

**Prompt:**
```
Read deny.toml and the existing CI configuration (.github/workflows/ if present).

Add a deny.toml entry or a separate CI step that flags any new dependency whose name or category suggests export-control concern (cryptography listed under EAR ECCN 5D002, dual-use software). The check should be advisory at first (emit warnings, not failures) and write its findings to docs/EXPORT-CONTROL.md as a living inventory.

Author docs/EXPORT-CONTROL.md describing the project's export-control posture, the ECCN classifications considered, and the rationale for deeming distribution permissible (or not).

Commit as "[spec-v6 step-23] export-control CI guard and posture doc".
```

---

## Dependency map

```
step-01 (split flags) ──┬── step-02 (CLI surface)
                        └── step-03 (audit-readiness)

step-04 (corpus) ──── step-05 (D7 chi-sq) ──── step-14 (statistics)

step-06 (S1 store) ── independent
step-07 (monitor)  ── after step-02

step-08 (chemistry) ─ independent (long horizon)
step-09 (HSM)       ─ independent (long horizon)
step-10 (replication) ─ independent (long horizon)
step-11 (platforms) ─ independent (long horizon)

step-12..23 — start any time after step-01..03
```

## Definition of done for spec v6

All of the following must be true to declare v6 complete:

1. Steps 1–7 and 12–18 are merged.
2. Steps 8, 9, 10, 11 each have a published design doc (implementation may continue beyond v6).
3. Steps 19, 20, 21 — user has chosen path A or B for each.
4. `docs/AUDIT-READINESS.md` reflects the merged state.
5. `cargo test --workspace` and `cargo clippy -- -D warnings` are clean.
6. The README's CLI usage section matches `invariant-bio --help` output.
