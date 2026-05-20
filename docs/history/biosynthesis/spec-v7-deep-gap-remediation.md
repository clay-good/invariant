> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Spec v7 — Deep Gap Remediation Plan

**Date:** 2026-05-01
**Branch baseline:** `codelicious/spec-spec-gap-analysis-part-3-part-2`
**Test baseline:** 691 passing; `cargo clippy -- -D warnings` clean
**Predecessors:**
- [spec-gap-analysis-part-4.md](spec-gap-analysis-part-4.md) — gap inventory
- [spec-v5-gap-closure.md](spec-v5-gap-closure.md) — D-family / C-family closure
- [spec-v6-gap-remediation.md](spec-v6-gap-remediation.md) — 23-step remediation plan dated 2026-05-01 (most steps not yet executed)

---

## How to use this document

This spec is the result of a fresh end-to-end gap analysis comparing **all** existing specs against the **current** code (post-chunk-04 C-family commit). It deliberately overlaps with v6 in places — when both documents describe the same fix, treat **v7 as authoritative** because it reflects code state on the day of writing. Where v7 references v6 by step number, the work in question is unchanged and you can cross-reference for additional context.

Each numbered step below is written as a **standalone Claude Code prompt**. Open a new conversation (or `/clear`), paste the prompt verbatim, and let the agent work. Steps are ordered by priority — earlier steps unblock later ones.

Each step states:

- **Goal** — the outcome that defines success.
- **Context** — what the agent needs to know before starting (file paths, prior state, dependencies).
- **Prompt** — the literal text to give Claude Code (no code snippets — Claude Code writes the code).
- **Acceptance** — what to check before moving on.
- **Severity / Effort** — Critical / High / Medium / Low; XS (<2h) / S (½ day) / M (1–2 days) / L (1+ week) / XL (multi-week + external deps).

Do **not** run more than one step in parallel without reading the dependency notes — several steps touch `validator.rs`, `BioProfile`, or the same CLI command file.

After every step: run `cargo test --workspace` and `cargo clippy -- -D warnings`. Commit per step using the message form `[spec-v7 step-NN] <short summary>`.

---

## Headline findings

The codebase is architecturally mature (5 crates, 691 tests, clean clippy, 34 invariants wired) but **is not production-ready**. Seven critical issues block any "production" claim:

1. **Chemical cheminformatics is regex/string-matching only** — no Molecule type, no SMARTS parser, no canonicalization. C1–C10 are advisory-only.
2. **Homology k-mer screener is uncalibrated** — D1–D10 verdicts have no published FN/FP statistical bounds.
3. **HSM backends are stubs** — only file-backed Ed25519 keys work in practice.
4. **Audit replication backends are stubs** — single-host audit log = single point of audit-trail loss.
5. **Stateful fragmentation detector is process-local** — fleet deployments cannot detect cross-instance fragmentation.
6. **Synthesizer-platform adapters do not exist** — there is no end-to-end path from firewall to a real synthesizer.
7. **Acceptance gates for the "production-ready" claim remain unmet** — README must not advertise production readiness until they flip.

A second tier of HIGH-severity gaps centers on **CLI feature reachability** (five library features silently unavailable through `invariant-bio validate`), **audit-readiness documentation absence**, and **structured consensus reporting**.

---

## Status snapshot of each spec dimension

| Dimension | State | Reference |
|---|---|---|
| D-family invariants (D1–D10) | Heuristic; D7 chi-squared partial; uncalibrated | [step-04](#step-4--build-the-d-family-reference-corpus-and-calibrate-d1d6) |
| P-family invariants (P1–P10) | P1–P5, P7, P10 implemented; P6/P8/P9 heuristic | [step-19](#step-19--decide-and-execute-p6p8p9-policy) |
| C-family invariants (C1–C10) | Regex-only stubs with advisory engine status | [step-08](#step-8--introduce-real-cheminformatics-backend-feature-gated) |
| Protocol invariants (PR1–PR4) | Implemented; PR2 vocab versioning underspecified | [step-21](#step-21--decide-pr2-vocabulary-extension-policy) |
| Stateful (S1) | Default-on; process-local only | [step-06](#step-6--add-stateful-store-trait-and-file-backed-store) |
| Authority / PCA chains | Implemented; depth bound declared but enforcement VERIFY | [step-17](#step-17--verify-and-test-pca-chain-depth-enforcement) |
| Audit hash chain | Implemented; replication stubbed | [step-09](#step-9--implement-s3-replicator-and-webhook-witness-feature-gated) |
| Attestation (COSE_Sign1) | Envelope types implemented; nonce log unbounded | [step-15](#step-15--rotate-the-attestation-nonce-log) |
| Threat scorer | 5 detectors; auto-wired BSL≥3 in lib; CLI surface incomplete | [step-02](#step-2--surface-five-existing-library-features-through-the-cli) |
| Screening / consensus | Implemented; disagreement is unstructured | [step-11](#step-11--structure-consensus-disagreement-as-a-typed-report) |
| Watchdog / heartbeat | Implemented | (no remediation needed) |
| Incident response | Defined but not wired to validator | [step-16](#step-16--wire-incident-responder-into-validator-post-verdict-path) |
| HSM / key mgmt | File-backed only; TPM/YubiHSM stubs | [step-07](#step-7--implement-tpm-and-yubihsm-key-stores-feature-gated) |
| Synthesizer adapters | None | [step-10](#step-10--implement-three-reference-synthesizer-adapters) |
| CLI completeness | Five features unreachable | [step-02](#step-2--surface-five-existing-library-features-through-the-cli) |
| Statistical validation | No Clopper–Pearson, no kappa | [step-13](#step-13--add-statistics-module-clopperpearson--kappa) |
| Performance benchmarks | None | [step-14](#step-14--add-criterion-benchmarks-and-baseline-doc) |
| Differential validation | Lib exists; not wired to `validate` flow | [step-12](#step-12--wire-differential-validation-into-the-validate-subcommand) |
| Audit-readiness doc | Missing | [step-03](#step-3--refresh-threat-model-and-write-audit-readiness-doc) |
| RFC / SLA / export-control | Missing | [step-22](#step-22--add-responsible-disclosure-sla-and-rfc-template), [step-23](#step-23--add-export-control-posture-and-ci-guard) |
| Acceptance gate tracking | No machine-checked gate ledger | [step-05](#step-5--introduce-a-machine-checked-acceptance-gate-ledger) |

---

# Tier 1 — Default-secure & unblock (start here)

These steps remove footguns or silent-downgrade paths and make existing safety reachable.

---

### Step 1 — Split `allow_unimplemented_invariants` into two narrow knobs

**Goal:** Stop a single profile flag from simultaneously silencing stub invariants AND downgrading stale hazard-DB errors. Make stale-DB tolerance explicit and BSL-gated.

**Severity / Effort:** Critical / S.

**Context:** [crates/invariant-biosynthesis-core/src/models/profile.rs](crates/invariant-biosynthesis-core/src/models/profile.rs) already exposes `allow_stale_screening` and `stale_screening_max_days` per project memory, but the validator at [crates/invariant-biosynthesis-core/src/validator.rs](crates/invariant-biosynthesis-core/src/validator.rs) (~lines 400–420) still consults `allow_unimplemented_invariants` for stale-DB downgrade. This step is identical in spirit to [spec-v6 step-01](spec-v6-gap-remediation.md). If v6 step-01 has already landed, skip this step and verify the acceptance criteria below; otherwise execute.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/models/profile.rs and crates/invariant-biosynthesis-core/src/validator.rs end to end. The profile field allow_unimplemented_invariants is currently overloaded: it silences stub invariants AND it downgrades a stale hazard database to an advisory. These are two different policies — separate them.

1. Confirm allow_stale_screening (bool, default false) and stale_screening_max_days (Option<u32>) already exist on BioProfile. If a field is missing, add it. stale_screening_max_days must be Some when allow_stale_screening is true.
2. In the validator, route stale-DB handling through allow_stale_screening only. Make allow_unimplemented_invariants control ONLY the stub-invariant pathway.
3. In BioProfile::validate, reject any profile where bsl_level >= 3 AND allow_stale_screening == true. Reject any profile where allow_stale_screening == true and stale_screening_max_days is None or > 30.
4. Update all six built-in profile JSON files under profiles/ so each declares allow_stale_screening explicitly (false for BSL>=3; false or true-with-cap for lower).
5. Add tests covering: (a) BSL=3 + allow_stale_screening=true is rejected at profile-validate time, (b) BSL=2 + allow_stale_screening=true + max_days=30 validates, (c) stale DB with allow_stale_screening=false produces Fail, (d) stale DB with allow_stale_screening=true (BSL<=2) produces Advisory.

Run cargo test --workspace and cargo clippy -- -D warnings. Commit as "[spec-v7 step-01] split stale-screening from unimplemented-invariants".
```

**Acceptance:** All six built-in profiles parse; new tests pass; no production profile (BSL≥3) can reach the stale-DB downgrade path.

---

### Step 2 — Surface five existing library features through the CLI

**Goal:** Expose threat-scorer threshold, quorum policy, attestation verification, persistent nonce log, and structured stateful-store path as CLI flags on `invariant-bio validate`.

**Severity / Effort:** High / S.

**Context:** Library code already implements all five features. The CLI in [crates/invariant-biosynthesis-cli/src/commands/validate.rs](crates/invariant-biosynthesis-cli/src/commands/validate.rs) does not expose them, so users silently get less safety than the library can provide. Overlaps with [spec-v6 step-02](spec-v6-gap-remediation.md). Depends on Step 6 (stateful store trait) for the `--stateful-store` flag, but the other four flags can land first.

**Prompt:**
```
Read crates/invariant-biosynthesis-cli/src/commands/validate.rs and the corresponding builder methods on Validator/ValidatorConfig in crates/invariant-biosynthesis-core/src/validator.rs, crates/invariant-biosynthesis-core/src/threat.rs, crates/invariant-biosynthesis-core/src/screening/mod.rs, and crates/invariant-biosynthesis-core/src/attestation.rs. Inventory which clap flags already exist before adding new ones; do not duplicate.

Add or finalize these clap arguments on the validate subcommand:

  --threat-threshold <f64>             Enables the threat scorer with this score gate (0.0..=1.0). When omitted, behavior is unchanged for BSL<3, and threat scorer auto-wires for BSL>=3 (already implemented).
  --quorum-policy <all|majority|n:M>   Selects the consensus quorum policy when one or more --hazard-db are provided. Default "all". Parse "n:M" into QuorumPolicy::AtLeast { n, of: M }.
  --attest <path>                      Path to a signed AttestedInputEnvelope to verify alongside the bundle. May be repeated. On signature failure, abort with a non-zero exit code and a structured JSON error written to stderr.
  --nonce-log <path>                   Path to the persistent attestation nonce log (created if absent). When omitted, in-memory only.
  --no-threat-scorer                   Explicit opt-out (overrides the BSL>=3 default-on). Refused for BSL>=3 unless --i-accept-the-risk is also passed; emit a stderr warning either way.

Wire each flag to the matching builder method. Print a concise stderr warning if --no-threat-scorer is used at any BSL level, including the audited reason for BSL>=3.

Add CLI integration tests under crates/invariant-biosynthesis-cli/tests/ covering: each flag's happy path, invalid quorum string is rejected, --no-threat-scorer without --i-accept-the-risk on a BSL=3 profile is rejected, --attest with a tampered envelope aborts with exit code 2.

Update README.md "CLI usage" section with the new flags. Run cargo test --workspace, cargo clippy -- -D warnings. Commit as "[spec-v7 step-02] expose threat/quorum/attest/nonce-log on validate CLI".
```

**Acceptance:** New flags appear in `invariant-bio validate --help`; integration tests pass; README updated.

---

### Step 3 — Refresh threat model and write audit-readiness doc

**Goal:** Bring [docs/threat-model.md](threat-model.md) up to date with the post-chunk-03/chunk-04 codebase, and create [docs/AUDIT-READINESS.md](AUDIT-READINESS.md) describing the build, test inventory, feature matrix, crypto primitives, and known limitations for an external auditor.

**Severity / Effort:** High / S.

**Context:** The current threat model predates the S1 detector and the chemistry advisory pipeline. There is no consolidated audit-readiness document. Identical to [spec-v6 step-03](spec-v6-gap-remediation.md) — execute it once.

**Prompt:**
```
Read these files completely: docs/threat-model.md, docs/spec.md, docs/spec-gap-analysis-part-4.md, docs/spec-v5-gap-closure.md, CLAUDE.md, README.md, crates/invariant-biosynthesis-core/src/lib.rs, crates/invariant-biosynthesis-core/src/invariants/stateful.rs, crates/invariant-biosynthesis-core/src/invariants/dna.rs, crates/invariant-biosynthesis-core/src/invariants/chemical.rs.

Task A — refresh docs/threat-model.md:
- Add a section on cross-bundle fragmentation attacks and how the S1 FragmentationBypassDetector defends against them, including its in-memory-state limitation (no fleet coordination yet).
- Add a section on chemistry coverage: the heuristic SMILES engine is advisory-grade only; do not claim CWC-level assurance until a real cheminformatics backend lands.
- Add a section on D10 (uncalibrated k-mer homology screener) describing residual FN/FP risk and the absence of a published acceptance gate.
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

No code changes; documentation only. Commit as "[spec-v7 step-03] refresh threat model and add audit-readiness doc".
```

**Acceptance:** `docs/threat-model.md` mentions S1, D10, chemistry advisory; `docs/AUDIT-READINESS.md` exists with all nine sections grounded in current code.

---

### Step 4 — Build the D-family reference corpus and calibrate D1–D6

**Goal:** Produce a published FN/FP statistical bound on the homology screener using a reference corpus of HHS Select-Agent positives, benign negatives, and codon-shuffled / homopolymer-padded variants. Stop claiming D1–D6 are "production" until this is done.

**Severity / Effort:** Critical / L (multi-day; corpus construction dominates).

**Context:** [crates/invariant-biosynthesis-core/src/invariants/dna.rs](crates/invariant-biosynthesis-core/src/invariants/dna.rs) implements `KmerHomologyEngine` with hardcoded `k=5` and Jaccard ≥ 0.30. Project memory notes "uncalibrated k-mer, FN/FP acceptance gate not met." Spec target is FN ≤ 1e-4, FP ≤ 1e-3. This step does not require an HMM — calibration of the k-mer engine alone is the deliverable.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/dna.rs and crates/invariant-biosynthesis-core/src/invariants/homology.rs. Also read docs/spec-gap-analysis-part-4.md section §C-2 and the threat-model section on D-family. The goal is to publish FN/FP confidence intervals for the k-mer homology screener so we can either declare D1–D6 calibrated or quantify the residual risk.

1. Create a new harness crate or example under crates/invariant-biosynthesis-core/examples/dna_calibration/ (do not call it a binary if a library example fits; otherwise put it under a feature-gated bin). Inside, build a corpus loader that reads:
   - A positives directory: HHS Select Agent and Toxin reference sequences (FASTA). Document where to obtain them (URL/source) but do NOT commit copyrighted FASTA into the repo. Provide a manifest.json that lists expected SHA-256 of each file so the harness can verify.
   - A negatives directory: benign reference genomes (E. coli K-12, S. cerevisiae S288C, human exome subset). Same manifest pattern.
   - A perturbation generator: codon-shuffles, homopolymer-pads, frameshifts, reverse-complements of positives — these are negatives that an attacker would try to bypass with.

2. Implement a grid search over (k in 4..=8, jaccard_threshold in 0.20..=0.60 step 0.05). For each grid point: count TP, FP, TN, FN; compute Clopper–Pearson 95% CIs (use the statrs crate or implement against beta inverse). Produce a CSV plus a Markdown summary table at docs/d-family-calibration.md.

3. Pick the operating point closest to FN <= 1e-4 / FP <= 1e-3 OR the Pareto front if no grid point meets both. Document the choice. Update KmerHomologyEngine defaults to that (k, threshold) pair and persist it as named constants. Keep the old defaults reachable behind a deprecated builder for a release.

4. Add an integration test in crates/invariant-biosynthesis-core/tests/ that runs a small subset of the corpus (committed as synthetic non-sensitive sequences) and asserts the chosen operating point holds within its CI on that mini-corpus.

Do not commit any sensitive sequence data; the harness must run on synthetic data in CI and on the real corpus only on operator workstations. Commit as "[spec-v7 step-04] D-family k-mer calibration harness and operating-point selection".
```

**Acceptance:** `docs/d-family-calibration.md` published with CIs; mini-corpus integration test passes; the chosen `(k, threshold)` is documented and reflected in defaults.

---

### Step 5 — Introduce a machine-checked acceptance-gate ledger

**Goal:** Replace prose claims about "production-ready" with a JSON ledger checked in CI. Each gate is either ✅ (with evidence) or ❌. README badges and `invariant-bio verify-self` consult the ledger.

**Severity / Effort:** Critical / S.

**Context:** Spec-gap-analysis-part-4 §X-3 lists seven acceptance gates. There is no machine-readable record of their state. The README must not advertise production readiness while any gate is ❌, but today this is enforced only by editorial discipline.

**Prompt:**
```
Create docs/acceptance-gates.json with this shape (exact field names matter):

{
  "gates": [
    { "id": "G1-phase2-closed", "description": "...", "status": "in_progress|met|not_met", "evidence": ["..."] },
    { "id": "G2-d-family-calibrated", ... },
    { "id": "G3-shadow-mode-agreement", ... },
    { "id": "G4-hsm-backend-prod", ... },
    { "id": "G5-synthesizer-end-to-end", ... },
    { "id": "G6-jurisdiction-compliance", ... },
    { "id": "G7-stateful-and-consensus-default", ... }
  ],
  "version": 1,
  "updated": "ISO8601"
}

Read docs/spec-gap-analysis-part-4.md section §X-3 to source descriptions. Set initial statuses based on current code state (most are not_met; G1 in_progress).

Then:
1. Add a CLI subcommand `invariant-bio verify-self gates` that loads the ledger and prints a table with colored status. Exit code 0 if all met; 1 otherwise.
2. Add a CI step (or extend an existing one) in .github/workflows/ that runs `invariant-bio verify-self gates --strict`. In strict mode, the command exits non-zero if any gate is "not_met"; today CI should pass with non-strict mode only.
3. Add a README.md badge area near the top showing gate counts (met / total). Use a simple text rendering, not external badge services.
4. Add tests for ledger parsing (malformed JSON, unknown status string, missing required field).

Commit as "[spec-v7 step-05] acceptance-gate ledger and verify-self gates subcommand".
```

**Acceptance:** Ledger exists; `invariant-bio verify-self gates` runs; README states current gate count without overclaiming production status.

---

# Tier 2 — Core capability completeness

---

### Step 6 — Add `StatefulStore` trait and file-backed store

**Goal:** Make the S1 FragmentationBypassDetector usable across multiple firewall instances on the same host (and lay the foundation for a fleet-wide store later).

**Severity / Effort:** Critical / M.

**Context:** [crates/invariant-biosynthesis-core/src/invariants/stateful.rs](crates/invariant-biosynthesis-core/src/invariants/stateful.rs) keeps state in-memory only. Two parallel validators see independent windows, so an attacker can fragment requests across processes. File-backed storage closes the same-host gap; Redis/etcd is a follow-up.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/stateful.rs end to end, then read how the validator constructs the detector in crates/invariant-biosynthesis-core/src/validator.rs around the `with_stateful_detector*` builders.

Refactor the detector to use a `StatefulStore` trait with these methods (sketch the names; final API is yours): record_observation, query_window, prune_expired. The trait must be object-safe (use dyn trait objects in the detector field).

Provide two implementations:
1. InMemoryStatefulStore — current behavior, the default.
2. FileStatefulStore — append-only JSONL at a configurable path. Each line is one observation event with a timestamp. On startup, load lines newer than the configured window. Periodically compact (rewrite, atomic rename) when the file exceeds a configurable size or age. Use fsync after each append; if the OS does not support O_APPEND atomicity, document the assumption.

Add a `--stateful-store <path>` CLI flag on `invariant-bio validate` (coordinate with step-02). When set, instantiate FileStatefulStore; when unset, InMemoryStatefulStore.

Add tests:
- Two separate validator instances writing to the same FileStatefulStore detect a fragmentation pattern that neither alone would catch.
- Restarting a validator preserves the window (state survives across processes).
- Compaction triggered by size threshold rewrites the file, drops expired entries, leaves all in-window entries intact.
- Concurrent writes from two processes do not corrupt the file (use a small concurrency stress test with std::process or std::thread).
- Corrupted line at startup (truncated or invalid JSON) is logged and skipped without crashing.

Document that Redis/etcd backends are future work; do not stub them now. Commit as "[spec-v7 step-06] StatefulStore trait + file-backed store for S1".
```

**Acceptance:** Cross-process detection demonstrated by integration test; in-memory remains default; clippy clean.

---

### Step 7 — Implement TPM and YubiHSM key stores (feature-gated)

**Goal:** Replace the HSM stubs with at least one real backend (TPM 2.0 via tss-esapi is the most portable; YubiHSM is a reasonable second). Document file-backed keys as **non-production** for BSL≥3.

**Severity / Effort:** Critical / L (external deps + hardware testing).

**Context:** [crates/invariant-biosynthesis-core/src/keys.rs](crates/invariant-biosynthesis-core/src/keys.rs) declares `OsKeyringStore`, `TpmKeyStore`, `YubiHsmKeyStore` but each returns `KeyStoreError::Unavailable`. Production deployments cannot secure their root authority key today.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/keys.rs in full, plus the Ed25519 sign/verify call sites in crates/invariant-biosynthesis-core/src/authority.rs.

Implement TpmKeyStore behind a `tpm` cargo feature, using the tss-esapi crate. Operations needed: generate Ed25519 key in TPM, retrieve public key, sign(message) -> signature, list keys by label. Use a persistent handle namespace under a documented owner-auth scheme. If the TPM device is absent, the constructor must fail-fast with a clear error rather than silently falling back to file storage.

Implement YubiHsmKeyStore behind a `yubihsm` cargo feature, using the yubihsm crate. Same operations, with audit-log entries on every sign call.

Both backends should expose a builder that takes the device path / connector URL plus an auth-key spec. Add an integration-test harness gated by the same features that uses the simulator (TPM software simulator: `swtpm`; YubiHSM simulator: `yubihsm-connector --simulator`). Document required system packages in docs/HSM-SETUP.md.

Update BioProfile::validate or ValidatorConfig builder to refuse a file-backed key store when bsl_level >= 3 unless an explicit `--i-accept-the-risk-file-backed-keys` opt-out is set; emit a stderr warning every validate run when the opt-out is in effect.

Add a CLI subcommand surface for key generation:
  invariant-bio keygen --backend file|tpm|yubihsm --label <name> [--device <path>]
keep existing file backend behavior; the new --backend flag picks the store.

Update README.md "Key management" section. Commit as "[spec-v7 step-07] TPM and YubiHSM key stores with simulator-based tests".
```

**Acceptance:** Both feature-gated backends compile and pass simulator-based tests in CI under their feature flags; default build (no features) is unchanged; BSL≥3 + file backend is refused without explicit opt-out.

---

### Step 8 — Introduce real cheminformatics backend (feature-gated)

**Goal:** Replace the regex-only chemistry engine with a real Molecule type, SMARTS parser, and structural-alert library — at least behind a feature flag — so C1–C10 can produce non-advisory verdicts.

**Severity / Effort:** Critical / XL (external dep choice + corpus).

**Context:** [crates/invariant-biosynthesis-core/src/invariants/chemical.rs](crates/invariant-biosynthesis-core/src/invariants/chemical.rs) and [crates/invariant-biosynthesis-core/src/invariants/molecule.rs](crates/invariant-biosynthesis-core/src/invariants/molecule.rs) (the in-house v1 SMARTS rule library from chunk-04) are heuristic. The validator already emits a `chemistry_engine_status` advisory check.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/chemical.rs, crates/invariant-biosynthesis-core/src/invariants/molecule.rs, and crates/invariant-biosynthesis-core/src/validator.rs (look for chemistry_engine_status). Also read docs/step3-bio-invariants.md for the C-family spec.

Step 1 — Decision (write up first, then implement):
Produce docs/chemistry-backend-decision.md comparing three options:
  (A) RDKit via FFI (rdkit-sys or rdkit-rs crate). Pros: gold standard. Cons: large C++ dep, build complexity.
  (B) OpenBabel via FFI. Pros: ubiquitous. Cons: similar build complexity, less SMARTS coverage than RDKit.
  (C) Python sidecar (rdkit pip + JSON-RPC over stdin/stdout). Pros: easy. Cons: process management, latency.
Recommend one with reasons. Stop and ask the user to confirm before proceeding to step 2.

Step 2 — Once a backend is chosen:
- Add the dep behind a feature flag `chem-backend-{rdkit|openbabel|python-sidecar}` (only one is enabled per build).
- Define a `CheminformaticsBackend` trait: parse_smiles, canonicalize, has_substructure(smarts), molecular_descriptors, fragment_complexity. Implement against the chosen backend.
- Replace the heuristic Molecule and string-pattern rules in chemical.rs with calls through the trait. Keep the old heuristic engine as a fallback and behind feature `chem-backend-heuristic`; the default-features cargo build retains the heuristic so new contributors can build without external deps.
- Update chemistry_engine_status: when a real backend is active, emit an Info check naming the backend; when only the heuristic is active, the existing advisory remains.
- Build a structural-alert corpus under tests/data/chem-corpus/: 50+ CWC-listed precursors, 50+ explosives signatures, 50+ benign drugs. Add tests: real backend correctly classifies the corpus; heuristic is allowed to miss some but must not generate Fail verdicts where backend produces Pass on benign.

Document required system packages in docs/CHEM-BACKEND-SETUP.md. Commit each step separately ("[spec-v7 step-08a] backend decision doc", "[spec-v7 step-08b] CheminformaticsBackend trait + selected backend").
```

**Acceptance:** Decision doc reviewed; one feature-gated real backend compiles and passes the corpus test in CI under its feature flag; heuristic remains the default-features build.

---

### Step 9 — Implement S3 replicator and webhook witness (feature-gated)

**Goal:** Make the audit hash chain durable across hosts. Today, loss of disk = loss of audit trail.

**Severity / Effort:** Critical / M.

**Context:** [crates/invariant-biosynthesis-core/src/replication.rs](crates/invariant-biosynthesis-core/src/replication.rs) declares `S3Replicator` and `WebhookWitness` returning `Unavailable`. Audit log is single-host today.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/replication.rs and the audit-append call sites in crates/invariant-biosynthesis-core/src/audit.rs.

Implement S3Replicator behind a `replicate-s3` feature using aws-sdk-s3:
- Periodic upload of audit log segments to a configurable bucket/prefix with server-side encryption.
- Object keys include the segment start/end Merkle root so out-of-order receipt is detectable.
- Backoff and retry with jitter on transient errors; surface persistent failures as IncidentRecord (depends on step-16).
- Configurable flush interval and segment size.

Implement WebhookWitness behind a `replicate-webhook` feature using reqwest:
- POST each new audit log Merkle root to a configurable HTTPS endpoint with HMAC signature header.
- Same backoff/retry/incident behavior as the S3 path.

Add a periodic Merkle-root gossip skeleton: a function that exchanges roots with N peer URLs and reports any mismatch as a fork incident. Behind a `replicate-gossip` feature; document fully in docs/REPLICATION-DESIGN.md but do not require it for the initial cut.

Tests (under each feature flag):
- S3: localstack-backed integration test confirms upload, retrieval, and tamper detection (a flipped byte fails Merkle verification).
- Webhook: a local reqwest-mock server confirms POST shape, retry on 503, and HMAC verification.

Add CLI flags on `invariant-bio validate` (or a new `replicate` subcommand): --replicate-s3-bucket, --replicate-webhook-url, --replicate-interval-seconds.

Commit as "[spec-v7 step-09] S3 replicator and webhook witness behind feature flags".
```

**Acceptance:** Feature-gated builds pass tests against localstack and a local mock server; default build unchanged.

---

### Step 10 — Implement three reference synthesizer adapters

**Goal:** Prove end-to-end execution-token → synthesizer → attested-readback flow with at least one DNA, one peptide, and one chemical synthesizer.

**Severity / Effort:** Critical / XL (depends on vendor cooperation).

**Context:** No vendor adapters exist today. [crates/invariant-biosynthesis-core/src/attestation.rs](crates/invariant-biosynthesis-core/src/attestation.rs) defines envelopes but no transport. The CLI lacks an `issue-token` command.

**Prompt:**
```
Read docs/step5-platform-integration.md, crates/invariant-biosynthesis-core/src/attestation.rs, and crates/invariant-biosynthesis-core/src/authority.rs.

Phase 1 — design (no code):
Produce docs/synthesizer-adapter-design.md describing:
- The execution-token format (build on AttestedInputEnvelope; add fields for synthesizer model, scheduled-window, operator-id).
- The pre-flight protocol: adapter receives token over a vendor-specific transport (HTTPS POST or vendor SDK), verifies signature and nonce against the persistent nonce log, and refuses if any check fails.
- The post-run readback: adapter signs an attested readback envelope (volume, timestamp, success/fail, optional QC metrics) with its own instrument key.
- Integration shape with `invariant-bio` (new `issue-token` CLI subcommand; new `verify-readback` CLI subcommand).

Stop and request user confirmation of the design before phase 2.

Phase 2 — implementation:
Pick three reference vendors (default: Twist for DNA, CEM Liberty for peptide, Chemspeed Swing for chemical — adjust if user designates others). For each:
- Add a feature-gated module under crates/invariant-biosynthesis-core/src/adapters/<vendor>/.
- Implement the request/response shape against vendor docs (mock if docs unavailable; mark the adapter `dev-only` until validated against real hardware).
- Verify the execution-token signature and nonce BEFORE making any vendor API call.
- Produce 5+ unit tests: token-accept, expired-token-reject, wrong-instrument-token-reject, signature-tampered-token-reject, nonce-replay-reject.
- Ship one example profile under profiles/ that names the adapter (e.g., bsl2_twist_oligo_dev.json).

Add CLI:
  invariant-bio issue-token --bundle <path> --synthesizer <name> --window-end <timestamp> --signing-key <handle>
  invariant-bio verify-readback --readback <path> --instrument-pubkey <hex>

Document the operator runbook in docs/SYNTHESIZER-INTEGRATION.md.

Commit each adapter separately ("[spec-v7 step-10a] design", "[spec-v7 step-10b] twist adapter", ...).
```

**Acceptance:** Three adapters compile under their feature flags; all unit tests pass; design doc reviewed; CLI commands documented.

---

# Tier 3 — Validator polish & observability

---

### Step 11 — Structure consensus disagreement as a typed report

**Goal:** Replace the string-label disagreement representation in the consensus screener with a typed `ConsensusReport` so compliance auditors can consume it programmatically.

**Severity / Effort:** Medium / S.

**Context:** [crates/invariant-biosynthesis-core/src/screening/mod.rs](crates/invariant-biosynthesis-core/src/screening/mod.rs) emits disagreement as a string today (~lines 397–406).

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/screening/mod.rs end to end. Define a new public type:

  pub struct ConsensusReport {
      pub sources: Vec<SourceVerdict>,
      pub policy: QuorumPolicy,
      pub agreed: bool,
      pub majority_verdict: Option<HazardVerdict>,
  }
  pub struct SourceVerdict { pub name: String, pub verdict: HazardVerdict, pub explanation: Option<String> }

Embed ConsensusReport on the appropriate hit type (likely a new field on whatever HazardScreenResult or similar struct is returned to the validator). Update Serialize/Deserialize derivations and JSON output schema accordingly.

Update existing consensus tests to assert on the typed report rather than substring-matching a label. Add a test that AtLeast { n: 2, of: 3 } with a 1–1–1 split produces agreed=false and majority_verdict=None.

Document the new field in docs/AUDIT-READINESS.md (if it exists from step-03) under the screening section.

Commit as "[spec-v7 step-11] typed ConsensusReport on screener output".
```

**Acceptance:** New tests pass; JSON output of `invariant-bio validate` includes `consensus_report` when relevant; clippy clean.

---

### Step 12 — Wire differential validation into the `validate` subcommand

**Goal:** Allow operators to run two validator configurations against the same bundle in one shot and escalate any disagreement to Fail (IEC 61508 SIL-2 framing).

**Severity / Effort:** Medium / S.

**Context:** [crates/invariant-biosynthesis-core/src/differential.rs](crates/invariant-biosynthesis-core/src/differential.rs) exists. The standalone `differential` CLI subcommand accepts pre-computed verdicts but cannot drive a fresh validation pair.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/differential.rs and crates/invariant-biosynthesis-cli/src/commands/differential.rs and crates/invariant-biosynthesis-cli/src/commands/validate.rs.

Add a `--differential <secondary-config-path>` flag to `invariant-bio validate`. When set:
1. Load the primary ValidatorConfig as today.
2. Load a secondary ValidatorConfig from the path (TOML or JSON; pick whichever is consistent with existing config loading).
3. Run both validators on the same bundle.
4. Compare verdicts; on disagreement (any per-invariant Pass-vs-Fail mismatch, or any Pass-vs-Advisory mismatch at BSL>=3), produce a DifferentialReport, escalate the overall verdict to Fail, and emit the report in the structured output.
5. On agreement, the report still appears (with `agreed: true`) so downstream consumers always have it.

Add tests:
- Two configs with identical thresholds: agreement, overall verdict matches single-validator result.
- Configs that diverge on jaccard threshold: disagreement on a borderline bundle, overall verdict escalated to Fail.
- Missing secondary config file: clear error, non-zero exit.

Document in README.md and docs/AUDIT-READINESS.md. Commit as "[spec-v7 step-12] --differential flag on validate".
```

**Acceptance:** New flag works; tests pass; README updated.

---

### Step 13 — Add statistics module (Clopper–Pearson + kappa)

**Goal:** Make the FN/FP claims of the D-family calibration (step-04) backed by reproducible code, not ad-hoc spreadsheets. Provide Cohen's and Fleiss's kappa for inter-rater agreement on consensus screening.

**Severity / Effort:** Medium / S.

**Context:** No `statistics` module today. statrs already in dep tree (verify).

**Prompt:**
```
Add module crates/invariant-biosynthesis-core/src/statistics.rs with:

  pub fn clopper_pearson(successes: u64, trials: u64, confidence: f64) -> (f64, f64)
  pub fn cohen_kappa(rater_a: &[u8], rater_b: &[u8]) -> f64
  pub fn fleiss_kappa(matrix: &[Vec<u8>]) -> f64   // [item][rater] -> category id

Use statrs (or implement against the regularized incomplete beta if statrs is not already present; check Cargo.toml first). Document edge cases: trials=0 returns (0.0, 1.0) by convention; confidence must be in (0,1).

Wire clopper_pearson into the dna_calibration harness from step-04 (replace any hand-rolled CI math).

Property tests: against known-good values from scipy.stats.beta (commit a small CSV of reference values into tests/data/); kappa cross-checked against irr R package outputs.

Commit as "[spec-v7 step-13] statistics module: clopper_pearson + kappa".
```

**Acceptance:** Module compiles; property tests within ~1e-6 of reference values; calibration harness uses it.

---

### Step 14 — Add criterion benchmarks and baseline doc

**Goal:** Prove latency budgets are met. Create a reproducible perf baseline before any future optimization claims.

**Severity / Effort:** Medium / S.

**Context:** No `benches/` today.

**Prompt:**
```
Add `benches/` to crates/invariant-biosynthesis-core with criterion harnesses:
- bench_validator_end_to_end: small (1 sequence, ~1 kb), medium (10 sequences, ~10 kb each), large (100 sequences, ~10 kb each) bundles.
- bench_kmer_homology: 10 kb DNA against a fixed in-test corpus of 100 references.
- bench_smiles_screen: 10,000 SMILES from tests/data/chem-corpus/ (or a synthetic batch if step-08 corpus does not exist yet).
- bench_audit_append_verify: 100,000 audit entries — measure append throughput and end-to-end Merkle verification time.

Write docs/PERFORMANCE.md with:
- Reproduction recipe (`cargo bench -p invariant-biosynthesis-core -- --save-baseline v0.x`).
- Captured baseline numbers for the host running the bench (CPU, OS, rustc version, commit hash, wall time).
- Latency budget targets per spec-gap-analysis-part-4 §M-4 (or the most recent budget definitions in any spec doc — read and cite explicitly).

Do NOT make these benches part of `cargo test --workspace`; they should run only via `cargo bench`. Commit as "[spec-v7 step-14] criterion benches and PERFORMANCE.md baseline".
```

**Acceptance:** `cargo bench -p invariant-biosynthesis-core` runs all four; PERFORMANCE.md reflects current host's numbers; clippy clean.

---

### Step 15 — Rotate the attestation nonce log

**Goal:** Long-running firewalls must not blow out their disks on the nonce log.

**Severity / Effort:** Medium / S.

**Context:** [crates/invariant-biosynthesis-core/src/attestation.rs](crates/invariant-biosynthesis-core/src/attestation.rs) (~lines 188–239) appends nonces forever.

**Prompt:**
```
Read the persistent nonce log code in crates/invariant-biosynthesis-core/src/attestation.rs.

Add segment-based rotation:
- Default segment size 64 MiB; default segment max age 90 days; both configurable.
- When a segment crosses size or age, seal it (write a checkpoint summary line containing segment start/end timestamps, nonce count, and the SHA-256 of the segment contents) and start a new segment.
- On startup, load the active segment plus the most recent N sealed segments whose checkpoint timestamps fall inside the configured replay-protection window (default 90 days).
- Verify each loaded segment's checkpoint hash; if a segment is corrupt, refuse to start (fail-closed) with a clear error pointing at the offending file.

Tests:
- Rotation triggers at size threshold; old segment sealed; new segment opened; verification still rejects nonces that appear in any in-window segment (sealed or active).
- Rotation triggers at age threshold (use a clock injection seam, not std::time::SystemTime, so tests are fast).
- Corrupted sealed segment causes startup failure with a useful error.
- Segment older than the replay-protection window is allowed to be deleted by the operator without breaking startup.

Document the operational policy in docs/AUDIT-READINESS.md (or create docs/NONCE-LOG.md if AUDIT-READINESS doesn't exist yet). Commit as "[spec-v7 step-15] rotate persistent nonce log with sealed-segment checkpoints".
```

**Acceptance:** All four tests pass; clippy clean; corrupted-segment path is fail-closed.

---

### Step 16 — Wire incident responder into validator post-verdict path

**Goal:** Turn `IncidentResponder` from a defined-but-unused module into an actual on-by-default observability hook.

**Severity / Effort:** Medium / S.

**Context:** [crates/invariant-biosynthesis-core/src/incident.rs](crates/invariant-biosynthesis-core/src/incident.rs) defines the types but the validator never invokes them.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/incident.rs and crates/invariant-biosynthesis-core/src/validator.rs.

Wire the incident responder into the validator post-verdict path:
- On any Fail verdict at BSL>=3.
- On any S1 (FragmentationBypassDetector) hit at any BSL.
- On any consensus disagreement (depends on step-11 typed ConsensusReport).
- On any --attest envelope verification failure (depends on step-02).

The validator gains a `with_incident_responder(IncidentResponder)` builder method. ValidatorConfig::new auto-wires a default responder with a stderr sink; users can replace it.

Implement these AlertSink variants now: Stderr (default), File (newline-delimited JSON), InMemory (test-only). Put Webhook and Syslog behind features `incident-webhook` and `incident-syslog`; when those features are enabled but the dependency is misconfigured (URL not set, syslog socket missing), fail fast at startup, not per-event.

Add a CLI flag on `invariant-bio validate`: `--incident-file <path>` to attach a File sink alongside stderr.

Tests:
- Forced Fail at BSL=3 produces an IncidentRecord with the expected fields and a stderr line that JSON-parses.
- S1 hit at BSL=2 still produces an incident.
- File sink writes one JSON object per line.
- Feature off (default) does not introduce reqwest/syslog dependencies.

Commit as "[spec-v7 step-16] wire incident responder; stderr/file sinks default; webhook/syslog feature-gated".
```

**Acceptance:** Tests pass; default build does not gain network or syslog deps; clippy clean.

---

### Step 17 — Verify and test PCA chain depth enforcement

**Goal:** Confirm that `BioProfile::max_authority_chain_depth` is actually enforced at validate time, and that all six built-in profiles cover the cases.

**Severity / Effort:** Medium / XS.

**Context:** Project memory states all six profiles declare `max_authority_chain_depth` explicitly, but it is unconfirmed whether the validator actually consults it. This is a verify-then-fix step.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/authority.rs (or chain.rs if the chain logic is in its own file) and crates/invariant-biosynthesis-core/src/validator.rs. Locate where the PCA chain is verified.

Step A (verify):
Confirm that the validator passes `profile.max_authority_chain_depth` into the chain-verification function. If it does, write an integration test that constructs a chain of depth N+1 against a profile with max=N and asserts the validate result is Fail with a "chain depth exceeded" reason. If it does not, add the wiring first, then the test.

Step B:
Add a second test that the chain-depth field has an upper bound (16 per memory) enforced at profile-validate time: a profile with max_authority_chain_depth=17 must fail BioProfile::validate.

Step C:
Update docs/AUDIT-READINESS.md authority section to reference these tests by name. Commit as "[spec-v7 step-17] verify and test PCA chain-depth enforcement".
```

**Acceptance:** New tests fail without the wiring (if it was missing) and pass after; clippy clean.

---

### Step 18 — Verify D7 chi-squared completeness

**Goal:** Confirm whether the D7 codon-usage chi-squared test is complete or partial; finish it if partial.

**Severity / Effort:** Medium / XS.

**Context:** Memory states D7 has CUTG tables and chi-squared logic. Spec-v6 step-05 still listed this as work to do. Verify which is correct.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/dna.rs around the D7 implementation (memory says lines 746–758 do the chi-squared, lines 809–889 hold CUTG tables).

Step A — verify:
- All four organisms (e_coli, s_cerevisiae, h_sapiens, cho_k1) have CUTG tables.
- The chi-squared statistic is computed correctly (degrees of freedom, expected counts, table lookup).
- The verdict thresholds have a documented source (cite the paper or RFC in code comments).
- profile.codon_entropy_band is consulted (or document why it is not).

Step B — finish if partial:
Whatever is missing, add it. Each organism gets a unit test with a hand-calculated expected p-value tolerance.

Step C — corpus test:
Add an integration test using 5 known-bad sequences (e.g., codon-shuffled GFP that should produce strong divergence from h_sapiens CUTG) and 5 known-good sequences. Assert the verdict matches the expectation in each case.

Update docs/AUDIT-READINESS.md D7 row with the chosen p-value thresholds and CUTG table source date. Commit as "[spec-v7 step-18] verify and complete D7 chi-squared codon-usage test".
```

**Acceptance:** Each organism has a unit test; corpus integration test passes; CUTG source documented.

---

# Tier 4 — Policy decisions & governance

These steps may require user input (architectural choices) before code lands.

---

### Step 19 — Decide and execute P6/P8/P9 policy

**Goal:** Resolve the peptide-invariant heuristics: either downgrade their verdicts to Advisory across the pipeline or integrate real predictors.

**Severity / Effort:** Medium / M (depending on path).

**Context:** [crates/invariant-biosynthesis-core/src/invariants/peptide.rs](crates/invariant-biosynthesis-core/src/invariants/peptide.rs) lines ~485–670 implement P6 (MHC binding) as a hydrophobic-window heuristic, P8 (aggregation) as a poly-(I/L/V/F/Y/W) window, P9 (PTM) as regex.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/peptide.rs. Read docs/spec-gap-analysis-part-4.md §H-5.

Step 1 — write a decision doc, do not modify code yet:
Produce docs/peptide-invariants-decision.md comparing:

  PATH A — Downgrade
    Mark P6/P8/P9 verdicts as Advisory by default; emit a peptide_engine_status check explaining that
    these are heuristic and not validated against published predictors. Operators can opt in to Fail
    behavior with a profile flag (peptide_advisory_strict: bool).

  PATH B — Integrate real predictors
    Add feature-gated integrations: `netmhcpan` for P6, `tango` for P8, structural-context predictor
    for P9. Fail-closed at startup if a feature is enabled but the predictor binary is missing.
    Heuristic remains the default-features build.

Recommend one. Wait for user confirmation before proceeding.

Step 2 — execute the chosen path, with tests and a corpus check.

Commit each step separately.
```

**Acceptance:** Decision doc reviewed and approved; chosen path implemented; tests pass.

---

### Step 20 — Implement D9 ViennaRNA secondary-structure path

**Goal:** Replace the rolling-hash perfect-complement heuristic in D9 with a real ΔG-based check, behind a feature flag.

**Severity / Effort:** Medium / S.

**Context:** [crates/invariant-biosynthesis-core/src/invariants/dna.rs](crates/invariant-biosynthesis-core/src/invariants/dna.rs) lines ~937–974 are heuristic.

**Prompt:**
```
Read the D9 implementation in crates/invariant-biosynthesis-core/src/invariants/dna.rs.

Add a `vienna-rna` cargo feature. When enabled at build time, D9 calls the RNAfold binary (subprocess; pass sequence on stdin, parse ΔG and dot-bracket structure from stdout). When the feature is enabled but the binary is missing at startup, fail-closed with a clear error rather than silently falling back. When the feature is disabled, the existing rolling-hash heuristic remains and D9 emits an Advisory.

Tests:
- Feature disabled: heuristic + advisory present.
- Feature enabled, binary mocked (use a small shell script in tests/bin/ or a `which`-overriding test util): real verdict path runs.
- Feature enabled, binary absent: startup error.

Document install in docs/CHEM-BACKEND-SETUP.md (or a new docs/D9-VIENNA-RNA.md). Commit as "[spec-v7 step-20] D9 ViennaRNA path behind feature flag".
```

**Acceptance:** Three test cases pass; default build unchanged; clippy clean.

---

### Step 21 — Decide PR2 vocabulary extension policy

**Goal:** Resolve whether `PROTOCOL_STEP_VOCAB` is a global ceiling (profiles can only narrow) or extensible per profile (profiles may add verbs with authority signing).

**Severity / Effort:** Low / XS.

**Context:** [crates/invariant-biosynthesis-core/src/invariants/protocol.rs](crates/invariant-biosynthesis-core/src/invariants/protocol.rs) sets `PROTOCOL_STEP_VOCAB_VERSION = 1`. Profiles declare `allowed_protocol_steps`. Spec is silent on extensibility.

**Prompt:**
```
Read crates/invariant-biosynthesis-core/src/invariants/protocol.rs and BioProfile::allowed_protocol_steps in models/profile.rs.

Write docs/protocol-vocab-decision.md proposing two options and recommending one:

  POLICY A — Global ceiling
    The built-in vocabulary is a hard upper bound. profile.allowed_protocol_steps may only narrow it.
    Vocabulary version bumps require a code release, an RFC, and a deprecation overlap window.

  POLICY B — Per-profile extensions
    Profiles may add custom verbs. Extensions must be signed by an authority key with scope
    "protocol-vocab-extension". The signature is verified at profile-load time. PROTOCOL_STEP_VOCAB_VERSION
    becomes a minimum-supported-vocab field on the profile.

Recommend one based on threat-model considerations (Policy A is simpler and more conservative; Policy B is more flexible but expands the trusted surface).

Wait for user confirmation. Then implement the chosen policy: tests, docs, profile-validate updates.

Commit each phase separately.
```

**Acceptance:** Decision doc reviewed; chosen policy implemented; tests pass.

---

### Step 22 — Add responsible-disclosure SLA and RFC template

**Goal:** Move from ad-hoc governance to documented timelines and a template for future architectural decisions.

**Severity / Effort:** Low / XS.

**Context:** [SECURITY.md](../SECURITY.md) lacks SLA timelines. There is no RFC process.

**Prompt:**
```
Update SECURITY.md to add explicit SLA timelines:
- Acknowledge new reports within 3 calendar days.
- Triage and assign severity within 7 calendar days.
- High-severity fix within 30 calendar days from triage.
- Medium-severity fix within 90 calendar days.
- Low-severity fix on the next minor release.
- Coordinated disclosure window default: 90 days.

Create docs/rfcs/0000-template.md with sections: Summary, Motivation, Detailed design, Drawbacks, Alternatives, Unresolved questions, Adoption checklist.

Create docs/rfcs/README.md explaining when an RFC is required (any change touching profile schema, invariant verdict semantics, audit format, attestation envelope, or the CLI surface contract).

Commit as "[spec-v7 step-22] disclosure SLA and RFC template".
```

**Acceptance:** Files exist; SLA numbers explicit; RFC template ready to use.

---

### Step 23 — Add export-control posture and CI guard

**Goal:** Document the export-control stance and add an advisory CI check that flags newly added crates with EAR/ITAR concern.

**Severity / Effort:** Low / S.

**Context:** [deny.toml](../deny.toml) covers licensing only.

**Prompt:**
```
Read deny.toml and the GitHub workflows under .github/workflows/.

Step A — Documentation:
Create docs/EXPORT-CONTROL.md describing:
- The project's export-control posture (likely EAR-classified crypto under ECCN 5D002 because of Ed25519/SHA-256; verify this by reading the BIS rules and citing them).
- The list of crates currently in the dep graph that have known export-control entries (cargo tree filtered for ed25519-dalek, sha2, aws-sdk-*, reqwest with TLS, etc.).
- The release-build classification (which jurisdictions are excluded; reference SECURITY.md).

Step B — CI guard:
Add a CI workflow step (or extend an existing one) that runs cargo-deny with a custom advisories file listing export-control-relevant crates. Make it advisory at first (warn-only). Fail the workflow only if the file is missing or malformed.

Commit as "[spec-v7 step-23] EXPORT-CONTROL.md and advisory CI guard".
```

**Acceptance:** Doc exists; CI step runs and reports without blocking; clippy clean.

---

# Appendix A — Verify-only checks (run before kicking off Tier 1)

Before starting, run these one-shot prompts as small sanity checks; many later steps depend on the answers.

```
1. Open crates/invariant-biosynthesis-core/src/validator.rs around lines 130–160. Confirm:
   - ValidatorConfig::new sets up a FragmentationBypassDetector by default.
   - ValidatorConfig::new auto-wires a ThreatScorer when profile.bsl_level >= 3.
   Report the exact line numbers.

2. Open crates/invariant-biosynthesis-cli/src/commands/validate.rs. List every clap argument the
   subcommand currently accepts. Compare to the desired list in spec-v7 step-02 and report which
   are present, which are missing, and which exist but with a different name.

3. Open profiles/*.json. For each, report bsl_level, max_authority_chain_depth, allow_stale_screening,
   stale_screening_max_days. Flag any profile where bsl_level >= 3 and allow_stale_screening = true
   (these violate the BSL guard from step-01).

4. Run `cargo tree -p invariant-biosynthesis-core | head -200`. Report whether statrs is already a dep
   (relevant for step-13).

5. Open crates/invariant-biosynthesis-core/src/invariants/dna.rs. Find the D7 implementation; report
   line ranges for: CUTG tables, chi-squared computation, organism dispatch, profile.codon_entropy_band
   consultation. (Relevant for step-18.)
```

These verifications take ~5 minutes and prevent wasted work on later steps.

---

# Appendix B — Severity / effort summary

| Tier | Step | Title | Severity | Effort |
|---|---|---|---|---|
| 1 | 1 | Split allow_unimplemented_invariants | Critical | S |
| 1 | 2 | Surface five CLI features | High | S |
| 1 | 3 | Threat model + audit-readiness | High | S |
| 1 | 4 | D-family calibration corpus | Critical | L |
| 1 | 5 | Acceptance-gate ledger | Critical | S |
| 2 | 6 | StatefulStore + file backend | Critical | M |
| 2 | 7 | TPM + YubiHSM key stores | Critical | L |
| 2 | 8 | Real cheminformatics backend | Critical | XL |
| 2 | 9 | S3 + webhook replication | Critical | M |
| 2 | 10 | Synthesizer adapters | Critical | XL |
| 3 | 11 | ConsensusReport struct | Medium | S |
| 3 | 12 | --differential on validate | Medium | S |
| 3 | 13 | statistics module | Medium | S |
| 3 | 14 | criterion benches | Medium | S |
| 3 | 15 | Nonce log rotation | Medium | S |
| 3 | 16 | Incident responder wired | Medium | S |
| 3 | 17 | Verify chain-depth enforcement | Medium | XS |
| 3 | 18 | Verify D7 chi-squared | Medium | XS |
| 4 | 19 | P6/P8/P9 policy | Medium | M |
| 4 | 20 | D9 ViennaRNA path | Medium | S |
| 4 | 21 | PR2 vocab policy | Low | XS |
| 4 | 22 | SLA + RFC template | Low | XS |
| 4 | 23 | Export-control posture | Low | S |

---

# Appendix C — Relationship to spec-v6

`spec-v6-gap-remediation.md` (dated 2026-05-01) describes 23 steps. v7 was produced after a fresh code re-read on the same day. Step-by-step relationship:

- **v7 step-01** ≡ v6 step-01 (split stale screening). Execute once.
- **v7 step-02** ≡ v6 step-02 plus a sixth flag (`--stateful-store`).
- **v7 step-03** ≡ v6 step-03 (threat model + audit readiness).
- **v7 step-04** ≡ v6 step-04 (D-family calibration).
- **v7 step-05** is **new**: the machine-checked acceptance-gate ledger is not in v6.
- **v7 step-06** ≡ v6 step-06 (StatefulStore trait).
- **v7 step-07** ≡ v6 step-09 (HSM backends).
- **v7 step-08** ≡ v6 step-08-or-equivalent but with explicit decision-doc-first phasing.
- **v7 step-09** ≡ v6 step-10 (replication backends).
- **v7 step-10** ≡ v6 step-11 (synthesizer adapters) but with decision-doc-first phasing.
- **v7 step-11** is **new**: typed `ConsensusReport` (v6 step §M-1 referenced it but did not write a Claude Code prompt).
- **v7 step-12** ≡ v6 step-13 (differential on validate).
- **v7 step-13** ≡ v6 step-14 (statistics).
- **v7 step-14** ≡ v6 step-15 (perf benches).
- **v7 step-15** ≡ v6 step-16 (nonce log rotation).
- **v7 step-16** ≡ v6 step-17 (incident responder).
- **v7 step-17** is **new (verify-only)**: chain-depth enforcement was assumed correct in v6 but never explicitly tested.
- **v7 step-18** is **new (verify-only)**: D7 chi-squared completeness was assumed in v6 step-05 but conflated with calibration; v7 separates them.
- **v7 step-19** ≡ v6 step-20 (P6/P8/P9 policy).
- **v7 step-20** ≡ v6 step-19 (D9 ViennaRNA).
- **v7 step-21** ≡ v6 step-21 (PR2 vocab).
- **v7 step-22** ≡ v6 step-22 (SLA + RFC).
- **v7 step-23** ≡ v6 step-23 (export control).

If you have already executed any v6 step, mark the corresponding v7 step as done and skip.
