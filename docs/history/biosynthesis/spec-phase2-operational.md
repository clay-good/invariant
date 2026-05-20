> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Invariant Biosynthesis — Phase 2 Spec

This spec closes the **remaining gaps** between the shipping firewall (Phase 1, gap-closure Steps 1–22 ✅, archived to `docs/spec-phase1-gap-closure.md`) and a system that can be deployed to a real lab.

It is structured the same way as the Phase 1 spec: each step is a self-contained prompt for Claude Code with goal, prompt, and acceptance check. **Run the steps in order** — later steps assume earlier ones have landed.

## Phase 1 vs Phase 2

Phase 1 delivered: 34 invariants (D1–D10, P1–P10, C1–C10, PR1–PR4) with real heuristics, file-backed signed hazard DB, attestation with replay/freshness/signature checks, all 11 CLI subcommands, sim/eval/fuzz crates, 6 bio profiles, ~540 tests across the workspace. The firewall produces signed verdicts.

Phase 2 closes the gaps that **deep gap analysis on 2026-04-25** identified:

- Several modules ship as **stubs returning `Unavailable`** — `incident.rs` webhook/syslog sinks, `replication.rs` S3 + webhook witness, `keys.rs` TPM/YubiHSM/OS-keyring backends.
- Several modules are **fully implemented but never invoked** — `threat.rs` scorer, `monitors.rs` runtime checks, the `StatefulInvariant` trait.
- Several invariants are **conservative heuristics** that the threat model assumes are real — D9 has no ΔG, the C-family has no SMARTS, D1–D3/P1–P5 rely on regex DBs instead of BLAST/HMMER.
- Several **platform integration adapters** described in `docs/step5-platform-integration.md` (Twist, IDT, Ansa, Kilobaser, BioXp, CEM, Chemspeed, ECL) **do not exist**.
- Several **operational gaps**: no benches, no chemical example bundles, no GitHub release artifacts, no Phase-2 `cargo deny` advisories, no nonce durability across restarts, no third-party security audit.

## Progress log

(Each step appends a `- [x] **Step N** — …` entry on completion, mirroring Phase 1's pattern.)

## Ground rules

- Preserve `#![forbid(unsafe_code)]` in every crate.
- New top-level deps require explicit step authorisation. Each Phase 2 step that adds a dep also adds a `cargo deny` entry as needed.
- Optional features (`tpm2`, `s3-replication`, `webhook-alerts`, `rdkit-cheminformatics`, `viennarna`, `blast-screening`) gate every heavy or platform-bound dep so the **default build stays the same lean dependency surface** as Phase 1.
- After every code-changing step run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings`. Don't move on until all three pass.
- One commit per step, message prefixed with the step number (e.g. `step-2-1: wire threat scorer into validator`).
- Never push directly to `main`.

---

## Snapshot of identified gaps (what this spec closes)

| # | Area | What ships today | What's missing |
|---|---|---|---|
| 1 | Threat scorer wiring | `threat.rs` fully implemented (5 detectors) | Validator hard-codes `threat_analysis: None`; nothing calls `analyze()` |
| 2 | Runtime monitors wiring | `monitors.rs` 6 checks implemented | No scheduler, no CLI mode, no alert path |
| 3 | StatefulInvariant pathway | Trait defined in `invariants/mod.rs:417` | Zero implementors; cross-bundle fragmentation undetected |
| 4 | Incident alert sinks | `AlertSink::Webhook` / `Syslog` return `Unavailable` | HTTP POST + UDP datagram impls |
| 5 | Replication backends | `S3Replicator` / `WebhookWitness` return `Unavailable` | Real S3 PUT + Merkle witness POST |
| 6 | HSM key store backends | `Tpm` / `YubiHsm` / `OsKeyring` return `Unavailable` | At least TPM 2.0 behind a feature flag |
| 7 | D9 ΔG estimation | Reverse-complement string match | ViennaRNA (or Rust ΔG approximation) under feature flag |
| 8 | C-family cheminformatics | SMILES regex tokens | SMARTS substructure matching, MW calc, canonical-form |
| 9 | D1–D3 homology | Curated regex DB | BLAST / HMMER / k-mer engines |
| 10 | Codon-usage host hints | Fixed entropy band `[2.5, 5.8]` | Profile-driven CAI / CUTG-derived band |
| 11 | Per-profile protocol vocab | Hard-coded 25-verb list | `BioProfile.allowed_protocol_steps: Option<Vec<String>>` |
| 12 | Attestation nonce durability | In-memory FIFO cache | Persist to / replay from audit log |
| 13 | Performance baseline | No benches | `criterion` harnesses for D/P/C/PR + validator end-to-end |
| 14 | Platform adapters | Zero | Twist + one peptide + one chemical adapter (Phase-2 minimum) |
| 15 | Chemical example bundles | None | `examples/{safe,dangerous}-chemical-bundle.json` |
| 16 | Demo campaign coverage | 3 scenarios (DNA + peptide) | + chemical, + profile-cap, + authority-escalation scenarios |
| 17 | Differential E2E test | Synthetic verdict construction | Real two-config divergence test |
| 18 | Audit replication E2E | Mocked | FS-backed write/read/tamper-detect integration test |
| 19 | Release artifacts | CI builds, no release | GitHub release workflow with linux/macOS/windows binaries |
| 20 | Security audit prep | None | Audit-ready threat-model walk-through, `cargo deny` re-baseline, supply-chain SBOM |
| 21 | Phase 2 PR | n/a | Open PR + handover |

The steps below close each in dependency order.

---

## Step 1 — Re-baseline the workspace

**Goal:** Confirm Phase 1 still builds clean, lock current test counts, create the working branch.

**Prompt for Claude Code:**

> Run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` and report exact pass/fail and per-crate test counts. Do not modify source. If anything fails, stop and report verbatim. If everything passes, ensure the working tree is a git repo (run `git init` first if not, then `git add -A && git commit -m "phase-1 snapshot"`), then create branch `phase-2` off `main` and confirm it is checked out. No code changes.

**Acceptance:** Three green commands; per-crate counts recorded; branch `phase-2` checked out; working tree is a git repo.

---

## Step 2 — Wire the threat scorer into the validator

**Goal:** `threat.rs` is fully implemented but unused. Make the validator instantiate it, feed bundles, gate approval on threshold breach.

**Prompt for Claude Code:**

> Read `crates/invariant-biosynthesis-core/src/threat.rs` and `validator.rs`. Add `threat_scorer: Option<Arc<Mutex<ThreatScorer>>>` to `ValidatorConfig` plus `with_threat_scorer(...)` and `with_threat_alert_threshold(f64)` builders. After invariants run and before signing the verdict, call `scorer.analyze(bundle)`; append a `threat_analysis` `CheckResult` to the verdict; if the composite score ≥ alert threshold, mark the check as failed and block approval. Add `threat_analysis: Option<ThreatAnalysis>` to `ValidationOutput`. Keep the `None` path: when no scorer is configured, no check is appended and behaviour is unchanged. Add 4 tests: (a) no scorer → no check; (b) scorer below threshold → check passes; (c) scorer above threshold → check fails and approval blocked; (d) `ThreatAnalysis` surfaces in `ValidationOutput`.

**Acceptance:** Threat scorer runs in the pipeline behind an opt-in config; approval gated on threshold; ≥4 new tests; clippy clean.

---

## Step 3 — Implement at least one StatefulInvariant

**Goal:** The `StatefulInvariant` trait exists but has no implementors. Ship a fragmentation-bypass detector that catches an attacker splitting a hazardous gene across multiple bundles.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/invariants/`, add `stateful.rs`. Implement `FragmentationBypassDetector`: keeps a per-principal sliding window of recent DNA k-mers (default k=24, window=20 bundles, capped at 200k k-mers per principal). On evaluate, computes Jaccard similarity between the current bundle's k-mer set and the union of recent bundles; if similarity > 0.4 and current bundle is from a different submission than any prior, raises `Advisory`; if a hazard-DB hit appears in the *union* but not in any single bundle, raises `Fail` with the union's class. Add `StatefulInvariantId::S1` and a `Stateful` family enum variant. Wire into the validator behind `ValidatorConfig::with_stateful_invariants(...)`. Add 6 tests covering: empty history pass, single-bundle below-threshold pass, two-bundle similarity advisory, three-bundle hazard-union fail, principal isolation (different principals don't pollute each other), eviction at window cap.

**Acceptance:** New module integrated; validator runs stateful invariants when configured; ≥6 new tests; existing tests still pass.

---

## Step 4 — Implement webhook + syslog incident alert sinks

**Goal:** `AlertSink::Webhook` and `AlertSink::Syslog` currently return `AlertError::Unavailable`. Make them real.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/incident.rs`, replace the `Webhook` stub with an implementation that POSTs the incident JSON to the configured URL with `Content-Type: application/json` (use `ureq` synchronously to avoid bringing tokio into the core crate; add `ureq` as an optional dep gated by feature `webhook-alerts`). Replace the `Syslog` stub with an implementation that sends a UDP datagram in RFC 5424 format to the configured `host:port` (use `std::net::UdpSocket`; no extra dep). Add 4 tests under `#[cfg(test)]`: webhook happy path against a `tiny_http` test server, webhook 5xx path returns `AlertError::Transport`, syslog datagram round-trip via a bound `UdpSocket`, syslog format conforms to RFC 5424 priority field. Document feature flags in the crate-level docs.

**Acceptance:** Both sinks send real messages; ≥4 new tests; default build unaffected when feature off (sink returns `Unavailable` with a clearer "feature `webhook-alerts` not enabled" message).

---

## Step 5 — Implement S3 replication + webhook Merkle witness

**Goal:** `replication.rs` ships two stubs. Phase 2 lights them up behind a feature flag.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/replication.rs`, gate `S3Replicator` behind feature `s3-replication` and depend on `aws-sdk-s3 = "1"` + `tokio = { version = "1", features = ["rt"] }` *only when the feature is on*. Implement `replicate(bytes)` as a `PutObject` call against the configured bucket/prefix; the call runs on a per-replicator owned single-thread tokio runtime so the public API stays sync. Implement `WebhookWitness::publish(merkle_root)` as a synchronous `ureq` POST to the configured URL with `{ "merkle_root": "<hex>", "ts": "<rfc3339>" }`. Add 4 tests behind feature flags using `aws-sdk-s3` localstack-or-mock and a `tiny_http` test server. Document operational concerns (idempotency keys, retry, backoff) in module Rustdoc.

**Acceptance:** Both backends usable behind their feature flags; default build unchanged; ≥4 new tests gated on features in CI.

---

## Step 6 — Implement TPM 2.0 key store backend

**Goal:** `KeyStore::Tpm` returns `Unavailable`. Threat-model §7 requires hardware-bound keys for production.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/keys.rs`, gate `TpmKeyStore` behind feature `tpm2` and depend on `tss-esapi = "7"` only when the feature is on. Implement: key-handle persistence in NV index, Ed25519 signing via `EsysContext::sign`, and verification of the resident key's public point against a stored expected point (refuses to use a swapped key). When the feature is off, retain the existing `Unavailable` stub. Add 3 tests gated on `feature = "tpm2"` using the `tpm2-tools` `swtpm` simulator; document a `make tpm-test` target that spins up swtpm. Leave `OsKeyringKeyStore` and `YubiHsmKeyStore` as stubs with TODO comments referencing this step.

**Acceptance:** TPM backend works against `swtpm` in CI (Linux only); default build unchanged; ≥3 new tests.

---

## Step 7 — Wire runtime monitors into a `monitor` CLI mode

**Goal:** `monitors.rs` has 6 checks (`check_binary_hash`, `check_profile_hash`, `check_audit_tail`, `check_hsm_health`, `check_memory_canary`, `check_clock_drift`) that nothing calls.

**Prompt for Claude Code:**

> Add `commands/monitor.rs` to the CLI: `invariant-bio monitor --interval-s <N> [--alert-webhook <URL>]`. The command runs the six checks on a loop, emits structured JSON lines to stdout, and (when `--alert-webhook` is set) routes any non-`Ok` `MonitorResult` through `incident::Alert::webhook`. Provide `--once` for one-shot execution (used by Kubernetes liveness/readiness probes). Add 5 integration tests: --once happy path, binary-hash mismatch detected, audit-tail tamper detected, clock-drift detected, --alert-webhook path posts to a `tiny_http` server. Update `docs/step7-hsm-key-mgmt.md` and the README operations section to document the monitor mode.

**Acceptance:** Monitor mode shipped; per-check integration tests; docs updated.

---

## Step 8 — Profile-driven codon-usage entropy band (D7)

**Goal:** D7's `[2.5, 5.8]` band is one-size-fits-all. Profiles should be able to override per host organism.

**Prompt for Claude Code:**

> In `models/profile.rs`, add `codon_usage_organism: Option<String>` and `codon_entropy_band: Option<(f64, f64)>` to `BioProfile`. In `invariants/dna.rs::CodonEntropyScreen`, prefer `ctx.profile.codon_entropy_band` when present; otherwise fall back to the existing default. Embed a small CUTG-derived table for `e_coli`, `s_cerevisiae`, `h_sapiens`, `cho_k1` mapping organism → recommended band; if `codon_usage_organism` is set but `codon_entropy_band` is not, look up the table. Update one existing profile (`industry_peptide.json` or similar) to set `codon_usage_organism: "h_sapiens"`. Add 4 tests covering: explicit band, organism lookup, missing override falls back to default, unknown organism is a profile load error.

**Acceptance:** Profile-driven entropy bands work; ≥4 new tests; existing 6 profiles still load + validate.

---

## Step 9 — Profile-driven protocol vocabulary (PR2)

**Goal:** PR2 uses a hard-coded 25-verb list. High-BSL profiles should be able to restrict it.

**Prompt for Claude Code:**

> In `models/profile.rs`, add `allowed_protocol_steps: Option<Vec<String>>`. In `invariants/protocol.rs::ProtocolAllowedVocabulary`, prefer the profile-supplied list when present; otherwise use the built-in default. The supplied list must be a *subset* of the built-in list (reject profile load if not). Add 4 tests: (a) profile-restricted list rejects a verb that the default would allow; (b) empty list rejects everything; (c) profile field absent → default behaviour; (d) profile with non-subset list fails to load. Update `government_bsl4_restricted.json` to set a restricted vocabulary (drop `image`, `transfer`, `wait`).

**Acceptance:** Per-profile vocab works; subset enforcement verified; ≥4 new tests.

---

## Step 10 — Persist attestation nonces across restarts

**Goal:** The replay-prevention nonce cache is in-memory only; a process restart inside the freshness window allows replay.

**Prompt for Claude Code:**

> In `attestation.rs`, add `AttestationVerifier::with_persistent_log(path)` which writes every accepted nonce as a JSONL line `{ "kid": ..., "nonce": ..., "ts": ... }` and on construction reads the file, dropping entries older than `max_age + clock_skew` and seeding the in-memory cache. Use `std::fs::File::options().append(true).create(true)` and an `fs2` advisory file lock to serialise writers (add `fs2` as a top-level dep). Add 5 tests: load-from-empty, load-from-existing replay-rejection, expiry purge on load, concurrent writer lock contention, missing-file → fresh cache. Document operational guidance: file lives next to the audit log; rotates monthly.

**Acceptance:** Persistent nonce log shipped; replay rejected across simulated process restart; ≥5 new tests.

---

## Step 11 — Optional ViennaRNA-backed D9 ΔG screen

**Goal:** D9 today does perfect-reverse-complement string match. Real labs need ΔG.

**Prompt for Claude Code:**

> Add feature `viennarna` to the core crate gating a new dep `viennarna-sys = "0.2"` (or a pure-Rust ΔG approximation crate if that one isn't on crates.io — document the choice). Implement `dna::secondary_structure_dg(seq) -> Option<f64>` returning kcal/mol when feature is on, `None` otherwise. Update `D9SecondaryStructureScreen::evaluate_with` to: when `dg < -10.0`, raise `Fail`; when `dg ∈ [-10.0, -5.0]`, raise `Advisory`; otherwise `Pass`. Keep the existing string-match heuristic as a fallback when the feature is off (no behaviour regression). Add 3 feature-gated tests on known stable hairpin sequences with expected ΔG bands.

**Acceptance:** Feature flag works; D9 strictly stronger when enabled; ≥3 new tests.

---

## Step 12 — Optional RDKit-backed C-family substructure screening

**Goal:** C1–C10 today match SMILES via regex. Real labs need SMARTS.

**Prompt for Claude Code:**

> Add feature `rdkit-cheminformatics` gating a Python-subprocess bridge or Rust-binding to RDKit. Pick one of: (a) `rdkit-rs` (pure Rust, partial SMARTS) for the lean path; (b) `pyo3` + RDKit-Python for full coverage. Document the trade-off in module Rustdoc. Implement `chemical::smarts_match(smiles, pattern) -> Result<bool>`; rewire C1 alkylphosphonate, C5 aromatic-amine, C9 reactive-reagent rules to use SMARTS when the feature is on, regex tokens when off. Add a SMARTS pattern table file `crates/invariant-biosynthesis-core/data/c-family-smarts.json` signed with the existing schema. Add 6 feature-gated tests on canonical positives + negatives per rule.

**Acceptance:** SMARTS path lights up under the feature; default unchanged; ≥6 new tests.

---

## Step 13 — Optional BLAST/HMMER homology screening

**Goal:** D1–D3 / P1–P5 today rely on curated regex; real homology requires BLAST or HMMER.

**Prompt for Claude Code:**

> Add feature `blast-screening` gating a subprocess call to `blastn` / `hmmscan`. Implement `screening::blast_screen(seq, db_path) -> Vec<HazardHit>` that runs a BLAST `outfmt 6` search and converts hits ≥ 70% identity over ≥ 50 nt into `HazardHit`. Implement `screening::hmm_screen(seq, hmm_path) -> Vec<HazardHit>` similarly via `hmmscan`. Add a fallback path: when feature off and `BLAST_DB`/`HMM_PATH` env vars set, log once that the env points to a DB but the feature is disabled (don't silently ignore). Add 3 feature-gated tests using `MakeBlastDB`-built tiny test DBs against the existing safe-bundle and dangerous-bundle. Document install steps for BLAST+ in the README.

**Acceptance:** Real BLAST/HMMER works behind the feature; clear messaging when disabled; ≥3 new tests.

---

## Step 14 — First platform adapter: Twist DNA synthesis

**Goal:** Zero platform adapters ship today. Build the canonical example.

**Prompt for Claude Code:**

> Read `docs/step5-platform-integration.md` §2.1. Add a new crate `crates/invariant-biosynthesis-platform-twist/`: depends on `invariant-biosynthesis-core`, `ureq`, `serde`, `serde_json`. Public surface: `TwistClient::new(api_token)`; `TwistClient::submit(execution_token: &ExecutionToken) -> Result<TwistOrderId>`; the client verifies the execution token's Ed25519 signature against the configured firewall pub key *before* contacting Twist (fail-closed if absent). Mock the Twist HTTP API surface in `mockito` for tests. Add 5 tests: signature-verifies + submit success, signature-mismatch refused, network 5xx surfaces error, malformed response, double-submit idempotency via token nonce. Add a sample profile `profiles/lab_with_twist.json` that declares `platform: "twist"`.

**Acceptance:** Twist adapter ships; signature gate enforced before any network call; ≥5 new tests; sample profile loads.

---

## Step 15 — Second + third platform adapters: peptide (CEM Liberty) and chemical (Chemspeed)

**Goal:** Cover the other two substrate platform shapes; reach the Phase-2 minimum (3 adapters).

**Prompt for Claude Code:**

> Following the Step-14 pattern, add `crates/invariant-biosynthesis-platform-cem/` (REST stub for the CEM Liberty Blue) and `crates/invariant-biosynthesis-platform-chemspeed/` (file-drop adapter writing signed protocol JSON to a watched directory + verifying executor signature on the result file). Each must verify execution-token signature pre-submit. Add 4 tests per crate covering happy path, signature mismatch, transport failure, idempotency. Add sample profiles `profiles/lab_with_cem.json`, `profiles/lab_with_chemspeed.json`.

**Acceptance:** Three platform adapters live; ≥8 new tests across the two new crates; profile library expands to 8 + 3 = 11 entries.

---

## Step 16 — Chemical example bundles + expanded demo campaign

**Goal:** Examples directory has DNA + peptide bundles but no chemical; demo campaign skips chemical scenarios.

**Prompt for Claude Code:**

> Add `examples/safe-chemical-bundle.json` (a benign reagent SMILES — e.g. ethanol) and `examples/dangerous-chemical-bundle.json` (an explosive-token SMILES that trips C2 + C9). Update `examples/demo-campaign.yaml` to add: chemical safe (expect approved), chemical dangerous (expect rejected), profile-volume-cap-exceeded (a DNA bundle whose volume exceeds the profile cap), and an authority-escalation scenario (PCA chain whose declared ops exceed the parent's). Add 4 sim-crate tests covering the new scenarios end-to-end.

**Acceptance:** Two new chemical examples; campaign covers all four substrates + 2 attack scenarios; ≥4 new sim tests.

---

## Step 17 — Performance benches with `criterion`

**Goal:** Lock down a performance baseline before Phase-2 features regress it.

**Prompt for Claude Code:**

> Add `crates/invariant-biosynthesis-core/benches/` with `criterion` harnesses for: D-family (per invariant on a 5000 nt synthetic sequence), P-family (per invariant on a 200 AA synthetic peptide), C-family (per invariant on a 100-char SMILES), PR-family (per invariant on a 64-step protocol), and end-to-end `validator::validate` on each substrate. Record baselines in `benches/BASELINES.md`. Add a CI job `bench` that runs `cargo bench --workspace --no-run` (compile-only) on every PR — full bench runs are reserved for merges to `main`.

**Acceptance:** Bench harness runs locally; baselines recorded; CI compiles benches.

---

## Step 18 — Differential E2E + audit replication E2E tests

**Goal:** Two test gaps the Phase-2 analysis flagged.

**Prompt for Claude Code:**

> (a) In `crates/invariant-biosynthesis-core/tests/`, add `differential_e2e.rs` that runs the **same bundle** through two real `ValidatorConfig`s (different hazard DBs and different profiles), then calls `differential::compare_verdicts` and asserts the diff catches the divergence. (b) Add `audit_replication_e2e.rs`: writes a real audit log to a tempdir with N=20 entries, replicates via a local `FileReplicator`, mutates one byte, asserts tamper detection on read. Both tests must run in <2 s and use no external services.

**Acceptance:** Two new integration tests, both deterministic and hermetic.

---

## Step 19 — Release workflow + binary artifacts

**Goal:** Today CI builds; nothing is published. Phase 2 ships binaries.

**Prompt for Claude Code:**

> Add `.github/workflows/release.yml` that triggers on `tag push: v*`. Builds release binaries for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`. Strips, gzips, computes SHA-256 + Ed25519 signature with a release key (key in repo secrets). Uploads to the GitHub Release. Generates an SBOM via `cargo-sbom` and uploads alongside. Document the release process in `docs/RELEASING.md` (key custody, tag-signing, two-person review).

**Acceptance:** Tagging a `v0.0.6` test tag produces a draft release with 4 signed binaries + SBOM; docs in place.

---

## Step 20 — Pre-audit hardening pass

**Goal:** Prepare the codebase for an external security audit (the Phase-2 spec's exit criterion).

**Prompt for Claude Code:**

> Run, in order: `cargo deny check` (re-baseline; resolve any new advisories), `cargo audit`, `cargo geiger` (confirm zero unsafe), `cargo udeps` (remove unused deps), `cargo doc --workspace --no-deps --document-private-items` with `RUSTDOCFLAGS="-D warnings"`. Walk every `Unavailable` / `not yet implemented` string and either implement it (folded into earlier steps) or move it to an explicit `#[deprecated(note = "phase 3")]` so reviewers see the boundary. Update `SECURITY.md` with the Phase-2 threat model delta + audit contact. Update `docs/threat-model.md` to mark which §3 attack vectors are now actively detected (post-Step-2 threat scorer + post-Step-3 stateful invariant). Produce `docs/AUDIT-READINESS.md` walking auditors through: build, run tests, list of supported features, list of known limitations, list of cryptographic primitives + library versions, supply-chain summary.

**Acceptance:** Five tools clean; `AUDIT-READINESS.md` lands; `SECURITY.md` and threat model reflect Phase-2 state.

---

## Step 21 — Open the Phase-2 PR

**Goal:** Hand Phase 2 over for human review.

**Prompt for Claude Code:**

> Confirm the working tree is clean and the branch is `phase-2`. Push the branch and open a pull request titled `Phase 2 — operational hardening + platform adapters`. The PR body must summarise: the gaps closed (numbered against the table at the top of this spec), the new test/bench count delta per crate, any deferred items, the new feature flags and their default state, the new optional dependencies, and a checklist mirroring this spec's step list. Do not request review; do not merge. Report the PR URL.

**Acceptance:** PR exists; body complete; branch not merged.

---

## Notes on ordering and parallelism

- Steps 2 (threat scorer wiring) and 3 (StatefulInvariant) are independent and can be done in parallel by separate agents in worktrees.
- Steps 4 (incident sinks), 5 (replication), and 6 (TPM) are independent and can each be done in parallel.
- Steps 8 (codon profile band), 9 (protocol vocab), and 10 (nonce persistence) are independent core-crate tweaks.
- Steps 11 (ViennaRNA), 12 (RDKit), 13 (BLAST/HMMER) are independent feature-gated dep additions; expect each to add ~2–4 hours of CI time only when the relevant feature is selected.
- Steps 14–15 (platform adapters) are independent of everything else and can land at any time after Step 1.
- Steps 17–20 are strictly final.

If you parallelise, give each parallel worktree its own branch off `phase-2` and merge them serially with a single integration commit before Step 20.

---

## Out-of-scope for Phase 2 (deferred to Phase 3)

These are real gaps but explicitly **not** in this spec:

1. **OS keyring + YubiHSM key store backends** — TPM 2.0 (Step 6) is sufficient for production; OS keyring and YubiHSM cover dev/edge cases that can wait.
2. **Multi-institutional federation** — cross-institution PCA cross-signing is in `docs/step4-pca-research-auth.md` but not on the Phase-2 critical path.
3. **AI/LLM integration tests** — `docs/step10-community-ecosystem.md` describes integration with LLM lab planners; integration tests require live model endpoints.
4. **Formal verification** — Lean 4 proofs of invariant correctness (mentioned in `docs/spec.md`) are Phase 3.
5. **GUI / Web UI** — there is no plan for one; CLI + library is the supported surface.
6. **FDA 21 CFR Part 11 / EU eIDAS qualified signature compliance** — flagged in `docs/step9-regulatory-compliance.md`; integration with regulator-specific signature schemes is out of scope.

Phase 3 will be planned after Phase 2 lands and the external audit completes.
