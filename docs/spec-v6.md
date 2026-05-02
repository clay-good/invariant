# spec-v6 — Gap Closure Plan

**Status:** Active
**Date:** 2026-04-29
**Supersedes:** docs/spec-gaps.md (which is now baseline; this document is the executable plan)
**Companion to:** docs/spec.md, docs/spec-v5.md, docs/spec-15m-campaign.md

This document is a **deep gap analysis** of the current Rust workspace against the cumulative specs (spec.md → spec-v5.md plus spec-15m-campaign.md) and an **executable closure plan** written as Claude Code prompts.

Each section below is a self-contained prompt you can paste into Claude Code (or invoke via `Agent`). Prompts are ordered so that earlier ones unblock later ones. Do not skip ahead — Phase 2 depends on Phase 1's data structures, etc.

Conventions used in every prompt:
- Always run `cargo build`, `cargo test`, and `cargo clippy -- -D warnings` after a change.
- Always read the cited files before modifying them.
- One commit per gap, message format `gap-NN: <title>`.
- If a prompt says "extend X", first re-read X to see what already exists; do not duplicate.

---

## Verified ground truth (2026-04-29)

These observations were confirmed by reading the tree and form the basis of the gaps below.

- `crates/invariant-core/src/audit.rs` and `models/audit.rs` track `sequence: u64` but **no session_id, no temporal binding, no executor identity, no predecessor digest** beyond the prev-hash chain.
- `crates/invariant-core/src/keys.rs:413, 462, 510` — OS keyring, TPM, and YubiHSM stores are documented stubs returning `KeyStoreError::Unavailable`.
- `crates/invariant-core/src/replication.rs:169, 257, 289` — S3 and webhook replication sinks return `ReplicationError::Unavailable`.
- `crates/invariant-cli/src/commands/` lists 23 subcommand files; **no `assemble.rs`** for `invariant campaign assemble` (proof-package builder).
- `proof_package.rs` exists but has no Merkle root, no Ed25519 manifest signature, no causal-binding A3.
- Profiles directory (`profiles/`) contains ~17 JSON files; spec-v5 §Profiles claims 34 supported platforms.
- `crates/invariant-sim/` has only `cnc_tending.py` Isaac Lab env; spec-v5 references humanoid, quadruped, dexterous-hand, mobile-base envs.
- `crates/invariant-fuzz/` has scenarios but coverage relative to spec-15m-campaign's 104 scenario types is sparse (~22 of 104 wired into the campaign harness).

---

## Phase 1 — Authority & safety (P0/P1, must land first)

### Prompt 1.1 — Implement execution-binding invariants B1–B4

You are closing a P0 safety gap. The cumulative spec defines four execution-binding invariants the audit log must enforce, but only a partial form (prev-hash chain + monotonic sequence) is implemented today.

**Read first:**
- `docs/spec.md` (search for "B1", "B2", "B3", "B4", "execution binding")
- `docs/spec-v5.md` for the latest definitions
- `crates/invariant-core/src/audit.rs`
- `crates/invariant-core/src/models/audit.rs`

**Task:** Extend `AuditEntry` and `AuditLogger` so that every appended entry carries:
- **B1 — Session binding:** a `session_id: [u8; 16]` (UUIDv4-style, generated when the logger is constructed) included in the canonical hash preimage.
- **B2 — Sequence monotonicity:** the existing `sequence` field, but the append path must use a compare-exchange / locked update so two concurrent appends cannot both write sequence N. Add a regression test that spawns 16 threads each appending 1k entries and asserts no gap, no duplicate, total = 16k. The current code path may have a TOCTOU window between `self.sequence += 1` and the hash computation — fix that by holding a `&mut self` for the entire append (or, if the type is `Arc<Mutex<…>>`-shaped already, by widening the critical section).
- **B3 — Temporal binding:** include a monotonic timestamp (`std::time::Instant`-derived nanos since logger start) **and** a wall-clock `chrono::DateTime<Utc>` in the preimage. Reject append if the wall clock would step backward more than the configured skew tolerance (default 5s) — return a new `AuditAppendError::ClockRegression` variant.
- **B4 — Executor identity:** include `executor_id: String` (operator/process identity) in the preimage. Pass it in via `AuditLogger::new` so it's fixed for the lifetime of the logger.

**Hash preimage order** (document this in a doc-comment on `AuditEntry::compute_hash`): `previous_hash || sequence_be || session_id || executor_id_len_be || executor_id_bytes || monotonic_nanos_be || wall_clock_rfc3339 || payload_canonical_json`.

**Backward compatibility:** none required. Older audit logs without these fields are simply rejected by the verifier; do not add a v1/v2 fork. Update all `AuditEntry` test fixtures.

**Acceptance criteria:**
- New unit tests for each of B1–B4 (4 tests minimum, plus the concurrency stress test).
- `cargo clippy -- -D warnings` passes.
- `invariant audit verify` (CLI) still works against a freshly-written log.
- Document the four invariants in the module-level doc-comment of `audit.rs` with `# B1 Session`, `# B2 Sequence`, `# B3 Temporal`, `# B4 Executor` subsections.

---

### Prompt 1.2 — Add causal binding A3 (predecessor digest)

**Read first:** `docs/spec.md` for "A3", "causal binding", "predecessor digest"; `crates/invariant-core/src/audit.rs`; any `proof_package.rs` references.

**Problem:** Today the audit chain self-binds (entry N references hash of entry N-1), but there is no binding from a *new* chain back to the most recent entry of the *previous* chain when a logger is rotated or a new session begins. This permits a "chain splice" attack where two valid chains are presented for the same execution.

**Task:**
1. In `AuditLogger::resume(...)` (the function that lets you continue from a known sequence/hash) require an additional parameter `predecessor_digest: [u8; 32]`. Store it on the logger.
2. The first entry produced by `resume` (or the genesis entry from `new`) must include `predecessor_digest` in its hash preimage. For a fresh genesis chain, use `[0u8; 32]`.
3. Verifier (`AuditLogger::verify`) takes a new arg `expected_predecessor: Option<[u8; 32]>`. If `Some`, verify entry 0 used it as predecessor; if `None`, require `[0u8; 32]`.
4. Wire this into the proof package: `manifest.json` records `predecessor_digest` for each chain segment, and `invariant audit verify --predecessor <hex>` is added to the CLI.

**Acceptance:** unit tests for genesis, resume-with-correct-predecessor, resume-with-wrong-predecessor (must fail). Update `crates/invariant-cli/src/commands/audit.rs` for the new flag.

---

### Prompt 1.3 — Strengthen sequence monotonicity under concurrency

**Note:** this may already be folded into Prompt 1.1. If after 1.1 the stress test passes, mark this gap closed and skip. Otherwise:

**Task:** Convert the append path to use either `parking_lot::Mutex<Inner>` with a single critical section spanning `read sequence → compute hash → write entry → bump sequence`, or restructure so `&mut self` is held throughout. Do *not* use atomic fetch-add and then hash — that introduces a window where two threads compute hashes against the same `previous_hash`.

Add a `loom`-style test gated behind a feature flag (`cfg(loom)`) that exhaustively explores 2-thread interleavings for the append path.

---

## Phase 2 — Proof package core (P1, blocks 15M campaign delivery)

### Prompt 2.1 — Merkle tree over audit log entries

**Read first:** `docs/spec-v5.md` (Merkle, proof-package), `crates/invariant-core/src/proof_package.rs`, `crates/invariant-core/src/audit.rs`.

**Task:** Add `audit::merkle` module:
- Function `pub fn merkle_root(entries: &[AuditEntry]) -> [u8; 32]` using SHA-256, leaf hash = `H(0x00 || entry.entry_hash)`, node hash = `H(0x01 || left || right)` (RFC 6962 style — domain separation between leaves and internal nodes is mandatory). Odd-count levels duplicate the last node.
- Function `pub fn merkle_proof(entries: &[AuditEntry], index: usize) -> MerkleInclusionProof` returning the sibling path.
- Function `pub fn verify_inclusion(leaf_hash: [u8; 32], proof: &MerkleInclusionProof, root: [u8; 32]) -> bool`.
- Add `merkle_root` to the proof-package manifest (Prompt 2.2).

**Acceptance:** unit tests with 1, 2, 3, 7, 1024 entries; cross-verify by computing a known root by hand for the 3-entry case; property test (`proptest`) that any inclusion proof for a random index verifies.

---

### Prompt 2.2 — Sign manifest.json with Ed25519

**Read first:** `crates/invariant-core/src/proof_package.rs`, `crates/invariant-core/src/keys.rs`, `docs/spec.md` for manifest schema.

**Task:**
1. Define `ProofManifest` struct (or extend the existing one) with at minimum: `schema_version`, `package_id` (UUID), `created_at` (RFC 3339), `audit_merkle_root`, `audit_chain_predecessor`, `entry_count`, `executor_id`, `session_id`, `signing_key_fingerprint`, plus a list of artifact entries each with `path`, `sha256`, `size_bytes`.
2. Canonicalize via JCS (RFC 8785) — use `serde_jcs` if available, otherwise implement a minimal sorted-key serializer; document the choice.
3. `pub fn sign_manifest(manifest: &ProofManifest, signer: &dyn KeyStore, key_id: &str) -> SignedManifest` writes `manifest.json` plus `manifest.sig` (raw 64-byte Ed25519). Public key is embedded in the package as `pubkey.pem`.
4. `pub fn verify_manifest(manifest_path, sig_path, pubkey_path) -> Result<ProofManifest>` and the corresponding CLI: `invariant proof verify <package-dir>`.

**Acceptance:** round-trip test (sign → verify), tampered-byte test (flip one byte in manifest, expect SignatureInvalid), wrong-key test.

---

### Prompt 2.3 — Add `invariant campaign assemble` subcommand

**Read first:** `crates/invariant-cli/src/commands/campaign.rs`, `crates/invariant-cli/src/commands/mod.rs`, `crates/invariant-cli/src/main.rs`, `docs/spec-15m-campaign.md` (assembly section).

**Task:** Add a new subcommand `invariant campaign assemble --input <run-dir> --output <package.tar.zst> [--key-id <id>]` that:
1. Walks the run directory, collects audit log segments, traces, evaluator outputs, fuzz reports, profile snapshot, and any artifacts referenced by them.
2. Verifies each audit segment locally (Prompt 1.2 verifier).
3. Computes Merkle root over the concatenated audit entries (Prompt 2.1).
4. Builds and signs a `ProofManifest` (Prompt 2.2).
5. Tars-and-zstd-compresses the directory, embedding `manifest.json`, `manifest.sig`, `pubkey.pem` at the root of the archive.
6. Prints a summary table (entry count, root hex, size, fingerprint) on stdout in the existing CLI style.

Use the existing CLI plumbing (`clap` derives, existing logging), and place the implementation in a new file `crates/invariant-cli/src/commands/campaign_assemble.rs` referenced from `commands/mod.rs` and the campaign subcommand router.

**Acceptance:** integration test under `crates/invariant-cli/tests/` that runs assemble on a fixture run-dir and then `invariant proof verify` on the output.

---

## Phase 3 — Campaign scenario coverage (P1, parallelizable across N agents)

### Prompt 3.1 — Inventory missing scenarios for the 15M campaign

**Read first:** `docs/spec-15m-campaign.md` in full. List every distinct scenario type it enumerates (the prior gap analysis estimated ~104; verify by counting).

**Task:** Produce `docs/scenario-coverage.md` (a *report*, not a spec) with a table: scenario name, spec section, status (`implemented` / `partial` / `missing`), and for implemented ones the concrete file path under `crates/invariant-fuzz/src/` or `crates/invariant-sim/src/` plus the registration site in the campaign runner.

Do not implement anything in this prompt — only audit. The report's job is to feed Prompts 3.2–3.N below.

**Acceptance:** the report compiles into a punch list. Cross-check at least 20 entries by opening their cited files.

---

### Prompt 3.2 — Implement the next batch of missing scenarios

**Read first:** `docs/scenario-coverage.md` (output of Prompt 3.1), `crates/invariant-fuzz/src/lib.rs` and existing scenarios for the established pattern.

**Task:** Pick the **5 highest-impact missing scenarios** (impact = appears in spec-15m-campaign §Category A or §Category B "must include"). For each:
1. Add a scenario module under `crates/invariant-fuzz/src/scenarios/` (or the project's existing convention — check first).
2. Register it in the scenario registry / dispatcher used by the campaign command.
3. Add at least one positive and one negative test per scenario.
4. Add a row in the campaign config describing the scenario's parameters and expected verdict distribution.

**Repeat this prompt** with different "next 5" until `docs/scenario-coverage.md` shows zero missing entries. Track progress by re-running the audit step from Prompt 3.1 at the end of each batch.

**Acceptance per batch:** `cargo test -p invariant-fuzz` passes; the campaign harness can dispatch the new scenarios; the coverage report is regenerated.

---

## Phase 4 — Production backends (P1, parallelizable; each is self-contained)

### Prompt 4.1 — Implement OS keyring KeyStore

**Read first:** `crates/invariant-core/src/keys.rs:413` (the OS keyring stub), the `keyring` crate docs.

**Task:** Replace the stub with a real implementation backed by the `keyring` crate (already in Cargo.toml? — check; if not, add it with version pinned). Service name `org.invariant-robotics`. Operations: `generate`, `sign`, `public_key`, `delete`. Map `keyring::Error::NoEntry` → `KeyStoreError::NotFound`, other errors → `KeyStoreError::Backend`.

Gate behind `#[cfg(feature = "os-keyring")]` and add the feature to `Cargo.toml`. Default off; CI runs at least one job with it on (Linux secret-service or macOS keychain).

**Acceptance:** integration test that round-trips a generated key (gated on the feature flag, skipped when unavailable in CI).

---

### Prompt 4.2 — Implement TPM and YubiHSM KeyStores

**Read first:** `crates/invariant-core/src/keys.rs:462, 510`.

**Task:** Two crates, two stubs, same shape as 4.1 but using `tss-esapi` for TPM and `yubihsm` for YubiHSM. Both behind feature flags (`tpm`, `yubihsm`). Both default off. Both must implement the full `KeyStore` trait and pass the same round-trip test (skipped when hardware absent).

If either crate is non-trivial to integrate in CI, document the manual test procedure in a `tests/README.md` rather than blocking on hardware.

---

### Prompt 4.3 — Implement S3 audit replication sink

**Read first:** `crates/invariant-core/src/replication.rs:169, 257`.

**Task:** Replace the stub with an S3 implementation using `aws-sdk-s3`. Bucket and prefix configured via `ReplicationConfig`. Each replicated entry written as `<prefix>/<session_id>/<sequence:020>.json`. Use `if-none-match: *` (or equivalent S3 conditional put) to make replication idempotent and to detect chain forks.

Behind feature flag `s3-replication`. Add an integration test using `localstack` if available in CI; otherwise gate with `#[ignore]` and document.

---

### Prompt 4.4 — Implement webhook audit replication and webhook alert sink

**Read first:** `crates/invariant-core/src/replication.rs:289`, plus alert sink code (search for "WebhookAlertSink" and "SyslogAlertSink").

**Task:** Webhook replication: HTTPS POST of canonical JSON, HMAC-SHA256 signature header `X-Invariant-Signature: <hex>` using a shared secret from config. 5xx → exponential backoff with jitter, max 5 retries. 4xx → permanent failure.

Webhook alert sink: same wire shape but a different payload schema (alert, not audit entry). Syslog alert sink: RFC 5424 over UDP and TCP, configurable.

All three behind feature flag `replication-net`. Each gets a wiremock-based unit test.

---

## Phase 5 — Correctness & robustness (P2)

### Prompt 5.1 — Bound the bridge `read_line` buffer

**Read first:** `crates/invariant-sim/` for the Isaac Lab bridge — find the `read_line` call and its surrounding loop.

**Problem:** unbounded `BufRead::read_line` against a network/pipe peer is an OOM vector — a malicious or buggy simulator can stream gigabytes without a newline.

**Task:** Replace `read_line` with a `take(MAX_LINE).read_until(b'\n', &mut buf)` pattern. `MAX_LINE = 1 MiB` by default, configurable via `BridgeConfig::max_line_bytes`. On overrun: drain to the next newline (so we resync), emit a `BridgeError::OverlongLine` event, and continue.

**Acceptance:** unit test that feeds 2 MiB without a newline and asserts the error is raised within bounded memory.

---

### Prompt 5.2 — Reconcile profile catalogue (claim 34, have ~17)

**Read first:** `profiles/`, `crates/invariant-core/src/profiles.rs`, the profile list in `docs/spec-v5.md`.

**Task:** Produce `docs/profile-coverage.md` listing every profile claimed by the spec, every profile file present, and the delta. For each missing profile, either:
- add the JSON file (if the platform is real and parameters are publicly known — use manufacturer datasheets and cite them in a `source_urls` field on the profile), or
- remove the claim from `spec-v5.md` (with a one-line note in the changelog) if the platform was aspirational.

Do not fabricate datasheet numbers. If a parameter is not publicly known, mark it `null` and add a `verification: "manufacturer_datasheet_pending"` field.

**Acceptance:** `invariant profile list` count matches the spec count; every claimed profile loads cleanly under `invariant profile validate <id>`.

---

### Prompt 5.3 — Backfill end_effectors and environment blocks on existing profiles

**Read first:** `crates/invariant-core/src/profiles.rs` to find the `end_effectors` and `environment` schema; spec-v5 for which profile checks (P11–P25 per the prior gap analysis) require which fields.

**Task:** Walk every JSON file in `profiles/`. For each that lacks `end_effectors` or `environment`, fill in defaults consistent with the platform class (industrial arm, mobile base, humanoid, quadruped, dexterous hand). Default-but-explicit is better than absent — silent skipping of physics checks is the bug we're fixing.

Add a CI lint (`scripts/check_profiles.sh` or similar) that fails if any profile is missing required blocks.

**Acceptance:** running `invariant validate` against representative traces now exercises P11–P25 on every profile.

---

### Prompt 5.4 — Profile schema validator: reject impossible parameters

**Read first:** `crates/invariant-core/src/profiles.rs`, `crates/invariant-cli/src/commands/profile_cmd.rs`.

**Task:** Extend the validator with cross-field consistency checks:
- `joint_limits.max_velocity` ≥ `joint_limits.cruise_velocity` ≥ 0
- end-effector grip force range strictly positive and `min < max`
- mass / inertia tensors positive-definite (eigenvalue check)
- environment temperature operating range strictly within survival range
- duty-cycle ∈ [0, 1]

Each violation is a distinct error variant with the offending field path. Add a regression test per check using a deliberately-broken profile fixture under `crates/invariant-core/tests/fixtures/profiles/bad_*.json`.

---

## Phase 6 — Simulation & evaluation breadth (P3)

### Prompt 6.1 — Add Isaac Lab environments for missing platform classes

**Read first:** `crates/invariant-sim/` (find existing `cnc_tending.py`), `docs/runpod-simulation-guide.md`, `docs/spec-v5.md` simulation section.

**Task:** Add Isaac Lab env scripts for: humanoid (e.g. Unitree H1), quadruped (e.g. ANYmal C / Spot), dexterous hand (e.g. Allegro), 6-axis arm general (UR5e), mobile base (Clearpath Jackal). Each env exposes the same observation/action interface as `cnc_tending.py` so the bridge does not need changes per env.

Each env gets a smoke test under the runpod guide's "verify install" section.

---

### Prompt 6.2 — Differential evaluator regression suite

**Read first:** `crates/invariant-core/src/differential.rs`, `crates/invariant-cli/src/commands/differential.rs`, `crates/invariant-eval/`.

**Task:** The differential evaluator compares two model runs; the spec promises monotonicity, determinism, and stability properties. Add a regression suite that:
- Fixes a seed, runs twice, asserts byte-identical diff output (determinism).
- Runs with epsilon=0 vs epsilon=1e-12 and asserts diff is empty (continuity at zero perturbation).
- Runs with a known deviation injected and asserts the diff localizes it to within the correct trace window.

Place tests under `crates/invariant-eval/tests/`.

---

## Phase 7 — Documentation, polish, release (P4)

### Prompt 7.1 — Reconcile docs against shipped behavior

**Read first:** `README.md`, `docs/public-release-polish.md`, `docs/spec-v5.md`.

**Task:** Walk every "the CLI supports …" claim in the README and the public-release-polish checklist. For each, run the actual subcommand with `--help` and confirm the synopsis matches. For each mismatch, prefer fixing the docs (less risky than changing CLI surface this late). Produce `CHANGELOG.md` entries for any flag/output changes since the last release.

---

### Prompt 7.2 — Compliance matrix

**Read first:** `crates/invariant-cli/src/commands/compliance.rs`, `docs/spec.md` compliance section, ISO 15066 / ISO 10218 / ANSI R15.06 references in `crates/invariant-core/src/physics/iso15066.rs`.

**Task:** Produce `docs/compliance-matrix.md` — for each cited standard clause, list the implementing module(s) and the test(s) that exercise it. Mark unmapped clauses as `aspirational` and either add a stub test that captures the intent (`#[ignore]`-d with a reason string) or strike the claim from the docs.

Update `invariant compliance status` to read this matrix and print a truthful summary.

---

### Prompt 7.3 — CI: matrix build, clippy gate, MSRV

**Read first:** any existing GitHub Actions or CI config in the repo root and `.github/`.

**Task:** Ensure CI runs:
- `cargo build --workspace --all-targets` on stable Linux, macOS, Windows.
- `cargo test --workspace --all-targets`.
- `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo fmt --all -- --check`.
- `cargo deny check` (config already at `deny.toml`).
- A nightly job that builds with `--all-features` to catch feature-flag bit-rot.
- Pin MSRV via `rust-toolchain.toml` (already present — verify it matches what the workspace actually uses).

If `.github/workflows/` does not exist, create the necessary YAML; otherwise extend.

---

## Cross-cutting prompts

### Prompt X.1 — Dead-code and TODO sweep

**Task:** Run `cargo +stable build --workspace --all-targets 2>&1 | grep -E "warning|TODO|unimplemented"` and `rg -n "TODO|FIXME|XXX|unimplemented!\(\)" crates/`. For each finding, either resolve, file a tracking issue with link in the comment, or delete dead code. Do not silence warnings with `#[allow]` without a justification comment.

---

### Prompt X.2 — Property tests for invariant kernel

**Read first:** `crates/invariant-core/src/validator.rs` and `crates/invariant-core/src/physics/`.

**Task:** Add `proptest` cases to the validator. For each physics check (P1..PN), generate random in-range and out-of-range inputs and assert the verdict matches the analytical answer. Aim for ≥256 cases per check, seeded for reproducibility.

---

### Prompt X.3 — Fuzz the parser surfaces

**Task:** Add `cargo-fuzz` targets under `fuzz/` for: profile JSON parser, audit-log entry parser, manifest parser, URDF parser (`crates/invariant-core/src/urdf.rs`), bridge line parser (after Prompt 5.1). Run each for at least 5 minutes locally before committing the corpus seed.

---

## Sequencing summary

```
Phase 1 (1.1, 1.2, 1.3) ──► Phase 2 (2.1, 2.2, 2.3) ──► Phase 3 (3.1 → 3.2 batches)
                                                  │
                                                  └► Phase 4 (4.1 ║ 4.2 ║ 4.3 ║ 4.4)   ─┐
Phase 5 (5.1, 5.2, 5.3, 5.4)  — anytime after Phase 1                                     │
Phase 6 (6.1, 6.2)            — anytime after Phase 5                                     │
Phase 7 (7.1, 7.2, 7.3)       — last, after everything else stabilizes  ◄─────────────────┘
X.1, X.2, X.3                  — opportunistic, run alongside any phase
```

`║` denotes prompts that can run on parallel agents because they touch disjoint files. Phase 3 batches are also parallelizable as long as each batch picks distinct scenario names.

---

## Definition of done for spec-v6

- Phase 1 prompts merged and `cargo test --workspace` green.
- Phase 2 prompts merged; `invariant campaign assemble` produces a package that `invariant proof verify` accepts.
- Phase 3: `docs/scenario-coverage.md` shows zero `missing` rows.
- Phase 4: each of the four backends has at least one CI job exercising it.
- Phase 5–7: their respective acceptance criteria met.
- `docs/spec-gaps.md` is updated with a "closed by spec-v6 prompt N.M" annotation per row, or deleted if fully superseded.
