# spec-v5.md — Gap-Closure Workplan

**Date:** 2026-05-01
**Status:** Active workplan. Supersedes `spec-gaps.md` for outstanding items.
**Audience:** Claude Code (and human collaborators) executing one task at a time.
**Format:** Each task is written as a self-contained prompt you can paste into a fresh Claude Code session. Do not include code snippets here — let the executing model read the current code and write the patch.

This file does **not** redefine invariants, scenarios, or architecture. For semantics, the canonical references are `spec.md` and `spec-15m-campaign.md`. This file is purely a list of gaps and the prompts that close them.

Tasks are grouped by severity (P1 → P4) and ordered so that earlier tasks unblock later ones. Each task has:

- **ID** — stable identifier (matches the gap analysis IDs)
- **Why this matters** — one sentence
- **Spec anchors** — exact references the executor must read first
- **Code anchors** — exact files the executor must read first
- **Prompt** — the instructions to give Claude Code
- **Done when** — observable acceptance criteria

---

## How to use this document

1. Pick the lowest-numbered open task.
2. Open a fresh Claude Code session in the repo root.
3. Paste the **Prompt** block verbatim. The prompt assumes no prior context.
4. After the model reports done, manually verify the **Done when** checks.
5. Commit per the repo convention (one commit per logical unit, never push to main).
6. Strike through the task here (or move it to a "completed" section) before starting the next.

If a prompt produces a result that fails verification, do not edit the prompt to make it pass — re-open the prompt with new context describing what failed and why. Drift in the prompt language drifts the outcome.

---

# P1 — Safety-critical and proof-package gaps

These block the Guardian-mode safety claim and the 15M-episode proof package. Land them first.

---

## TASK P1-01 — Add predecessor-digest binding to PCA chain (closes A3 / G-09)

**Why this matters.** Today `verify_chain` checks each hop's signature and monotonicity, but does not check that hop N is causally bound to hop N-1. Two independently valid chains signed by the same key can be spliced. Spec §3.3 invariant A3 ("Continuity") requires causal binding.

**Spec anchors (read first).**
- `docs/spec.md` lines 230–232 (PoC definition) and 388–392 (A3 statement).
- `docs/spec-15m-campaign.md` line 179 (G-09 attack: cross-chain splice, expected REJECT).

**Code anchors (read first).**
- `crates/invariant-core/src/authority/chain.rs` (`verify_chain` and helpers)
- `crates/invariant-core/src/models/authority.rs` (the `SignedPca` / `Pca` types and any serialization)
- Any fixture files under `crates/invariant-core/src/authority/tests/` or similar that build PCA chains
- All call sites of `verify_chain` (use ripgrep)

**Prompt.**

> You are closing gap A3 in the Invariant Robotics codebase: the PCA chain verifier does not bind hop N to hop N-1, which permits a cross-chain splice attack. Read `docs/spec.md` lines 220–410 (definitions, A1/A2/A3) and `docs/spec-15m-campaign.md` lines 170–185 (G-09 description) before touching code. Then read `crates/invariant-core/src/authority/chain.rs` and `crates/invariant-core/src/models/authority.rs` end-to-end, plus every call site of `verify_chain` and every test fixture that constructs a `SignedPca` chain.
>
> Implement predecessor-digest binding:
> 1. Add a `predecessor_digest: Option<[u8; 32]>` field to the signed-PCA structure. The root hop has `None`; every subsequent hop has `Some(sha256(canonical_bytes(prev_hop)))`. Use a stable canonical serialization (the same one already used for signing) — do not invent a new one.
> 2. Update the signing helper(s) to compute and populate this field when chaining a new hop.
> 3. Update `verify_chain` to reject any non-root hop whose `predecessor_digest` does not match the SHA-256 of the previous hop's canonical bytes. The error must be a distinct variant (e.g. `ChainError::PredecessorMismatch { hop_index }`), not folded into a generic signature error.
> 4. Update every existing fixture and helper that builds chains so existing tests still pass.
> 5. Add a new test `g09_cross_chain_splice_rejected` that builds two valid 5-hop chains with the same signing key, swaps hop 4 from chain B into chain A, and asserts `verify_chain` returns `PredecessorMismatch { hop_index: 4 }`.
> 6. Add a positive test that asserts a freshly-built chain verifies and that every non-root hop's `predecessor_digest` matches the SHA-256 of the prior hop.
>
> Do not change unrelated code. Do not add comments explaining what the code does. Run `cargo test -p invariant-core` and `cargo clippy -- -D warnings` and fix any issues you introduce. Migration: if any on-disk fixtures contain serialized chains, regenerate them with the helper rather than hand-editing.

**Done when.**
- `cargo test -p invariant-core` passes.
- `cargo clippy --workspace -- -D warnings` passes.
- `g09_cross_chain_splice_rejected` exists and passes.
- `rg "predecessor_digest" crates/` shows the field defined, populated by the signing helper, checked by the verifier, and exercised by ≥2 tests.

---

## TASK P1-02 — Implement Execution Binding invariants B1–B4

**Why this matters.** Spec §3.3 lists four binding invariants — session, sequence, temporal, executor — but none are enforced. A command authorized for one session/executor can be replayed in another. Category H scenarios in the campaign cannot pass without this.

**Spec anchors (read first).**
- `docs/spec.md` lines 394–435 (B1–B4 definitions, watchdog).
- `docs/spec-15m-campaign.md` Category H (temporal/sequence attacks).

**Code anchors (read first).**
- `crates/invariant-core/src/authority/` (whole module — note `binding.rs` does not yet exist).
- `crates/invariant-core/src/validator.rs` (the validator entry point).
- `crates/invariant-cli/src/commands/serve.rs` (per-connection state).
- `crates/invariant-core/src/models/command.rs` (or wherever `Command` and sequence are defined).

**Prompt.**

> You are implementing the four Execution Binding invariants (B1 session, B2 sequence, B3 temporal window, B4 executor identity) defined in `docs/spec.md` §3.3 lines 394–435. Read that section in full, then read every file under `crates/invariant-core/src/authority/` and the validator entry point at `crates/invariant-core/src/validator.rs`. Also read `crates/invariant-cli/src/commands/serve.rs` to understand how per-connection state is held today.
>
> Build a new module `crates/invariant-core/src/authority/binding.rs`:
> - Define `ExecutionContext { session_id: Uuid, executor_id: String, time_window_sec: u32 }` and a per-context counter holding the last accepted sequence number.
> - Define `BindingError` with one variant per invariant (`SessionMismatch`, `SequenceReplay`, `OutsideTemporalWindow`, `ExecutorMismatch`) so verdict reasons are unambiguous.
> - Provide a `verify_execution_binding(cmd, ctx, pca)` function that checks all four bindings in a documented order and returns the first failure.
> - The sequence check must be atomic with the acceptance side-effect: use `compare_exchange` (or equivalent) so two concurrent commands with the same sequence cannot both succeed. If you cannot make it atomic inside this function alone, expose a `try_advance_sequence` helper that the caller uses after all other checks pass.
>
> Wire it through:
> - Extend the validator to accept (and require) an `ExecutionContext` for any signed command path. Sim-only paths may bypass via a clearly-named test helper, but no production path may bypass.
> - In `serve.rs`, hold one `ExecutionContext` per accepted connection. Reject any command whose `executor_id` or `session_id` does not match.
>
> Add tests in `crates/invariant-core/src/authority/binding.rs` (or sibling test file): one passing and one failing test per invariant (8 minimum). The B2 hostile test must spawn ≥10 concurrent acceptance attempts of the same sequence and assert exactly one succeeds.
>
> Update `docs/spec-15m-campaign.md` Category H scenario IDs only if the existing IDs are inconsistent with the new error variants — do not invent new scenario IDs.
>
> Do not add fallback "unbound" code paths for backwards compatibility. Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

**Done when.**
- `crates/invariant-core/src/authority/binding.rs` exists.
- 8+ binding tests pass; the B2 concurrency test asserts `1 == winners`.
- `serve.rs` holds per-connection `ExecutionContext` and rejects mismatches.
- `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` pass.

---

## TASK P1-03 — Add G-07 wildcard-exploitation tests

**Why this matters.** Wildcard semantics are documented but never exercised by adversarial tests. G-07 in the campaign expects `actuate:*` to be rejected when used to authorize `read:sensor`.

**Spec anchors (read first).**
- `docs/spec-15m-campaign.md` lines 175–180 (G-07).
- Wildcard semantics in `crates/invariant-core/src/models/operations.rs` (read the existing comments).

**Code anchors (read first).**
- `crates/invariant-core/src/authority/tests.rs` (or wherever G-series tests live — `rg "G-0" crates/`).
- `crates/invariant-core/src/models/operations.rs`.

**Prompt.**

> Add adversarial tests for the G-07 wildcard exploitation case described in `docs/spec-15m-campaign.md` lines 175–180. First read `crates/invariant-core/src/models/operations.rs` to confirm wildcard semantics, then locate the existing G-series tests via `rg "G-0[0-9]" crates/` and add two new tests in the same file (or the most analogous test module):
>
> - `test_g07_actuate_wildcard_does_not_cover_read`: assert that an authority granting `actuate:*` cannot authorize `read:proprioception`.
> - `test_g07_move_arm_wildcard_does_not_cover_base`: assert that `move:arm:*` cannot authorize `move:base:forward`.
>
> If the existing wildcard-matching helper is missing the necessary semantics, fix it — but the fix must not loosen any other check. Run `cargo test -p invariant-core` and `cargo clippy --workspace -- -D warnings`.

**Done when.** Both tests exist and pass; `rg "G-07" crates/` shows them.

---

## TASK P1-04 — Implement S3 audit replication and webhook witness

**Why this matters.** Audit completeness invariants L1–L4 in `spec.md` §2.4 require off-system witnesses. Today both `S3Replicator` and `WebhookWitness` return `Unavailable`.

**Spec anchors (read first).**
- `docs/spec.md` §2.4 (audit completeness L1–L4) and §6 (deployment).

**Code anchors (read first).**
- `crates/invariant-core/src/replication.rs` end-to-end.
- The audit logger (`crates/invariant-core/src/audit.rs`) — understand how entries are appended and how the Merkle root rotates.
- `Cargo.toml` workspace and `crates/invariant-core/Cargo.toml` (you will be adding optional deps behind features).

**Prompt.**

> Implement real backends for `S3Replicator` and `WebhookWitness` in `crates/invariant-core/src/replication.rs`, replacing the `Unavailable` stubs. Read that file and `crates/invariant-core/src/audit.rs` end-to-end first.
>
> Put both backends behind cargo features:
> - `replication-s3` — pulls in `aws-sdk-s3` and friends.
> - `replication-webhook` — pulls in `reqwest` (rustls only, no native TLS) and `hmac` + `sha2`.
> Default features must not change. The stubs remain compiled when features are off and continue to return `Unavailable`.
>
> S3 backend requirements:
> - Object key: `{prefix}/{epoch_ms}-{seq:020}.jsonl` to keep lexical ordering.
> - Server-side encryption with KMS (`SSE-KMS`) key configured at construction.
> - On retryable errors, exponential backoff with jitter, capped retries, then surface a typed error.
> - Resume: persist last-replicated sequence on disk in the audit directory (`replication_state.json`). On startup, replay from the next sequence.
>
> Webhook backend requirements:
> - On Merkle root rotation, POST `{root, count, signature}` JSON to the configured URL.
> - Sign the body with HMAC-SHA256 using a configured shared secret. Header: `X-Invariant-Signature`.
> - Bounded in-memory queue (configurable, default 1024); on overflow, spill to a file in the audit directory and resume on next successful send.
>
> Do not block the validator hot path. The replication tasks must run on a separate async task (use the existing tokio runtime if one is in scope; otherwise spawn one in a dedicated module).
>
> Tests:
> - Unit tests for the resume-from-disk logic (no network required).
> - Feature-gated integration test for S3 against a MinIO container. If you cannot stand up MinIO in the local dev environment, write the test guarded behind `#[ignore]` with a comment giving the docker command to run it.
> - Feature-gated integration test for the webhook backend against `wiremock` or a hand-rolled `tokio` listener.
>
> Run `cargo test --workspace`, `cargo test --workspace --features replication-s3,replication-webhook`, and `cargo clippy --workspace --all-features -- -D warnings`.

**Done when.**
- Default `cargo build` and `cargo test` still work.
- `cargo build --features replication-s3,replication-webhook` succeeds.
- `replication_state.json` mechanism survives a restart in the unit test.
- Webhook integration test verifies HMAC signature.

---

## TASK P1-05 — Implement WebhookAlertSink and SyslogAlertSink

**Why this matters.** Without real alert sinks, production deployments are blind. Spec §6 incident hooks reference both.

**Spec anchors (read first).**
- `docs/spec.md` §6 incident-hook section.
- `docs/spec-v3.md` hardening section.

**Code anchors (read first).**
- `crates/invariant-core/src/incident.rs` (see the two stub sinks).

**Prompt.**

> Implement real `WebhookAlertSink` and `SyslogAlertSink` in `crates/invariant-core/src/incident.rs`. Read the file and the `Incident`/`Severity` types end-to-end first.
>
> Put each behind a feature: `alerts-webhook` (uses `reqwest` rustls), `alerts-syslog` (uses a maintained syslog crate — do not write a hand-rolled UDP packet builder unless no decent crate exists; if you must, RFC 5424 compliant).
>
> Webhook sink:
> - POST signed JSON `{incident_id, severity, verdict_id, message, timestamp}`.
> - HMAC-SHA256 header `X-Invariant-Signature`.
> - Bounded retry queue with disk spillover under the audit directory.
>
> Syslog sink:
> - RFC 5424 structured-data carries `verdict_id` and `severity`.
> - Support both UDP (default) and TCP+TLS (when configured with cert paths).
>
> Hard requirement: neither sink may block the validator hot path. Use a bounded async channel with non-blocking `try_send`; on overflow, increment a dropped-alerts counter (exposed in the existing health endpoint if there is one) and drop the alert. Log the drop at WARN level once per N drops to avoid log floods.
>
> Tests: unit tests with in-process listeners. Run `cargo test --workspace --all-features` and `cargo clippy --workspace --all-features -- -D warnings`.

**Done when.** Both sinks send real packets in tests; default build is unchanged; dropped-alerts counter is observable.

---

## TASK P1-06 — Implement OS-keyring / TPM / YubiHSM key stores

**Why this matters.** Guardian mode assumes hardware-backed keys; today every backend silently falls back to file-based storage.

**Spec anchors (read first).**
- `docs/spec.md` §7 (limitations, root-key security).
- `docs/spec-v3.md` §2.1.

**Code anchors (read first).**
- `crates/invariant-core/src/keys.rs` (the three stubs around lines 400–550).
- The `keygen` CLI (`crates/invariant-cli/src/commands/keygen.rs`) so you can plumb a `--store` flag.

**Prompt.**
>
> Replace the `Unavailable` stubs in `crates/invariant-core/src/keys.rs` for `OsKeyringKeyStore`, `TpmKeyStore`, `YubiHsmKeyStore`. Read the file end-to-end and the `keygen` CLI command first.
>
> Each backend goes behind its own feature flag (`keystore-os`, `keystore-tpm`, `keystore-yubihsm`). Default features unchanged. Use these crates if available and maintained: `keyring`, `tss-esapi`, `yubihsm`.
>
> Keep the existing `KeyStore` trait surface — backends must support `generate`, `load`, `sign`, and `delete`. If hardware backends cannot expose private key material (they should not), `load` returns a handle, not bytes; `sign` operates via the handle. Do not introduce a separate trait for hardware — the trait must accommodate both.
>
> Plumb a `--store {file,os,tpm,yubihsm}` flag to `keygen` and any other CLI command that creates or signs with keys. The flag's available values should reflect the compiled-in features.
>
> Tests: unit tests for the file backend stay; for hardware backends, gate with `#[cfg(feature = "...")]` and `#[ignore]` and document the prerequisites in a comment (e.g. `swtpm` for TPM, `softhsm`/YubiHSM SDK simulator for YubiHSM, OS keychain for the OS backend). Do not silently skip — `#[ignore]` keeps them visible.
>
> Run `cargo build --features keystore-os`, `cargo build --features keystore-tpm`, `cargo build --features keystore-yubihsm`, `cargo test --workspace`, `cargo clippy --workspace --all-features -- -D warnings`.

**Done when.** All three feature builds compile; CLI `--help` for `keygen` shows the available `--store` values; ignored hardware tests exist with documented prerequisites.

---

## TASK P1-07 — Add SHA-256 Merkle tree and signed manifest to proof package

**Why this matters.** The proof package is the headline campaign artifact. Today the manifest is unsigned and there is no Merkle root or inclusion proof for individual audit entries — exactly the verifiability the campaign promises.

**Spec anchors (read first).**
- `docs/spec-15m-campaign.md` lines 371–407 (proof-package layout, `audit/merkle_root.txt`, signed `manifest.json`).

**Code anchors (read first).**
- `crates/invariant-core/src/proof_package.rs` end-to-end.
- `crates/invariant-cli/src/commands/verify_package.rs`.
- `crates/invariant-core/src/audit.rs` (entry serialization).

**Prompt.**
>
> Implement Merkle-tree generation and signed-manifest support for the proof package. Read `docs/spec-15m-campaign.md` lines 371–407 first, then `crates/invariant-core/src/proof_package.rs` and `crates/invariant-cli/src/commands/verify_package.rs` end-to-end.
>
> Changes:
> 1. In `proof_package.rs`, build a binary SHA-256 Merkle tree over the canonical bytes of every audit JSONL entry (one leaf per entry, in file order). For odd nodes, duplicate the last node at each level (standard Bitcoin-style padding).
> 2. Write the root to `audit/merkle_root.txt` as lowercase hex.
> 3. Provide `pub fn merkle_proof(seq: u64) -> Result<Vec<[u8; 32]>>` returning the inclusion-proof path. Provide a sibling verifier `pub fn verify_merkle_proof(leaf, proof, root) -> bool`.
> 4. Sign `manifest.json` with the campaign Ed25519 key. The signature goes in a separate file `manifest.sig` (binary or hex — pick one and stick with it). The signing key path comes from a new `--key` flag on the assembly entry point. If no key is provided, do not silently skip — return an error so the caller cannot accidentally produce an unsigned package.
> 5. Update `verify_package`:
>    - Take a `--public-key` argument; verify `manifest.sig` against `manifest.json` using it.
>    - Re-build the Merkle tree from the JSONL files and assert the root matches `audit/merkle_root.txt`.
>    - Re-check existing per-file SHA-256 digests in `manifest.json`.
> 6. Round-trip test on a 2-shard fixture: assemble → verify must pass; mutate one byte of any audit entry → verify must fail with a clear error pointing at the failing leaf or file.
>
> Do not change the JSONL format or the existing per-file digest scheme — only add the Merkle root and signature on top. Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

**Done when.** Round-trip test passes; tampering test fails with a leaf-specific error; `merkle_root.txt` and `manifest.sig` appear in the fixture output; `verify-package` rejects an unsigned manifest by default.

---

## TASK P1-08 — Wire `invariant campaign assemble` CLI subcommand

**Why this matters.** Today `proof_package::assemble` is a library API only, so the campaign artifact must be hand-assembled. The §7 roadmap calls for a CLI.

**Spec anchors (read first).** `docs/spec-15m-campaign.md` §7 (implementation roadmap).

**Code anchors (read first).**
- `crates/invariant-cli/src/main.rs` (subcommand registry).
- `crates/invariant-cli/src/commands/campaign.rs` (existing dry-run subcommand).
- The library API completed in TASK P1-07.

**Prompt.**
>
> Add an `assemble` action to the existing `invariant campaign` subcommand (or, if `clap` structure makes a flat subcommand cleaner, add `invariant campaign-assemble` — pick whichever matches the existing `clap` style in `crates/invariant-cli/src/main.rs`). First, read `main.rs` and `crates/invariant-cli/src/commands/campaign.rs` to match conventions.
>
> Behavior:
> - Inputs: `--shards <DIR>` (one subdirectory per shard, each containing JSONL audit + summary), `--output <PATH>` (proof-package directory or tarball), `--key <PATH>` (Ed25519 signing key for the manifest, required after TASK P1-07).
> - Calls the library `proof_package::assemble` from TASK P1-07.
> - Computes per-category Clopper-Pearson 95% CIs from the per-shard summaries and writes them under `stats/` in the package.
> - On success, prints the proof-package root path and the manifest digest. Exit 0.
> - On any error (missing shard, bad key, signature failure), exit non-zero with a clear message.
>
> Add an integration test under `crates/invariant-cli/tests/` that runs the binary against a 2-shard fixture and then runs `invariant verify-package` against the output. Both must succeed.
>
> Update `CLAUDE.md` and `README.md` subcommand lists. Run `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo run -p invariant-cli -- campaign --help` to sanity-check the help output.

**Done when.** New subcommand visible in `--help`; round-trip integration test passes; docs updated.

---

## TASK P1-09 — Expand campaign scenarios from 22 to all 104 IDs

**Why this matters.** The 15M-episode statistical claim assumes 104 scenarios across categories A–N. Only 22 exist today.

**Spec anchors (read first).**
- `docs/spec-15m-campaign.md` §3 (scenarios A-01 … N-08), §2.1 (per-category episode counts).

**Code anchors (read first).**
- `crates/invariant-sim/src/scenario.rs` (`ScenarioType` enum and helpers).
- `crates/invariant-sim/src/campaign.rs` (scenario generation and the per-category counts).

**Prompt.**
>
> Expand the campaign scenario coverage to all 104 IDs defined in `docs/spec-15m-campaign.md` §3. Read that section in full and `crates/invariant-sim/src/scenario.rs` and `crates/invariant-sim/src/campaign.rs` end-to-end before changing anything.
>
> Approach:
> 1. Decide whether to add 82 enum variants or to introduce a parameterized `Scenario { category: Category, index: u8, params: ScenarioParams }`. Choose whichever requires less duplication for the parameter sweeps in Categories B and C. Document the decision in a one-line comment at the top of the type.
> 2. Implement `fn spec_id(&self) -> String` returning the canonical ID (e.g. `"B-04"`).
> 3. Implement `fn from_spec_id(id: &str) -> Option<Self>` for round-tripping.
> 4. Provide `fn all_scenario_entries() -> impl Iterator<Item = Self>` enumerating all 104.
> 5. Update the campaign generator so the per-category episode counts in the spec match the generated plan exactly. Sum must equal 15,000,000.
>
> Tests:
> - All 104 IDs round-trip through `from_spec_id` / `spec_id`.
> - `all_scenario_entries().count() == 104`.
> - Per-category episode counts match the spec table; failure messages name the category and the delta.
>
> Do not implement the per-scenario episode logic in this task — only the enumeration, IDs, and counts. Per-scenario behavior is exercised by the existing simulator and by Isaac envs (TASK P1-10). Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

**Done when.** Round-trip test on 104 IDs; total-episode test equals 15M; per-category counts match spec.

---

## TASK P1-10 — Add Isaac Lab task environments for all profile families

**Why this matters.** The campaign currently only has `cnc_tending.py`. The 34 built-in profiles span arms, humanoids, quadrupeds, hands, and mobile manipulators. Without envs, the campaign cannot run live.

**Spec anchors (read first).**
- `docs/spec-15m-campaign.md` §2.4 (Isaac Lab integration), §3 (profile families).

**Code anchors (read first).**
- `isaac/envs/` (existing `cnc_tending.py` and `cell_config.py`) — these are the conventions to match.
- `crates/invariant-sim/src/isaac/bridge.rs` (the protocol the envs speak).
- `crates/invariant-cli/src/commands/campaign.rs` (the dry-run shim).
- `docs/runpod-simulation-guide.md` for deployment context.

**Prompt.**
>
> Add Isaac Lab task environments for all profile families used in the 15M campaign. Read `isaac/envs/cnc_tending.py` and `isaac/envs/cell_config.py` to learn the conventions, then read `crates/invariant-sim/src/isaac/bridge.rs` for the wire protocol and `docs/runpod-simulation-guide.md` for deployment context.
>
> Create one env per family in `isaac/envs/`:
> - `arm.py` — 6/7 DOF arm pick-and-place
> - `humanoid.py` — bimanual upper-body manipulation
> - `quadruped.py` — locomotion + arm (if applicable)
> - `hand.py` — dexterous in-hand manipulation
> - `mobile_base.py` — mobile manipulator (base + arm)
>
> Each must implement `reset(seed) -> obs`, `step(action) -> (obs, info)`, and `observe() -> SensorPayload` matching the bridge protocol. Use deterministic seeding throughout — no `time.time()` or `random()` without a seeded RNG.
>
> Add `isaac/run_campaign.py`, a headless driver that:
> - Reads a campaign-config JSON (the format already produced by `generate_15m_configs`).
> - Spawns the right env per scenario.
> - Streams per-episode JSON traces to stdout (one JSON object per line).
> - Supports `--shard <i>/<n>` to partition work across nodes.
> - Supports `--max-episodes` to bound runs for smoke tests.
>
> Smoke test (separate from CI; document the command in `docs/runpod-simulation-guide.md`): 1000 Category-A episodes for one humanoid profile and one arm profile, with zero validator errors and a complete audit JSONL.
>
> Do not change the bridge protocol. If you find a mismatch between the bridge and what these envs need, file it as a follow-up note in this file (TASK P2-NEW) — do not change the protocol unilaterally.

**Done when.** Five env files exist; `run_campaign.py` parses an existing config and runs end-to-end on at least one env locally; smoke-test command is documented.

---

# P2 — Correctness, integration, and missing CLI surface

---

## TASK P2-01 — Split SR1 (env-state range) and SR2 (payload range) checks

**Why.** Spec §2.2 lists them as distinct invariants; both are folded into one `CheckResult` today, so coverage cannot be accounted separately.

**Anchors.** Read `docs/spec-v2.md` lines 139–145 and `crates/invariant-core/src/physics/environment.rs` lines 361–427 plus the registration in `crates/invariant-core/src/physics/mod.rs` line 326.

**Prompt.**
>
> Split the single `check_sensor_range` in `crates/invariant-core/src/physics/environment.rs` into two functions: `check_sensor_range_env` (SR1) and `check_sensor_range_payload` (SR2), each producing its own `CheckResult` with distinct check IDs `"SR1"` and `"SR2"`. Update the registration in `physics/mod.rs` so both are invoked. Update any test that asserts on `"sensor_range"` to assert on the new IDs. Add tests covering: SR1 fails / SR2 passes; SR1 passes / SR2 fails; both pass; both fail. Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

**Done when.** Both check IDs appear in verdicts; four new tests pass.

---

## TASK P2-02 — Make audit-write failure non-silent (closes L1 gap)

**Why.** Today `serve.rs` logs an audit-write error to stderr and still returns the verdict. That violates L1 (every command must produce a signed verdict and an audit entry).

**Anchors.** `crates/invariant-cli/src/commands/serve.rs` lines ~420–445; `docs/spec.md` §2.4 L1.

**Prompt.**
>
> In `crates/invariant-cli/src/commands/serve.rs`, harden the audit-write path. Read the whole file first.
>
> Changes:
> - Add an `audit_errors: AtomicU64` counter to the existing `AppState`.
> - Increment it on any audit write failure.
> - Expose the counter in the existing `/health` (or equivalent) endpoint.
> - Add a CLI flag `--fail-on-audit-error`. When set, any audit write failure causes the request to return HTTP 503 instead of the verdict, and the verdict is not delivered downstream.
> - Default behavior (log + continue + increment) is preserved when the flag is unset, so this is non-breaking.
>
> Tests: an integration test for each mode (default and `--fail-on-audit-error`), simulating an audit failure by pointing the audit log at an unwritable path. Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

**Done when.** Counter visible in `/health`; both modes covered by tests.

---

## TASK P2-03 — Per-connection watchdog in the Isaac bridge

**Why.** Today a single shared watchdog means a second misbehaving client can starve the first client's safe-stop.

**Anchors.** `crates/invariant-sim/src/isaac/bridge.rs` lines 13–16 (the FIXME comment) and the bridge loop.

**Prompt.**
>
> Replace the shared watchdog state in `crates/invariant-sim/src/isaac/bridge.rs` with per-connection state. Read the whole file first.
>
> Two acceptable designs — pick whichever matches the existing concurrency model:
> 1. One watchdog per accepted connection, each tracking its own last-heartbeat.
> 2. Single-client enforcement: reject the second connection with `BridgeError::SecondClient`.
>
> Justify the choice in the commit message, not in a code comment.
>
> Test: spawn two concurrent clients, one sending invalid commands, and assert both clients (or just the first, in design 2) reach safe-stop within the configured timeout. Run `cargo test -p invariant-sim` and `cargo clippy --workspace -- -D warnings`.

**Done when.** New test passes; the FIXME comment is gone (because the issue is fixed, not because the comment is silently deleted).

---

## TASK P2-04 — Add `validate-profiles --strict` subcommand and CI enforcement

**Why.** Profile validation gaps (missing `environment`, missing `end_effectors`) silently disable safety checks.

**Anchors.** `profiles/`, `crates/invariant-core/src/profiles.rs`, `crates/invariant-cli/src/main.rs`.

**Prompt.**
>
> Add a `validate-profiles` subcommand to `invariant-cli` that, in `--strict` mode, fails when a profile permits operations but lacks the corresponding required block. Read `crates/invariant-core/src/profiles.rs` to understand current loading and validation, then `crates/invariant-cli/src/main.rs` to match subcommand style.
>
> Rules in strict mode:
> - A profile that permits any motion-affecting operation must have an `environment` block, OR be marked `"adversarial": true`.
> - A profile that permits manipulation operations must have an `end_effectors` block, OR be marked `"platform_class": "locomotion-only"`, OR be marked `"adversarial": true`.
> - Add fields `adversarial: bool` (default false) and `platform_class: Option<String>` to the profile schema. Update profile parsing accordingly.
>
> Then update the eleven flagged profiles (see prior gap-closure spec for the list — verify it against current state with `rg -l 'environment\|end_effectors' profiles/`):
> - Add `"adversarial": true` to the four `adversarial_*.json` profiles that intentionally omit blocks.
> - Add `"platform_class": "locomotion-only"` to `spot.json`, `quadruped_12dof.json`, `unitree_a1.json`, `unitree_go2.json`, `anybotics_anymal.json`.
> - Add the missing `end_effectors` block to `agility_digit.json` (or, if you cannot define it accurately, mark it `"platform_class": "locomotion-only"` and document why in `CHANGELOG.md`).
>
> Add a CI step (`.github/workflows/*.yml`) that runs `invariant validate-profiles --strict --dir profiles/`. Add a unit test that does the same.
>
> Run `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, and the new validator binary against `profiles/` locally.

**Done when.** New subcommand exists; all built-in profiles pass strict validation; CI enforces it.

---

## TASK P2-05 — Add `fleet` subcommand and 10-robot coordinator integration test

**Why.** `invariant-coordinator` exists but is only pairwise tested and has no CLI surface.

**Anchors.** `crates/invariant-coordinator/src/`, `crates/invariant-cli/src/main.rs`, `docs/spec.md` lines 534–538.

**Prompt.**
>
> Expose `invariant-coordinator` through a new CLI subcommand and add a 10-robot integration test. Read the whole `crates/invariant-coordinator/` crate first, then look at how other subcommands are wired in `crates/invariant-cli/src/`.
>
> CLI:
> - `invariant fleet status [--coordinator <ADDR>]` prints separation guarantees, partitioning state, and stale-policy status. Output format: human-readable by default, with a `--json` flag for machine-readable.
>
> Integration test:
> - Set up 10 robots (8 arms + 2 mobile bases) running through the coordinator.
> - Verify pairwise separation invariants hold across all 45 pairs.
> - Exercise at least one partition split and merge.
>
> If the coordinator API does not currently support 10-robot fleets (e.g. has hard-coded pairwise assumptions), fix that first; do not skip the test.
>
> Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

**Done when.** Subcommand exists; 10-robot integration test passes; output formats both work.

---

## TASK P2-06 — Tighten the serve sequence-counter to use compare-exchange

**Why.** TOCTOU between `last_sequence.load()` and the later `fetch_max()` allows two concurrent commands with the same sequence to both pass. This duplicates B2 enforcement that should also be added by TASK P1-02; do this task only if P1-02's binding helper does not already replace the serve.rs path.

**Prompt.**
>
> If TASK P1-02's `try_advance_sequence` helper now governs the serve path, this task is no-op — verify and mark it complete in this file. Otherwise: in `crates/invariant-cli/src/commands/serve.rs`, replace the load-then-set sequence pattern with a `compare_exchange_weak` loop on the `AtomicU64` so only one concurrent caller wins. Add a stress test that spawns ≥10 concurrent requests with the same sequence and asserts exactly one returns success.

**Done when.** Either marked redundant (with one-line note) or stress test passes.

---

## TASK P2-07 — Per-check distinct IDs (L1–L4, M1, W1, SR1, SR2) in verdict reasons

**Why.** Today rejected verdicts cannot be attributed to specific invariants for campaign analysis.

**Anchors.** `crates/invariant-core/src/models/verdict.rs`, every site that constructs a `Reject` with a reason string.

**Prompt.**
>
> Standardize check-ID strings in rejection verdicts. Read `crates/invariant-core/src/models/verdict.rs` and `rg "Verdict::Reject\|reason:" crates/`.
>
> Define a constants module (e.g. `verdict::check_ids`) with `pub const L1: &str = "L1"; ...` for L1, L2, L3, L4, M1, W1, SR1, SR2 (and any other invariants currently using prose-only reasons). Update every `Reject` site to include the corresponding check ID at the start of the reason string in a parseable form (e.g. `"[L1] audit write failure: ..."`).
>
> Add a campaign-analysis test that scans a fixture audit log and counts rejects per check ID; assert each ID has at least one passing and one failing fixture.
>
> Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

**Done when.** Every listed check ID appears in at least one passing and one failing fixture; the analysis test enumerates all IDs.

---

## TASK P2-08 — Per-category success-criteria tests

**Why.** Only Category B has strict success-criteria assertions; A and C–N do not, so a campaign regression in any other category goes undetected.

**Anchors.** `crates/invariant-sim/src/campaign.rs` (look for `generate_15m_success_criteria_strict`), `docs/spec-15m-campaign.md` §5.

**Prompt.**
>
> Extend `generate_15m_success_criteria_strict` (or the analogous helper) in `crates/invariant-sim/src/campaign.rs` to cover all 14 categories A–N. Read `docs/spec-15m-campaign.md` §5 and the existing Category B implementation first.
>
> The criteria must be expressed declaratively (e.g. as a `&[(Category, MinApprovalRate, MaxRejectRate)]` table) so they are visibly aligned with the spec. Add a test that enumerates the 14 categories and fails with a category-named message if any is missing.
>
> Run `cargo test -p invariant-sim` and `cargo clippy --workspace -- -D warnings`.

**Done when.** Test enumerates all 14 categories and passes.

---

## TASK P2-09 — Wire `invariant-ros2` into the workspace or move it to examples

**Why.** Today `invariant-ros2/` sits at the repo root, is not in the workspace `Cargo.toml`, and has no smoke test. README implies it is integrated.

**Prompt.**
>
> Decide and implement: either (a) add `invariant-ros2/` to the workspace `members` in the root `Cargo.toml`, ensure it builds with `cargo build`, and add a smoke test exercising at least one publisher and one subscriber against a stub; or (b) move it to `examples/invariant-ros2/` and update README to qualify it as an example integration that is unmaintained until milestone X.
>
> Make the decision based on whether the crate currently compiles cleanly and has any active call sites in the workspace. If it does not compile and no other crate depends on it, choose (b). Document the choice in `CHANGELOG.md`.

**Done when.** Either workspace build is green including ros2, or directory is moved and README updated.

---

# P3 — Documentation, performance, supply-chain

---

## TASK P3-01 — Reconcile spec lineage and consolidate

**Why.** Five overlapping spec files plus this one is confusing. Some claim to supersede each other.

**Prompt.**
>
> Make `docs/spec.md` the canonical live spec and `docs/spec-15m-campaign.md` the campaign addendum. Read all current spec files in `docs/` first.
>
> Move `spec-v1.md`, `spec-v2.md`, `spec-v3.md`, `spec-v4.md` to `docs/history/`, each with a one-line header redirecting readers to `spec.md`. Move `spec-gaps.md` and `spec-v5.md` (this file) to `docs/workplans/` once their items are closed; until then leave them at `docs/`.
>
> Add a "Specification History" section at the bottom of `spec.md` summarizing what each archived version contributed.
>
> Do not edit the substantive content of any spec — only the headers and the lineage section.

**Done when.** Archived files moved; redirect headers in place; lineage section in `spec.md`.

---

## TASK P3-02 — Stop hardcoding test counts in docs

**Why.** README, CHANGELOG, and spec-v2 all cite different test counts (~2047, 128 doc-tests, 2023+); the actual count is ~1800. Drift.

**Prompt.**
>
> Add a CI step that runs `cargo test --workspace` and emits the parsed `test result: ok. N passed` count to `docs/test-count.txt`. Replace hard-coded counts in `README.md`, `CHANGELOG.md`, `docs/spec-v2.md`, `public-release-polish.md`, and any spec files with a reference to that file (e.g. "see `docs/test-count.txt` for the current passing-test count").
>
> Do not commit the generated file with a stale value — either commit it from a fresh local run before merging, or have CI commit it post-merge (only if a CI workflow already does post-merge commits; otherwise leave it as a build artifact).

**Done when.** No spec/README contains a hard-coded test count; `docs/test-count.txt` exists and is current.

---

## TASK P3-03 — Document the formal-proof status honestly

**Why.** `spec.md` §8 reads as if the master safety theorem is proven, but `formal/` contains `sorry`s and `axiom`s.

**Prompt.**
>
> Audit every file under `formal/` and produce `formal/README.md` containing a table of theorem name | status (`proved` / `sorry` / `axiom`) | spec cross-reference. Use ripgrep to find every `sorry` and `axiom`.
>
> Then update `docs/spec.md` §8 (and any other section that overstates) to say "specifies; mechanized proofs in progress" and reference `formal/README.md` for the current state of each theorem. Do not delete the proof sketches.
>
> Optionally, add a non-blocking CI job that runs `lake build` if Lean is available, and reports a warning (not failure) if it doesn't compile.

**Done when.** `formal/README.md` exists and is accurate; spec.md §8 wording matches reality.

---

## TASK P3-04 — Reduce hot-path allocations in the validator

**Why.** ~26 clones per command at 1kHz adds up; the latency budget is 350µs.

**Prompt.**
>
> Profile and reduce hot-path allocations in `crates/invariant-core/src/validator.rs`. First, write a Criterion benchmark (`benches/validator.rs` if not present) measuring p50/p95/p99 single-command validation latency on a representative profile. Run it and record the baseline.
>
> Then reduce allocations without changing public API:
> - Convert profile-name and profile-hash fields to `Arc<str>`.
> - Replace `String` fields constructed per-command from constants with `&'static str` or `Cow<str>` where lifetimes permit.
> - Stream the SHA-256 input rather than materializing the full canonical JSON when computing the command digest.
>
> Re-run the benchmark and report the delta in the commit message. Stop optimizing once p99 < 250µs on the test machine, or once further changes require API breakage. Run `cargo test --workspace` and `cargo bench --workspace`.

**Done when.** Benchmark exists; p99 improvement reported in commit message; no API change.

---

## TASK P3-05 — Optimize `read_last_line` in the audit logger

**Why.** Current implementation issues one syscall per byte scanning backward.

**Prompt.**
>
> In `crates/invariant-core/src/audit.rs`, replace the byte-by-byte backward scan in `read_last_line` with a single read of the last 128 KiB (or file size, whichever is smaller) into a buffer and a backward scan in memory. Handle the edge case where the last line is longer than 128 KiB by doubling the buffer until found or EOF reached.
>
> Add tests for: empty file, single line shorter than buffer, file ending in newline, file not ending in newline, line spanning buffer boundary, line longer than initial buffer. Add a microbenchmark or just-time-this-test on a 100 MB synthetic log; target startup time < 10 ms.
>
> Run `cargo test -p invariant-core` and `cargo clippy --workspace -- -D warnings`.

**Done when.** New tests pass; benchmark/timed test under 10 ms.

---

## TASK P3-06 — Generate and sign SBOM in release workflow

**Why.** Supply-chain hygiene; called out in `spec-v3.md` §4.3.

**Prompt.**
>
> Update `.github/workflows/release.yml` (create if it doesn't exist) to:
> - Install `cargo-cyclonedx`.
> - Generate `sbom.cdx.json` for the workspace.
> - Sign it with the release key (use whatever release-signing mechanism is already in place; if none, use `cosign` with a keyless OIDC flow and document the choice in `SECURITY.md`).
> - Attach `sbom.cdx.json` and its signature to the GitHub release.
>
> Do not add unrelated workflow changes.

**Done when.** Release workflow produces and attaches a signed SBOM.

---

## TASK P3-07 — Reproducible-build verification script

**Why.** Closes the supply-chain story.

**Prompt.**
>
> Add `scripts/repro.sh` that builds the `invariant` binary inside the published `Dockerfile`, computes its SHA-256, and asserts it matches a checked-in expected digest at `scripts/repro.expected.sha256`. The script exits non-zero on mismatch. Document in `SECURITY.md` how to update the expected digest after an intentional toolchain or dependency bump (i.e. the policy: only on tagged releases, signed-off by maintainer).
>
> Do not add this to CI yet (reproducibility takes a session to verify); leave it as a manual `make repro` target.

**Done when.** Script exists, runs locally, documented.

---

## TASK P3-08 — Compliance mapping documents

**Why.** Proof package references compliance/, but the mapping documents do not exist.

**Prompt.**
>
> Create `docs/compliance/`:
> - `iec_61508_mapping.md`
> - `iso_10218_mapping.md`
> - `iso_ts_15066_mapping.md`
> - `nist_ai_600_1_mapping.md`
>
> Each maps spec sections (with `spec.md` line references) to standard requirements (citing standard section numbers) and to code locations (file paths). Tables are fine; prose is not required. Do not invent compliance claims that the code does not actually meet — if a requirement is partially met or out of scope, say so.
>
> Update the proof-package assembly (TASK P1-08) to copy `docs/compliance/` into the package under `compliance/`.

**Done when.** Four mapping files exist with non-trivial content; proof package includes them.

---

## TASK P3-09 — Shadow-deployment runbook

**Why.** §7 Step 7 of the campaign spec calls for ≥100 robot-hours of shadow deployment; today the only doc is exploratory.

**Prompt.**
>
> Write `docs/shadow-deployment.md` covering:
> - Prerequisites (signed binary, hardware key store, Guardian-mode config).
> - Cell setup (sensor calibration, network isolation, kill-switch wiring).
> - Metric collection plan: divergence rate, validator latency p50/p95/p99, rejection rate per category, alert volumes.
> - Divergence triage protocol: who looks at what, in what order, with what tools.
> - Sign-off criteria for moving from shadow to active enforcement.
>
> Length: prefer prescriptive checklists over prose. Do not duplicate the spec; reference it.

**Done when.** Document exists with all five sections and at least one explicit sign-off criterion per metric.

---

# P4 — Polish

---

## TASK P4-01 — `docs/cli-reference.md` with examples per subcommand

**Prompt.**
>
> Generate `docs/cli-reference.md` with one section per `invariant` subcommand (use `cargo run -p invariant-cli -- --help` and per-subcommand `--help` to enumerate). Each section: synopsis, every flag (with default), one realistic example invocation, expected exit codes. Cross-reference the spec section that motivates each subcommand.

**Done when.** File exists; every subcommand has an example.

---

## TASK P4-02 — `docs/deployment-modes.md`

**Prompt.**
>
> Write `docs/deployment-modes.md` describing Forge (sim), Shadow (real robot, unsigned), and Guardian (real robot, signed) modes; embedded vs sidecar CAT placement; process isolation expectations; production key-management options (file/keyring/TPM/YubiHSM, see TASK P1-06). Use a comparison table; cite spec sections.

**Done when.** File exists with the table and three mode sections.

---

# Glossary of "Done when" verifications

For every task above, the bare minimum is:

1. `cargo build --workspace` succeeds.
2. `cargo test --workspace` (and any added feature combinations) pass.
3. `cargo clippy --workspace --all-features -- -D warnings` is clean.
4. The "Done when" bullets in the task itself are observably true.
5. Commit message follows the repo convention; one logical unit per commit; not pushed to `main`.

If any of those fail, the task is not done — even if the prompt said so.
