# spec-v6 — Gap Remediation Plan

**Status**: living plan
**Date**: 2026-04-28
**Branch at authoring**: `codelicious/spec-spec-15m-campaign-part-7`
**Supersedes (for remediation tracking)**: `docs/spec-v5.md`, `docs/spec-gaps.md`
**Authoritative spec**: `docs/spec.md` (and `docs/spec-15m-campaign.md` for campaign-specific scope)

This document is the result of a deep gap analysis between the spec corpus
(`docs/spec*.md`, `docs/spec-15m-campaign.md`, `docs/spec-gaps.md`,
`docs/public-release-polish.md`, `docs/runpod-simulation-guide.md`) and the
actual code in `crates/`, `formal/`, `fuzz/`, `campaigns/`, `isaac/`,
`invariant-ros2/`, `profiles/`, `examples/`, and `scripts/`.

Each gap is captured as a **self-contained Claude Code prompt**. A future
Claude Code session should be able to execute any single prompt without
re-reading this file in full. Prompts are prose instructions, not code
snippets — they tell Claude what to read, what to add, what to test, and
what CLI wiring to put in place.

## How to use this file

1. Pick the **next unblocked gap** in execution order (blockers first, then
   important, then nice-to-have). The dependency notes inside each prompt
   call out hard ordering constraints (e.g. G3 depends on G1, G31 builds
   on G8).
2. Spawn a Claude Code session and paste the prompt body verbatim.
3. After the session lands a green commit, tick the checkbox in the index
   below and move to the next gap.
4. Run G26 (spec consolidation) **last** — it touches files many earlier
   prompts edit.

## Index

### Blockers (release-critical)

- [ ] **G1** — PCA predecessor digest binding (authority continuity, A3)
- [ ] **G2** — Execution-binding invariants B1–B4
- [ ] **G7** — Merkle tree + signed manifest in proof package
- [ ] **G8** — `invariant campaign assemble` CLI subcommand

### Important (severely weakens safety claims)

- [ ] **G3** — Wildcard exploitation (G-07) and cross-chain splice (G-09) negative tests *(after G1)*
- [ ] **G9** — Scenario coverage: implement remaining campaign IDs
- [ ] **G10** — Isaac Lab environments for profile families
- [ ] **G23** — `compliance --require-coverage` mode *(after G8)*
- [ ] **G29** — Bridge handshake declares executor identity *(supports G2/B4)*
- [ ] **G31** — Bridge `invariant-fuzz` into campaign runner *(after G8)*

### Nice-to-have (polish, documentation, hygiene)

- [ ] **G4**  — Hardware key-store backends (`os-keyring`, `tpm`, `yubihsm`)
- [ ] **G5**  — S3 audit replication + webhook witness
- [ ] **G6**  — Alert sinks: webhook + syslog
- [ ] **G13** — Split SR1 / SR2 sensor-range checks
- [ ] **G14** — Profile `end_effectors` audit + `validate-profiles --strict`
- [ ] **G15** — Fleet-scale coordinator test + `fleet status` CLI
- [ ] **G16** — Per-connection watchdog state
- [ ] **G17** — Intent end-to-end integration test
- [ ] **G18** — Eval engine driven by real campaign traces
- [ ] **G19** — Tampered-binary negative test for `verify-self`
- [ ] **G20** — Lean formal status reconciliation
- [ ] **G21** — SBOM + reproducible-build verification
- [ ] **G22** — ROS2 bindings disposition
- [ ] **G24** — Cognitive-escape strategies (I-01..I-10) as scenario variants
- [ ] **G25** — Test-count drift elimination
- [ ] **G27** — Spec-section cross-refs in `digital_twin` and `monitors`
- [ ] **G28** — Decide fate of `forge.rs`
- [ ] **G30** — RunPod script: SIGTERM trap, resume, `MAX_USD` ceiling
- [ ] **G32** — Shadow-deployment runbook
- [ ] **G33** — `proof_package` layout enforcement
- [ ] **G26** — Spec consolidation (move v1–v4 to history) — **run last**

---

## Conventions for every prompt

Each prompt assumes the executing Claude session will:

- Run `cargo build`, `cargo test --workspace`, and `cargo clippy -- -D warnings`
  before declaring the task done.
- Read existing files before modifying them, per `CLAUDE.md`.
- Land **one logical commit** with the corresponding gap ID in the subject
  (e.g. `[gap-G1] core: bind PCA predecessor digests into chain verification`).
- Never push directly to `main`.
- Update relevant docs (`README.md`, `CHANGELOG.md`, the live spec) when a
  prompt changes user-facing behavior.

Where a prompt says "verify", that is the green-bar criterion. If a step
cannot be honestly satisfied, the executing session should narrow the scope
and amend the spec rather than over-claim.

---

## Blockers

### G1 — PCA predecessor digest binding (authority continuity, A3)

**Promised in**: `docs/spec.md` lines 230–232 and 388–392; `docs/spec-15m-campaign.md` line 179.
**Current state**: missing. `crates/invariant-core/src/authority/chain.rs` has no predecessor digest field, so cross-chain hop splicing (campaign attack G-09) is not structurally prevented.
**Severity**: blocker.

**Prompt**:

> Read `crates/invariant-core/src/authority/chain.rs`, `crates/invariant-core/src/models/authority.rs`, and `docs/spec.md` §A3 (lines 230–232). Add a `predecessor_digest: [u8; 32]` field to the `Pca` struct. Implement `Pca::canonical_bytes()` as a deterministic serialization that excludes the signature. Update `verify_chain()` so that hop 0 requires `predecessor_digest == sha256(GENESIS_CONSTANT)` (define the genesis constant in the same module with a doc comment citing the spec line) and every later hop requires `predecessor_digest == sha256(previous_hop.canonical_bytes())`.
>
> Add four unit tests in the same crate: `predecessor_digest_genesis_hop_accepted`, `predecessor_digest_chain_accepted`, `g09_cross_chain_splice_rejected`, `predecessor_digest_mutation_rejected`.
>
> Find every existing fixture that constructs `Pca { … }` literally (`rg "Pca \\{" crates/`) and regenerate them with the new field so the rest of the workspace keeps compiling and passing.
>
> Verify: `cargo test -p invariant-core authority` is green, the entire workspace `cargo test` passes, and `cargo clippy -- -D warnings` is clean. Commit as `[gap-G1] core: bind PCA predecessor digests into chain verification`.

---

### G2 — Execution-binding invariants B1–B4

**Promised in**: `docs/spec.md` lines 394–403.
**Current state**: missing. There is no `crates/invariant-core/src/authority/binding.rs`. The validator tracks sequence numbers but does not bind to session, executor identity, or temporal window, so replay and cross-session attacks are not structurally prevented.
**Severity**: blocker.

**Prompt**:

> Read `docs/spec.md` lines 394–403, `crates/invariant-core/src/validator.rs` (sequence-number handling), and the connection model in `crates/invariant-cli/src/commands/serve.rs`.
>
> Create `crates/invariant-core/src/authority/binding.rs` containing:
>
> - `ExecutionContext { session_id: SessionId, executor_id: ExecutorId, time_window: TimeWindow }` with newtype IDs and `serde + Debug` derives.
> - `BindingError { SessionMismatch, SequenceRegression { last, got }, OutOfWindow { now_ms, window }, ExecutorMismatch }` using `thiserror`.
> - `verify_execution_binding(cmd: &Command, ctx: &ExecutionContext, pca: &Pca) -> Result<(), BindingError>` enforcing B1 (session), B2 (sequence), B3 (temporal), B4 (executor) in that order.
>
> Wire it into `ValidatorConfig` as an optional `execution_context` field. When set, the validator must call `verify_execution_binding` before physics checks. When unset, behavior is unchanged so offline tools still work. Update `serve.rs` to construct a per-connection `ExecutionContext` from the negotiated session, the executor identity claim (see G29 for the handshake — until that lands, accept a CLI-supplied executor id), and the temporal window.
>
> Add `crates/invariant-core/tests/binding.rs` with eight tests: one positive and one negative for each of B1–B4.
>
> Verify: `cargo test -p invariant-core --test binding` green, `cargo test --workspace` green, `cargo clippy -- -D warnings` clean. Commit as `[gap-G2] core: enforce execution-binding invariants B1–B4`.

---

### G7 — Merkle tree + signed manifest in the proof package

**Promised in**: `docs/spec-15m-campaign.md` lines 371–407; `docs/spec.md` line 124.
**Current state**: stub. `crates/invariant-core/src/proof_package.rs` builds a manifest of per-file SHA-256 hashes but no Merkle tree and no signature. The headline campaign deliverable does not match the spec artifact list.
**Severity**: blocker.

**Prompt**:

> Read `crates/invariant-core/src/proof_package.rs` in full, `crates/invariant-core/src/audit.rs`, and `crates/invariant-cli/src/commands/verify_package.rs` to understand the existing `assemble` API.
>
> Add a `MerkleTree { root: [u8; 32], leaves: Vec<[u8; 32]> }` type and `merkle_proof(&self, seq: u64) -> Vec<[u8; 32]>` returning the sibling path for a leaf. Use binary SHA-256: leaves are `sha256(jsonl_line_bytes)`, internal nodes are `sha256(0x01 || left || right)`, odd levels duplicate the last leaf. Document the construction in the module docstring.
>
> During `assemble()`: build the tree from the audit JSONL files in shard order, write the hex root to `audit/merkle_root.txt`, write `audit/chain_verification.json` containing shard count, leaf count, and root, and sign canonical JSON of `manifest.json` with a caller-supplied Ed25519 key, emitting `manifest.sig` next to the manifest.
>
> During `verify_package()`: rebuild the tree from JSONL, assert the root matches `audit/merkle_root.txt`, verify `manifest.sig` against a caller-supplied public key, and re-check per-file SHA-256 (existing behavior).
>
> Add `crates/invariant-core/tests/proof_package_signed.rs`: build a 2-shard fixture with about twenty audit entries, assemble with a freshly generated Ed25519 key, verify with the matching public key (success path), then mutate one byte of a JSONL leaf (expect Merkle mismatch), mutate `manifest.json` (expect signature mismatch), and mutate `manifest.sig` (expect signature mismatch).
>
> Update existing `verify_package.rs` tests to keep passing.
>
> Verify: `cargo test -p invariant-core --test proof_package_signed` green, full workspace tests green, clippy clean. Commit as `[gap-G7] core: add Merkle tree and signed manifest to proof package`.

---

### G8 — `invariant campaign assemble` CLI subcommand

**Promised in**: `docs/spec-15m-campaign.md` lines 220–245; spec-v5 prompt P1.G8.
**Current state**: missing CLI surface. The Rust `proof_package::assemble` API exists (and after G7 is complete) but `crates/invariant-cli/src/commands/campaign.rs` only runs the dry-run orchestrator — there is no front end for assembling a real package.
**Severity**: blocker. Depends on G7.

**Prompt**:

> Read the subcommand registry in `crates/invariant-cli/src/main.rs`, the existing `crates/invariant-cli/src/commands/campaign.rs`, and the CLI ergonomics of `verify_package.rs`.
>
> Extend the `Campaign` enum (or add a top-level `CampaignAssemble` if it makes the help text clearer) with flags `--shards <DIR>` (per-shard audit JSONL plus shard summary JSON), `--output <PATH>` (proof-package output directory), and `--key <PATH>` (Ed25519 signing key). Validate that inputs exist before touching the output.
>
> Call `proof_package::assemble()` (now Merkle-and-signature-aware after G7). Compute roll-up Clopper–Pearson 99.9% confidence intervals per category (A–N from `docs/spec-15m-campaign.md` §2.1) and write them to `results/per_category/ci.json`. Emit profile fingerprints — SHA-256 of canonical profile JSON per shard — to `results/per_profile/fingerprints.json`. Print a human-readable summary table to stdout.
>
> Add `crates/invariant-cli/tests/cli_assemble.rs`: build a 2-shard fixture on disk, run the new subcommand via `assert_cmd`, then run `verify-package` on the output and assert success (use `tempfile`).
>
> Update `README.md` and `docs/spec-15m-campaign.md` §7 Step 6 with the subcommand reference.
>
> Verify: `cargo test -p invariant-cli --test cli_assemble` green, workspace tests green, clippy clean. Commit as `[gap-G8] cli: add campaign assemble subcommand for proof packages`.

---

## Important

### G3 — Wildcard (G-07) and cross-chain splice (G-09) negative tests

**Promised in**: `docs/spec-15m-campaign.md` lines 177–179.
**Current state**: partial. Wildcard semantics are documented at `crates/invariant-core/src/authority/operations.rs:11-14` but no targeted hostile tests exist. The G-09 splice test cannot be written until G1 lands.
**Severity**: important. Depends on G1.

**Prompt**:

> Read `crates/invariant-core/src/authority/operations.rs` to confirm wildcard-matching rules, and the campaign descriptions of G-07 and G-09 in `docs/spec-15m-campaign.md` §3 Category G.
>
> Add three tests to `crates/invariant-core/src/authority/tests.rs`:
>
> 1. `g07_wildcard_actuate_does_not_cover_read` — chain authorizing `actuate:*` cannot read `read:proprioception`; reject with operation-scope mismatch.
> 2. `g07_move_namespace_wildcard_does_not_cross_subsystem` — chain authorizing `move:arm.*` cannot execute `move:base.linear`; reject.
> 3. `g09_cross_chain_splice_rejected` — assemble two valid chains sharing an issuer, splice hop 1 from chain A into chain B, expect verifier to reject because `hop[1].predecessor_digest` no longer matches `sha256(chain_b[0].canonical_bytes())`.
>
> Use existing test helpers; no new fixtures required. Each test must run in under 100 ms.
>
> Verify: `cargo test -p invariant-core authority` green, clippy clean. Commit as `[gap-G3] core: hostile wildcard and splice tests for authority chain`.

---

### G9 — Scenario coverage: implement remaining campaign IDs

**Promised in**: `docs/spec-15m-campaign.md` line 69 (104 scenarios A–N) and §5 statistical claims that depend on this.
**Current state**: partial. `crates/invariant-sim/src/scenario.rs` defines 37 `ScenarioType` variants; 67 campaign-spec IDs remain unimplemented.
**Severity**: important.

**Prompt**:

> Read `crates/invariant-sim/src/scenario.rs`, `crates/invariant-sim/src/orchestrator.rs`, `crates/invariant-sim/src/injector.rs`, and `docs/spec-15m-campaign.md` lines 80–300.
>
> Add `ScenarioType::all() -> &'static [ScenarioType]` and a stable `pub const SPEC_ID: &str` accessor on each variant (e.g. `Baseline.SPEC_ID = "A-01"`).
>
> Create `crates/invariant-sim/tests/scenario_coverage.rs` that asserts every spec ID in `docs/spec-15m-campaign.md` §3 (you may hard-code the ID list with a comment pointing to the spec section) corresponds to a `ScenarioType` whose `SPEC_ID` matches.
>
> Implement missing scenarios category-by-category in this order: E, H, I, M, N, then A, B, C, F, G, J, K, L. For each category: add variants and generators in `scenario.rs`; wire snake_case names into the dry-run parser; update `is_expected_reject` and `expected_reject_classification`; test the happy path and the failure path per scenario; commit per-category as `[gap-G9.<cat>] sim: implement Category <cat> scenarios`.
>
> If a scenario genuinely cannot be implemented in dry-run (e.g. humanoid push-recovery requiring Isaac), implement a faithful stub that exercises the firewall path and document the Isaac follow-up in `docs/spec-15m-campaign.md` §7. If honest effort cannot reach 104, **amend the campaign spec downward** to the achievable count and re-derive §5 Clopper–Pearson CIs in the same commit — do not leave a misleading count in the doc.
>
> Verify: `scenario_coverage` test passes, full workspace `cargo test` green, clippy clean.

---

### G10 — Isaac Lab environments for profile families

**Promised in**: `docs/spec-15m-campaign.md` line 34 ("All 34 built-in profiles") and §3 lines 80–87 requiring humanoid, quadruped, and hand coverage.
**Current state**: partial. `isaac/envs/` contains only `__init__.py`, `cell_config.py`, and `cnc_tending.py`. No envs for humanoid, quadruped, hand, or mobile-base families. `crates/invariant-cli/src/commands/campaign.rs:24-35` exits with "live campaigns use the Python runner".
**Severity**: important.

**Prompt**:

> Read `isaac/envs/cell_config.py` and `isaac/envs/cnc_tending.py` for the task API conventions, and `crates/invariant-sim/src/isaac/bridge.rs` for the bridge protocol.
>
> Create `isaac/envs/{arm,humanoid,quadruped,hand,mobile_base}.py` implementing `reset()`, `step(action)`, and `observe()`. Each env must publish sensor payloads matching the Rust-side `SensorPayload` (verify by deserializing a payload back through the bridge in a smoke test). Each env accepts deterministic seeds.
>
> Create `isaac/run_campaign.py`: a headless driver that consumes a campaign config (the YAML produced by `generate_15m_configs`), spawns the right env per profile, and emits per-episode JSON traces compatible with the proof-package `assemble` command from G8.
>
> Add `isaac/tests/test_envs_smoke.py` running 1,000 Category-A episodes for one humanoid (`unitree_h1`) and one arm (`franka_panda`); assert zero validator errors and a complete audit JSONL, and round-trip the result through `invariant verify-package`. Mark with `@pytest.mark.skipif` when Isaac is not installed.
>
> Document Isaac version requirements and local dev setup in `docs/runpod-simulation-guide.md`.
>
> Verify: `pytest isaac/tests/test_envs_smoke.py` either runs cleanly or gracefully skips, and `invariant campaign run --profile <humanoid> --dry-run=false` reaches the Isaac driver without error. Commit as `[gap-G10] isaac: per-family envs and headless campaign runner`.

---

### G23 — `compliance --require-coverage` mode

**Promised in**: `docs/spec-15m-campaign.md` line 326 (success criterion 10) and §5.1 row 10.
**Current state**: missing. `crates/invariant-cli/src/commands/compliance.rs` has no coverage-enforcement flag, so a campaign can assemble with incomplete invariant coverage.
**Severity**: important. Depends on G8.

**Prompt**:

> Read `crates/invariant-cli/src/commands/compliance.rs` and `docs/spec-15m-campaign.md` §5.1.
>
> Define a static `INVARIANT_IDS` manifest listing every numbered invariant currently shipped (P1–P25, A1–A3, L1–L4, M1, W1, SR1–SR2). Either parse from rustdoc cross-refs or list them manually with `// SPEC: <id>` markers in `physics`, `authority`, and `incident` modules.
>
> Add `--require-coverage` to the `compliance` subcommand. When set, walk `audit/audit.jsonl` from an assembled package and assert every ID has at least one entry with `Outcome::Admit` and at least one with `Outcome::Reject`. Emit `compliance/coverage.md` listing missing IDs alongside spec section pointers. Wire this flag into `campaign assemble` (G8) so packages fail assembly when coverage is incomplete; provide `--allow-partial-coverage` to override for dev assemblies.
>
> Add a synthetic test where one ID is removed from the audit trace and assembly exits non-zero, plus a counter-test where full coverage is present and the package assembles cleanly.
>
> Verify: workspace `cargo test` green, clippy clean. Commit as `[gap-G23] cli: enforce invariant coverage at campaign assembly`.

---

### G29 — Bridge handshake declares executor identity

**Promised in**: `docs/spec.md` line 434; spec-v5 prompt P4.G29.
**Current state**: missing. `crates/invariant-sim/src/isaac/bridge.rs` has no handshake protocol carrying executor identity, so B4 of G2 cannot verify the executor matches the PCA without this channel.
**Severity**: important. Supports G2/B4.

**Prompt**:

> Read `crates/invariant-sim/src/isaac/bridge.rs` in full.
>
> Define an opening `HandshakeMessage { executor_id: ExecutorId, challenge_signature: Ed25519Signature }` where the challenge is a server-issued nonce signed with the executor's key. The server publishes a fresh nonce on connect and rejects the handshake if the signature does not verify or the executor is unknown. Plumb the verified `executor_id` into the per-connection `ExecutionContext` consumed by G2.
>
> Add tests: valid handshake accepted, missing handshake rejected, bad signature rejected, unknown executor rejected.
>
> Verify: the B4 negative test from G2 now uses this handshake instead of a placeholder, existing bridge tests green, clippy clean. Commit as `[gap-G29] sim: bridge handshake binds executor identity`.

---

### G31 — Bridge `invariant-fuzz` into the campaign runner

**Promised in**: `docs/spec-15m-campaign.md` lines 266–282 (Category N: Adversarial Red Team); spec-v5 prompt P2.G31.
**Current state**: partial. `crates/invariant-fuzz/src/lib.rs` has protocol/system/cognitive generators but no scenario-layer integration into the campaign. `ScenarioType` has no `RedTeamFuzz` variant.
**Severity**: important. Depends on G8.

**Prompt**:

> Read `crates/invariant-fuzz/src/lib.rs` and submodules to enumerate available generators, and `docs/spec-15m-campaign.md` Category N (500K episodes, 10 methods N-01 to N-10).
>
> Define `FuzzMethod { Mutation, Generation, GrammarBased, CoverageGuided }` in the `invariant-sim` scenario module and wire each method to the matching `invariant-fuzz` generator via a thin adapter trait. Add `ScenarioType::RedTeamFuzz { method: FuzzMethod }`. Emit per-attempt audit entries tagged with the method.
>
> Add a unit test that runs 100 attempts per method (400 total) and asserts the validator rejects 100% of them — this is the release gate from `docs/spec.md` §7.2.
>
> Update `campaign assemble` (G8) to populate the `adversarial/` directory from these traces and remove any `_pending` marker.
>
> Verify: 100% rejection in the unit test, no `_pending` marker in assembled packages, full `cargo test` green. An additional property-style test over 1,000 mutation cases is welcome but cap its runtime for CI. Commit as `[gap-G31] sim: red-team fuzz scenarios integrated into campaign`.

---

## Nice-to-have

### G4 — Hardware key-store backends

**Promised in**: `docs/spec.md` line 838; spec-v3 hardening list.
**Current state**: stubs. `crates/invariant-core/src/keys.rs:413-539` returns `Unavailable` for all three backends.
**Severity**: nice-to-have.

**Prompt**:

> Read `crates/invariant-core/src/keys.rs` in full to understand the `KeyStore` trait. Add three Cargo features in `crates/invariant-core/Cargo.toml`: `os-keyring` (gating the `keyring` crate), `tpm` (gating `tss-esapi`), and `yubihsm` (gating the `yubihsm` crate).
>
> For each: replace the stub with a real implementation behind feature gates; when the feature is off, retain `Unavailable` so the default build keeps working. Implement round-trip Ed25519 key storage:
>
> - **OS keyring**: `service = "io.invariant-robotics.signing"`, `account = label`.
> - **TPM**: persistent keys under the owner hierarchy with an on-disk label index.
> - **YubiHSM**: auth via password-derived session.
>
> Wire CLI `keygen --store=<kind>` to select at runtime; unknown kinds fail with a typed error.
>
> Replace stub tests with feature-gated integration tests under `crates/invariant-core/tests/{keyring,tpm,yubihsm}.rs`, marked `#[ignore]` when the device is unavailable. Document the manual run command in each test file.
>
> Verify: default `cargo build` and `cargo test` succeed, each feature builds individually, `cargo clippy --features <feature> -- -D warnings` is clean. Commit as `[gap-G4] core: real key-store backends behind feature flags`.

---

### G5 — S3 audit replication + webhook witness

**Promised in**: `docs/spec.md` lines 124, 410–412; `docs/spec-gaps.md` §2.2.
**Current state**: stubs. `crates/invariant-core/src/replication.rs:257-259, 289-292` return `Unavailable`.
**Severity**: nice-to-have.

**Prompt**:

> Read `crates/invariant-core/src/replication.rs` and `audit.rs` in full.
>
> Add a `replication-s3` feature gating `aws-sdk-s3`. Implement `S3Replicator::push` with object naming `{prefix}/{epoch_ms}-{seq}.jsonl`, SSE-KMS via a configured KMS ARN (fail if unconfigured), S3 Object Lock retention per `ReplicationConfig`, exponential backoff on throttle (capped retries surfaced as `ReplicationError::Throttled`), and resume-from-highest-replicated-sequence on startup.
>
> Implement `WebhookWitness`: on each Merkle-root rotation (introduced in G7), POST `{root, count, signature}` JSON with an HMAC-SHA256 signature in `X-Invariant-Signature`, a bounded in-memory retry queue with disk spillover under the audit directory, and persistent failure (≥ N attempts) surfacing as an incident.
>
> Add a live test (gated by `INVARIANT_REPL_TEST=1`) against MinIO + a local webhook receiver, exercising chaos-restart and asserting no leaf is lost. Otherwise mark `#[ignore]`. Document RTO/RPO assumptions in module rustdoc.
>
> Verify: default build unaffected, feature build and tests pass, clippy clean.

---

### G6 — Alert sinks: webhook + syslog

**Promised in**: `docs/spec.md` line 830; spec-v3 incident-hooks section.
**Current state**: stubs. `crates/invariant-core/src/incident.rs:175-180, 194-197` return `Unavailable`.
**Severity**: nice-to-have.

**Prompt**:

> Read `crates/invariant-core/src/incident.rs` in full.
>
> Implement `WebhookAlertSink` with HMAC-SHA256-signed POST, a bounded retry queue with disk spillover next to the audit log, configurable per-host concurrency, and execution on a dedicated Tokio task so the validator hot path is never blocked. Implement `SyslogAlertSink` supporting RFC 5424 over UDP and TCP+TLS (selectable via config), with a structured-data field carrying verdict ID and severity per RFC 5424 §6.3.
>
> Add a HIL test (gated by `INVARIANT_ALERT_TEST=1`) against a `rsyslog` container and a local HTTP receiver. Verify back-pressure on the sink does not increase validator latency more than 5% under 10 kHz load.
>
> Verify: default tests pass, clippy clean.

---

### G13 — Split SR1 / SR2 sensor-range checks

**Promised in**: `docs/spec-v2.md` lines 139–145; `docs/spec-gaps.md` §4.1.
**Current state**: merged. `crates/invariant-core/src/physics/environment.rs:361-427` implements both as a single `check_sensor_range`.
**Severity**: nice-to-have.

**Prompt**:

> Read `crates/invariant-core/src/physics/environment.rs:361-427` and the registration in `crates/invariant-core/src/physics/mod.rs:326`.
>
> Split into `check_sensor_range_env` (SR1: battery, temperature, IMU, latency) and `check_sensor_range_payload` (SR2: position, encoder, force ranges), each returning its own `CheckResult` named `"sensor_range_env"` and `"sensor_range_payload"`. Update registration and all callers. Update the `compliance` subcommand to count both independently. Add tests asserting each fires on its own domain and never crosses. Update tests dependent on the merged name.
>
> Verify: `cargo test` green, SR1 and SR2 appear as distinct rows in compliance output, clippy clean.

---

### G14 — Profile `end_effectors` audit + `validate-profiles --strict`

**Promised in**: `docs/spec-v1.md` lines 38–97; `docs/spec-gaps.md` §4.2.
**Current state**: drift. Nine profiles lack `end_effectors` blocks; no strict validator exists.
**Severity**: nice-to-have.

**Prompt**:

> For locomotion-only profiles (`anybotics_anymal`, `quadruped_12dof`, `spot`, `unitree_a1`, `unitree_go2`) add `"end_effectors": []` and `"platform_class": "locomotion-only"`. For `agility_digit`, add a real `end_effectors` block (cite the source) or set `platform_class: "locomotion-only"` with a policy-layer manipulation-denial note. For adversarial profiles, add `"adversarial": true` to metadata and ensure `adversarial_max_joints` and `adversarial_single_joint` have `environment` blocks (add conservative defaults if missing).
>
> Add a CLI subcommand `validate-profiles [--strict] [PATHS...]` (defaults to `profiles/*.json`). Without `--strict` it is schema-only; with `--strict` it fails when a profile permits manipulation but has no `end_effectors`, unless `"adversarial": true`.
>
> Wire `cargo run -p invariant-cli -- validate-profiles --strict` into `.github/workflows/ci.yml` as a gate.
>
> Add a test that loads every profile and asserts strict validation passes.
>
> Verify: `cargo run -p invariant-cli -- validate-profiles --strict` succeeds, `cargo test` green, CI gate is in place.

---

### G15 — Fleet-scale coordinator test + `fleet status` CLI

**Promised in**: `docs/spec.md` lines 534–538; `docs/spec-gaps.md` §4.3.
**Current state**: partial. `crates/invariant-coordinator/src/{lib,monitor,partition}.rs` exist but there is no scaled fleet test or CLI surface.
**Severity**: nice-to-have.

**Prompt**:

> Read `crates/invariant-coordinator/src/{lib,monitor,partition}.rs` and the CLI registry in `crates/invariant-cli/src/main.rs`.
>
> Add `crates/invariant-coordinator/tests/fleet_10_robot.rs` simulating 8 arms + 2 mobile bases under 60 s of synthetic traffic from a deterministic seed. Assert zero false positives (no near-miss flagged where positions exceed configured separation) and zero missed near-misses (a hand-scripted close-approach event is embedded in the trace).
>
> Add CLI `invariant fleet status` reading coordinator state via the in-memory monitor API (or status file). Output a JSON summary of active robots, current separations, and recent partitions.
>
> Verify: `cargo test -p invariant-coordinator --test fleet_10_robot` green in under 90 s, `invariant fleet status --help` documented. Update subcommand-count statements only after G25 lands.

---

### G16 — Per-connection watchdog state

**Promised in**: `docs/spec.md` lines 421–424 (W1); `docs/spec-gaps.md` §4.4.
**Current state**: shared. `crates/invariant-sim/src/isaac/bridge.rs:13-17` documents a single shared watchdog across all bridge clients, so a misbehaving client can mask another's missed heartbeat.
**Severity**: nice-to-have.

**Prompt**:

> Read `crates/invariant-sim/src/isaac/bridge.rs` in full and the file-header limitation comment.
>
> Choose whichever of these takes under four hours: (A) refactor to `HashMap<ClientId, WatchdogState>`, initialize on connection, tear down on disconnect, update only the per-client entry on heartbeat, fire safe-stop per-client only; or (B) enforce single-client and return `BridgeError::SecondClient` on a second concurrent connection. Document the choice in the module rustdoc.
>
> Add a test: two clients connect, one goes silent, assert only that one's watchdog fires (Option A) or the second client is rejected (Option B).
>
> Verify: `cargo test -p invariant-sim` green, clippy clean.

---

### G17 — Intent end-to-end integration test

**Promised in**: spec-v5 prompt P4.G25.
**Current state**: partial. The intent module exists but there is no end-to-end test wiring compile → PCA → serve validation.
**Severity**: nice-to-have.

**Prompt**:

> Read `crates/invariant-core/src/intent.rs` and `crates/invariant-cli/src/commands/intent.rs`.
>
> Add `crates/invariant-cli/tests/intent_end_to_end.rs` that reads a textual intent fixture from `tests/fixtures/intent*.txt`, pipes it through `invariant intent compile` to produce a PCA, submits a matching command to a serve-mode validator, and asserts admission for in-scope ops and rejection with the expected error for out-of-scope ops. Minimum four test cases (two admit, two reject) covering distinct operation classes.
>
> Verify: test green, all fixtures load, clippy clean.

---

### G18 — Eval engine driven by real campaign traces

**Promised in**: spec-v5 prompt P4.G26.
**Current state**: partial. `crates/invariant-eval/src/{presets,guardrails}.rs` exist but no integration test drives them against campaign dry-run output.
**Severity**: nice-to-have.

**Prompt**:

> Add `crates/invariant-eval/tests/from_dry_run.rs` that runs a small dry-run campaign (five scenarios across varied profiles), exports the resulting trace, runs every preset and guardrail against the trace, and asserts that no preset panics, every guardrail produces a verdict, and rubric scoring is monotonic on a deliberately-degraded trace. Use a registry pattern so future guardrails are auto-exercised. Must complete in under 60 s.
>
> Verify: test green, clippy clean.

---

### G19 — Tampered-binary negative test for `verify-self`

**Promised in**: spec-v5 prompt P4.G30.
**Current state**: missing. The subcommand exists but there is no CI test verifying it detects binary tampering.
**Severity**: nice-to-have.

**Prompt**:

> Add a CI test that copies the built `invariant` binary, flips one byte at a known offset, runs `verify-self` against the modified copy, and asserts a non-zero exit code. Skip on Windows and when the binary is missing.
>
> Verify: test green on macOS/Linux CI lanes; if `verify-self` is later weakened, this test should fail.

---

### G20 — Lean formal status reconciliation

**Promised in**: `docs/spec.md` lines 799–831; `docs/spec-gaps.md` §5.1.
**Current state**: over-claims. The spec says "proves" but `formal/Invariant.lean` has one `sorry` and two axioms, and no `lake build` runs in CI.
**Severity**: nice-to-have.

**Prompt**:

> Read `formal/Invariant.lean` and submodules.
>
> Create `formal/README.md` with a status table: theorem name | status | `docs/spec.md` reference | notes (e.g. `safety_guarantee`: hypothesis-discharge; `monotonicity_transitive`: `sorry`; `hash_collision_resistant`: axiom).
>
> Attempt to discharge `monotonicity_transitive` by direct induction on hop indices. If intractable, rename it to a conjecture and document why in the README.
>
> Add a `lake build` job to `.github/workflows/ci.yml` with `continue-on-error: true` so we detect Lean breakage without blocking PRs until the master theorems close.
>
> Update `docs/spec.md` §8 to qualify "proves" as "specifies; mechanized proofs in progress (see `formal/README.md`)".
>
> Verify: `cd formal && lake build` succeeds, the CI workflow lints with `actionlint`.

---

### G21 — SBOM + reproducible-build verification

**Promised in**: spec-v3 release-hygiene section; `docs/spec-gaps.md` §5.2.
**Current state**: missing. `.github/workflows/release.yml` has no cyclonedx step and there is no `scripts/repro.sh`.
**Severity**: nice-to-have.

**Prompt**:

> Add to `.github/workflows/release.yml` a step that installs `cyclonedx-cargo` (pin via action where possible), runs `cargo cyclonedx --format json --output sbom.cdx.json`, signs the SBOM with the release Ed25519 key, and uploads both as release assets.
>
> Add `scripts/repro.sh` that builds the release binary inside the repo's `Dockerfile` with `--no-cache`, computes the SHA-256 of the resulting binary, compares it against `docs/repro-digest.txt` (commit the current digest), and exits non-zero on mismatch.
>
> Add a `Makefile` target `make repro`.
>
> Add a CI job in `ci.yml` that runs `scripts/repro.sh` on PRs touching `Dockerfile`, `Cargo.lock`, or `rust-toolchain.toml`.
>
> Verify: `bash scripts/repro.sh` succeeds locally and `actionlint .github/workflows/*.yml` passes.

---

### G22 — ROS2 bindings disposition

**Promised in**: `README.md` (invariant-ros2 integration); `docs/spec-gaps.md` §5.3.
**Current state**: ambiguous. `invariant-ros2/` at the repo root is not a Cargo workspace member.
**Severity**: nice-to-have.

**Prompt**:

> Inspect `invariant-ros2/` and confirm it is not in the workspace members list of `Cargo.toml`.
>
> Choose whichever takes under four hours:
>
> - **(A)** Wire it in: add to workspace members, fix any build breakage, add a smoke test for publish/subscribe round-trip against a mock.
> - **(B)** Move to examples: `git mv invariant-ros2 examples/ros2-bindings`, add an example README qualifying it as "unmaintained until milestone X", and update `README.md` accordingly.
>
> Default to Option B if uncertain. Document the choice in the commit message.
>
> Verify: `cargo build --workspace` succeeds (Option A) or `README.md` and `examples/` reflect the moved binding (Option B).

---

### G24 — Cognitive-escape strategies (I-01..I-10) as scenario variants

**Promised in**: `docs/spec-15m-campaign.md` lines 195–210 (Category I, 10 strategies); spec-v5 prompt P2.G24.
**Current state**: missing. There is no `CognitiveEscapeStrategy` enum and no `ScenarioType::CognitiveEscape` variant.
**Severity**: nice-to-have.

**Prompt**:

> Read `crates/invariant-fuzz/src/cognitive/escape.rs` and `docs/spec-15m-campaign.md` Category I.
>
> Define `CognitiveEscapeStrategy { GradualDrift, DistractionFlooding, SemanticConfusion, AuthorityLaundering, ErrorMining, WatchdogManipulation, ProfileProbing, MultiAgentCollusion, TimingExploitation, RollbackReplay }` corresponding to I-01..I-10. Map each to a strategy in `escape.rs`, adding missing strategies rather than overloading existing ones.
>
> For each variant, add a 1k-attempt integration test asserting zero successful bypasses. Wire `ScenarioType::CognitiveEscape { strategy: CognitiveEscapeStrategy }` into the campaign orchestrator so `per_category/I.json` is populated after a dry-run. Update the `scenario_coverage` test from G9 to enforce Category I presence.
>
> Verify: ten variants, ten zero-bypass tests, `scenario_coverage` covers Category I, full `cargo test` green.

---

### G25 — Test-count drift elimination

**Promised in**: `docs/spec-v2.md` line 307; `docs/spec-gaps.md` §4.5.
**Current state**: drift. README, CHANGELOG, spec-v2, and public-release-polish each cite different totals (1,951–2,047). The actual workspace has roughly 1,881 `#[test]` markers.
**Severity**: nice-to-have.

**Prompt**:

> Add a CI step in `.github/workflows/ci.yml` that runs `cargo test --workspace 2>&1`, parses each `test result:` line, sums the counts, and writes the total to `docs/test-count.txt` (single integer + newline). Commit the file with the current accurate count. Add a CI guard that fails when this file would change versus `HEAD`.
>
> Update `README.md`, `CHANGELOG.md`, `docs/spec-v2.md`, and `docs/public-release-polish.md` to reference `docs/test-count.txt` instead of hard-coded literals (e.g. "see [docs/test-count.txt](docs/test-count.txt) for current count").
>
> Update the subcommand-count statements only after G8, G14, and G15 land (target: 24 subcommands). Update scenario-count statements only after G9 lands.
>
> Verify: `cargo test`, `cat docs/test-count.txt` matches actual count.

---

### G27 — Spec-section cross-refs in `digital_twin` and `monitors`

**Promised in**: spec-v5 prompt P5.G27.
**Current state**: missing rustdoc anchors linking code to spec sections.
**Severity**: nice-to-have.

**Prompt**:

> Add `// SPEC: docs/spec.md §<n>` rustdoc comments at the top of each public item in `crates/invariant-core/src/digital_twin.rs` and `crates/invariant-core/src/monitors.rs`, matching the section that motivates the item. No code changes — only doc comments.
>
> Verify: every `pub fn`, `pub struct`, and `pub enum` in those two files has an inline spec ref. Commit as `[gap-G27] core: cite spec sections in digital_twin and monitors`.

---

### G28 — Decide fate of `forge.rs`

**Promised in**: spec-v5 prompt P5.G28.
**Current state**: unclear. `crates/invariant-cli/src/commands/forge.rs` exists but is not wired into the subcommand registry.
**Severity**: nice-to-have.

**Prompt**:

> Read `crates/invariant-cli/src/commands/forge.rs` and `crates/invariant-cli/src/main.rs`.
>
> Choose: (A) wire `Forge` into the subcommand registry, document what it does (surface for `docs/spec.md` §1.6 Forge mode), and add a help-output test; or (B) delete the file and any cross-references. Default to Option B if the purpose is unclear.
>
> Document the choice in the commit message.
>
> Verify: `cargo build` succeeds, clippy clean.

---

### G30 — RunPod script: SIGTERM trap, resume, `MAX_USD` ceiling

**Promised in**: `docs/spec-15m-campaign.md` §7 Step 5; `docs/spec-gaps.md` §3.5.
**Current state**: partial. `scripts/run_15m_campaign.sh`, `scripts/runpod_setup.sh`, and `scripts/upload_results.py` exist but lack preempt-recovery and a cost ceiling.
**Severity**: nice-to-have.

**Prompt**:

> Read `scripts/run_15m_campaign.sh`.
>
> Add: (1) a SIGTERM/SIGINT trap that flushes the in-flight shard summary before exit; (2) idempotent resume — on start, scan the output dir for completed-shard markers and skip them; (3) a `MAX_USD` env var (default unset = unbounded) that tracks elapsed runtime × on-demand rate, aborts cleanly if exceeded, and logs the abort reason to the output dir.
>
> Add `shellcheck` to CI. Add a small Bash test (using `bats`, or plain bash with `set -e`) that invokes the script with a stub binary and exercises the SIGTERM path on a 5-shard fanout.
>
> Verify: SIGTERM during a shard yields a clean partial result, re-running after kill resumes correctly, `MAX_USD=0.01` aborts within one shard.

---

### G32 — Shadow-deployment runbook

**Promised in**: `docs/spec-15m-campaign.md` §7 Step 7; `docs/spec-gaps.md` §3.5.
**Current state**: missing. `docs/runpod-simulation-guide.md` is exploratory; no shadow runbook.
**Severity**: nice-to-have.

**Prompt**:

> Create `docs/shadow-deployment.md` (~300–500 lines) covering: (1) scope (≥100 robot-hours on a UR10e CNC cell); (2) setup (shadow-mode wiring via the `serve` subcommand, with config links); (3) metrics collected (latency p50/p95/p99, rejection rate per check, divergence map between sim and real); (4) divergence triage (table of divergence type → owner → SLO); (5) sign-off criteria — zero unexplained divergences for 100 hours, <0.1% latency regression, explicit sign-off checklist by Safety + Engineering leads.
>
> Cross-link from `docs/spec-15m-campaign.md` §7 Step 7 and the deployment section of `README.md`.
>
> Verify: file present, `mdformat` clean, cross-links resolve.

---

### G33 — `proof_package` layout enforcement

**Promised in**: `docs/spec-15m-campaign.md` §6; spec-v5 prompt P4.G32.
**Current state**: partial. `proof_package::assemble` produces the §6 layout and `verify_package` consumes it, but there is no separate layout validation.
**Severity**: nice-to-have.

**Prompt**:

> Define a typed `ProofPackageLayout` enumerating every directory and file required by `docs/spec-15m-campaign.md` §6 (`manifest.json`, `audit/`, `results/`, `compliance/`, `adversarial/`, …). Have `proof_package::assemble` produce that layout exclusively, and have `verify_package` consume it, validating presence of every required path. Rejecting unknown top-level paths is acceptable but not required.
>
> Add tests: (1) packages assembled by G8 already comply (no diff); (2) a fixture missing one §6 path causes `verify_package` to exit non-zero with a layout-error code distinct from tampering codes.
>
> Verify: assembled packages compliant, missing-path test green, clippy clean.

---

### G26 — Spec consolidation (move v1–v4 to history) — run last

**Promised in**: `docs/spec-gaps.md` §5.4.
**Current state**: fragmented. Multiple specs claim to supersede each other.
**Severity**: nice-to-have. **Run last** — many earlier prompts edit `docs/spec.md` and the campaign spec.

**Prompt**:

> Move `docs/spec-v1.md`, `docs/spec-v2.md`, `docs/spec-v3.md`, and `docs/spec-v4.md` to `docs/history/`. Replace each original with a one-line redirect pointing at `docs/spec.md` and linking to the historical version. `docs/spec.md` becomes the single live spec; `docs/spec-15m-campaign.md` remains as a campaign-specific addendum. `docs/spec-gaps.md` and `docs/spec-v5.md` may be deleted once every remediation prompt is landed and green in CI.
>
> Update `README.md`, `CHANGELOG.md`, `CLAUDE.md`, and any rustdoc that uses `spec-v[1-4].md` paths to reference `docs/spec.md` directly.
>
> Decide separately whether this `docs/spec-v6.md` plan moves to `docs/history/` once the remediation is complete (probably yes).
>
> Verify: `grep -r "spec-v[1234]" docs/ README.md CHANGELOG.md` returns only redirect lines and historical references.

---

## Closure

This plan is closed when:

1. Every checkbox in the index above is ticked.
2. CI is green on `main` with all new tests in place.
3. `docs/spec-gaps.md` and `docs/spec-v5.md` have been removed (or moved to `docs/history/`) by G26.
4. A fresh `invariant campaign assemble` produces a proof package that `invariant verify-package` accepts end-to-end.

At that point this file should also move to `docs/history/spec-v6.md` and `docs/spec.md` becomes the single source of truth.
