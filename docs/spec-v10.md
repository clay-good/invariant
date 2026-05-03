# spec-v10: Gap-Closure Plan

**Status:** Active
**Supersedes:** none (companion to `spec.md`, `spec-15m-campaign.md`)
**Purpose:** Step-by-step instructions, written as Claude Code prompts, to close every concrete gap identified in a deep diff between published specs (`spec.md`, `spec-v1.md` … `spec-v9.md`, `spec-15m-campaign.md`, `spec-gaps.md`) and the current implementation under `crates/`.

This document is a **work plan**, not a specification. Each numbered chunk is meant to be handed verbatim to Claude Code as a single task. Chunks are ordered to respect dependencies (foundational invariants land before campaign artifacts depend on them). Prompts deliberately describe *what to build, why, and how to verify it* — not code.

A chunk is "done" when:
1. The acceptance criteria pass.
2. `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo fmt --check` are clean.
3. CHANGELOG.md has a one-line entry; relevant spec is reconciled (see chunks 18–22).

Chunks may be parallelized within the same severity tier if they touch disjoint files; the per-chunk "Touches" list is provided to make that explicit.

---

## Tier 1 — Critical correctness (must land before any new campaign claim)

### Chunk 1 — Implement execution-binding invariants B1–B4

> Read `docs/spec.md` §B1–B4 (around lines 394–403 and 478) and `docs/spec-gaps.md` §1.1. The spec declares four execution-binding invariants — session binding (B1), sequence monotonicity vs PCA (B2), temporal window (B3), executor identity (B4) — but no `binding.rs` exists in `crates/invariant-core/src/authority/`. Today the validator can be replayed across sessions, executors, and time windows.
>
> Create a new module `crates/invariant-core/src/authority/binding.rs` exporting an `ExecutionContext` carrying `session_id`, `executor_id`, `temporal_window_ms`, and a `verify_execution_binding(intent, pca, ctx) -> Result<(), BindingError>` function. Wire it into `Validator::verify` so every command must satisfy B1–B4 *before* physics checks run; physics rejection should never mask a binding rejection.
>
> Define a typed error per invariant (`SessionMismatch`, `SequenceRegression`, `OutsideTemporalWindow`, `ExecutorIdentityMismatch`) so audit verdicts can route to the correct rubric. Do not silently widen acceptance — a missing field in the intent is a rejection, not a bypass.
>
> Add unit tests in `binding.rs` covering, for each of B1–B4: one positive case, one direct violation, and one *hostile* case (e.g. valid signature but reused session id). Add an integration test in `crates/invariant-core/tests/` proving that a command rejected by binding never reaches the physics layer (assert via instrumentation counter).
>
> Update `spec-gaps.md` to mark §1.1 closed and add a CHANGELOG entry.
>
> **Touches:** `crates/invariant-core/src/authority/{mod.rs, binding.rs}`, `crates/invariant-core/src/validator.rs`, tests.

### Chunk 2 — Causal binding for Proof of Continuity (A3)

> Today PCA hops are linked only by signature and monotonic sequence (`crates/invariant-core/src/authority/chain.rs:31`). The spec (`spec.md` lines 230–232, 388–392) requires each hop to carry a *non-forgeable proof* that it is a valid causal successor, so that splice attacks (campaign scenario G-09) are structurally impossible.
>
> Add a `predecessor_digest: [u8; 32]` field to the `PcaHop` struct, computed as SHA-256 over the canonical encoding of hop `i-1`. Update `verify_chain` so that for every `i > 0` it recomputes the digest of the prior hop and rejects mismatches. The first hop's predecessor digest must be the all-zero sentinel and verified against a domain-separated genesis tag (`b"invariant.pca.genesis.v1"`) to prevent cross-deployment splices.
>
> Migration path: this is a wire-format change. Add a version byte to PcaHop, accept v1 only on read with a deprecation warning, and bump the file format version emitted by all writers. Add a `chain_migrate` helper used by replay tools — do *not* attempt silent backward compat at the verifier.
>
> Add tests:
> 1. Round-trip: build chain, verify, mutate one byte of hop `k`, expect rejection at hop `k+1`.
> 2. G-09 splice: take two valid chains, join them at a sequence boundary, expect rejection on the seam.
> 3. Genesis: empty chain accepts; chain whose first hop's predecessor is non-zero rejects.
>
> Document the wire change in CHANGELOG and `spec.md` §authority.
>
> **Touches:** `crates/invariant-core/src/authority/chain.rs`, fixtures under `crates/invariant-core/tests/fixtures/`, tools that emit chains.

### Chunk 3 — Wildcard-exploitation tests (G-07) and splice tests (G-09)

> `spec-15m-campaign.md` lines 177–179 specify adversarial tests G-07 (wildcard exploitation: `actuate:*` must not subsume `read:sensor`; `move:*` must not cross subsystems) and G-09 (cross-chain splice). Greps against the codebase return zero matches for either ID.
>
> Add tests in `crates/invariant-core/src/authority/tests.rs` (or a new `tests_adversarial.rs` if cleaner):
> - `g07_actuate_wildcard_does_not_cover_read`
> - `g07_move_wildcard_does_not_cross_subsystem`
> - `g07_namespace_traversal_rejected` (e.g. `actuate:arm.*` must not match `actuate:base.wheel`)
> - `g09_cross_chain_splice_rejected` (depends on Chunk 2)
> - `g09_replay_after_rotation_rejected`
>
> Each test must assert the *specific* error variant, not just `is_err()`, so a future regression that fails for the wrong reason is caught. Add IDs as comments tying tests to scenario IDs in the campaign spec.
>
> **Touches:** `crates/invariant-core/src/authority/`. Depends on Chunk 2.

### Chunk 4 — Implement hardware key-store backends

> `crates/invariant-core/src/keys.rs` lines 413, 436, 462, 482 ship three production backends — `OsKeyringKeyStore`, `TpmKeyStore`, `YubiHsmKeyStore` — that all return `Unavailable`. Spec.md line 838 and spec-v3 hardening list mark root-key security as a required architectural property; the file backend is development-only.
>
> Implement each backend behind a Cargo feature flag so the default build pulls no extra deps:
> - `os-keyring` using the `keyring` crate, mapping macOS Keychain, Linux Secret Service, and Windows Credential Manager. Store Ed25519 seeds, never raw private scalars; round-trip seed → keypair on load.
> - `tpm` using `tss-esapi` against a local TPM 2.0; persistent keys under the owner hierarchy with policy session for use; document required PCRs.
> - `yubihsm` using the `yubihsm` crate with password-derived authenticated sessions; keys created with `EXPORTABLE_UNDER_WRAP` denied.
>
> The CLI `keygen` subcommand grows a `--store=<file|os-keyring|tpm|yubihsm>` flag; default remains `file`. `serve` and `validate` discover the store from config. Wrong store on read is a hard error, not a fallback.
>
> Each backend gets a feature-gated integration test exercising generate → sign → verify → rotate. Add a `docs/key-stores.md` runbook covering bootstrap, rotation, and disaster-recovery for each backend.
>
> **Touches:** `crates/invariant-core/src/keys.rs`, `crates/invariant-cli/src/commands/keygen.rs`, workspace `Cargo.toml`, new docs file.

### Chunk 5 — Implement audit replication and external witness

> `crates/invariant-core/src/replication.rs` lines 257–259 and 289–292 leave `S3Replicator` and `WebhookWitness` as stubs. The audit invariants L1–L4 in `spec.md` lines 410–412 cannot be upheld in production without working replication.
>
> Behind feature `replication-s3`, implement `S3Replicator` using `aws-sdk-s3`:
> - Object naming `{prefix}/{epoch_ms:013}-{seq:010}.jsonl`, lexicographic resume.
> - SSE-KMS encryption; bucket policy enforced via Object Lock retention.
> - Exponential backoff on `ThrottlingException`, bounded queue, disk spillover at `XDG_STATE_HOME/invariant/replication-spill/`.
> - Resume from highest replicated sequence at process start.
>
> Implement `WebhookWitness` posting `{root, count, signature, prev_root}` JSON on every Merkle-root rotation, signed with HMAC-SHA256 (header `X-Invariant-Signature: v1=<hex>`). Bounded retry queue with disk spillover; per-host concurrency cap.
>
> Document RTO/RPO assumptions in `docs/audit-replication.md`. Add integration tests against MinIO (S3) and a local `axum` receiver (webhook); a chaos test restarts the replicator mid-flight and asserts no audit entry is lost or duplicated.
>
> **Touches:** `crates/invariant-core/src/replication.rs`, workspace `Cargo.toml`, new docs and tests.

### Chunk 6 — Proof package: Merkle tree + signed manifest

> `spec-15m-campaign.md` lines 371–407 require the proof package to publish `audit/merkle_root.txt`, `audit/chain_verification.json`, and a signed `manifest.json`. Today `crates/invariant-core/src/proof_package.rs:241` writes only an unsigned `HashMap<String, String>` of per-file SHA-256.
>
> Build a SHA-256 binary Merkle tree over canonicalized audit JSONL entries. Domain-separate leaf vs node hashes (`0x00 || entry`, `0x01 || left || right`) to prevent second-preimage attacks. Persist:
> - `audit/merkle_root.txt` — hex root, one line, trailing newline.
> - `audit/chain_verification.json` — `{ first_seq, last_seq, count, root, predecessor_anchor }`.
>
> Add `merkle_proof(seq) -> Vec<[u8; 32]>` and `verify_proof(leaf, proof, root) -> bool` so external auditors can spot-check entries without rehashing the whole shard.
>
> Sign `manifest.json` with the campaign Ed25519 key; emit `manifest.sig`. `verify_package()` rebuilds the tree, verifies the signature against the campaign public key, and validates each file digest. Mismatches must specify *which* file failed.
>
> Extend the existing round-trip test on a 2-shard fixture. Add a tamper test: flip one bit in one entry, expect verify to fail and identify the leaf.
>
> **Touches:** `crates/invariant-core/src/proof_package.rs`, fixtures, CLI `verify-package`.

---

## Tier 2 — High-impact campaign blockers

### Chunk 7 — `campaign assemble` CLI subcommand

> `proof_package::assemble` is wired in Rust but no CLI surface exposes it. `spec-15m-campaign.md` §6 step 6 lists `assemble` as a required step.
>
> Add a subcommand at `crates/invariant-cli/src/commands/campaign.rs` with the shape:
>
> `invariant campaign assemble --shards <DIR> --output <PATH> --key <PATH> [--public-key <PATH>]`
>
> Inputs: directory containing per-shard `audit-*.jsonl` and per-shard `summary-*.json`. Outputs: a single proof package directory containing the artifacts from Chunk 6, plus per-category Clopper-Pearson 95% CIs (lower bound only is meaningful for safety claims), profile fingerprints (SHA-256 over canonical JSON), and a top-level `summary.json`.
>
> Validate inputs strictly: shard count, sequence contiguity across shards, no overlapping sequence ranges, no missing summaries. A non-contiguous shard set is a hard error with a remediation hint.
>
> Add an integration test on a 2-shard fixture round-tripping through `verify-package`. Update README's subcommand count.
>
> **Touches:** `crates/invariant-cli/src/commands/campaign.rs`, registry, README. Depends on Chunk 6.

### Chunk 8 — Scenario coverage: 22 → ≥104

> `crates/invariant-sim/src/scenario.rs` enumerates 22 `ScenarioType` variants. `spec-15m-campaign.md` line 69 cites 104 IDs across categories A–N (with a few specs claiming 106). Coverage today: A 1/8, B 0/8, C 1/6, D 0/10, E 0/6, F 0/8, G 2/10, H 0/6, I 0/10, J 4/8, K 2/6, L 2/4, M 0/6, N 0/10.
>
> First, reconcile the count discrepancy (see Chunk 21). Then for each missing scenario:
> 1. Add a `ScenarioType` variant whose name matches the campaign-spec ID (e.g. `B03_TwoArmJointEnvelope`).
> 2. Implement seed-stable construction returning the deterministic intent + sensor sequence the scenario is meant to exercise.
> 3. Tag positive vs adversarial in the variant doc comment so coverage reports can count separately.
>
> Add `pub fn all() -> &'static [ScenarioType]`. Add a `scenario_coverage` integration test enumerating every spec-cited ID and asserting a `ScenarioType` variant exists. The test reads the campaign spec at compile time via `include_str!` and parses IDs with a small regex — drift between spec and code becomes a test failure, not a silent miss.
>
> If 104 is too large to land in one chunk, split by category and land each as its own commit (`B`, `D`, `E`, `F`, `H`, `I`, `M`, `N` are the empty ones). Update README and CHANGELOG only when full coverage lands.
>
> **Touches:** `crates/invariant-sim/src/scenario.rs`, scenario test fixtures, possibly `crates/invariant-eval/` rubrics.

### Chunk 9 — Isaac Lab task environments for all platform families

> `isaac/envs/` contains `cnc_tending.py` only. `spec-15m-campaign.md` §3 requires humanoid, quadruped, hand, mobile-base, and arm coverage; `spec.md` line 34 advertises 34 built-in profiles.
>
> Add one env per family under `isaac/envs/`: `arm.py`, `humanoid.py`, `quadruped.py`, `hand.py`, `mobile_base.py`. Each implements `reset / step / observe`, emits `SensorPayload` matching the Rust schema (validate via the existing JSON schema), accepts a deterministic seed, and exposes a registry entry consumed by the headless driver.
>
> Add `isaac/run_campaign.py` — a headless driver that consumes the same campaign config the Rust dry-run uses, emits per-episode JSON traces compatible with `invariant-eval`, and respects the shard/seed contract.
>
> Smoke run: 1,000 Category-A episodes on humanoid + arm, asserting zero validator errors and complete audit JSONL. Wire this run into a `make isaac-smoke` target with documented dependencies (Isaac Lab version, GPU requirements).
>
> Note: Isaac Lab is a heavyweight external dependency. Do not check in binaries; document setup in `docs/runpod-simulation-guide.md` updates and keep CI green without GPU.
>
> **Touches:** `isaac/envs/`, `isaac/run_campaign.py`, docs, Makefile.

### Chunk 10 — Multi-robot coordination: fleet test + CLI

> `spec.md` lines 534–538 and line 281 (scenario A-08) require multi-robot coordination safety, but `crates/invariant-coordinator/` only has pairwise tests, and the CLI has no `fleet` subcommand.
>
> Add a 10-robot integration test (e.g. 8 arms + 2 mobile bases) running a 60-second synthetic traffic pattern, asserting zero false positives on a no-conflict trace and zero misses on a scripted near-miss trace. Use deterministic seeds; record expected separation-violation timestamps as a fixture.
>
> Add `invariant fleet status` CLI subcommand reading coordinator state and printing per-robot region, partition, and last-checked timestamp. Add `invariant fleet plan --conflict-graph` rendering a Graphviz `dot` of current partitions for operators.
>
> Update README subcommand count (now 21+) only when CLI lands.
>
> **Touches:** `crates/invariant-coordinator/`, `crates/invariant-cli/`, fixtures.

### Chunk 11 — Per-connection watchdog isolation

> `crates/invariant-sim/src/isaac/bridge.rs` lines 13–16 document a single shared watchdog. Spec.md lines 421–424 (W1, per-cognitive-layer heartbeat) require isolation: a misbehaving second client must not starve the first's timeout.
>
> Refactor watchdog state to be per-connection (keyed by negotiated connection id). Either (a) maintain an independent `Watchdog` per connection, or (b) enforce single-client by rejecting concurrent connections with a typed `BridgeError::SecondClient` and surfacing the rejection in audit. Pick (a) unless single-client is intentional — document the choice.
>
> Add a regression test: open two bridge connections, stop heartbeats on connection B, assert connection A's watchdog does *not* trip and connection B's does. Use a virtual clock; do not sleep on real wall-time.
>
> **Touches:** `crates/invariant-sim/src/isaac/bridge.rs`, related tests.

### Chunk 12 — Alert sinks (webhook + syslog)

> `crates/invariant-core/src/incident.rs` lines 175–180 and 194–197 leave `WebhookAlertSink` and `SyslogAlertSink` as stubs. Spec-v3 hardening requires both for production deployment.
>
> Implement WebhookAlertSink: HMAC-SHA256 signed POST (`X-Invariant-Signature` header), bounded retry queue with disk spillover, per-host concurrency limit, structured JSON payload `{verdict_id, severity, ts, summary, links: {audit, replay}}`.
>
> Implement SyslogAlertSink: RFC 5424 over UDP (default) and TCP+TLS (opt-in), structured-data field carrying verdict id and severity. Truncate-or-fragment behavior must be explicit and documented.
>
> Both sinks run on a dedicated tokio task — back-pressure must never block the validator hot path. Add HIL-style integration tests against an `rsyslog` container and a local axum receiver. Document in `docs/incident-hooks.md`.
>
> **Touches:** `crates/invariant-core/src/incident.rs`, workspace deps, docs.

### Chunk 13 — SBOM and reproducible-build verification

> Spec-v3 release-hygiene calls for SBOM and reproducible builds; CI has neither.
>
> Add a CI job emitting CycloneDX SBOM via `cargo cyclonedx`, signing it with the release key, and attaching to the GitHub release. Sign-and-verify both on push and on release.
>
> Add `make repro` (or `scripts/repro.sh`) that builds inside the published `Dockerfile` and asserts a stable binary digest against a checked-in `release-digests.txt`. Drift fails the job. Document the procedure in `docs/release-hygiene.md` and link from CONTRIBUTING.
>
> **Touches:** `.github/workflows/release.yml`, `scripts/repro.sh` (new), docs, `release-digests.txt` (new).

---

## Tier 3 — Medium-impact correctness and hygiene

### Chunk 14 — Split sensor-range checks SR1 and SR2

> `crates/invariant-core/src/physics/environment.rs` lines 361–427 implement SR1 (env-state range) and SR2 (payload range) under a single `check_sensor_range` returning one `CheckResult`. Spec-v2 lines 139–145 separate them; coverage tables under-count today.
>
> Split into `check_sensor_range_env` and `check_sensor_range_payload`. Update registration in `crates/invariant-core/src/physics/mod.rs` around line 326. Update `compliance` subcommand and any rubric that filters by check name. Add a regression test asserting both names appear independently in coverage output.
>
> **Touches:** `crates/invariant-core/src/physics/environment.rs`, `mod.rs`, `crates/invariant-cli/src/commands/compliance.rs`, eval rubrics.

### Chunk 15 — Profile `end_effectors` field cleanup + strict validator

> Nine profiles lack `end_effectors` blocks. Spec-v1 §1.1 (lines 38–97) requires the field for any platform that can manipulate.
>
> For each locomotion-only profile, add `"platform_class": "locomotion-only"` and `"end_effectors": []`. For Digit, add a real EE block (or document descope in profile comments). For adversarial fixtures, require an explicit `"adversarial": true` flag to exempt them from the strict check.
>
> Add `invariant validate-profiles --strict` (CLI does not exist today) that fails when a profile permits manipulation but declares no EE, or when EE schema is malformed. Wire it into CI as a required check.
>
> **Touches:** `profiles/*.json`, new CLI subcommand under `crates/invariant-cli/src/commands/`, CI workflow.

### Chunk 16 — Formal layer: status table, fewer sorries, optional CI

> `formal/Invariant.lean` lines 54–63 discharge hypotheses without proving composition; `Invariant/Authority.lean` lines 85–90 contain a `sorry`; `Audit.lean` line 82 axiomatizes hash-collision resistance; `Physics.lean` line 132 axiomatizes `pointInConvexPolygon`. CI does not run `lake build`.
>
> Create `formal/README.md` with a status table — one row per theorem, columns: name, status (`proved` | `sorry` | `axiom`), spec cross-reference, owner. Replace the `Authority.lean` `sorry` with a real proof (the obligation is small) or descope the surrounding claim. Where axioms are unavoidable (e.g. crypto primitives), label them as trust assumptions with a one-line justification.
>
> Add a non-blocking `lake build` job to CI under `.github/workflows/formal.yml`. Until proofs land, qualify `spec.md` §8 from "proves" to "specifies; mechanized proofs in progress" — see Chunk 22.
>
> **Touches:** `formal/`, `.github/workflows/`, `spec.md`.

### Chunk 17 — ROS2 bindings: wire in or move to examples

> `invariant-ros2/` exists but is not in workspace members; no crate depends on it. README advertises ROS2 integration as a feature.
>
> Pick one path:
> - **(a)** Add `invariant-ros2` to workspace `Cargo.toml`, fix any rot, add a smoke test that builds and exercises a single message round-trip on a non-ROS environment via mocked transport.
> - **(b)** Move to `examples/ros2/` and qualify the README claim to "example integration, unmaintained until milestone X."
>
> Whichever path is chosen, the README, CHANGELOG, and `spec.md` must agree. Default to (b) unless ROS2 is on the active campaign critical path.
>
> **Touches:** `invariant-ros2/` (location), workspace `Cargo.toml`, README.

---

## Tier 4 — Documentation reconciliation (do these last; depend on Tiers 1–3)

### Chunk 18 — Move superseded specs to `docs/history/`

> `docs/` carries `spec.md`, `spec-v1.md` … `spec-v9.md`, `spec-15m-campaign.md`, `spec-gaps.md`, `public-release-polish.md`, and now this file. Multiple specs claim to supersede prior ones, leaving readers unable to identify the live spec.
>
> Create `docs/history/` and move `spec-v1.md` … `spec-v9.md` into it. Replace each moved file at its original location with a one-line redirect stub:
>
> `> Superseded by [spec.md](spec.md) and [spec-v10.md](spec-v10.md). Original preserved at [history/spec-vN.md](history/spec-vN.md).`
>
> Update any inbound links (grep the repo). `spec.md` remains the single live spec; `spec-15m-campaign.md` remains as the campaign addendum; `spec-gaps.md` is retired (Chunk 19); `spec-v10.md` (this file) is the live work plan and should itself be retired once all chunks land.
>
> **Touches:** `docs/`, anything that links to the old paths.

### Chunk 19 — Retire `spec-gaps.md`

> Once Chunks 1, 4, 5, 6 land, the items tracked in `docs/spec-gaps.md` are either closed or have migrated to this v10 plan. Move `spec-gaps.md` to `docs/history/` with a redirect stub pointing at `spec-v10.md`. Re-derive the §1.1 closure verbatim in CHANGELOG so the trail is visible to future readers.
>
> **Touches:** `docs/spec-gaps.md`, CHANGELOG.

### Chunk 20 — CI-emitted counts replace hard-coded literals

> README and several specs cite literal counts (≈2,047 tests, 128 doc-tests, 22 scenarios, N subcommands) that drift quickly. Actual `#[test]` count today is 1,881.
>
> Add a CI step that emits `docs/test-count.txt`, `docs/scenario-count.txt`, and `docs/subcommand-count.txt` from the workspace and commits them on the release branch (or publishes as artifacts and links from the README). README and specs must reference these files, not literal numbers.
>
> Replace every hard-coded count in README, `spec.md`, and `spec-15m-campaign.md` with a link or a templated insertion. Forbid literal counts in prose via a CI lint (a small grep rule is enough).
>
> **Touches:** CI, README, specs.

### Chunk 21 — Reconcile scenario count (22 vs 104 vs 106)

> `spec.md` line 556 says 22; `spec-v1.md` implies 104; `spec-15m-campaign.md` line 69 says 106; code has 22. The disagreement is structural — campaign statistical claims in `spec-15m-campaign.md` §5 depend on the count.
>
> Decide the canonical target (recommend: 104, matching the campaign IDs). Update either:
> - **Down-path:** Amend `spec-15m-campaign.md` §5 statistics to the actual implemented count. Document this as a campaign-scope reduction with a follow-up issue.
> - **Up-path:** Use Chunk 8 to reach the canonical target, then update `spec.md` line 556 and remove the discrepancy.
>
> Whichever path, do this reconciliation in a single commit so the spec is internally consistent at every revision.
>
> **Touches:** `spec.md`, `spec-15m-campaign.md`, possibly `crates/invariant-sim/src/scenario.rs`. Depends on Chunk 8 if up-path.

### Chunk 22 — Tighten `spec.md` claim language

> Several `spec.md` claims overreach today's evidence:
> - §8 says formal proofs "prove" theorems; they don't (sorries + axioms; see Chunk 16).
> - §audit says verdicts are "hash-chained and Ed25519-signed"; manifest signing is missing until Chunk 6 lands.
> - §coordination claims multi-robot safety; only pairwise is tested until Chunk 10 lands.
> - §security implies hardware key storage works; it doesn't until Chunk 4 lands.
>
> Walk `spec.md` end-to-end and qualify each claim to match the post-Tier-1+2 reality. Where a chunk has landed, the claim returns to unqualified. Where it hasn't, the language reads "specified; implementation tracked in spec-v10 chunk N."
>
> Acceptance: a reader of `spec.md` should not be able to find a single claim that is unsupported by either landed code or an explicit "tracked in chunk N" pointer.
>
> **Touches:** `spec.md`. Do this *last*, after Tiers 1–3.

---

## Cross-cutting acceptance gate

When all chunks above have landed, the following must all be true simultaneously:

1. `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --check` clean.
2. `make repro` produces the expected digest.
3. `lake build` succeeds (non-blocking but green).
4. `invariant campaign assemble` round-trips a 2-shard fixture through `verify-package` with Merkle root + signed manifest.
5. `scenario_coverage` test passes against the canonical scenario count.
6. `validate-profiles --strict` passes against `profiles/`.
7. No `todo!()`, `unimplemented!()`, or `Unavailable` returned from any non-test code path on the default feature set.
8. `spec.md` claims all match landed code or carry an explicit chunk-N pointer.
9. `docs/spec-gaps.md` and `docs/spec-v1.md`…`spec-v9.md` are in `docs/history/` with redirect stubs.
10. CHANGELOG carries one entry per chunk.

When the gate is green, this file (`spec-v10.md`) itself moves to `docs/history/` with a redirect to `spec.md`.
