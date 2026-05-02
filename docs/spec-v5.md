# spec-v5 — Gap Remediation Plan

Date: 2026-04-28
Supersedes: nothing. This document is an executable companion to `docs/spec.md`,
`docs/spec-15m-campaign.md`, and `docs/spec-gaps.md`. It exists to close the 32
gaps identified in the 2026-04-28 deep gap analysis.

This file is structured as a sequence of **prompts** to feed to Claude Code, one
per task. Each prompt is self-contained: it states the goal, the spec
references, the files involved, the acceptance criteria, and the verification
steps. Prompts are ordered so that earlier work unblocks later work. Where
work can be parallelised it is called out explicitly.

Conventions for every prompt below:

- Always `cargo test -p <crate>` for the directly-touched crate, then
  `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`
  before declaring the task done.
- Add or update unit/integration tests in the same commit as the code change.
- One prompt → one logical commit, on a feature branch off `main`. Commit
  messages should reference the `[spec-v5 G<n>]` tag for traceability.
- Never push to `main` directly. Open a PR per phase (or per prompt for
  high-risk items G1, G2, G7).
- If a prompt says "do not implement X yet", respect that — later prompts
  depend on the earlier surface staying minimal.

Status legend used inside each prompt's acceptance criteria:

- `MUST` — release-blocking; CI gate failing means the task is not done.
- `SHOULD` — strongly preferred; deviation requires a note in the PR
  description explaining why.

---

## Phase 0 — Pre-flight

### Prompt P0.1 — Stand up a remediation tracker

> Read `docs/spec-v5.md` end-to-end. Then create `docs/spec-v5-progress.md`
> as a checklist with one row per gap (G1 through G32) and columns:
> `Status`, `PR`, `Owner`, `Notes`. Initialise every row with
> `Status: not started`. Do not modify `spec-v5.md` itself. Commit on a
> branch named `spec-v5/tracker`. The progress file is updated by every
> subsequent prompt as part of its acceptance criteria.

### Prompt P0.2 — Add a `verify-all` CI lane that this plan can rely on

> Open `.github/workflows/ci.yml`. If a job already runs
> `cargo test --workspace --all-features` and `cargo clippy --workspace
> --all-features -- -D warnings`, do nothing. Otherwise add a job named
> `verify-all` that does both, on stable Rust, on Linux, with caching.
> The remainder of `spec-v5.md` assumes this lane exists and is required
> on PRs. Do not add new features here; only the lane.

---

## Phase 1 — P0 correctness gaps (authority and proof package)

These four prompts are the minimum to make the system's headline safety claims
true. Do not start Phase 2 until Phase 1 is merged.

### Prompt P1.G1 — Bind PCA hops to predecessor digest (A3)

> Read `docs/spec.md` sections 2.2 and 3.2, and `docs/spec-15m-campaign.md`
> finding G-09. Then read `crates/invariant-core/src/authority/chain.rs`
> and `crates/invariant-core/src/models/authority.rs` in full.
>
> Goal: every PCA hop after the principal hop must carry a cryptographic
> hash of the canonical bytes of its parent hop, and `verify_chain` must
> reject any chain where the predecessor digest does not match. This
> closes the "splice attack" pathway documented in spec-15m-campaign G-09.
>
> Tasks, in order:
>
> 1. Add a `predecessor_digest: Option<[u8; 32]>` field to the PCA payload
>    struct. Document that it is `None` for the principal hop and
>    `Some(sha256(parent.canonical_bytes()))` for every later hop.
> 2. Define `Pca::canonical_bytes()` — a deterministic byte serialisation
>    that excludes the signature itself and is stable under serde
>    round-trip. Add a unit test that asserts byte-for-byte stability
>    across re-serialisation.
> 3. Update `verify_chain` to (a) require `predecessor_digest` be
>    `None` exactly at index 0, and (b) require it to equal
>    `sha256(chain[i-1].canonical_bytes())` at every later index.
> 4. Regenerate any committed PCA fixtures so existing tests still pass.
>    Add a new negative test `splice_attack_rejected` that constructs
>    two locally valid chains sharing `p_0` and an issuer, splices them,
>    and asserts the verifier returns `AuthorityError::PredecessorMismatch`.
> 5. Add a positive test `predecessor_digest_chains_through_three_hops`.
> 6. Update `docs/spec.md` §3.2 only if the wording is now incorrect;
>    do not rewrite the section.
>
> Acceptance:
> - MUST: `cargo test -p invariant-core authority::` green, including
>   the two new tests.
> - MUST: existing audit, validator, and serve tests still green.
> - MUST: `cargo clippy --workspace -- -D warnings` clean.
> - SHOULD: a doctest on `predecessor_digest` showing how to construct
>   a hop manually.

### Prompt P1.G2 — Implement execution-binding invariants B1–B4

> Read `docs/spec.md` §3.3 (lines 394–403) and the planned module layout
> in §4.1. Read `crates/invariant-core/src/validator.rs` and
> `crates/invariant-cli/src/commands/serve.rs` in full. Confirm that
> `crates/invariant-core/src/authority/binding.rs` does not exist.
>
> Goal: stop accepting commands purely on signature + sequence. Bind
> every approved command to an explicit execution context (session,
> executor, time window) and reject any command whose context does not
> match its PCA.
>
> Tasks:
>
> 1. Create `crates/invariant-core/src/authority/binding.rs` exposing:
>    - `pub struct ExecutionContext { session_id: SessionId, executor_id:
>      ExecutorId, now: SystemTime }`
>    - `pub fn verify_execution_binding(pca_chain: &[Pca], cmd: &Command,
>      ctx: &ExecutionContext, session: &mut SessionState) -> Result<(),
>      BindingError>`
>    - `BindingError` variants `B1CrossSessionReplay`, `B2WithinSessionReplay`,
>      `B3StaleCommand`, `B4ExecutorMismatch`.
>    - `SessionState` tracking the highest-seen sequence per
>      `(session_id, pca_root)`.
> 2. Wire `verify_execution_binding` into `Validator::admit` after the
>    existing chain check; thread `ExecutionContext` through
>    `ValidatorConfig` and the `serve` command's per-connection state.
> 3. Add per-invariant tests under
>    `crates/invariant-core/src/authority/tests.rs`: one positive and
>    one negative case for each of B1, B2, B3, B4. Negative tests must
>    return the matching `BindingError` variant.
> 4. Update `crates/invariant-cli/src/commands/serve.rs` so that each
>    incoming connection establishes a `session_id` and declares an
>    `executor_id` (consume the bridge handshake added in G29 if it
>    has landed; otherwise add a temporary plaintext header field with
>    a TODO referencing G29).
> 5. Document the new context plumbing with rustdoc on `ExecutionContext`.
>
> Acceptance:
> - MUST: 8 new tests (4 positive, 4 negative) all green.
> - MUST: existing validator/serve tests still green.
> - MUST: clippy clean.

### Prompt P1.G7 — Merkle root and signed manifest in proof packages

> Read `docs/spec-15m-campaign.md` §6 (lines 371–407) and
> `crates/invariant-core/src/proof_package.rs` in full. Read
> `crates/invariant-cli/src/commands/verify_package.rs`.
>
> Goal: produce the deliverables the campaign spec actually promises:
> a Merkle tree over audit-log entries (so partial-tampering is
> detectable), and an Ed25519 signature over the manifest (so the
> manifest itself cannot be forged).
>
> Tasks:
>
> 1. Add a `merkle.rs` submodule under `proof_package` that builds a
>    binary SHA-256 Merkle tree over `Vec<AuditEntry>` in canonical
>    order, exposing `root() -> [u8;32]` and
>    `inclusion_proof(seq) -> MerkleProof`. Property-test that
>    `verify_proof(root, leaf, proof)` succeeds on valid proofs and
>    fails on any single-bit perturbation.
> 2. Extend `proof_package::assemble` to emit `audit/merkle_root.txt`
>    (hex) alongside the JSONL log and to include the Merkle root
>    inside `manifest.json` under a new `audit_merkle_root` field.
> 3. Sign `manifest.json` (canonical-JSON serialised) with the
>    campaign Ed25519 key; emit `manifest.sig` next to the manifest.
>    Use the existing `KeyStore` abstraction so the dev path is the
>    file backend and production paths fall through to G4 backends
>    when those land.
> 4. Update `verify-package` to (a) re-derive every file digest in
>    `manifest.json`, (b) verify `manifest.sig` against
>    `public_keys/manifest.pub`, (c) recompute the audit Merkle root
>    and confirm it matches `audit/merkle_root.txt`. Each check failing
>    must produce a distinct exit code (10/11/12).
> 5. Add an integration test that assembles a small synthetic
>    package, mutates one byte in one audit entry, and asserts
>    `verify-package` exits non-zero with the Merkle-mismatch code.
>
> Acceptance:
> - MUST: round-trip integration test (assemble → verify) green.
> - MUST: tamper test green.
> - MUST: `verify-package --help` documents the new behaviour.
> - SHOULD: a CHANGELOG entry under "Unreleased".

### Prompt P1.G8 — Add `invariant campaign assemble` subcommand

> Read `docs/spec-15m-campaign.md` §7 step 6 and `crates/invariant-cli/
> src/commands/campaign.rs` in full. Note that `proof_package::assemble`
> already exists as a Rust API but has no CLI front-end.
>
> Goal: a single command that takes a directory of per-shard outputs
> from `scripts/run_15m_campaign.sh` and writes the §6 directory layout
> (signed manifest + Merkle root from G7 included).
>
> Tasks:
>
> 1. Extend the `Campaign` clap subcommand enum with an
>    `Assemble { shards: PathBuf, output: PathBuf, key: PathBuf,
>    profile_set: Option<PathBuf> }` variant.
> 2. Implement the assemble path: enumerate shards, merge audit
>    JSONL preserving global sequence ordering, compute per-category
>    and per-profile rollups, produce Clopper-Pearson 99.9% CI per
>    category, write the §6 layout exactly:
>      - `audit/{audit.jsonl, merkle_root.txt}`
>      - `manifest.json`, `manifest.sig`, `public_keys/manifest.pub`
>      - `per_category/<id>.json`
>      - `per_profile/<id>.json`
>      - `per_check/<invariant_id>.json` (defer rich content if blocked
>        on G23, but the file must exist)
>      - `latency_distribution.json`
>      - `total_bypass_rate.json`
>      - `compliance/` (one .md per regime listed in spec.md §6)
>      - `adversarial/{protocol,authority,cognitive,compound}_attacks.json`
>        (empty arrays acceptable until G31 lands; emit a `_pending`
>        marker file in that subdirectory)
> 3. Add a CLI integration test that points at a fixture shards
>    directory under `crates/invariant-cli/tests/fixtures/shards/`
>    and asserts the produced layout matches §6 exactly (file presence
>    only — content schemas are tested by their owning crates).
>
> Acceptance:
> - MUST: `invariant campaign assemble --help` documents every flag.
> - MUST: integration test asserts every §6 path exists.
> - MUST: round-trip with `verify-package` from G7 succeeds.

---

## Phase 2 — P0/P1 campaign deliverable

These prompts make the 15M-episode campaign scientifically defensible.
They depend on Phase 1.

### Prompt P2.G9 — Implement remaining campaign scenarios

> Read `docs/spec-15m-campaign.md` §2.1 and §3 in full. Read
> `crates/invariant-sim/src/scenario.rs` to enumerate the existing 22
> `ScenarioType` variants. The spec defines 104 scenarios across
> categories A–N; only 22 are wired today.
>
> Goal: every spec-listed scenario ID must map to exactly one
> `ScenarioType` variant. This may be split across multiple commits;
> do one category per commit so review is tractable.
>
> Tasks (repeat per category in order: E, H, I, M, N, then fill A, B,
> C, F, G, J, K, L):
>
> 1. For category X, list the spec IDs (X-01..X-NN) and their target
>    episode counts.
> 2. Add one variant per ID to `ScenarioType` with a `#[doc]` that
>    quotes the spec line.
> 3. Implement the generator in the matching submodule under
>    `crates/invariant-sim/src/scenarios/` (create the submodule if
>    missing); reuse existing primitives where possible.
> 4. For each new scenario, add at least one happy-path and one
>    failure-path unit test, asserting that the scenario produces
>    audit entries the validator labels with the expected outcome
>    (admit / reject / safe-stop).
> 5. After all scenarios are in, add a workspace-level integration
>    test `scenario_coverage` that asserts: for every spec ID listed
>    in `docs/spec-15m-campaign.md` §3, exactly one `ScenarioType`
>    variant has a `#[doc]` matching that ID. Use a regex parse of
>    the spec; do not hand-maintain the list.
>
> Acceptance:
> - MUST: `scenario_coverage` test green.
> - MUST: per-category episode counts in the dry-run runner match
>   the spec's allocations.
> - MUST: `cargo test -p invariant-sim` runs in under 5 minutes on
>   the CI lane (use `#[cfg_attr(not(feature = "long"), ignore)]`
>   for any per-scenario test that exceeds 200ms).
> - SHOULD: a separate PR per category, not one giant PR.

### Prompt P2.G10 — Isaac Lab task envs for remaining profile families

> Read `isaac/envs/cnc_tending.py` and `isaac/envs/cell_config.py` to
> understand the existing UR10e env. Read `docs/spec-15m-campaign.md`
> §3 to enumerate the required profile families: arm, humanoid,
> quadruped, hand, mobile-manipulator.
>
> Goal: at least one Isaac Lab env per family that exposes
> `reset()`, `step(action)`, `observe()`, and emits the same JSON
> trace shape today's UR10e env emits.
>
> Tasks:
>
> 1. Create `isaac/envs/{arm,humanoid,quadruped,hand,mobile_base}.py`
>    each implementing the minimum env contract.
> 2. Create a headless driver `isaac/run_campaign.py` that takes a
>    profile JSON path and a scenario ID and selects the matching env.
> 3. Update `crates/invariant-cli/src/commands/campaign.rs` so the
>    non-dry-run path shells out to `run_campaign.py` instead of
>    erroring.
> 4. Document Isaac Lab version requirements and known-limitations
>    in `docs/runpod-simulation-guide.md`.
> 5. Add a smoke test `tests/isaac_envs_smoke.rs` (gated behind a
>    `--ignored` filter) that imports each env in a Python subprocess
>    and confirms it loads.
>
> Acceptance:
> - MUST: 5 env files present and individually loadable.
> - MUST: `invariant campaign run --profile <humanoid> --dry-run=false`
>   reaches the Isaac driver without erroring (an Isaac-not-installed
>   environment may still skip, but the wiring must succeed).
> - SHOULD: physical-world fidelity tuning is explicitly out of scope
>   here; record a `TODO(spec-v5 G10)` for any obviously-stubbed
>   physics parameters.

### Prompt P2.G31 — Bridge `invariant-fuzz` into the campaign runner

> Read `crates/invariant-fuzz/src/lib.rs` and submodules to enumerate
> available generators (protocol, system, cognitive). Read
> `docs/spec-15m-campaign.md` Category N.
>
> Goal: a `ScenarioType::RedTeamFuzz { method: FuzzMethod }` variant
> that lets the campaign orchestrator produce N-XX outcomes.
>
> Tasks:
>
> 1. Define `FuzzMethod { Mutation, Generation, GrammarBased,
>    CoverageGuided }` in `invariant-sim`. Wire each to the matching
>    `invariant-fuzz` generator behind a thin adapter trait.
> 2. Emit per-attempt audit entries tagged with the method, so the
>    proof package's `adversarial/<method>_attacks.json` can be
>    materialised by `campaign assemble` (G8).
> 3. Add a unit test that runs 100 attempts per method and confirms
>    the validator rejects every one (this is a release gate per
>    `docs/spec.md` §7.2).
> 4. Update `campaign assemble` (G8) to populate the `adversarial/`
>    directory from these traces and remove the `_pending` marker.
>
> Acceptance:
> - MUST: 100% rejection across 400 attempts in the unit test.
> - MUST: `_pending` marker no longer present in assembled packages.
> - SHOULD: a property-style test using `proptest` over mutation
>   inputs, capped at 1k cases for CI duration.

### Prompt P2.G24 — Cognitive-escape strategies map 1:1 to I-01..I-10

> Read `crates/invariant-fuzz/src/cognitive/escape.rs` (~808 lines)
> and `docs/spec-15m-campaign.md` Category I (10 strategies).
>
> Goal: every strategy I-01..I-10 has a uniquely named generator
> reachable from a `ScenarioType::CognitiveEscape { strategy }`
> variant. The `scenario_coverage` test from G9 must enforce
> presence; a new `cognitive_escape_zero_bypass` test must enforce
> behavior.
>
> Tasks:
>
> 1. Add a `CognitiveEscapeStrategy` enum with the 10 I-XX variants
>    documented inline.
> 2. Map each variant to one strategy in `escape.rs`; add missing
>    strategies (e.g. multi-agent collusion if absent) rather than
>    overloading existing ones.
> 3. For each variant, add a 1k-attempt integration test asserting
>    zero successful bypasses.
> 4. Wire the new `ScenarioType::CognitiveEscape` into the campaign
>    orchestrator so `per_category/I.json` is non-empty after a
>    dry-run campaign.
>
> Acceptance:
> - MUST: 10 variants, 10 tests, all asserting zero bypass.
> - MUST: `scenario_coverage` passes for category I.

### Prompt P2.G3 — Negative tests for G-07 wildcard and G-09 splice

> Read `crates/invariant-core/src/authority/operations.rs` and
> `crates/invariant-core/src/authority/tests.rs`.
>
> Goal: explicit, named tests for G-07 (wildcard exploitation) and
> G-09 (cross-chain splice). G-09 cannot be written until G1 lands,
> so this prompt is sequenced after Phase 1.
>
> Tasks:
>
> 1. Add `g07_wildcard_actuate_does_not_cover_read` asserting an
>    `actuate:*` operation does not authorise `read:joint_state`.
> 2. Add `g07_namespace_wildcard_does_not_cross_subsystem` asserting
>    an `actuate:arm:*` does not authorise `actuate:gripper:close`.
> 3. Add `g09_cross_chain_splice_rejected` constructing two valid
>    chains sharing `p_0` and an issuer, splicing them, and asserting
>    `AuthorityError::PredecessorMismatch`.
>
> Acceptance:
> - MUST: 3 new tests green.
> - MUST: `cargo test -p invariant-core authority::tests` complete
>   in under 1s.

### Prompt P2.G23 — `compliance --require-coverage` mode

> Read `crates/invariant-cli/src/commands/compliance.rs` and
> `docs/spec-15m-campaign.md` §5.1 row 10.
>
> Goal: the campaign release gate fails if any numbered invariant
> (P/A/B/L/M/W) lacks both a passing and a failing trace in the
> assembled package.
>
> Tasks:
>
> 1. Define a static manifest `INVARIANT_IDS` of every numbered
>    invariant currently shipped (parse from rustdoc cross-refs or
>    list manually with `// SPEC: <id>` markers).
> 2. Add a `--require-coverage` flag to `compliance` that walks
>    `audit/audit.jsonl` of an assembled package and asserts every
>    ID has at least one entry tagged `Outcome::Admit` and one
>    tagged `Outcome::Reject`.
> 3. Emit `compliance/coverage.md` listing missing IDs with their
>    spec sections.
> 4. Wire the flag into `campaign assemble` so the assembled package
>    fails to produce when coverage is incomplete (override with
>    `--allow-partial-coverage` for development assemblies).
>
> Acceptance:
> - MUST: a synthetic test where one ID is removed from the audit
>   trace asserts non-zero exit.
> - MUST: full-coverage path produces zero exit and a clean
>   `coverage.md`.

### Prompt P2.G13 — Split SR1 / SR2 sensor-range checks

> Read `crates/invariant-core/src/physics/environment.rs` lines
> 361–427 and `docs/spec-v2.md` lines 139–145.
>
> Goal: SR1 (env-state) and SR2 (payload) report independently.
>
> Tasks:
>
> 1. Rename the existing `check_sensor_range` to
>    `check_sensor_range_env` (SR1).
> 2. Add `check_sensor_range_payload` (SR2) consuming the payload
>    block.
> 3. Register both in `physics/mod.rs:326`.
> 4. Update `compliance` to count them separately.
> 5. Update tests that previously asserted the combined name.
>
> Acceptance:
> - MUST: spec coverage table (G23 output) shows SR1 and SR2 as
>   distinct rows.
> - MUST: existing physics boundary tests still green after the
>   rename.

### Prompt P2.G29 — Bridge handshake declares executor identity

> Read `crates/invariant-sim/src/isaac/bridge.rs` in full. Goal:
> the bridge protocol carries a per-connection executor identity
> that B4 (G2) can match against the PCA.
>
> Tasks:
>
> 1. Define an opening `HandshakeMessage { executor_id: ExecutorId,
>    challenge_signature: Ed25519Signature }`. The challenge is the
>    server's nonce signed with the executor's key.
> 2. The server publishes a fresh nonce on connect; rejects the
>    connection if the signature does not verify or if the executor
>    is unknown.
> 3. Plumb the verified `executor_id` into the per-connection
>    `ExecutionContext` consumed by G2.
> 4. Add tests for: valid handshake, missing handshake, bad signature,
>    unknown executor.
>
> Acceptance:
> - MUST: B4 negative test from G2 now uses this handshake instead
>   of a placeholder.
> - MUST: existing bridge tests green.

---

## Phase 3 — P1 production backends

These can be parallelised: G4, G5, G6 each touch independent files.

### Prompt P3.G4 — Real key-store backends

> Read `crates/invariant-core/src/keys.rs` to understand the
> `KeyStore` trait and the three stub backends (OS keyring, TPM,
> YubiHSM). Read `docs/spec.md` §1.5 and §9.
>
> Goal: each backend works against a real implementation, gated
> behind a Cargo feature, with at least one ignored integration
> test that exercises a real device or service in CI on opt-in.
>
> Tasks:
>
> 1. Add features `os-keyring` (using `keyring` crate),
>    `tpm` (using `tss-esapi`), `yubihsm` (using `yubihsm` crate).
>    Each is off by default.
> 2. Replace the `Unavailable` returns with real impls behind their
>    feature flags. When the feature is off, retain the
>    `Unavailable` error so the workspace still builds.
> 3. Replace stub-semantics tests with real-backend integration
>    tests under `#[ignore]` plus an `--ignored` CI lane that runs
>    only on a labelled PR.
> 4. Update `docs/spec.md` §9 only if a constraint changed; do not
>    rewrite.
>
> Acceptance:
> - MUST: default `cargo build --workspace` succeeds with all three
>   features off.
> - MUST: each feature builds individually (`cargo build -p
>   invariant-core --features tpm`, etc).
> - MUST: ignored tests are runnable locally and pass against a
>   fresh device.

### Prompt P3.G5 — S3 audit replication and HMAC webhook witness

> Read `crates/invariant-core/src/replication.rs`. Goal: real S3
> replication with SSE-KMS + Object Lock, and an HMAC-signed
> webhook witness with bounded retry.
>
> Tasks:
>
> 1. Add feature `replication-s3` using `aws-sdk-s3`. Implement
>    `S3Replicator::push` to stream entries with content SHA-256
>    set as Object Lock metadata; assert SSE-KMS is configured at
>    bucket level (fail fast if not).
> 2. Implement `WebhookWitness` with `hmac-sha256` signature header,
>    exponential backoff (max 5 tries, 30s total), and a
>    file-backed spillover queue at the path supplied in config.
> 3. Run replication on a dedicated tokio task; the validator hot
>    path must never await replication.
> 4. Add tests: S3 against `localstack` (ignored, opt-in), webhook
>    against `httpmock`.
>
> Acceptance:
> - MUST: validator throughput regression test shows <5% delta with
>   replication enabled vs. disabled (replication is async).
> - MUST: webhook spillover survives a process restart.

### Prompt P3.G6 — Real alert sinks (webhook, syslog)

> Read `crates/invariant-core/src/incident.rs`. Goal: webhook and
> syslog sinks deliver real alerts without blocking the validator.
>
> Tasks:
>
> 1. Webhook sink: HMAC-signed POST, retry/backoff identical to G5
>    webhook witness, dedicated task.
> 2. Syslog sink: RFC 5424, both UDP and TCP+TLS transports;
>    severity mapping documented in rustdoc.
> 3. Wire alert sinks to the existing incident bus; verify with an
>    integration test that an audit-gap incident produces both a
>    webhook POST and a syslog line.
> 4. Replace the existing `Unavailable` stub tests.
>
> Acceptance:
> - MUST: integration test using `httpmock` and a local syslog
>   listener passes.
> - MUST: validator latency unaffected (sink runs off the hot path).

---

## Phase 4 — P2 polish and integration tests

These are small, individually-scoped, and parallelisable.

### Prompt P4.G14 — Profile end-effector hygiene

> For each profile JSON listed below, fix as described:
>
> - `profiles/{anybotics_anymal,quadruped_12dof,spot,unitree_a1,
>   unitree_go2}.json`: add `"platform_class": "locomotion-only"` and
>   `"end_effectors": []`.
> - `profiles/agility_digit.json`: add a real `end_effectors` block
>   based on Agility Digit's published hand specs (cite the source
>   in a doc comment near the top of the file).
> - `profiles/adversarial_*.json`: add `"adversarial": true`. Two of
>   them lack an `environment` block; add one with placeholder values
>   and a TODO citing this prompt.
>
> Then run G15.

### Prompt P4.G15 — `invariant profile validate --strict`

> Add a `--strict` flag to the `profile` subcommand that fails if
> any profile permits a manipulation operation but declares no
> `end_effectors`. Wire `--strict` into the `verify-all` CI lane.
> Test against the profiles changed in G14.
>
> Acceptance:
> - MUST: `cargo run -- profile validate --strict` exits zero on
>   the cleaned profile set.
> - MUST: a temporary "broken" profile (manipulation op without
>   EE) makes it exit non-zero.

### Prompt P4.G16 — Fleet-scale coordinator test and `fleet status` CLI

> Read `crates/invariant-coordinator/src/{lib,monitor,partition}.rs`.
>
> Goal: prove the coordinator scales beyond pairwise; expose state
> over the CLI.
>
> Tasks:
>
> 1. Add an integration test `fleet_10_robots_60s` constructing
>    8 arms + 2 mobile bases with synthetic traffic for 60 seconds
>    and asserting (a) zero separation violations, (b) partitioning
>    correctness, (c) bounded per-step latency (<5ms median).
> 2. Add `Fleet { Status }` to the CLI subcommand registry, calling
>    into the coordinator to print active partitions, separations,
>    and last update times.
>
> Acceptance:
> - MUST: integration test green; runs in under 90s.
> - MUST: `invariant fleet status --help` documented.

### Prompt P4.G17 — Per-connection watchdog state

> Read `crates/invariant-sim/src/isaac/bridge.rs` lines 13–17 and
> the watchdog wiring downstream. The current single watchdog is
> shared across all clients of one bridge instance; a misbehaving
> client can mask another's missed heartbeat.
>
> Pick one of:
>
> Option A (preferred): refactor to a per-connection
> `WatchdogState`, keyed by the executor id from G29.
>
> Option B: enforce single-client, returning `BridgeError::SecondClient`
> on a second concurrent connection.
>
> Document the choice in the bridge module rustdoc; tests for both
> behaviours.
>
> Acceptance:
> - MUST: a test where two clients connect and one stops sending
>   heartbeats produces a watchdog event scoped to that client only
>   (Option A) or rejects the second client (Option B).

### Prompt P4.G25 — Intent end-to-end integration test

> Add `crates/invariant-cli/tests/intent_end_to_end.rs` that:
>
> 1. Reads a textual intent fixture.
> 2. Pipes it through `invariant intent compile` to produce a PCA.
> 3. Submits a matching command to a `serve`-mode validator.
> 4. Asserts admission for in-scope ops and rejection (with the
>    expected error variant) for out-of-scope ops.
>
> Acceptance:
> - MUST: at least 4 cases (2 admit, 2 reject) covering distinct
>   operation classes.

### Prompt P4.G26 — Eval engine driven by real campaign traces

> Add `crates/invariant-eval/tests/from_dry_run.rs` that:
>
> 1. Runs a small dry-run campaign (5 scenarios).
> 2. Exports the resulting trace.
> 3. Runs every preset in `presets.rs` and every guardrail in
>    `guardrails.rs` against the trace.
> 4. Asserts no preset panics, every guardrail produces a verdict,
>    and rubric scoring is monotonic on a deliberately-degraded
>    trace.
>
> Acceptance:
> - MUST: test runs in under 60s.
> - MUST: any new guardrail added in the future automatically gets
>   exercised (use a registry pattern).

### Prompt P4.G30 — Tampered-binary negative test for `verify-self`

> Add a CI test that copies the built `invariant` binary, flips one
> byte at a known offset, runs `verify-self` against the modified
> copy, and asserts a non-zero exit. Skip on Windows. Skip if the
> binary is not present (graceful no-op for unit-test runs).
>
> Acceptance:
> - MUST: test green on macOS and Linux CI lanes.
> - MUST: regression — if `verify-self` is accidentally weakened,
>   this test fails.

### Prompt P4.G32 — `proof_package` enforces §6 layout

> Define a typed `ProofPackageLayout` enumerating every directory
> and file required by `docs/spec-15m-campaign.md` §6. Have
> `proof_package::assemble` produce that layout exclusively; have
> `verify-package` consume it. Rejecting unknown top-level paths
> is acceptable but not required.
>
> Acceptance:
> - MUST: assembled packages from G8 already comply (no diff).
> - MUST: a fixture missing one §6 path causes `verify-package`
>   to exit non-zero with a layout-error code distinct from G7's
>   tamper code.

---

## Phase 5 — P2/P3 hygiene

### Prompt P5.G11 — RunPod script: SIGTERM trap, resume, MAX_USD ceiling

> Read `scripts/run_15m_campaign.sh` (~142 lines). Add:
>
> 1. A `trap` on SIGTERM/SIGINT that flushes the in-flight shard's
>    summary to disk before exit.
> 2. Idempotent resume: on start, scan the output dir for completed
>    shard markers and skip them.
> 3. A `MAX_USD` env var (default unset = unbounded). When set,
>    track elapsed wall time × on-demand rate; abort cleanly if
>    exceeded; log the abort reason to the output dir.
>
> Add a shellcheck pass to CI. Add a small Bats or shellspec test
> that invokes the script with a stub binary.
>
> Acceptance:
> - MUST: SIGTERM during a shard yields a clean partial result.
> - MUST: re-running the script after a kill resumes correctly.
> - MUST: `MAX_USD=0.01` aborts within one shard.

### Prompt P5.G12 — Shadow-mode deployment runbook

> Write `docs/shadow-deployment.md` covering: target robot-hours
> (≥100 on the UR10e CNC cell); metrics to collect (latency
> distribution, divergence count, audit gaps, watchdog trips);
> divergence triage protocol; explicit go/no-go criteria for
> Forge → Shadow → Guardian transition; on-call playbook stub.
> Cross-link from `docs/spec.md` §7.1 stage 3 and from README.
>
> Acceptance:
> - MUST: file present, ~300–500 lines.
> - MUST: README points to it.

### Prompt P5.G18 — Eliminate documentation count drift

> Goal: no spec or README cites a literal test count or subcommand
> count; both are derived from the build.
>
> Tasks:
>
> 1. Add `scripts/emit-counts.sh` that runs `cargo test --workspace
>    --no-run` and produces `docs/test-count.txt` with totals.
> 2. CI runs the script and uploads the file as an artifact.
> 3. Replace literal counts in `README.md`, `CHANGELOG.md`,
>    `docs/spec-v2.md`, `docs/public-release-polish.md` with a
>    pointer phrase ("see `docs/test-count.txt` in the latest
>    release artifacts").
>
> Acceptance:
> - MUST: `grep -rE "[12],[0-9]{3}\\+? tests" docs/ README.md
>   CHANGELOG.md` returns no matches.

### Prompt P5.G19 — Honest framing of the Lean formalisation

> Read `formal/Invariant.lean` and submodules (~740 lines). Note
> the `sorry` in `Authority.lean:90` and the axiomatized predicates
> in `Audit.lean:82` and `Physics.lean:132`.
>
> Tasks:
>
> 1. Write `formal/README.md` containing a status table: one row
>    per theorem, columns `Status` (proven / `sorry` / axiom /
>    sketch), `File:Line`, `Notes`. Be honest.
> 2. Close the `monotonicity_transitive` `sorry` if straightforward;
>    otherwise document the remaining proof obligation.
> 3. Add a non-blocking `lake build` job to CI; it must fail loudly
>    on a new `sorry` in code that previously had none.
> 4. Re-word `docs/spec.md` §8 to "specifies; mechanized proofs
>    in progress" rather than "proves". Keep it short.
>
> Acceptance:
> - MUST: status table accurate to the line numbers cited.
> - MUST: spec.md §8 wording updated.
> - SHOULD: at least one previously-unproven obligation closed.

### Prompt P5.G20 — SBOM and reproducible build verification

> Tasks:
>
> 1. Add a `cargo cyclonedx` step to `.github/workflows/release.yml`
>    that emits a CycloneDX SBOM and attaches it to the release.
> 2. Add `scripts/repro.sh` that builds inside the published
>    Dockerfile and asserts a stable image digest across two
>    consecutive runs (`SOURCE_DATE_EPOCH` pinned).
> 3. Document both in `docs/spec.md` (release-hygiene section).
>
> Acceptance:
> - MUST: a release dry-run produces an SBOM artifact.
> - MUST: `scripts/repro.sh` exits zero locally.

### Prompt P5.G21 — Resolve ROS2 binding ambiguity

> Read `invariant-ros2/` in full. It is a Python ROS2 node, not a
> Rust crate, and `Cargo.toml` does not reference it.
>
> Pick one:
>
> Option A: keep as a separate Python package; move under
> `examples/ros2/`; update README to say "Python ROS2 example
> (not built by the Rust workspace)"; add a CI smoke test that
> imports the module against a stubbed bridge.
>
> Option B: build a real Rust ROS2 crate using `r2r`, add to the
> workspace, deprecate the Python node.
>
> Default to Option A unless the user explicitly opts into B; B is
> a much larger commitment and would warrant its own spec doc.
>
> Acceptance:
> - MUST: README claim about ROS2 matches what the repo actually
>   builds and tests.

### Prompt P5.G22 — Spec consolidation

> Move `docs/spec-v1.md` … `docs/spec-v4.md` to
> `docs/history/spec-v1.md` … `docs/history/spec-v4.md`. Add a
> two-line header to each historical file pointing readers at
> `docs/spec.md`. Keep `docs/spec.md`, `docs/spec-15m-campaign.md`,
> `docs/spec-gaps.md`, and `docs/spec-v5.md` (this file) at the
> top level.
>
> Update every cross-reference in `README.md`, `CHANGELOG.md`,
> `CLAUDE.md`, and any rustdoc using `docs/spec-v[1-4].md` paths.
>
> Acceptance:
> - MUST: `grep -r "spec-v[1-4]" .` only matches the historical
>   directory or this file (`spec-v5.md`).

### Prompt P5.G27 — Spec-section cross-refs in `digital_twin` and `monitors`

> Add `// SPEC: docs/spec.md §<n>` rustdoc anchors at the top of
> each public item in `digital_twin.rs` and `monitors.rs`,
> matching the section that motivates the item. No code changes.
>
> Acceptance:
> - MUST: every `pub fn`, `pub struct`, `pub enum` in those two
>   files has an inline spec ref.

### Prompt P5.G28 — Decide the fate of `forge.rs`

> Read `crates/invariant-cli/src/commands/forge.rs` and `main.rs`.
>
> Pick one:
>
> Option A: wire `Forge` into the subcommand registry, document
> what it does (likely surface for `docs/spec.md` §1.6 Forge mode),
> add a help-output test.
>
> Option B: delete the file and any cross-references.
>
> The user should make this call. If unclear, default to Option B
> and surface a question in the PR description.

---

## Cross-cutting acceptance criteria

These must hold at the end of every Phase, not just at the end of the plan:

- `cargo test --workspace --all-features` green on macOS and Linux CI.
- `cargo clippy --workspace --all-features -- -D warnings` clean.
- No new `panic!`, `unwrap`, `expect("…")`, or `unimplemented!()` on a
  production path. Use `Result` and a typed error.
- `docs/spec-v5-progress.md` reflects current status.
- No spec text claims a behavior that is not exercised by at least one
  test. If a spec section becomes aspirational again, mark it
  explicitly as such with a `[planned]` marker and a link to the
  tracking issue.

## Suggested ordering and parallelism

```
Phase 1 (serial):     P1.G1 → P1.G2 → P1.G7 → P1.G8
Phase 2 (mostly serial, with parallel branches):
                      P2.G9 (per-category, parallelisable across categories)
                      P2.G10 (parallel with G9 once interfaces stable)
                      P2.G31 (after G8)
                      P2.G24 (after G9 cat I)
                      P2.G3  (after G1)
                      P2.G23 (after G8)
                      P2.G13 (independent)
                      P2.G29 (before or alongside G2 finalisation)
Phase 3 (parallel):   P3.G4, P3.G5, P3.G6
Phase 4 (parallel):   P4.G14 → P4.G15
                      P4.G16, P4.G17, P4.G25, P4.G26, P4.G30, P4.G32
Phase 5 (parallel):   P5.G11, P5.G12, P5.G18, P5.G19,
                      P5.G20, P5.G21, P5.G22, P5.G27, P5.G28
```

Phase 1 is the only strict prerequisite for everything else; Phases 3, 4,
and 5 are largely independent and can run as parallel work streams once
Phase 1 lands.
