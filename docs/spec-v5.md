# spec-v5: Gap-Closure Plan

This document is the actionable follow-up to a deep gap analysis comparing
`docs/spec.md`, `docs/spec-v1..v4.md`, and `docs/spec-15m-campaign.md` against
the actual implementation in `crates/`. It enumerates **20 gaps** and provides,
for each one, a self-contained prompt suitable for handing to Claude Code as a
single task.

Each prompt is written so it can be copy-pasted into a fresh Claude Code session
with no other context. Prompts intentionally avoid embedding code snippets;
they describe *intent, files, function signatures, tests, and acceptance
criteria* and let the implementer produce the actual code. Prompts assume
working tree clean on `main` unless stated otherwise.

After every prompt, the implementer must run, in this exact order:

1. `cargo build`
2. `cargo test`
3. `cargo clippy -- -D warnings`

and only commit if all three pass. Use one logical commit per prompt.

---

## Recommended execution order

1. Phase A — Authority & proof-package correctness: P1, P2, P3, P4
2. Phase B — Production safety hardening: P18, P19
3. Phase C — CLI surface & compliance accuracy: P8, P12, P13
4. Phase D — Pluggable backends (feature-gated, parallelizable): P5, P6, P7
5. Phase E — Coverage & breadth: P9, P10, P11
6. Phase F — Long-tail tests & documentation: P14, P15, P16, P17, P20

---

## Phase A — Authority & proof-package correctness

### P1 — Implement execution-binding invariants B1–B4

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: implement the four execution-binding invariants B1–B4 defined in
docs/spec.md (search for "B1", "B2", "B3", "B4" — execution binding section).
These invariants currently do not exist in code. The crate
crates/invariant-core/src/authority/ contains chain.rs, crypto.rs, mod.rs,
operations.rs, tests.rs, but no binding.rs.

Steps:
1. Read docs/spec.md sections describing B1 (session binding), B2 (sequence
   monotonicity vs. PCA), B3 (temporal window), B4 (executor identity).
2. Read crates/invariant-core/src/authority/mod.rs and chain.rs to understand
   the existing types (Pca, AuthorityChain, verify_chain).
3. Create crates/invariant-core/src/authority/binding.rs with:
   - An ExecutionContext struct carrying session_id, last_sequence,
     wall_clock_now, executor_pubkey.
   - A BindingError enum with one variant per invariant.
   - A pub fn verify_execution_binding(chain: &AuthorityChain, ctx:
     &ExecutionContext) -> Result<(), BindingError> that enforces all four
     invariants.
4. Re-export the new types from authority/mod.rs.
5. Wire verify_execution_binding into the request path of
   crates/invariant-cli/src/commands/serve.rs so each request constructs an
   ExecutionContext from per-connection state and rejects on BindingError.
6. Add unit tests in authority/binding.rs covering each invariant in isolation
   (one passing case + one failing case per invariant) and one end-to-end test
   in the serve command exercising rejection.

Acceptance: cargo test passes including new tests; cargo clippy clean.
Do not modify behavior of existing chain.rs verification — binding is a
separate, additional layer applied at the executor edge.
```

### P2 — Add A3 predecessor-digest causal binding to PCA chain

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: enforce A3 causal binding between PCA hops as described in docs/spec.md
(search for "A3", "predecessor", "PoC"). Today verify_chain in
crates/invariant-core/src/authority/chain.rs only checks signatures and
sequence monotonicity; nothing prevents two valid sub-chains from being
spliced together (campaign attack G-09).

Steps:
1. Read docs/spec.md and docs/spec-15m-campaign.md sections on A3 and G-09.
2. Add a fixed-size [u8;32] predecessor_digest field to the Pca struct in
   crates/invariant-core/src/authority/operations.rs (or wherever Pca is
   defined). The first hop's predecessor_digest is all zeros by convention.
3. Implement a canonical_bytes() method on Pca that produces a deterministic
   byte serialization (document the exact format; do not change existing
   signing input semantics — sign over canonical_bytes EXCLUDING
   predecessor_digest if that would otherwise create a circular dependency,
   then sign the digest separately as part of the hop's signed payload —
   choose whichever variant keeps existing signature tests green and document
   the decision).
4. Modify verify_chain to enforce hop[i].predecessor_digest ==
   sha256(hop[i-1].canonical_bytes()) for i >= 1, returning a new
   ChainError::PredecessorMismatch { index } variant on failure.
5. Update every test fixture and constructor that builds a Pca chain to
   populate predecessor_digest correctly. Centralize this in a helper if it
   reduces churn.
6. Add a test g09_cross_chain_splice_rejected that builds two valid chains A
   and B, splices hop 2 from B onto A, and asserts PredecessorMismatch
   { index: 2 }.

Acceptance: cargo test passes (including all pre-existing chain tests, which
must continue to validate); cargo clippy clean. Update any docs in
docs/spec.md or docs/spec-v*.md that describe the on-disk PCA format.
```

### P3 — Merkle root over audit log in proof package

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: produce a Merkle root over all audit JSONL entries and emit it as part
of the proof package, as required by docs/spec-15m-campaign.md (search for
"merkle_root.txt") and docs/spec.md (audit chain section).

Steps:
1. Create crates/invariant-core/src/merkle.rs implementing a binary SHA-256
   Merkle tree over Vec<[u8;32]> leaves. Define leaf encoding as
   sha256(0x00 || raw_jsonl_line_bytes) and internal nodes as
   sha256(0x01 || left || right). Pad odd levels by duplicating the last
   node (document the choice).
3. Re-export from crates/invariant-core/src/lib.rs.
4. Modify crates/invariant-core/src/proof_package.rs::assemble to:
   - Stream every audit JSONL line across all shards in canonical order.
   - Compute the Merkle root.
   - Write merkle_root.txt (hex-encoded root) into the package.
   - Include the root in the manifest.json.
5. Extend verify_package to recompute the root from the bundled JSONL and
   compare against merkle_root.txt and the manifest field. On mismatch,
   return ProofPackageError::MerkleMismatch.
6. Add unit tests for merkle.rs (empty tree, single leaf, two leaves, odd
   leaves) and an integration test for assemble + verify_package round-trip
   across a small synthetic audit.

Acceptance: cargo test passes; cargo clippy clean. Pre-existing
proof_package tests must be updated to expect the new artifact.
```

### P4 — Sign the manifest in proof packages

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: emit a detached Ed25519 signature over manifest.json so the proof
package is self-authenticating. Today
crates/invariant-core/src/proof_package.rs::assemble explicitly leaves the
manifest unsigned.

Steps:
1. Add a signing_key parameter (type matching the existing Ed25519 SigningKey
   used elsewhere in keys.rs) to proof_package::assemble. Make it required;
   do not default to None.
2. After writing manifest.json, compute Ed25519 signature over its exact
   on-disk bytes and write manifest.sig in the package directory.
3. Extend verify_package to take a verifying key and require manifest.sig to
   be present and valid. Define ProofPackageError::ManifestSignatureInvalid
   and ::ManifestSignatureMissing.
4. Update every caller of assemble in the workspace (CLI, tests, examples)
   to pass a key. For tests, use a hard-coded deterministic test key.
5. Update docs/spec-15m-campaign.md if it does not already describe
   manifest.sig in the package layout section.

Acceptance: cargo test passes; cargo clippy clean. Round-trip test
(assemble → tamper with manifest.json → verify_package fails with
ManifestSignatureInvalid) is included.
```

---

## Phase B — Production safety hardening

### P18 — Bound bridge read_line to prevent OOM

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: fix a DoS vector in crates/invariant-sim/src/isaac/bridge.rs where a
malicious client can buffer arbitrary bytes via read_line before the size
check fires.

Steps:
1. Read bridge.rs around the read_line call (it is in the per-connection
   read loop, near a max_msg constant).
2. Replace the unbounded read_line with a bounded read by wrapping the
   reader in a Take adapter limited to max_msg bytes, then call read_line.
3. After read_line returns, check whether the buffered line ends in '\n'.
   If not (i.e. the limit was hit before a newline arrived), emit a
   structured BridgeError::MessageTooLarge to the client over the channel
   protocol and close the connection cleanly. Do not leak per-byte read
   errors to the client.
4. Add a unit/integration test that connects to the bridge, sends max_msg+1
   bytes with no newline, and asserts the connection is closed and process
   memory does not grow unbounded (memory check can be a soft assertion;
   the structural assertion is "connection closed without a panic").

Acceptance: cargo test passes; cargo clippy clean. Ensure no regression in
the existing bridge happy-path test.
```

### P19 — Atomic sequence-monotonicity check in serve

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: eliminate a TOCTOU race in crates/invariant-cli/src/commands/serve.rs
where two concurrent requests carrying the same sequence number can both
pass the monotonicity check (replay).

Steps:
1. Locate the AtomicU64 used for last_sequence and the load + fetch_max
   pattern around it.
2. Replace with a compare_exchange loop: read current, verify
   request.sequence > current, then attempt
   compare_exchange(current, request.sequence). Loop only on contention
   (Err returning a fresher current). On request.sequence <= current, reject
   with the existing replay error.
3. Add a stress test that spawns N=10 tokio tasks all submitting requests
   with the same sequence number against a shared serve handler; assert
   exactly one succeeds and N-1 are rejected. Use a deterministic seed and
   a small loop count so the test runs in <1s.

Acceptance: cargo test passes; cargo clippy clean. Existing serve tests
remain green.
```

---

## Phase C — CLI surface & compliance accuracy

### P8 — Add `invariant campaign assemble` subcommand

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: expose the existing proof_package::assemble Rust API as a CLI
subcommand under crates/invariant-cli/src/commands/campaign.rs.

Steps:
1. Read crates/invariant-cli/src/commands/campaign.rs and surrounding clap
   command registration (likely in commands/mod.rs or main.rs).
2. Add a new `assemble` subcommand under `campaign` with these flags:
   --shards <DIR> (required, contains per-shard audit JSONL + summary JSON),
   --output <PATH> (required, output package directory),
   --key <PATH> (required, Ed25519 signing key file as already used by
     keygen subcommand).
3. Implement the handler: enumerate shard directories, collect audit JSONL
   streams and summary JSONs, call proof_package::assemble (which now
   requires the signing key per P4 and produces a Merkle root per P3).
4. Compute Clopper-Pearson 95% confidence intervals per scenario category
   from the summary data and include them in a top-level
   confidence_intervals.json next to the manifest. Use the statrs crate if
   already a dependency; otherwise implement directly.
5. Add an end-to-end CLI test that builds a fake two-shard tree on tmpdir,
   runs the subcommand, and verifies the output package via verify_package.
6. Update CLAUDE.md subcommand list and README if it enumerates subcommands.

Acceptance: cargo test passes; cargo clippy clean.
```

### P12 — Add end_effectors / environment blocks to nine profiles

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: bring profile JSONs into compliance with docs/spec-v1.md §1.1 which
requires an end_effectors block on manipulation profiles and an environment
block on adversarial profiles.

Steps:
1. Audit profiles/ — confirm which of the following lack end_effectors:
   franka_panda.json, humanoid_28dof.json, quadruped_12dof.json, ur10.json,
   ur10e_haas_cell.json, shadow_hand.json, allegro_hand.json, leap_hand.json,
   psyonic_ability.json. Also confirm adversarial_max_joints.json and
   adversarial_single_joint.json lack environment blocks.
2. For each manipulation profile, add an end_effectors block populated from
   the public datasheet of the corresponding hardware, including realistic
   max grasp force, max payload, and degrees-of-freedom for each
   end-effector. For humanoid/quadruped without manipulators, add an empty
   end_effectors: [] and a comment in adjacent docs (not in the JSON itself)
   explaining the convention.
3. For adversarial profiles, add an environment block consistent with the
   other adversarial fixtures.
4. Add a CLI subcommand `validate-profiles --strict` (or extend the existing
   validate command with --strict) that fails the build if any builtin
   manipulation profile is missing end_effectors when manipulation
   capabilities are declared. Wire the strict check into a workspace test.

Acceptance: cargo test passes; cargo clippy clean. The new strict check is
green against the updated profiles.
```

### P13 — Split sensor-range pre-filter into SR1 (env) and SR2 (payload)

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: docs/spec-v2.md defines SR1 (environment-state range) and SR2 (payload
range) as two distinct pre-filters, but
crates/invariant-core/src/physics/environment.rs implements them in a single
check returning a CheckResult named "sensor_range".

Steps:
1. Read docs/spec-v2.md SR1/SR2 section.
2. In environment.rs, split check_sensor_range into
   check_sensor_range_env (SR1) and check_sensor_range_payload (SR2). Each
   returns a CheckResult with a distinct name string.
3. Update crates/invariant-core/src/physics/mod.rs registration so both
   checks appear in the registry.
4. Update any compliance/coverage subcommand that aggregates check counts
   so SR1 and SR2 are reported separately.
5. Update docs/spec-v*.md only if they reference the unified check name.
6. Update or add unit tests covering each split check independently.

Acceptance: cargo test passes; cargo clippy clean.
```

---

## Phase D — Pluggable backends (feature-gated, parallelizable)

### P5 — Implement OS keyring / TPM / YubiHSM key stores

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: replace the three KeyStoreError::Unavailable stubs in
crates/invariant-core/src/keys.rs (OsKeyringKeyStore, TpmKeyStore,
YubiHsmKeyStore) with real implementations gated behind cargo features
`os-keyring`, `tpm`, `yubihsm`.

Steps:
1. Read keys.rs to understand the KeyStore trait surface.
2. Add three optional features to crates/invariant-core/Cargo.toml. Pull in
   appropriate libraries (e.g. `keyring` for OS keyring, `tss-esapi` for
   TPM2, `yubihsm` for YubiHSM) only under their respective feature flags.
3. Implement get/set/delete and Ed25519 sign for each backend. For TPM and
   YubiHSM, use device-resident keys where possible and never expose raw
   private bytes outside the device.
4. Add a `--store {file,os-keyring,tpm,yubihsm}` flag to the keygen
   subcommand. Default remains `file`.
5. Add feature-gated integration tests that round-trip Ed25519 sign + verify
   per backend. These tests must be #[ignore]'d by default if the backend
   requires hardware not present in CI; document the manual run command.
6. Update docs/spec-v3.md hardening section to mark these as implemented.

Acceptance: `cargo build --all-features` succeeds; `cargo test` (no
features) passes unchanged; `cargo clippy --all-features -- -D warnings`
clean. Document the feature matrix in README.
```

### P6 — Implement S3 replication and webhook witness

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: replace the ReplicationError::Unavailable stubs in
crates/invariant-core/src/replication.rs (S3Replicator::push,
WebhookWitness::push) with real implementations gated behind cargo features
`replication-s3` and `replication-webhook`.

Steps:
1. Read replication.rs to understand the Replicator trait and existing
   in-memory backend.
2. For S3: behind feature `replication-s3`, use `aws-sdk-s3` to PUT objects
   with SSE-KMS configured via env (KMS key ARN). Set Object Lock (governance
   mode) retention if a configured retention duration is provided. Surface
   credential / config errors as ReplicationError variants.
3. For webhook: behind feature `replication-webhook`, POST the payload as
   JSON with an HMAC-SHA256 signature header (X-Invariant-Signature) over
   the raw body using a shared secret. Add disk-spillover retry with
   exponential backoff so a failing endpoint does not block the hot path.
4. Add a MinIO-based integration test (under `tests/`, gated by an env var
   like INVARIANT_TEST_MINIO=1) that pushes 100 records, kills the MinIO
   container, restarts it, and verifies the replicator drains its queue.
5. Update docs/spec.md L1–L4 audit invariants section if it claimed these
   were already done.

Acceptance: `cargo build --all-features` succeeds; default `cargo test`
unchanged; `cargo clippy --all-features -- -D warnings` clean.
```

### P7 — Implement webhook + syslog incident alert sinks

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: replace the AlertSinkError::Unavailable stubs in
crates/invariant-core/src/incident.rs (WebhookAlertSink, SyslogAlertSink)
with real implementations gated behind cargo features `incident-webhook`
and `incident-syslog`.

Steps:
1. Read incident.rs to understand the AlertSink trait.
2. WebhookAlertSink (feature `incident-webhook`): POST JSON with
   HMAC-SHA256 signature header. Bounded retry queue with disk spillover
   so the hot path never blocks on a slow endpoint.
3. SyslogAlertSink (feature `incident-syslog`): emit RFC 5424 messages over
   either UDP or TCP+TLS, configurable via the constructor. Severity maps
   from IncidentSeverity to syslog priority.
4. Add load tests asserting that a stuck sink does not introduce more than
   N microseconds of latency on the calling thread (use a fault-injection
   wrapper around the transport).
5. Update docs/spec-v3.md incident-alerting section.

Acceptance: `cargo build --all-features` succeeds; default `cargo test`
unchanged; `cargo clippy --all-features -- -D warnings` clean.
```

---

## Phase E — Coverage & breadth

### P9 — Implement remaining 82 scenario variants

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: docs/spec-15m-campaign.md enumerates 104 scenario IDs, but
crates/invariant-sim/src/scenario.rs only defines 22 ScenarioType variants.
Statistical claims in the campaign spec assume full coverage.

Steps:
1. Read docs/spec-15m-campaign.md scenario index (Categories A–N).
2. Inventory the 22 existing variants in scenario.rs and identify the
   missing ones, especially: full Category E (Manipulation, 6 IDs), H
   (Temporal, 6 IDs), I (Cognitive, 10 IDs), N (Red-Team Fuzz, 10 IDs),
   plus partial gaps in J/K/L/M.
3. For each missing scenario, add a ScenarioType variant and the minimum
   logic needed to drive it through the existing simulation harness.
4. Add a Scenario::all() -> &'static [ScenarioType] enumerator.
5. Update is_expected_reject classification logic so each new scenario has
   a defined expected outcome.
6. Add a scenario_coverage integration test that loads the campaign-spec
   ID list (consider extracting it to a JSON in profiles/ or campaigns/ if
   that simplifies testing) and asserts every ID has a matching variant.

Acceptance: cargo test passes; cargo clippy clean. The coverage test is
green and will fail in future if a new spec ID is added without a variant.
```

### P10 — Add missing Isaac Lab task environments

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: docs/spec-15m-campaign.md §3 requires humanoid, quadruped, hand,
mobile-base, and arm task envs, but isaac/envs/ contains only
__init__.py, cell_config.py, cnc_tending.py.

Steps:
1. Read isaac/envs/cnc_tending.py to learn the existing env conventions
   (reset, step, observation schema, alignment with SensorPayload).
2. Create five new env modules under isaac/envs/: humanoid.py, quadruped.py,
   hand.py, mobile_base.py, arm.py. Each implements reset/step/observe with
   observations matching SensorPayload as defined in the Rust core.
3. Create isaac/run_campaign.py — a headless driver that consumes a campaign
   YAML, instantiates the appropriate env per scenario, and writes audit
   JSONL to a shard directory.
4. Replace the stub in crates/invariant-cli/src/commands/campaign.rs that
   prints "use Python runner and exits" with an actual subprocess invocation
   of run_campaign.py (or document the new command flow if Python is meant
   to be invoked directly).
5. Add a 1K-episode smoke test (gated by env var INVARIANT_ISAAC=1) for
   one humanoid + one arm scenario.

Acceptance: cargo test passes (default); when INVARIANT_ISAAC=1 with Isaac
Lab installed, the smoke test passes. cargo clippy clean.
```

### P11 — Reconcile profile count: 17 implemented vs. 34 claimed

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: docs/spec-15m-campaign.md claims 34 builtin profiles (30 real-world +
4 synthetic). profiles/ contains ~17 JSONs.

Steps:
1. Inventory profiles/ and list every builtin currently registered.
2. Compare against the 30 real-world profiles claimed by the campaign spec
   (Fourier GR-1, Tesla Optimus, Figure 02, Boston Dynamics Atlas, Agility
   Digit, Sanctuary Phoenix, 1X NEO, Apptronik Apollo, ANYbotics ANYmal,
   etc.).
3. Decide per missing profile whether to (a) author a new JSON from public
   URDF/datasheet sources or (b) drop it from the spec with rationale.
4. Author the JSONs you committed to in step 3, ensuring each passes the
   strict validate-profiles check from P12.
5. If any profiles are dropped, update docs/spec-15m-campaign.md §4 with an
   explicit table listing what was removed and why.
6. Add a profile-loading smoke test that loads every builtin and asserts no
   panics, no validation errors.

Acceptance: cargo test passes; cargo clippy clean. Spec claim and code
reality match.
```

---

## Phase F — Long-tail tests & documentation

### P14 — Add G-07 wildcard-exploitation tests

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: docs/spec-15m-campaign.md G-07 specifies that an authority chain
granting actuate:* must NOT cover read:*, and namespace wildcards must not
cross namespace boundaries. No tests cover this today.

Steps:
1. Read crates/invariant-core/src/authority/operations.rs for wildcard
   semantics.
2. Add to authority/tests.rs (or a new file):
   - g07_wildcard_actuate_does_not_cover_read: chain grants actuate:*, a
     PCA requesting read:proprioception is rejected.
   - g07_move_namespace_wildcard: chain grants move:arm.*, a PCA requesting
     move:base.linear is rejected.
3. Add at least one positive test per pair to lock in the intended
   semantics (e.g. move:arm.* covers move:arm.shoulder).

Acceptance: cargo test passes; cargo clippy clean.
```

### P15 — Add G-09 cross-chain splice test (depends on P2)

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: lock in the A3 predecessor-digest behavior delivered by P2 with an
explicit attack test for campaign attack G-09.

Prerequisite: P2 has landed.

Steps:
1. In authority/tests.rs (or chain.rs tests), add
   g09_cross_chain_splice_rejected: build two valid chains A and B with the
   same root issuer, splice hop 2 from B onto A so signatures still verify
   in isolation, run verify_chain on the spliced chain, assert
   ChainError::PredecessorMismatch { index: 2 }.
2. Confirm the test fails on a synthetic regression where you set
   predecessor_digest equal to the wrong hop's digest.

Acceptance: cargo test passes; cargo clippy clean.
```

### P16 — Multi-robot fleet coverage and `fleet status` subcommand

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: exercise crates/invariant-coordinator end-to-end and expose its state
to operators.

Steps:
1. Read crates/invariant-coordinator/src/{monitor.rs,partition.rs}.
2. Add an integration test fleet_10_robot under
   crates/invariant-coordinator/tests/ that simulates 8 manipulator arms +
   2 mobile bases over a 60-second virtual horizon, scripts a near-miss,
   and asserts the coordinator detects and prevents collision.
3. Add a `fleet status` subcommand to invariant-cli that reads the
   coordinator state (via whatever IPC or in-process handle currently
   exists) and prints a human-readable report plus a --json output.
4. Update CLAUDE.md and README subcommand counts in lockstep with P8 and
   any other CLI additions.

Acceptance: cargo test passes; cargo clippy clean.
```

### P17 — Per-connection bridge watchdog isolation

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: docs/spec.md W1 requires per-cognitive-layer heartbeats; today
crates/invariant-sim/src/isaac/bridge.rs uses a single shared watchdog
across all connections — a stalled client can interfere with others.

Steps:
1. Read bridge.rs around the watchdog and connection accept loop.
2. Choose one of two fixes (document the decision in the commit message):
   (a) refactor watchdog state to be per-connection so each client is
       monitored independently, or
   (b) explicitly enforce single-client-at-a-time and reject additional
       connections with BridgeError::SecondClient.
3. Add a regression test verifying that a stalled connection (one that
   stops sending heartbeats) does NOT cause healthy connections to be
   killed, OR (under choice b) that a second connection is cleanly
   rejected.

Acceptance: cargo test passes; cargo clippy clean.
```

### P20 — Eliminate documentation count drift

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: README, CHANGELOG, spec-v2.md, and other docs cite divergent test
counts ("~2,047", "128", "2,023+"); actual is currently 1,881. Subcommand
counts also drift as new subcommands land (P8 and P16 each add one).

Steps:
1. Add a `scripts/emit-counts.sh` (or extend an existing script) that runs
   `cargo test --no-run -- --list 2>/dev/null` (or grep -rc "#\[test\]"
   crates/) to compute the test count, and computes the subcommand count
   by parsing the clap definitions. Write the results to docs/test-count.txt
   and docs/subcommand-count.txt.
2. Run the script in CI; fail the build if either file changed but was not
   committed.
3. Replace hard-coded counts in README.md, CHANGELOG.md, and any
   docs/spec-v*.md with references to these files (e.g. "see
   docs/test-count.txt for the live count") rather than literal numbers.
4. Commit the current count files.

Acceptance: CI is green; no literal test or subcommand counts remain in
documentation.
```

---

## Cross-cutting checklist

When a prompt is finished, before opening a PR, the implementer should also:

- Run `cargo build`, `cargo test`, `cargo clippy -- -D walls` (per CLAUDE.md).
- Confirm no `unimplemented!()` or `todo!()` was added.
- Update `docs/spec-gaps.md` to mark the corresponding gap closed.
- Keep one commit per prompt — squash within a prompt if intermediate commits
  accumulate.
- Never push directly to `main` (per CLAUDE.md).

---

## Out of scope for this document

- Performance tuning beyond what each gap requires.
- New features not already implied by docs/spec*.md.
- Refactors of code paths that are correct as written.

If during implementation a prompt is found to be ambiguous, the implementer
should pause and request clarification rather than guess; an under-specified
prompt is a bug in this document, not a license to improvise.
