# Spec v6 — Gap Closure Workplan (Prompt-Driven)

**Date:** 2026-05-01
**Audience:** A Claude Code (or equivalent agent) implementer working ticket-by-ticket through this file.
**Source of gap inventory:** Deep gap analysis comparing all of `docs/spec.md`, `docs/spec-v1.md` … `docs/spec-v5.md`, and `docs/spec-15m-campaign.md` against the current state of the six crates under `crates/`.
**Goal:** Drive the codebase to the state described by spec-v5 + spec-15m-campaign, resolving the contradictions in earlier specs along the way.

> ## How to use this document
>
> Each section below is a **standalone Claude Code prompt**. Copy the prompt into a fresh Claude Code session (or a subagent) and let it run end-to-end. Prompts are ordered by dependency: do not start a later task before its predecessors are merged. Each prompt is self-contained — it names the files, lines, and acceptance criteria the implementer needs.
>
> Definition of done for every prompt:
> 1. `cargo build --workspace` succeeds.
> 2. `cargo test --workspace` succeeds; new tests added per the prompt's "Tests" section.
> 3. `cargo clippy --workspace --all-targets -- -D warnings` is clean.
> 4. The implementer leaves a one-paragraph summary in the PR description that maps to the prompt's "Acceptance" bullets.
>
> **Do not** combine prompts into one PR — one prompt = one logical commit/PR per `CLAUDE.md` conventions.

---

## Phase 0 — Spec Hygiene (do first; ~½ day)

### Prompt 0.1 — Reconcile spec lineage and vocabulary

```
You are working in /Users/user/Documents/development/public/invariant-robotics.

Goal: produce a single, coherent spec lineage so future readers (and you) can find the
authoritative requirement for any feature without cross-referencing four overlapping files.

Background: docs/ currently contains spec.md plus spec-v1.md … spec-v6.md and
spec-15m-campaign.md. The files contradict each other on:
  - Profile counts (spec.md/v2 §4 says 13; codebase has 34 in
    crates/invariant-sim/src/campaign.rs:1141–1320; spec-v4 §2.1 flagged this).
  - Category A scenario count (spec-15m-campaign.md §2.1 says 6; §3 detail table says 8).
  - Vocabulary: "PIC" (Provenance/Intent/Continuity) vs "PCA" (Provenance Chain Authority)
    are used interchangeably across specs.

Tasks:
1. Create docs/history/ and move spec.md, spec-v1.md, spec-v2.md, spec-v3.md, spec-v4.md
   into it without modification. Leave spec-v5.md and spec-v6.md (this file) and
   spec-15m-campaign.md in docs/.
2. Create docs/spec.md (NEW) as a 1–2 page index that:
   - States that spec-v5.md is the authoritative requirement set, spec-v6.md is the
     active workplan, and spec-15m-campaign.md is the campaign contract.
   - Lists historical specs with one-line summaries and points to docs/history/.
   - Defines a single vocabulary section (PCA ≡ PIC; pick "PCA" as the canonical term;
     note the alias). Define ExecutionContext, BindingInvariant, and the L/M/W/SR check
     id families in one place.
3. Resolve the Category A count: edit docs/spec-15m-campaign.md so §2.1 row A and §3
   detail agree. Choose A=8 (the more detailed table is more recent). Recompute the
   per-category totals in §2.1 so they still sum to 15,000,000.
4. Resolve the profile count: edit docs/spec-15m-campaign.md §1.1 and §4 so the platform
   matrix matches BUILTIN_NAMES in crates/invariant-core/src/profiles.rs (expect ~30
   real-world + 4 synthetic = 34). Update §4 distribution table to enumerate every
   profile actually present.
5. Grep the repo for stale references to moved files
   (`grep -rn "docs/spec-v[1-4]" --include='*.rs' --include='*.md'`) and update them
   to point at docs/history/spec-vN.md or, for requirements still in force, at spec-v5.md.

Acceptance:
- `ls docs/` shows: spec.md, spec-v5.md, spec-v6.md, spec-15m-campaign.md, history/,
  public-release-polish.md, runpod-simulation-guide.md.
- New docs/spec.md is the single entry point.
- Category A count and profile count are internally consistent within
  spec-15m-campaign.md.
- No source file references a missing spec path.
```

---

## Phase 1 — Authority & Binding Hardening (BLOCKERS; ~3 weeks)

These prompts close the safety-critical correctness gaps in the PCA chain (A1–A3) and
introduce the missing execution binding invariants (B1–B4) without which the system
cannot defend against replay or cross-session command injection.

### Prompt 1.1 — Add predecessor-digest binding to PCA chain (closes A3)

```
Goal: prevent cross-chain splice attacks by binding each PCA hop to the cryptographic
digest of its predecessor.

Read first:
- docs/spec-v5.md §P1-01.
- docs/spec.md §2.1–2.6 and §3.2 (after Phase 0 lineage cleanup).
- crates/invariant-core/src/authority/chain.rs (entire file; verify_chain is the
  function under test).
- crates/invariant-core/src/models/authority.rs (PCA struct definition).

Tasks:
1. Add a `predecessor_digest: Option<[u8; 32]>` field to the PCA struct in
   crates/invariant-core/src/models/authority.rs. The root hop holds None; every
   non-root hop holds Some(SHA-256 of the canonical serialization of the previous hop's
   signed payload).
2. Provide a `PCA::digest(&self) -> [u8; 32]` method that hashes the canonicalized
   payload (everything except the signature itself). Use serde_json with sorted keys, or
   add a small `to_canonical_bytes()` helper. Document the canonicalization rule in
   the function-level comment (this is one of the rare cases where a comment is
   warranted — the rule must not drift).
3. In `verify_chain`, after signature verification of hop i, compute hop i's digest and
   require that hop i+1's `predecessor_digest == Some(digest)`. Reject otherwise with a
   structured error (extend the existing error enum; do not stringify).
4. Migrate existing PCA constructors and tests to populate `predecessor_digest`
   correctly. Do NOT add a backwards-compatibility flag — change the type and fix all
   call sites.

Tests (add to crates/invariant-core/src/authority/tests.rs or chain.rs `#[cfg(test)]`):
- `g09_cross_chain_splice_rejected`: build two valid 3-hop chains A→B→C and X→Y→Z;
  attempt to splice (A, B, Z); assert verify_chain returns the new error.
- `predecessor_digest_root_must_be_none`: assert root hop with Some(_) is rejected.
- `predecessor_digest_tamper_detected`: flip one byte in hop 1's payload; assert hop 2
  verification fails.

Acceptance:
- All existing chain tests still pass after migration.
- The 3 new tests above pass.
- `verify_chain` rejects spliced chains with a typed error variant (no panics, no
  stringly-typed errors).
```

### Prompt 1.2 — Implement Binding Invariants B1–B4 (ExecutionContext, session, sequence CAS, temporal, executor)

```
Goal: introduce ExecutionContext and enforce the four binding invariants required by
docs/spec.md §3.3 and docs/spec-v5.md §P1-02. Without these, replay and cross-session
attacks succeed even on a chain that verifies.

Read first:
- docs/spec.md §3.3 ("Binding to execution context").
- docs/spec-v5.md §P1-02.
- crates/invariant-core/src/validator.rs (current orchestration entry point).
- crates/invariant-cli/src/commands/serve.rs:280–295 (the existing non-atomic sequence
  check that B2 must replace).
- crates/invariant-core/src/models/command.rs (Command struct — needs new fields).
- crates/invariant-core/src/models/authority.rs (PCA struct — needs executor field).

Tasks:
1. Create crates/invariant-core/src/authority/binding.rs (NEW). Define:
   - `pub struct ExecutionContext { session_id: SessionId, last_seq:
     std::sync::atomic::AtomicU64, executor: ExecutorId, time_window_sec: u32, clock:
     Box<dyn Clock + Send + Sync> }`.
   - A `Clock` trait with `now() -> i64` and a `SystemClock` impl + `MockClock` impl
     (only the mock under #[cfg(test)]).
   - Four free functions or methods: `check_b1_session(cmd, ctx)`,
     `check_b2_sequence(cmd, ctx)`, `check_b3_temporal(cmd, ctx)`,
     `check_b4_executor(cmd, pca, ctx)`. Each returns
     Result<(), BindingViolation>. BindingViolation is a typed enum with one variant per
     invariant.
   - B2 MUST use compare_exchange (or fetch_update with a strict ordering check), not
     load + store. Reject any seq <= last; on success, atomically advance.
2. Add fields to Command (crates/invariant-core/src/models/command.rs):
     - `session_id: SessionId`
     - `seq: u64`
     - `timestamp: i64` (unix millis)
     - `executor_binding: ExecutorId`
   Migrate all constructors/serializers/tests. No back-compat shims.
3. Add `executor: ExecutorId` to the leaf PCA hop. Serialize/deserialize accordingly.
4. Wire all four checks into `validator.rs` immediately after chain verification and
   before any physics check. Threading: ExecutionContext is per-connection; pass it in
   from the caller (serve.rs constructs one per accepted client).
5. Replace the existing non-atomic sequence handling in
   crates/invariant-cli/src/commands/serve.rs:280–295 with a call to
   `check_b2_sequence`. Remove the now-redundant code path.

Tests:
- 8 dedicated tests in binding.rs: pass + fail per invariant (B1 wrong session, B2
  replay/regress, B3 outside window past + future, B4 wrong executor).
- 1 race test in serve.rs spawning 32 concurrent threads each sending seq=N; assert
  exactly one accept and 31 rejects, no panics.

Acceptance:
- Cannot construct or serialize a Command without all four binding fields.
- Binding violations surface as typed BindingViolation, not strings.
- B2 passes the race test deterministically across 100 runs.
```

### Prompt 1.3 — G-07 wildcard exploitation tests (closes A2 coverage)

```
Goal: prove that operation wildcards (`actuate:*`, `move:arm:*`) cannot be used to
escalate into unrelated operation domains.

Read first:
- crates/invariant-core/src/authority/operations.rs (wildcard matching logic).
- docs/spec-v5.md §P1-03.

Tasks:
1. Add adversarial tests to crates/invariant-core/src/authority/operations.rs
   `#[cfg(test)]`:
   - `actuate_wildcard_does_not_cover_read_sensor`
   - `move_arm_wildcard_does_not_cover_move_base`
   - `bare_star_does_not_cover_anything_outside_root_hop`
2. If any test fails, fix the matcher (do not weaken the test). The matcher must be
   path-segment scoped, not substring scoped.

Acceptance: 3 new tests pass; no other tests regress.
```

---

## Phase 2 — Bug Fixes Already Diagnosed (CRITICAL; ~1 week)

These are well-localized bugs documented in spec-v3 / spec-v5. Each fits in a single
small PR.

### Prompt 2.1 — Fix Isaac bridge OOM via bounded read

```
Goal: stop the Unix-socket bridge from being DoSed by an unbounded message.

Read first: crates/invariant-sim/src/isaac/bridge.rs:196–220 and the surrounding
connection handler. Note the existing `max_msg` variable that is read AFTER the read
completes (too late).

Task: replace the unbounded `buf_reader.read_line(&mut line)` call with a `Read::take`
or manual byte-cap loop that aborts the connection (logs + closes) once `max_msg`
bytes are read without seeing a newline.

Tests: add a unit test in the same file that connects, sends max_msg+1 bytes without a
newline, and asserts the connection is closed and the server is still accepting new
connections.

Acceptance: malicious client cannot exhaust memory; existing well-formed traffic still
works.
```

### Prompt 2.2 — Audit-write failure must not be silent (closes L1 gap)

```
Goal: when the signed audit log cannot be written, the verdict must NOT be returned to
the motor controller as if nothing happened.

Read first:
- crates/invariant-cli/src/commands/serve.rs:425–445 (the swallowed error).
- docs/spec-v5.md §P2-02.
- crates/invariant-core/src/audit.rs (AuditLog API).

Tasks:
1. In serve.rs, on audit append failure: increment a new `audit_errors` Prometheus-
   style counter, log at error level, and return an internal-error response to the
   client. Do not return a (potentially permissive) verdict.
2. Add a new CLI flag `--fail-on-audit-error` (default: true; can be set false only
   for explicit dev/testing). When true, also propagate the failure to abort the
   request handler. When false, behavior reverts to today's logging-only mode but the
   counter still increments.
3. Expose the counter via the existing metrics endpoint (or stub one if absent — read
   serve.rs to see what already exists).

Tests: integration test that injects a failing AuditLog (use an injected trait /
filesystem permissions trick) and asserts:
  - response is internal error,
  - audit_errors counter increments,
  - no PASS verdict is sent to the simulated motor.

Acceptance: no code path returns a PASS verdict when audit append failed.
```

### Prompt 2.3 — Constant-time token comparison & misc serve hardening

```
Read: crates/invariant-cli/src/commands/serve.rs:237–244, 574, and the audit open-mode
in crates/invariant-core/src/audit.rs:405. Reference: docs/history/spec-v3.md §1.4, §2.1,
§2.2; docs/spec-v5.md §P2-06.

Tasks:
1. Make token comparison length-oblivious: pad/compare in fixed-size blocks (use the
   `subtle` crate if not already a dep — check Cargo.toml first; otherwise hand-roll a
   constant-time loop that compares full max-token-length even on length mismatch).
2. Open the audit file with `.append(true)` (POSIX O_APPEND) so concurrent writers
   atomically extend the file.
3. Replace the inconsistent `if let Ok(...)` mutex-poison handling at serve.rs:574
   with the same `unwrap_or_else(|e| e.into_inner())` pattern used elsewhere.

Tests: minimal — comparison test asserting equal latency for mismatched-length and
mismatched-content tokens (use std::time::Instant repeated runs; tolerate noise).

Acceptance: token comparison is length-oblivious; audit log opens O_APPEND; mutex
handling uniform across serve.rs.
```

### Prompt 2.4 — Per-connection bridge watchdog

```
Goal: stop one slow Isaac client from starving others via a shared watchdog.

Read first: crates/invariant-sim/src/isaac/bridge.rs:13–16 (FIXME comment) and the
heartbeat path. Reference: docs/spec-v5.md §P2-03.

Task: replace the shared watchdog state with one watchdog per accepted connection.
Each connection's task holds its own deadline and triggers safe-stop only for itself.
Global safe-stop remains for fatal conditions (process restart, etc.) — be specific
about which is which.

Tests: spawn two simulated clients on the bridge; one stops sending heartbeats; assert
the other continues to receive responses for at least 5× the watchdog window.

Acceptance: concurrent-client starvation eliminated; existing single-client tests pass.
```

### Prompt 2.5 — Dockerfile non-root and CI Python tests

```
Read: Dockerfile (repo root) and .github/workflows/ci.yml. Reference:
docs/history/spec-v3.md §1.6, §4.1.

Tasks:
1. Add a non-root user to Dockerfile (`RUN useradd ...; USER invariant`). Make sure
   the binary and any required directories are owned/readable by that uid.
2. Add a CI job that runs the Isaac bridge Python tests (find them first; spec-v3
   says ~42 exist locally). Use the smallest viable Python version matrix.

Acceptance: container does not run as root; PRs run Python tests.
```

---

## Phase 3 — Audit Replication, Alerts, Key Stores, Proof-Package Integrity (BLOCKERS; ~2 weeks)

These four prompts implement the witness, alerting, and cryptographic-integrity
guarantees that the proof package depends on.

### Prompt 3.1 — S3 replicator + webhook witness (audit replication)

```
Goal: implement off-system audit witnesses behind cargo features so audit-log
tampering on the host cannot go undetected.

Read first:
- crates/invariant-core/src/replication.rs (current Unavailable stubs).
- docs/spec-v5.md §P1-04.

Tasks:
1. Add cargo features `replication-s3` and `replication-webhook` (optional dependencies
   on aws-sdk-s3 and reqwest respectively). Default features: none.
2. Implement S3Replicator: append-only object-per-batch, with replication_state.json
   (last successful sequence, retry-after, backoff state) checkpointed to disk so
   restarts resume.
3. Implement WebhookWitness: HMAC-SHA256 signs each batch with a configured secret;
   POSTs to URL with retries + exponential backoff. Failure modes feed the same
   `audit_errors` counter introduced in Prompt 2.2.
4. Wire both into the AuditLog write path so a single append fans out to local file +
   any enabled replicators. Replicator failures are non-fatal at the request boundary
   but increment audit_errors.

Tests: per-feature unit tests using an in-memory S3 fake (build one) and an httptest
local server. Resume-after-restart test: kill mid-batch, restart, assert no gaps.

Acceptance: features compile cleanly together and individually; restart resumes from
last checkpoint; HMAC verifies on the receiver side.
```

### Prompt 3.2 — Webhook + syslog alert sinks

```
Read: crates/invariant-core/src/incident.rs (current Unavailable stubs);
docs/spec-v5.md §P1-05.

Tasks:
1. Add cargo features `alerts-webhook` and `alerts-syslog`.
2. Implement WebhookAlertSink (POST JSON, retries, backoff).
3. Implement SyslogAlertSink: RFC 5424 framing over UDP and TCP; TCP reconnects on
   failure.
4. Both sinks are pluggable via the existing IncidentSink trait. Document, in the
   trait-level comment, that sinks must be lossy-tolerant (drop with a counter rather
   than block).

Tests: integration tests using a local UDP listener and a local HTTP server. Verify
RFC 5424 fields (PRI, TIMESTAMP, HOSTNAME, APP-NAME, MSGID).

Acceptance: features compile individually and together; both sinks deliver alerts to
test receivers.
```

### Prompt 3.3 — Hardware key stores (OS keyring, TPM, YubiHSM) behind features

```
Read: crates/invariant-core/src/keys.rs:400–550 (Unavailable stubs); docs/spec-v5.md
§P1-06.

Tasks:
1. Add features `keys-keyring`, `keys-tpm`, `keys-yubihsm`.
2. Implement OsKeyringKeyStore using the `keyring` crate (Linux Secret Service / macOS
   Keychain / Windows Credential Manager).
3. Implement TpmKeyStore using `tss-esapi` (Linux only — gate on cfg(target_os =
   "linux") inside the feature).
4. Implement YubiHsmKeyStore using `yubihsm` crate.
5. Each store implements the same KeyStore trait already present; signing operations
   must NEVER export the raw key.

Tests: TPM and YubiHSM tests run only when respective hardware is present (use a
runtime probe; skip otherwise). Keyring test runs on macOS/Linux CI matrices using a
session keyring or mock backend.

Acceptance: each feature compiles independently; private key never crosses the
process/library boundary in any of the implementations.
```

### Prompt 3.4 — Merkle tree audit + signed manifest (proof-package integrity)

```
Goal: replace the unsigned, opaque manifest with a Merkle-tree-backed integrity
record that tampering can be cryptographically detected against.

Read first:
- crates/invariant-core/src/proof_package.rs (current assemble() function and Manifest
  struct).
- docs/spec-15m-campaign.md §6 (proof-package layout).
- docs/spec-v5.md §P1-07.

Tasks:
1. Build a binary Merkle tree (SHA-256) over the audit JSONL entries during proof-
   package assembly. Persist:
     - audit/merkle_root.txt — hex-encoded 32-byte root.
     - audit/sample_entries/ — at least 1000 verified entries with inclusion proofs
       (each as a JSON file containing the entry + proof path).
2. Sign manifest.json with Ed25519 using a key obtained via the KeyStore trait
   (from Prompt 3.3). Embed the signer kid + the signature alongside the manifest.
3. Implement `pub fn verify_package(path: &Path, trusted_keys: &[PublicKey]) ->
   Result<VerifiedPackage, _>` that:
     a) verifies manifest signature with one of the trusted keys,
     b) recomputes file hashes and matches the manifest's table,
     c) walks the audit Merkle tree from the sample entries to the stored root.
4. Add `invariant verify-package <path> --trusted-keys <file>` CLI subcommand wired
   to verify_package.

Tests: round-trip in tests/proof_package_roundtrip.rs:
  - assemble a small package; verify_package returns Ok.
  - flip one byte in a results file; verify_package returns FileTamper(path).
  - flip one byte in a sample audit entry; verify_package returns AuditTamper(idx).
  - swap manifest signature; verify_package returns SignatureInvalid.

Acceptance: tampering at any of {file, audit entry, manifest} is detected; the trip is
< 5 seconds for a 10MB sample package.
```

---

## Phase 4 — Scenario Coverage Expansion (BLOCKER; ~2 weeks)

The 15M-episode campaign cannot run while only 22 of 104 scenario IDs are reachable
from the campaign generator. This phase parameterizes and expands scenarios.

### Prompt 4.1 — Expand ScenarioType to all 104 IDs

```
Read first:
- crates/invariant-sim/src/scenario.rs:51–100 (current 22-variant enum).
- docs/spec-15m-campaign.md §3 (the full A-01 … N-10 detail table, post Phase 0
  reconciliation).
- crates/invariant-sim/src/campaign.rs:800–1000 (how scenarios are dispatched).

Tasks:
1. Refactor ScenarioType from 22 hardcoded variants to a structured representation
   that can express all 104 IDs. Two acceptable shapes:
     A) Enum-of-categories with per-category sub-enums:
        `enum ScenarioType { A(CategoryA), B(CategoryB), ..., N(CategoryN) }`
        with each sub-enum listing its IDs (CategoryA::A01, A02, …).
     B) `struct ScenarioType { category: Category, index: u8 }` with a constants table
        mapping (category, index) → metadata.
   Pick (A) for type safety; this is the convention already used by joint_safety
   (Category B). Justify the choice in the module doc.
2. Provide `from_spec_id("A-01") -> Option<ScenarioType>` and inverse
   `spec_id(&self) -> &'static str`. These are the canonical serialization.
3. Update the campaign dispatcher to compile-error when a ScenarioType is unhandled
   (use a `match` with no `_ =>` branch).

Tests: round-trip every one of the 104 IDs through from_spec_id ↔ spec_id; assert no
duplicates and no holes.

Acceptance: 104 IDs reachable; cargo build fails the day someone adds a 105th variant
without handling it.
```

### Prompt 4.2 — Per-category scenario submodules (A, C–N)

```
Read first:
- crates/invariant-sim/src/scenario/joint_safety.rs (the existing Category B
  template).
- crates/invariant-sim/src/campaign.rs:800–1000 (current dispatch).
- docs/spec-15m-campaign.md §3 (per-category requirements).

Task: create one submodule per category not yet present (A, C, D, E, F, G, H, I, J,
K, L, M, N), mirroring the structure of joint_safety.rs:
  - per-scenario constructor returning a ScenarioConfig,
  - per-scenario expected-verdict assertions used by dry-run,
  - any category-specific helpers (e.g., adversarial-key generator for Category G).

Stub bodies are acceptable in this prompt as long as each submodule:
  - compiles,
  - exposes one function per ID it owns,
  - is exported from scenario/mod.rs.

The next prompt (4.3) fills in step counts; later prompts (4.4, 5.x) fill in concrete
behavior. Mark stubs with `todo!("4.4: step count")` etc., NOT silent no-ops.

Tests: a meta-test that iterates all 104 ScenarioType values and asserts each maps to
a constructor function (use a registry pattern).

Acceptance: every spec ID has a typed home in source.
```

### Prompt 4.3 — Per-scenario step counts and category episode budgets

```
Read first:
- docs/spec-15m-campaign.md §3 (the "Steps" column for every scenario).
- docs/spec-15m-campaign.md §2.1 (per-category episode budget).
- crates/invariant-sim/src/campaign.rs:950–1000 (current default-200-step path).

Tasks:
1. Encode each scenario's step count as a `const STEPS: u32` in its module function
   or as a field on its config. Eliminate the default-200 fallback — every ScenarioType
   must declare its own.
2. Encode the per-category episode budget as a similar table. Sum the budgets and
   `static_assert`-style panic if the total != 15_000_000.
3. Replace the existing distribution logic in `generate_15m_configs` with one that
   reads from these tables.

Tests: assert sum(category_budgets) == 15_000_000 at compile or test time. For each
category, assert sum(per-scenario episodes within that category) == category budget.

Acceptance: dry-run campaign reports exactly 15,000,000 episodes scheduled across the
correct distribution.
```

### Prompt 4.4 — Implement first-class cognitive scenarios I-01..I-10

```
Read first:
- The current Category I dispatch in crates/invariant-sim/src/campaign.rs:800–900
  where I-01..I-10 are aliased to compound scenarios.
- docs/history/spec-v4.md §5.1 (acceptance criteria for cognitive scenarios).

Task: implement each of I-01..I-10 as a distinct attack scenario, NOT an alias. Each
must produce a different command/PCA pattern that targets the cognitive layer
described in the spec (model jailbreaks, instruction smuggling, intent overload, etc.).
Treat each ID as a small standalone module under a new
crates/invariant-sim/src/scenario/cognitive/ directory.

Tests: for each I-NN, one positive (attack rejected with the expected check ID) and
one negative (benign control variant accepted) test.

Acceptance: 20 new tests pass; no I-NN scenario shares a body with another.
```

### Prompt 4.5 — Implement M-01..M-06 (cross-platform stress) and N-01..N-10 (adversarial fuzz)

```
Read: docs/history/spec-v4.md §5.2; the current dispatch in
crates/invariant-sim/src/campaign.rs:1000–1100 that maps M-* and N-* to generic
stress/fuzz code paths.

Task: implement each M-* and N-* scenario as a distinct module with the specific
attack/stress described by spec. M-* must vary the platform under test; N-* must use
the invariant-fuzz crate to generate adversarial inputs targeting one specific
invariant per scenario.

Tests: per-ID smoke test asserting the right ScenarioType is constructed, the correct
fuzz generator is invoked for N-*, and the correct platform under test is selected for
M-*.

Acceptance: all 16 IDs are first-class.
```

### Prompt 4.6 — Multi-robot scenarios A-08, J-08 + `invariant fleet status` CLI

```
Read first:
- crates/invariant-coordinator/src/lib.rs (multi-robot safety).
- docs/spec-v5.md §P2-05.
- crates/invariant-cli/src/main.rs and the commands/ directory pattern.

Tasks:
1. Implement scenario A-08 (all profile pairs separation) and J-08 (multi-robot
   coordination attack) routed through invariant-coordinator. Each must spin up at
   least 10 robots in the dry-run harness.
2. Add `invariant fleet status` CLI subcommand at
   crates/invariant-cli/src/commands/fleet.rs (NEW) that queries the coordinator state
   and prints separation/partitioning summaries as JSON.
3. Add an integration test under crates/invariant-coordinator/tests/ that runs a
   10-robot mixed scenario (mix of arms, mobile bases) for 1000 ticks and asserts no
   separation violations and no partition oscillations.

Acceptance: both scenarios appear in 15M campaign output; CLI returns valid JSON;
10-robot integration test passes deterministically.
```

---

## Phase 5 — Profile & Sensor Completeness (IMPORTANT; ~1 week)

### Prompt 5.1 — Add environment + end_effectors blocks to incomplete profiles

```
Read first:
- profiles/*.json (the 34 profile files).
- docs/history/spec-v3.md §2.3, §2.4 for the lists of incomplete profiles.
- crates/invariant-core/src/physics/environment.rs (P21–P25 — what's expected in
  `environment`).
- crates/invariant-core/src/physics/end_effectors.rs (or wherever P11–P14 lives).

Tasks:
1. For each of the 13 profiles missing `environment`, add a realistic block (use
   manufacturer datasheets where available; otherwise use the values from a similar
   profile and add a `"source": "derived_from_<other>"` field for traceability).
2. For each of the 15 profiles missing `end_effectors`, add a realistic block.
   Note: `quadruped_12dof` legitimately has no end effectors — leave it alone but add
   `"end_effectors": []` so the strict validator (Prompt 5.2) does not flag it.

Acceptance: every non-stub profile has both blocks; no profile silently disables P11–
P14 or P21–P25.
```

### Prompt 5.2 — `validate-profiles --strict` CLI + CI gate

```
Read: existing CLI command pattern under crates/invariant-cli/src/commands/. Reference:
docs/spec-v5.md §P2-04.

Tasks:
1. Create crates/invariant-cli/src/commands/validate_profiles.rs implementing
   `invariant validate-profiles [--strict] [<dir>]`:
     - Loads every JSON profile in the given directory (default: profiles/).
     - --strict: requires `environment` and `end_effectors` blocks (empty arrays
       allowed only if explicitly present and the profile is annotated as having no
       end effectors via a top-level `"no_end_effectors": true` field).
     - Returns nonzero exit on any failure.
2. Wire into .github/workflows/ci.yml as a required step on every PR.

Tests: unit tests with a fixture profile dir containing one good and one bad profile;
assert exit codes.

Acceptance: incomplete profiles fail CI before merge.
```

### Prompt 5.3 — Split SR1/SR2 check IDs

```
Read: crates/invariant-core/src/physics/environment.rs:361–427 (current single
check_sensor_range). Reference: docs/spec-v5.md §P2-01.

Task: split the check into two functions producing two distinct CheckResult IDs:
  - SR1: environment-state sensors (temperature, force, etc.).
  - SR2: payload/grasp sensors.
Both must be invoked from the validator with separate result entries in the verdict.
Update verdict serialization, dashboards, and any test that asserts a single SR result.

Tests: a profile that violates only SR1 must show SR1 in the rejection and not SR2,
and vice versa.

Acceptance: campaign accounting separates SR1 from SR2.
```

### Prompt 5.4 — Standardize check-ID constants (L1–L4, M1, W1, SR1, SR2)

```
Read: crates/invariant-core/src/models/verdict.rs; docs/spec-v5.md §P2-07.

Task: introduce a `pub mod check_ids` exposing string constants for every L/M/W/SR/B
check id. Replace all string literals at verdict construction sites with these
constants. Add a serde-tagged `check_id` field to verdict entries so downstream
analysis can group programmatically.

Tests: a parameterized test that walks all known check IDs and asserts each appears in
at least one rejection-path test fixture.

Acceptance: grep for hardcoded "L1"/"M1" etc. at verdict construction sites returns
nothing in src/.
```

---

## Phase 6 — Isaac Lab Task Environments + Campaign Assembly (BLOCKER; ~2 weeks)

### Prompt 6.1 — Isaac Lab task environments for all robot families

```
Read first:
- isaac/envs/cnc_tending.py (the existing template).
- crates/invariant-sim/src/isaac/bridge.rs (the wire protocol: Unix socket + JSONL).
- docs/runpod-simulation-guide.md (deployment context).
- docs/spec-v5.md §P1-10.

Task: create one Isaac Lab environment per robot family, mirroring cnc_tending.py:
  - isaac/envs/arm.py — Franka, UR10e, Kinova Gen3 etc.
  - isaac/envs/humanoid.py — humanoid_28dof and friends.
  - isaac/envs/quadruped.py — quadruped_12dof.
  - isaac/envs/hand.py — Allegro, Shadow, LEAP, Psyonic.
  - isaac/envs/mobile_base.py — mobile manipulators.

Each env must:
  - Connect to the bridge socket using the same protocol as cnc_tending.py.
  - Emit observations, accept actions, support reset(seed) and step(action).
  - Provide a make_env(profile_name) factory consumed by the campaign runner.

Tests: each env has a smoke test that runs a 10-step random rollout and asserts the
bridge round-trips without error. Skip these tests by default in CI; gate behind an
env var ISAAC_PRESENT=1.

Acceptance: all 5 envs present and importable; smoke tests pass on a host with Isaac
Lab installed.
```

### Prompt 6.2 — `invariant campaign assemble` and `invariant campaign replay` CLI

```
Read first:
- crates/invariant-cli/src/commands/campaign.rs (current command surface).
- crates/invariant-core/src/proof_package.rs (assemble API).
- docs/spec-v5.md §P1-08; docs/history/spec-v4.md §3.2.

Tasks:
1. Add `invariant campaign assemble --shards <DIR> --output <PATH> --key <PATH>`
   wiring to proof_package::assemble and the manifest signing introduced in Prompt
   3.4.
2. Add `invariant campaign replay --seed <u64> [--scenario <ID>]` that re-runs the
   given seed and asserts the resulting verdicts match those in the recorded results
   directory. This is the determinism check.

Tests: end-to-end test that runs assemble on a small fixture shard set, then runs
replay against a known seed and asserts byte-identical verdict output.

Acceptance: both subcommands work end-to-end against a small fixture; replay catches
non-determinism (test by deliberately making one scenario non-deterministic and
asserting replay fails).
```

### Prompt 6.3 — Latency distribution capture + p99 < 1ms gate

```
Read: crates/invariant-sim/src/collector.rs and the campaign harness. Reference:
docs/history/spec-v4.md §3.3.

Tasks:
1. Use HDR histogram (the `hdrhistogram` crate) to capture per-step validation latency
   across the entire campaign.
2. Persist as latency_distribution.json (p50/p95/p99/p99.9/max + raw histogram bins
   for reproducibility) inside the proof package under integrity/.
3. Add a campaign success gate: if p99 ≥ 1ms, fail the campaign and surface the
   offending percentile in the verdict.

Tests: synthetic latency injection test asserting both pass and fail paths.

Acceptance: 15M campaign cannot succeed without p99 < 1ms.
```

### Prompt 6.4 — RunPod orchestrator: `invariant campaign submit --shards`

```
Read: crates/invariant-sim/src/orchestrator.rs (currently empty); docs/runpod-
simulation-guide.md; docs/history/spec-v4.md §6.1.

Task: implement `invariant campaign submit --shards <DIR> --backend runpod` that
serializes shard configs and submits batch jobs. For this prompt, build only the
backend-trait abstraction + a `LocalBackend` impl that runs shards in subprocesses,
plus a `RunPodBackend` stub that returns Unimplemented (gated behind a feature
`backend-runpod`). Document the exact API a real RunPod adapter would need.

Tests: LocalBackend integration test that submits 4 small shards and aggregates the
results.

Acceptance: orchestrator skeleton compiled, LocalBackend works; RunPodBackend wired
behind feature with clear stub.
```

---

## Phase 7 — Per-Category Success Criteria (IMPORTANT; ~1 week)

### Prompt 7.1 — Generalize success-criteria assertions from Category B to A–N

```
Read: crates/invariant-sim/src/campaign.rs:1400–1500 (Category B criteria); docs/spec-
15m-campaign.md §5; docs/spec-v5.md §P2-08.

Task: extract Category B's assertion pattern into a `CategoryCriteria` trait with
methods:
  - required_invariants(&self) -> &[CheckId]
  - max_failure_rate(&self) -> f64
  - assert_results(&self, results: &CampaignResults) -> Result<(), CriteriaFailure>

Implement this trait for Categories A, C, D, E, F, G, H, I, J, K, L, M, N using the
spec table. The dry-run campaign invokes assert_results for every category and a
single failed criterion fails the campaign.

Tests: per-category test using a synthetic CampaignResults fixture that exercises
both pass and fail paths.

Acceptance: every category has machine-checkable success criteria.
```

---

## Phase 8 — Polish and Documentation (MINOR; ongoing)

These are small, mostly independent prompts. Order by team capacity, not dependency.

### Prompt 8.1 — Auto-generated test count

```
Stop hardcoding test counts in README.md, CHANGELOG.md, and any spec doc. Add a CI
step that runs `cargo test -- --list 2>/dev/null | grep -c ': test$'` (or the
equivalent), writes to docs/test-count.txt, and a docs/README.md template substitution
or a README badge that reads from that file. Reference: docs/spec-v5.md §P3-02.

Acceptance: changing test count never requires editing prose docs.
```

### Prompt 8.2 — Honesty audit of formal/

```
Read every .lean file under formal/. For each top-level theorem, classify as:
  - PROVED (no `sorry`, no `axiom` in dependencies),
  - SORRY (depends on a `sorry`),
  - AXIOM (depends on a non-trivial axiom).
Produce formal/STATUS.md with the table. Update docs/spec.md (the new index from
Phase 0) so it points to formal/STATUS.md instead of claiming end-to-end proof.
Reference: docs/spec-v5.md §P3-03.
```

### Prompt 8.3 — SBOM, signed binaries, repro script

```
Reference: docs/spec-v5.md §P3-06, §P3-07; docs/history/spec-v3.md §4.2, §4.3.

Tasks:
1. Add `cargo-cyclonedx` (or equivalent) to the release workflow; attach SBOM to
   GitHub release.
2. Build x86_64-linux, aarch64-linux, x86_64-darwin, aarch64-darwin binaries on
   release; sign with cosign keyless (OIDC) and attach signatures.
3. Add scripts/repro.sh that builds with locked deps and asserts `sha256sum` of the
   binary matches the released artifact.

Acceptance: release artifact set includes binaries + signatures + SBOM; repro script
passes on a clean machine.
```

### Prompt 8.4 — Compliance mappings, deployment-modes, shadow runbook, CLI reference

```
Reference: docs/spec-v5.md §P3-08, §P3-09, §P4-01, §P4-02.

Create the following docs (no code):
- docs/compliance/iec-61508.md
- docs/compliance/iso-10218.md
- docs/compliance/iso-ts-15066.md
- docs/compliance/nist-ai-600-1.md
- docs/deployment-modes.md (Forge / Shadow / Guardian comparison + key-management
  options)
- docs/shadow-deployment.md (prerequisites, setup, metrics, triage, sign-off)
- docs/cli-reference.md (auto-generated from clap if possible — try `clap_mangen` or
  `clap-markdown`; otherwise hand-write per subcommand)

Each compliance doc maps the proof package's contents to the standard's clauses.
Acceptance: every doc exists and is linked from the new docs/spec.md index.
```

### Prompt 8.5 — Allocation reduction on the validator hot path

```
Reference: docs/spec-v5.md §P3-04. Read crates/invariant-core/src/validator.rs and
profile a single `validate_command` call; the analysis identified ~26 clones.

Tasks:
1. Convert profile string fields to `Arc<str>` where the same string is shared across
   commands.
2. Pass references rather than owned values into check functions where lifetimes
   permit.
3. Switch SHA-256 of canonical command bytes to a streaming Hasher (no intermediate
   Vec<u8>).

Tests: existing test suite must pass; add a criterion benchmark
benches/validate_command.rs showing measured improvement.

Acceptance: bench delta documented in PR; no allocations regression elsewhere.
```

### Prompt 8.6 — Audit `read_last_line` batching

```
Reference: docs/spec-v5.md §P3-05. Read crates/invariant-core/src/audit.rs:470–530.

Task: replace the byte-by-byte backward scan with a single 128KiB tail read followed
by an in-memory split. Handle the multi-block-tail case correctly (lines longer than
128KiB should still work — fall back to a larger read).

Tests: existing audit tests + a new test with a single line of 200KiB and a file with
many small lines.

Acceptance: syscall count for tailing the audit log reduced from O(line_length) to
O(1) on typical entries.
```

### Prompt 8.7 — invariant-ros2 disposition

```
Reference: docs/spec-v5.md §P2-09.

Decision: pick one.
  A) Move invariant-ros2/ to examples/invariant-ros2/ and remove any reference that
     implies it is a workspace member.
  B) Add it to the workspace `members = [...]` and write at least one smoke test that
     compiles against rclrs.

If unsure, choose (A); ROS 2 integration is properly an example, not a core crate, and
adds toolchain pain to CI.

Acceptance: the directory is unambiguously categorized; the workspace builds without
warnings.
```

---

## Closing Notes

- After each phase, run a full `cargo test --workspace --all-features` and update
  CHANGELOG.md with one line per merged prompt.
- Phase 1 and Phase 3 prompts gate the safety claims of the proof package — do not
  defer them to ship a "proof package" that lacks these guarantees.
- If a prompt's premise turns out wrong (e.g., the bug was already fixed in another
  PR), still produce the PR with an empty diff and a note explaining what evidence
  closed the gap; this keeps the audit trail honest.
- When in doubt about a contradiction between an older spec and spec-v5, defer to
  spec-v5. When in doubt about a contradiction between spec-v5 and the campaign
  contract (spec-15m-campaign.md), the campaign contract wins for anything campaign-
  scoped.
