> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Spec v9 — Deep Gap Remediation (Implementation Prompts)

**Date:** 2026-05-01
**Baseline:** 691 passing tests; `cargo clippy --workspace -- -D warnings` clean.
**Branch base:** `main` (or wherever v8 lands).
**Predecessors:** `spec-v8-deep-gap-remediation.md` (covers GAP-1..GAP-30; do not re-execute those steps), `spec-v7-deep-gap-remediation.md`, `spec-v6-gap-remediation.md`, `spec-v5-gap-closure.md`.

This spec captures gaps identified by a **deep re-analysis** of every `crates/*/src/*.rs` file against `docs/spec.md`, `docs/step3-bio-invariants.md`, `docs/threat-model.md`, and the previous remediation specs. It only contains gaps that v8 does **not** address, plus three corrections to v8 prompts whose preconditions about the existing code do not hold.

## How to use this spec

Each section is a self-contained prompt for a fresh Claude Code session. The session has access to the repo and `CLAUDE.md`; it has no other context. Run them roughly in the order given. After each prompt:

1. `cargo build --workspace`
2. `cargo test --workspace`
3. `cargo clippy --workspace -- -D warnings`
4. One commit per prompt; commit message must reference the V9-id (e.g. `V9-1: verify profile signatures at load`).

If a prompt's preconditions don't hold (e.g. a referenced file or type has been renamed since this spec was written), stop and surface it before continuing. Do not "infer" — read the code.

---

## Severity legend

- **Critical** — security-relevant; default behavior is fail-open or accepts unauthenticated input.
- **High** — security-adjacent or false-confidence; spec claims the behavior is implemented and code does not deliver it.
- **Medium** — correctness, observability, or developer-facing surface drift.
- **Low** — polish, naming, doc-vs-code wording.

---

## Chunk A — Critical security: profile-signature verification (V9-1, V9-2)

### Prompt A.1 — V9-1 (Critical): Verify `profile_signature` on load

> **Context.** `BioProfile` (in `crates/invariant-biosynthesis-core/src/models/profile.rs`) carries `profile_signature: Option<String>` and `profile_signer_kid: Option<String>`. These fields are populated by hand-edited JSON, **never verified anywhere in the workspace.** The CLI's `inspect` subcommand even prints the signature with the literal string `"signed (unverified) by kid=..."` (`crates/invariant-biosynthesis-cli/src/commands/inspect.rs:200`). Grep confirms: every test, every CLI path, every validator path passes `profile_signature: None`, and there is no `verify_profile` function. A tampered profile loaded from disk will pass through to validation as-is, which silently breaks the entire authority model: an attacker who can write a profile JSON can lower BSL, expand `allowed_substrates`, set `allow_stale_screening: true`, etc.
>
> **Task.**
> 1. Add `pub fn verify_signature(&self, trusted_keys: &HashMap<String, VerifyingKey>) -> Result<ProfileSignatureStatus, ProfileSignatureError>` to `BioProfile`. Define:
>    ```rust
>    pub enum ProfileSignatureStatus {
>        VerifiedSignedBy { kid: String },
>        Unsigned,
>    }
>    pub enum ProfileSignatureError {
>        SignatureWithoutKid,
>        KidWithoutSignature,
>        UnknownSigner { kid: String },
>        SignatureInvalid { kid: String },
>        Decode(String),
>    }
>    ```
>    The signature covers the canonical-JSON serialization of the profile **with `profile_signature` and `profile_signer_kid` set to `null`**. Use `serde_json::to_vec` over a clone with those two fields cleared (do not invent a new canonicalization — match the pattern already used by the audit module; read `crates/invariant-biosynthesis-core/src/audit.rs` for the canonical-JSON convention before coding).
> 2. Add a builder method `pub fn sign(&mut self, signing_key: &SigningKey, kid: &str)` for offline signing of profiles (used by tests and by a future `invariant-bio profile sign` command — do not add the CLI command in this prompt; just the library API).
> 3. In `ValidatorConfig::new`, take a new optional argument `trusted_profile_signers: Option<&HashMap<String, VerifyingKey>>` (or thread an existing `trusted_keys` map; pick the cleaner shape after reading the existing constructor). On `new`:
>    - If `profile.profile_signature.is_some()` and trusted-signers map is present: call `verify_signature` and return `ValidatorError::ProfileSignatureInvalid { kid, reason }` on any failure.
>    - If profile is unsigned and `profile.bsl_level >= 3`: return `ValidatorError::ProfileMustBeSignedAtBsl3 { bsl: u8 }`. Add an opt-out `accept_unsigned_profile_for_dev: bool` field on the profile (default `false`, with a doc comment that flipping it for production is a sackable offense).
>    - Otherwise log a one-line stderr advisory `"note: profile <name> is unsigned (BSL-{n})"`.
> 4. Update `inspect.rs` to print `"signature: VERIFIED by kid=..."` / `"INVALID"` / `"unsigned"` based on the new function (it needs to take a `--trusted-key` file the same way `validate` does).
> 5. Tests:
>    - Round-trip: sign a fixture profile, mutate one byte, verify fails with `SignatureInvalid`.
>    - Unknown signer kid → `UnknownSigner`.
>    - Missing signature with kid present (or vice versa) → matched error variant.
>    - BSL-3 unsigned profile in `ValidatorConfig::new` → error.
>    - BSL-3 unsigned profile with `accept_unsigned_profile_for_dev: true` → succeeds with stderr advisory (capture stderr in test).
>    - Unsigned BSL-2 profile → succeeds with stderr advisory.
> 6. Update `docs/AUDIT-READINESS.md` (which v8 chunk 7.1 introduces) with a new row in the cryptographic-primitives table for "Profile signing: Ed25519 over canonical-JSON-with-signature-fields-nulled."
> 7. Update `docs/threat-model.md`: add a "Profile tampering" section noting that prior to V9-1 a writable-disk attacker could escalate trust by editing profile JSON; v9 closes this for BSL≥3 and warns at lower BSL.
>
> **Acceptance.** All six built-in profiles in `profiles/*.json` are still loadable (they remain unsigned and BSL≤4 — adjust the BSL-3/BSL-4 built-ins to set `accept_unsigned_profile_for_dev: true` with a doc comment that this is for the dev/example profiles only, OR sign them with a checked-in dev key whose pubkey is embedded in the binary the same way the profile JSONs are; pick whichever matches the existing key-distribution story in `keys.rs` and `profiles.rs`). Tests pass; clippy clean.

### Prompt A.2 — V9-2 (Critical): CLI `--trusted-key` and remove the empty default `trusted_keys`

> **Context.** `crates/invariant-biosynthesis-cli/src/commands/validate.rs:137` constructs `ValidatorConfig::new` with `HashMap::<String, VerifyingKey>::new()`. The map is empty. Any bundle whose authority chain contains *any* hop will fail authority verification because no root keys are trusted. The existing tests pass only because the `safe-bundle.json` fixture has an empty chain or the verdict is allowed to come back rejected. This is not a fail-closed property — it's a fail-incoherent property: validation runs, screens, calls invariants, then the chain check rejects, and the user sees an exit code 1 with a misleading reason. There is no CLI surface to provide trusted keys at all.
>
> **Task.**
> 1. Add `#[arg(long = "trusted-key", value_name = "PATH")] pub trusted_key: Vec<PathBuf>` to `ValidateArgs`. Each path is a key file in the same format `keygen` and `--hazard-db-issuer-pub` already use. Reuse `crate::key_file::load_key_file` + `load_verifying_key`.
> 2. Build `let trusted_keys: HashMap<String, VerifyingKey> = ...` from those paths and thread it into `ValidatorConfig::new`. Do not silently merge with the hazard-db issuer key — those serve different roles. (If the user wants the hazard-db issuer to also be a chain-root key, they pass it twice. Document this in the flag's help text.)
> 3. If `--trusted-key` is empty AND the bundle has a non-empty authority chain: emit a clear stderr error and exit 3 before validation runs: `error: bundle has authority chain but no --trusted-key was provided; refusing to run with empty trust set`.
> 4. If the bundle has an empty authority chain and the profile's BSL ≥ 3: refuse with exit 3. (Library-side this should already be enforced by the chain check at BSL≥3 — confirm before adding a duplicate guard. If the library does not enforce it, that is a separate gap and you should fix it in the validator and add the test there, not in the CLI.)
> 5. Tests in `crates/invariant-biosynthesis-cli/tests/`:
>    - Bundle with chain + matching `--trusted-key` → validation runs and reaches the verdict step.
>    - Bundle with chain + no `--trusted-key` → exit 3 with error pointing at the missing flag.
>    - BSL-3 profile + empty chain → exit 3.
> 6. Update README.md usage section.
>
> **Acceptance.** Existing CLI tests adjust to pass `--trusted-key` where they exercise non-trivial chains. Clippy clean.

---

## Chunk B — High: unwired safety mechanisms (V9-3, V9-4)

### Prompt B.1 — V9-3 (High): Wire `DbStale` fail-closed at the invariant layer

> **Context.** `crates/invariant-biosynthesis-core/src/invariants/mod.rs:338` defines `HazardDatabase::is_stale(&self) -> bool` as a default trait method. `crates/invariant-biosynthesis-core/src/validator.rs:497-515` correctly handles `InvariantStatus::DbStale` (fail-closed unless `allow_stale_screening` and inside `stale_screening_max_days`). Connection between the two is missing: **grep `crates/invariant-biosynthesis-core/src/invariants/{dna,peptide,chemical,protocol}.rs` for `DbStale` returns zero hits.** No invariant ever emits `DbStale`. A 6-month-old hazard DB sails through screening today.
>
> **Task.**
> 1. In each of D1–D6 (the screening-backed DNA invariants in `dna.rs`), P1–P3 (peptide screening invariants), C1–C3 (chemical screening invariants) — wherever the invariant calls `hazard_db.screen_payload(...)` (or the `Screening` trait equivalent — read the existing call sites first; do not invent), add a pre-check: `if db.is_stale() { return InvariantStatus::DbStale { reason: format!("hazard DB age {age:?} exceeds freshness window {window:?} for {invariant_id}") }; }`. The validator's `DbStale` handler will then apply the policy.
> 2. The exact list of "screening-backed invariants" depends on which existing invariants today take the screening DB as a dependency. Find them by grepping for `&dyn HazardScreener`, `Arc<dyn HazardScreener>`, and `screen_payload` in `crates/invariant-biosynthesis-core/src/invariants/`. For each one, add the staleness pre-check as the first body line.
> 3. Add a unit test per family (`dna_d1_db_stale_emits_dbstale`, `peptide_p1_db_stale_emits_dbstale`, `chemical_c1_db_stale_emits_dbstale`) using a stub `HazardScreener` whose `freshness()` returns more than `freshness_window()`.
> 4. Add an end-to-end validator test: BSL-2 profile with `allow_stale_screening = false`, stale DB, hazard hits → final verdict Fail with check details containing `db-stale (fail-closed)`. BSL-2 profile with `allow_stale_screening = true` and DB inside `stale_screening_max_days` → verdict carries Advisory check, approved.
> 5. Update `docs/AUDIT-READINESS.md` known-limitations to remove the (currently absent) "stale DB silently accepted" caveat once this lands.
>
> **Acceptance.** Tests pass; clippy clean. The validator's existing `DbStale` handling code is now reachable.

### Prompt B.2 — V9-4 (High): Implement watchdog timing + heartbeat verification

> **Context.** `crates/invariant-biosynthesis-core/src/watchdog.rs` is a 50-line file containing only the `Heartbeat` struct, a `SafeStopAction` enum, and a single serialization test. Lines 7–9 of its module doc admit: *"The full timing logic is ported in Step 3; Step 0 only defines the type shape so downstream crates can link."* Step 3 never happened. `docs/spec.md` lists the watchdog as a fail-stop mechanism — emit signed heartbeats, the platform halts synthesis if the signed heartbeat does not arrive within `timeout_ms`. None of that exists. The `Heartbeat` struct has fields for `signature` and `signer_kid` and **nothing in the workspace ever signs or verifies a heartbeat.**
>
> **Task.**
> 1. Add canonical-JSON signing/verification for `Heartbeat`. Reuse the convention used elsewhere (likely `serde_json::to_vec` over the struct with `signature` cleared). Functions: `Heartbeat::sign(unsigned: HeartbeatBody, key: &SigningKey, kid: &str) -> Heartbeat` and `Heartbeat::verify(&self, trusted: &HashMap<String, VerifyingKey>) -> Result<(), HeartbeatVerifyError>`. Define the error enum.
> 2. Add `WatchdogMonitor`:
>    ```rust
>    pub struct WatchdogMonitor {
>        last_seen: Option<DateTime<Utc>>,
>        last_sequence: Option<u64>,
>        timeout: Duration,
>        on_timeout: SafeStopAction,
>    }
>    impl WatchdogMonitor {
>        pub fn new(timeout: Duration, on_timeout: SafeStopAction) -> Self;
>        pub fn record(&mut self, hb: &Heartbeat, trusted: &HashMap<String, VerifyingKey>) -> Result<(), HeartbeatVerifyError>;
>        pub fn check(&self, now: DateTime<Utc>) -> WatchdogStatus;
>    }
>    pub enum WatchdogStatus { Ok, Stale { since: Duration, action: SafeStopAction } }
>    ```
>    `record` rejects out-of-order sequence numbers and replayed heartbeats (last_sequence must strictly increase).
> 3. Add a CLI subcommand `invariant-bio watchdog` with two modes:
>    - `invariant-bio watchdog emit --interval 5s --timeout 30s --signing-key <path> --on-timeout halt-synthesis` — long-running; emits signed heartbeats to stdout (newline-delimited JSON).
>    - `invariant-bio watchdog monitor --trusted-key <path> --timeout 30s` — long-running; reads heartbeats from stdin, calls `record`, prints `WatchdogStatus` on each tick or on timeout. Exit non-zero on timeout. Both modes must accept `--once` for testability.
> 4. Tests:
>    - Sign + verify round-trip; tampered heartbeat fails `verify`.
>    - `record` rejects replayed sequence number.
>    - `record` rejects sequence going backward.
>    - `check` returns `Stale` when `now - last_seen > timeout`.
>    - CLI emit + monitor connected via a pipe in a single integration test (use `tokio::process` or `std::process` with stdin piping; `--once` for both ends so the test terminates).
> 5. Update the module-level doc comment in `watchdog.rs` to drop the "Step 3 not yet ported" note.
> 6. Add a row in `docs/AUDIT-READINESS.md` (from v8 chunk 7.1) for "Heartbeat: Ed25519 over canonical-JSON; replay-protected by strictly-increasing sequence; verifier is single-instance."
>
> **Acceptance.** New tests pass; existing tests still pass; clippy clean. The watchdog is now functional, not a placeholder. Distributed-watchdog quorum is explicitly out of scope for v9 — open a follow-up gap V9-OPEN-1 in `docs/acceptance-gates.json` if you have authored that file (it lands in v8 chunk 4).

---

## Chunk C — High: corrections to v8 prompts (V9-5, V9-6, V9-7)

These three prompts are not new gaps; they patch v8 prompts whose preconditions about the existing code are wrong. **Apply these instead of (or after) the corresponding v8 prompts**, depending on whether v8 has been executed yet.

### Prompt C.1 — V9-5 (High): Correct v8-2.4 (`QuorumPolicy` variant shape)

> **Context.** Spec v8 prompt 2.4 instructs Claude to make the quorum parser produce `QuorumPolicy::AtLeast { n, of: M }`. **The current code defines `QuorumPolicy::AtLeast(usize)` as a tuple variant**, not a struct variant. The current parser accepts `"k:N"` (single number, no second field) — see `crates/invariant-biosynthesis-cli/src/commands/validate.rs:255` and `crates/invariant-biosynthesis-core/src/screening/mod.rs:290-298`. Additionally, the v8 prompt mentions `"majority"` as already-parsed; it is not.
>
> **Task.** Pick one of the two corrected designs and implement consistently:
>
> **Design 1 (preferred — minimal change).** Keep `QuorumPolicy::AtLeast(usize)` as today. Extend the parser at `validate.rs::parse_quorum` to accept:
> - `"any"` → `QuorumPolicy::Any`
> - `"all"` → `QuorumPolicy::All`
> - `"majority"` → compute `(n_sources / 2) + 1` at consensus-screener construction time. This requires a new variant `QuorumPolicy::Majority` since the parser does not know the source count yet, OR resolve it in `ConsensusHazardScreener::new`. Simplest: add `QuorumPolicy::Majority` and resolve in `ConsensusHazardScreener::screen_payload` (one line: `Majority => (n / 2) + 1`).
> - `"k:N"` (existing syntax — keep working for backward compat) → `QuorumPolicy::AtLeast(N)`.
> - `"n:M"` (new syntax aligned with v8) → reject unless `1 <= n <= M`; map to `QuorumPolicy::AtLeast(n)` AND validate at screener construction that `M == source_count`. Exact behavior: parser returns `(n, Some(M))`; `validate.rs` checks `M == args.hazard_db.len()`; mismatch returns a clap-friendly error before the validator runs.
>
> **Design 2 (matches v8's stated end-state).** Refactor `QuorumPolicy::AtLeast(usize)` to `QuorumPolicy::AtLeast { n: usize, of: Option<usize> }` (Option because callers may not know the source count up front). Update every existing match arm in `screening/mod.rs` and tests. Add `Majority`. This is a bigger refactor and breaks library users — only pick this if you are already executing v8 and want strict alignment.
>
> Whichever design you pick, write `docs/quorum-policy-decision.md` recording the choice and *why*. Commit message: `V9-5: correct v8-2.4 quorum parser; design <1|2>; see docs/quorum-policy-decision.md`.
>
> Tests: parse `"any"`, `"all"`, `"majority"`, `"k:N"`, `"2:3"`, plus malformed `":"`, `""`, `"3:2"` (n > M), `"0:3"`, `"2:3"` against a 2-source screener (mismatch error).
>
> **Acceptance.** Tests pass; existing screener tests still pass; clippy clean.

### Prompt C.2 — V9-6 (Medium): Correct v8-3.1 (`IncidentResponder` constructor shape)

> **Context.** v8 prompt 3.1 says to add `incident_responder: Option<Arc<Mutex<IncidentResponder>>>` to `ValidatorConfig`. **Verify this assumption first** — read `crates/invariant-biosynthesis-core/src/incident.rs` and confirm whether `IncidentResponder` is `Send + Sync`, and whether the existing `AlertSink` trait already serializes access internally. If sinks already lock internally, an `Arc<Mutex<IncidentResponder>>` is double-locking and breaks the existing API style of the validator (which uses `Arc<Mutex<...>>` for `ThreatScorer` only because the scorer is mutable; check if responder is mutable per call or owned-immutable).
>
> **Task.** Read `incident.rs` end-to-end. If `IncidentResponder::dispatch` (or whatever the dispatch entrypoint is) takes `&self`, store it as `Arc<dyn IncidentSink>` or `Arc<IncidentResponder>` without the `Mutex`. If it takes `&mut self`, keep `Arc<Mutex<>>`. Then proceed with v8-3.1's wiring. Document the choice in a comment on the new field.
>
> **Acceptance.** Wired correctly per the actual API. Tests as in v8-3.1.

### Prompt C.3 — V9-7 (Medium): Correct v8-6.2 about `models/execution_token.rs`

> **Context.** v8 prompt 6.2 says "`crates/invariant-biosynthesis-core/src/models/execution_token.rs` may already exist — read it before adding anything." This file **does** exist (`find` confirms). Before authoring `issue-token` / `verify-readback`, read it fully and check what's already implemented. The v8 prompt's design (COSE_Sign1 over CBOR with `{bundle_hash, profile_id, synthesizer, window_start, window_end, nonce, issuer_kid}`) may not match the existing struct, in which case the prompt's task is *migration* not *creation*. Surface the mismatch to the user before implementing if the existing fields differ materially.
>
> **Task.**
> 1. Read `models/execution_token.rs` and write a 200-word summary in your reply describing: existing fields, existing builders, existing tests, and any signing/verification helpers.
> 2. If the existing shape matches the v8 design within trivial naming differences: proceed with v8-6.2.
> 3. If it does not match: stop and write `docs/execution-token-design-reconciliation.md` listing the deltas (rename/add/remove per field) and propose either (A) extending the existing struct or (B) deprecating it for a new one. Wait for user approval.
>
> **Acceptance.** Either v8-6.2 proceeds with confirmation that the existing struct fits, or a reconciliation doc exists.

---

## Chunk D — Medium: verdict-truthfulness and observability (V9-8, V9-9, V9-10, V9-11)

### Prompt D.1 — V9-8: Surface advisory severity in `CheckResult`

> **Context.** `crates/invariant-biosynthesis-core/src/validator.rs:516` maps `InvariantStatus::Advisory { note }` to `CheckResult { passed: true, details: format!("advisory: {note}") }`. Downstream consumers parsing the verdict JSON (operators piping to `jq '.verdict.checks[] | select(.passed == false)'`) will miss every advisory. The CLI exit code logic gets it right (it inspects `r.status` directly), but the verdict-on-the-wire is misleading: a profile with a real C-family Advisory hit looks identical to a profile with all clean Pass checks.
>
> **Task.**
> 1. Add `pub severity: CheckSeverity` to `CheckResult`. Define `pub enum CheckSeverity { Pass, Advisory, Fail, DbStale, Unimplemented }` with `#[serde(rename_all = "snake_case")]`.
> 2. In the validator's status-to-check mapping (around line 491–524): set `severity` per status; `passed` remains a derived bool, but explicitly set it to `true` only for `Pass` and (`Advisory` if and only if `Advisory` is currently approval-eligible — preserve existing behavior). The exit-code matrix in `validate.rs` does not need to change (it already reads `InvariantStatus`).
> 3. Add a serde-compat test: a verdict JSON serialized before this change (paste a fixture under `crates/invariant-biosynthesis-core/tests/fixtures/verdict_pre_v9.json` if missing) round-trips. Decide whether `severity` defaults to `Pass` for backward-compat deserialize; document the choice in `docs/rfcs/0001-check-severity.md` (or just inline doc-comment if the RFC infra from v8-7.4 is not yet in place).
> 4. Update `inspect.rs` verdict-printing to use the severity field instead of inferring from `passed`.
>
> **Acceptance.** Existing tests adjust; new severity-field test asserts Advisory shows `severity: "advisory"`. Clippy clean.

### Prompt D.2 — V9-9: Trusted-keys plumbing for hazard-DB consensus

> **Context.** `crates/invariant-biosynthesis-cli/src/commands/validate.rs:49` declares a single `--hazard-db-issuer-pub` path, but `--hazard-db` is `Vec<PathBuf>`. If two hazard DBs are signed by different issuers (the realistic consensus posture), the CLI cannot accept both. The `trusted` map at `validate.rs:106` only ever contains one entry.
>
> **Task.**
> 1. Change `--hazard-db-issuer-pub` to `Vec<PathBuf>`. Each file is a key file with a kid; aggregate them all into `trusted: HashMap<String, VerifyingKey>`. Reject duplicate kids with a clear error.
> 2. Each `FileBackedHazardDatabase::load` call already takes `&trusted` and validates the signing kid is present. No change needed there. Confirm by re-reading `screening/mod.rs::FileBackedHazardDatabase::load`.
> 3. Tests: 2 hazard DBs signed by 2 issuers, both pubkeys passed → loads fine; missing one issuer → load error names the missing kid; duplicate kid in two files → CLI error before validation.
> 4. Update `--help` text and README example.
>
> **Acceptance.** Existing single-DB usage still works (single `--hazard-db-issuer-pub` flag occurrence). Clippy clean.

### Prompt D.3 — V9-10: BSL≥3 must require multi-source consensus

> **Context.** `docs/threat-model.md` and `docs/step6-screening-databases.md` (read it) treat consensus as a fail-safe against a compromised single hazard-DB issuer. The validator does not enforce this: a BSL-3 or BSL-4 bundle can be approved against a single hazard DB.
>
> **Task.**
> 1. In `ValidatorConfig::new` (or the closest pre-validation hook): if `profile.bsl_level >= 3` and the configured screener is not a `ConsensusHazardScreener` with `source_count() >= 2`, return `ValidatorError::ConsensusRequiredAtBslHigh { bsl: u8 }`. Add a profile field `accept_single_source_screening: bool` (default false, doc-commented as dev-only) for the escape hatch.
> 2. The existing built-in BSL-3 / BSL-4 profiles (`profiles/university_bsl3_dna.json`, `profiles/government_bsl4_restricted.json`) need to either set `accept_single_source_screening: true` (with the dev-only doc) or the test harness needs to wire two test DBs. Pick the path that keeps existing tests green and document it in the profile JSON's `description` field if such exists.
> 3. Tests: BSL-3 + single-DB screener → error; BSL-3 + 2-DB consensus screener → succeeds; BSL-3 + single-DB + `accept_single_source_screening: true` → succeeds with stderr advisory.
>
> **Acceptance.** Clippy clean; tests pass.

### Prompt D.4 — V9-11: `Unimplemented` invariant inventory and gate

> **Context.** `crates/invariant-biosynthesis-core/src/invariants/mod.rs:7` says: *"`InvariantStatus::Unimplemented`; Step 3b fills in the real logic."* Grep for `InvariantStatus::Unimplemented` across `invariants/{dna,peptide,chemical,protocol,stateful,homology}.rs` to find which invariants still return it. The v8 spec does not require an inventory of these.
>
> **Task.**
> 1. Run the grep. Build a markdown table at `docs/unimplemented-invariants.md`: `| ID | Name | File:Line | Reason | Owner | Target phase |`.
> 2. In `BioProfile::validate`: if `bsl_level >= 3` and `allow_unimplemented_invariants` is true (or whatever the existing field name is — check `validator.rs:252`), reject with an error. Production BSL-3+ may not run with unimplemented invariants accepted.
> 3. Add a `verify-self` subcommand row in v8's gates ledger pointing at this list (open follow-up tickets per row).
> 4. Tests: BSL-3 + `allow_unimplemented_invariants: true` → ValidatorConfig::new errors. BSL-2 same → succeeds.
>
> **Acceptance.** The doc is accurate as of the current commit. Clippy clean.

---

## Chunk E — Medium: error and exit-code hygiene (V9-12, V9-13)

### Prompt E.1 — V9-12: Distinct exit codes for authority-block vs invariant-fail

> **Context.** `crates/invariant-biosynthesis-cli/src/commands/validate.rs:200-221` collapses two distinct rejection modes into the same exit code 1: (a) an invariant returned Fail/DbStale, and (b) "approval blocked by authority/screening but no invariant Fail." A user (and CI) cannot tell from the exit code which happened. Today the comment at line 219 acknowledges this: *"Approval blocked by authority/screening but no invariant Fail."*
>
> **Task.**
> 1. Allocate exit code 4 for "authority/chain rejection" and exit code 5 for "screening-required but no DB / staleness fail." Document the full exit-code table at the top of `validate.rs` and in README.
> 2. Update the exit-code logic to inspect the verdict's reason rather than the boolean. The `SignedVerdict` already carries structured reasons (read it in `validator.rs` first).
> 3. Tests: each exit-code path has a dedicated integration test.
> 4. Update v8 chunk 7.1 (AUDIT-READINESS) once it lands to include the new exit codes.
>
> **Acceptance.** No existing test changes meaning except where it now asserts a more specific exit code; clippy clean.

### Prompt E.2 — V9-13: Error messages must not include secrets

> **Context.** Several `Err(format!("..."))` paths in `validate.rs`, `keygen.rs`, and `key_file.rs` propagate underlying errors verbatim. Audit whether any of these include the raw bytes of a private key, a base64-encoded secret, or a path that contains a secret in the filename. The `.claude/rules/security.md` rule "Never log secrets" applies.
>
> **Task.** Audit the following files and either confirm no secret leaks or add redaction:
> - `crates/invariant-biosynthesis-cli/src/commands/keygen.rs`
> - `crates/invariant-biosynthesis-cli/src/key_file.rs`
> - `crates/invariant-biosynthesis-core/src/keys.rs` (especially the `FileKeyStore` paths)
> - Any `format!("...{e}", e = anyhow::Error)` chain that bubbles up from a key-decode error
>
> Add a `crates/invariant-biosynthesis-core/src/keys.rs` test that asserts the `Display` impl of `KeyStoreError` does not contain the secret material when the underlying I/O error includes file contents (construct the error path artificially in the test).
>
> **Acceptance.** Audit doc `docs/secret-redaction-audit.md` exists, lists every reviewed call site with verdict (clean / fixed). Test asserts no leak. Clippy clean.

---

## Chunk F — Low: doc-vs-code drift (V9-14, V9-15)

### Prompt F.1 — V9-14: Module doc comments lying about implementation status

> **Context.** Several modules contain doc comments referencing "Step 3," "Step 0," "to be ported," "stub for downstream linking," or "Step 3b fills in the real logic." After v8+v9 land, none of these phrases should remain unless the corresponding stubness is still real.
>
> **Task.**
> 1. Grep for `"Step 3"`, `"Step 0"`, `"to be ported"`, `"stub for"`, `"will be filled"`, `"placeholder"` across `crates/invariant-biosynthesis-core/src/`.
> 2. For each hit, either: (a) implementation is in fact present → delete or rewrite the comment; (b) implementation is still missing → leave the comment but add a `TODO(V9-OPEN-N)` marker pointing at an entry you append to v8's `docs/acceptance-gates.json`.
>
> **Acceptance.** Grep-after produces only TODO-tagged entries that map to real open gates.

### Prompt F.2 — V9-15: README accurate as of v9

> **Task.** Update `README.md` to reflect the v9 changes: profile signing requirement at BSL≥3, `--trusted-key`, `--hazard-db-issuer-pub` accepting multiple values, watchdog subcommand, new exit codes, `accept_unsigned_profile_for_dev` field. One-line acceptance-gates status block (already mandated by v8 chunk 4) should remain accurate.
>
> **Acceptance.** A reader can run the documented example end-to-end against the current binary.

---

## Done definition for this spec

- All V9-1..V9-15 either implemented in code (commit message references the V9 id) or deferred with a written decision under `docs/` naming an owner.
- Where v9 corrects v8 (V9-5, V9-6, V9-7), the v8 prompt is annotated as "superseded by V9-N" in v8 itself or in a note appended to v8.
- `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` clean on every commit.
- `docs/acceptance-gates.json` (from v8 chunk 4) gets at least these new gate entries:
  - **G8** — Profile signature verification on (V9-1).
  - **G9** — Watchdog signed-heartbeat round-trip exercised in CI (V9-4).
  - **G10** — DbStale fail-closed exercised (V9-3).
- No new public deps in the default build.

## Out of scope for v9

- Distributed/quorum watchdog (V9-4 implements single-monitor only).
- Profile-signing CLI subcommand (`invariant-bio profile sign`) — library API only in V9-1; CLI tool is a follow-up.
- Per-source heartbeat replay log persistence across restarts (in-memory only).
- Real cheminformatics, real HSM, real S3 replication — all still gated by v8.

## Sequencing notes

- **Chunk A first.** Profile signing is the deepest prerequisite — once trusted-key plumbing is in place, the `--trusted-key` flag from V9-2 is reused by D.2 and (later) by the watchdog monitor in B.2.
- **Chunk B second.** DbStale and watchdog are independent of A but build on the trust plumbing for the watchdog monitor's `--trusted-key`.
- **Chunk C** is a set of corrections; apply each only when you are about to execute or have just executed the corresponding v8 prompt.
- **Chunk D, E, F** can be done in any order after A and B; D.1 (severity) touches a public type and may trigger downstream churn — prefer doing it before any consumer-facing v9 doc edits.
