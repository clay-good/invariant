> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

## Spec v10 — Deep Gap Remediation (Implementation Prompts)

**Date:** 2026-05-01
**Baseline:** 691 passing tests; `cargo clippy --workspace -- -D warnings` clean.
**Branch base:** `main` (or wherever v9 lands).
**Predecessors:** `spec-v9-deep-gap-remediation.md`, `spec-v8-deep-gap-remediation.md`, `spec-v7-deep-gap-remediation.md`, `spec-v6-gap-remediation.md`, `spec-v5-gap-closure.md`.

This spec captures gaps surfaced by yet another deep re-read of every `crates/*/src/*.rs` file against `docs/spec.md`, `docs/threat-model.md`, `docs/step3-bio-invariants.md`, `docs/step6-screening-databases.md`, `docs/step7-hsm-key-mgmt.md`, and the previous remediation specs. **No prompt here duplicates a v6/v7/v8/v9 step**; before executing each prompt, double-check that the gap still exists in the code (specs and code drift quickly between spec writing and execution).

## How to use this spec

Each section is a self-contained prompt for a fresh Claude Code session. The session has access to the repo and `CLAUDE.md`; it has no other context. Run them roughly in the order given. After each prompt:

1. `cargo build --workspace`
2. `cargo test --workspace`
3. `cargo clippy --workspace -- -D warnings`
4. One commit per prompt; commit message must reference the V10-id (e.g. `V10-1: deny_unknown_fields on bundle types`).

If a prompt's preconditions don't hold (e.g. a referenced file or type has been renamed, or v9 already closed a gap that v10 listed), stop and surface it before continuing. Do not "infer" — read the code. **Especially** re-grep for the identifiers and line numbers cited; v9's prompts may have moved them.

---

## Severity legend

- **Critical** — security-relevant; default behavior is fail-open, accepts unauthenticated input, or opens a covert channel.
- **High** — security-adjacent or false-confidence; spec or threat model claims behavior is implemented and code does not deliver it.
- **Medium** — correctness, observability, or DoS surface drift.
- **Low** — polish, error-message granularity, missed boundary tests.

---

## Chunk A — Critical: schema closure and input bounds (V10-1, V10-2, V10-3, V10-4)

These four are bundled because they all touch `models/bundle.rs` and the validator's pre-check phase. Do them as one PR, one commit per prompt.

### Prompt A.1 — V10-1 (Critical): `deny_unknown_fields` on `SynthesisBundle`, `SynthesisPayload`, `BundleAuthority`

> **Context.** `crates/invariant-biosynthesis-core/src/models/bundle.rs` defines `SynthesisBundle`, `SynthesisPayload`, and `BundleAuthority` with serde derives but **without** `#[serde(deny_unknown_fields)]`. The screening module (`screening/mod.rs`) correctly applies the guard, and the profile module does too — but the bundle types do not. Any extra JSON fields are silently dropped at deserialization. This is a textbook covert-channel vector (threat model AV-8): a cognitive layer can stuff `"exfil": "..."` into the bundle, the firewall ignores it, and a downstream LLM/audit-log/replay tool may pick it up. It also defeats schema-based versioning: a typo'd field name (`"sequecne"` for `"sequence"`) is silently zero rather than rejected.
>
> **Task.**
> 1. Read `crates/invariant-biosynthesis-core/src/models/bundle.rs` end-to-end. Identify every `#[derive(... Deserialize ...)]` struct and enum in this file (and any related types in `models/` that get embedded inside a bundle and are not already closed). Add `#[serde(deny_unknown_fields)]` to each.
> 2. For tagged enums (`SynthesisPayload` if it uses `#[serde(tag = "...")]`), use `#[serde(deny_unknown_fields)]` per variant where serde supports it; otherwise add it at the enum level following the convention used in `screening/mod.rs`.
> 3. Add a new test module `crates/invariant-biosynthesis-core/src/models/bundle.rs::tests::reject_unknown_fields` with one test per closed type: construct a JSON string carrying a known-good field plus `"exfil_channel": "..."`, attempt to `serde_json::from_str::<SynthesisBundle>(...)`, assert it errors with a message mentioning the unknown field.
> 4. Re-run **every** test fixture under `crates/invariant-biosynthesis-core/tests/fixtures/`, `crates/invariant-biosynthesis-cli/tests/fixtures/` (and any inline fixture string in tests). If any fixture has an extraneous field that was previously tolerated, either fix the fixture (preferred) or document why the field is meaningful (and add it to the struct).
> 5. Update `docs/threat-model.md` AV-8 section: add a one-line note "Schema closure (`deny_unknown_fields`) on bundle types — V10-1, [year/month]."
>
> **Acceptance.** New tests pass; existing tests still pass; clippy clean. Grep `crates/invariant-biosynthesis-core/src/models/` for `Deserialize` and confirm every external-input-bearing type has `deny_unknown_fields` (or a deliberate doc comment explaining why not).

### Prompt A.2 — V10-2 (High): Length bound on `SynthesisBundle::source`

> **Context.** `crates/invariant-biosynthesis-core/src/models/bundle.rs` declares `pub source: String` (the cognitive-layer identifier). Nothing validates its length. An attacker — or a buggy upstream — can supply `source: ""` (silently breaks rate-limiting and threat scoring's per-source state) or a multi-megabyte string (audit-log bloat; potential regex DoS in any downstream consumer that pattern-matches the source). Threat model AV-8 mandates canonical-form validation.
>
> **Task.**
> 1. Add `pub fn validate_bundle_shape(&self) -> Result<(), BundleShapeError>` to `SynthesisBundle` (or extend `BioProfile::validate_bundle` if a precedent exists — read first). Define `BundleShapeError` with variants `SourceEmpty`, `SourceTooLong { len: usize, max: usize }`, plus the variants needed for V10-3 and V10-4 below.
> 2. Reject `source.is_empty()` and `source.len() > 256`. Use a constant `MAX_BUNDLE_SOURCE_LEN: usize = 256` near the top of the module.
> 3. Call `validate_bundle_shape` from the validator at the **first** step of `validate()`, before authority/screening/invariants. On error, emit `ValidatorError::BundleShape(...)` and exit-code-2 path.
> 4. Tests: empty source rejected; 256-byte source accepted; 257-byte source rejected; the validator's error variant is plumbed through to the CLI exit code.
>
> **Acceptance.** Tests pass; clippy clean. **Do not silently truncate** — fail closed.

### Prompt A.3 — V10-3 (High): Bound bundle metadata size

> **Context.** `SynthesisBundle::metadata: HashMap<String, String>`. The doc comment says "String values only to prevent deeply-nested JSON objects." But strings are unbounded. A 10MB key or value will: blow up the audit log; slow down deserialization; potentially DoS regex-based invariants if metadata is fed into any matcher.
>
> **Task.**
> 1. Extend `validate_bundle_shape` (from V10-2) to enforce: each key ≤ 128 bytes, each value ≤ 1024 bytes, total `keys.len() + values.len()` summed bytes ≤ 10 KiB, total entry count ≤ 64. Constants at module top.
> 2. Add new error variants: `MetadataKeyTooLong`, `MetadataValueTooLong`, `MetadataTooManyEntries`, `MetadataTotalTooLarge`.
> 3. Tests: each boundary, plus a happy-path bundle with realistic metadata.
> 4. If any built-in fixture currently exceeds these bounds, shrink it.
>
> **Acceptance.** Tests pass; clippy clean.

### Prompt A.4 — V10-4 (High): Per-payload sequence-length cap, profile-driven

> **Context.** `SynthesisPayload::Dna { sequence }`, `Peptide { sequence }`, and `Chemical { smiles }` all carry unbounded strings. The validator runs regex-heavy invariants (D7-D10, P-family, C-family) over the full string. A 100MB DNA sequence triggers OOM during deserialization plus quadratic-or-worse cost in several invariants. Threat model §1.3 (resource exhaustion) explicitly flags this. The profile schema **already** has `max_synthesis_volume_ml` and similar caps but no length cap on payload strings.
>
> **Task.**
> 1. Add to `BioProfile`:
>    - `pub max_dna_length_bp: Option<u64>` (default applied at validation time: 1_000_000 bp; documented in the profile struct doc comment).
>    - `pub max_peptide_length_aa: Option<u64>` (default 100_000 aa).
>    - `pub max_smiles_length_chars: Option<u64>` (default 100_000 chars).
> 2. Add the corresponding fields to all six built-in profile JSONs in `profiles/*.json` set explicitly to a sensible value per profile (BSL-2 lower than BSL-4, etc.). Do not rely on the default in built-ins — make the policy auditable from the JSON.
> 3. In `validate_bundle_shape` (extending V10-2): match on the payload variant and check the appropriate cap. Add error variants `PayloadTooLong { kind: &'static str, len: u64, max: u64 }`.
> 4. Tests per payload kind; tests that built-in profiles round-trip the new fields; a test where a 1KB profile cap rejects a 2KB sequence.
> 5. Document in `docs/threat-model.md` §1.3 that V10-4 closes the unbounded-payload DoS vector.
>
> **Acceptance.** Tests pass; clippy clean. The validator never reads more than `cap` bytes of payload into a regex/SMARTS engine without first checking the cap.

---

## Chunk B — High: trust enforcement gaps in validator (V10-5, V10-6, V10-7)

### Prompt B.1 — V10-5 (High): Validator must use `profile.max_authority_chain_depth` (not the hardcoded `DEFAULT_MAX_HOPS`)

> **Context.** `crates/invariant-biosynthesis-core/src/authority/chain.rs` defines `DEFAULT_MAX_HOPS = 16`. `BioProfile::max_authority_chain_depth: usize` (default 5) is declared and validated at profile-load. **Read `validator.rs` carefully** to locate the chain-verify call site. If the call uses `DEFAULT_MAX_HOPS` (or any constant) instead of `self.config.profile.max_authority_chain_depth`, a profile that declares `max_authority_chain_depth: 3` is overridden by the validator and accepts up to 16 hops. (If after re-reading you find the value is already threaded through, this prompt becomes a "verify and add a regression test" task — say so, write the test, and stop.)
>
> **Task.**
> 1. Grep `crates/invariant-biosynthesis-core/src/` for `DEFAULT_MAX_HOPS` and for `verify_chain` / `verify_chain_with_max_depth`. List every call site in your reply.
> 2. At every call site that runs during bundle validation, replace the hardcoded constant with `self.config.profile.max_authority_chain_depth` (or thread it from `&BioProfile` if the call site doesn't already have it).
> 3. Confirm `BioProfile::validate` already caps `max_authority_chain_depth` to `[1, 16]` (per project memory it does); if not, add the cap.
> 4. Tests: profile with `max_authority_chain_depth: 3` and a 4-hop chain → reject; same profile with a 3-hop chain → accept; profile with default 5 and a 5-hop chain → accept; 6-hop → reject.
>
> **Acceptance.** Profile field is honored. Clippy clean.

### Prompt B.2 — V10-6 (High): Reject bundles with future timestamps (with bounded clock-skew tolerance)

> **Context.** `SynthesisBundle::timestamp` is consumed by the audit log and the threat scorer. Nothing checks it is `<= now() + tolerance`. A bundle with `timestamp: 2099-01-01T00:00:00Z` will: (a) corrupt audit-log ordering invariants if any consumer assumes monotonicity; (b) confuse stateful detectors that use timestamp deltas; (c) potentially expire a legitimate replay-window check on PCA delegations (whose `valid_until` is past relative to the future bundle but future relative to now).
>
> **Task.**
> 1. Add `pub clock_skew_tolerance: Duration` to `ValidatorConfig` (default 60 seconds — document why: NTP-class skew on commodity servers).
> 2. As part of `validate_bundle_shape` (V10-2) **or** as the second pre-check in `validate()` after shape, compare `bundle.timestamp` to `chrono::Utc::now()`. If `bundle.timestamp > now + tolerance`, return `ValidatorError::BundleTimestampInFuture { skew: Duration }`.
> 3. Also reject `bundle.timestamp` more than 30 days in the past (default; configurable via `max_bundle_age: Duration` on `ValidatorConfig`). The validator should not be re-validating ancient bundles — that is replay territory; reuse the constant from any existing nonce-log expiration logic if precedents exist.
> 4. To keep tests deterministic, abstract the clock: add a `Clock` trait or accept a `now: Option<DateTime<Utc>>` arg on the public validate method (whichever pattern the codebase already uses — `grep` first; do not invent a new clock abstraction if one exists). The threat scorer or audit module probably already has one.
> 5. Tests: future bundle (>60s skew) → reject; future bundle within 60s → accept; 31-day-old bundle → reject; 29-day-old bundle → accept (assuming valid otherwise).
>
> **Acceptance.** Clippy clean. Tests use the injected clock, not wall-clock.

### Prompt B.3 — V10-7 (High): Threat-score escalation to `IncidentResponder`

> **Context.** v8 chunk 3.1 wired `IncidentResponder` into `ValidatorConfig` (and v9-6 corrected its constructor shape). The triggers are S1 fragmentation, consensus disagreement, attestation failure. The threat scorer (`crates/invariant-biosynthesis-core/src/threat.rs`) auto-wires at BSL ≥ 3 (per V8 chunk 2.2) and produces a composite score per bundle, gating approval. **But:** sustained-elevated threat scores never trigger an incident. The threat scorer is per-bundle; the lockdown-worthy signal — a campaign of high-but-individually-permissible-score bundles (AV-1 slow-drift) — is invisible.
>
> **Task.**
> 1. In `threat.rs`, extend the scorer to maintain a sliding window of recent scores per `bundle.source` (e.g., last 32). Add `pub fn campaign_signal(&self, source: &str) -> CampaignSignal` returning `Quiet | Elevated { mean: f64, count: u32 } | Critical { mean: f64, count: u32 }`. Define thresholds in `ThreatScorerConfig` (defaults: elevated = mean ≥ 0.6 over ≥ 8 bundles; critical = mean ≥ 0.8 over ≥ 8 bundles).
> 2. In `validator.rs`, after the per-bundle threat check (whether or not it gated approval), call `campaign_signal(&bundle.source)`. On `Critical`, fire the incident responder with a new trigger variant `IncidentTrigger::ThreatCampaign { source: String, mean: f64, count: u32 }`. On `Elevated`, log a single stderr advisory line.
> 3. Persistence is **not** in scope for v10 — the sliding window is process-local; document this as a limitation in `incident.rs` doc and add an entry to `docs/acceptance-gates.json` (from v8 chunk 4) `V10-OPEN-1: cross-process campaign signal persistence`.
> 4. Tests: feed 8 bundles with synthetic-high scores from one source → assert incident fires once with `ThreatCampaign`. Feed 8 from one source and 1 from another → only first source triggers. Reset the scorer → no carryover.
>
> **Acceptance.** Tests pass; clippy clean. The incident responder receives the new variant and dispatches to its sinks like any other trigger.

---

## Chunk C — Medium: protocol vocab, screening DoS, nonce log hygiene (V10-8, V10-9, V10-10)

### Prompt C.1 — V10-8 (Medium): Wire `profile.allowed_protocol_steps` into PR2

> **Context.** `BioProfile::allowed_protocol_steps: Option<Vec<String>>` is declared in `models/profile.rs`. PR2 (`crates/invariant-biosynthesis-core/src/invariants/protocol.rs`) checks each protocol step's verb against the **built-in** vocabulary (`PROTOCOL_STEP_VOCAB_VERSION = 1`). It does **not** restrict to the profile's allow-list. A profile that declares `allowed_protocol_steps: ["aspirate", "dispense", "mix"]` (an institutional restriction) is silently overridden — `ligate`, `digest`, etc. are still accepted.
>
> **Task.**
> 1. Confirm by grep that `protocol.rs` does not currently consult `profile.allowed_protocol_steps`. If it does, this prompt becomes "add a test"; do that and stop.
> 2. Thread the profile's allowed-steps slice into `InvariantContext` (or whatever struct PR2 receives — read first). Modify PR2 such that:
>    - If `profile.allowed_protocol_steps.is_none()` → behavior unchanged (allow whole built-in vocab).
>    - If `Some(allow_list)` → the verb must be in the built-in vocab **and** in the allow-list. Verbs in the allow-list but **not** in the built-in vocab are a profile-loading error (`BioProfile::validate` should reject them) — add that check too if absent.
> 3. Tests: profile with allow-list of three verbs accepts a protocol using only those; rejects a protocol with a fourth (built-in but not allowed) verb; profile referring to a non-existent verb fails to load.
> 4. Update `docs/step3-bio-invariants.md` PR2 section to remove any "Known Gap" note about profile-restricted vocab.
>
> **Acceptance.** Tests pass; clippy clean.

### Prompt C.2 — V10-9 (Medium): Per-source-DB timeout in `ConsensusHazardScreener`

> **Context.** `crates/invariant-biosynthesis-core/src/screening/mod.rs` defines `ConsensusHazardScreener`, which iterates configured hazard DBs and aggregates per the quorum policy. There is no timeout on any individual `screen_payload` call. A pathological DB (slow I/O; catastrophic regex backtracking on a crafted payload) can stall the entire validator. Combined with V10-4 (payload-length caps), this closes the largest DoS vector — but the DB-side regex/IO timeout is still missing.
>
> **Task.**
> 1. Add `pub per_db_timeout: Option<Duration>` to `ConsensusHazardScreenerConfig` (or to the screener struct constructor — whichever shape exists). Default `Some(Duration::from_secs(5))`.
> 2. Wrap each per-DB `screen_payload(...)` call in a timeout. On expiry, treat the DB as having returned `DbStale` for that bundle (so the v9-3 fail-closed path applies) and log a single stderr advisory `note: hazard DB <name> timed out (>{timeout:?}); applying DbStale fail-closed policy`.
> 3. **Implementation note:** if `screen_payload` is sync, you cannot truly cancel a CPU-bound regex from another thread without process-level isolation. Acceptable approximations: (a) run each DB in its own thread, give up waiting after timeout, leave the thread to drain; (b) document this as a "best-effort" timeout in the doc comment. Do **not** introduce tokio just for this; keep the dep surface unchanged.
> 4. Tests: a stub `HazardScreener` whose `screen_payload` sleeps 10 s; with timeout 1 s, the validator returns within ~1 s with the DB marked stale.
>
> **Acceptance.** Tests pass; clippy clean. No new public deps.

### Prompt C.3 — V10-10 (Medium): Persistent nonce-log rotation

> **Context.** `crates/invariant-biosynthesis-core/src/attestation.rs` has `DEFAULT_NONCE_CACHE_CAP = 4096` for the in-memory cache, but the persistent log (`--nonce-log`, wired by v8 chunk 2.1) is append-only, no rotation, no expiration. After hundreds of thousands of attestations the file becomes load-time-prohibitive and disk-space-prohibitive on long-running deployments.
>
> **Task.**
> 1. Add to `ValidatorConfig` (or `AttestationVerifierConfig` if a sub-config exists):
>    - `nonce_log_max_age: Option<Duration>` (default 30 days).
>    - `nonce_log_max_entries: Option<usize>` (default 1_000_000).
>    - `nonce_log_rotation_keep: usize` (default 4 — keep `.0` through `.4`, delete older).
> 2. On nonce-log load: drop entries older than `max_age`. On nonce-log persist: if entry count exceeds `max_entries` after this run, rotate (`log` → `log.1`, `log.1` → `log.2`, etc.; delete `log.{rotation_keep+1}`); start fresh `log` with only the most recent `max_entries / 2`.
> 3. Atomic-write the rotated files (write `log.tmp`, fsync, rename) — match the convention used by `audit.rs`.
> 4. Tests: synthesize 1.5 × max_entries nonces over time → rotation occurs; old entries beyond `rotation_keep` are deleted; entries within `max_age` survive a load; entries past `max_age` are dropped.
>
> **Acceptance.** Tests pass; clippy clean. Nonce uniqueness is preserved across rotations (i.e., any nonce within the `max_age` window is still in some `log.N` file and is loaded on startup).

---

## Chunk D — Medium: incident sink atomicity, secondary-crate integration, hazard-DB publisher metadata (V10-11, V10-12, V10-13)

### Prompt D.1 — V10-11 (Medium): Atomic-write semantics for `IncidentResponder` file sinks

> **Context.** `crates/invariant-biosynthesis-core/src/incident.rs` (post-v8/v9) supports an `AlertSink::File` (or equivalent — read first; the variant name may differ) that writes alerts via `fs::write` or `OpenOptions::append`. Neither is atomic. A process crash during alert-write leaves a truncated file. Auditors lose forensic evidence of the trigger that caused lockdown.
>
> **Task.**
> 1. Read `incident.rs` and identify the file-sink path. If it already uses atomic-write, this prompt is a verify+test and stop.
> 2. Otherwise, refactor to: write to `path.tmp.<pid>.<random>`, `fsync`, then `rename`. For append-style sinks, do read-modify-write under a per-path advisory lock (use `fs2` only if the project already depends on it; otherwise serialize with a `Mutex` inside the sink and document the single-process limitation).
> 3. Tests: simulate a crash by writing partial content to `path.tmp` and asserting that the **target** path still parses (i.e., the partial write is invisible); incident sink writes succeed concurrently from multiple threads without interleaving.
>
> **Acceptance.** Tests pass; clippy clean.

### Prompt D.2 — V10-12 (Medium): One end-to-end test connecting eval/sim/fuzz to the core validator

> **Context.** `crates/invariant-biosynthesis-eval`, `crates/invariant-biosynthesis-sim`, and `crates/invariant-biosynthesis-fuzz` each implement secondary-testing harnesses (per project memory, partially built out across phases). None of them runs as part of the cross-crate test suite asserting consistency with `invariant-biosynthesis-core` — i.e., a regression that only the eval rubric or a fuzz attack would catch will not show up in `cargo test --workspace`. Read each of these crates' top-level `lib.rs` and `tests/` to confirm.
>
> **Task.**
> 1. In each of `eval`, `sim`, `fuzz`, add **one** integration test under `tests/`:
>    - `eval`: load a fixture trace JSON, evaluate against the default rubric, assert at least one expected violation/clean signal is produced (specific to whatever the eval crate's surface looks like — read first).
>    - `sim`: run a one-step dry-run scenario through the simulator, capture the emitted bundle, validate it via the core validator, and assert the verdict matches the scenario's `expected_verdict` field.
>    - `fuzz`: pick one canned attack from each of the four families (protocol/authority/system/cognitive) declared in the crate (read `lib.rs` to enumerate), submit each generated bundle to the validator, assert the validator flags it as `Fail` (or whatever the family's expected outcome is). Do **not** spend cycles fuzzing — pick deterministic seeds and assert a fixed outcome.
> 2. Each test must run in `cargo test --workspace` without external resources.
> 3. If the secondary crates do not currently expose enough public API for these tests, surface that to the user and stop — do not add public surface area without explicit alignment.
>
> **Acceptance.** Three new green tests; existing tests still pass; clippy clean. A future regression in core invariants will at least one of these tests.

### Prompt D.3 — V10-13 (Medium): Hazard-DB publisher metadata (claims, not just kid)

> **Context.** A signed hazard DB carries an `issuer_kid`. The trusted-keys map says "this kid is trusted." It says nothing about *who* the kid is. A rotated/repurposed key (e.g., a key originally issued to "HHS SAP" later reassigned to "Internal Lab #4") will quietly accept the new publisher's content under the old trust. Threat model AV-3 (compromised hazard-DB) is partially closed by consensus (V9-10) and trusted-key plumbing (V9-2/V9-9), but identity-claim verification is missing.
>
> **Task.**
> 1. Add an optional field on the signed hazard-DB envelope (read `screening/mod.rs::SignedHazardFile` or equivalent first; the type may be named differently): `publisher_claims: Option<HashMap<String, String>>` covered by the existing signature.
> 2. Add a CLI flag on `validate`: `--require-hazard-db-publisher KEY=VALUE` (repeatable). At hazard-DB load, for every loaded DB, assert each required claim is present and matches; on mismatch, exit with code 3 and a clear error naming the DB and the failing claim.
> 3. The trusted-keys map shape stays as-is (kid → VerifyingKey). Publisher claims are an **additional** assertion, not a replacement for kid trust.
> 4. Tests: a hazard DB signed with claims `{"publisher": "HHS SAP"}` loads when the CLI passes `--require-hazard-db-publisher publisher=HHS SAP`; rejects with a different value; rejects when the flag is required but the DB has no claims.
> 5. The six built-in profile JSONs do not change; this is a CLI-side enforcement only. Document the flag in `README.md`.
>
> **Acceptance.** Tests pass; clippy clean.

---

## Chunk E — Low: error granularity, polish, and missed boundary tests (V10-14, V10-15, V10-16, V10-17)

### Prompt E.1 — V10-14 (Low): Granular `AuthorityError` for malformed COSE_Sign1

> **Status (2026-05-17): DONE.** New typed
> [`CoseDecodeReason`](../../crates/invariant-core/src/models/error.rs)
> enum in `invariant-core::models::error` covers nine variants:
> `CborInvalid(String)`, `MissingProtectedHeader`, `MissingKid`,
> `InvalidKidEncoding(String)`, `MissingPayload`,
> `PayloadDecode(String)`, `SignatureSlotEmpty`,
> `WrongTag { expected, got }`, `Other(String)`. New
> `AuthorityError::CoseDecode { hop, reason: CoseDecodeReason }` variant
> alongside the legacy `CoseError` (kept for backwards compatibility —
> downstream consumers can still pattern-match it; no new code path
> produces it). All five internal call sites in
> [crates/invariant-core/src/authority/crypto.rs](../../crates/invariant-core/src/authority/crypto.rs)
> migrated:
>   - `parse_cose` → `CoseDecode { reason: CborInvalid(_) }`
>   - `extract_kid_from_parsed` empty kid → `CoseDecode { reason: MissingKid }`
>   - `extract_kid_from_parsed` non-UTF8 kid → `CoseDecode { reason: InvalidKidEncoding(_) }`
>   - `decode_pca_payload_from_parsed` no payload → `CoseDecode { reason: MissingPayload }`
>   - `decode_pca_payload_from_parsed` parse failure → `CoseDecode { reason: PayloadDecode(_) }`
>
> Hop index is plumbed through the chain-walk loop as before — no
> structural change there.
>
> Updated all internal matchers: the two crypto-module unit tests now
> match on `CoseDecode { reason: MissingPayload, .. }` and `CoseDecode
> { reason: InvalidKidEncoding(_), .. }`; `authority::tests` matches
> on `CoseDecode { hop: 0, .. }`. New snapshot test cases in
> [crates/invariant-core/tests/error_stability.rs](../../crates/invariant-core/tests/error_stability.rs)
> anchor the `Display` for all nine `CoseDecodeReason` variants plus
> the wrapping `CoseDecode` shape. `MissingProtectedHeader`,
> `SignatureSlotEmpty`, and `WrongTag` are reserved for forensic
> completeness — `coset` currently surfaces those cases through
> `CborInvalid`. [docs/error-stability.md](../error-stability.md)
> gains an `AuthorityError::CoseDecode` row and a dedicated
> `CoseDecodeReason` table. `cargo test --workspace` + `cargo clippy
> --workspace --lib -- -D warnings` clean.
>
> **Context.** `crates/invariant-biosynthesis-core/src/authority/` parses each PCA-chain hop as a COSE_Sign1 envelope. A malformed envelope yields a generic decode error with little forensic value (auditors cannot distinguish "garbage bytes" from "missing kid header" from "wrong COSE tag"). Authority-chain failures are exactly the situation where granular forensics matters most.
>
> **Task.**
> 1. Read the COSE-parse path in `authority/`. Identify every place a generic CBOR/COSE decode error is wrapped.
> 2. Add granular variants to `AuthorityError` (or whatever the chain-level error enum is): `CoseDecode { hop_index: usize, reason: CoseDecodeReason }`, where `CoseDecodeReason` covers at least: `CborInvalid(String)`, `MissingProtectedHeader`, `MissingKid`, `WrongTag { expected: u64, got: u64 }`, `SignatureSlotEmpty`, `Other(String)`.
> 3. Plumb the hop index from the chain-walk loop down into the parse helper.
> 4. Tests: synthesize a chain with one malformed hop per reason variant and assert the error pinpoints the hop and reason.
>
> **Acceptance.** Tests pass; clippy clean. No behavior change for valid chains.

### Prompt E.2 — V10-15 (Low): `BioProfile::validate` boundary tests for `bsl_level`

> **Status (2026-05-17): DONE.** Three new tests in
> [crates/invariant-biosynthesis/src/models/profile.rs](../../crates/invariant-biosynthesis/src/models/profile.rs)
> `mod tests`: `bsl_level_zero_rejected`, `bsl_level_five_rejected`,
> `bsl_level_boundaries_accepted` (sweeps 1..=4). All three green; the
> existing `[1,4]` validator branch is unchanged. Lib test count moved
> from 355 → 358.
>
> **Context.** `BioProfile::validate` already rejects `bsl_level` outside `[1,4]` (per project memory). Boundary tests for `0` and `5` are absent — easy to cover.
>
> **Task.** Add unit tests in `models/profile.rs`: `bsl_level_zero_rejected`, `bsl_level_five_rejected`, `bsl_level_boundaries_accepted` (1, 2, 3, 4). One commit, no behavior change.
>
> **Acceptance.** Tests pass.

### Prompt E.3 — V10-16 (Low): Test bundle-sequence reordering through threat scorer

> **Context.** `SynthesisBundle::sequence: u64` is a monotonic counter per source. The threat scorer should detect out-of-order bundles per source (replay/reorder, AV-6). Whether it does is undocumented at the test level.
>
> **Task.**
> 1. **First, read `threat.rs` end-to-end** and verify whether a per-source sequence-monotonicity detector exists. If yes, add a regression test asserting that submitting `seq=10, seq=5` from the same source increments the scorer's anomaly-count and (after the campaign threshold from V10-7) triggers an incident. If no, surface the gap to the user before adding the detector — implementing a new detector is out of scope for this prompt.
> 2. The deliverable is either: (a) a green regression test, or (b) a written one-paragraph note added to this spec under "V10-OPEN" listing it as an unaddressed sub-gap.
>
> **Acceptance.** Test passes (case a) or note added (case b). No half-implemented detector left in the tree.

> **Resolution (2026-05-17): option (b) — note added.** Read
> [crates/invariant-biosynthesis/src/threat.rs](../../crates/invariant-biosynthesis/src/threat.rs)
> end-to-end. `ThreatScorer::score` calls five detectors (boundary
> clustering, authority probing, replay similarity, drift, anomaly);
> none consult `bundle.sequence`. There is no per-source monotonic
> counter (the `DriftTracker` is keyed by principal but tracks running
> mean payload size, not sequence ordering). Adding a sixth detector
> is explicitly out of scope per the prompt; the gap is recorded
> under [§V10-OPEN below](#v10-open) as **V10-OPEN-2**.

### Prompt E.4 — V10-17 (Low): Verdict-signature self-verification round-trip test

> **Status (2026-05-17): DONE.** New integration test
> [crates/invariant-biosynthesis/tests/verdict_signature_roundtrip.rs](../../crates/invariant-biosynthesis/tests/verdict_signature_roundtrip.rs).
> Two tests:
> `signed_verdict_round_trips_through_disk_and_verifies` runs a known
> bundle through `ValidatorConfig::validate` with a deterministic
> 32-byte seeded `SigningKey`, writes the resulting `SignedVerdict`
> JSON to a `tempfile::tempdir` path, re-reads it with
> `serde_json::from_slice` against an *independent* `SignedVerdict`
> binding (no shared in-memory state), reconstructs the canonical
> preimage byte-for-byte the way `validator.rs::validate` builds it
> (`sha256:<hex>` ASCII of `sha256(serde_json::to_vec(&verdict))`),
> and asserts `verify_strict` accepts.
> `mutating_loaded_verdict_body_invalidates_signature` mutates the
> `command_sequence` field of the parsed verdict (any body bit-flip
> rewrites the preimage) and asserts `verify_strict` rejects. The
> test's doc-comment explicitly notes it stands in for the still-
> absent synthesizer-platform adapter (V8/V9-OPEN).
> `cargo test -p invariant-biosynthesis --test verdict_signature_roundtrip`
> → 2/2 pass; `cargo clippy --test verdict_signature_roundtrip -- -D
> warnings` clean.
>
> **Context.** `SignedVerdict` (from `validator.rs` or `models/verdict.rs` — read first) carries an Ed25519 signature. There is no test that exercises an end-to-end synthesizer-side verification: load a serialized verdict from disk, rebuild the canonical-JSON, verify the signature against the firewall's pubkey. Without this test, we cannot catch a regression that breaks downstream verifiability — and that is precisely what synthesizer integration depends on.
>
> **Task.**
> 1. Add a test in `validator.rs` (or a new `tests/` integration test): construct a deterministic key, run a known-good bundle through the validator, write the verdict to a temp file, **load it back** with `serde_json::from_str` (no shared state), reconstruct canonical-JSON the same way the signer did, and verify the signature. Assert success.
> 2. Mutate one byte of the loaded verdict's body and assert the signature verification fails.
> 3. Document in the test's doc comment that this test stands in for the (still-absent) synthesizer-platform adapter; the spec calls this out as V8/V9-OPEN.
>
> **Acceptance.** Test passes; clippy clean.

---

## V10-OPEN

Items consciously deferred during v10 closure. Each entry names the
unaddressed sub-gap, the rationale for deferral, and where the work
should pick up.

- **V10-OPEN-1 — Cross-process campaign-signal persistence.** The
  `ThreatScorer` sliding window and `IncidentResponder` state are
  process-local. A bio firewall restart loses every running
  campaign-signal aggregate. Per [Prompt B.3](#prompt-b3--v10-7-high-threat-score-escalation-to-incidentresponder)
  step 3, persistence was explicitly out of scope for v10. **Pick up
  at:** future "v11-bio" or a dedicated `incident-persistence` spec;
  the natural sink is a small append-only sidecar next to the audit
  log keyed by `(principal, window_id)`.

- **V10-OPEN-2 — Per-source bundle-sequence-monotonicity detector.**
  `SynthesisBundle::sequence: u64` is documented as a monotonic
  per-source counter (replay/reorder guard, AV-6 in
  [docs/biosynthesis/threat-model.md](threat-model.md)), but the
  threat scorer has no detector that asserts monotonicity per source.
  Submitting `seq=10` then `seq=5` from the same source today is a
  silent reorder: the validator's existing per-bundle checks do not
  cover cross-bundle ordering, and the scorer's five detectors look
  only at payload/principal aggregates. Per [Prompt E.3](#prompt-e3--v10-16-low-test-bundle-sequence-reordering-through-threat-scorer)
  this was resolved as "note, don't implement" — adding a new
  detector requires its own design decision (which signal? what
  weight? how does it compose with the existing five?) and per-
  detector tests. **Pick up at:** a new prompt that (i) adds a
  `score_sequence_monotonicity` detector keyed by `bundle.source`,
  (ii) wires its weight into `ThreatWeights` with a default in the
  0.1–0.2 band, and (iii) lands the `seq=10, seq=5` regression test
  the original prompt sketches.

## Done definition for this spec

- All V10-1..V10-17 either implemented in code (commit message references the V10-id) or deferred with a written decision under `docs/` naming an owner.
- `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` clean on every commit.
- `docs/acceptance-gates.json` (from v8 chunk 4) gets at least these new entries:
  - **G11** — Bundle schema closure (`deny_unknown_fields`) tested (V10-1).
  - **G12** — Bundle input-bound caps tested at boundary (V10-2..V10-4).
  - **G13** — Profile chain-depth honored end-to-end (V10-5).
  - **G14** — Future-timestamp rejection exercised (V10-6).
  - **G15** — Threat-campaign incident escalation exercised (V10-7).
  - **G16** — Hazard-DB per-source timeout exercised (V10-9).
  - **G17** — Nonce-log rotation exercised (V10-10).
- No new public deps in the default build.

## Out of scope for v10

- Cross-process persistence of campaign-signal state (V10-7) — process-local only.
- Real cheminformatics SMILES canonicalization — flagged by previous specs; deferred until a real backend lands.
- True regex/CPU cancellation in the screening timeout (V10-9) — best-effort; thread will drain.
- Synthesizer-platform adapter crate — V10-17 only adds a self-verification test; the adapter itself is a future phase.

## Sequencing notes

- **Chunk A first.** Schema closure and input bounds change deserialization behavior; doing them up front lets later chunks rely on bounded inputs in their tests.
- **Chunk B second.** Trust enforcement gaps build on bounded inputs (e.g., V10-7's per-source state is keyed by `source` whose length is now bounded by V10-2).
- **Chunk C** can run in any order after A. C.3 (nonce-log rotation) touches code that v8/v9 wrote — re-confirm v8/v9 landed before starting.
- **Chunk D** is mostly independent; D.2 (secondary-crate integration tests) may surface missing public API and stop early — that is fine, the deliverable is the surfaced finding.
- **Chunk E** is polish; do it last.
