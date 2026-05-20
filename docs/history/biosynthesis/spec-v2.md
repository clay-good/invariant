> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# spec-v2 — Gap Closure & Production Hardening

**Status:** Draft, 2026-05-02
**Scope:** This spec is the actionable companion to [`spec-gap-analysis.md`](spec-gap-analysis.md). It walks the delta between the shipping code on `codelicious/spec-spec-gap-analysis-part-2` and the union of promises made in [`spec.md`](spec.md), [`spec-phase1-gap-closure.md`](spec-phase1-gap-closure.md), [`spec-phase2-operational.md`](spec-phase2-operational.md), [`step3`–`step10`], and [`threat-model.md`](threat-model.md). Each step is written as a self-contained Claude Code prompt — paste into a fresh session and it should be enough context to do the work.

This deep audit re-verified the current source tree (file by file, not by trusting the prior gap doc) and folds in (a) gaps the prior analysis catalogued and that are still open, (b) gaps the prior analysis missed, and (c) the un-executed Phase-2 step list. It does **not** repeat steps already marked complete in `spec-phase1-gap-closure.md`.

## Why this matters

Today the cryptographic spine is sound (PCA chain, audit hash chain, attestation envelopes) but the biology/chemistry layers are largely heuristic, the platform/HSM/replication backends are stubs, and several validator integrations are still left to the caller. A production deployment would silently lose its audit log if the operator forgot to call `AuditLogger`, accept profile signatures unverified, and miss any hazard whose sequence the regex hit-class did not literally match. spec-v2 closes those gaps in priority order and ends with the regulatory and ecosystem polish needed before a release can credibly claim "production-ready for synthesis."

## Progress log

(Each completed step appends `- [x] **Step N** — …`, matching the style of the archived Phase-1 spec.)

## Ground rules (apply to every step)

- Preserve `#![forbid(unsafe_code)]` in every crate.
- After every code-changing step, run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings`. Do not move on until all three pass.
- One commit per step, prefixed with the step id (e.g. `v2-03: profile signature verified on load`). Never push directly to `main`.
- New top-level dependencies require a feature flag and a justification line in the step's commit message. Phase A may add no new top-level deps.
- Update `docs/spec-gap-analysis.md` (mark the matching gap closed) and `CHANGELOG.md` in the same commit as the code change.
- When a step adds a CLI subcommand, also add a `--help` integration test and an entry in `README.md`.
- When a step changes `BioProfile`, also update every JSON file under `profiles/` and every fixture under `examples/`, then run `cargo test` to confirm parsers still load them.

---

# Phase A — Validator integration & correctness (no new deps)

These are the "the code already exists, but the wiring is wrong" gaps. They are all small, low-risk, and unblock everything that follows.

## Step v2-01 — Re-baseline the workspace and create the working branch

**Prompt for Claude Code:**

You are starting Phase A of `spec-v2.md`. From the repo root, create branch `codelicious/spec-v2-phase-a` off the current branch. Confirm the workspace is green: run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings`. Record the test count and the clippy state in the commit message of an empty (`--allow-empty`) baseline commit `v2-01: re-baseline at <sha>`. If anything is red, stop and surface the failure — do not begin Phase A on a red baseline.

## Step v2-02 — Wire the validator into the audit log by default

**Spec source:** `spec-phase1-gap-closure.md` §A2 (intent), `spec-gap-analysis.md` §0/§8.

**Prompt for Claude Code:**

Today `Validator::validate(...)` returns a `Verdict` and trusts the caller to call `AuditLogger::append(...)`. The CLI does this; library users may not. Change the default `Validator` so it owns an `Option<Arc<AuditLogger>>` and, when present, appends an `AuditEntry` for every verdict (Pass, Fail, Block, Advisory) **before** returning. Add a builder method `Validator::with_audit_logger(...)`. Do not break existing callers — existing call sites that already explicitly append should still work, but assert (debug-only) that an entry is not double-written for the same `bundle_id`. Add tests that prove: (a) verdict-without-logger still works; (b) verdict-with-logger writes exactly one entry; (c) a panic in audit append is surfaced as a `Validator` error rather than swallowed. Update the CLI `validate` command to use the new builder method instead of the manual append.

## Step v2-03 — Verify profile signatures on load (fail-closed)

**Spec source:** `spec-phase1-gap-closure.md` §A3, `spec-gap-analysis.md` §5.

**Prompt for Claude Code:**

`BioProfile` already carries optional `profile_signature` and `profile_signer_kid` fields ([crates/invariant-biosynthesis-core/src/models/profile.rs](crates/invariant-biosynthesis-core/src/models/profile.rs)). Nothing verifies them. Change `ProfileLoader` (or whatever module loads profile JSON in `crates/invariant-biosynthesis-core/src/profiles.rs`) so that: (a) loading a signed profile requires a configured `KeyStore` capable of resolving `profile_signer_kid` to a public key; (b) signature verification is performed over a canonical JSON form (use the same canonicaliser as A6 in Phase-1 if one exists, else introduce a tiny deterministic JSON serializer for this purpose); (c) verification failure is a hard error, never an advisory; (d) production profiles (`bsl_level >= 3` or `export_controlled = true`) MUST be signed — loading an unsigned one is a hard error. Add a `--allow-unsigned-profile` CLI flag that downgrades (c) to a warning; the flag is gated behind `cfg(debug_assertions)` or env `INVARIANT_BIO_DEV_MODE=1`. Tests: signed-good loads, signed-bad rejects, unsigned-bsl4 rejects, unsigned-bsl1 with flag warns and loads.

## Step v2-04 — Make stale screening fail-closed unconditionally in production

**Spec source:** `spec-gap-analysis.md` §5.3, `step6-screening-databases.md`.

**Prompt for Claude Code:**

`HazardDatabase` already supports a freshness window. Today the validator can be configured with `allow_unimplemented_invariants=true` and that flag bleeds into the staleness path so a stale DB downgrades to advisory. Audit `crates/invariant-biosynthesis-core/src/screening/mod.rs` and `validator.rs` and confirm that staleness produces a `Verdict::Block` whenever the running profile is non-development. Introduce a single `is_production_profile(&BioProfile) -> bool` helper (true unless `name` starts with `dev_`/`test_` or `bsl_level == 1` AND `export_controlled == false`) and reuse it. Cover the matrix: production+stale → Block; production+fresh → continue; dev+stale → Advisory. The `--allow-stale-screening` CLI flag, if it exists, must be no-op when `is_production_profile` is true.

## Step v2-05 — Persist `BioProfile` schema additions and enforce them

**Spec source:** `spec-phase1-gap-closure.md` §A11, `spec-gap-analysis.md` §1/§5/§7.

**Prompt for Claude Code:**

Add the following fields to `BioProfile` (all optional in the JSON to preserve back-compat for older fixtures, but enforced when present). For each, also add the runtime check:

1. `protein_kmer_k: Option<u8>` (range 3..=8) and `protein_kmer_threshold: Option<f64>` (range 0.0..=1.0) — replaces the hardcoded constants in `dna.rs::translate_dna_sequence` codepath.
2. `allow_stale_screening: bool` (default false) and `stale_screening_max_days: Option<u32>` (required when `allow_stale_screening = true`) — used by Step v2-04.
3. `max_authority_chain_depth: u8` (default 5, max 16) — enforced in `authority::chain` against the loaded chain length.
4. `required_attestation_kinds: Vec<String>` — every named attestation must appear and verify in the bundle's attached attestations or the bundle is `Block`'d.
5. `max_bundles_per_day: Option<u32>` — enforced by a new `RateLimiter` keyed on the PCA chain root kid; in-memory for now (Step v2-19 persists it).
6. `expires_at: Option<DateTime<Utc>>` and `bundle_version: u8` on `SynthesisBundle` — bundle is rejected if `expires_at < now` or `bundle_version` does not match a profile-allowed set.

Update every file in `profiles/` to declare the new fields explicitly. Validation tests for each field (good value, edge value, bad value) and a JSON round-trip test per profile.

## Step v2-06 — Move PR2 verb vocabulary into `BioProfile` (close the README "Known gaps" item)

**Spec source:** `spec-gap-analysis.md` §4, `spec-phase2-operational.md` Step 9.

**Prompt for Claude Code:**

The 25-verb whitelist is hardcoded in [crates/invariant-biosynthesis-core/src/invariants/protocol.rs](crates/invariant-biosynthesis-core/src/invariants/protocol.rs). `BioProfile.allowed_protocol_steps` already exists. Wire PR2 to honour it: when `Some`, the profile's list replaces (not augments) the hardcoded default; when `None`, the hardcoded default is used. Keep `is_builtin_verb` so profile validation still constrains entries to known verbs. Add a test fixture `profiles/restricted_protocol.json` with a 5-verb list and a unit test proving that a bundle using a verb outside that list is `Block`'d under that profile but `Pass`'d under a default profile.

## Step v2-07 — Wire the threat scorer into the validator pipeline

**Spec source:** `spec-phase2-operational.md` Step 2.

**Prompt for Claude Code:**

`crates/invariant-biosynthesis-core/src/threat.rs` exposes a `ThreatScorer` with five detectors but the validator only uses it when the caller calls `with_threat_scorer(...)`. Make it default-on for production profiles: `Validator::default()` builds with a `ThreatScorer::production()` preset. Each detector contributes a `ThreatSignal` to the verdict's `signals` field, and any signal with `Severity >= High` upgrades a Pass to Advisory and a Fail to Block. Document the scorer's outputs in the CLI `inspect` subcommand so an operator can see why the scorer fired. Tests: each of the 5 detectors triggers on a tailored bundle and is reflected in the verdict.

## Step v2-08 — Wire the `S1` stateful fragmentation detector by default

**Spec source:** `spec-phase2-operational.md` Step 3, `spec-gap-analysis.md` §1.4.

**Prompt for Claude Code:**

`stateful.rs::FragmentationBypassDetector` exists but is opt-in via `Validator::with_stateful_detector(...)`. Make it default-on. The session key is the PCA chain root kid plus a 24-hour rolling window. Persist state to `~/.invariant-bio/state/fragmentation.jsonl` (append-only, hash-chained, mode 0o600); load on startup. Provide a CLI subcommand `invariant-bio state prune` that drops sessions older than the configured window. Tests: 4 bundles each carrying a fragment of a hazard sequence return Pass individually but the 4th returns Block when state is on; persistence survives a fresh `Validator` instance.

## Step v2-09 — Tighten `Invariant` trait API and normalise hazard-class matching

**Spec source:** `spec-phase1-gap-closure.md` §A4, §A7.

**Prompt for Claude Code:**

Two correctness items the deep audit surfaced:

1. The `Invariant` trait returns a free-form `String` for evidence; downstream code parses substrings to reason about checks. Replace the string with a typed `Evidence` enum (`HitClass`, `Window`, `Score`, `External { kind, payload }`). Migrate all 34 invariant impls. The CLI rendering layer keeps the human-readable formatting.
2. Hazard-class matching in `screening/mod.rs` is case-sensitive and whitespace-sensitive in places, but profile JSON sometimes uses `"Select-Agent"` vs `"select_agent"`. Normalise both sides through a `HazardClass` newtype with a deterministic constructor (`HazardClass::parse(&str)` lowercases and replaces `-`/space with `_`).

## Step v2-10 — Validate `kid` strings, COSE metadata reserved keys, and pin canonical JSON

**Spec source:** `spec-phase1-gap-closure.md` §A5, §A6.

**Prompt for Claude Code:**

1. `kid` strings reach the keystore and the audit log. Constrain the form: 8-64 chars, ASCII `[a-zA-Z0-9_:-]`, must contain a `:` (e.g. `inst:lab-1`). Reject at COSE envelope parse time, at `KeyStore::resolve`, and at audit append.
2. The COSE metadata map currently accepts arbitrary keys. Reserve a fixed set (`alg`, `kid`, `iat`, `exp`, `nonce`, `chain_root`) and reject any unknown reserved-prefix key (`x-invariant-*`).
3. JSON canonicalisation today uses `serde_json` insertion order. Pin a canonical form (sorted keys, no whitespace, NFC-normalised strings) in a single `canonical_json::encode` helper used by every signing path (PCA, profile signing, audit signature). Add a property test that two semantically equal JSON values produce byte-identical canonical forms.

## Step v2-11 — Wire `differential` validation into the standard validate flow

**Spec source:** `spec-gap-analysis.md` §10.

**Prompt for Claude Code:**

`differential.rs` runs but is not invoked by the standard validate path. Add a `--differential` CLI flag to `validate` that runs the bundle through two independently-constructed `Validator` instances and reports check-level disagreements. For production profiles (per `is_production_profile` from Step v2-04) the flag is implicit: the standard validate flow always runs differentially and any disagreement degrades the verdict by one tier (Pass→Advisory, Advisory→Fail). Document the IEC 61508 SIL 2 framing in the validator rustdoc. Tests: matching verdicts pass through; injected disagreement (one validator with a bug-stub) downgrades; performance overhead is bounded (criterion bench in Step v2-25).

---

# Phase B — Production trust boundary (HSM, replication, attestation persistence)

These steps add real backends behind feature flags. Each new top-level dep is justified inline in the step.

## Step v2-12 — TPM 2.0 key-store backend

**Spec source:** `spec-phase2-operational.md` Step 6, `step7-hsm-key-mgmt.md`.

**Prompt for Claude Code:**

Implement `TpmKeyStore` ([crates/invariant-biosynthesis-core/src/keys.rs](crates/invariant-biosynthesis-core/src/keys.rs)) against `tss-esapi` behind a `tpm` cargo feature. Operations: `generate(kid, algorithm)` creates a primary key under the owner hierarchy and returns the public half; `sign(kid, payload)` runs an Ed25519 (or P-256 if the TPM does not support Ed25519 — surface in the error) signature; `public_key(kid)` reads the public area. Use the swtpm software TPM in CI for tests; do not require hardware. If `cfg(not(feature = "tpm"))`, keep the existing stub returning `Unavailable` so default builds are unchanged.

## Step v2-13 — YubiHSM 2 and OS keyring backends

**Spec source:** `step7-hsm-key-mgmt.md`, `spec-gap-analysis.md` §7.

**Prompt for Claude Code:**

Mirror the v2-12 pattern for `YubiHsmKeyStore` (crate `yubihsm`, feature `yubihsm`) and `OsKeyringStore` (crate `keyring`, feature `os-keyring`). YubiHSM tests run only when `INVARIANT_BIO_YUBIHSM_HOST` is set; otherwise skip with `#[ignore]`. OS keyring tests run on macOS and Linux; on Linux without a Secret Service (CI) they skip. The `KeyStore::from_url(...)` factory must already wire `yubihsm://`, `tpm://`, and `keyring://` URIs once these backends compile.

## Step v2-14 — Multi-party threshold root-key ceremony command

**Spec source:** `step7-hsm-key-mgmt.md`, `spec-gap-analysis.md` §7.2.

**Prompt for Claude Code:**

Add `invariant-bio keygen ceremony` with subcommands `init`, `contribute`, `finalize`. Use FROST for Ed25519 (`frost-ed25519` crate) for an `m-of-n` ceremony. `init` writes a ceremony manifest (n, m, participant kids, deadline). Each `contribute` produces a signed share that references the manifest hash. `finalize` reconstructs the public root, writes it to the keystore (any backend), and produces an audit-log entry recording every share's signer kid. The ceremony files are mode-0o600 and self-clean on finalize. End-to-end test: 3-of-5 happy path; 2-of-5 fails; tampered share fails verification.

## Step v2-15 — Key rotation with overlap window

**Spec source:** `step7-hsm-key-mgmt.md`, `spec-gap-analysis.md` §7.3.

**Prompt for Claude Code:**

Extend `KeyStore` with `rotate(kid, new_algorithm) -> RotationResult { old_kid_archived, new_kid }` and a profile-level `rotation_overlap_days` (default 14). During the overlap window, both kids verify but only the new kid signs. The audit log records rotation as a typed `KeyRotation` event. CLI: `invariant-bio keygen rotate --kid <kid>`. Tests: signing during overlap uses new key; verifying signatures from the old key still passes inside overlap; verifying after overlap expires fails.

## Step v2-16 — S3 replication backend

**Spec source:** `spec-phase2-operational.md` Step 5, `spec-gap-analysis.md` §8.1.

**Prompt for Claude Code:**

Implement `S3Replicator` ([crates/invariant-biosynthesis-core/src/replication.rs](crates/invariant-biosynthesis-core/src/replication.rs)) against `aws-sdk-s3` behind feature `s3`. Append-only, server-side encrypted, object key `audit/{instance_id}/{epoch_segment}.jsonl`. Cross-region: support an optional `secondary_bucket` and write fan-out. Recovery-on-restart: on construction, list objects, find the latest segment, and resume appending. Test against `localstack` in CI behind `INVARIANT_BIO_S3_TESTS=1`; default skip. Hard failure modes (auth error, network) propagate as `ReplicationError::Transport`; do **not** silently degrade.

## Step v2-17 — Webhook Merkle witness + cross-instance reconciliation

**Spec source:** `spec-phase2-operational.md` Step 5, `spec-gap-analysis.md` §8.2/§8.3.

**Prompt for Claude Code:**

Implement `WebhookWitness::publish(root, period_id)` POSTing a JSON body `{root, period_id, instance_id, signature}` to the configured URL with retries (3, exponential backoff, jitter, hard cap 30s). Add a verifier client `WitnessClient::fetch(period_id)` that returns the persisted root and proves inclusion of an audit entry. Add `invariant-bio audit reconcile --peer <url>` that exchanges current Merkle roots with another firewall instance and surfaces divergence with the first divergent entry id. Write integration tests against a local hyper server fixture; do not require an external endpoint.

## Step v2-18 — Persist attestation nonces across restarts

**Spec source:** `spec-phase2-operational.md` Step 10.

**Prompt for Claude Code:**

`attestation.rs` currently keeps issued nonces in memory; a restart re-opens the replay window. Move nonce state to `~/.invariant-bio/state/attestation_nonces.jsonl` (append-only, sealed-by-hash chain). Replay window is configurable per profile (`attestation_replay_window_minutes`, default 15). On startup, load nonces newer than the window; older ones are pruned. Tests: nonce issued before restart is still rejected on second use after restart; nonce older than the window is GC'd.

## Step v2-19 — Persist rate-limiter state and watchdog state

**Spec source:** `spec-phase1-gap-closure.md` §A11 (rate limit), `spec.md` watchdog section.

**Prompt for Claude Code:**

The `max_bundles_per_day` rate limiter from Step v2-05 is in-memory. Move it to the same `~/.invariant-bio/state/` directory used by Steps v2-08 and v2-18, sharing a single `StateStore` abstraction (single writer, fsync per append, hash-chained). Likewise persist watchdog timer state ([watchdog.rs](crates/invariant-biosynthesis-core/src/watchdog.rs)) so a watchdog firing during a crash is not lost. Reuse audit's hash-chain logic — do not reinvent. Add an `invariant-bio state inspect` CLI for operators.

## Step v2-20 — Webhook + syslog incident alert sinks

**Spec source:** `spec-phase2-operational.md` Step 4, `incident.rs`.

**Prompt for Claude Code:**

`incident.rs` only has a stdout sink. Add `WebhookSink` (POST JSON, retries as in Step v2-17) and `SyslogSink` (RFC 5424, UDP/TCP, structured `STRUCTURED-DATA` carrying the incident id, severity, and signed digest). Both are configured via env (`INVARIANT_BIO_INCIDENT_WEBHOOK`, `INVARIANT_BIO_INCIDENT_SYSLOG`) and via the new `incident_sinks` array in `BioProfile`. Failure to deliver to *any* configured sink for a `Severity::Critical` incident degrades the validator into a "fail-closed" state until the next successful send. Tests cover happy path, sink failure, and the fail-closed degradation.

## Step v2-21 — Runtime monitor CLI mode

**Spec source:** `spec-phase2-operational.md` Step 7, `monitors.rs`.

**Prompt for Claude Code:**

Add `invariant-bio monitor` that runs the registered `RuntimeMonitor`s ([monitors.rs](crates/invariant-biosynthesis-core/src/monitors.rs)) on a schedule and emits Prometheus exposition format on `0.0.0.0:9091/metrics` (configurable). Default monitors: audit-chain head age, replication lag (from v2-16), pending fragmentation sessions (v2-08), nonce store size (v2-18), failed-verdict rate over the last hour. Use `tiny_http` (no tokio) to keep the core dep surface minimal. The mode runs forever; SIGTERM flushes state and exits 0.

---

# Phase C — Real biology, real chemistry, real predictors

These add the optional heavy dependencies. Each is gated behind a cargo feature so the default build stays small.

## Step v2-22 — D-family: BLAST/HMMER homology screening

**Spec source:** `step3-bio-invariants.md` D1–D6, `spec-phase2-operational.md` Step 13, `spec-gap-analysis.md` §1.

**Prompt for Claude Code:**

Replace the regex hit-class evaluator in `dna.rs` D1–D6 with a real homology engine behind feature `homology`. Two strategies in one PR:

1. **HMMER subprocess** when `hmmscan` is on PATH. Pass translated 3-frame protein sequences to a profile DB shipped under `data/hmm/select_agent_v1.hmm` (download script in `scripts/`, signed manifest, not committed binary). Parse `--tblout` output. Bit-score thresholds per profile (calibrated GA cutoffs).
2. **Pure-Rust k-mer fallback** using `rust-bio` minimizers when HMMER is unavailable; emits `Severity::Advisory` instead of `High`/`Critical`, with a `homology_engine_status` advisory check identifying the fallback.

Wire `translate_dna_sequence()` into the homology engine across all 3 frames. Replace D7's hardcoded `[2.5, 5.8]` with the profile band from Step v2-05. Add the curated select-agent reference set in `tests/fixtures/select_agent_corpus/` and report FN/FP at the end of `cargo test`. Acceptance gate: FN ≤ 1e-4, FP ≤ 1e-3 (Clopper–Pearson), or the test suite fails.

## Step v2-23 — D9 ΔG via ViennaRNA

**Spec source:** `spec-phase2-operational.md` Step 11.

**Prompt for Claude Code:**

D9's rolling-hash hairpin detector approximates secondary structure. Behind feature `vienna`, link `librna` (ViennaRNA C library) via `bindgen` and replace D9 with a real ΔG screen at the spec-defined window size and step. Threshold per profile (`hairpin_dg_threshold_kcal_mol`, default −20.0). Without the feature, keep the existing detector but emit a `secondary_structure_engine_status` advisory check noting the approximation. Tests: known stable hairpin (e.g. tRNA cloverleaf) trips D9 with the real engine; benign sequence does not.

## Step v2-24 — C-family: `Molecule` type, RDKit, SMARTS rule library

**Spec source:** `step3-bio-invariants.md` C-family, `spec-phase2-operational.md` Step 12, `spec-gap-analysis.md` §2.

**Prompt for Claude Code:**

Three sub-tasks in one step (commit them as v2-24a/b/c if useful):

1. Introduce a `Molecule` type ([crates/invariant-biosynthesis-core/src/invariants/molecule.rs](crates/invariant-biosynthesis-core/src/invariants/molecule.rs) — file already exists, expand it). It owns `original_smiles: String`, `canonical_smiles: String`, `inchi_key: String`, `formula: String`, `mw: f64`. Construction from a raw SMILES string runs canonicalisation; parse failure is `Verdict::Block` with reason `chemical_smiles_uncanonical`.
2. Behind feature `rdkit`, link `rdkit-sys` and use it for canonicalisation, InChIKey, formula, MW, and substructure matching. Without the feature, use a heuristic canonicaliser (existing C-family code) and emit a `chemistry_engine_status` advisory check.
3. Move the SMARTS heuristics out of regex literals into `data/smarts/cwc_v1.smarts` (signed manifest, like the hazard DB). Loader is a `SmartsRuleSet` mirroring `HazardDatabase`. CWC schedules 1/2 and the NTA explosives list are the seed content.

Acceptance: known-positive molecules (CWC schedules) yield Fail; their structural isomers also Fail; benign isosters do not. Tests live in `tests/fixtures/chemical_corpus/`.

## Step v2-25 — P-family: real predictors for P5/P6/P8

**Spec source:** `spec-gap-analysis.md` §3, `step3-bio-invariants.md` peptide section.

**Prompt for Claude Code:**

Replace the regex/heuristic checks for P5 (active-site motif), P6 (MHC binding), and P8 (aggregation):

1. **P6** behind feature `mhc`: subprocess call to NetMHCpan (env `INVARIANT_BIO_NETMHCPAN_PATH`); without the binary, emit `Severity::Advisory` and tag the check with `predictor_unavailable`.
2. **P8** behind feature `aggregation`: bundle a small TANGO-equivalent scorer (or call out to TANGO if installed). Calibrate the cutoff against the bundled benchmark set; document the calibration in the rustdoc.
3. **P5**: until a structure-aware predictor lands, downgrade P5 to `Severity::Advisory` and add a check-level note `p5_structural_context_unavailable`.

Phase-out plan: keep the regex implementation as a fallback so the default build still ships P-family checks; the feature-gated predictors are upgrades, not replacements.

## Step v2-26 — Multi-publisher consensus & SecureDNA-style oblivious queries

**Spec source:** `step6-screening-databases.md`, `spec-gap-analysis.md` §1.5/§5.

**Prompt for Claude Code:**

Step v2-05 already constrained staleness. Now generalise the screener:

1. Validator config accepts a list of `HazardDatabase` instances and a `QuorumPolicy` (`Any`, `All`, `AtLeast(n)`). Default for production profiles is `AtLeast(2)` with at least two distinct publishers. Disagreement between publishers surfaces as a `screening_consensus` advisory check listing each publisher's verdict.
2. Behind feature `securedna`, add a `SecureDnaClient` that performs oblivious-query lookups against an upstream service. Without the feature, the client returns `Unavailable` and the consensus path falls back to local DBs only.

Tests: 2-of-3 publishers concur on Block → Block; 1-of-3 says Block under `AtLeast(2)` → Pass with advisory; under `Any` → Block.

---

# Phase D — Platform integration & execution tokens

## Step v2-27 — New `invariant-biosynthesis-platform` crate with `Platform` trait

**Spec source:** `step5-platform-integration.md`, `spec-gap-analysis.md` §9.

**Prompt for Claude Code:**

Create a new workspace crate `invariant-biosynthesis-platform`. Define a `Platform` trait with: `submit_token(&ExecutionToken) -> Result<Receipt>`, `fetch_attestation(&ReceiptId) -> Result<AttestedReading>`, `name() -> &'static str`, `supported_substrates() -> &[&str]`. Provide a `MockPlatform` for tests. Add the crate to the workspace Cargo.toml. The trait does **not** force tokio — implementations choose; the trait is sync with a blocking `Result`. Document the verification protocol an instrument-side library would implement.

## Step v2-28 — First vendor adapter: Twist DNA (or Emerald cloud lab)

**Spec source:** `spec-phase2-operational.md` Step 14, `step5-platform-integration.md`.

**Prompt for Claude Code:**

Implement `TwistPlatform` (or `EmeraldPlatform` if Twist's API requires NDA — pick the one with a public sandbox) inside `invariant-biosynthesis-platform`. HTTP transport via `ureq` (sync, no tokio). The adapter authenticates via API key from env, submits a payload that wraps the `ExecutionToken` in the vendor's order schema, and parses the receipt. Mock the vendor in tests with `httpmock`. Document the credential lifecycle and audit logging in the crate-level rustdoc.

## Step v2-29 — Execution-token issuance CLI

**Spec source:** `spec-gap-analysis.md` §9.2, `step5-platform-integration.md`.

**Prompt for Claude Code:**

Add `invariant-bio issue-token --bundle <path> --validity <duration>` that runs validate, and on Pass produces a signed `ExecutionToken` JSON. The token is detached from the bundle and verifiable offline by an instrument given the firewall public key. Document the verification protocol step-by-step in `docs/execution-token-protocol.md`. Audit log records token issuance with the bundle hash and validity window. Tests: issue, verify offline, verify expired token rejected, verify wrong-bundle token rejected.

## Step v2-30 — Reference instrument-side verifier

**Spec source:** `spec-gap-analysis.md` §9.3.

**Prompt for Claude Code:**

In `examples/instrument_verifier/`, write a small standalone Rust binary that takes (a) a firewall public key, (b) an execution token, (c) a synthesis bundle, and prints `OK` or a failure reason. The binary depends only on `invariant-biosynthesis-core`'s verification surface — it is what an instrument vendor would embed. Add a CI job that builds the example with `--no-default-features` to prove the verification surface is minimal.

## Step v2-31 — Second + third platform adapters: peptide (CEM Liberty) and chemical (Chemspeed)

**Spec source:** `spec-phase2-operational.md` Step 15.

**Prompt for Claude Code:**

Mirror v2-28 for one peptide vendor (CEM Liberty) and one chemical vendor (Chemspeed). Both adapters follow the `Platform` trait. Where the vendor lacks a public sandbox, ship only the adapter scaffolding plus a thorough mock test suite, and document the integration steps a customer would follow.

---

# Phase E — Compliance, regulatory, and auditor controls

## Step v2-32 — New `invariant-biosynthesis-compliance` crate

**Spec source:** `step9-regulatory-compliance.md`, `spec-gap-analysis.md` §12.

**Prompt for Claude Code:**

Create a workspace crate `invariant-biosynthesis-compliance`. Each jurisdiction is a module exposing a `ReportGenerator` trait: `generate(audit_window: AuditWindow, verdicts: &[Verdict]) -> Result<JurisdictionReport>`. Land report generators for: CDC Select Agent, NIH rDNA, FDA, USDA APHIS, EPA TSCA, CWC, ITAR, Australia Group, Wassenaar. Each report serializes to the agency-required schema (start with the closest published JSON/XML form; document where the schema is sourced from). CLI: `invariant-bio compliance report --jurisdiction <name> --since <ts> --until <ts>`.

## Step v2-33 — Auditor RBAC role and read-only audit accessor

**Spec source:** `spec-gap-analysis.md` §12.2.

**Prompt for Claude Code:**

Today any reader of the JSONL audit file sees everything. Introduce an `AuditAccessor` role authenticated against a separate keypair (kid prefix `auditor:`). Reads go through a `ReadGate` that filters fields per a per-jurisdiction redaction policy (e.g. internal threat scores hidden from a CDC accessor by default, visible to FDA). Auditor sessions are themselves audited (reader kid + filter + entry range). CLI: `invariant-bio audit read --as <kid> --jurisdiction <name>`.

## Step v2-34 — Per-jurisdiction profile variants and invariant gating

**Spec source:** `spec-gap-analysis.md` §12.3.

**Prompt for Claude Code:**

Add `jurisdictions: Vec<String>` to `BioProfile`. Each invariant declares the jurisdictions under which it is mandatory; under others it may be Advisory. Provide preset profiles `profiles/fda_pharma.json`, `profiles/usda_agri.json`, `profiles/cwc_chemical.json`. The validator skips or downgrades non-applicable invariants per the matrix. Document the matrix in `docs/jurisdiction_matrix.md`.

---

# Phase F — Testing rigor, statistical validation, performance

## Step v2-35 — Synthetic sequence corpora and FP/FN measurement harness

**Spec source:** `spec-gap-analysis.md` §11.1, `step8-testing-validation.md`.

**Prompt for Claude Code:**

Add `crates/invariant-biosynthesis-eval/src/corpora/` with generators that synthesize: (a) legitimate research sequences sampled from configurable codon-usage distributions; (b) known hazard variants (literal, codon-substituted, fragmented across N bundles); (c) adversarial near-misses. The harness runs the full validator across the corpora and reports FP/FN with Clopper–Pearson 95% confidence intervals. Output is JSON for machine consumption and a markdown summary for the PR.

## Step v2-36 — Statistical validation framework

**Spec source:** `spec-gap-analysis.md` §11.2.

**Prompt for Claude Code:**

Add a `stats` module to `invariant-biosynthesis-eval`: Clopper–Pearson, Wilson, exact binomial; power analysis for a given target FN/FP; Bayesian update of the rate estimate as new corpora roll in. Used by Step v2-35 and v2-22 acceptance gates. No new heavy dep — pure Rust (`statrs` is acceptable).

## Step v2-37 — Property-based tests for D-, P-, C-, PR-families

**Spec source:** `spec-phase1-gap-closure.md` §A12.

**Prompt for Claude Code:**

Add `proptest` to dev-dependencies. For each invariant family, write generators that produce in-distribution inputs (well-formed DNA/peptide/SMILES/protocol) and assert invariants the spec promises (e.g. canonicalisation idempotency, codon translation round-trip, hazard-class normalisation idempotency). Run with the default 256 cases; failure shrinks to a minimal counterexample. Target ≥ 30 properties total.

## Step v2-38 — Cargo-fuzz targets

**Spec source:** `step8-testing-validation.md`, `spec-gap-analysis.md` §11.

**Prompt for Claude Code:**

Add `crates/invariant-biosynthesis-fuzz/fuzz/` with libFuzzer targets for: COSE envelope parsing, profile JSON parsing, SMILES parsing, hazard DB JSON parsing, and the canonical-JSON round trip from Step v2-10. Document a minute-budget run (`cargo fuzz run <target> -- -max_total_time=60`) and wire it into a nightly CI job.

## Step v2-39 — Shadow-mode evaluation infrastructure

**Spec source:** `spec-gap-analysis.md` §11.3.

**Prompt for Claude Code:**

Add an `invariant-bio shadow` mode that consumes a stream of bundles (from a JSONL file or stdin), produces verdicts in parallel with a (file-supplied) expert-review verdict, and reports per-check agreement rates with confidence intervals. Spec target: ≥99% agreement on borderline cases over a documented N. The output is the artefact a release manager attaches to a "production-ready" claim.

## Step v2-40 — Performance benches with `criterion`

**Spec source:** `spec-phase2-operational.md` Step 17.

**Prompt for Claude Code:**

Add `benches/` with criterion benches for: validate (small/medium/large bundle), audit append (single + 10k batch), differential overhead, S1 stateful detector under N concurrent sessions. Publish results as a markdown table in `docs/performance.md`. Set regression budgets (criterion baseline) so CI fails on > 10% slowdown.

## Step v2-41 — Differential E2E and audit replication E2E tests

**Spec source:** `spec-phase2-operational.md` Step 18.

**Prompt for Claude Code:**

Add integration tests that boot two `Validator` instances in-process, sync their audit logs via `S3Replicator` (against localstack from Step v2-16), and assert convergence after a series of mixed bundles. Also: differential mode produces a verdict with both validators in agreement on the example bundles in `examples/`, and divergence is caught when one validator is stubbed.

---

# Phase G — Release engineering, ecosystem, governance

## Step v2-42 — Release workflow + signed binary artifacts

**Spec source:** `spec-phase2-operational.md` Step 19.

**Prompt for Claude Code:**

Add `.github/workflows/release.yml` (no, wait — this repo may use a different CI). Detect the existing CI provider and add a release pipeline that, on a `v*` tag: builds linux-x86_64, linux-aarch64, macos-x86_64, macos-aarch64, windows-x86_64 binaries; runs the test suite; signs the artifacts with `cosign` (keyless OIDC against the project Sigstore root); uploads to the release; publishes a checksums file. Documented release procedure in `docs/release-procedure.md`.

## Step v2-43 — MSRV verification and pinned workspace dependencies

**Spec source:** `spec-phase1-gap-closure.md` §A16/§A17.

**Prompt for Claude Code:**

Pin MSRV in `rust-toolchain.toml` to a specific stable version and assert it in CI (`cargo +msrv check --workspace`). Pin every workspace dependency to an exact version (no `^` ranges) and document an upgrade procedure in `docs/dependency-policy.md`. Add `cargo deny check` as a CI gate (already configured in `deny.toml` — extend to ban `*` versions).

## Step v2-44 — Pre-audit hardening pass

**Spec source:** `spec-phase2-operational.md` Step 20.

**Prompt for Claude Code:**

A focused audit-readiness pass: (a) run `cargo geiger` and confirm zero unsafe in the workspace; (b) run `cargo audit` and resolve any open advisories; (c) review every `unwrap()` / `expect()` in non-test code and either justify with a comment or replace with a typed error; (d) confirm every public item has rustdoc; (e) run `cargo doc --no-deps --workspace` and resolve all broken intra-doc links.

## Step v2-45 — Export-control CI check + responsible-disclosure SLA

**Spec source:** `spec-gap-analysis.md` §13.

**Prompt for Claude Code:**

Two governance items:

1. Extend `deny.toml` (or add a sibling tool) to flag dependencies whose origin or maintainer is on a sanctions or export-control list. The check is best-effort but documented and runs in CI.
2. Update `SECURITY.md` with a responsible-disclosure SLA (acknowledge in 72h, mitigation timeline, CVE issuance commitment) and an RFC process in a new `docs/rfc-process.md`.

---

# Acceptance gates for spec-v2

A release may claim **"production-ready for synthesis"** only when every item below is true. Each is testable; each maps to one or more steps above.

1. Phase A and Phase B fully landed; CI green on all relevant suites.
2. At least one HSM backend (Steps v2-12/13) in production use; file-backed keys disabled in the production preset.
3. The select-agent reference set (Step v2-22) reports FN ≤ 1e-4 and FP ≤ 1e-3 with published Clopper–Pearson bounds.
4. Shadow-mode (Step v2-39) reports ≥ 99% agreement with expert review on borderline cases over a documented N.
5. At least one synthesiser vendor (Step v2-28 or v2-31) verifies execution tokens end-to-end against the reference instrument-side verifier (Step v2-30).
6. At least one jurisdiction's compliance report (Step v2-32) has been accepted by counsel.
7. The pre-audit hardening pass (Step v2-44) is clean.

Until then, the codebase is a sound reference implementation and a clean integration surface — not a deployable firewall.

---

# Notes on ordering and parallelism

- Phase A is strictly sequential within itself (each step touches the validator pipeline) and must land before any other phase begins.
- Phase B steps v2-12/13/14/15 (HSM family) can run in parallel with v2-16/17/18/19 (replication/state family).
- Phase C steps v2-22/23/24/25 are independent and can be parallelised across contributors.
- Phase D depends on Phase B (key store) but is independent of Phase C.
- Phase E depends on Phase A only.
- Phase F can begin as soon as Phase A is in.
- Phase G runs at the end.

# Out-of-scope for spec-v2 (deferred to a future spec-v3)

- HSM-backed firmware attestation of synthesisers themselves (vendor-side work).
- Federated-learning-style hazard-DB updates across firewalls.
- A web UI; the CLI is the supported surface.
- Non-Rust client SDKs.
