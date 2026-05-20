> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# spec-v3 — Authoritative Remaining Gap Closure

**Status:** Active working document, 2026-05-02
**Branch at time of audit:** codelicious/spec-spec-gap-analysis-part-2
**Supersedes:** spec-v2.md (kept for reference; completed items are documented there)
**Scope:** This spec is the result of a fresh, file-by-file audit of the Rust workspace at the commit described above. It catalogs every spec-v2 step as Done / Partial / Not-Started with exact file and line citations, then prescribes actionable follow-up steps. Every item listed here is either a partial that needs finishing, a gap spec-v2 missed entirely, or a new gap discovered during this audit.

---

## 1. Audit Summary Table

The following table covers all 45 steps from spec-v2.md (v2-01 through v2-45) plus a set of new gaps not captured in spec-v2.

| Step | Title | Status | Evidence |
|------|-------|--------|----------|
| v2-01 | Re-baseline / working branch | Done | Current branch is codelicious/spec-spec-gap-analysis-part-2; 647 tests pass, clippy clean |
| v2-02 | Wire validator into audit log by default | Not-Started | validator.rs:1–1211: no `Option<Arc<AuditLogger>>` field on ValidatorConfig; caller still does manual append |
| v2-03 | Verify profile signatures on load | Not-Started | profile.rs:32–76: fields `profile_signature` / `profile_signer_kid` exist but no verification path anywhere in profiles.rs or validator.rs |
| v2-04 | Stale screening fail-closed unconditionally in production | Done | validator.rs:407–443: `is_production_profile` called; production always blocks on stale; `allow_stale_screening` respected only for non-production |
| v2-05 | BioProfile schema additions and enforcement | Partial | profile.rs:53–76: `protein_kmer_k`, `protein_kmer_threshold`, `allow_stale_screening`, `stale_screening_max_days`, `max_authority_chain_depth` all present. MISSING: `required_attestation_kinds`, `max_bundles_per_day`, `expires_at` on bundle, `bundle_version`, `rotation_overlap_days`, `attestation_replay_window_minutes`, `hairpin_dg_threshold_kcal_mol`, `incident_sinks` |
| v2-06 | PR2 verb vocabulary wired to BioProfile | Done | protocol.rs:59–61: `is_builtin_verb` exists; profile.rs:135–146: `allowed_protocol_steps` validated against builtin list; protocol.rs:80–130: PR2 uses `ctx.profile.allowed_protocol_steps.as_deref()` to replace the default |
| v2-07 | Threat scorer wired into validator pipeline | Partial | validator.rs:99–108, 639–675: `with_threat_scorer` builder exists and fires when set; BUT scorer is NOT default-on for production profiles — it remains opt-in |
| v2-08 | S1 stateful fragmentation detector default-on | Partial | validator.rs:109, 616–636: `with_stateful_detector` builder exists and fires; BUT not default-on; no persistence to `~/.invariant-bio/state/fragmentation.jsonl`; no `state prune` CLI subcommand |
| v2-09 | Typed `Evidence` enum / HazardClass normalisation | Not-Started | invariants/mod.rs:250–276: `InvariantStatus` returns free-form String for `Fail.reason`, `Advisory.note`; no `Evidence` enum; chemical.rs:77–86 and dna.rs:37–46: hazard-class matching is case-sensitive substring, no `HazardClass` newtype |
| v2-10 | kid validation, COSE reserved keys, canonical JSON | Partial | keygen.rs:23: `validate_kid` exists in CLI; validator.rs uses `sha256_hex_json` but it is insertion-order serde_json, not sorted-key canonical JSON; no COSE reserved-key enforcement |
| v2-11 | Differential validation wired into standard validate flow | Partial | differential.rs fully implemented as a library; CLI `differential` subcommand exists (differential.rs compares two pre-existing verdict files); BUT `--differential` flag is absent from `validate` subcommand; production-profile implicit differential is NOT implemented |
| v2-12 | TPM 2.0 key-store backend | Not-Started | keys.rs: `InMemoryKeyStore` only; no `TpmKeyStore`; no `tpm` cargo feature |
| v2-13 | YubiHSM 2 and OS keyring backends | Not-Started | absent |
| v2-14 | FROST key ceremony CLI | Not-Started | keygen.rs implements only `keygen --kid --output`; no `ceremony init/contribute/finalize` |
| v2-15 | Key rotation with overlap window | Not-Started | no `rotate` subcommand; no `rotation_overlap_days` in BioProfile |
| v2-16 | S3 replication backend | Not-Started | replication.rs: `FileReplicator` stub + `MerkleTree` + `WitnessRecord`; `S3Replicator` absent; no `s3` cargo feature |
| v2-17 | Webhook Merkle witness + cross-instance reconciliation | Not-Started | replication.rs: `WitnessRecord` struct and `merkle_root` exist; no `WebhookWitness`; no `audit reconcile` CLI |
| v2-18 | Persist attestation nonces across restarts | Not-Started | attestation.rs:19–34: nonce cache is in-memory `VecDeque`; no JSONL persistence |
| v2-19 | Persist rate-limiter and watchdog state | Not-Started | no `max_bundles_per_day` rate limiter; no `StateStore` abstraction; watchdog.rs is a type stub |
| v2-20 | Webhook + syslog incident alert sinks | Not-Started | incident.rs: stdout sink only; no `WebhookSink`; no `SyslogSink`; no `incident_sinks` in BioProfile |
| v2-21 | Runtime monitor CLI mode | Not-Started | monitors.rs has monitor structs; no `invariant-bio monitor` subcommand; no Prometheus exposition |
| v2-22 | D-family: BLAST/HMMER homology screening | Not-Started | dna.rs: k-mer heuristic engine present (lines 60–200); no HMMER subprocess path; no `homology` cargo feature; no select-agent reference corpus |
| v2-23 | D9 delta-G via ViennaRNA | Not-Started | dna.rs: rolling-hash hairpin approximation present; no `vienna` feature; no `hairpin_dg_threshold_kcal_mol` in BioProfile |
| v2-24 | Molecule type, RDKit, SMARTS rule library | Partial | models/molecule.rs: `Molecule` type implemented (bracket balance + char set validation); chemical_rules.rs: `ChemicalRuleSet` declared; BUT no InChI key / formula / MW fields on Molecule; no `rdkit` feature; SMARTS rules embedded as inline rules in chemical_rules.rs rather than loaded from signed `data/smarts/cwc_v1.smarts` file |
| v2-25 | P-family real predictors for P5/P6/P8 | Not-Started | peptide.rs: P5/P6/P8 are heuristic regex/window checks; no `mhc`/`aggregation` features; no NetMHCpan / TANGO subprocess paths |
| v2-26 | Multi-publisher consensus and SecureDNA oblivious queries | Partial | screening/mod.rs: `ConsensusHazardScreener` + `QuorumPolicy` fully implemented; BUT no `securedna` feature/client; no `SecureDnaClient` struct |
| v2-27 | New `invariant-biosynthesis-platform` crate | Not-Started | absent from workspace |
| v2-28 | First vendor adapter (Twist or Emerald) | Not-Started | absent |
| v2-29 | Execution-token issuance CLI | Not-Started | models/execution_token.rs: `ExecutionToken` type exists but is a bare data type with no signing logic; no `issue-token` CLI subcommand |
| v2-30 | Reference instrument-side verifier | Not-Started | absent from `examples/` |
| v2-31 | Second + third platform adapters (CEM, Chemspeed) | Not-Started | absent |
| v2-32 | New `invariant-biosynthesis-compliance` crate | Not-Started | absent from workspace |
| v2-33 | Auditor RBAC + ReadGate | Not-Started | audit.rs: no `AuditAccessor` role; no `ReadGate`; no `audit read` CLI |
| v2-34 | Per-jurisdiction profile variants | Not-Started | BioProfile has no `jurisdictions` field; no preset profiles; no matrix doc |
| v2-35 | Synthetic sequence corpora + FP/FN harness | Not-Started | eval crate: lib.rs is a skeleton |
| v2-36 | Statistical validation framework | Not-Started | no `stats` module in eval crate |
| v2-37 | Property-based tests (proptest) | Not-Started | no `proptest` in any dev-dependencies |
| v2-38 | Cargo-fuzz targets | Not-Started | fuzz crate: adversarial attack suites exist but no `fuzz/` directory with libFuzzer targets |
| v2-39 | Shadow-mode evaluation | Not-Started | no `invariant-bio shadow` subcommand |
| v2-40 | Criterion performance benches | Not-Started | no `benches/` directory |
| v2-41 | Differential E2E + audit replication E2E tests | Partial | tests/differential_e2e.rs exists; tests/audit_replication_e2e.rs exists but requires localstack — may be skipped in CI; no S3Replicator yet so the E2E is incomplete |
| v2-42 | Release workflow + signed binary artifacts | Not-Started | no `.github/workflows/release.yml` or equivalent |
| v2-43 | MSRV verification + pinned workspace deps | Not-Started | no `rust-toolchain.toml`; no `deny.toml` checked |
| v2-44 | Pre-audit hardening pass | Not-Started | unwrap() calls exist in non-test non-production paths (e.g. validator.rs:705 `expect("threat scorer mutex poisoned")`) |
| v2-45 | Export-control CI check + responsible-disclosure SLA | Not-Started | no `SECURITY.md`; no `rfc-process.md` |

### New gaps found beyond spec-v2 scope

| Gap id | Description | File / evidence |
|--------|-------------|-----------------|
| N-01 | `canonical_json` uses serde insertion order, not sorted-key form — every signing path is fragile | util.rs:17–38 |
| N-02 | `AuditLogger` is not owned by `Validator`; L1-completeness is caller responsibility | validator.rs entire file |
| N-03 | `ExecutionToken` has no signing constructor; issuance is impossible without external glue | models/execution_token.rs:17–32 |
| N-04 | Profile load does not verify `profile_signature` even when field is present | profiles.rs:42–47 |
| N-05 | `validate` CLI constructs a fresh ephemeral signing key on every run (no key file flag) | validate.rs:94 |
| N-06 | `HazardClass` matching is done as raw `to_ascii_lowercase()` string comparison without normalisation (dash vs underscore) | dna.rs:37–46, chemical.rs:77–86 |
| N-07 | All CLI subcommands lack `--help` integration tests | commands/mod.rs |
| N-08 | No `rust-toolchain.toml` so MSRV is undeclared and could silently drift | repo root |
| N-09 | `models/execution_token.rs` has no `valid_until` / expiry field, so tokens cannot expire | execution_token.rs:17–32 |
| N-10 | `invariant-bio validate` CLI `default_profile()` is bsl_level=2 but exported as "cli-default" — matches `is_production_profile` rule (not `test_`/`dev_`; bsl=2) so it behaves as production and threat scorer will be absent by default | validate.rs:171–195 |
| N-11 | `Molecule` struct lacks `inchi_key`, `formula`, `mw` fields promised by spec-v2 §24.1 | models/molecule.rs:67–71 |
| N-12 | `chemical_rules.rs` rule library has no file-backed signed loader; rules are programmatic, not signable | chemical_rules.rs:57–200 |
| N-13 | `BioProfile.allowed_protocol_steps` entries are validated against `is_builtin_verb` but there is no test for a profile-restricted bundle in a real validator run | protocol.rs; no fixture `restricted_protocol.json` |
| N-14 | `validate` CLI exit-code 2 is advisory-only but only checks invariant results, not screening or authority advisories | validate.rs:150–165 |
| N-15 | `screening/mod.rs` `ConsensusHazardScreener` not wired into any default validator; operators must construct manually | screening/mod.rs: no validator integration |

---

## 2. Ground rules

These apply to every step below without exception.

- Preserve `#![forbid(unsafe_code)]` in every crate touched.
- After every code-changing step run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings`. Do not advance to the next step until all three pass.
- One commit per step, prefixed with the step id (e.g. `v3-01: <subject>`). Never push directly to `main`.
- New top-level dependencies require a feature flag or explicit justification in the commit message. Phases A and B may add no new heavy dependencies beyond `proptest` for testing.
- When a step changes `BioProfile`, also update every JSON file under `profiles/` and every fixture under `examples/` and confirm `cargo test` still passes.
- When a step adds a CLI subcommand, also add a `--help` integration test and a one-line entry in `README.md`.
- Update `docs/spec-gap-analysis.md` (mark the matching gap closed) and `CHANGELOG.md` in the same commit as the code change.

---

## 3. Phases and steps

### Phase A — Correctness and wiring gaps (no new heavy deps, highest priority)

These close logic errors and missing wirings. All are blocking for any production claim.

---

#### v3-01 — Pin canonical JSON to sorted-key form

**Spec source:** spec-v2.md §v2-10; gap N-01 above.

**Current state:** `crates/invariant-biosynthesis-core/src/util.rs` line 17 uses `serde_json::Serializer` which produces insertion-order JSON. Every signing path — PCA chain signatures, audit entry signatures, verdict signatures, profile-signature verification (once added) — ultimately calls `sha256_hex_json`. Two semantically identical values where field order differs at the Rust struct layout level could produce different hashes if struct field order ever changes across recompiles or Rust versions.

**Prompt for Claude Code:** You are implementing step v3-01 in the invariant-biosynthesis workspace. Your task is to replace the current `sha256_hex_json` implementation in `crates/invariant-biosynthesis-core/src/util.rs` with a canonical form that sorts object keys lexicographically, uses no whitespace, and NFC-normalises strings. Do not add new external crates: implement sorting by first serialising to `serde_json::Value`, recursively sorting all object keys, then serialising that sorted value through the existing hash writer. Expose a separate `canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>, serde_json::Error>` helper (also using sorted keys) that signing paths can use when they need the bytes rather than just the hash. All existing signing paths in `audit.rs`, `validator.rs`, `attestation.rs`, `authority/`, `screening/mod.rs`, and `bundle.rs` must continue to call `sha256_hex_json` (or, for the bytes variant, `canonical_json_bytes`) — do not change their call sites unless required. Add a unit test that constructs two `serde_json::Value::Object` maps with the same keys and values but declared in opposite insertion order and asserts that `sha256_hex_json` produces byte-identical results for both. Add a second property-style test with at least three structurally equal JSON values that differ only in field declaration order. Keep `#![forbid(unsafe_code)]`. Run `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, then commit as `v3-01: pin canonical JSON to sorted-key form`.

---

#### v3-02 — Wire `AuditLogger` into `ValidatorConfig` by default

**Spec source:** spec-v2.md §v2-02; gap N-02 above.

**Current state:** `crates/invariant-biosynthesis-core/src/validator.rs` owns no `AuditLogger`. The CLI `validate` command does not call `AuditLogger::append` at all (see `validate.rs` lines 94–107). Library consumers that forget to append lose L1 completeness silently.

**Prompt for Claude Code:** You are implementing step v3-02 in the invariant-biosynthesis workspace. Extend `ValidatorConfig` in `crates/invariant-biosynthesis-core/src/validator.rs` with an optional field `audit_logger: Option<Arc<Mutex<AuditLogger>>>`. Add a builder method `with_audit_logger(logger: Arc<Mutex<AuditLogger>>) -> Self`. Inside `validate_inner`, after the signed verdict is assembled (currently around line 700), if `audit_logger` is `Some`, acquire the lock, call `logger.log(&bundle, &out.signed_verdict)`, and map any `AuditError` to `ValidatorError::Serialization` — do not swallow it. Do not call `AuditLogger::append` (a lower-level method) directly; use the `log` method that already exists. Add the following tests inside the existing `#[cfg(test)]` block: (a) a validator without a logger produces a valid verdict and does not panic; (b) a validator with a logger appended to a `Vec<u8>` sink produces exactly one JSONL line per `validate` call; (c) an `AuditLogger` that returns `Err` on write is surfaced as `ValidatorError::Serialization`. Update the CLI `validate` command (`crates/invariant-biosynthesis-cli/src/commands/validate.rs`) to construct an `AuditLogger` writing to `~/.invariant-bio/audit/default.jsonl` (mode 0o600, created with `std::fs::create_dir_all` on the parent) and pass it via `with_audit_logger`. The key for signing audit entries should be the same ephemeral signing key used by the validator; document in a rustdoc comment that production deployments should persist this key (covered by a later step). Keep `#![forbid(unsafe_code)]`. Run the full suite and commit as `v3-02: wire AuditLogger into ValidatorConfig`.

---

#### v3-03 — Verify `profile_signature` on load (fail-closed for production profiles)

**Spec source:** spec-v2.md §v2-03; gap N-04 above.

**Current state:** `crates/invariant-biosynthesis-core/src/models/profile.rs` carries `profile_signature: Option<String>` and `profile_signer_kid: Option<String>` (lines 32–36) but the `Validate` impl (lines 82–180) never checks them. `profiles.rs` loads builtin profiles without any signature verification.

**Prompt for Claude Code:** You are implementing step v3-03 in the invariant-biosynthesis workspace. Add a `ProfileLoader` struct to `crates/invariant-biosynthesis-core/src/profiles.rs`. It holds an optional `HashMap<String, VerifyingKey>` representing trusted profile-signer public keys. Add a method `ProfileLoader::load_profile(json: &str) -> Result<BioProfile, ProfileLoadError>` where `ProfileLoadError` is a new `thiserror`-derived error type in the same file with variants: `ParseError(serde_json::Error)`, `SignatureRequired { name: String }`, `UnknownSigner { kid: String }`, `SignatureInvalid { reason: String }`, `ValidationError(#[from] ValidationError)`. The loading logic is: (1) parse the JSON; (2) call `BioProfile::validate()`; (3) if `profile_signature` and `profile_signer_kid` are both present, look up the key in the trusted map, compute `canonical_json_bytes` of the profile with `profile_signature` set to the empty string and `profile_signer_kid` left as-is, and verify the Ed25519 signature; (4) if either field is absent and `is_production_profile` returns true for the loaded profile, return `ProfileLoadError::SignatureRequired`. If both fields are absent and the profile is non-production, proceed without verification. Expose a `ProfileLoader::new_permissive()` constructor that carries no trusted keys and never rejects unsigned profiles — for use in tests and the dev CLI path. Update the CLI `validate` subcommand to use `ProfileLoader` when `--profile` is supplied; for the built-in default profile, use `ProfileLoader::new_permissive()`. Add tests: signed-good loads, signed-bad-signature rejects with `SignatureInvalid`, unsigned-bsl4 profile rejects with `SignatureRequired`, unsigned-bsl1-non-export loads with permissive loader. Keep `#![forbid(unsafe_code)]`. Commit as `v3-03: verify profile_signature on load`.

---

#### v3-04 — Normalise hazard-class matching with `HazardClass` newtype

**Spec source:** spec-v2.md §v2-09 (second half); gap N-06 above.

**Current state:** `dna.rs` lines 37–46 and `chemical.rs` lines 77–86 both do `to_ascii_lowercase()` string equality on hazard class strings. The constants use dash-separated forms (`"select-agent"`) but profile JSON and external databases may use underscore or mixed-case. There is no normalisation of whitespace or separators.

**Prompt for Claude Code:** You are implementing step v3-04 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-core/src/invariants/mod.rs`, add a `HazardClass` newtype wrapping a `String`. Provide a `HazardClass::parse(raw: &str) -> HazardClass` constructor that lowercases the input, replaces hyphens, spaces, and forward-slashes with underscores, and collapses consecutive underscores to one. Implement `PartialEq`, `Eq`, `Hash`, `Display`, and `serde::Serialize`/`Deserialize` (round-trip through the raw string). In `dna.rs`, `peptide.rs`, and `chemical.rs`, replace every raw hazard-class comparison slice (the `hits_in_classes` helper and the constant arrays) with `HazardClass::parse`-normalised comparisons on both sides. Also normalise `HazardEntry::hazard_class` on load in `screening/mod.rs` so the DB entries go through `HazardClass::parse`. Add unit tests that confirm `HazardClass::parse("Select-Agent") == HazardClass::parse("select_agent") == HazardClass::parse("SELECT AGENT")`. Add a property-style test that idempotency holds: `parse(parse(x).to_string()) == parse(x)` for a representative set of inputs. Keep `#![forbid(unsafe_code)]`. Do not change any public API beyond adding the new type. Run the full suite and commit as `v3-04: normalise hazard-class matching with HazardClass newtype`.

---

#### v3-05 — Typed `Evidence` enum replacing free-form strings

**Spec source:** spec-v2.md §v2-09 (first half).

**Current state:** `InvariantStatus::Fail { reason: String }` and `InvariantStatus::Advisory { note: String }` carry unstructured strings. Downstream code (CLI rendering, threat scorer) parses substrings to reason about what triggered a check. This makes invariant output fragile against wording changes.

**Prompt for Claude Code:** You are implementing step v3-05 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-core/src/invariants/mod.rs`, introduce an `Evidence` enum with variants: `HazardHit { class: HazardClass, entry_id: String }`, `Window { start: usize, end: usize, score: Option<f64> }`, `Score { metric: String, value: f64, threshold: f64 }`, `StructuralAlert { rule_id: String, description: String }`, `External { kind: String, payload: String }`, `Simple { message: String }`. All variants are `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]`. Change `InvariantStatus::Fail` to carry `evidence: Vec<Evidence>` instead of `reason: String`. Change `InvariantStatus::Advisory` to carry `evidence: Vec<Evidence>` instead of `note: String`. Provide a `to_human_string(&self) -> String` method on `Evidence` that CLI rendering calls. Migrate all 34 invariant implementations in `dna.rs`, `peptide.rs`, `chemical.rs`, and `protocol.rs` to use the typed evidence. For existing implementations that produce a simple message, use `Evidence::Simple { message }`. For implementations that fire on a hazard-database hit, use `Evidence::HazardHit`. For score-based checks (D7, D8, D9, P6, P8), use `Evidence::Score`. Update `validator.rs` to render `InvariantStatus::Fail.evidence` and `Advisory.evidence` via `to_human_string` for the `CheckResult.details` field. Add tests that `InvariantStatus` round-trips through serde JSON, that `to_human_string` is non-empty for all Evidence variants, and that the existing validator tests still produce the same count of checks. Keep `#![forbid(unsafe_code)]`. Commit as `v3-05: typed Evidence enum for invariant results`.

---

#### v3-06 — Make threat scorer default-on for production profiles

**Spec source:** spec-v2.md §v2-07; audit finding for v2-07 above.

**Current state:** `ValidatorConfig::new` (validator.rs line 138) sets `threat_scorer: None`. The scorer is only active when the caller calls `with_threat_scorer`. For production profiles this violates the spec intent.

**Prompt for Claude Code:** You are implementing step v3-06 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-core/src/validator.rs`, change `ValidatorConfig::new` so that when `is_production_profile(&profile)` returns true it automatically constructs `ThreatScorer::with_defaults()` and stores it in `threat_scorer`. Add a builder method `with_no_threat_scorer() -> Self` that forces `threat_scorer = None` — this is used by tests and by non-production callers that deliberately opt out. Update the `with_threat_scorer` builder to replace whatever default was set. Add the following tests: (a) a validator built with a production profile (`bsl_level >= 2`, non-`test_`/`dev_` name) emits a `threat_analysis` check in the verdict without any explicit `with_threat_scorer` call; (b) `with_no_threat_scorer` suppresses the check even on a production profile; (c) the existing tests that use `test_profile` or `dev_*` names still pass because `is_production_profile` returns false for them. Update the CLI `validate` subcommand: remove any explicit `with_threat_scorer` call if present; add a comment explaining the implicit default. Keep `#![forbid(unsafe_code)]`. Commit as `v3-06: threat scorer default-on for production profiles`.

---

#### v3-07 — `validate` CLI uses a persistent signing key file

**Spec source:** gap N-05 above.

**Current state:** `crates/invariant-biosynthesis-cli/src/commands/validate.rs` line 94 calls `generate_keypair(&mut OsRng)` on every invocation, producing a fresh ephemeral key. Verdict signatures are therefore unverifiable after the process exits.

**Prompt for Claude Code:** You are implementing step v3-07 in the invariant-biosynthesis workspace. Add a `--signing-key <PATH>` argument to `ValidateArgs` in `crates/invariant-biosynthesis-cli/src/commands/validate.rs`. When the argument is supplied, load the key file at that path using `crate::key_file::load_key_file` and decode it via `load_signing_key`. When the argument is absent, generate an ephemeral key (preserving current behaviour) and emit a `stderr` warning: "no --signing-key provided; verdict signatures are ephemeral and cannot be verified offline". Do not change the default behaviour in terms of correctness — the validator still works without a key file. Add a CLI integration test that passes a generated key file via `--signing-key`, validates a bundle, reads the output verdict, and asserts that `signer_kid` matches the kid in the key file. Keep `#![forbid(unsafe_code)]`. Commit as `v3-07: validate CLI uses persistent signing key file`.

---

#### v3-08 — `required_attestation_kinds`, `max_bundles_per_day`, bundle `expires_at` and `bundle_version`

**Spec source:** spec-v2.md §v2-05 (remaining fields).

**Current state:** `BioProfile` is missing `required_attestation_kinds`, `max_bundles_per_day`, `rotation_overlap_days`, `attestation_replay_window_minutes`, `hairpin_dg_threshold_kcal_mol`, and `incident_sinks`. `SynthesisBundle` in `crates/invariant-biosynthesis-core/src/models/bundle.rs` is missing `expires_at` and `bundle_version`.

**Prompt for Claude Code:** You are implementing step v3-08 in the invariant-biosynthesis workspace. Add the following optional fields to `BioProfile` in `crates/invariant-biosynthesis-core/src/models/profile.rs`, all `#[serde(default, skip_serializing_if = "...")]` so existing profile JSON remains valid: `required_attestation_kinds: Vec<String>` (default empty), `max_bundles_per_day: Option<u32>`, `rotation_overlap_days: Option<u32>` (default 14 if absent, used by key rotation steps), `attestation_replay_window_minutes: Option<u32>` (default 15), `hairpin_dg_threshold_kcal_mol: Option<f64>` (default negative 20.0), `incident_sinks: Vec<String>` (default empty). Add `expires_at: Option<chrono::DateTime<chrono::Utc>>` and `bundle_version: Option<u8>` to `SynthesisBundle`. In `validator.rs` validate_inner, after the authority check: if `bundle.expires_at` is `Some(t)` and `t < now`, emit a failing `CheckResult` named `bundle_expired` and set `approved = false`. If `profile.required_attestation_kinds` is non-empty, for each named kind check that `attested_inputs` contains at least one entry whose `source` starts with that kind; missing kinds produce a failing `screening_attestation_missing_kind` check. In-memory rate limiter: add a `rate_limiter: Option<Arc<Mutex<InMemoryRateLimiter>>>` field to `ValidatorConfig`; `InMemoryRateLimiter` is a new struct in a `rate_limit.rs` module that counts bundles per principal per UTC day keyed on the PCA chain root kid; when `max_bundles_per_day` is set on the profile, the rate limiter is auto-constructed and checked. Add profile-validation checks: `hairpin_dg_threshold_kcal_mol` must be finite and negative; `attestation_replay_window_minutes` must be 1..=1440. Update all six profile JSON files under `profiles/` to explicitly declare the new fields. Add tests covering each new enforcement point. Keep `#![forbid(unsafe_code)]`. Commit as `v3-08: BioProfile and bundle schema additions`.

---

#### v3-09 — `--differential` flag on `validate`; implicit differential for production profiles

**Spec source:** spec-v2.md §v2-11.

**Current state:** `differential.rs` in the core crate implements `DifferentialValidator` and `compare_verdicts` fully. The CLI `differential` subcommand compares two pre-existing verdict files. But `validate` has no `--differential` flag, and there is no implicit dual-run for production profiles.

**Prompt for Claude Code:** You are implementing step v3-09 in the invariant-biosynthesis workspace. Add a `--differential` boolean flag to `ValidateArgs` in `crates/invariant-biosynthesis-cli/src/commands/validate.rs`. When the flag is set (or when `is_production_profile` returns true for the loaded profile), build a second `ValidatorConfig` with an independent signing key and the same profile and hazard DB, run `DifferentialValidator::new(&cfg_a, &cfg_b).validate(&bundle, now)`, and include the `DifferentialResult` in the output. If `!result.fully_agrees()`, degrade the final exit code by one tier (0 to 1, 1 stays 1) and print the disagreements to stderr. If the differential run reveals disagreement on `approved`, always exit 1 regardless of the individual verdicts. Expose `DifferentialResult` in the verdict output JSON under a `differential` key, or write it to a separate `--differential-report <PATH>` file when that argument is supplied. Add a rustdoc comment on the `validate` function explaining the IEC 61508 SIL 2 framing. Add integration tests: same validator twice with the same bundle produces `fully_agrees = true`; a validator with a buggy stub (inject by passing a `with_hazard_db` on one instance and not the other) produces `fully_agrees = false` and exit code 1. Keep `#![forbid(unsafe_code)]`. Commit as `v3-09: --differential flag on validate; implicit for production profiles`.

---

#### v3-10 — `kid` string validation at all entry points

**Spec source:** spec-v2.md §v2-10 (first point).

**Current state:** `keygen.rs` in the CLI calls `validate_kid`, but `ValidatorConfig::new` only checks that `signer_kid` is non-empty (validator.rs line 120–123). Hazard DB `issuer_kid` is accepted without format validation (screening/mod.rs). Audit entry `signer_kid` is set from the caller without validation.

**Prompt for Claude Code:** You are implementing step v3-10 in the invariant-biosynthesis workspace. Move the `validate_kid` function from `crates/invariant-biosynthesis-cli/src/key_file.rs` into `crates/invariant-biosynthesis-core/src/keys.rs` (or a new `crates/invariant-biosynthesis-core/src/kid.rs` module) so it is usable from the core crate. The constraint is: 8 to 64 ASCII characters drawn from `[a-zA-Z0-9_:-]`, and the string must contain at least one colon (e.g. `inst:lab-1`). Return a typed `KidError` on violation. Call `validate_kid` in: `ValidatorConfig::new` (on `signer_kid`), `FileBackedHazardDatabase::from_bytes` (on `issuer_kid`), `AuditLogger::new` (on `signer_kid`), `AttestationVerifier::new` (on each key in the map), and in the `ProfileLoader` when resolving `profile_signer_kid`. The CLI `key_file.rs` should re-export or call the core function. Keep all existing tests passing; add new tests for boundary cases (8 chars, 64 chars, 7 chars rejected, 65 chars rejected, no colon rejected, valid colon present). Keep `#![forbid(unsafe_code)]`. Commit as `v3-10: kid string validation at all entry points`.

---

#### v3-11 — Signed `ChemicalRuleSet` file loader and `data/smarts/` directory

**Spec source:** spec-v2.md §v2-24 (third sub-task); gap N-12 above.

**Current state:** `chemical_rules.rs` defines `ChemicalRuleSet` and `StructuralAlertRule` as data types (lines 57–200) but all rules are hardcoded as inline Rust rather than loaded from a signed external file. The spec calls for a `data/smarts/cwc_v1.smarts` file with a signed manifest.

**Prompt for Claude Code:** You are implementing step v3-11 in the invariant-biosynthesis workspace. Add a `data/smarts/` directory at the repo root. Create `data/smarts/cwc_v1_rules.json` as a human-readable JSON file containing a `ChemicalRuleSet` value: at minimum the CWC Schedule 1 phosphonate/fluoride patterns from the current hardcoded rules. Create a `scripts/sign_chemical_rules.sh` that generates an Ed25519 key, signs the canonical JSON of the rule file, and writes `data/smarts/cwc_v1_rules.signed.json` with the same envelope format as `SignedHazardFile` (`issuer_kid`, `signature`, and the body inlined). In `crates/invariant-biosynthesis-core/src/invariants/chemical_rules.rs`, add a `ChemicalRuleSet::from_signed_bytes(bytes: &[u8], trusted_keys: &HashMap<String, VerifyingKey>) -> Result<ChemicalRuleSet, RuleSetLoadError>` constructor that mirrors `FileBackedHazardDatabase::from_bytes`. Add `RuleSetLoadError` with variants for signature failure, parse failure, and unknown issuer. The chemical invariants `C1`–`C10` should continue to work with the programmatic rule set (used in tests); the signed-file loader is an additional construction path tested in a new integration test. Add a unit test that round-trips the signed file through the loader with the correct key and verifies a subset of rules are present. Keep `#![forbid(unsafe_code)]`. Commit as `v3-11: signed ChemicalRuleSet file loader and data/smarts/ directory`.

---

#### v3-12 — `ExecutionToken` signing constructor and `issue-token` CLI

**Spec source:** spec-v2.md §v2-29; gap N-03 and N-09 above.

**Current state:** `crates/invariant-biosynthesis-core/src/models/execution_token.rs` is a bare data struct with no signing logic and no `valid_until` field. The `issue-token` CLI subcommand does not exist.

**Prompt for Claude Code:** You are implementing step v3-12 in the invariant-biosynthesis workspace. Add `valid_until: chrono::DateTime<chrono::Utc>` to `ExecutionToken`. Implement `ExecutionToken::issue(bundle_hash: &str, verdict: &SignedVerdict, validity: chrono::Duration, signer_kid: &str, signing_key: &SigningKey) -> Result<ExecutionToken, TokenError>` where `TokenError` is a `thiserror` enum with `Serialization` and `SignatureFailed` variants. The signing convention: set `signature = ""`, compute `canonical_json_bytes` of the token, sign, set `signature = base64(sig)`. Implement `ExecutionToken::verify(bundle_hash: &str, verifying_key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), TokenError>` that checks the signature, bundle hash match, and `valid_until > now`. Add a `TokenError::Expired` variant. Add `invariant-bio issue-token --bundle <PATH> --verdict <PATH> --signing-key <PATH> --validity <DURATION> --output <PATH>` CLI subcommand in `crates/invariant-biosynthesis-cli/src/commands/`. The command reads the bundle and verdict, calls `ExecutionToken::issue`, writes JSON to `--output`. Emit an error if the verdict is not approved. Document the offline verification protocol in `docs/execution-token-protocol.md` (prose only, no code blocks). Add tests: issue, verify-valid, verify-expired, verify-wrong-bundle-hash all have correct outcomes. Add a `--help` test. Keep `#![forbid(unsafe_code)]`. Commit as `v3-12: ExecutionToken signing and issue-token CLI`.

---

#### v3-13 — `--help` integration tests for all CLI subcommands

**Spec source:** spec-v2.md ground rules; gap N-07 above.

**Current state:** There are no integration tests that invoke `invariant-bio <subcommand> --help` and verify exit code 0.

**Prompt for Claude Code:** You are implementing step v3-13 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-cli/tests/` (create the directory if absent), add a file `help_tests.rs`. For each subcommand that currently exists — `validate`, `inspect`, `differential`, `intent`, `campaign`, `eval`, `adversarial`, `keygen`, `audit`, `audit-gaps`, `verify`, `verify-self`, and any subcommand added by earlier v3 steps — add a test that invokes the binary with `--help` via `std::process::Command`, asserts exit code 0, and asserts that stdout is non-empty. Use the `env!("CARGO_BIN_EXE_invariant-bio")` macro to locate the binary rather than hardcoding a path. Add the test file to the `[[test]]` stanza in `Cargo.toml` for the CLI crate if needed (or it will be picked up automatically as an integration test). Do not change any subcommand implementations. Keep `#![forbid(unsafe_code)]`. Commit as `v3-13: --help integration tests for all CLI subcommands`.

---

#### v3-14 — `rust-toolchain.toml` and MSRV declaration

**Spec source:** spec-v2.md §v2-43; gap N-08 above.

**Current state:** There is no `rust-toolchain.toml` at the repo root. The MSRV is undeclared and could silently drift as authors upgrade locally.

**Prompt for Claude Code:** You are implementing step v3-14 in the invariant-biosynthesis workspace. Run `rustc --version` to get the currently installed stable toolchain. Create `rust-toolchain.toml` at the repo root declaring `[toolchain] channel = "<that version>"`. Add a `[workspace.package] rust-version = "<msrv>"` field to the root `Cargo.toml` (pick the same version or an appropriate minimum — prefer the oldest stable that still compiles the workspace). Add `rust-version` to each crate's `Cargo.toml` inheriting from workspace via `rust-version.workspace = true`. Add a comment in `rust-toolchain.toml` describing the upgrade procedure: bump the channel, run the full test suite, update `CHANGELOG.md`, commit. Verify that `cargo check --workspace` still passes with the pinned toolchain. Keep `#![forbid(unsafe_code)]`. Commit as `v3-14: pin rust-toolchain and MSRV`.

---

### Phase B — State persistence and trust boundary (medium priority)

---

#### v3-15 — Persist S1 fragmentation state and add `state prune` CLI

**Spec source:** spec-v2.md §v2-08 (persistence part).

**Current state:** `stateful.rs` `FragmentationBypassDetector` is an in-memory struct. The validator exposes `with_stateful_detector` but the caller always constructs a fresh detector. State is lost on restart.

**Prompt for Claude Code:** You are implementing step v3-15 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-core/src/invariants/stateful.rs`, add `FragmentationBypassDetector::load_or_new(path: &Path, window_hours: u64) -> Result<Self, StatefulError>` that opens the file at `path` (mode 0o600), reads existing sessions from an append-only JSONL format, discards sessions older than `window_hours`, and initialises the detector from the remaining sessions. Add `FragmentationBypassDetector::persist(&self, path: &Path) -> Result<(), StatefulError>` that rewrites the file with current sessions. The format for each line: `{"principal": "<str>", "kmers": [...], "window_start_ts": "<iso8601>"}`. Add `StatefulError` as a `thiserror` enum with `Io`, `Serialization`, and `HashChainBroken` variants. The validator `validate_inner` should call `persist` after each evaluation when the detector was loaded from a file (thread-safe: acquire the mutex, evaluate, persist, release). Add a `invariant-bio state prune` CLI subcommand that loads the state file at `~/.invariant-bio/state/fragmentation.jsonl`, drops sessions older than the configured window (default 24 hours, configurable via `--window-hours`), rewrites the file, and exits 0. Add tests: a fresh detector with no file starts empty; after four evaluations the file contains four sessions; loading from the file on a new detector instance restores the sessions; `state prune` removes expired sessions. Keep `#![forbid(unsafe_code)]`. Commit as `v3-15: persist S1 fragmentation state and add state prune CLI`.

---

#### v3-16 — Persist attestation nonces across restarts

**Spec source:** spec-v2.md §v2-18.

**Current state:** `crates/invariant-biosynthesis-core/src/attestation.rs` line 19 uses an in-memory `VecDeque<String>` capped at 4096. Restarting the process re-opens the replay window for all nonces issued before the restart.

**Prompt for Claude Code:** You are implementing step v3-16 in the invariant-biosynthesis workspace. Add `AttestationVerifier::load_or_new(path: &Path, replay_window: Duration) -> Result<Self, AttestationPersistError>` that reads nonces younger than `replay_window` from an append-only JSONL file (`{"nonce": "<str>", "ts": "<iso8601>"}` per line), discards older ones, and initialises the in-memory cache. Add `AttestationVerifier::flush(&self, path: &Path) -> Result<(), AttestationPersistError>` that rewrites the file with current nonces. When `verify_input` is called and the verifier was loaded from a file, call `flush` after each successful nonce acceptance. The replay window should be read from `profile.attestation_replay_window_minutes` (defaulting to 15) when a profile is available; the `AttestationVerifier` keeps it as a `Duration` field. Add tests: a nonce issued before restart is still rejected on second use after re-loading from file; a nonce older than the window is absent from the reloaded state. Keep `#![forbid(unsafe_code)]`. Commit as `v3-16: persist attestation nonces across restarts`.

---

#### v3-17 — Incident alert sinks: webhook and syslog

**Spec source:** spec-v2.md §v2-20.

**Current state:** `crates/invariant-biosynthesis-core/src/incident.rs` defines `IncidentState` and `IncidentTrigger` but has only a stdout sink.

**Prompt for Claude Code:** You are implementing step v3-17 in the invariant-biosynthesis workspace. Add to `incident.rs` an `IncidentSink` trait with a single method `send(&self, incident: &IncidentRecord) -> Result<(), SinkError>` where `IncidentRecord` is a new struct carrying `id: String`, `severity: Severity`, `trigger: IncidentTrigger`, `timestamp: DateTime<Utc>`, and `signed_digest: String`. Implement `StdoutSink` (existing behaviour), `WebhookSink { url: String, max_retries: u8 }` that POSTs JSON via `ureq` with up to three retries and exponential back-off capped at 30 seconds, and `SyslogSink { address: SocketAddr }` that sends RFC 5424 UDP messages carrying `STRUCTURED-DATA` with the incident id and severity. Both real sinks are gated behind `cfg(feature = "incident-sinks")` so the default build stays dep-light. Add `incident_sinks: Vec<SinkConfig>` to `BioProfile` where `SinkConfig` is a serialisable enum `{ Webhook { url }, Syslog { address }, Stdout }`. When a `Severity::Critical` incident fails delivery to every configured sink, set the `IncidentResponder` into `IncidentState::Lockdown`. Add tests using a local TCP echo server fixture for `WebhookSink` and a bound UDP socket for `SyslogSink`. Update all six profile JSON files to include `"incident_sinks": []`. Keep `#![forbid(unsafe_code)]`. Commit as `v3-17: incident alert sinks (webhook, syslog)`.

---

#### v3-18 — Audit replication: `FileReplicator` wired, `WebhookWitness`, `audit reconcile` CLI

**Spec source:** spec-v2.md §v2-16 and §v2-17 (file-based parts; S3 deferred).

**Current state:** `replication.rs` has `MerkleTree`, `WitnessRecord`, and a `FileReplicator` stub. Nothing wires replication into the audit logger. No `WebhookWitness`. No `audit reconcile` CLI.

**Prompt for Claude Code:** You are implementing step v3-18 in the invariant-biosynthesis workspace. Wire `FileReplicator` into `AuditLogger`: add `AuditLogger::with_replicator(replicator: Box<dyn AuditReplicator>) -> Self` where `AuditReplicator` is a trait with `replicate(&self, entry: &SignedAuditEntry) -> Result<(), ReplicationError>`. `FileReplicator` implements this by appending the entry JSON line to a second file. Add `WebhookWitness { url: String }` (behind `cfg(feature = "webhook-witness")`) implementing a `Witness` trait with `publish(root: &str, period_id: u64, instance_id: &str, signature: &str) -> Result<(), WitnessError>` using `ureq`. Add `invariant-bio audit reconcile --peer <URL> --audit-log <PATH> --signing-key <PATH>` CLI subcommand that computes the Merkle root of the local log, POSTs it to `<URL>/reconcile`, receives the peer's root, and if they differ prints the first divergent entry id. Write integration tests for `FileReplicator` (write then read back) and for `WebhookWitness` using an `httpmock` or `tiny_http` local fixture. Keep `#![forbid(unsafe_code)]`. Commit as `v3-18: AuditLogger replication wired; WebhookWitness; audit reconcile CLI`.

---

### Phase C — Biology and chemistry fidelity (feature-gated, can parallelise)

---

#### v3-19 — D-family: pure-Rust k-mer engine wired to profile params; `homology_engine_status` accuracy

**Spec source:** spec-v2.md §v2-22 (pure-Rust fallback track only; HMMER deferred to spec-v4).

**Current state:** `dna.rs` lines 60–200 implement a protein k-mer Jaccard engine with hardcoded constants `PROTEIN_KMER_K = 5` and `PROTEIN_KMER_THRESHOLD = 0.30`. The profile fields `protein_kmer_k` and `protein_kmer_threshold` are parsed and validated in `profile.rs` but the invariant code ignores the profile fields and always uses the hardcoded defaults.

**Prompt for Claude Code:** You are implementing step v3-19 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-core/src/invariants/dna.rs`, in every place that reads `PROTEIN_KMER_K` or `PROTEIN_KMER_THRESHOLD`, replace with values read from `ctx.profile.protein_kmer_k.unwrap_or(PROTEIN_KMER_K as u8) as usize` and `ctx.profile.protein_kmer_threshold.unwrap_or(PROTEIN_KMER_THRESHOLD)`. All six protein-space-screening invariants (D1–D6) call the k-mer engine via `evaluate_with`; ensure `ctx` is threaded through consistently. Update the `homology_engine_status` advisory check text in `validator.rs` to include the effective k and threshold values so operators can confirm the profile params are in effect. Add tests that construct two profiles, one with k=3 threshold=0.0 (catch-all) and one with k=8 threshold=1.0 (miss-all), validate the same DNA bundle against each, and confirm that the high-sensitivity profile produces a Hit advisory and the strict profile does not. Keep `#![forbid(unsafe_code)]`. Commit as `v3-19: D-family k-mer engine wired to profile params`.

---

#### v3-20 — D9 hairpin threshold wired to `hairpin_dg_threshold_kcal_mol` profile field

**Spec source:** spec-v2.md §v2-23 (threshold wiring without ViennaRNA; ViennaRNA deferred to spec-v4).

**Current state:** `dna.rs` D9 `SecondaryStructureScreen` uses a hardcoded window-based rolling hash; the profile field `hairpin_dg_threshold_kcal_mol` (introduced in v3-08) is not consulted.

**Prompt for Claude Code:** You are implementing step v3-20 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-core/src/invariants/dna.rs`, the `SecondaryStructureScreen::evaluate_with` method currently uses a hardcoded GC-run threshold. Add a new scoring path: compute the fraction of windows of length 8 that have GC content above 75 percent, then compare that fraction against a threshold derived from `ctx.profile.hairpin_dg_threshold_kcal_mol`. Since the real ΔG cannot be computed without ViennaRNA, the heuristic maps the profile threshold linearly: a threshold of negative 20.0 kcal/mol (the default) corresponds to a GC-fraction window threshold of 0.6; stricter thresholds (more negative) tighten the GC-fraction cutoff proportionally. Emit `Evidence::Score { metric: "gc_hairpin_fraction", value, threshold }` in the Advisory or Fail evidence. Update the `secondary_structure_engine_status` advisory (emitted in `validator.rs`) to include the effective ΔG threshold and note the approximation. Add a test that a high-GC sequence triggers D9 under the default threshold and does not trigger under a very permissive threshold (set via profile). Keep `#![forbid(unsafe_code)]`. Commit as `v3-20: D9 hairpin threshold wired to profile field`.

---

#### v3-21 — P5 downgrade to Advisory with `p5_structural_context_unavailable` note

**Spec source:** spec-v2.md §v2-25 (P5 sub-task).

**Current state:** `peptide.rs` P5 `EnzymeActiveSiteMimicScreen` fires a `Fail` on regex motif matches without any structural context, producing false positives.

**Prompt for Claude Code:** You are implementing step v3-21 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-core/src/invariants/peptide.rs`, change `EnzymeActiveSiteMimicScreen::evaluate_with` so that motif hits produce `InvariantStatus::Advisory` with evidence carrying a `Simple` note including the text `p5_structural_context_unavailable` and describing the matched motif. The motif-match logic itself is unchanged. Update the `peptide_engine_status` advisory in `validator.rs` to mention P5 explicitly. Add a test that a peptide containing an active-site motif produces an Advisory, not a Fail. Keep `#![forbid(unsafe_code)]`. Commit as `v3-21: P5 downgrade to Advisory pending structural context`.

---

#### v3-22 — `Molecule` type extended with `formula` and `mw` heuristics

**Spec source:** spec-v2.md §v2-24 (sub-task 1); gap N-11 above.

**Current state:** `models/molecule.rs` `Molecule` carries only `canonical: String` and `original: String`. The spec promises `formula: String`, `mw: f64`, and (future) `inchi_key: String`.

**Prompt for Claude Code:** You are implementing step v3-22 in the invariant-biosynthesis workspace. Extend `crates/invariant-biosynthesis-core/src/models/molecule.rs` `Molecule` with two additional fields: `formula: String` and `mw: f64`. Implement heuristic computation of both inside `Molecule::from_smiles`: count each element symbol's occurrences in the SMILES string to build a Hill-order formula (C first, H second, then remaining elements alphabetically), and estimate MW using a lookup table of the most common SMILES elements (C=12.011, H=1.008, N=14.007, O=15.999, F=18.998, Cl=35.45, Br=79.904, I=126.904, P=30.974, S=32.06; anything else contributes 0 to MW with a note). These are intentionally rough — document their limitations in the rustdoc. Add an `inchi_key: Option<String>` field set to `None` until the `rdkit` feature lands. Add tests: `CCO` (ethanol) produces formula `C2H6O` and MW close to 46.07; `c1ccccc1` (benzene) produces formula `C6H6`; an empty molecule returns the existing error. Keep `#![forbid(unsafe_code)]`. Commit as `v3-22: Molecule extended with formula and mw heuristics`.

---

#### v3-23 — `ConsensusHazardScreener` wired into `ValidatorConfig` default for production profiles

**Spec source:** spec-v2.md §v2-26; gap N-15 above.

**Current state:** `ConsensusHazardScreener` and `QuorumPolicy` are fully implemented in `screening/mod.rs` but `ValidatorConfig` accepts only a single `Option<Arc<dyn HazardScreener>>`. There is no way to pass multiple independent DBs.

**Prompt for Claude Code:** You are implementing step v3-23 in the invariant-biosynthesis workspace. Change `ValidatorConfig` in `validator.rs` to accept multiple screeners: rename the `hazard_db` field to `hazard_dbs: Vec<Arc<dyn HazardScreener>>` and add a `quorum_policy: QuorumPolicy` field (defaulting to `QuorumPolicy::AtLeast(1)` to preserve current single-DB behaviour). Keep `with_hazard_db(db)` as a convenience builder that pushes one db and sets `quorum_policy = AtLeast(1)`. Add `with_hazard_dbs(dbs: Vec<...>, policy: QuorumPolicy) -> Self`. In `validate_inner`, if there are two or more DBs, wrap them in a `ConsensusHazardScreener` with the configured policy before screening; if there is one DB, use it directly; if there are none, apply the existing fail-closed logic. For production profiles (`is_production_profile`) default `quorum_policy` to `AtLeast(2)` — and if fewer than two DBs are provided, emit an advisory check `screening_consensus_underconfigured` noting that at least two independent sources are recommended for production. Add tests: single-DB path unchanged; two-DB path with `AtLeast(2)` and one hitting produces a pass; two-DB path with `Any` and one hitting produces a hit (union). Keep `#![forbid(unsafe_code)]`. Commit as `v3-23: ConsensusHazardScreener wired into ValidatorConfig`.

---

### Phase D — Platform and compliance scaffolding

---

#### v3-24 — `invariant-biosynthesis-platform` crate with `Platform` trait and `MockPlatform`

**Spec source:** spec-v2.md §v2-27.

**Current state:** No `invariant-biosynthesis-platform` crate exists.

**Prompt for Claude Code:** You are implementing step v3-24 in the invariant-biosynthesis workspace. Create a new library crate `crates/invariant-biosynthesis-platform/` and add it to the workspace `Cargo.toml`. The crate must begin with `#![forbid(unsafe_code)]`. Define a `Platform` trait with methods: `submit_token(&self, token: &ExecutionToken) -> Result<Receipt, PlatformError>`, `fetch_attestation(&self, receipt_id: &str) -> Result<AttestedReading, PlatformError>`, `name(&self) -> &'static str`, `supported_substrates(&self) -> &[&'static str]`. Define `Receipt`, `AttestedReading`, and `PlatformError` (with variants `Rejected`, `NotFound`, `Transport { reason: String }`, `Unsupported`) as public types in the crate. The trait is synchronous (no async) — implementations use blocking HTTP internally. Implement `MockPlatform` that accepts any token and returns a dummy receipt. Write tests that `MockPlatform` implements the full trait contract. Add a crate-level rustdoc explaining the verification protocol an instrument vendor would implement. Keep all existing crates unmodified. Run the full suite and commit as `v3-24: invariant-biosynthesis-platform crate with Platform trait`.

---

#### v3-25 — `invariant-biosynthesis-compliance` crate scaffold

**Spec source:** spec-v2.md §v2-32.

**Current state:** No `invariant-biosynthesis-compliance` crate exists.

**Prompt for Claude Code:** You are implementing step v3-25 in the invariant-biosynthesis workspace. Create a new library crate `crates/invariant-biosynthesis-compliance/` and add it to the workspace `Cargo.toml`. The crate must begin with `#![forbid(unsafe_code)]`. Define a `ReportGenerator` trait with method `generate(verdicts: &[SignedVerdict], since: DateTime<Utc>, until: DateTime<Utc>) -> Result<JurisdictionReport, ReportError>`. Define `JurisdictionReport` carrying `jurisdiction: String`, `generated_at: DateTime<Utc>`, `period_start: DateTime<Utc>`, `period_end: DateTime<Utc>`, `approved_count: u64`, `rejected_count: u64`, `advisory_count: u64`, and `body: serde_json::Value` for jurisdiction-specific schema. Create stub `ReportGenerator` implementations in submodules: `cdc_select_agent`, `nih_rdna`, `fda`, `cwc`, `itar`. Each stub returns a `JurisdictionReport` with appropriate field values and an empty `body` (full schema in spec-v4). Add a `invariant-bio compliance report --jurisdiction <name> --audit-log <PATH> --since <timestamp> --until <timestamp>` CLI subcommand. Add tests that each stub produces a non-error report for a given set of sample verdicts. Keep `#![forbid(unsafe_code)]`. Commit as `v3-25: invariant-biosynthesis-compliance crate scaffold`.

---

#### v3-26 — Auditor RBAC: `AuditAccessor` and `ReadGate`

**Spec source:** spec-v2.md §v2-33.

**Current state:** `audit.rs` provides `AuditLogger` and `verify_log`. Any reader of the JSONL file sees everything with no access control or redaction.

**Prompt for Claude Code:** You are implementing step v3-26 in the invariant-biosynthesis workspace. Add to `crates/invariant-biosynthesis-core/src/audit.rs` an `AuditAccessor` struct that holds a `kid: String` (must start with `"auditor:"`), a `verifying_key: VerifyingKey` for authentication, and a `ReadPolicy`. `ReadPolicy` is an enum with variants `Full` (see everything) and `Redacted { hide_threat_scores: bool, hide_invariant_details: bool }`. Implement `AuditAccessor::read_entry(entry: &SignedAuditEntry, now: DateTime<Utc>) -> Result<serde_json::Value, AccessError>` that verifies the accessor is authentic (Ed25519 challenge–response is out of scope here; check that `accessor.kid` starts with `"auditor:"` and the key is in a provided trusted-keys map), applies the `ReadPolicy` by removing `threat_analysis` from the verdict JSON when `hide_threat_scores`, and removing per-check `details` fields when `hide_invariant_details`, and logs the read access as a new audit entry type `AuditRead { accessor_kid, policy, entry_sequence_read }`. Add `invariant-bio audit read --as <kid> --audit-log <PATH> --since <u64> --until <u64>` CLI subcommand. Tests: full-policy reader sees all fields; redacted-policy reader cannot see `threat_analysis`; non-`auditor:` kid is rejected. Keep `#![forbid(unsafe_code)]`. Commit as `v3-26: AuditAccessor and ReadGate RBAC`.

---

### Phase E — Testing rigour

---

#### v3-27 — Property-based tests with `proptest` for invariant families

**Spec source:** spec-v2.md §v2-37.

**Current state:** No `proptest` in any dev-dependencies. All tests are example-based.

**Prompt for Claude Code:** You are implementing step v3-27 in the invariant-biosynthesis workspace. Add `proptest = "1"` to the dev-dependencies of `crates/invariant-biosynthesis-core`. In a new `crates/invariant-biosynthesis-core/src/invariants/proptest_invariants.rs` (included under `#[cfg(test)]`), write at minimum the following 30 properties using `proptest!`: (1) For DNA invariants: codon translation of a well-formed sequence of length divisible by 3 produces a non-empty amino acid string; HazardClass::parse is idempotent (parse(parse(x)) == parse(x)); GC content for a sequence of all-G is 1.0 and all-A is 0.0. (2) For peptide invariants: net_charge of a sequence of all-K is positive; hydrophobic_fraction of a sequence of all-G is 0.0; a sequence of all canonical amino acids passes P9 PTM screen. (3) For chemical invariants: `Molecule::from_smiles` on a canonicalized string returns the same canonical string (idempotency given inputs already in canonical form); any input with unbalanced parentheses returns `UnbalancedBrackets`. (4) For protocol invariants: a protocol bundle with zero steps passes PR1; a bundle with 257 or more steps fails PR1. (5) General: `InvariantStatus` round-trips through JSON; `run_all` always returns exactly 34 results for any non-disabled selection. Use `Strategy` combinators to generate well-formed DNA strings (alphabet ACGT, length 1..=300) and well-formed amino acid strings. Run with 256 cases minimum. Keep `#![forbid(unsafe_code)]`. Commit as `v3-27: proptest property-based tests for invariant families`.

---

#### v3-28 — libFuzzer targets for parsing entry points

**Spec source:** spec-v2.md §v2-38.

**Current state:** `crates/invariant-biosynthesis-fuzz/` contains adversarial attack suites but no `fuzz/` directory with libFuzzer targets. The crate is a library of programmatic attack generators, not a fuzzing harness.

**Prompt for Claude Code:** You are implementing step v3-28 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-fuzz/fuzz/`, create five fuzzing targets as Rust source files following the `cargo-fuzz` convention (each file begins with `#![no_main]` and uses `libfuzzer_sys::fuzz_target!`). The five targets are: `fuzz_profile_json` (parse arbitrary bytes as `BioProfile` via serde_json); `fuzz_bundle_json` (parse arbitrary bytes as `SynthesisBundle`); `fuzz_hazard_db_json` (pass bytes through `FileBackedHazardDatabase::from_bytes` with a known test key); `fuzz_molecule_smiles` (pass arbitrary UTF-8 string to `Molecule::from_smiles` and assert no panic, only Ok or Err); `fuzz_canonical_json` (serialise then `canonical_json_bytes` a generated `serde_json::Value` and assert no panic). Add a `Cargo.toml` for the fuzz targets following cargo-fuzz conventions. Add `[profile.fuzz]` to the workspace `Cargo.toml` if needed. Document in `crates/invariant-biosynthesis-fuzz/README.md` how to run a 60-second budget: `cargo fuzz run fuzz_profile_json -- -max_total_time=60`. Note that fuzz targets are not run by default in `cargo test`; add a CI comment explaining the nightly job. Keep `#![forbid(unsafe_code)]` in the fuzz crate lib. Commit as `v3-28: libFuzzer targets for parsing entry points`.

---

#### v3-29 — Synthetic FP/FN measurement harness in `eval` crate

**Spec source:** spec-v2.md §v2-35.

**Current state:** `crates/invariant-biosynthesis-eval/src/lib.rs` is a skeleton with `#![forbid(unsafe_code)]` and no content.

**Prompt for Claude Code:** You are implementing step v3-29 in the invariant-biosynthesis workspace. In `crates/invariant-biosynthesis-eval/src/`, implement the following modules. `corpus/generators.rs`: a `CorpusGenerator` struct with methods `dna_legitimate(n: usize, seed: u64) -> Vec<SynthesisBundle>` (random valid DNA using ACGT alphabet, codon-aligned, length 50..=500), `dna_hazard_variants(patterns: &[&str], n_per_pattern: usize, seed: u64) -> Vec<(SynthesisBundle, bool)>` (each bundle embeds a hazard pattern in a random context, ground truth = true), `peptide_legitimate(n: usize, seed: u64)`, `chemical_legitimate(n: usize, seed: u64)`. `harness/runner.rs`: a `EvalRunner` that takes a `ValidatorConfig`, runs it over a `Vec<(SynthesisBundle, bool)>` where the bool is the ground-truth label, and returns a `HarnessResult` with `tp, fp, tn, fn_count`. `stats/clopper_pearson.rs`: `fn clopper_pearson_interval(k: u64, n: u64, alpha: f64) -> (f64, f64)` using the Beta distribution inverse CDF (pure Rust, no new heavy deps — implement the regularised incomplete beta function directly or use the `statrs` crate if approved). Expose a top-level `fn run_eval(config: ValidatorConfig, generator: &CorpusGenerator) -> EvalReport` where `EvalReport` contains the confusion matrix, FP/FN rates, and 95-percent Clopper-Pearson intervals. Add tests for each module. The harness must not require network access. Keep `#![forbid(unsafe_code)]`. Commit as `v3-29: FP/FN eval harness in eval crate`.

---

#### v3-30 — Criterion performance benches

**Spec source:** spec-v2.md §v2-40.

**Current state:** No `benches/` directory anywhere in the workspace.

**Prompt for Claude Code:** You are implementing step v3-30 in the invariant-biosynthesis workspace. Add `criterion` to dev-dependencies of `crates/invariant-biosynthesis-core`. Create `crates/invariant-biosynthesis-core/benches/validate.rs` with the following benchmarks: `bench_validate_small_dna` (50-base sequence, no hazard DB), `bench_validate_medium_dna` (500-base sequence, hazard DB with 10 patterns), `bench_validate_large_dna` (5000-base sequence), `bench_audit_append_single` (one audit logger append), `bench_audit_append_batch_10k` (10,000 appends into a `Vec<u8>` sink), `bench_canonical_json_small` (10-field struct), `bench_canonical_json_large` (100-field struct). Each bench uses a deterministic RNG seed so it is reproducible. In `docs/performance.md`, document what the benches measure, their machine-independent context (what the benchmark tests), and a note that CI baselines are set with `cargo bench -- --save-baseline main` on a reference machine. Do not gate CI on bench regressions in this step (that requires a baseline file). Keep `#![forbid(unsafe_code)]`. Commit as `v3-30: criterion performance benches`.

---

#### v3-31 — Shadow-mode evaluation CLI

**Spec source:** spec-v2.md §v2-39.

**Current state:** No `invariant-bio shadow` subcommand.

**Prompt for Claude Code:** You are implementing step v3-31 in the invariant-biosynthesis workspace. Add `invariant-bio shadow --input <JSONL> --labels <JSONL> --profile <PATH> --hazard-db <PATH> --issuer-pub <PATH> --output <REPORT>` CLI subcommand. The `--input` JSONL file contains one `SynthesisBundle` per line. The `--labels` JSONL contains `{"bundle_hash": "<sha256>", "expert_approved": <bool>}` per line. The command runs each bundle through a freshly constructed `ValidatorConfig` (same construction path as the `validate` subcommand), computes the confusion matrix against expert labels matched by `bundle_hash`, and writes a JSON report containing: total bundles evaluated, TP/FP/TN/FN counts, agreement rate, FP rate, FN rate, per-check disagreement counts (which checks most often disagree with expert labels), and 95-percent confidence intervals using Clopper-Pearson (from the eval crate). Exit code 0 when FN rate upper bound is below 0.01 (spec threshold), exit code 1 when it exceeds it, exit code 2 when fewer than 100 bundles are evaluated (insufficient statistical power). Add a `--help` integration test. Keep `#![forbid(unsafe_code)]`. Commit as `v3-31: shadow-mode evaluation CLI`.

---

### Phase F — Release engineering and governance

---

#### v3-32 — `cargo deny` configuration and dependency audit

**Spec source:** spec-v2.md §v2-43 and §v2-44.

**Current state:** No `deny.toml` exists at the repo root.

**Prompt for Claude Code:** You are implementing step v3-32 in the invariant-biosynthesis workspace. Create `deny.toml` at the repo root with the following sections: `[licenses]` deny all licences except `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-DFS-2016`; `[bans]` with `multiple-versions = "warn"` and explicit denials for `openssl` (prefer `rustls`); `[advisories]` with `vulnerability = "deny"`, `unmaintained = "warn"`, `notice = "warn"`, `ignore = []`; `[sources]` allowing only `crates-io`. Run `cargo deny check` and resolve any violations — if a crate cannot be replaced, add it to `deny.toml` with a comment justifying the exception. Add a CI check step that runs `cargo deny check` (comment in `Makefile` or a shell script `scripts/check-deps.sh`). Keep `#![forbid(unsafe_code)]`. Commit as `v3-32: cargo deny configuration and dependency audit`.

---

#### v3-33 — Pre-audit hardening pass

**Spec source:** spec-v2.md §v2-44.

**Current state:** Several `unwrap()` / `expect()` calls exist in non-test production paths. Not every public item has rustdoc. Broken intra-doc links are possible.

**Prompt for Claude Code:** You are implementing step v3-33 in the invariant-biosynthesis workspace. Perform the following hardening steps across the entire workspace. First, identify every `unwrap()` and `expect()` call in non-test source files (excluding lines inside `#[cfg(test)]` blocks). For each: if the invariant is provably unreachable, add a comment explaining why and change to `expect("<reason>")` with a meaningful message. If it can realistically fail (I/O, lock poisoning, parse), replace with `?` or a typed error return. Specific known cases to address: `validator.rs` line containing `expect("threat scorer mutex poisoned")` — this is a legitimate never-panic justification for a poisoned mutex in a safety-critical system; add a clear comment explaining the deliberate panic. Second, run `cargo doc --no-deps --workspace 2>&1 | grep warning` and resolve all broken intra-doc links. Third, verify every public struct, enum, trait, and function in `crates/invariant-biosynthesis-core/src/` has at least one sentence of rustdoc. Fourth, add a `#[deny(missing_docs)]` annotation to the core crate `lib.rs` (not `#![deny]` — do it at module level for newly touched modules to avoid a flag day). Add a note in `CHANGELOG.md`. Keep `#![forbid(unsafe_code)]`. Commit as `v3-33: pre-audit hardening pass`.

---

#### v3-34 — `SECURITY.md` and `docs/rfc-process.md`

**Spec source:** spec-v2.md §v2-45.

**Current state:** No `SECURITY.md` or `docs/rfc-process.md` exist.

**Prompt for Claude Code:** You are implementing step v3-34 in the invariant-biosynthesis workspace. Create `SECURITY.md` at the repo root with the following sections: Scope (what is in scope for responsible disclosure — synthesis firewall logic, cryptographic primitives, key management, audit log integrity; what is out of scope — upstream crate vulnerabilities already in `cargo audit`); Reporting process (email address or GitHub Security Advisory link; acknowledge within 72 hours; commit to a mitigation timeline; CVE issuance for CVSS >= 7.0 issues); Embargo policy (90-day coordinated disclosure default; shorter for active exploitation); Hall of fame structure for acknowledged reporters. Create `docs/rfc-process.md` with the following sections: Purpose, RFC lifecycle (Draft, Review, Accepted, Implemented, Obsolete), numbering scheme (RFC-NNNN), required sections for an RFC (Summary, Motivation, Detailed Design, Drawbacks, Alternatives, Unresolved Questions), tooling (Markdown file in `docs/rfcs/`), decision process (maintainer consensus or two-of-N approval). Neither file contains code. Keep `#![forbid(unsafe_code)]` (not applicable to docs). Commit as `v3-34: SECURITY.md and rfc-process.md`.

---

#### v3-35 — `CHANGELOG.md` and `README.md` audit; examples smoke tests

**Spec source:** spec-v2.md ground rules; gap N-10 above.

**Current state:** The ground rules require `CHANGELOG.md` updates with every step but there is no audit of whether it has been maintained. The CLI `validate` subcommand's default profile is `"cli-default"` with `bsl_level = 2` which `is_production_profile` returns true for (because the name does not start with `test_`/`dev_` and bsl_level is not 1). This means the production threat scorer auto-attaches in v3-06 but the default profile was clearly not designed as a production profile.

**Prompt for Claude Code:** You are implementing step v3-35 in the invariant-biosynthesis workspace. Address two items. First, rename the `validate.rs` CLI default profile from `"cli-default"` to `"dev_cli_default"` so `is_production_profile` returns false for it. Update the rustdoc comment on `default_profile()` to explain that this is intentionally a development-only profile and that production uses should always supply `--profile`. Add a test that `default_profile()` returns a profile where `is_production_profile` is false. Second, add an `examples/` integration smoke test: create `crates/invariant-biosynthesis-cli/tests/examples_smoke.rs` that loads each JSON file from the repo's `examples/` directory, parses it as `SynthesisBundle` using serde_json, and asserts it round-trips without error. This catches drift between the example files and the schema. Keep `#![forbid(unsafe_code)]`. Commit as `v3-35: rename dev CLI default profile; examples smoke tests`.

---

## 4. Acceptance gates for spec-v3

A release may claim "production-ready for synthesis" only when all items below are true:

1. All Phase A steps (v3-01 through v3-14) are landed and CI is green.
2. Phase B persistence steps (v3-15, v3-16) are landed; S1 state survives a restart test.
3. Phase C biology steps (v3-19 through v3-23) are landed; the `eval` harness reports FN rate upper bound below 0.01 on the bundled corpus.
4. Phase D crate scaffolding (v3-24, v3-25) exists; at least one platform adapter (covered in spec-v4) is verified end-to-end.
5. Phase E testing (v3-27 through v3-31) is landed; shadow-mode exits 0 on the reference corpus with at least 100 bundles.
6. Phase F governance (v3-32 through v3-35) is landed; `cargo deny check` is clean; `SECURITY.md` is reviewed by a human maintainer.
7. `cargo audit` shows no open advisories.
8. All `--help` integration tests (v3-13) pass.
9. Profile signature verification (v3-03) rejects an unsigned BSL-4 profile.
10. Canonical JSON (v3-01) is byte-identical for two structurally equal values.

---

## 5. Out-of-scope — deferred to spec-v4

The following items are acknowledged gaps but are explicitly deferred because they require architectural work, external vendors, or hardware that is outside the current build environment:

- HMMER / BLAST subprocess path for D-family invariants (spec-v2 §v2-22 HMMER track). A pure-Rust fallback is covered by v3-19.
- ViennaRNA FFI for real ΔG computation in D9 (spec-v2 §v2-23). The threshold wiring is covered by v3-20.
- RDKit FFI for canonical SMILES, InChI key, and SMARTS substructure matching (spec-v2 §v2-24 sub-task 2). Heuristic is in place via v3-22.
- NetMHCpan subprocess for P6 MHC binding (spec-v2 §v2-25 P6 sub-task).
- TANGO-equivalent aggregation scorer for P8 (spec-v2 §v2-25 P8 sub-task).
- TPM 2.0 and YubiHSM 2 key-store backends (spec-v2 §v2-12, §v2-13).
- FROST multi-party key ceremony CLI (spec-v2 §v2-14).
- Key rotation overlap window (spec-v2 §v2-15).
- S3 replication backend (spec-v2 §v2-16). File replication is covered by v3-18.
- SecureDNA oblivious-query client (spec-v2 §v2-26 sub-task 2).
- First vendor synthesis platform adapter (spec-v2 §v2-28). Crate scaffold is in v3-24.
- Reference instrument-side verifier binary (spec-v2 §v2-30).
- CEM Liberty and Chemspeed platform adapters (spec-v2 §v2-31).
- Full jurisdiction compliance report schemas — CDC Select Agent, NIH rDNA, FDA, USDA, EPA TSCA, CWC, ITAR, Australia Group, Wassenaar (spec-v2 §v2-32). Scaffold is in v3-25.
- Auditor RBAC per-jurisdiction redaction matrix (spec-v2 §v2-33 full matrix).
- Per-jurisdiction `BioProfile` variants and invariant gating matrix (spec-v2 §v2-34).
- Runtime monitor Prometheus exposition (spec-v2 §v2-21).
- Signed release workflow + cosign binary signing (spec-v2 §v2-42).
- Export-control CI check on dependencies (spec-v2 §v2-45 sub-task 1).
- Web UI.
- Non-Rust client SDKs.
- HSM-backed firmware attestation of synthesisers (vendor-side).
- Federated-learning-style hazard-DB updates across firewalls.
