> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Invariant Biosynthesis — Hardening Spec (Phase 2 + Phase 3)

**Status:** active. This spec subsumes the previous archived plans:

- Phase-1 gap-closure (Steps 1–22) — `docs/spec-phase1-gap-closure.md` (✅ complete).
- Phase-2 operational hardening (21 platform/feature steps) — `docs/spec-phase2-operational.md` (drafted, **not yet executed**).
- Phase-3 second-pass corrections (this document, §A below) — fresh from a deep-read audit on 2026-04-25.

A second-pass deep audit of the shipping code surfaced a class of gaps the Phase-2 plan did **not** catch: subtle correctness details inside shipping invariants, schema fields declared-but-not-enforced, validator pipeline integration that was left to callers, and a small set of security details that an external auditor would flag immediately. Those are folded in as **§A — Correctness, Integration, and Audit-Readiness**, and run **before** the Phase-2 platform work in §B because most are low-risk fixes that should land first.

## Why this matters

Phase-1 left the firewall functionally complete (verdict in / verdict out, all 34 invariants real, 540 tests). Phase-2 was scoped at adding optional dependencies and platform adapters. The gap this third pass closes is in between: the *shipping core* has integration seams and silent assumptions that mean a production deployment today would have an audit log that only fills if the operator remembers to call `AuditLogger`, profiles whose signatures are accepted unverified, and several invariants whose hard-coded window sizes can't be tuned for a specific lab. This spec fixes those before any new feature work.

## Progress log

(Each completed step appends a `- [x] **Step N** — …` entry, matching the style of the archived Phase-1 spec.)

## Ground rules

- Preserve `#![forbid(unsafe_code)]` everywhere.
- §A steps add **no** new top-level dependencies. §B steps may add deps only behind feature flags.
- After every code-changing step run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings`. Don't move on until all three pass.
- One commit per step, prefixed with the step id (e.g. `a3: enforce profile signature on load`).
- Never push directly to `main`.

---

# §A — Correctness, Integration, and Audit-Readiness

These are **fixes inside the shipping code**, not new features. Do them first.

## A1 — Re-baseline the workspace and create the working branch

**Goal:** Confirm the snapshot, lock per-crate test counts, ensure the working tree is a real git repo (Phase 1's Step-22 blocker), branch off.

**Prompt for Claude Code:**

> Run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` and report exact pass/fail and per-crate test counts. If anything fails, stop and report verbatim. Then verify the working tree is a git repo (`git rev-parse --git-dir`); if not, run `git init && git add -A && git commit -m "phase-1 + phase-3 baseline"`. Create branch `hardening` off `main` and confirm checkout. No code changes.

**Acceptance:** Three green commands; per-crate counts recorded; branch `hardening` checked out; working tree is a git repo.

---

## A2 — Wire the validator into the audit log

**Goal:** Today `audit.rs` is a self-contained module. The validator returns a `SignedVerdict` but never appends it to an audit log; that's left to callers, and none of the CLI commands do it. As a result, a deployed firewall has no automatic tamper-evident trail.

**Prompt for Claude Code:**

> Read `crates/invariant-biosynthesis-core/src/{audit,validator}.rs`. Add `audit_logger: Option<Arc<Mutex<AuditLogger<File>>>>` to `ValidatorConfig` plus `with_audit_logger(...)` builder. After `validate(...)` produces a `SignedVerdict`, when the logger is present, call `logger.lock().log(bundle, &verdict)?` and propagate any error as a new `ValidatorError::AuditAppendFailed`. Add `validate_no_audit(...)` that explicitly skips logging for tests / dry-runs. Update `validate` CLI to wire `--audit-log <PATH>` into the configured logger. Add 4 tests: (a) no logger → no I/O; (b) logger present → entry appended with monotonic sequence; (c) logger I/O failure surfaces as `ValidatorError`; (d) two consecutive validates produce a hash-chained pair.

**Acceptance:** Audit log auto-appended on every validate when configured; ≥4 new tests; existing tests unchanged.

---

## A3 — Verify profile signatures on load

**Goal:** `BioProfile` declares `profile_signature: Option<String>` and `profile_signer_kid: Option<String>`, but `BioProfile::validate()` never checks them. A caller can edit a profile JSON in place and the firewall will accept it.

**Prompt for Claude Code:**

> Read `crates/invariant-biosynthesis-core/src/models/profile.rs` and the embedded profile loader in `profiles.rs`. Define a canonical-bytes function for `BioProfile` that excludes the signature fields (mirror the pattern in `screening/mod.rs::sign_body_for_tests`). Add `BioProfile::verify_signature(&self, trusted_keys: &TrustedKeyMap) -> Result<(), ProfileSignatureError>`. The validator's `with_profile_with_signature(...)` builder must call this before accepting the profile. When the signature fields are both `None`, status depends on a new `ValidatorConfig::allow_unsigned_profile: bool` (default `false`, fail-closed in production). Add a public `sign_profile_for_tests` helper. Add 5 tests: (a) signed-and-trusted profile accepted; (b) tampered body rejected; (c) wrong-key rejected; (d) unsigned with default policy rejected; (e) unsigned with `allow_unsigned_profile=true` accepted with a warning check on the verdict.

**Acceptance:** Profile signatures verified on load; ≥5 new tests; the 6 built-in profiles either gain signatures or are loaded under the explicit `allow_unsigned_profile` opt-in for backwards compatibility.

---

## A4 — Tighten the `Invariant` trait API

**Goal:** Today the trait exposes both `evaluate()` and `evaluate_with()`. The validator only calls `evaluate_with`, but `evaluate()` remains a footgun — a future call site (or a third-party crate impl) can bypass `InvariantContext` entirely, losing the screening hits and profile.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/invariants/mod.rs`, swap the trait so `evaluate_with(&self, bundle, ctx)` is the only **required** method and `evaluate(&self, bundle)` becomes a default that constructs a synthetic empty context (`InvariantContext::empty()`) and calls `evaluate_with`. Mark the legacy `evaluate(&self)` direct path as `#[deprecated(note = "prefer evaluate_with; this convenience constructs an empty context")]`. Add `InvariantContext::empty()` returning a context with no screening hits and a permissive default profile. Walk every test in the workspace and migrate to `evaluate_with` (the deprecation warning will flag the call sites). No behaviour change in shipping production code paths.

**Acceptance:** `evaluate` is deprecated; all test call sites migrated; clippy clean (deprecations gated to `#[allow(deprecated)]` only inside the trait itself).

---

## A5 — Validate kid strings and metadata reserved keys

**Goal:** `signer_kid`, `profile_signer_kid`, attestation kid, audit-entry kid — all are bare `String` fields. An attacker (or careless tooling) can pass an empty kid, a kid with control characters, or a kid that collides with reserved metadata keys. Likewise `SynthesisBundle::metadata: HashMap<String, String>` accepts arbitrary keys including ones that shadow reserved names (`kid`, `signature`, `bundle_version`, etc.).

**Prompt for Claude Code:**

> Add `crate::util::validate_kid(kid: &str) -> Result<(), KidError>` that enforces: 1–128 bytes, every byte ASCII printable in `[A-Za-z0-9_.:-]`, no leading or trailing `.`. Call it on every kid-accepting boundary: `AttestationVerifier::verify_input/verify_reading`, `BioProfile::verify_signature`, `AuditLogger::new`, the validator's signing-kid setter. Add `crate::util::RESERVED_METADATA_KEYS` (`kid`, `signature`, `bundle_version`, `nonce`, `timestamp`, `pca_chain`) and reject any `SynthesisBundle::metadata` whose keys collide with that set on bundle deserialisation (`#[serde(deny_unknown_fields)]` is already on the envelope; this adds key-level rejection inside the `metadata` map). Add 8 tests covering empty kid, control-char kid, oversize kid, valid-edge-case kid (with each allowed special), reserved-key collision per name.

**Acceptance:** Kid + metadata validation enforced at every boundary; ≥8 new tests; no shipping fixture rejected.

---

## A6 — Pin canonical JSON serialization

**Goal:** Every signed envelope (verdict, audit entry, hazard DB body, attestation canonical, profile body) hashes a `serde_json::to_vec(&body)` output. `serde_json` happens to preserve struct field order, but this is implicit. A future refactor that reorders fields silently breaks every signature already deployed against that struct.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/util.rs`, add a doc block enumerating the canonical-bytes contract: (1) field order matches struct declaration; (2) maps are serialised with `BTreeMap`-equivalent key ordering (use `serde_json::Value` round-trip if the type contains a `HashMap`); (3) integers serialise without `+` or leading zeros; (4) floats are forbidden in canonical bodies (use fixed-precision strings or rationals). Audit every struct used in a signed canonical body and add `#[serde(deny_unknown_fields)]` plus a Rustdoc note `// canonical: do not reorder fields`. Add a regression test that serialises a small fixture and asserts the byte sequence equals a hard-coded golden — this freezes the format. Document the implication: any field reorder requires a schema-version bump.

**Acceptance:** Canonical bytes contract documented; golden test in place; no behaviour change.

---

## A7 — Normalise hazard-class matching

**Goal:** The C-, D-, and P-family invariants compare DB-emitted `hazard_class` to hard-coded lower-case constants. Real-world hazard DBs use mixed delimiters (`schedule-1`, `schedule_1`, `Schedule 1`, `SCHEDULE-1`). Today only the lowercase-hyphenated form matches.

**Prompt for Claude Code:**

> Add `crate::screening::normalise_hazard_class(s: &str) -> String` that lowercases and replaces every run of `[\s_]+` with `-`. Apply it on both ends of every comparison: at hazard-DB load time (normalise once into the `HazardEntry`) and inside every invariant's `hits_in_classes(...)` helper. Add 6 tests on canonical aliases (`Schedule 1`, `schedule_1`, `SCHEDULE-1` → all match `schedule-1`). Update `HazardEntry`'s Rustdoc to document the normalisation.

**Acceptance:** Class matching robust to delimiter / case drift; ≥6 new tests; existing fixture DBs continue to match.

---

## A8 — Profile-driven invariant tunables

**Goal:** D8 (GC window 100), D9 (hairpin window 20), D7 (entropy band [2.5, 5.8]), P3 (hydrophobic window 18), P8 (aggregation window 6), PR4 (volume cap factor 0.5), PR1 (step-count cap 256) are all hard-coded. Different labs need different cutoffs. Phase-2 §B already picks up D7 and PR2; this step covers the rest.

**Prompt for Claude Code:**

> Add a `BioProfileTunables` struct embedded in `BioProfile` carrying optional overrides for: D8 GC window + low/high; D9 hairpin window; P3 amphipath window + thresholds; P8 aggregation window + threshold; PR1 step cap; PR4 volume advisory factor. Each invariant pulls its threshold from `ctx.profile.tunables.<field>.unwrap_or(<built-in default>)`. Add validation: on profile load, every tunable must lie in a documented sane range (e.g. D8 window ∈ [10, 1000], D9 window ∈ [10, 200]). Add 7 tests (one per tunable: overridden value affects outcome). Update `government_bsl4_restricted.json` to demonstrate one override.

**Acceptance:** Per-profile invariant tunables shipped; ≥7 new tests; built-in defaults preserved when not overridden.

---

## A9 — Strengthen PR4 and PR2 input parsing

**Goal:** PR4's volume regex parses `<digits>.<digits>` as a float, but accepts `100.5.5` as a malformed extra-dot input by truncating silently. PR2's verb extraction takes the first whitespace-delimited token, but a step like `\taspirate` or `aspirate;` (semicolon-terminated) parses inconsistently with the test fixtures.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/invariants/protocol.rs`, replace the volume parser with a strict regex `\b(\d+(?:\.\d+)?)\s*(uL|mL|L)\b`; reject (Fail) any step containing a malformed numeric-with-unit pattern (e.g. `100.5.5 mL`, `1e3 mL`, `-5 mL`). Update the verb extractor to split on `[\s\t,;]` and reject any step starting with non-`[A-Za-z]`. Add 8 tests: malformed decimal, scientific notation, negative volume, leading whitespace, semicolon-suffix, comma-suffix, tab-prefix, and the existing happy paths still pass.

**Acceptance:** Stricter parsing; ≥8 new tests; no false-pass on adversarial inputs.

---

## A10 — Add `expires_at` and `bundle_version` to `SynthesisBundle`

**Goal:** Today a signed bundle has `nonce` and `timestamp` (replay-window) but no explicit expiry, and no schema version. The threat model assumes time-bounded bundles (§3.4) and assumes a forward path for schema evolution.

**Prompt for Claude Code:**

> In `crates/invariant-biosynthesis-core/src/models/bundle.rs`, add `bundle_version: u32` (canonical = current = 1) and `expires_at: DateTime<Utc>` to `SynthesisBundle`. The signature canonical-bytes already cover the whole struct, so adding these is a hard schema break — bump `bundle_version` to 1, document that fixtures with no `bundle_version` field fail load, and add a one-time migration helper `SynthesisBundle::upgrade_v0(...)` that adds `bundle_version=1` and `expires_at = timestamp + Duration::hours(24)` for legacy fixtures. The validator must reject any bundle whose `expires_at < now`. Add 4 tests: missing version rejected, future expiry accepted, past expiry rejected, upgrade helper round-trips. Update every fixture in `examples/` and every test fixture inline.

**Acceptance:** Schema versioned; expiry enforced; existing fixtures migrated; ≥4 new tests.

---

## A11 — Add `required_attestation_kinds` and `max_bundles_per_day` to `BioProfile`

**Goal:** Threat model assumes profiles can require specific attested-input kinds (e.g. "BSL-4 needs an instrument-temperature attestation") and per-principal rate caps. Profiles today have neither.

**Prompt for Claude Code:**

> In `models/profile.rs`, add `required_attestation_kinds: Vec<String>` (default empty) and `max_bundles_per_day_per_principal: Option<u32>` (default `None`). Wire `required_attestation_kinds` into the validator: every kind in the list must appear at least once in the `&[AttestedInput]` slice or the verdict's `screening_attestation` check fails. Wire the rate cap into `threat.rs::ThreatScorer` (depends on Phase-2 §B Step 2 wiring; if Phase-2 §B-2 has not yet landed, gate this behind a `RateCounter` standalone helper that the validator instantiates lazily). Add 5 tests: (a) no kinds required → no check; (b) one required, present → pass; (c) one required, absent → fail; (d) rate cap unset → no check; (e) rate cap exceeded → fail. Add the new fields to `government_bsl4_restricted.json`.

**Acceptance:** Per-profile attestation + rate enforcement; ≥5 new tests; BSL-4 profile demonstrates both.

---

## A12 — Property-based tests for D-, P-, C-, PR-families

**Goal:** Every existing test is hand-crafted. Property testing would catch silent edge cases (empty input, all-N, lowercase only, length-exactly-window, length-window-minus-one). Today none of those are exercised systematically.

**Prompt for Claude Code:**

> Add `proptest` as a dev-dependency to `invariant-biosynthesis-core`. For every invariant, write at least one proptest that asserts an *invariant property* (something true for all inputs of a given shape), e.g.: D7 entropy never panics on any byte string of length 0..10000; D8 returns Pass on any sequence of length < 10 nt; P10 is idempotent under repeated normalisation; PR4 returns the same status on permutation-of-same-volume-tokens; every invariant on every payload of every length 0..200 returns either Pass / Fail / Advisory (never panics). Aim for one proptest per invariant (34 total) plus 4 cross-invariant properties (validator never panics; verdict approval iff every check passes; canonical-bytes deterministic; signature round-trips on every random bundle). Use a fixed seed so failures are reproducible.

**Acceptance:** ≥38 new proptests; runs in <60 s; CI configured to print the seed on failure.

---

## A13 — Edge-case unit tests for invariant boundaries

**Goal:** Property tests cover broad shape; spot tests cover the boundaries the threat model cares about.

**Prompt for Claude Code:**

> Add explicit unit tests for: empty DNA (`""`), single-base DNA (`"A"`), exactly-window-length DNA (D8 100 nt, D9 20 nt), all-N DNA, all-lowercase DNA, mixed-case peptide, peptide of length exactly the P3 window (18), peptide of length exactly the P8 window (6), empty SMILES, lowercase SMILES (`"cn1cc..."`), SMILES with bracket atoms (`"[Cl-]"`), empty protocol, single-step protocol, exactly 256-step protocol, 257-step protocol. One test file per family; ≥20 new tests total.

**Acceptance:** ≥20 new boundary unit tests; clippy clean.

---

## A14 — Backfill the unimplemented-policy test matrix

**Goal:** `ValidatorConfig::allow_unimplemented_invariants` was added in Phase-1 Step 2. After Steps 6–9 landed, no shipping invariant returns `Unimplemented`, but the policy is still unexercised. A future addition that returns `Unimplemented` will silently bypass the policy unless tests cover both modes.

**Prompt for Claude Code:**

> Add a test-only `StubInvariant` that always returns `Unimplemented`, gated behind `#[cfg(test)]` and inserted into the validator via a new `with_extra_invariant(...)` test helper. Write 4 tests: (a) `allow=false` + stub present → fail; (b) `allow=true` + stub present → check recorded as advisory pass; (c) reason string lists the stub's id; (d) approval still requires every other invariant to pass.

**Acceptance:** Policy fully exercised; ≥4 new tests.

---

## A15 — Reconcile CHANGELOG with git history

**Goal:** `CHANGELOG.md` describes versions 0.0.1–0.0.5 in detail. `git log --oneline` shows one commit (`8e672a3 Initial commit`). An auditor reading the CHANGELOG and then `git log` will see a contradiction.

**Prompt for Claude Code:**

> Either: (a) rewrite `CHANGELOG.md` to a single `0.0.5 (2026-04-25) — initial public release` entry that summarises the shipped surface without claiming a 0.0.1→0.0.5 history that doesn't exist; or (b) add a banner at the top of `CHANGELOG.md` explaining that the version-by-version history reflects logical development phases (gap-closure Steps 1–22) but the public git history starts at the initial commit. Prefer (a) for cleanliness; if the team wants to keep the per-step narrative, use (b) and add the banner verbatim. Either way, add a `cargo deny` advisories block to remind reviewers to bump the version on the next release.

**Acceptance:** CHANGELOG no longer contradicts git history.

---

## A16 — MSRV verification in CI

**Goal:** `Cargo.toml` claims `rust-version = "1.75"`. CI today probably uses `stable`, which is 1.85+. Code may have drifted to 1.76+ features without anyone noticing.

**Prompt for Claude Code:**

> Add a `.github/workflows/msrv.yml` job that runs `cargo +1.75 build --workspace` on `ubuntu-latest`. If the build fails, raise the `rust-version` field instead of pinning the toolchain — the floor should match what we actually compile against. Add a `Swatinem/rust-cache@v2` step. Either way, the floor + CI now match.

**Acceptance:** MSRV either is verified on every PR or has been bumped to a verifiable version.

---

## A17 — Pin workspace dependency versions

**Goal:** Workspace deps use caret ranges (`"2.1"` for `ed25519-dalek`, `"1.0"` for `serde`, etc.). A minor-version bump can change behaviour silently. For a security-critical core crate this is loose.

**Prompt for Claude Code:**

> In root `Cargo.toml`, replace every workspace dep version range with the exact version that's already in `Cargo.lock` (e.g. `ed25519-dalek = "=2.1.1"`). Run `cargo update --dry-run` before/after to confirm no transitive surprise. Add a `[workspace.dependencies]` doc comment explaining the policy. Add a `dependabot.yml` rule that opens grouped weekly PRs for these pins so the team explicitly reviews each bump.

**Acceptance:** All workspace deps exactly pinned; dependabot configured; tests still green.

---

## A18 — Audit-readiness packet refresh

**Goal:** Last document the §A delta in a single place an external auditor can walk in 30 minutes.

**Prompt for Claude Code:**

> Update or create `docs/AUDIT-READINESS.md` (per Phase-2 Step 20, but with the §A additions baked in). Include: the build-and-test invocation, the feature-flag matrix, the canonical-bytes contract from §A6, the kid grammar from §A5, the profile-signature requirement from §A3, the bundle schema (post-§A10), the supply-chain summary (post-§A17), and the threat-model § that each invariant defends. Cross-link to `docs/spec-phase1-gap-closure.md`, `docs/spec-phase2-operational.md`, and this file. Cap at 1500 words.

**Acceptance:** Single auditor-walkable doc that reflects the post-§A state.

---

# §B — Phase-2 Operational Hardening (defer or run after §A)

Steps B1–B21 are the previously-drafted Phase-2 plan, retained verbatim from `docs/spec-phase2-operational.md`. **Do not re-read them here**; treat that file as the canonical source. The list, in order:

| ID | Title (see archived doc for full prompt) |
|---|---|
| B1 | Re-baseline (subsumed by A1; mark done when A1 lands) |
| B2 | Wire threat scorer into validator |
| B3 | Implement `FragmentationBypassDetector` (StatefulInvariant) |
| B4 | Webhook + syslog incident alert sinks |
| B5 | S3 replication + Merkle-witness webhook |
| B6 | TPM 2.0 key-store backend (`feature = "tpm2"`) |
| B7 | `monitor` CLI mode |
| B8 | Profile-driven D7 codon-entropy band (subsumed by A8 — mark done when A8 lands and merge any spec-doc text) |
| B9 | Profile-driven PR2 vocabulary (subsumed by A8 — same note) |
| B10 | Persistent attestation nonce log |
| B11 | Optional ViennaRNA D9 (`feature = "viennarna"`) |
| B12 | Optional RDKit/SMARTS C-family (`feature = "rdkit-cheminformatics"`) |
| B13 | Optional BLAST/HMMER homology (`feature = "blast-screening"`) |
| B14 | Twist DNA platform adapter |
| B15 | CEM Liberty + Chemspeed adapters |
| B16 | Chemical examples + expanded demo campaign |
| B17 | Criterion benches + `BASELINES.md` |
| B18 | Differential E2E + audit replication E2E tests |
| B19 | Release workflow with signed binaries + SBOM |
| B20 | Pre-audit hardening pass (subsumes A18 — mark done when A18 lands) |
| B21 | Open the hardening PR |

Run §B in dependency order **after** §A. The merge order matters: §A removes silent integration gaps that §B's heavier features otherwise paper over.

---

## Notes on ordering and parallelism

- §A1 is strictly first.
- §A2–A11 are all small, mostly-independent core-crate edits. They can be done in parallel by separate agents in worktrees. Watch for collisions on `models/profile.rs` (A3, A8, A11 all touch it) — schedule those serially or coordinate the diff.
- §A12, A13, A14 are pure test additions, parallelisable trivially.
- §A15, A16, A17, A18 are housekeeping, parallelisable.
- §B1 = A1 (alias).
- §B steps depend on §A as noted in the table above.

If parallelising, give each worktree its own branch off `hardening` and merge serially via integration commits.

---

## Out of scope

These are real future-work items but explicitly **not** in this spec:

1. OS-keyring + YubiHSM key store backends (Phase-3 hardware diversity).
2. Multi-institutional PCA cross-signing federation.
3. Live LLM-planner integration tests.
4. Lean 4 formal proofs of invariant correctness.
5. Web UI / GUI.
6. FDA 21 CFR Part 11 / EU eIDAS qualified signature compliance integrations.
7. Real-time collaborative review UI for advisory triage.

These will be revisited after §A + §B land and the external audit completes.
