> Superseded by [docs/biosynthesis/spec.md](../../biosynthesis/spec.md) as of 2026-05-19. Kept for historical reference.

# Spec v8 — Deep Gap Remediation (Implementation Prompts)

**Date:** 2026-05-01
**Baseline:** 691 passing tests; `cargo clippy -- -D warnings` clean.
**Branch base:** `main`.
**Predecessors:** `spec-v7-deep-gap-remediation.md`, `spec-v6-gap-remediation.md`, `spec-v5-gap-closure.md`.

## How to use this spec

Each section below is a self-contained **prompt** intended to be given to Claude Code. Run them in the order given (they are roughly ordered by blast radius and dependency). After each step:

1. `cargo build --workspace`
2. `cargo test --workspace`
3. `cargo clippy --workspace -- -D warnings`
4. One commit per step, with a message that names the GAP id.

Do not skip ahead and do not bundle steps. If a step uncovers something the prompt did not anticipate, stop and surface it before continuing.

The 30 gaps from the gap analysis are grouped here into 10 chunks. Each prompt is detailed enough that a fresh Claude Code session, with no other context than the repo and `CLAUDE.md`, can execute it.

---

## Chunk 1 — Profile schema fix (GAP-1)

### Prompt 1.1 — Add `allow_stale_screening` to all built-in profiles

> **Context.** `BioProfile` (in `crates/invariant-biosynthesis-core/src/models/profile.rs`) declares an `allow_stale_screening: bool` field with a partner `stale_screening_max_days: Option<u32>`. The six built-in profiles in `profiles/` should each declare these fields explicitly so that JSON parsing is unambiguous and audit reviewers can read the policy off the file. Today, none of the six profile JSONs declare the field.
>
> **Task.** Read each of `profiles/university_bsl2_dna.json`, `profiles/university_bsl3_dna.json`, `profiles/industry_peptide.json`, `profiles/industry_chemical.json`, `profiles/export_controlled_chemical.json`, `profiles/government_bsl4_restricted.json`. For each, add `"allow_stale_screening": false` near the other policy booleans. Do **not** set `stale_screening_max_days` (it is `Option<u32>` and should remain absent when stale screening is disallowed).
>
> Then add a parser-level test in `crates/invariant-biosynthesis-core/src/models/profile.rs` (or wherever the existing built-in-profile tests live) that asserts: every embedded profile JSON parses and `allow_stale_screening` round-trips to `false`. Also add a `BioProfile::validate` rule that returns an error if `allow_stale_screening = true` and `bsl_level >= 3` — BSL-3 and BSL-4 must always require fresh screening. Add a test for that rule too.
>
> **Acceptance.** All six profile files contain the field; new tests pass; existing tests still pass; clippy clean.

---

## Chunk 2 — CLI surface for attestation and validation (GAP-3, GAP-4, GAP-5, GAP-13, GAP-14)

These five gaps share the `validate` subcommand and should be done together so we touch the file once.

### Prompt 2.1 — Wire `--attest` and `--nonce-log` into validate

> **Context.** `crates/invariant-biosynthesis-core/src/attestation.rs` already implements `AttestationVerifier`, persistent nonce-log loading, and envelope verification. `crates/invariant-biosynthesis-cli/src/commands/validate.rs` declares a `--nonce-log` flag (`pub nonce_log: Option<PathBuf>`) but never passes it to `validator.validate(...)` — the third argument is hardcoded `None`. There is no `--attest` flag at all, even though spec-v7 step-02 mandates one.
>
> **Task.** In `validate.rs`:
> 1. Add `#[arg(long = "attest", value_name = "PATH")] pub attest: Vec<PathBuf>` to `ValidateArgs`. (Use `Vec` so the flag can repeat.)
> 2. In `run_inner` (or whatever the run function is called), if `args.nonce_log` is set, call `AttestationVerifier::load_persistent_nonce_log(path)` (or the equivalent constructor) and thread the resulting nonce log through to `validate()` instead of `None`. After validation, persist any nonce-log mutations back to the same path atomically (write to `*.tmp`, fsync, rename).
> 3. For each `--attest` path: read the file as a COSE_Sign1 envelope, call `AttestationVerifier::verify_envelope(...)`, and on failure exit with code 2 and a clear error pointing at the bad envelope path. On success, attach the verified `AttestedInput` / `AttestedReading` to the validator inputs (or whichever channel the validator uses to consume attested inputs — read the existing library API rather than guessing).
> 4. Add integration tests under `crates/invariant-biosynthesis-cli/tests/`: one for `--attest` happy path, one for tampered envelope (must exit non-zero), one for `--nonce-log` round-trip showing replay rejection across two CLI invocations.
>
> **Acceptance.** New tests pass; existing tests still pass; clippy clean.

### Prompt 2.2 — Auto-wire threat scorer at CLI for BSL ≥ 3 with override

> **Context.** `ValidatorConfig::new` in `crates/invariant-biosynthesis-core/src/validator.rs` already auto-wires the threat scorer when `profile.bsl_level >= 3`. But `validate.rs` only adds the threat scorer when the user explicitly passes `--threat-threshold`. Result: library users get a default protection that CLI users silently lose.
>
> **Task.** In `validate.rs::run_inner`, after the profile is loaded:
> 1. If `profile.bsl_level >= 3` and `args.threat_threshold` is `None`, do **not** disable the threat scorer — let the library default kick in. Emit a single line to stderr: `note: threat scorer auto-enabled for BSL≥3 profile; pass --threat-threshold <f64> to override or --no-threat-scorer to opt out`.
> 2. Add `#[arg(long)] pub no_threat_scorer: bool`. When set, call `ValidatorConfig::without_threat_scorer()`. If the user passes both `--no-threat-scorer` and `--threat-threshold`, exit with a usage error.
> 3. Test: run validate against a BSL-3 profile with no flags, assert stderr contains the auto-enable note. Run with `--no-threat-scorer` and assert the note is absent and the scorer is in fact off (assert via a structured-output field or via an audit-log entry).
>
> **Acceptance.** Tests pass; clippy clean. The CLI behavior matches the library default.

### Prompt 2.3 — Add `--differential` to validate

> **Context.** `crates/invariant-biosynthesis-core/src/differential.rs` implements `DifferentialValidator`, and there is a separate `differential` subcommand. Spec-v7 step-12 wants `validate` itself to support a `--differential <secondary-config-path>` flag so a single command can run primary + secondary validators and escalate to Fail on disagreement.
>
> **Task.** Add `#[arg(long, value_name = "CONFIG")] pub differential: Option<PathBuf>` to `ValidateArgs`. When set:
> 1. Load the secondary `ValidatorConfig` from the path. Decide and document the file format (likely a JSON config matching whatever the existing `differential` subcommand consumes — read it before designing).
> 2. Run primary and secondary validators against the same bundle.
> 3. Use `DifferentialValidator::compare(...)` (or whatever the public API is — confirm before calling) to produce a `DifferentialReport`.
> 4. If verdicts disagree, the final verdict is Fail with reason `"differential disagreement: primary=X secondary=Y"`. Attach the full report to structured output.
> 5. Add tests: agreement → primary verdict preserved; disagreement → Fail; secondary missing/invalid → clear error before validation runs.
>
> **Acceptance.** Tests pass; clippy clean. The standalone `differential` subcommand still works (no regression).

### Prompt 2.4 — Quorum policy `n:M` parser

> **Context.** `validate.rs` has `pub quorum: String` and a helper that parses it into a `QuorumPolicy`. Today only `"all"`, `"any"`, and `"majority"` parse. Spec-v7 step-02 requires also accepting `"n:M"` → `QuorumPolicy::AtLeast { n, of: M }`.
>
> **Task.** Update the helper to: trim, lowercase, then match `all`, `any`, `majority`. If the input contains a colon, parse `n` and `M` as `usize`, validate `1 <= n <= M`, and return `QuorumPolicy::AtLeast { n, of: M }`. On any parse failure, return a `clap`-friendly error string: `quorum format invalid; expected 'all', 'any', 'majority', or 'n:M' (e.g. '2:3')`. Add unit tests for each case including malformed inputs (`"2:0"`, `"3:2"`, `":"`, `""`).
>
> **Acceptance.** Tests pass; clippy clean.

---

## Chunk 3 — Incident responder integration (GAP-2)

### Prompt 3.1 — Wire `IncidentResponder` into validator and CLI

> **Context.** `crates/invariant-biosynthesis-core/src/incident.rs` defines `IncidentResponder`, `IncidentTrigger`, `IncidentRecord`, and the `AlertSink` trait with `Stderr`, `File`, and `InMemory` implementations. None of the validator code paths invoke it today. Spec-v7 step-16 requires the responder to fire on certain failure classes.
>
> **Task.**
> 1. In `ValidatorConfig`, add an optional `incident_responder: Option<Arc<Mutex<IncidentResponder>>>` field plus `with_incident_responder(...)` builder. (Confirm the existing API style — many configs in this crate already use `Arc<Mutex<...>>`; match it.)
> 2. After the validator computes its final verdict, call the responder for these triggers:
>    - any `Verdict::Fail` at `bsl_level >= 3`
>    - any S1 (FragmentationBypassDetector) hit at any BSL
>    - consensus disagreement (when the consensus screener returns disagreement)
>    - attestation envelope verification failure
>   Pass an `IncidentRecord` carrying the bundle id, profile id, BSL level, trigger kind, and the verdict reason.
> 3. Default builder behavior at BSL ≥ 3: auto-wire a `StderrSink` so operators always see incidents, with the same opt-out pattern as the threat scorer.
> 4. Add a `--incident-file <path>` flag to `validate` that constructs a `FileSink`. Append-only JSONL.
> 5. Tests: BSL-3 fail produces an incident record on stderr; S1 hit produces one at any BSL; `--incident-file` path is created and contains the expected record; opt-out flag suppresses output.
>
> **Acceptance.** No new runtime deps in default build; clippy clean; tests pass.

---

## Chunk 4 — Acceptance-gate ledger and `verify-self gates` (GAP-7, GAP-10)

### Prompt 4.1 — Create `docs/acceptance-gates.json` and the verifier subcommand

> **Context.** Spec-v7 step-05 requires replacing prose "production-ready" claims with a JSON ledger that CI can check. None of this exists yet.
>
> **Task.**
> 1. Author `docs/acceptance-gates.json` with this schema:
>    ```json
>    {
>      "schema_version": 1,
>      "gates": [
>        {
>          "id": "G1",
>          "title": "D-family calibrated with published FN/FP CIs",
>          "status": "not_met",
>          "evidence": null,
>          "owner": "core",
>          "depends_on": ["GAP-9", "GAP-23"]
>        },
>        ...
>      ]
>    }
>    ```
>    Gates G1–G7 cover: (G1) D-family calibration, (G2) real chemistry backend, (G3) HSM backend, (G4) audit replication, (G5) synthesizer adapter end-to-end, (G6) perf baselines published, (G7) external audit completed. All start `not_met` or `in_progress`.
> 2. Implement `invariant-bio verify-self gates` as a subcommand under the existing `verify-self` group. It loads the ledger, prints a table (id, title, status, owner), exits 0 if all `met`, 1 otherwise. Add a `--strict` flag that exits 1 if any gate is `not_met` (used by CI; same semantics as the default but the name documents intent).
> 3. Update README.md: add a one-line status block near the top: `Acceptance gates: 0/7 met — see docs/acceptance-gates.json`. Do not add badges; plain text only.
> 4. Add a CI step (or document the command if CI config lives elsewhere) that runs `invariant-bio verify-self gates`. The build must not fail just because gates are unmet — failure is reserved for malformed ledger or unknown status values. (CI will fail closed once gates flip to `met` and someone needs to argue against regressing.)
> 5. Add a parser test for malformed ledger and an integration test that runs the subcommand against a fixture ledger and asserts exit code + stdout shape.
>
> **Acceptance.** Tests pass; clippy clean; the README line is accurate.

---

## Chunk 5 — Stateful detector store (GAP-6)

### Prompt 5.1 — `StatefulStore` trait with in-memory and file backends

> **Context.** `crates/invariant-biosynthesis-core/src/invariants/stateful.rs` keeps the S1 fragmentation-detection window in a private `VecDeque<Observation>`. Two firewall processes on the same host see independent windows and cannot detect cross-process fragmentation. Spec-v7 step-06 wants a pluggable backend.
>
> **Task.**
> 1. Define `pub trait StatefulStore: Send + Sync` with:
>    ```rust
>    fn record(&mut self, obs: Observation) -> Result<(), StatefulStoreError>;
>    fn window(&self, max_age: Duration) -> Result<Vec<Observation>, StatefulStoreError>;
>    fn prune_expired(&mut self, max_age: Duration) -> Result<usize, StatefulStoreError>;
>    ```
>    (Use the existing `Observation` type; do not redefine it.)
> 2. Refactor `FragmentationBypassDetector` to hold `Box<dyn StatefulStore>`. Provide `InMemoryStatefulStore` (the existing behavior) as the default constructor.
> 3. Implement `FileStatefulStore` backed by an append-only JSONL file with file-locking (`fs2::FileExt::lock_exclusive` or equivalent — pick what is already used elsewhere in the workspace). On `record`, append + fsync. On `window`, scan the tail. Prune by writing a fresh file under a temp name and renaming. Document concurrency limits clearly: this is "single-host multi-process," not distributed.
> 4. Add `--stateful-store <path>` to `validate`. When set, build the detector with `FileStatefulStore::open(path)`. Default remains in-memory.
> 5. Tests: in-memory store passes existing S1 tests; file store survives a process restart (write some observations, drop the store, re-open, assert window is intact); two store handles in the same process see each other's writes after fsync; prune correctness.
>
> **Acceptance.** Existing S1 tests still pass with the in-memory default; new file-store tests pass; clippy clean.

---

## Chunk 6 — Synthesizer adapters and execution-token CLI (GAP-15, GAP-16, GAP-17)

These three are interdependent; do them as one chunk.

### Prompt 6.1 — Design doc first

> **Context.** Spec-v7 step-10 mandates a design doc before any code: `docs/synthesizer-adapter-design.md`. The doc must cover execution-token format, pre-flight handshake, post-run readback, key handling, and CLI integration. There is no code for synthesizer adapters yet.
>
> **Task.** Write `docs/synthesizer-adapter-design.md`. Sections:
> 1. Goals and non-goals.
> 2. Execution token: COSE_Sign1 over a CBOR payload with fields `{bundle_hash, profile_id, synthesizer, window_start, window_end, nonce, issuer_kid}`. Token signing uses the operator authority key. Token TTL ≤ 24 h.
> 3. Pre-flight: synthesizer adapter receives token, verifies signature with operator pubkey it is configured to trust, checks `window_start <= now <= window_end`, refuses if nonce already burned in its own log.
> 4. Post-run readback: synthesizer signs an `AttestedReading` with its instrument key, including `{token_hash, run_status, observed_volume_ml, timestamp, nonce}`. Returned to operator for verification.
> 5. CLI surface: `invariant-bio issue-token --bundle <path> --synthesizer <name> --window-end <iso8601> --signing-key <handle>` and `invariant-bio verify-readback --readback <path> --instrument-pubkey <hex>`.
> 6. Trust establishment: who provisions instrument pubkeys, how revocation is communicated. (Out of scope to implement; in scope to write down assumptions.)
> 7. Reference vendors planned for future phases: Twist (DNA), CEM Liberty (peptide), Chemspeed (chemical). No vendor SDK calls in this phase — only the protocol.
>
> Surface the doc to the user for review before any code lands. **Stop here and wait.**

### Prompt 6.2 — Implement `issue-token` and `verify-readback` CLI commands

> **Prerequisite.** Prompt 6.1 must be approved by the user.
>
> **Context.** With the design approved, implement the two CLI subcommands and the supporting library code. `crates/invariant-biosynthesis-core/src/models/execution_token.rs` may already exist — read it before adding anything. Reuse `AttestationVerifier` for readback verification.
>
> **Task.**
> 1. If missing, add `ExecutionToken` and `ExecutionTokenBuilder` types in core, behind no feature flag (they are protocol primitives).
> 2. Create `crates/invariant-biosynthesis-cli/src/commands/issue_token.rs` and `verify_readback.rs`. Wire both into the CLI dispatcher. Match the flag set from the design doc.
> 3. `issue-token` reads the bundle, hashes it, builds the COSE_Sign1 envelope with the signing key, prints the envelope to stdout (or `--out` if set).
> 4. `verify-readback` reads the readback envelope, verifies the signature against `--instrument-pubkey` (hex), prints a JSON summary on success and exits non-zero on failure.
> 5. Tests: round-trip issue → verify (against the bundle hash); tampered readback fails; expired window fails; replayed nonce fails (requires touching the persistent nonce log used by attestation).
>
> **Acceptance.** Tests pass; clippy clean. No vendor SDK code.

### Prompt 6.3 — Synthesizer adapter scaffolding (deferred / feature-gated)

> **Prerequisite.** 6.1 and 6.2 done.
>
> **Task.** Create `crates/invariant-biosynthesis-core/src/adapters/{twist,cem_liberty,chemspeed}/mod.rs` behind features `adapter-twist`, `adapter-cem-liberty`, `adapter-chemspeed`. Each module defines a `SynthesizerAdapter` trait implementation that *only* exercises the protocol (token verify in, readback sign out) using an in-process mock. No vendor HTTP/serial calls. Add an example profile per adapter (e.g., `profiles/bsl2_twist_oligo_dev.json`). Tests: protocol round-trip per adapter.
>
> **Acceptance.** With each feature enabled, tests pass. Default build is unaffected. Clippy clean under each feature.

---

## Chunk 7 — Documentation and policy (GAP-11, GAP-12, GAP-21, GAP-29, GAP-30)

These are pure-doc steps and can run in any order, but doing them together captures audit-readiness for one review pass.

### Prompt 7.1 — Author `docs/AUDIT-READINESS.md`

> **Context.** External audits will ask for a single document that names every cryptographic primitive, every invariant, every CLI flag, and every known limitation. Spec-v7 step-03 mandates `docs/AUDIT-READINESS.md`.
>
> **Task.** Write `docs/AUDIT-READINESS.md` with these sections, in order:
> 1. **Scope and version.** Repo SHA, crate versions, date.
> 2. **Build instructions.** Reproduce a release binary from a clean checkout. Include `cargo build --workspace --release` and any feature flags.
> 3. **Crate inventory.** One-paragraph description of each of the five crates.
> 4. **Cryptographic primitives.** Ed25519 (crate `ed25519-dalek` + version), SHA-256 (crate + version), COSE_Sign1 (crate + version). For each, state where in the code it is used and what payload it covers.
> 5. **Invariant matrix.** For D1–D10, P1–P10, C1–C10, PR1–PR4, S1: a row with file path, function name, verdict severity (Block/Advisory), and any known gaps. Lift the gap data from this spec where applicable.
> 6. **CLI feature matrix.** Every subcommand and flag with one-line semantics.
> 7. **Known limitations.** D-family uncalibrated; chemistry advisory-only; HSM file-backed; audit not replicated by default; S1 process-local; nonce log unrotated. Cite the GAP ids from this spec.
> 8. **Sensitive-operations checklist.** What must operators do that the firewall cannot enforce (key custody, profile signing, log monitoring).
> 9. **Reproducible-build notes.** Toolchain pin (`rust-toolchain.toml`), `cargo-deny` config, `Cargo.lock` policy.
>
> Read the actual code to fill in file paths and verdict severities — do not extrapolate.
>
> **Acceptance.** Doc exists and is accurate when spot-checked against the code by the next reviewer.

### Prompt 7.2 — Refresh `docs/threat-model.md`

> **Context.** The current threat model predates S1 (FragmentationBypassDetector), the chemistry advisory-only verdict policy, and the D10 calibration gap.
>
> **Task.** Edit `docs/threat-model.md` to add four sections:
> 1. **Cross-bundle fragmentation (S1).** Describe the attack (split a hazardous synthesis across multiple bundles), how `FragmentationBypassDetector` mitigates it within one process, and the residual risk that fleet-wide fragmentation across multiple firewall processes is undetected until `StatefulStore`-with-shared-backend is deployed (see GAP-6).
> 2. **Chemistry coverage limitations.** State plainly that C1–C10 are heuristic regex/string-matching producing Advisory verdicts only. Do not claim CWC-level assurance until a real cheminformatics backend lands (GAP-8).
> 3. **D-family calibration gap (D10).** K-mer homology lacks published FN/FP confidence intervals. Residual risk is operator-borne until the calibration harness runs and `docs/d-family-calibration.md` exists.
> 4. **Open assumptions.** Single-firewall deployment by default, file-based key storage in dev, local-only audit log, process-local stateful detection, manual nonce-log rotation.
>
> **Acceptance.** No false claims survive the edit. Reviewer can map every claim to either code or this spec's GAP table.

### Prompt 7.3 — Decide protocol-vocabulary policy

> **Context.** `PROTOCOL_STEP_VOCAB_VERSION = 1` in `invariants/protocol.rs`. Profiles can narrow the verb list via `allowed_protocol_steps`, but it is unclear whether profiles can also *extend* the vocab. Spec-v7 step-21 wants a written decision.
>
> **Task.** Write `docs/protocol-vocab-decision.md`. Compare two policies:
> - **A: Global ceiling.** Profiles may only narrow. Adding a verb requires a code release + RFC + deprecation window.
> - **B: Per-profile extension.** Profiles may extend, but each extension must be signed by an authority key with a `protocol-vocab-extension` scope, verified at profile load.
>
> Recommend one (default to A unless there is a strong field-driven reason for B). Implement only the recommended policy:
> - If A: tighten validator to reject any verb not in the global vocab even if the profile lists it as allowed; add test.
> - If B: add scope verification on profile load; reject extensions not signed by an extension-scoped key; add tests for accept/reject paths.
>
> **Acceptance.** Doc exists; chosen policy is enforced by code; tests pass.

### Prompt 7.4 — Disclosure SLA and RFC template

> **Task.**
> 1. Update `SECURITY.md`: add a *Response timelines* section with explicit SLAs (acknowledge 3 days; triage 7 days; High fix 30 days; Medium 90 days; Low next minor; coordinated disclosure default 90 days).
> 2. Create `docs/rfcs/0000-template.md` with sections: Summary, Motivation, Detailed design, Drawbacks, Alternatives, Unresolved questions, Adoption checklist.
> 3. Create `docs/rfcs/README.md` listing change classes that *require* an RFC: profile schema changes, invariant verdict semantics, audit format, attestation envelope format, CLI surface (subcommand add/remove or flag rename).
>
> **Acceptance.** Files exist; SLAs are realistic; reviewer can use the template without further instruction.

### Prompt 7.5 — Export-control posture

> **Task.** Write `docs/EXPORT-CONTROL.md`. Document EAR classification of cryptographic dependencies (`ed25519-dalek`, `sha2`, `coset` or whichever COSE crate is in use). Note that release-build artifacts are subject to BIS rules; list jurisdictions excluded from binary distribution. Add an *advisory* CI step (or document the command) that fails if `deny.toml` is malformed; do not attempt automatic export-control classification.
>
> **Acceptance.** Doc exists; CI does not get a false positive on the existing dep set.

---

## Chunk 8 — Architectural-deferred backends (GAP-8, GAP-9, GAP-18, GAP-19, GAP-25, GAP-26)

These items each need a written decision before code. Do **not** implement first.

### Prompt 8.1 — Chemistry backend decision (GAP-8)

> **Task.** Write `docs/chemistry-backend-decision.md` comparing RDKit (C++ FFI), OpenBabel (C++ FFI), and a Python sidecar (subprocess JSON-RPC). Compare on: license, build complexity on macOS+Linux+Windows, perf (one or two cited benchmarks; if none exist, say so), feature coverage (SMARTS, fingerprints, descriptors), maintenance posture. Recommend one. Define a `CheminformaticsBackend` trait sketch. Mark the work as "deferred — start in next phase." Do not write FFI code.
>
> **Acceptance.** Doc exists with a clear recommendation and trait sketch.

### Prompt 8.2 — D-family calibration plan (GAP-9, GAP-23)

> **Task.** Write `docs/d-family-calibration-plan.md`. Describe a calibration harness under `crates/invariant-biosynthesis-core/examples/dna_calibration/` that grid-searches `k ∈ [4..=8]`, Jaccard threshold ∈ `[0.20, 0.60]`. Inputs: HHS Select Agent positives, benign negatives, adversarial variants (codon-shuffled, frameshifted). Outputs: per-operating-point FN/FP rates with Clopper–Pearson 95% CIs.
>
> Then create `crates/invariant-biosynthesis-core/src/statistics.rs` with:
> ```rust
> pub fn clopper_pearson(successes: u64, trials: u64, confidence: f64) -> (f64, f64);
> pub fn cohen_kappa(rater_a: &[u8], rater_b: &[u8]) -> f64;
> pub fn fleiss_kappa(matrix: &[Vec<u8>]) -> f64;
> ```
> with property tests against scipy reference values (use cited constants in the test, not a runtime dep on Python). Add `statrs` to Cargo.toml if it is not already there. Do **not** run the calibration harness yet (corpus does not exist). Stub the harness binary so it compiles.
>
> **Acceptance.** Plan doc exists; statistics module exists with tests; harness compiles with placeholder data; clippy clean.

### Prompt 8.3 — P6/P8/P9 peptide-invariant decision (GAP-18)

> **Task.** Write `docs/peptide-invariants-decision.md`. Compare:
> - **A:** Downgrade P6 (MHC), P8 (aggregation), P9 (PTM) verdicts to Advisory permanently; add a strict opt-in mode that runs the heuristic but treats the heuristic verdict as Block (operator accepts known FP/FN).
> - **B:** Integrate real predictors (NetMHCpan for P6, TANGO for P8, structural-context model for P9) behind feature flags.
>
> Recommend A as the default near-term path with B as the stretch goal. Implement A: each of P6/P8/P9 returns `InvariantStatus::Advisory { engine: "heuristic-pep-v1" }`. Add a "strict-peptide-heuristics" config flag for the opt-in escalation. Update tests.
>
> **Acceptance.** Doc exists; chosen path is implemented; verdict severity is documented in `docs/AUDIT-READINESS.md`.

### Prompt 8.4 — D9 ΔG decision (GAP-19)

> **Task.** Write `docs/d9-secondary-structure-decision.md`. Recommend gating real ΔG-based screening behind a `vienna-rna` feature that shells out to `RNAfold`. When the feature is off, D9 emits Advisory with engine `"d9-heuristic"`. When on, fail-closed if the binary is missing. Implement the feature flag and the subprocess invocation. Mock the binary in tests via a small wrapper script under `tests/fixtures/`.
>
> **Acceptance.** Default build behavior unchanged; with feature on, tests using the mock pass; clippy clean under both feature configurations.

### Prompt 8.5 — Audit replication and HSM stubs (GAP-25, GAP-26)

> **Task.** For each of `S3Replicator`, `WebhookWitness`, `TpmKeyStore`, `YubiHsmKeyStore`, `OsKeyringStore`:
> 1. Add a doc comment that this is a stub returning `Unavailable`, with a link to the GAP id from this spec.
> 2. Add a unit test that asserts the stub returns `Unavailable` so future implementers don't accidentally regress the placeholder semantics.
> 3. Add `BioProfile::validate` rule: if `bsl_level >= 3` and the configured key store is `FileBackedKeyStore`, return an error unless an explicit `accept_file_backed_keys_for_bsl_high: bool` field is set to `true` in the profile (with a stern doc comment that this is for development only). Add a test for accept and reject paths.
>
> Do **not** implement the real backends in this chunk. Open follow-up items: real S3 replication (feature `replicate-s3`), real TPM (feature `tpm`), real YubiHSM (feature `yubihsm`). Track these via gates G3 and G4 in the acceptance ledger from Chunk 4.
>
> **Acceptance.** Stub semantics are now self-documenting and gate-protected; clippy clean.

---

## Chunk 9 — Smaller correctness and observability items (GAP-20, GAP-24, GAP-27, GAP-28)

### Prompt 9.1 — Verify D7 CUTG completeness (GAP-20)

> **Task.** Read `crates/invariant-biosynthesis-core/src/invariants/dna.rs` around the D7 implementation. Confirm that all four organisms (`e_coli`, `s_cerevisiae`, `h_sapiens`, `cho_k1`) have CUTG tables, that the chi-squared statistic uses degrees of freedom equal to (codon_count − 1), and that the p-value threshold is sourced (cite the source as a doc comment). If any organism is missing a table, add it from a documented CUTG snapshot. Add an integration test with five codon-skewed sequences (expected Block) and five typical sequences (expected Pass). Then add a row in `docs/AUDIT-READINESS.md` (Chunk 7.1) for D7 with the source and threshold.
>
> **Acceptance.** Tests pass; doc comment cites the CUTG source; AUDIT-READINESS has the row.

### Prompt 9.2 — Nonce-log rotation (GAP-24)

> **Task.** In `crates/invariant-biosynthesis-core/src/attestation.rs`, change the persistent nonce log from a single growing file to segment-based storage:
> - Default segment size: 64 MiB. Default max age: 90 days. Both configurable via builder.
> - When a segment crosses either threshold, seal it: write a checkpoint containing `{segment_start_ts, segment_end_ts, nonce_count, sha256(segment_bytes)}` and start a new segment.
> - On startup, load the active segment plus all sealed segments whose `segment_end_ts` is within the configured retention window. Verify each checkpoint; fail-closed on mismatch.
> - Old, out-of-window segments are ignored (not deleted automatically — leave deletion to operators).
>
> Add tests for: rotation triggers (size and age), checkpoint verification round-trip, corruption detection, and startup loading after rotation.
>
> **Acceptance.** No regression on the existing nonce-log tests; new tests pass; clippy clean.

### Prompt 9.3 — Typed `ConsensusReport` (GAP-27)

> **Task.** In `crates/invariant-biosynthesis-core/src/screening/mod.rs`, replace the string-label disagreement representation with:
> ```rust
> pub struct ConsensusReport {
>     pub sources: Vec<SourceVerdict>,
>     pub agreed: bool,
>     pub majority_verdict: Option<HazardVerdict>,
>     pub policy: QuorumPolicy,
> }
> pub struct SourceVerdict {
>     pub source: String,
>     pub verdict: HazardVerdict,
> }
> ```
> Embed `ConsensusReport` on the screener output. Update consumers to read structured fields. Update the existing string-format test to assert structured fields. Add a test for `AtLeast { n: 2, of: 3 }` with a 1-1-1 split asserting `agreed == false` and `majority_verdict == None`. Update the screening section of `docs/AUDIT-READINESS.md` (Chunk 7.1).
>
> **Acceptance.** All consumers updated; tests pass; clippy clean.

### Prompt 9.4 — Test PCA chain-depth enforcement (GAP-28)

> **Task.** In `crates/invariant-biosynthesis-core/src/validator.rs`, confirm that `BioProfile::max_authority_chain_depth` is read and passed to the chain verifier. If it is not, add the wiring. Then add three tests:
> 1. Chain of depth `N` against profile `max=N` → Pass.
> 2. Chain of depth `N+1` against profile `max=N` → Fail with reason containing "chain depth exceeded".
> 3. Profile JSON with `max_authority_chain_depth = 17` fails `BioProfile::validate` (upper bound is 16 per the existing schema).
>
> **Acceptance.** Tests pass; clippy clean. The first test should already pass; the second is the regression-catcher.

---

## Chunk 10 — Performance baselines (GAP-22)

### Prompt 10.1 — Criterion harness and `docs/PERFORMANCE.md`

> **Context.** Spec-v7 step-14 requires reproducible perf baselines before any future optimization claims. There are no benches today.
>
> **Task.**
> 1. Create `crates/invariant-biosynthesis-core/benches/` with criterion harnesses for: (a) end-to-end validate on small/medium/large bundle fixtures, (b) k-mer homology screen, (c) SMILES screen, (d) audit append + verify.
> 2. Add `criterion` as a dev-dependency.
> 3. Run `cargo bench` once locally, capture the numbers, and write `docs/PERFORMANCE.md` with: hardware spec, exact reproduction recipe, captured baseline numbers as a table, and references to the latency budgets from `spec-gap-analysis-part-4 §M-4` if they exist (otherwise note the absence and propose budgets).
> 4. Do **not** add `cargo bench` to the default CI loop; the baseline is reproduced manually.
>
> **Acceptance.** Benches compile and run; doc exists; clippy clean.

---

## Done definition for this spec

- All 30 GAPs have either an action taken in this branch (commit message references the GAP id) or a written decision committed under `docs/` that defers them with a named owner.
- `docs/acceptance-gates.json` exists and reflects the post-spec status (some gates likely flip to `in_progress`; few flip to `met`).
- `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` clean on every commit.
- README's acceptance-gates line is updated.
- No new public deps in the default build (TPM, S3, ViennaRNA, real chem backends are all feature-gated).

## Sequencing notes

- Chunks 1, 2, 3, 4 are independent and can be done in parallel branches if desired, but the recommended order is 1 → 2 → 3 → 4 because each adds CLI surface or test infrastructure used by later chunks.
- Chunk 5 (StatefulStore) is independent of Chunks 1–4.
- Chunk 6 has an internal stop-and-review gate after 6.1.
- Chunk 7 is mostly docs and can be interleaved.
- Chunk 8 is decision-doc-heavy; do not let it block the operational chunks.
- Chunks 9, 10 can be done last.

## Out of scope for v8

- Real RDKit/OpenBabel integration (deferred — gate G2).
- Real TPM/YubiHSM integration (deferred — gate G3).
- Real S3/webhook replication (deferred — gate G4).
- Vendor synthesizer SDK calls (deferred — gate G5 phase 2).
- External audit (gate G7).
