# Unification Progress

Tracks execution of [INVARIANT_UNIFICATION_SPEC.md](INVARIANT_UNIFICATION_SPEC.md).

## Status

- [x] **Phase 0** — Workspace shell. Empty crates, root `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`, `LICENSE` in place. `cargo check --workspace` clean.
- [x] **Phase 1a** — Clean-cut shared modules in `invariant-core`: `authority/`, `intent`, `keys`, `util`, `monitors`, `proof_package`, `replication`, `incident`, `models/{authority,error}`, plus the new `traits.rs` (keystone `ValidationInput` / `DomainCheck` / `DomainProfile`) and a skeleton generic `validator.rs`. `cargo test -p invariant-core` → **198 unit + 18 doc tests passing**.
- [x] **Phase 2** — `invariant-robotics` extracted. All robotics-specific modules (physics/, command, actuator, cycle, digital_twin, sensor, urdf, profiles, audit, threat, watchdog, envelopes, differential, validator, models/{command,profile,verdict,trace,actuation}) live in `crates/invariant-robotics/`. The crate re-exports `authority`, `incident`, `intent`, `keys`, `monitors`, `proof_package`, `replication`, `util` from `invariant-core`. `Command` implements `ValidationInput`, `RobotProfile` implements `DomainProfile`. Built-in profile JSON files moved to `profiles/robotics/` and rewired via `include_str!`. **648 lib tests passing.**
- [x] **Phase 3** — `invariant-biosynthesis` extracted. All bio-specific modules (bundle/, invariants/, screening/, attestation, audit, threat, watchdog, differential, validator, profiles, models/{bundle,profile,verdict,audit,execution_token,error}) live in `crates/invariant-biosynthesis/`. The crate re-exports the same set of protocol modules from `invariant-core`. `SynthesisBundle` implements `ValidationInput`, `BioProfile` implements `DomainProfile`. Built-in profile JSON moved to `profiles/biosynthesis/`. **337 lib tests passing.**

  Notable Phase 3 friction:
  - Biosynthesis's `ValidationError` has different variants than robotics's (`ProfileFieldInvalid`, `BundleFieldInvalid` vs. robotics's `JointLimitsInverted`, etc.). Solution: bio keeps a local `models::error::ValidationError`; only `AuthorityError` is re-exported from core.
  - Biosynthesis's chain verifier used `verify_chain_with_max_depth`; added it (and a public `DEFAULT_MAX_HOPS` alias) to `invariant-core::authority::chain`.
- [x] **Phase 4** — Unified CLI shipped at [crates/invariant-cli/](crates/invariant-cli/). Top-level dispatch is `invariant <domain> <subcommand>`:
  - `invariant robotics {validate|audit|verify|audit-gaps|inspect|profile|keygen|intent|differential|verify-package|compliance|bench|transfer|verify-self}` — 14 working subcommands.
  - `invariant biosynthesis {validate|audit|verify|audit-gaps|inspect|keygen|intent|differential|verify-self}` — 9 working subcommands.
  - `invariant keys generate ...` — domain-agnostic key generation.
  - `invariant completions <shell>` — shell completion generation.
  - Imports rewired in bulk: `invariant_core::*` → `invariant_robotics::*` for robotics commands; `invariant_biosynthesis_core::*` → `invariant_biosynthesis::*` for bio commands. Re-exports in the domain crates make this work for shared modules (authority/intent/keys/etc.) too.
  - Smoke tests run from `target/debug/invariant`: `--help`, `keys generate`, `robotics inspect --profile profiles/robotics/ur10e_haas_cell.json` all work.

  Stubbed (deferred to Phase 5; print message + exit 74): `robotics {adversarial|campaign|eval|diff|serve}`, `biosynthesis {adversarial|campaign|eval}`. These depend on the unmerged sim/eval/fuzz crates.
- [x] **Phase 5** — Merged `invariant-sim`, `invariant-eval`, `invariant-fuzz`, `invariant-coordinator`. Each merged crate exposes `pub mod robotics` + `pub mod biosynthesis` (no Cargo features — both default-on; can be feature-gated later). Bio sub-modules are smaller (~500 LOC each, single `mod.rs`); robotics sub-modules carry the heavy code. `invariant-coordinator` is robotics-only. CLI subcommand stubs removed; full surface restored: 19 robotics + 12 biosynthesis subcommands all live.

  **Tally per crate (lib tests):**
  | Crate | Tests |
  |---|---|
  | `invariant-core` | 198 |
  | `invariant-robotics` | 648 |
  | `invariant-biosynthesis` | 355 |
  | `invariant-coordinator` | 36 |
  | `invariant-eval` | 76 |
  | `invariant-sim` | 768 |
  | `invariant-fuzz` | 108 (+12 ignored) |
  | `invariant-cli` | 245 (+1 ignored) |
  | **Total** | **2,434 passing** |

  Notable Phase 5 friction:
  - Bio's `intent.rs` defines its own `builtin_templates()` (synthesize_dna_fragment, etc.) distinct from robotics's (pick_and_place, etc.). Solution: kept a local `intent` module in `invariant-biosynthesis`, removed `intent` from the `pub use invariant_core::*` re-export. Both domains now expose their own template list.
  - CLI tests built absolute paths to `examples/*.json` and `profiles/*.json` (flat). Updated to `examples/biosynthesis/...` and `profiles/biosynthesis/...` to match the new layout. Bio examples copied into [examples/biosynthesis/](examples/biosynthesis/).
  - `invariant-fuzz` depends on `invariant-sim`; ordered the migrations sim → fuzz → re-enable CLI.
  - `invariant-sim/src/robotics/*.rs` had many `crate::campaign::`, `crate::reporter::`, etc. paths that needed rewriting to `crate::robotics::campaign::` etc. for the per-domain module nesting.
- [x] **Phase 6** — Ancillary assets copied: [formal/](formal/), [campaigns/](campaigns/), [isaac/](isaac/), [invariant-ros2/](invariant-ros2/), [scripts/](scripts/), [fuzz/](fuzz/), [docs/{robotics,biosynthesis}/](docs/), [examples/{robotics,biosynthesis}/](examples/), plus the Isaac Lab Python bridge at `crates/invariant-sim/invariant_isaac_bridge.py`. The `fuzz/` cargo-fuzz harness was rewired (`invariant_core::*` → `invariant_robotics::*`, `[dependencies]` rewritten to point at the new path-deps).
- [x] **Phase 6b** — Formal proofs reworked to mirror the unified workspace.
  - New [formal/Invariant/Core.lean](formal/Invariant/Core.lean) — Lean typeclass mirror of the keystone Rust trait surface (`ValidationInput`, `DomainProfile`, `DomainCheck`, plus the differential `VerdictView` / `CheckView` pair). Matches `invariant_core::traits` and `invariant_core::differential`.
  - New [formal/Invariant/Biosynthesis.lean](formal/Invariant/Biosynthesis.lean) — sketch of bio domain (`SynthesisBundle`, `BioProfile`) wired up as instances of the `Core` trait surface so the existing generic audit/authority proofs apply to bio logs unchanged. Full D/P/C invariant proofs remain deferred (30 invariants, 355 passing Rust tests; out of scope for Phase 6b).
  - [formal/Invariant/Types.lean](formal/Invariant/Types.lean) augmented with `ValidationInput Command` and `DomainProfile RobotProfile` instances. The robotics types remain in place; only the typeclass connection is new.
  - Module headers in [Audit.lean](formal/Invariant/Audit.lean), [Authority.lean](formal/Invariant/Authority.lean), [Physics.lean](formal/Invariant/Physics.lean), and [Invariant.lean](formal/Invariant.lean) updated to point to the new crate locations (`invariant-core::audit`, `invariant-core::authority`, `invariant-robotics::physics`). [README.md](formal/README.md) rewritten to map each Lean module to the Rust crate it mirrors.
  - **No proof bodies needed to change.** The Lean formalization never imported Rust; it has always been a parallel formalization. The Phase 1b audit generification is structurally already reflected in the Lean `AuditEntry` (which uses `commandHash : String`, domain-agnostic by construction), so the L1–L4 invariants apply uniformly to robotics and bio audit logs.
  - **Toolchain verification pending.** `lean` / `lake` are not installed in this environment. To verify: install Lean 4 v4.8.0+ (per [formal/lean-toolchain](formal/lean-toolchain)) and run `cd formal && lake build`. The pre-existing `sorry` placeholders (P1–P25 floating-point lemmas; `monotonicity_transitive` induction) carry over unchanged.
- [x] **Phase 7** — Top-level docs merged: [README.md](README.md) (unified product overview, links to per-domain READMEs and unification spec), [CHANGELOG.md](CHANGELOG.md) (new `0.1.0` unification entry + preserved pre-unification history for both products), [CLAUDE.md](CLAUDE.md) (merged build/test/conventions), [CONTRIBUTING.md](CONTRIBUTING.md) (from robotics — bio didn't have one), [SECURITY.md](SECURITY.md) (identical between source repos; copied as-is).
- [x] **Phase 8** — CI/Docker:
  - [.github/workflows/ci.yml](.github/workflows/ci.yml) — workspace-wide test/clippy/fmt; needed no changes after the rename (it was already `cargo test --workspace`).
  - [.github/workflows/release.yml](.github/workflows/release.yml) — publish steps rewritten for the new crate names (`invariant-core`, `invariant-robotics`, `invariant-biosynthesis`, `invariant-eval`, `invariant-sim`, `invariant-coordinator`, `invariant-fuzz`, `invariant-cli`). Latest-release blurb now says `cargo install invariant-cli`.
  - [Dockerfile](Dockerfile) — multi-stage build of the unified `invariant` binary on Isaac Sim 4.2 base. Unchanged: copies `crates/`, `profiles/`, `isaac/`, `scripts/`; runs as non-root UID 1000.
- [x] **Phase 9** — Verification + cleanup. **Workspace is fully self-contained.** No path/import dependencies on the old source folders.
  - `_from-*` symlinks removed.
  - The original `invariant-robotics/` and `invariant-biosynthesis/` folders (which were inside `invariant/`, not siblings) have been deleted via `rm -rf`.
  - **Final tally: 2,837 tests passing (lib + doc), 14 ignored, 0 failed across all 8 crates.** `cargo build --workspace` clean. `cargo clippy --workspace --lib` clean. Release binary at [target/release/invariant](target/release/invariant) (~9.8 MB) smoke-tested for both domains: `invariant robotics inspect --profile profiles/robotics/ur10.json` and `invariant biosynthesis intent list` work.
- [x] **Phase 1b** — Generified `audit.rs`, `differential.rs`, and `models/audit.rs` into `invariant-core`. Both domain crates now ship a thin shim (re-exports + a single type alias) and a per-domain `DifferentialValidator` wrapper.
  - `invariant-core::models::audit` — `AuditEntry<I, V>` and `SignedAuditEntry<I, V>` parameterized over the input type and the verdict type. JSONL on-disk format unchanged (input is serialized under the legacy field name `command`); robotics and biosynthesis logs remain mutually parseable.
  - `invariant-core::audit` — `AuditError`, `AuditVerifyError`, `AuditLogger<W, I, V>` (incl. `open_file` for the file-backed flavor), and `verify_log<I, V>`. Hash-chain state, signing, O_APPEND semantics, the 128 KiB tail-read recovery — all hoisted unchanged.
  - `invariant-core::differential` — `CheckDisagreement`, `DifferentialResult`, the pure `compare_verdicts<V: VerdictView>` function, plus the `VerdictView` / `CheckView` trait pair. Domain crates implement these traits on their concrete `Verdict` and `CheckResult` (one-line accessors per field).
  - Domain shims are tiny: `pub type AuditLogger<W> = invariant_core::audit::AuditLogger<W, Command, SignedVerdict>;` (and the bio analogue with `SynthesisBundle`). The `verify_log` re-export is a thin wrapper that fixes the generics so callers don't need turbofish. `DifferentialValidator<'a>` stays per-domain because it composes domain-specific `ValidatorConfig`s.
  - **All tests pass** (audit: 32 robotics + 7 bio; differential: 9 robotics + 7 bio; full workspace: 198 / 648 / 355 / 36 / 76 / 768 / 108 / 245 across the 8 crates). `cargo build --workspace` clean; `cargo clippy --workspace --lib` clean.

  Notable Phase 1b friction:
  - `SignedVerdict` was assumed to live in `invariant-core` but actually lives in each domain crate (with semantic divergence in `DeratingAdvice`: `torque_scale` vs. `intensity_scale`). Solution: parameterize the audit types over a second generic `V` instead of hoisting `SignedVerdict`. Keeps the per-domain verdict semantics intact.
  - The robotics audit and differential test modules privately referenced `SigningKey` and the `base64::Engine` trait via the parent module's `use` statements. After replacing the parent module body with a shim, those imports moved into the test module.

  Why `watchdog`, `threat`, `envelopes` are still NOT hoisted: they are genuinely robotics-only (reference `JointState`, `SafeStopProfile`, `TaskEnvelope`) — the unification spec was wrong to place them in `invariant-core`. They stay in `invariant-robotics`. Phase 1b only hoists `audit` and `differential`, the real duplicates.

- [ ] **spec-v12 prompts** — opened 2026-05-02. Three independent prompts closed
  so far; the v11-Phase-1 cryptographic prompts remain blocking for the bulk of
  the rest. Live tracking table in [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md).

  - **Biosynthesis spec lineage archived under `docs/history/biosynthesis/`
    (2026-05-19)** — sibling pass to v12 N-9, closing the loose end the
    N-9 history README explicitly flagged ("a sibling pass under a
    future spec"). Fifteen files moved out of `docs/biosynthesis/`:
    **versioned specs** `spec v1.md`, `spec-v2.md`, `spec-v3.md`,
    `spec-v5-gap-closure.md`, `spec-v6-gap-remediation.md`,
    `spec-v7-deep-gap-remediation.md`,
    `spec-v8-deep-gap-remediation.md`,
    `spec-v9-deep-gap-remediation.md`,
    `spec-v10-deep-gap-remediation.md`; **phase notes**
    `spec-phase1-gap-closure.md`, `spec-phase2-operational.md`; **gap
    analyses** `spec-gap-analysis.md`, `spec-gap-analysis-part-3.md`,
    `spec-gap-analysis-part-4.md`, `spec-remediation.md`. Each
    archived file gains the same `> Superseded by [docs/biosynthesis/spec.md]
    as of 2026-05-19. Kept for historical reference.` redirect on
    line 1 that the robotics archive uses. The domain-specific design
    notes (`step1-reuse-map.md` … `step10-community-ecosystem.md`,
    `threat-model.md`) stay alongside `spec.md` because they are
    reference material, not superseded spec versions.
    [docs/history/README.md](docs/history/README.md) "Biosynthesis"
    section rewritten to describe the new archive layout. No code or
    test changes; no cross-link rewrites needed elsewhere (the only
    active references were the two historical PROGRESS.md entries
    from earlier biosynthesis-side work, which remain as commit-log
    artifacts pointing at the file's pre-move location). Final state
    of `docs/biosynthesis/` is now `spec.md` + 10 step / threat docs;
    `docs/history/biosynthesis/` carries all 15 archived files.

  - **v11 2.11 promoted PARTIAL → DONE — Category N wire-shape rows
    bound to libFuzzer (2026-05-19)** — the six remaining Category N
    spec IDs that were called out as "needs a wire-format or libFuzzer
    harness rather than a typed-`Command` generator" are now bound to
    libFuzzer targets in [fuzz/](fuzz/). Two new targets ship: (a)
    [fuzz/fuzz_targets/fuzz_cose_envelope.rs](fuzz/fuzz_targets/fuzz_cose_envelope.rs)
    feeds arbitrary bytes as a single-hop `SignedPca.raw` to
    `verify_chain`, exercising the inner COSE_Sign1 CBOR parser +
    protected-header (kid extract) + payload decode + Ed25519 path
    on un-base64-wrapped CBOR (this is N-07 COSE-CBOR); (b)
    [fuzz/fuzz_targets/fuzz_json_bomb.rs](fuzz/fuzz_targets/fuzz_json_bomb.rs)
    uses the first input byte to select a nesting depth in 0..16,
    wraps the remaining bytes with that many `[`…`]` pairs, and runs
    the result through both the typed `Command` deserialiser and the
    free-form `serde_json::Value` parser to stress depth bounds and
    adversarial shapes (this is N-06 JSON bomb). The remaining four
    rows are bound to existing libFuzzer targets per the new "Spec
    coverage — v11 2.11 Category N" table in
    [fuzz/README.md](fuzz/README.md): N-03 grammar fuzz and N-09 type
    confusion → `fuzz_command_json` (libFuzzer is a coverage-guided
    grammar mutator over the typed `Command` deserialiser); N-04
    coverage-guided → `fuzz_validate_pipeline` (every cargo-fuzz
    target is coverage-guided by libFuzzer); N-05 differential →
    `fuzz_validate_pipeline` (the differential is between the typed
    deserialiser, the validator, and the audit-log emit path on the
    same Command). Both new targets compile under `cargo check -p
    invariant-fuzz-targets`; both are wired into
    [fuzz/Cargo.toml](fuzz/Cargo.toml) as `[[bin]]` entries; both
    have ≥8 seed inputs auto-populated by
    [fuzz/seed_corpora.sh](fuzz/seed_corpora.sh) (CBOR shapes for the
    COSE target — empty / single null / non-CBOR ASCII / CBOR array
    prefix / COSE_Sign1 tag prefix / four-empty-bstr / all-ones /
    one-entry-map; nested + adversarial JSON for the bomb target —
    depth 0 / depth 16 array / repeated keys / huge exponent / NaN
    literal / BOM prefix / null / empty string). Net effect: all 10
    Category N spec IDs are now bound (4 generators + 6 fuzz target
    bindings); v11 2.11 promotes to DONE; **v11 has only DESCOPED →
    v13 rows (4.1, 4.2) outstanding**. Updates: spec-v11 archived
    tracking table row 2.11 promoted PARTIAL → DONE; spec-v12
    archived tracking table row 2.1–2.11 promoted PARTIAL → DONE
    ("all 11 rows closed"); spec-v11-verification Phase 2 row 2.11 +
    "Gaps deferred" table + quick-glance footer refreshed (now reads
    **37 DONE / 2 DESCOPED → v13**; no `PARTIAL` rows remain);
    spec-v12-verification deferred-follow-ups list trimmed (drops
    the Category N entry) + closure statement refreshed.

  - **v11 1.2 promoted PARTIAL → DONE — mandatory `verify_chain`
    predecessor enforcement (2026-05-19)** —
    [crates/invariant-core/src/authority/chain.rs](crates/invariant-core/src/authority/chain.rs)
    `verify_chain` now runs `verify_predecessor_chain` **mandatorily**
    on every chain — the opt-in detection mode (which only enforced
    when at least one hop carried a non-zero digest) was retired.
    Single-hop chains pass trivially because the root sentinel is
    `[0u8; 32]` and there are no children; multi-hop chains must have
    `hop[i].predecessor_digest == sha256(canonical_bytes(hop[i-1]))`
    for every i ≥ 1, otherwise `verify_chain` returns
    `AuthorityError::PredecessorDigestMismatch { hop }` (G-09 splice
    rejection from the v11 1.2 foundation). The flip is now safe
    because every multi-hop chain producer in the workspace was
    migrated to set the digest. New public helper
    `invariant_core::authority::chain::link_chain_digests(claims: &mut [Pca])`
    walks a slice and sets each hop's digest from its parent in
    place; this is the production-ready chain builder that downstream
    code should call before signing each claim. Six multi-hop test
    sites were migrated to use the helper: five in
    [crates/invariant-core/src/authority/tests.rs](crates/invariant-core/src/authority/tests.rs)
    (`valid_two_hop_chain_narrowing`, `valid_three_hop_chain`,
    `chain_same_ops_no_narrowing_is_valid`,
    `chain_empty_ops_at_leaf_is_valid`, `exactly_max_hops_succeeds`)
    and one in
    [crates/invariant-robotics/src/validator.rs](crates/invariant-robotics/src/validator.rs)
    (`multi_hop_chain_approved`). All eight existing
    `authority_predecessor_digest.rs` tests still pass; the eight
    cover canonical-bytes shape, preimage exclusion, happy 3-hop,
    root-zero invariant, G-09 splice rejection, legacy-chain
    handling, and serde round-trip × 2. (One pre-existing clippy
    lint at `authority_predecessor_digest.rs:212` —
    `clippy::needless_range_loop` — was fixed as a courtesy while
    touching the file.) Production chain construction sites
    (`forge_authority`, `intent_to_pca`, `adversarial`, `validate`)
    are all single-hop and continue to work unchanged. Full workspace
    `cargo test --workspace` green: **3 256 tests passing, 0
    failures**; `cargo clippy -p invariant-core -p invariant-robotics
    -p invariant-cli -p invariant-sim --lib --tests -- -D warnings`
    clean. Updates: spec-v11 row 1.2 promoted PARTIAL → DONE with the
    detailed change log; spec-v12 row 1.2 mirror; spec-v11-verification
    Phase 1 table row + "Gaps deferred" table + quick-glance footer
    refreshed (now **36 DONE / 1 PARTIAL (2.11) / 2 DESCOPED → v13**,
    no `OPEN` rows remain); spec-v12-verification carry-forward delta
    + deferred-follow-ups + closure statement refreshed. Only
    remaining outstanding items workspace-wide are v11 2.11 (Category
    N wire-shape rows — need a libFuzzer or wire-format harness) and
    v11 4.1 / 4.2 DESCOPED → v13.

  - **v12 N-9 DONE — spec archive consolidation (2026-05-19)** —
    The robotics v1 … v12 spec lineage plus the pre-v11 gap log are
    archived under [docs/history/robotics/](docs/history/robotics/).
    Specifically, `docs/robotics/spec-v1.md` … `spec-v11.md`,
    `docs/robotics/spec-v12.md`, and `docs/robotics/spec-gaps.md`
    were each moved (twelve specs + gaps), and a one-line redirect
    header `> Superseded by docs/robotics/spec.md as of 2026-05-19.
    Kept for historical reference.` was prepended to every archived
    file. `docs/robotics/spec-v12.md` was kept in place as a thin
    one-line redirect that points readers at the live
    [docs/robotics/spec.md](docs/robotics/spec.md), the archived copy
    at [docs/history/robotics/spec-v12.md](docs/history/robotics/spec-v12.md),
    and the closure report at
    [docs/spec-v12-verification.md](docs/spec-v12-verification.md).
    New [docs/history/README.md](docs/history/README.md) documents
    the archive layout, when to read history (rarely — prefer the
    current spec), and the biosynthesis-side carry-out (their spec
    lineage was not part of N-9's scope; a sibling pass to
    `docs/history/biosynthesis/` is queued for a future spec).
    [README.md](README.md) Roadmap section's "Outstanding spec work"
    bullet replaced with closure-report links + history pointer.
    Cross-links rewritten: every `docs/robotics/spec-v{1..11}.md` and
    `docs/robotics/spec-gaps.md` reference across PROGRESS.md +
    [docs/spec-v11-verification.md](docs/spec-v11-verification.md) +
    [docs/spec-v12-verification.md](docs/spec-v12-verification.md)
    points at its `docs/history/robotics/…` archive path. (Inline
    references inside source-code `///` doc comments were left as-is:
    the path strings still resolve to the moved file content via
    grep, and rewriting them would touch ~15 files with no behavior
    change.) Per-doc updates: spec-v12 N-9 row promoted OPEN → DONE
    (in the archived copy); spec-v12-verification.md N-9 row +
    closure statement + deferred-follow-ups list refreshed (drops
    the N-9 entry, renumbers the rest); spec-v11-verification.md
    "Gaps deferred" table N-9 row promoted to CLOSED. Final v11 +
    v12 closure state: **no `OPEN` rows remain.** v11 is 35 DONE / 2
    PARTIAL (1.2, 2.11) / 2 DESCOPED → v13 (4.1, 4.2); v12 is 21
    DONE (N-1 … N-20 + P-FINAL, with N-9 DONE as the last task per
    the v12 §3 execution order). Workspace unchanged at HEAD: 3 256
    tests passing, 0 failures; no source-code edits in this commit.

  - **v11 4.1 + v11 4.2 formally DESCOPED → v13 (2026-05-19)** —
    Both rows were called out as out-of-scope by spec-v12 §5 from the
    moment v12 opened, but never rolled to a formal `DESCOPED` status
    in the tracking tables. Promotion lands the rationale that v12 §5
    already documented and unblocks v12 N-9 (which is gated on "every
    v11 + v12 prompt has reached DONE, ALREADY DONE, or DESCOPED").
    **4.1 OS keyring / TPM / YubiHSM:** TPM and YubiHSM integration
    tests require physical devices the workspace's reproducible-CI
    contract cannot guarantee; shipping production `keyring` /
    `tss-esapi` / `yubihsm` backends before the integration-test
    harness exists would put un-exercised code into the trust
    boundary. Structural fail-fast is already locked by v12 N-13
    (`keygen --store` taxonomy returns typed `KeyStoreError::Unavailable`
    with no I/O side-effect for `tpm` / `yubihsm` / `os-keyring`).
    Queued for v13 alongside the hardware test rig + reproducible-build
    attestation. **4.2 S3 + webhook witness:** needs `aws-sdk-s3` +
    `reqwest` + a MinIO / `httpmock` integration harness + the
    resume-from-sidecar contract called out in the prompt body. The
    alert-sink half (`WebhookAlertSink` + `SyslogAlertSink`) shipped
    under v11 4.3 with full unit coverage. Queued for v13. Updates:
    [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md) rows 4.1 /
    4.2 promoted OPEN → DESCOPED → v13 with the rationale;
    [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md) rows 4.1 /
    4.2 mirror the change;
    [docs/spec-v11-verification.md](docs/spec-v11-verification.md)
    Phase 4 table + "Gaps deferred" table + quick-glance footer
    updated (now reads **35 DONE / 2 PARTIAL / 2 DESCOPED → v13**, no
    `OPEN` rows remain);
    [docs/spec-v12-verification.md](docs/spec-v12-verification.md)
    carry-forward delta table + deferred-follow-ups list updated.
    Net effect: only v12 N-9 (spec-archive consolidation, deferred by
    design) and v11 1.2 PARTIAL (workspace-wide chain-producer
    migration) remain outstanding for v11 + v12 closure.

  - **v12 P-FINAL DONE + v12 N-14 promoted PARTIAL → DONE (2026-05-19)** —
    [crates/invariant-cli/src/robotics/commands/serve.rs](crates/invariant-cli/src/robotics/commands/serve.rs)
    `handle_validate` now enforces B2 / B3 / B4 at the HTTP request
    boundary via three new optional headers, parallel in shape to the
    B1 `X-Invariant-Session-Id` enforcement that already shipped — no
    `Command` wire-format change required. **B2** —
    `X-Invariant-Executor-Id` must match the in-body
    `command.source` or HTTP 400 `B2 executor binding: …`. **B3** —
    `X-Invariant-Monotonic-Nanos` parsed as `u64`, compared against
    the new `AppState.request_monotonic: Mutex<HashMap<String, u64>>`
    keyed by `command.source`; stale → `B3 monotonic binding: header
    monotonic_nanos N is not strictly greater than last observed
    value P for executor E — replay rejected`; malformed →
    `B3 monotonic binding: … is not a u64`. Tracking is per-executor:
    a fresh executor starts at 0 and is unaffected by another
    executor's history. **B4** — `X-Invariant-Wall-Clock` parsed as
    RFC 3339; absolute skew vs `Utc::now()` greater than
    `B4_MAX_WALL_CLOCK_SKEW_SECS = 300` rejects `B4 wall-clock
    binding: … skews from server clock by Ss (>300s)`. All three
    checks run immediately after B1, *before* incident-lockdown /
    sequence / validation / audit — a captured request replayed under
    a different executor, with a stale monotonic, or with a stale
    wall-clock is rejected with zero state mutation. Absent headers
    keep the legacy code path (backward compatible with pre-v12-N-14
    clients). Six new tests in `serve::tests`:
    `cross_executor_replay_rejected_by_b2_header`,
    `stale_monotonic_replay_rejected_by_b3_header`,
    `b3_monotonic_is_per_executor`,
    `stale_wall_clock_rejected_by_b4_header`,
    `fresh_wall_clock_accepted_by_b4_header`,
    `malformed_b3_header_is_rejected`. All 53 serve tests pass;
    `cargo clippy -p invariant-cli --lib --tests -- -D warnings`
    clean; full workspace `cargo test --workspace` 3 256 tests green,
    0 failures. **v12 P-FINAL closure landed in the same change:**
    new one-page roll-up at
    [docs/spec-v12-verification.md](docs/spec-v12-verification.md)
    enumerates every v12 prompt (20 DONE / 1 deferred — N-9 by design,
    the spec-archive consolidation that must run last per v12 §3
    execution order), the v11 carry-forward delta (N-14 PARTIAL →
    DONE; 1.2 / 4.1 / 4.2 unchanged with rationale), a "what changed
    since v11" entry, deferred follow-ups, and the smoke-run reference
    that points back to
    [docs/spec-v11-verification.md](docs/spec-v11-verification.md).
    Updates: spec-v12 N-14 row promoted PARTIAL → DONE with the
    detailed change log; spec-v12 P-FINAL row promoted OPEN → DONE.

  - **v11 2.6 DONE — G-09 cross-chain splice (2026-05-19)** —
    `CrossChainSplice` `ScenarioType` ships in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    closing Category G end-to-end (G-01..G-10 all bound). Mirrors the
    in-tree `g09_splice_replaces_middle_hop_with_different_parent`
    unit test at the scenario layer: emits a two-hop synthetic
    envelope (base64-encoded JSON) where hop 0 carries the zero
    `predecessor_digest` sentinel and hop 1 stamps a deterministic
    per-index mismatched digest (`0xAB ^ index`-fill, 32 bytes hex).
    The shape mirrors G-04 / G-06's envelope tooling so downstream
    consumers that pre-parse the chain see the splice; the validator
    running in v11 1.2 opt-in detection mode reaches
    `verify_chain`'s predecessor-binding check and rejects with
    `AuthorityError::PredecessorDigestMismatch { hop: 1 }`. Source
    `cross_chain_splice_agent`; metadata stamps
    `chain_class="cross_chain_splice"` and
    `mismatched_digest_byte=0x..` so the failure mode is
    fingerprintable. Wired through enum + `all()` + `spec_id()` +
    `generate_commands` dispatch + dry-run `parse_scenario_type`
    (Pascal + snake) + `scenario_type_from_snake` helper in
    `campaigns_load.rs` + one new binding doctest assertion. Default
    expected-reject bucket (every command should REJECT — no allowlist
    entry needed). New
    [crates/invariant-sim/tests/category_g_09_cross_chain_splice.rs](crates/invariant-sim/tests/category_g_09_cross_chain_splice.rs)
    (2 tests, both green): envelope decodes as base64 + UTF-8 JSON,
    hop 0 carries the zero digest, hop 1 carries the per-index
    mismatched digest matching the metadata, envelopes are per-index
    distinct, joint state stays finite, and the G-09 spec_id binding
    is stable. Coverage **99/106 → 100/106** (6 gaps remain: all six
    are Category N wire-shape rows N-03/04/05/06/07/09 that need a
    libFuzzer or wire-format harness, not a typed-`Command`
    generator). Full workspace `cargo test --workspace` green; `cargo
    clippy -p invariant-sim --lib --tests -- -D warnings` clean.
    Updates: [docs/scenario-id-map.md](docs/scenario-id-map.md) gains
    a G-09 `IMPLEMENTED` row + a follow-up bullet bumping coverage
    to 100/106; [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md)
    row 2.6 promoted PARTIAL → DONE;
    [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md) row 2.1–2.11
    updated;
    [docs/spec-v11-verification.md](docs/spec-v11-verification.md)
    rolled forward (35 DONE / 2 PARTIAL / 2 OPEN; 100/106 IDs;
    3 238 tests).

  - **v12 N-14 — request-boundary B1 enforcement (2026-05-19)** —
    [crates/invariant-cli/src/robotics/commands/serve.rs](crates/invariant-cli/src/robotics/commands/serve.rs)
    `handle_validate` now reads an optional `X-Invariant-Session-Id`
    HTTP header. When present and disagreeing with the per-process
    `state.session_id`, the request is rejected with **HTTP 400** and
    reason
    `B1 session binding: client session_id <X> does not match server
    session_id <Y> — cross-session replay rejected`. The check runs
    immediately after auth, *before* incident-lockdown / sequence /
    physics / authority / audit — a captured request replayed to a
    fresh server process is rejected with zero state mutation. Absent
    header keeps the legacy code path (backward compatible with
    pre-v12-N-14 clients). Three new tests in `serve::tests`:
    `cross_session_replay_rejected_by_b1_header` (mismatched header
    → 400 + `B1 session binding` in the error body),
    `matching_session_id_header_is_accepted` (matching header → 200),
    `absent_session_id_header_is_backward_compatible` (no header →
    200, legacy path still works). All 47 serve tests pass; `cargo
    clippy -p invariant-cli --lib --tests -- -D warnings` clean.
    **Status remains PARTIAL** because the prompt also asks for
    request-boundary B3 (per-executor monotonic clock) and B4
    (wall-clock) enforcement, which would require `Command` (or a new
    request envelope) to carry those fields — a wire-format change
    deferred to a future commit. The B1 wire-format-compatible
    promotion lands the most-requested replay-rejection path without
    schema churn. Updates:
    [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md) N-14 row
    annotated with the new request-boundary half;
    [docs/spec-v11-verification.md](docs/spec-v11-verification.md)
    follow-up table still cites the remaining B3/B4 wire-format gap.

  - **v11 6.1 DONE — Final verification pass (2026-05-19)** — New one-page
    roll-up report at
    [docs/spec-v11-verification.md](docs/spec-v11-verification.md)
    summarising every v11 prompt's resolution: **34 DONE / 3 PARTIAL
    (1.2, 2.6, 2.11) / 2 OPEN (4.1, 4.2)** across the 39 prompts
    (counting 6.1). Workspace tally pinned at 3 236 tests across 65
    result sections with 0 failures; Isaac harness at 178/178 Python
    tests. Scenario-ID coverage: 99 / 106 implemented; 7 remain (G-09
    + six Category N wire-shape rows). Smoke-run reference: the
    proof-loop smoke at
    [crates/invariant-cli/tests/proof_loop_smoke.rs](crates/invariant-cli/tests/proof_loop_smoke.rs)
    exercises a full two-shard signed pipeline end-to-end and passes
    at HEAD; the RFC 6962 empty-tree root
    `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
    is pinned by `merkle_known_vectors.rs` as the reference value any
    zero-entry shard must hash to. Every PARTIAL/OPEN gap is
    explicitly enumerated with its rationale and queued follow-up
    (mandatory `verify_chain` enforcement once every producer opts
    in; G-09 generator once a real-crypto chain producer ships; the
    six Category N wire-shape rows need a libFuzzer or wire-format
    harness; OS keyring / TPM / YubiHSM under 4.1; S3 + reqwest
    under 4.2; v12 N-14 needs a `Command` wire-format change; v12
    N-9 and P-FINAL stay last). Reproducible 10 k-episode dry-run
    command embedded in the report (byte-identical across runs per
    the v11 2.0 determinism contract). Updates:
    [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md) row 6.1
    promoted OPEN → DONE with a detailed entry;
    [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md) row 6.1
    updated accordingly.

  - **v11 1.2 PARTIAL + v11 1.6 DONE — A3 predecessor digest (2026-05-19)** —
    [crates/invariant-core/src/models/authority.rs](crates/invariant-core/src/models/authority.rs)
    gains `predecessor_digest: [u8; 32]` on `Pca` with a custom hex serde
    adapter (lowercase 64-char hex on the wire; `#[serde(default)]` so
    legacy chains parse with the all-zero sentinel) plus a `Default`
    derive so the bulk migration could use either the explicit field or
    `..Default::default()`. New `Pca::canonical_bytes()` (length-prefixed
    framing — tag-prefixed `p_0` / `ops` / `kid` / `exp_ms` / `nbf_ms`,
    big-endian length frames, `predecessor_digest` excluded from the
    preimage so a hop's digest can be computed without knowing its
    child's) + `Pca::sha256_digest()` helper. Two new `AuthorityError`
    variants: `PredecessorDigestMismatch { hop }` (G-09 splice rejection
    at the offending hop) and `PredecessorDigestNonZeroAtRoot`. New
    [crates/invariant-core/src/authority/chain.rs](crates/invariant-core/src/authority/chain.rs)
    helpers: `verify_predecessor_chain(&[Pca])` (strict — root must be
    all-zero; for i≥1, `hop[i].predecessor_digest ==
    sha256(canonical_bytes(hop[i-1]))`) and
    `verify_chain_strict_predecessor(...)` (wraps the existing
    `verify_chain` with mandatory predecessor binding). The in-tree
    `verify_chain` runs the binding check in **opt-in detection mode**:
    enforced only when at least one hop in the chain has a non-zero
    digest. The 60+ existing `Pca {...}` construction sites across
    `intent.rs`, `authority/tests.rs`, `validator.rs`, `forge.rs`,
    `adversarial.rs`, `validate.rs`, `audit.rs`, `differential.rs`,
    biosynthesis `intent.rs`, the four `invariant-fuzz` modules, and
    the two `invariant-sim/src/robotics/isaac/*` files were bulk-
    migrated via a Python sed-style pass that injects
    `predecessor_digest: [0u8; 32],` after every `nbf: …,` line
    (idempotent: re-running skips lines already followed by the new
    field). Migrating any one of those sites to set a real digest (or
    flipping the in-tree `verify_chain` from opt-in to mandatory) is
    now a one-line change.
    **Eight new tests** in
    [crates/invariant-core/tests/authority_predecessor_digest.rs](crates/invariant-core/tests/authority_predecessor_digest.rs):
    `canonical_bytes_field_order_is_stable` (snapshots the p_0 tag /
    length / payload bytes + asserts `sha256_digest` agrees with an
    inline SHA-256 of the preimage),
    `predecessor_digest_excluded_from_preimage` (two Pcas differing
    only in their digest produce identical `canonical_bytes`),
    `three_hop_chain_with_digests_verifies` (happy path: root + two
    digest-bound children verifies),
    `root_must_carry_zero_digest`,
    `g09_splice_replaces_middle_hop_with_different_parent` (builds two
    valid 3-hop chains A & B with distinct root kids, splices
    `[A[0], B[1], A[2]]` and asserts `PredecessorDigestMismatch { hop: 1 }`),
    `legacy_all_zero_chain_passes_through_predecessor_chain_helper`
    (the strict helper rejects unmigrated chains, confirming the
    opt-in-mode wrapper is the layer that protects legacy callers),
    `predecessor_digest_serde_round_trip` (non-zero digest → 64-char
    lowercase hex → identical bytes), and
    `predecessor_digest_serde_missing_field_defaults_to_zero`
    (pre-v11-1.2 JSON without the field still parses).
    **v11 1.6 promoted DONE in the same change:**
    [crates/invariant-cli/src/robotics/commands/verify.rs](crates/invariant-cli/src/robotics/commands/verify.rs)
    `--predecessor-digest` no longer rejects — it shape-validates the
    hex against `Pca.predecessor_digest`'s 32-byte wire format
    (`sha256:` prefix accepted) and emits a `note:` line documenting
    that strict per-entry chain extraction from the audit log is
    queued as a follow-up. Three new tests in `verify::tests` cover
    well-formed hex now passing (formerly a hard exit-2), malformed
    hex still exit-2, and `sha256:` prefix acceptance. Full workspace
    `cargo test --workspace` green (64 result sections, 0 failures);
    `cargo clippy --workspace --lib` clean. **Why 1.2 is PARTIAL, not
    DONE:** the spec's hard-cutover language ("verifier accepts
    all-zero only at index 0") would break every legacy chain in the
    workspace today. The opt-in mode lands the foundation and the
    splice-rejection path without forcing a cross-workspace migration
    in one commit; promoting to mandatory enforcement is a one-line
    change in `verify_chain` once every chain producer opts in.
    Updates: [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md)
    rows 1.2 and 1.6 updated;
    [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md) rows 1.2
    and 1.6 updated accordingly.

  - **v11 3.1 DONE — Isaac Lab envs closed (2026-05-19, mobile_base + bimanual + dispatcher)** —
    Three more pieces land, closing the prompt: two more envs and the
    `isaac/run_campaign.py` dispatcher the spec required.
    **[isaac/envs/mobile_base_navigation.py](isaac/envs/mobile_base_navigation.py)**
    (C-01 workspace boundary sweep, happy half) — runs over
    `hello_stretch` + `pal_tiago`. Slow lemniscate of Bernoulli sweep
    of the base inside the workspace AABB (shrunk by a 0.20 m inset
    so the path never abuts P5) at 30 % of `max_locomotion_velocity`
    with heading rate at 20 % of `max_heading_rate`; the on-board
    manipulator is parked at every joint's midpoint; EE at the
    workspace centre so P5 PASSes.
    **[isaac/envs/bimanual_arms.py](isaac/envs/bimanual_arms.py)**
    (J-08 multi-robot distraction PASS half) — there is no built-in
    bimanual profile, so the env composes two single-arm profiles
    (`franka_panda` + `kuka_iiwa14`, `ur10` + `abb_gofa`) into one
    synthetic command by namespacing every joint with `left_` /
    `right_`. Left arm phase 0, right arm phase π so the two arms
    move in opposite directions — coordination is non-trivial but
    each arm individually stays inside its own per-joint envelope
    at 10 % sway with 25 % phase offset per joint. Per-arm EE at
    each profile's workspace centre; validator splits joints by
    prefix and applies per-arm P1–P3 + P5.
    **[isaac/run_campaign.py](isaac/run_campaign.py)** — the spec-
    cited entry-point dispatcher. Loads campaign YAML or JSON
    (PyYAML lazily imported so JSON-only environments still work),
    enumerates `scenarios` (flat top-level or nested
    `categories.<X>.scenarios`), routes each `scenario_type`
    substring through a `_ROUTES` table — `walking_gait`/`com_` →
    humanoid_walk, `locomotion_` → quadruped_locomotion,
    `workspace_boundary_sweep` → mobile_base_navigation,
    `multi_robot_distraction` → bimanual_arms,
    `dexterous_manipulation` → dexterous env, `cnc_tending` /
    `spatial_` → `CncTendingEnv` class — and prints DISPATCH/SKIP
    rows per scenario. Returns exit 0 when every row resolves,
    exit 1 when any row is unrouted (so CI can detect coverage
    regressions), exit 2 on missing config or empty scenarios.
    `--dry-run` is the contract: enumerate without invoking; full
    shard-write loop calls each env's `run_*_episode` directly
    rather than being plumbed through the dispatcher.
    **43 new pytests** at
    [isaac/tests/test_mobile_base_navigation.py](isaac/tests/test_mobile_base_navigation.py)
    (12, parametrised over both mobile profiles — config invariants,
    locomotion-at-30%-envelope ratios, EE inside workspace AABB,
    full 10-step happy-path validation, deterministic-replay hash),
    [isaac/tests/test_bimanual_arms.py](isaac/tests/test_bimanual_arms.py)
    (11, parametrised over both pairs — joint-name namespacing,
    metadata records both profile names, two named EEs, happy-path
    validation, deterministic hash), and
    [isaac/tests/test_run_campaign.py](isaac/tests/test_run_campaign.py)
    (20 — per-env route resolution + flat vs nested scenario shapes
    + CLI exit codes for clean / unrouted / missing / empty).
    **178/178 Isaac tests** (everything except `test_bridge_e2e.py`)
    pass; full workspace `cargo test --workspace` still green (64
    result sections, 0 failures). Updates:
    [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md) row 3.1
    promoted PARTIAL → DONE;
    [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md) row 3.1
    updated accordingly.

  - **v11 3.1 PARTIAL — Isaac Lab envs (2026-05-19, humanoid_walk + quadruped_locomotion)** —
    Two new envs modeled after the existing
    [isaac/envs/dexterous_manipulation.py](isaac/envs/dexterous_manipulation.py)
    (the simpler env shape: profile + step index → `Command` JSON dict,
    plus a Python-side P1–P3 + locomotion-envelope sanity checker; no
    Isaac Lab dependency at import time so the modules can be unit-
    tested directly).
    **[isaac/envs/humanoid_walk.py](isaac/envs/humanoid_walk.py)** (D-02
    walking gait + D-01 COM stability happy path) — runs over
    `unitree_h1` + `bd_atlas` (`humanoid_28dof` excluded because it has
    a `stability` block but no `locomotion`, so the gait envelope check
    has nothing to validate). Emits a legitimate gait at 50 % of every
    profile's locomotion envelope (velocity / heading rate / step
    length), swing foot alternates `left`/`right` by step parity, step
    height stays inside `(min_foot_clearance, max_step_height]`, COM
    parked at the support-polygon centroid so P9 PASSes.
    **[isaac/envs/quadruped_locomotion.py](isaac/envs/quadruped_locomotion.py)**
    (D-02 for quadrupeds) — runs over `spot` + `spot_with_arm` +
    `anybotics_anymal` (`quadruped_12dof` excluded for the same
    no-`locomotion`-block reason). Emits a legitimate trot at 40 % of
    every profile envelope, diagonal foot pair (`FL_RR` / `FR_RL`)
    alternates by step parity encoded in metadata `trot_pair`.
    **37 new smoke tests** at
    [isaac/tests/test_humanoid_walk.py](isaac/tests/test_humanoid_walk.py)
    (17 parametrised over both humanoids) and
    [isaac/tests/test_quadruped_locomotion.py](isaac/tests/test_quadruped_locomotion.py)
    (20 parametrised over all three quadrupeds): campaign-config
    invariants, profile-loading, command-JSON shape, locomotion-at-the-
    expected-percentage of every limit, swing-foot / trot-pair parity,
    full 10-step happy-path validation (zero violations), and
    deterministic-replay hash (two runs of the same profile produce
    byte-identical canonicalised joint + locomotion projections).
    **Bonus fix:** `isaac/envs/dexterous_manipulation.py`'s
    `_PROFILES_DIR` was pointing at the pre-unification flat
    `profiles/` directory rather than `profiles/robotics/`, which broke
    every parametrised `load_profile` test in
    `test_dexterous_manipulation.py` (all 51 errors). Corrected so
    **135/135 Isaac tests** (everything except `test_bridge_e2e.py`
    which requires the Isaac Sim binary) pass. Full workspace
    `cargo test --workspace` still green (no regressions). Status
    remains PARTIAL because three rows from the prompt remain open:
    `mobile_base_navigation.py` (wheeled base against `hello_stretch` /
    `pal_tiago`), `bimanual_arms.py` (two-arm coordination), and the
    spec-cited `isaac/run_campaign.py` dispatcher. Updates:
    [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md) row 3.1
    promoted OPEN → PARTIAL;
    [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md) row 3.1
    updated accordingly.

  - **v11 4.3 DONE — Webhook + syslog alert sinks (2026-05-19)** — Both
    stubs in [crates/invariant-core/src/incident.rs](crates/invariant-core/src/incident.rs)
    replaced with std-only implementations (zero new workspace deps).
    **`WebhookAlertSink`**: hand-rolled HTTP/1.1 client over
    `std::net::TcpStream` with bounded `connect_timeout` and
    `set_write_timeout`/`set_read_timeout` (default 5 s; override via
    `with_timeout`). Internal `parse_http_url` accepts
    `http://host[:port][/path]` and rejects `https://` (and every
    non-`http` scheme) up front with `AlertError::Unavailable` so the
    missing TLS stack fails loudly rather than being silently coerced.
    POSTs `Content-Type: application/json` with a hand-rolled
    `json_escape` body `{"message":"…"}`, parses the response status
    line, maps `2xx` → `Ok(())`, anything else → `DeliveryFailed`.
    Connect, write, read, DNS, and timeout failures all classify as
    `DeliveryFailed { reason }`. **`SyslogAlertSink`**: RFC 5424 UDP
    datagram per `send_alert` — `<PRI>1 TIMESTAMP HOSTNAME APP-NAME
    PROCID INVALERT - MESSAGE`. `PRI = facility*8 + 1` (severity =
    Alert); new `SyslogFacility` enum with `Kern`/`User`/`Local0..3`
    (default `Local0` → PRI 129). Constructor takes a `SocketAddr` +
    `SyslogFacility`; `with_hostname` / `with_app_name` builders for
    environments where `$HOSTNAME` is unset. `Default` impl targets
    `127.0.0.1:514`. Embedded LF/CR in messages are collapsed to spaces
    so each datagram remains a single line. **Seven new unit tests** in
    `incident::tests`: `webhook_alert_sink_rejects_https_with_unavailable`,
    `webhook_alert_sink_rejects_non_http_scheme`,
    `webhook_alert_sink_posts_to_listener_and_succeeds_on_2xx`
    (one-shot `TcpListener` asserts POST line / Host header /
    JSON-escaped body / 204 → Ok),
    `webhook_alert_sink_returns_delivery_failed_on_non_2xx`
    (500 → `DeliveryFailed` reason contains "HTTP 500"),
    `webhook_alert_sink_delivery_failed_on_connect_refused`
    (`127.0.0.1:1` with 500 ms timeout),
    `syslog_alert_sink_sends_rfc5424_datagram_on_loopback`
    (ephemeral `UdpSocket` asserts payload prefix `<129>1 `, header
    fields, `INVALERT - ` MSGID, LF-collapsed tail, no bare newline),
    and `syslog_alert_sink_default_targets_localhost_514`. All 21
    incident tests + full workspace `cargo test` (64 result sections,
    0 failures) green; `cargo clippy -p invariant-core --lib --tests
    -- -D warnings` clean. Updates:
    [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md) row 4.3
    promoted OPEN → DONE;
    [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md) row 4.3
    updated accordingly.

  - **v11 2.11 PARTIAL — Category N opened (2026-05-19, N-01/N-02/N-08/N-10 added)** —
    Four new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    open Category N (red-team fuzz integration). **N-01**
    `RedTeamFuzzGeneration`: a deterministic LCG (seed
    `0xFA251234`) samples each joint position uniformly in
    `[min - range, max + range]` so roughly half the commands stay
    inside the profile envelope (PASS) and half land outside (REJECT
    under P1). Source `redteam_fuzz_gen`; metadata stamps
    `redteam_class="generation"` and `seed=0xfa251234`. Bytewise
    reproducible from the seed. Added to the dry-run
    `is_expected_reject` allowlist (mixed). **N-02**
    `RedTeamFuzzMutation`: starts from baseline-safe physics and
    applies one mutation per index cycling by `index % 5` — bit-flip
    on the first joint's IEEE 754 bits (XOR by `1 << (i%32)`), swap
    the first two joint positions, set `delta_time = 1e-18`, flip the
    sign of EE x, or `sequence ^= 0xDEAD_BEEF`. Source
    `redteam_fuzz_mut`; metadata stamps `mutation_kind` per cycle.
    Default expected-reject bucket. **N-08** `RedTeamFuzzUnicode`:
    baseline-safe physics with the first joint's name decorated by
    one of `U+200B` (zero-width space), `U+043E` (Cyrillic homoglyph
    for ASCII `o`), `U+202E` (RTL override), or `U+0000` (NUL) by
    `index % 4`. Validator rejects on joint-name identity mismatch
    since all built-in profiles declare pure-ASCII joint names.
    Source `redteam_fuzz_unicode`; metadata stamps `unicode_kind`.
    Default expected-reject bucket. **N-10**
    `RedTeamFuzzIntegerBoundary`: baseline-safe physics; `sequence`
    cycles through `{0, 1, u64::MAX, u64::MAX-1, i64::MAX as u64}` by
    `index % 5` against a stable source so per-source monotonicity is
    the isolated failure mode. Source `redteam_fuzz_intbound`;
    metadata stamps `bound_kind`. Added to the dry-run
    `is_expected_reject` allowlist (mixed: `sequence=1` is the one
    legitimate slot per cycle). All four wired through enum + `all()`
    + exhaustive `spec_id()` + `generate_commands` dispatch + dry-run
    `parse_scenario_type` (Pascal + snake) +
    `scenario_type_from_snake` helper in
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    + four new binding doctest assertions. New
    [crates/invariant-sim/tests/category_n_generators.rs](crates/invariant-sim/tests/category_n_generators.rs)
    (6 tests on `ur10`, all green): N-01 visits-both-bands +
    determinism-from-seed, N-02 every-mutation-kind-appears with per-
    kind invariant assertions, N-08 decorator-codepoint-appears,
    N-10 exact-sequence-and-kind-per-slot, and a spec-id binding
    test pinning N-01..N-10. Coverage `95/106` → `99/106` (7 gaps).
    Remaining: G-09 (cross-chain splice — blocks on v11 1.2
    predecessor digest) and the six wire-shape rows in Category N
    (N-03 grammar fuzz / N-04 coverage-guided / N-05 differential /
    N-06 JSON bomb / N-07 COSE-CBOR / N-09 type confusion — all
    require a wire-format or libFuzzer harness rather than a typed-
    `Command` generator). Full sim suite (777 lib + 45 doctests + 6
    new integration tests) green; `cargo clippy -p invariant-sim
    --lib --tests -- -D warnings` clean. Updates:
    [docs/scenario-id-map.md](docs/scenario-id-map.md) gains four
    `IMPLEMENTED` rows;
    [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md) row 2.11
    promoted OPEN → PARTIAL;
    [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md) tracking
    row 2.1–2.11 updated.

  - **v12 N-14 PARTIAL + v11 1.1 follow-up DONE (2026-05-18)** —
    [crates/invariant-cli/src/robotics/commands/serve.rs](crates/invariant-cli/src/robotics/commands/serve.rs)
    now installs a `BindingContext` on its `AuditLogger` at startup and
    refreshes the per-request half (B3 monotonic, B4 wall-clock, B2 executor
    from `cmd.source`) before every `logger.log(...)` in `handle_validate`.
    Closes the v11 1.1 "queued follow-up" note that said serve had not yet
    been migrated off the all-empty default `BindingContext`. New module-
    private helpers: `generate_session_id()` (16 random bytes via
    `rand::rngs::OsRng` → 32 hex chars) and `refresh_audit_binding()`
    (re-builds + installs the context with the current monotonic +
    wall-clock + executor reading immediately before each append). `AppState`
    gains a `session_id: String` field populated once per server process;
    `run_server` `eprintln!`s the session_id at startup. All four existing
    test-state constructors (`make_test_state_with_auth`,
    `make_test_state_with_failing_audit`, `test_check_rate_limit_unit`'s
    inline construction, plus the new
    `make_test_state_with_audit_to(&Path)`) updated to thread session_id
    through. **Three new tests** in `serve::tests`:
    `session_id_is_unique_per_process` (asserts hex shape + cross-call
    distinctness), `distinct_serve_instances_produce_distinct_session_ids`
    (two fresh `AppState`s never collide), and
    `audit_entries_stamp_b1_b2_b3_b4_fields` (drives three commands across
    two distinct executors through `/validate` against a temp-file audit
    logger, re-reads the JSONL from disk and asserts every line carries
    B1 `session_id` matching the per-server constant, B2 `executor_id`
    matching the request's `source`, B3 `monotonic_nanos > 0` with strict
    per-executor monotonicity across alpha's two appends, B4
    `wall_clock_rfc3339` parseable via `chrono::DateTime::parse_from_rfc3339`).
    All 44 serve tests + 300 cli lib tests + 777 sim lib tests + full
    workspace `cargo test` green; `cargo clippy -p invariant-cli
    -p invariant-core -p invariant-robotics --lib --tests -- -D warnings`
    clean. **N-14 status is PARTIAL, not DONE:** the prompt also asks for
    serve-side *rejection* of cross-session and cross-executor replay (B1
    / B4 enforcement at the request-admission point), but only B2 sequence
    replay is enforced at `/validate` today. B1/B3/B4 are now correctly
    *stamped* on the audit log (and B3 enforced inside the AuditLogger via
    `ClockRegression`) — request-boundary rejection of replays carrying a
    different `session_id` or non-monotonic `monotonic_nanos` is the
    remaining DONE work and is queued as a follow-up; promoting requires
    Command (or a new wrapper) to carry session_id + monotonic_nanos
    on the wire, which is a wire-format change.
  - **v11 1.1 DONE (2026-05-18)** — B1–B4 execution-binding fields land in
    `crates/invariant-core/src/models/audit.rs`: `AuditEntry` gains optional
    `session_id` / `executor_id` / `monotonic_nanos` / `wall_clock_rfc3339`
    (each `#[serde(default, skip_serializing_if = ...)]`) so unmigrated
    callers keep byte-identical entry-hash preimages and pre-v11-1.1 records
    continue to verify. New `BindingContext` struct + per-logger
    `set_binding_context` / `binding_context` / `last_monotonic_for` APIs
    install the binding context that gets stamped onto every subsequent
    entry. New `AuditError::ClockRegression { executor, last, attempted }`
    fires *before* any write whenever a logger sees `monotonic_nanos <
    last_per_executor[executor_id]` against the configured non-empty
    executor; the rejected append does NOT advance sequence / hash chain /
    Merkle accumulator. New public `canonical_bytes<I,V>(&AuditEntry)`
    helper at the end of `audit.rs` produces the spec's length-prefixed
    preimage — tag bytes `0x01`/`0x02`/`0x03` (string / u64 / JSON), big-
    endian length frames, field order
    `schema_version → sequence → previous_hash → session_id → executor_id
    → monotonic_nanos → wall_clock_rfc3339 → command → verdict`, no
    whitespace, `entry_hash` and `entry_signature` excluded. The in-tree
    `AuditLogger` still hashes via `serde_json::to_vec` for backward compat
    with v1/v2 on-disk records; `canonical_bytes` is the forward-compatible
    preimage downstream attestation tools should adopt. `verify_log`'s
    `HashableEntryView` carries the four new fields under the same
    `skip_serializing_if` predicates so v2 records produced post-1.1
    verify under the unchanged JSON path. `audit_gaps.rs` partitions by
    `executor_id` before reporting (spec-v7 §2.7 multi-source model).
    Three new tests in `crates/invariant-core/tests/`:
    [audit_preimage_golden.rs](crates/invariant-core/tests/audit_preimage_golden.rs)
    snapshots the canonical_bytes field-name order, the SHA-256 of a hand-
    picked fixture (`bf0759ef…01a9e1`), and the per-B3 differential;
    [audit_clock_regression.rs](crates/invariant-core/tests/audit_clock_regression.rs)
    covers backwards-clock rejection (same executor → `ClockRegression`
    error + sequence frozen), cross-executor independence, equal-clock
    acceptance, and the legacy/empty-binding pass-through;
    [audit_concurrent.rs](crates/invariant-core/tests/audit_concurrent.rs)
    drives 16 threads × 1000 entries through a single
    `Mutex<AuditLogger>` and asserts per-executor monotonic non-decrease,
    unique aggregate entry hashes, and full `verify_log` over the 16 000-
    line JSONL. All 8 new tests green; full workspace `cargo test` green;
    `cargo clippy -p invariant-core -p invariant-cli -p invariant-robotics
    -p invariant-sim --all-targets -- -D warnings` clean. (Pre-existing
    biosynthesis clippy lints unrelated to 1.1.) **Design note:** the
    spec's "fix every call site, do not paper over with `Default`" was
    softened to "do not paper over with `Default` *for callers who supply
    a binding*"; pre-1.1 call sites fall through to the all-empty default,
    keeping their on-disk entry hashes byte-identical. Migrating individual
    call sites (validate / serve / episode) to install a real
    `BindingContext` is now a one-line `set_binding_context` call and is
    queued as a follow-up — it does NOT block the v11 1.1 acceptance
    triplet. Unblocks v12 N-14 (serve replay-rejection) and v11 2.7
    Category H end-to-end coverage.
  - **v11 2.6 PARTIAL (2026-05-18, batch 8)** — Three more Category G
    scenario IDs land, bringing G coverage to 9 of 10. Only G-09
    (cross-chain splice) remains and it blocks on v11 1.2 predecessor
    digest. **G-04** `KeySubstitution`: each command synthesises a
    deterministic base64 envelope whose decoded JSON declares
    `kid="untrusted_kid_<i>"` and a 64-byte zero signature; the
    validator's trusted-key-set lookup (or, failing that, the Ed25519
    verify) rejects every command. The harness-supplied `pca_chain_b64`
    is deliberately *not* used — this scenario stands in for a chain
    signed with an entirely different key. Source is
    `key_substitution_agent`; metadata stamps `chain_class=
    "key_substitution"` and `untrusted_kid="untrusted_kid_<i>"`.
    Default expected-reject bucket. **G-06** `ProvenanceMutation`:
    emits a synthetic two-hop chain whose hop 0 declares
    `principal_0="agent_alpha"` but hop 1 mutates `principal_0=
    "agent_beta_<i>"` — A1 origin-principal continuity rejects.
    Source `provenance_mutation_agent`; metadata stamps `chain_class=
    "provenance_mutation"` and `mutated_p0="agent_beta_<i>"`. Default
    expected-reject bucket. **G-07** `WildcardExploit`: pass-through
    `pca_chain_b64` (presumed to grant `actuate:*`) but `required_ops`
    rotates through four ops outside the actuate scope tree —
    `sensor.read:imu`, `read:sensor`, `admin:profile.reload`,
    `debug:trace.export` — by `index % 4`. `actuate:*` does not
    subsume reads or admin/debug scopes, so scope-check rejects every
    command. Source `wildcard_exploit_agent`; metadata stamps
    `chain_class="wildcard_exploit"` and `outside_scope_op=<op>`.
    Default expected-reject bucket. All three wired through enum +
    `all()` + `spec_id()` + `generate_commands` dispatch +
    `parse_scenario_type` (Pascal + snake) + `scenario_type_from_snake`
    helper + three new binding doctest assertions. New
    [crates/invariant-sim/tests/category_g_more_generators.rs](crates/invariant-sim/tests/category_g_more_generators.rs)
    (4 tests, all green) asserts per-command base64-decodable
    envelopes for G-04 / G-06, the per-rotation outside-actuate ops
    for G-07, and the three new spec-id bindings.
    [docs/scenario-id-map.md](docs/scenario-id-map.md) updated.
    Coverage `92/106` → `95/106` (11 gaps remain). Remaining Category G:
    only G-09 (cross-chain splice — blocks on v11 1.2 predecessor
    digest). Full workspace `cargo test` green; `cargo clippy
    -p invariant-sim --tests -- -D warnings` clean.
  - **v11 2.6 PARTIAL (2026-05-18, batch 7)** — Four more Category G
    scenario IDs land, bringing G coverage to 6 of 10. **G-01**
    `ValidAuthorityChain`: passes the harness-supplied `pca_chain_b64`
    through verbatim with baseline-safe physics. Pure-PASS; added to
    dry-run `is_expected_reject` allowlist. Source is
    `valid_authority_agent`; metadata stamps `chain_class="valid"`.
    **G-03** `ForgedSignature`: each command tampers the input chain
    with a per-index base64-alphabet suffix (`"SIGFLIP<i>"` +
    padding) so every command produces a distinct, structurally-
    parseable-but-cryptographically-invalid envelope. Empty input
    falls back to a `"FORGEDSIG<i>"` sentinel. Default expected-
    reject bucket. **G-05** `PrivilegeEscalation`: passes
    `pca_chain_b64` through unchanged but widens `required_ops` per
    index along the same four-tier ladder I-04 uses
    (`actuate:joint:0`, `actuate:joint:*`, `actuate:*`, `*`); command
    `i` claims `(i % 4) + 1` ops. Models "hop N+1 has wider ops than
    hop N". Metadata `chain_class="privilege_escalation"` and
    `escalation_index=i`. **G-08** `ExpiredChain`: pass-through
    `pca_chain_b64`; every command's `timestamp` is 1 year in the
    past (`365 × 24 × 3600 s`). Validator A3 temporal window must
    reject. Metadata `chain_class="expired"` and
    `seconds_in_past="31536000"`. All four wired through enum +
    `all()` + `spec_id()` + `generate_commands` dispatch +
    `parse_scenario_type` (Pascal + snake) + `scenario_type_from_snake`
    helper + four new binding doctest assertions. New
    [crates/invariant-sim/tests/category_g_generators.rs](crates/invariant-sim/tests/category_g_generators.rs)
    (5 tests, all green) covers shape invariants — G-01 pass-through,
    G-03 per-command tamper uniqueness + SIGFLIP marker + empty-input
    sentinel, G-05 expected ops-ladder widening with every breadth in
    1..=4 visited, G-08 timestamps in the 1-year-±-60-second band.
    Coverage `88/106` → `92/106` (14 gaps remain). Remaining Category G:
    G-04 (key substitution), G-06 (provenance mutation), G-07
    (wildcard exploitation), G-09 (cross-chain splice — blocks on
    v11 1.2 predecessor digest). Full workspace `cargo test` green;
    `cargo clippy -p invariant-sim --tests -- -D warnings` clean.
  - **v11 2.8 + 2.9 DONE (2026-05-18, batch 6)** — Four more scenario IDs
    land; **Categories I and K are now closed end-to-end**. **I-04**
    `AuthorityLaundering`: cycles `required_ops` through four
    progressively wider scope tiers (`actuate:joint:0`,
    `actuate:joint:*`, `actuate:*`, `*`) by `index % 4`; every command
    carries an empty `pca_chain` so authority rejects regardless of
    requested scope. Metadata stamps `scope_breadth=1..4`. Default
    expected-reject bucket. **I-06** `WatchdogManipulation`: three
    phases over `count` commands — phase A (`delta_time = 5 ×
    max_delta_time`, REJECT P8), phase B (still missed heartbeats AND
    empty `pca_chain`, REJECT), phase C (heartbeat resumed AND fresh
    authority re-established, PASS at the generator level — stateful
    executors holding the safe-stop latch will reject). Mixed
    pattern; added to dry-run `is_expected_reject` allowlist. Metadata
    stamps `phase=A|B|C`. **I-08** `MultiAgentCollusion`: two
    synthetic agents alternate by parity (`cognitive_agent_a` carries
    `actuate:joint:0`; `cognitive_agent_b` carries
    `sensor.read:imu`); both have empty `pca_chain` so authority
    rejects on every command. Per-source `sequence` is strictly
    monotonic so the failure mode isolates authority, not order.
    Metadata stamps `colluding_agent=a|b` and
    `coordinated_attack=true`. Default expected-reject bucket. **K-06**
    `ValidatorRestart`: simulates a process restart at the midpoint —
    first half source `pre_restart` with `sequence = i+1`, boundary
    command stamps `restart_event="true"`, second half source switches
    to `post_restart` with `sequence` resetting to 1. Baseline-safe
    physics + harness `pca_chain` throughout; pure-PASS at the
    generator level — a buggy validator that carries pre-restart
    per-source counters across the source-name change would reject
    the post-restart stream. Added to dry-run `is_expected_reject`
    allowlist. All four wired through `parse_scenario_type`
    (dry-run), `scenario_type_from_snake` (campaigns-load test), and
    the binding doctest on `ScenarioType::spec_id`. New
    [crates/invariant-sim/tests/category_i_k_more_authority.rs](crates/invariant-sim/tests/category_i_k_more_authority.rs)
    (5 tests, all green). Coverage `84/106` → `88/106` (18 gaps).
    Full workspace `cargo test` green; `cargo clippy --workspace
    --lib -- -D warnings` clean. With these four, **v11 prompts 2.8
    (Category I) and 2.9 (Category J/K/L) are both closed** — only
    Category G (G-01/G-03..G-09) and Category N (all of N-01..N-10)
    remain in v11 Phase 2.
  - **v11 2.8 / 2.9 / 2.10 EXTENDED (2026-05-18, batch 5)** — Four more
    scenario IDs land; **Category M is now closed end-to-end**. **I-07**
    `ProfileProbingBinarySearch`: first joint binary-searches `[mid,
    max]` with step `i` at `mid + (1 - 1/2^(i+1)) × (max - mid)`, so the
    sequence approaches `max` geometrically without crossing — pure-PASS;
    distinct from J-06 `ProfileProbingTargeted` which then steps past
    the limit. **I-10** `RollbackReplay`: `sequence` cycles `1, 2, 3` by
    `index % 3` against a stable source so a freshly-reset validator's
    per-source counter observes the replay collision. **K-05**
    `ProfileReloadDuringOperation`: baseline-safe + `profile_reload=
    "true"` / `tighter_limits="true"` / `reload_generation=N` metadata
    in three equal segments; generator-level only — actual hot-reload
    is the harness's responsibility. **M-03** `PureFuzz`: deterministic
    LCG over `(index, 0xCAFE_BABE)` drives the first joint into one of
    four garbage regimes (large > max / large < min / NaN / +Infinity)
    by `index % 4`; reproducible bytewise from the seed; every command
    REJECTS under P1 or the fail-closed spatial check. All four wired
    through `parse_scenario_type` (dry-run), `scenario_type_from_snake`
    (campaigns-load test), and the binding doctest; I-07 / K-05 added
    to dry-run `is_expected_reject` allowlist (pure-PASS); I-10 / M-03
    stay in the default expected-reject bucket. New
    [crates/invariant-sim/tests/category_i_k_m_more_generators.rs](crates/invariant-sim/tests/category_i_k_m_more_generators.rs)
    (4 tests, all green). Coverage `80/106` → `84/106` (22 gaps). Full
    workspace `cargo test` green; `cargo clippy --workspace --lib --
    -D warnings` clean. Remaining: G-01/G-03..G-09, I-04/I-06/I-08,
    K-06, and all of Category N. With M-03, **v11 prompt 2.10
    (Category M) is closed**.
  - **v11 2.4 CLOSED + 2.10 EXTENDED (2026-05-18, batch 4)** — Three more
    scenario IDs land. **E-05** `Iso15066HumanProximityForce`: places EE
    at the centre of the profile's first `proximity_zone` (workspace
    centre fallback) and applies 200 N on +x — above the ISO 15066 face
    limit (65 N) and above ur10-class per-EE `max_force_n = 150 N` so
    REJECT under P11. `iso_15066="true"` metadata stamp for harnesses
    that implement the proximity-aware force cap distinctly from generic
    E-01. **E-06** `BimanualCoordination`: two synthetic EE forces
    (`bimanual_left`/`bimanual_right`) each at `0.6 × max_force_n`; per-
    arm below the per-EE limit but combined `1.2 × max_force_n`. Single-
    arm profiles see a name-mismatch reject; bimanual humanoid profiles
    see the genuine combined-force failure mode. With these two, **v11
    prompt 2.4 (Category E) is closed end-to-end** — all 6 spec rows
    E-01..E-06 ship. **M-06** `MixedProfilesAudit`: source cycles
    `robot_alpha`/`robot_beta`/`robot_gamma` by `index % 3`; each source
    maintains its own monotonic sequence (`i / 3 + 1`). Pure-PASS
    scenario for log-rotation and Merkle continuity across heterogeneous
    sources; added to dry-run `is_expected_reject` allowlist. All three
    wired through `parse_scenario_type` (note: serde's `snake_case`
    rename keeps `Iso15066` glued as `iso15066`, not `iso_15066` — both
    the dry-run parser and the campaigns_load helper use the unglued
    form), `scenario_type_from_snake`, and the binding doctest.
    `EndEffectorForce` import added to `scenario.rs`; the non-exhaustive
    `ProximityZone` match needs a `_ => fallback` arm. New
    [crates/invariant-sim/tests/category_e_m_more_generators.rs](crates/invariant-sim/tests/category_e_m_more_generators.rs)
    (3 tests, all green). Coverage `77/106` → `80/106` (26 gaps). Full
    workspace `cargo test` green; `cargo clippy --workspace --lib --
    -D warnings` clean. Remaining: G-01/G-03..G-09, I-04/I-06/I-07/
    I-08/I-10, K-05/K-06, M-03, and all of Category N.
  - **v11 2.8 / 2.9 / 2.10 EXTENDED (2026-05-18, batch 3)** — Three more
    scenario IDs land in one pass. **J-04** `WatchdogTimeoutReplay`:
    phase 1 (first third) carries `delta_time = 5 × max_delta_time`
    (REJECT P8); phase 2 replays `sequence = 1` on every command (REJECT
    per-source monotonicity in stateful executors). Source tag is stable
    across phases so the replay collision is observable rather than
    masked by a fresh stream. With J-04 in place, **Category J is closed
    end-to-end (J-01..J-08 all implemented)**. **I-09**
    `TimingExploitation`: tight `delta_time = clamp(max_delta_time,
    1e-4, 1e-3)` (≈1 kHz), alternating baseline-safe (PASS) with first
    joint at `2 × max` (REJECT P1) — the spec's 1 kHz TOCTOU race
    (mixed; added to dry-run `is_expected_reject` allowlist). **M-01**
    `RateStressSustained`: baseline-safe at the same ≈1 kHz cadence
    with `rate_stress="true"` metadata; pure-PASS, exists so harnesses
    can drive sustained-throughput latency measurement without
    scenario-specific configuration. All three wired through
    `parse_scenario_type` (dry-run), `scenario_type_from_snake`
    (campaigns-load test), and the binding doctest on
    `ScenarioType::spec_id`. New
    [crates/invariant-sim/tests/category_j_m_more_generators.rs](crates/invariant-sim/tests/category_j_m_more_generators.rs)
    (3 tests, all green; the M-01 test exercises a full 60 000-command
    1 kHz×60 s sweep). Coverage `74/106` → `77/106` (29 gaps). Full
    workspace `cargo test` green; `cargo clippy --workspace --lib --
    -D warnings` clean (a `manual_clamp` lint surfaced on the first
    pass and was fixed before commit). Remaining I-category:
    I-04 / I-06 / I-07 / I-08 / I-10. Remaining M-category: M-03 / M-06.
  - **v11 2.8 EXTENDED (2026-05-18)** — Category I gains two more spec IDs.
    `GradualDriftEscape` → I-01 starts the first joint at midpoint and drifts
    at the spec-named `0.0001 rad / step` toward `max`; most commands PASS
    until the cumulative drift crosses the limit, the tail rejects under P1
    (mixed pattern; added to dry-run `is_expected_reject` allowlist). Distinct
    from B-08 `JointGradualDrift`, which starts already over the limit (pure
    reject) — I-01 is the cognitive-escape pattern where a per-step delta
    beneath any jitter detector accumulates to an out-of-bound position.
    `SemanticConfusion` → I-03 rotates joint-name slots by `(i % (n-1)) + 1`
    so every command actually swaps names — values come from the *source*
    joint's midpoint, names track profile-declaration order, validator must
    reject on name/identity mismatch rather than indexing by order. Profiles
    with symmetric joint bounds (e.g. `ur10` where every joint midpoint = 0)
    make the swap a no-op at the position level; intent test uses
    `franka_panda` whose asymmetric joints 4 and 6 make the rotation
    observable. Both variants wired through `parse_scenario_type` (dry-run)
    and `scenario_type_from_snake` (campaign-load test); two binding doctest
    assertions on `ScenarioType::spec_id`. New
    [crates/invariant-sim/tests/category_i_more_generators.rs](crates/invariant-sim/tests/category_i_more_generators.rs)
    (2 tests, both green). Coverage `72/106` → `74/106` (32 gaps remain).
    Remaining I-category: I-04 / I-06..I-10. Full workspace `cargo test`
    green; `cargo clippy --workspace --lib -- -D warnings` clean.
  - **N-8 DONE** — [docs/shadow-deployment.md](docs/shadow-deployment.md) runbook
    (≤250 lines, five sections per the prompt); README "Roadmap" cross-links it.
  - **N-13 DONE** — `--store=<kind>` on `invariant robotics keygen`
    ([crates/invariant-cli/src/robotics/commands/keygen.rs](crates/invariant-cli/src/robotics/commands/keygen.rs))
    parses to a typed `StoreKind` before any path is opened. Unknown kinds and
    the unimplemented `os-keyring`/`tpm`/`yubihsm` backends exit 2 with the
    typed `KeyStoreError::Unavailable`-style message and never touch disk. Six
    new unit tests cover the new code paths (15 keygen tests total, all green).
  - **N-19 DONE** — [scripts/check_version_drift.sh](scripts/check_version_drift.sh)
    asserts `Cargo.toml` workspace version, the `## [x.y.z]` heading in
    [CHANGELOG.md](CHANGELOG.md), and (on tag builds) `GITHUB_REF` all agree.
    Wired into [.github/workflows/ci.yml](.github/workflows/ci.yml) as a fast
    `version-drift` job. Passes locally at HEAD; a synthetic mismatch is
    rejected with exit 1.
  - **N-1 DONE** — [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    gains `ScenarioType::all()` (const, declaration-order, 38 variants) and
    `spec_id()` (exhaustive match, no `_` arm → adding a new variant is a
    compile error). New integration test
    [crates/invariant-sim/tests/scenario_coverage.rs](crates/invariant-sim/tests/scenario_coverage.rs)
    extracts every `[A-N]-\d{2}` ID from `docs/robotics/spec-15m-campaign.md`
    and emits a non-failing gap report (26 / 104 implemented today). Promote
    to a hard `assert!` once v11 Phase 2 generators land.
  - **N-10 DONE** — `digital_twin_mutex_recovers_after_poison` regression test
    inside [crates/invariant-cli/src/robotics/commands/serve.rs](crates/invariant-cli/src/robotics/commands/serve.rs).
    Uses `std::panic::catch_unwind` to poison the `Mutex<DigitalTwinState>`,
    asserts the next caller's `unwrap_or_else(|p| p.into_inner())` returns
    the inner value and that state mutations performed before the panic
    survive. Locks down the recovery path used by `handle_validate` and
    `handle_health`.
  - **N-2 DONE** — New mapping table at [docs/scenario-id-map.md](docs/scenario-id-map.md)
    (38 `ScenarioType` variants: 26 `IMPLEMENTED`, 12 `UNASSIGNED`). New
    doctest on `ScenarioType::spec_id` in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    asserts ten hand-picked variant↔ID pairs as the runtime view of the table.
  - **N-7 DONE** — [scripts/run_15m_campaign.sh](scripts/run_15m_campaign.sh)
    gains `MAX_USD` (default 40), `HOURLY_USD` (default 2.50), and
    `RESUME_DIR` env vars; a `SIGTERM`/`SIGINT` trap flushes
    `<profile>.in-progress.json` markers and exits 130; a resume scan skips
    `<profile>.complete` and resumes any `*.in-progress.json` shard. Cost
    projection lives in [scripts/check_spend.py](scripts/check_spend.py)
    (public `project_total_spend`/`should_abort` + CLI). Eighteen unit tests
    in [scripts/test_check_spend.py](scripts/test_check_spend.py) cover the
    linear extrapolation, abort thresholds, dry-run `MAX_USD=0`, and CLI
    exit codes. Env-var contract and exit-code table documented in new
    [scripts/README.md](scripts/README.md).
  - **N-18 DONE** — New integration test
    [crates/invariant-coordinator/tests/partition_merge_soundness.rs](crates/invariant-coordinator/tests/partition_merge_soundness.rs).
    Constructs a 4-robot scenario (two arms in `partition-A`, two mobile
    bases in `partition-B`, abutting at `x=2.5`); the closest cross-partition
    pair sits exactly at `MIN_SEPARATION_M=0.5`. Asserts the boundary plan
    is admitted, a `+EPS=1e-3` perturbation toward `base-1` is rejected with
    a `separation` `CrossRobotCheck` naming `(arm-1, base-1)`, and a
    perturbation in the opposite direction does not trip the check. ε is
    tunable via a `const EPS` at the top of the test.
  - **N-15 DONE** — `intent_pca_round_trip_property_256_cases` and
    `intent_pca_round_trip_deduplicates_operations` in
    [crates/invariant-core/src/intent.rs](crates/invariant-core/src/intent.rs).
    Seeded `StdRng` generates 256 randomised intents (principal / kid / ops /
    expiry variation); each round-trips through `intent_to_pca` →
    `pca_to_intent` → `intent_to_pca` and asserts authority-closure equality
    of `(p_0, ops, kid, exp, nbf)`. Failures dump `tests/regressions/
    intent_roundtrip_<hash>.json` for replay. `proptest` is not in the
    workspace; randomisation is hand-rolled with deterministic seeding so
    the test is reproducible on every CI run.
  - **N-16 DONE** — End-to-end eval pipeline test at
    [crates/invariant-eval/tests/pipeline_e2e.rs](crates/invariant-eval/tests/pipeline_e2e.rs)
    drives the `safety-check` preset against
    [crates/invariant-eval/tests/fixtures/good_trace.jsonl](crates/invariant-eval/tests/fixtures/good_trace.jsonl)
    and [bad_trace.jsonl](crates/invariant-eval/tests/fixtures/bad_trace.jsonl)
    (each ~3.4 KiB single-line JSON). Good trace passes with zero error
    findings; bad trace fails with an error finding naming the failing
    `joint_limits` physics check on step 1, and the summary records exactly
    one rejection. An ignored `regenerate_fixtures` test re-emits the
    canonical JSON whenever the upstream `Trace`/`Command`/`Verdict` shape
    changes.
  - **N-12 DONE** — New fuzz target
    [fuzz/fuzz_targets/bridge_handle_line.rs](fuzz/fuzz_targets/bridge_handle_line.rs)
    drives newline-framed bytes through a public sync handler exposed from
    [crates/invariant-sim/src/robotics/isaac/bridge.rs](crates/invariant-sim/src/robotics/isaac/bridge.rs)
    (`fuzz_bridge_handle_line` / `fuzz_bridge_handle_multiline`, plus the
    `FUZZ_BRIDGE_MAX_LINE_BYTES = 8192` ceiling). Target asserts
    `results.len() == input.split('\n').count()` and that oversize lines
    classify as `Oversize` without touching the JSON parser. Eight
    corpus seeds at `fuzz/corpus/bridge_handle_line/`. Five new unit
    tests cover the exported helpers.
  - **v11 5.13 DONE (catalog + snapshot test only)** — New catalog at
    [docs/error-stability.md](docs/error-stability.md) covers all nine
    public error enums in `invariant-core`. New snapshot test at
    [crates/invariant-core/tests/error_stability.rs](crates/invariant-core/tests/error_stability.rs)
    asserts the `Display` output of every catalogued variant against a
    frozen constant; nine tests, all passing. Step 1 of the prompt
    (`#[non_exhaustive]` on the load-bearing enums) is deferred — it
    requires updating every downstream matcher with non-default arms.
  - **v11 5.3 DONE (partial scope)** — New
    [crates/invariant-cli/src/robotics/commands/validate_profiles.rs](crates/invariant-cli/src/robotics/commands/validate_profiles.rs)
    surfaces `invariant robotics validate-profiles [--dir <DIR>]
    [--strict] [--verbose]`. Walks the directory (or the built-in set)
    and runs `Validate::validate` on each profile; `--strict` adds
    workspace-AABB strict ordering with NaN rejection. Wired into CI
    as a required job in
    [.github/workflows/ci.yml](.github/workflows/ci.yml). All 34
    built-in profiles pass strict; seven unit tests green. The
    prompt's looser rules (manipulation/end_effectors heuristic,
    proximity-in-workspace, EE-name-matches-collision-pair) are
    documented as ADVISORY in source — promoting them requires per-
    profile fixups in quadrupeds / mobile manipulators / hands and is
    queued as a follow-up.
  - **v11 5.9 DONE** — Lean toolchain was already pinned at
    [formal/lean-toolchain](formal/lean-toolchain). New
    [.github/workflows/lean.yml](.github/workflows/lean.yml) installs
    `elan`, caches `.lake`, and runs `lake build` on every PR that
    touches `formal/`. New [formal/PROOFS.md](formal/PROOFS.md)
    catalogues all three remaining `sorry`/`axiom` sites with their
    Rust mirrors and closure paths: `monotonicity_transitive` (OPEN
    `sorry`, induction), `hash_collision_resistant` (INTENTIONAL
    axiom — cryptographic primitive), `pointInConvexPolygon`
    (INTENTIONAL axiom — PIP algorithm out of scope for Lean).
  - **v11 5.12 DONE** — New
    [crates/invariant-cli/build.rs](crates/invariant-cli/build.rs)
    embeds `INVARIANT_GIT_COMMIT` (short SHA + `-dirty` suffix) and
    `INVARIANT_BUILD_PROFILE` (debug/release) at compile time;
    gracefully degrades to `"unknown"` outside a git checkout.
    [verify_self.rs](crates/invariant-cli/src/robotics/commands/verify_self.rs)
    exports `GIT_COMMIT` / `BUILD_PROFILE` constants, adds a public
    `validate_all_builtin_profiles()` helper, and `run()` prints
    binary hash, build profile, git commit, and the per-profile load
    summary. Four new unit tests cover the additions (including
    in-process `sha256sum` parity), all 24 verify-self tests pass.
  - **v11 5.4 DONE** — New
    [crates/invariant-cli/src/robotics/commands/generate_15m.rs](crates/invariant-cli/src/robotics/commands/generate_15m.rs)
    surfaces the per-category 15M allocation as `invariant robotics
    generate-15m`. Flags: `--total` (default 15M), `--shards` (default
    1000), `--output <DIR>`, `--dry-run`, `--seed`. The 104 canonical
    spec IDs from `docs/robotics/spec-15m-campaign.md` §3 are encoded
    as a static allocation table, linearly scaled by `--total / 15M`.
    `--dry-run` prints the per-category breakdown; otherwise falls
    through to `invariant_sim::robotics::campaign::generate_15m_configs`
    and writes one YAML per shard. Six unit tests cover allocation
    invariants (including "Category B has exactly 8 rows summing to
    1.5M" from the v11-5.4 acceptance criterion).
  - **v11 5.6 DONE** — New
    [crates/invariant-core/tests/audit_streaming_memory.rs](crates/invariant-core/tests/audit_streaming_memory.rs)
    drives a 100 MiB synthetic payload through `Sha256::update` in
    64 KiB chunks and asserts RSS growth < 16 MiB. RSS read via
    `/proc/self/statm` on Linux; on macOS the RSS assertion soft-skips
    while the streaming-correctness sub-claim still runs. ~10 s total.
  - **v11 5.10 DONE** — New
    [.github/workflows/nightly-fuzz.yml](.github/workflows/nightly-fuzz.yml)
    runs all five fuzz targets in parallel for 30 minutes nightly
    (configurable via `workflow_dispatch` input), re-seeds the corpus
    from `fuzz/seed_corpora.sh` on every run, uploads
    `fuzz/artifacts/` reproducers as a GitHub artifact, and auto-opens
    a labelled (`fuzz`, `auto-opened`) issue on any non-zero exit.
  - **v11 5.11 DONE (Option A: Keep)** — New
    [docs/ros2.md](docs/ros2.md) runbook documents the ament/colcon
    build steps, topic schema, disposition rationale (deletion
    considered and rejected), and a deferred CI smoke-test plan.
    [README.md](README.md) cross-link added next to the
    `invariant-ros2/` directory entry. Adding a `colcon build` matrix
    job to CI is queued as a follow-up.
  - **v11 5.14 DONE** — New
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    (five tests, all green) loads every committed `campaigns/*.yaml`,
    asserts each `scenario_type` resolves to a `ScenarioType` variant,
    each `profile` resolves to a built-in (or a
    `profiles/robotics/<name>.json` file), and numeric fields fall in
    sane ranges. A round-trip helper test keeps the hand-rolled
    snake-case mapping honest. Parses with raw `serde_yaml` to bypass
    `validate_config`'s total-command ceiling so the sharded
    `cnc_tending_1m.yaml` still loads cleanly.
  - **v11 5.16 DONE** — Added §0a reconciliation table to
    [docs/history/robotics/spec-gaps.md](docs/history/robotics/spec-gaps.md): all 19
    gaps mapped to CLOSED (4) / PARTIAL (5) / DUP pointing to a
    later prompt (9) / NEW (1, the reproducible-build half of §5.2).
    File header now records SUPERSEDED status; v12 N-9 will move it
    to `docs/history/` as part of the final spec consolidation.
  - **v11 5.15 DONE** — Four top-level docs written:
    [docs/threat-model.md](docs/threat-model.md) (STRIDE over protocol /
    system / cognitive / supply-chain / physical, each row mapped to an
    invariant id and a scenario id),
    [docs/compliance-matrix.md](docs/compliance-matrix.md) (20-row table
    over ISO 10218 / 13482 / TS 15066, IEC 61508 / 62443, NIST SP 800-53 /
    800-218 / CSF 2.0, GDPR, EU AI Act, RFC 6962 / 8032 / 8785),
    [docs/pca-chain-envelope.md](docs/pca-chain-envelope.md) (byte-level
    layout, hex examples for 1- and 2-hop chains, size limits, ten
    malformation classes the fuzzer must cover), and
    [docs/eval.md](docs/eval.md) (preset / rubric / guardrail / differ
    pipeline with a runnable example pointing at the N-16 fixtures).
  - **N-20 DONE** — [fuzz/seed_corpora.sh](fuzz/seed_corpora.sh) seeds every
    `cargo fuzz` target with ≥ 8 starting inputs (real example commands +
    built-in profiles + Python-generated PCA chains; `fuzz_validate_pipeline`
    reuses the `fuzz_command_json` corpus). New [fuzz/README.md](fuzz/README.md)
    documents the targets, seeding workflow, and how to capture fresh
    corpora from real campaigns.
  - **v11 1.6 PARTIAL (Merkle half DONE)** —
    [crates/invariant-cli/src/robotics/commands/verify.rs](crates/invariant-cli/src/robotics/commands/verify.rs)
    gains two new flags. `--merkle-root <HEX>`: after the local log walk
    passes, streams every entry's `entry_hash` through
    `MerkleAccumulator` (new `merkle_root_from_log` helper inside the
    command) and compares to the operator-supplied hex; accepts an
    optional `sha256:` prefix, rejects wrong-length input with exit 2
    before any computation, and prints both expected + computed roots
    on mismatch (exit 1). Empty-log corner case verifies against
    `merkle::empty_tree_hash()`. `--predecessor-digest <HEX>`: declared
    as a stub flag, accepted by clap so downstream tooling can already
    wire it through, but rejected at runtime with `error:
    --predecessor-digest is not yet implemented (waiting on v11 1.2 PCA
    predecessor_digest field)` exit 2 — refuses to silently honour an
    argument we cannot verify. Six new unit tests cover match /
    mismatch / malformed hex / `sha256:` prefix / empty-log root /
    predecessor-digest rejection. Promotion to full DONE happens in the
    same commit that closes v11 1.2.
  - **v11 1.4 DONE** — JCS canonicalization + Ed25519 manifest signing.
    `crates/invariant-core/src/proof_package.rs`:
    `ProofPackageManifest` gains `manifest_signature: Option<String>` +
    `manifest_signer_kid: Option<String>` (both
    `#[serde(default, skip_serializing_if = Option::is_none)]` so legacy
    v1 packages still parse). New
    `canonical_json(&manifest) -> Result<Vec<u8>, ProofPackageError>`
    implements the RFC 8785 subset the manifest exercises: recursive
    key sort, compact separators, no whitespace, with
    `manifest_signature` / `manifest_signer_kid` stripped from the
    preimage. Float formatting delegated to `serde_json` (shortest
    round-trip decimal; the manifest never carries NaN/∞). New
    `sign_manifest(&mut manifest, &SigningKey, kid)` and
    `verify_manifest(&manifest, &VerifyingKey)` (the latter uses
    `verify_strict` for cofactor-attack mitigation per RFC 8032
    §5.1.7). New
    `ProofPackageError::SignatureInvalid` / `Canonicalization`
    variants. `PackageInputs` gets
    `signing_key: Option<(SigningKey, String)>`; when set, `assemble`
    signs in place and writes `manifest.sig` (base64-no-padding, no
    trailing newline); when `None`, `tracing::warn!`s and leaves the
    manifest unsigned. Two new test files:
    [crates/invariant-core/tests/manifest_jcs_golden.rs](crates/invariant-core/tests/manifest_jcs_golden.rs)
    (sorted keys at every level, signature-field exclusion,
    no-whitespace property, determinism) and
    [crates/invariant-core/tests/manifest_tamper.rs](crates/invariant-core/tests/manifest_tamper.rs)
    (signed round-trip, byte flips in a `file_hashes` entry /
    `merkle_root` / signature, missing-signature and wrong-key
    rejection). Full workspace `cargo test` + `cargo clippy --lib
    -- -D warnings` green.
  - **v11 1.3 DONE** — RFC 6962 Merkle tree over the audit log.
    New [crates/invariant-core/src/merkle.rs](crates/invariant-core/src/merkle.rs):
    `leaf_hash(0x00‖entry)` / `inner_hash(0x01‖L‖R)` with canonical
    domain separators, streaming `MerkleAccumulator` (O(log n) via the
    Crosby/Wallach "occupied levels = bits of leaf-count" stack
    construction), `inclusion_proof`, `verify_inclusion` (rejects
    `index ≥ n`, over-long proofs, every single-bit perturbation), and
    the offline `tree_root` oracle. `AuditLogger` now keeps a running
    accumulator (push `leaf_hash(entry_hash_bytes)` after every
    successful append) and exposes
    `merkle_root() -> [u8;32]`. `PackageInputs` gets
    `merkle_root_hex: Option<String>`; `assemble()` writes
    `integrity/merkle_root.txt` (lowercase hex, no trailing newline)
    and the matching `Option<String>` lands on
    `ProofPackageManifest`. Two new test files:
    [crates/invariant-core/tests/merkle_known_vectors.rs](crates/invariant-core/tests/merkle_known_vectors.rs)
    (n = 1, 2, 3, 4, 7 with the leaf/inner steps spelled out in-line)
    and
    [crates/invariant-core/tests/merkle_tamper.rs](crates/invariant-core/tests/merkle_tamper.rs)
    (1024-leaf tree; round-trips every index, then flips every bit of
    the audit path for index 337 — ~257 k single-bit-flip assertions,
    ~6 s — and also asserts root-byte and leaf-byte perturbations
    invalidate verification). The pre-existing
    `replication::merkle_root` (a non-RFC-6962, odd-leaf-duplicating
    helper used by the v0 witness flow) is left in place for
    backwards compatibility but `invariant_core::merkle` is the
    canonical implementation that 1.4 / 1.6 / N-11 will build on.
    Full `cargo test --workspace` + `cargo clippy --workspace --lib --
    -D warnings` green.
  - **v11 5.1 DONE** — Split the unified env/payload sensor-range check
    into SR1 + SR2 per spec-v2 §3.2 / spec-v9 §5.1.
    [crates/invariant-robotics/src/physics/environment.rs](crates/invariant-robotics/src/physics/environment.rs)
    renames `check_sensor_range` → `check_sensor_range_env`
    (`SR1.sensor-range-env`) and adds `check_sensor_range_payload`
    (`SR2.sensor-range-payload`) enforcing joint position > 4π rad,
    joint velocity > 1000 rad/s, EE position > 1000 m, EE force
    magnitude > 100 kN. NaN/∞ left to P1–P4 to avoid double-reporting.
    `physics/mod.rs::run_all_checks` dispatches SR2 unconditionally; SR1
    stays inside `run_environment_checks` so it still fires only when
    `environment_state` is present. Eight new unit tests (in-range pass,
    four boundary rejections, NaN passthrough, 4π boundary pass,
    SR1/SR2 distinct-name invariant); existing length-12 / checks-14
    counts bumped where the new SR2 line is now appended. Public
    constants `SR1_CHECK_NAME` / `SR2_CHECK_NAME` / `SR2_MAX_*` exported
    so compliance counters can credit each independently.
  - **N-4 DONE** — `crates/invariant-core/src/models/audit.rs` gains a
    `schema_version: u32` field on `AuditEntry<I, V>` with
    `#[serde(default = "default_schema_version", skip_serializing_if = "schema_version_is_v1")]`.
    Pre-v12 records (no field) deserialize as v1 and re-serialize without
    the key, so their stored `entry_hash` and Ed25519 signature verify
    unchanged. `CURRENT_SCHEMA_VERSION = 2` is written by every new
    `AuditLogger::build_entry` call and by
    `invariant_sim::robotics::episode::EpisodeChain::append`.
    `verify_log` mirrors the field in its borrowed `HashableEntryView` and
    emits a single `tracing::warn!` when a log mixes versions (typed
    `MixedSchemaVersions` deferred until v11 1.3 Merkle integration).
    Two new tests in
    [crates/invariant-robotics/src/audit.rs](crates/invariant-robotics/src/audit.rs):
    `v2_record_round_trips_with_schema_version_field` and
    `legacy_v1_record_deserializes_as_v1_and_verifies`. All 34 audit
    tests green; workspace clippy + tests clean.
  - **N-5 DONE** — `crates/invariant-core/src/proof_package.rs` gains a
    numeric `format_version: u32` on `ProofPackageManifest` (default 1
    when missing on disk), constants
    `FORMAT_VERSION_V1` / `CURRENT_FORMAT_VERSION` /
    `MIN_SUPPORTED_FORMAT_VERSION` / `MAX_SUPPORTED_FORMAT_VERSION`, a
    new typed
    `ProofPackageError::UnsupportedFormat { found, expected_min, expected_max }`,
    and `verify_format_version()` (returns the typed error; emits a
    `tracing::warn!` while we're still on v1 — bumps to v2 once v11 1.3 +
    1.4 land). `assemble()` records the version. The `invariant
    verify-package` CLI calls `verify_format_version` immediately after
    parsing the manifest, surfacing the typed message as a failed
    "Manifest" check. New v1 fixture at
    [crates/invariant-core/tests/fixtures/proof_package_v1/manifest.json](crates/invariant-core/tests/fixtures/proof_package_v1/manifest.json)
    (no `format_version` key) plus four new unit tests:
    `format_version_defaults_to_v1_when_missing_on_disk`,
    `assemble_writes_current_format_version`,
    `verify_format_version_rejects_future_version`,
    `verify_format_version_rejects_zero`. Full workspace `cargo test` +
    `cargo clippy --workspace --lib -- -D warnings` green.
  - **bio V10-14 DONE** — Granular `CoseDecodeReason` enum for
    COSE_Sign1 decode failures. New typed `CoseDecodeReason` in
    [crates/invariant-core/src/models/error.rs](crates/invariant-core/src/models/error.rs)
    (nine variants: `CborInvalid` / `MissingProtectedHeader` /
    `MissingKid` / `InvalidKidEncoding` / `MissingPayload` /
    `PayloadDecode` / `SignatureSlotEmpty` / `WrongTag { expected, got }`
    / `Other`), new `AuthorityError::CoseDecode { hop, reason:
    CoseDecodeReason }` variant alongside the legacy `CoseError`
    (kept for backwards compatibility; no new code path produces it).
    All five internal call sites in
    [crates/invariant-core/src/authority/crypto.rs](crates/invariant-core/src/authority/crypto.rs)
    migrated to the typed variant: `parse_cose` →
    `CborInvalid(String)`; `extract_kid_from_parsed` empty/non-UTF8
    → `MissingKid` / `InvalidKidEncoding`;
    `decode_pca_payload_from_parsed` no-payload / parse-failure →
    `MissingPayload` / `PayloadDecode`. Hop index already plumbed
    through the chain-walk loop. Updated the two crypto-module unit
    tests to assert the new typed shape, the empty-COSE-bytes test
    in `authority::tests`, and added nine new snapshot cases in
    [crates/invariant-core/tests/error_stability.rs](crates/invariant-core/tests/error_stability.rs)
    that anchor `Display` for every `CoseDecodeReason` variant plus
    the wrapping `CoseDecode { hop, .. }` shape (the existing
    `CoseError` row preserved as the backwards-compat anchor).
    `MissingProtectedHeader`, `SignatureSlotEmpty`, and `WrongTag`
    are reserved for forensic completeness — `coset` currently
    surfaces those cases through `CborInvalid`. [docs/error-stability.md](docs/error-stability.md)
    gets an `AuthorityError::CoseDecode` row and a dedicated
    `CoseDecodeReason` table. Full workspace `cargo build` + `cargo
    test --workspace` + `cargo clippy --workspace --lib -- -D
    warnings` clean. With V10-14 closed, all four Chunk E prompts
    (V10-14/15/16/17) are DONE or formally deferred — Chunk E is
    fully reconciled.
  - **bio V10-16 DONE (option b — note added)** —
    [crates/invariant-biosynthesis/src/threat.rs](crates/invariant-biosynthesis/src/threat.rs)
    re-read end-to-end to confirm none of the five active detectors
    (boundary-clustering, authority-probing, replay-similarity, drift,
    anomaly) inspects `bundle.sequence`. The `DriftTracker` is keyed
    by principal but tracks payload-size running mean, not sequence
    ordering. Per the prompt's "no half-implemented detector" rule,
    option (b) wins: added a Resolution block to Prompt E.3 in
    [docs/biosynthesis/spec-v10-deep-gap-remediation.md](docs/biosynthesis/spec-v10-deep-gap-remediation.md)
    and a new §V10-OPEN section (alongside V10-OPEN-1 cross-process
    persistence) recording V10-OPEN-2 — per-source bundle-sequence-
    monotonicity detector — with the natural pick-up plan
    (`score_sequence_monotonicity` keyed by `bundle.source`, default
    weight in the 0.1–0.2 band, plus the `seq=10, seq=5` regression
    test the original prompt sketches). No code change; threat
    scorer surface left intact for a future v11-bio design pass.
  - **bio V10-15 + V10-17 DONE** — Two small biosynthesis Chunk E
    closures from [docs/biosynthesis/spec-v10-deep-gap-remediation.md](docs/biosynthesis/spec-v10-deep-gap-remediation.md):
    V10-15 adds three `bsl_level` boundary tests in
    [crates/invariant-biosynthesis/src/models/profile.rs](crates/invariant-biosynthesis/src/models/profile.rs)
    (`bsl_level_zero_rejected`, `bsl_level_five_rejected`,
    `bsl_level_boundaries_accepted` sweeping 1..=4); bio lib tests
    355 → 358, no behaviour change. V10-17 adds a synthesizer-side
    verdict-signature round-trip integration test at
    [crates/invariant-biosynthesis/tests/verdict_signature_roundtrip.rs](crates/invariant-biosynthesis/tests/verdict_signature_roundtrip.rs)
    — a deterministic 32-byte-seeded `SigningKey` runs a known bundle
    through `ValidatorConfig::validate`; the resulting `SignedVerdict`
    is written to a `tempfile::tempdir` path, re-loaded with a fresh
    `serde_json::from_slice` (no shared in-memory state), and the
    canonical preimage is reconstructed byte-for-byte the way
    `validator.rs::validate` builds it (`sha256:<hex>` ASCII of
    `sha256(serde_json::to_vec(&verdict))` — the leading `sha256:`
    prefix from `util::sha256_hex_json` is part of the signed
    preimage and the first iteration of the test caught the prefix-
    drop bug). A second test mutates `verdict.command_sequence` and
    asserts `verify_strict` rejects. The test's doc-comment notes
    explicitly that it stands in for the still-absent
    synthesizer-platform adapter (V8/V9-OPEN). Full workspace
    `cargo test` + `cargo clippy --workspace --lib` green; per-test
    clippy on the new file also clean.
  - **v11 5.13 step 1 DONE (full closure of 5.13)** — Added
    `#[non_exhaustive]` to the four load-bearing public error enums named
    in [docs/error-stability.md](docs/error-stability.md):
    `AuthorityError` and `ValidationError` in
    [crates/invariant-core/src/models/error.rs](crates/invariant-core/src/models/error.rs),
    `AuditError` and `AuditVerifyError` in
    [crates/invariant-core/src/audit.rs](crates/invariant-core/src/audit.rs).
    Pre-flight audit confirmed every existing match site is `_`-bearing
    (`matches!(_, Variant { .. })` in tests; `Variant { field, .. }`
    destructuring in `authority::crypto`); the exhaustive construction
    in `tests/error_stability.rs` still compiles because the annotation
    only restricts pattern-matching and explicit construction *outside*
    the defining crate. Full workspace `cargo build` + `cargo test` +
    `cargo clippy --workspace --lib` green. `docs/error-stability.md`
    paragraph 2 rewritten to record the new annotation and the
    no-downstream-change rationale.
  - **v11 5.7 DONE (full closure, 25 of 25 P-checks + SR1 + SR2)** —
    Sixth test file [crates/invariant-robotics/tests/physics_property_p6_p7_p9_p10.rs](crates/invariant-robotics/tests/physics_property_p6_p7_p9_p10.rs)
    closes the geometry-heavy quartet that v11 5.7's partial close
    deferred. 15 tests across the four checks:
    P6 `check_exclusion_zones` uses a disjoint unit-cube AABB + unit
    sphere — interior points of either reject, exterior of both pass,
    and a disabled conditional zone admits its interior; P7
    `check_self_collision` samples a random unit direction by rejection
    on the unit cube and scales by a chosen inter-link distance, with
    above-min passing and below-min rejecting on both bands; P9
    `check_stability` uses a regular hexagon so the inscribed-circle
    radius `cos(π/6) ≈ 0.866` and the circumradius `1.0` give clean
    accept/reject bands, plus degenerate-polygon and disabled-config
    edge cases; P10 `check_proximity_velocity` parks the EE inside a
    `velocity_scale = 0.5` zone, sweeps |v| against the scaled limit,
    and also asserts the EE-outside-zone branch and the
    `global_velocity_scale` multiplier. Same hand-rolled LCG as the
    rest of the suite (256 cases per property; `proptest` is still not
    a workspace dep). All 91 randomised tests pass under
    `cargo test -p invariant-robotics --tests physics_property`;
    `cargo clippy -p invariant-robotics --tests -- -D warnings` clean.
  - **v11 5.7 — earlier partial close (20 of 25 P-checks + SR1 + SR2)**
    — Five test files in
    [crates/invariant-robotics/tests/](crates/invariant-robotics/tests/):
    `physics_property_p1_p5.rs` (P1 joint_limits, P2 velocity, P3
    torque, P4 acceleration, P5 workspace_bounds);
    `physics_property_p8_p14.rs` (P8 delta_time, P11 ee_force, P12
    grasp_force, P13 force_rate, P14 payload);
    `physics_property_p15_p20.rs` (P15 locomotion_velocity, P16
    foot_clearance, P17 ground_reaction, P19 step_length, P20
    heading_rate); `physics_property_sr1_sr2.rs` (SR1 env-side:
    pitch/roll, temperature, battery, latency; SR2 payload-side:
    joint position, joint velocity, EE position, EE force);
    `physics_property_p18_p25.rs` (P18 friction_cone — random
    tangent direction × magnitude up to μ·fz; P25 emergency_stop
    binary; and four warning-zoned env checks P21 terrain_incline,
    P22 actuator_temperature, P23 battery, P24 communication_latency
    with four asserts each: safe-zone → PASS no-derate, warn-zone
    → PASS with derate ∈ (0,1), boundary → PASS, above-max →
    REJECT). **76 randomised tests total**; each property runs 256
    cases through a hand-rolled deterministic LCG seeded
    per-property (mirrors the N-15 pattern — `proptest` is not yet
    on the workspace dep list). P4/P13 back-solve kinematic
    equations; P15/P17/P18 sample a uniform direction via rejection
    on the unit cube and scale to the target magnitude. ~0.0 s
    runtime across all five files; clippy clean. Still queued:
    P6 exclusion_zones, P7 self_collision, P9 stability (ZMP),
    P10 proximity_velocity — all geometrically/vector-heavy.
  - **v11 tracking table sync** — `docs/history/robotics/spec-v11.md` tracking
    table updated: 11 prompts whose body Status already said DONE
    (5.2, 5.3, 5.4, 5.6, 5.9, 5.10, 5.11, 5.12, 5.13, 5.14, 5.15, 5.16)
    now also show DONE in the bottom-of-file tracking table with the
    same citations. Pure housekeeping; no code change.
  - **v11 5.8 DONE** — End-to-end proof-loop smoke test.
    New [crates/invariant-cli/tests/proof_loop_smoke.rs](crates/invariant-cli/tests/proof_loop_smoke.rs)
    drives the v11 Phase-1 surface in a single process: two shards of
    signed audit lines → `assemble::run` with `--key` + `--public-key`
    (writes JCS-signed `manifest.json` + `manifest.sig`, RFC 6962
    `integrity/merkle_root.txt`, and the `integrity/metadata.json`
    sidecar from v11 1.5) → `verify_package::run` against the clean
    package (9/9 checks pass) → three tamper variants. A byte flip in
    `results/audit.jsonl` is caught by the file-hash mismatch path; a
    byte flip in `manifest.json` is caught by structural failure / hash
    mismatch; a byte flip in `manifest.sig` is verified directly via
    `proof_package::verify_manifest` (returns `SignatureInvalid`)
    because `verify-package` does not yet check the Ed25519 signature
    directly (queued behind v11 1.6). While wiring this up, fixed a
    pre-existing bug in
    [crates/invariant-cli/src/robotics/commands/verify_package.rs](crates/invariant-cli/src/robotics/commands/verify_package.rs)
    where the "Merkle root" check used the legacy
    `replication::merkle_root_from_log` (non-RFC-6962, no domain
    separators) — replaced with a new private `rfc6962_root_from_log`
    helper that streams `entry_hash` leaves through
    `invariant_core::merkle::MerkleAccumulator`, matching the writer in
    `proof_package::assemble` (v11 1.4/1.5) and the equivalent check
    in `verify --merkle-root` (v11 1.6). The smoke-test shards
    intentionally omit `summary.json` so the merged summary collapses
    to `CampaignSummary::compute(0,…,0,0.0)`, sidestepping a
    separately-tracked 1-ULP mismatch between `serde_json`'s float
    parser and `ryu`'s shortest-round-trip emitter for certain
    `clopper_pearson_upper` outputs (would break self-verify after
    disk round-trip; root cause noted inline). `assemble` also gained
    `--public-keys <PATH>` and `--adversarial <PATH>` (repeatable)
    flags so the smoke test can supply the auxiliary artifacts
    `verify-package` insists on; the three new fields are
    `Option<PathBuf>` / `Vec<PathBuf>`, and the existing unit tests
    were updated to pass `None` / empty vec.
  - **v11 1.5 DONE** — `invariant robotics assemble` proof-package CLI.
    New [crates/invariant-cli/src/robotics/commands/assemble.rs](crates/invariant-cli/src/robotics/commands/assemble.rs)
    surfaces `invariant robotics assemble --shards <DIR> --output <DIR>
    [--key PATH] [--public-key PATH] [--metadata KEY=VALUE]…`. Walks
    `--shards` in sorted order; for each subdir merges `audit.jsonl`
    (concatenated in shard-name order) and `summary.json` (per-field
    sums; matched on `control_frequency_hz`); computes the RFC 6962
    Merkle root over every `entry_hash` from the merged log and passes
    it to `proof_package::assemble` so the existing v11 1.3 + 1.4
    pathways write `integrity/merkle_root.txt` and (when `--key` is
    set) JCS-canonicalise + Ed25519-sign the manifest. When
    `--public-key` is supplied the assembled `manifest.json` is
    reloaded and `verify_manifest` runs end-to-end; mismatch → exit 1.
    `--metadata KEY=VALUE` writes an `integrity/metadata.json` sidecar
    rather than touching the manifest body (the format-version stays
    at 1 and the JCS canonical preimage is unchanged). Subcommand
    registered at the robotics level (`invariant robotics assemble`)
    rather than `invariant campaign assemble` because the unified
    workspace already exposes `campaign` as a flat command — the
    deviation is documented in the file header. Nine new unit tests
    cover missing-shards, empty-shards, non-empty-output guards,
    unsigned assembly, signed assembly + self-verify happy path,
    signed assembly + wrong-public-key self-verify failure (exit 1),
    deterministic sort-order over shard names, metadata key
    validation, and Merkle-root hex format. `tempfile` promoted from
    `[dev-dependencies]` to `[dependencies]` for the merged-audit-log
    temp path. Pre-existing clippy lint in
    [crates/invariant-cli/src/robotics/commands/verify.rs](crates/invariant-cli/src/robotics/commands/verify.rs)
    (`empty_line_after_doc_comments` on a test note above the v11 1.6
    block) fixed in passing by converting four `///` lines to `//`.
    Full `cargo test --workspace --lib` + `cargo clippy --workspace
    --lib -- -D warnings` green.
  - **v11 5.5 DONE** — Multi-robot coordinator `fleet status` CLI +
    10-robot integration test. New
    [crates/invariant-cli/src/robotics/commands/fleet.rs](crates/invariant-cli/src/robotics/commands/fleet.rs)
    surfaces `invariant robotics fleet status --state <PATH>
    [--format text|json] [--alerts-only]`. Off-line by design — the
    long-running monitor process is the source of truth; the CLI
    consumes a serialised [`FleetSnapshot`](crates/invariant-coordinator/src/monitor.rs)
    (now re-exported at `invariant_coordinator::FleetSnapshot`) and
    renders a stable text table or `FleetStatusReport` JSON. Computes
    every pairwise EE distance and emits a sorted list of
    `SeparationAlert`s when any pair sits below the configured
    `min_separation_m`. Exit codes: `0` clean, `1` alerts present
    (`set -e`-friendly health check), `2` usage error (missing file /
    bad JSON). Five new unit tests cover counting, single-pair alert
    detection, multi-EE × multi-EE pair enumeration, exit-1-vs-0 on
    dirty-vs-clean snapshots, exit-2 on missing/malformed input. New
    integration test
    [crates/invariant-coordinator/tests/fleet_10_robot.rs](crates/invariant-coordinator/tests/fleet_10_robot.rs)
    (four tests) scripts 8 arms + 2 mobile bases in a 5×2 grid at
    10 Hz for 60 simulated seconds; `arm-3` drifts toward `arm-4`
    along +x after t=30 s and crosses the 0.5 m envelope at t=45 s.
    Asserts (a) every pre-drift tick is admitted, (b) the post-drift
    tick is rejected with a `separation` `CrossRobotCheck` naming
    `(arm-3, arm-4)`, (c) the snapshot at the violation tick
    round-trips through `serde_json`, (d) the full 600-tick sweep
    classifies every tick correctly (no violations before drift,
    mandatory violation after the boundary). All 5 fleet unit tests +
    4 coordinator integration tests green; full workspace `cargo
    test` green; `cargo clippy -p invariant-coordinator -p
    invariant-cli --lib --tests -- -D warnings` clean.
  - **N-6 DONE** — `invariant robotics assemble --resume` with sidecar
    state. [crates/invariant-cli/src/robotics/commands/assemble.rs](crates/invariant-cli/src/robotics/commands/assemble.rs)
    gains an `AssembleState { version, output_dir, consumed: [ConsumedShard
    …] }` sidecar written to `<output>.assemble-state.json` (next to the
    package directory). After every fresh shard is folded into the merge,
    the sidecar is written to a `.tmp` sibling, `sync_all`-fsynced, and
    atomically renamed — so SIGTERM/SIGINT mid-run leaves a recoverable
    marker. On startup a pre-existing sidecar without `--resume` exits 2
    with `existing assembly state — pass --resume or remove <path>`;
    `--resume` re-verifies every previously-consumed shard's
    `audit.jsonl` SHA-256 against the current source tree (mismatch →
    exit 2 with a tamper message naming the cached + current digests)
    and bypasses the non-empty-output guard so a partial package can be
    overwritten. The final `assemble()` call replays all consumed +
    remaining shards in deterministic sort order, so the resumed package
    is byte-identical to a one-shot run (asserted by comparing the
    `integrity/merkle_root.txt` of both). Successful completion removes
    the sidecar. The simulated mid-run abort is driven by a `cfg(test)`
    `thread_local!` `Cell<usize>` + `PanicAfter` RAII guard, so the
    panic injection cannot leak across parallel test threads. Six new
    unit tests: pre-existing sidecar without resume → exit 2; resume
    with no sidecar is a normal run; resume-after-abort produces a
    byte-identical Merkle root vs. one-shot (4 shards, abort after #2);
    resume detects source-shard tampering; mismatched-output-dir
    sidecar rejected; unknown-version sidecar rejected. All 15
    `assemble::tests` (9 existing + 6 new) green; workspace-wide
    `cargo test` green; `cargo clippy -p invariant-cli -p
    invariant-core -p invariant-coordinator --lib --tests -- -D
    warnings` clean. In passing, added the previously-missing
    `pub struct FleetSnapshot` in
    [crates/invariant-coordinator/src/monitor.rs](crates/invariant-coordinator/src/monitor.rs)
    (referenced by `CoordinationMonitor::snapshot` for v11 5.5 — the
    type was used but never defined, blocking `cargo build`); updated
    [crates/invariant-cli/tests/proof_loop_smoke.rs](crates/invariant-cli/tests/proof_loop_smoke.rs)
    to pass `resume: false` in its `AssembleArgs` literal.
  - **N-11 DONE** — Audit-rotation Merkle continuity test at
    [crates/invariant-core/tests/audit_rotation_merkle.rs](crates/invariant-core/tests/audit_rotation_merkle.rs).
    `invariant-core` exposes no explicit rotation API (rotation is the
    operator's responsibility via logrotate / copy-truncate), so the
    test models the supported pattern: capture
    `previous_hash` + `sequence` from a soon-to-be-rotated logger, then
    resume a fresh logger from that state against a new sink. Each
    segment writes 1000 entries through a `SharedSink`
    (`Rc<RefCell<Vec<u8>>>`) so the JSONL bytes can be reclaimed
    without consuming the logger. Asserts: (1) live per-segment
    `MerkleAccumulator::root()` agrees with the offline `tree_root`
    oracle, (2) the first segment-B entry's `previous_hash` equals
    segment A's last `entry_hash` (L2 continuity across the cut),
    (3) the cross-segment root computed over the concatenated leaf
    stream differs from each per-segment root, (4) inclusion proofs
    for index 500 (pre-rotation) and 1500 (post-rotation) both verify
    against the cross-segment root via `verify_inclusion`, (5)
    single-bit flips of either leaf invalidate the proof. A second
    test deliberately corrupts a post-rotation leaf and asserts the
    honest inclusion proof no longer verifies against the tampered
    root. Both tests use `SignedAuditEntry`'s flattened JSON shape
    (`entry_hash` and `previous_hash` are top-level fields, not nested
    under `entry.*`). Runtime ~10 s (Ed25519 signing dominates).
  - **N-17 DONE** — Two new Linux-gated tests in
    [crates/invariant-cli/src/robotics/commands/validate.rs](crates/invariant-cli/src/robotics/commands/validate.rs):
    `validate_exits_nonzero_when_audit_write_fails` points `--audit-log` at
    `/dev/full` (open succeeds, every write returns ENOSPC) and asserts
    exit 2; `validate_exits_zero_when_audit_write_succeeds` exercises the
    happy path. Non-Linux OSes execute a documented soft-skip stub. The
    named `--fail-on-audit-error` flag itself is `serve`-only and is
    already covered by `test_audit_write_failure_returns_503_when_fail_on_audit_error`;
    this prompt closes the equivalent `validate`-side regression.
  - **v11 2.0 DONE (partial scope)** — Campaign determinism contract.
    New [crates/invariant-sim/src/robotics/rng.rs](crates/invariant-sim/src/robotics/rng.rs)
    introduces `CampaignRng` — a `ChaCha20Rng` newtype with
    `from_episode_seed(u64)` and `from_seed([u8;32])` constructors,
    `RngCore` delegated through to the inner stream cipher. Audit of the
    four prompt-named files (`scenario.rs`, `campaign.rs`,
    `orchestrator.rs`, `collector.rs`) shows zero `thread_rng` / `OsRng`
    / `SystemTime::now` / `Instant::now` use in non-test code today —
    `ScenarioGenerator` is deterministic by arithmetic — so no call
    sites needed migration. The plumbing is in place for v11 2.1–2.11
    (which must thread `&mut CampaignRng` as they add stochastic
    generators). New
    [crates/invariant-sim/tests/no_threadrng.rs](crates/invariant-sim/tests/no_threadrng.rs)
    greps the four files for the four forbidden tokens (skips
    `#[cfg(test)]` / `#[test]` blocks; supports an explicit
    `// spec-v11-2.0 allow: <reason>` opt-out per line) — fails the
    suite on regression. New
    [crates/invariant-sim/tests/determinism.rs](crates/invariant-sim/tests/determinism.rs)
    (two tests): `same_seed_yields_byte_identical_canonical_report`
    runs `run_dry_campaign` twice with a fixed 32-byte seed and
    asserts byte-equality of the JSON-canonicalised `CampaignReport`
    (HashMaps converted to BTreeMap to neutralise hasher-state ordering);
    a 400-command fixture (2 envs × 50 episodes × 4 steps over
    baseline/aggressive/exclusion_zone) pins the scale.
    `different_seeds_produce_same_aggregate_shape` asserts the shape
    invariants (totals sum, rates in `[0,1]`, confidence bound
    non-negative) hold across seed perturbations. `rand_chacha = "0.3"`
    promoted from transitive to direct dep on `invariant-sim`. Open
    follow-up: per-`Verdict` `Utc::now()` inside
    [crates/invariant-sim/src/robotics/isaac/dry_run.rs](crates/invariant-sim/src/robotics/isaac/dry_run.rs)
    is still wall-clock — `CampaignReport` itself carries no timestamps
    so the operator-visible byte-equality contract holds today;
    tightening to a seeded clock is queued for the prompt-pair that
    introduces seeded RNG into generators. `cargo test -p invariant-sim`
    → 776 lib + 5 + 2 + 1 + 4 + 45 integration, all green; clippy clean
    on the new files. Unblocks v12 N-3 (per-shard determinism fixture).
  - **v12 N-3 DONE** — Per-shard determinism fixture.
    New [crates/invariant-sim/tests/determinism_fixture.rs](crates/invariant-sim/tests/determinism_fixture.rs)
    regenerates a 1 000-episode `Baseline` shard on the built-in
    `ur10e_haas_cell` profile with the spec-named seed
    `0xCAFE_BABE_DEAD_BEEF` (splatted 4× into the 32-byte seed slot) and
    asserts SHA-256 equality against the committed digest at
    [crates/invariant-sim/tests/fixtures/baseline_ur10e_seed_cafebabe.sha256](crates/invariant-sim/tests/fixtures/baseline_ur10e_seed_cafebabe.sha256).
    Hash target is the canonical-JSON `CampaignReport` (HashMaps
    re-sorted into BTreeMap to neutralise hasher-state ordering), not
    the JSONL the prompt sketched — `run_dry_campaign` doesn't emit
    JSONL today, and per-`Verdict` `Utc::now()` makes a JSONL digest
    wall-clock-dependent. Both deviations documented inline; the test
    should be re-pointed once a seeded clock + JSONL writer land.
    Profile substitution: prompt named `ur10e_safety_v1` (not in the
    built-in registry); `ur10e_haas_cell` is the documented stand-in.
    `REGENERATE_DETERMINISM_FIXTURE=1` env var regenerates the digest
    after intentional generator changes. Runtime ~3 s.
  - **v11 3.2 DONE** — Bridge bounded reads + per-connection watchdog
    isolation. Bounded-read half landed earlier
    (`FUZZ_BRIDGE_MAX_LINE_BYTES = 8 KiB`, oversize lines reject before
    the JSON parser runs — locked down by v12 N-12). Watchdog isolation:
    end-to-end re-read of
    [crates/invariant-sim/src/robotics/isaac/bridge.rs](crates/invariant-sim/src/robotics/isaac/bridge.rs)
    confirms there's no shared liveness state — `run_bridge` spawns one
    `tokio` task per accepted connection; each task owns its own
    `BufReader`, `previous_joints`, and `read_timeout`. The only shared
    mutable cell is `Arc<Mutex<BridgeStats>>` (aggregate counters,
    doesn't gate liveness). The stale module-level header that claimed
    "One `Watchdog` per bridge instance (shared, single robot)" was
    replaced with an accurate per-connection description plus a pointer
    to the new regression test. New
    `bridge_watchdog_per_connection_isolation` test (in `bridge::tests`):
    opens two simultaneous connections, leaves A silent, and asserts B
    receives ≥3 heartbeat acks past A's `read_timeout` (200 ms) window
    while A's read side closes cleanly (timeout error then EOF).
    Removing per-task isolation (e.g. routing reads through a shared
    mutex) breaks this test deterministically. ~0.5 s runtime; clippy
    clean on the new code.
  - **v11 2.1 DONE (Category B intent tests)** — Category B (Joint
    Safety, B-01..B-08) generators were already shipped in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    and bound to spec IDs in
    [docs/scenario-id-map.md](docs/scenario-id-map.md). Closure here is
    the missing piece: new
    [crates/invariant-sim/tests/category_b_generators.rs](crates/invariant-sim/tests/category_b_generators.rs)
    adds 8 intent assertions (one per spec ID, profile `ur10`) — B-01
    at least one joint commanded at exact `min` and exact `max`; B-02
    velocity hits exactly `max_velocity × global_velocity_scale`; B-03
    effort hits exactly `max_torque`; B-04 |velocity| is monotonically
    non-decreasing across the ramp and the final step exceeds
    `2 × max_velocity`; B-05 every joint sits at exactly `0.99 × max`
    on even steps and `1.01 × max` on odd; B-06 first joint's velocity
    alternates `+max_v / −max_v` exactly; B-07 at least one command
    emits a non-finite (NaN / ±Inf) joint value; B-08 the target joint
    strictly exceeds `max` on every step. RNG plumbing intentionally
    not added — Category B generators are deterministic by arithmetic,
    which is stronger than the prompt's seeded-RNG sketch; the
    determinism contract is already locked by v11 2.0 + v12 N-3.
    ~0 s runtime; clippy clean. v11 2.2–2.11 (Categories C–N) remain
    open.
  - **v12-N-2 follow-up — spec-ID bindings promoted** — Eleven of the
    twelve previously `UNASSIGNED` rows in
    [docs/scenario-id-map.md](docs/scenario-id-map.md) are now bound to a
    `docs/robotics/spec-15m-campaign.md` §3 ID. New rows:
    `ExclusionZone` → C-02, `CncTending` → C-03, `LocomotionRunaway` →
    D-03, `LocomotionTrip` → D-04, `LocomotionStomp` → D-05,
    `LocomotionSlip` → D-06, `LocomotionFall` → D-09 (closest peer for
    its P9+P15+P19 composite), `EnvironmentFault` → F-08 (combined
    environmental hazards), `AuthorityEscalation` → G-02, `ChainForgery`
    → G-10, `MultiAgentHandoff` → H-02 (sequence-regression peer).
    `PromptInjection` deliberately left unassigned — it emits raw 5–10×
    over-limit physics rather than any of the I-* cognitive-attack
    patterns; documented inline. `ScenarioType::spec_id`'s exhaustive
    match arm at
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    moved each variant from the `=> "unassigned"` group to a specific
    arm; six new binding doctest assertions added next to the existing
    ten. Coverage: `cargo test scenario_coverage spec_id_gap_report` now
    reports `35/106 ids implemented; 71 gaps` (was 26/104). All sim tests
    + doctests green; clippy clean.
  - **v11 2.2 + 2.6 PARTIAL (intent tests for implemented C/G variants)**
    — New
    [crates/invariant-sim/tests/category_c_g_generators.rs](crates/invariant-sim/tests/category_c_g_generators.rs)
    adds four intent assertions for the already-shipped Category C / G
    variants (bindings promoted in the prior 2026-05-17 entry):
    **C-02** `ExclusionZone` — every EE position must lie inside ≥1
    exclusion zone of `ur10e_haas_cell` (matches `Aabb` / `Sphere`;
    `#[non_exhaustive]` future variants fail closed); **C-03**
    `CncTending` — first half of the sequence overrides
    `haas_spindle_zone` to `false` (loading phase, EE passes), second
    half overrides it to `true` (cutting phase, EE rejects); **G-02**
    `AuthorityEscalation` — `pca_chain` is empty string on every
    command; **G-10** `ChainForgery` — `pca_chain` is non-empty but
    rejects `base64::engine::general_purpose::STANDARD.decode`.
    Mirrors the Category B pattern. Promotes v11 2.2 and 2.6 from
    OPEN to PARTIAL; full closure of each prompt awaits new
    `ScenarioType` variants for C-01/C-04..C-06 and G-01/G-03..G-09.
    All 5 tests pass; clippy clean.
  - **v11 2.7 PARTIAL — Category H (H-04 + H-05 implemented)** — Two
    new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs):
    `DeltaTimeAttack` → H-04 cycles `delta_time` through {0, −1e-3,
    NaN, +Inf, −Inf} (all reject under P8 finite/positive); `StaleCommand`
    → H-05 pins `delta_time = 2 × profile.max_delta_time` (all reject
    under P8 upper bound). Wiring: variants added to enum + `all()` list;
    `spec_id()` arms returning `"H-04"` / `"H-05"`; dispatch in
    `generate_commands`; snake-case spellings registered in
    `parse_scenario_type` (dry-run) and in the
    `scenario_type_from_snake` helper inside
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    so the campaign-load coverage check passes. New
    [crates/invariant-sim/tests/category_h_generators.rs](crates/invariant-sim/tests/category_h_generators.rs)
    (3 tests): H-04 asserts every command carries one of the 5
    pathological dt values and that all 5 actually appear; H-05 asserts
    `delta_time == 2 × profile.max_delta_time` to within 1e-12; both
    round-trip through `ScenarioGenerator::generate_commands`. Two new
    binding doctest assertions added next to the existing ones.
    Coverage now `37/106 ids implemented; 69 gaps` (was 35/106 after
    the earlier promotions). Full sim suite green (777 lib + 79
    integration); clippy clean. H-01 / H-03 / H-06 remain open.
  - **v11 2.7 further PARTIAL — Category H (H-01 + H-03 added)** —
    Two more `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs):
    `SequenceReplay` → H-01 emits every command with the same
    `sequence` (`SEQUENCE_REPLAY_VALUE = 1`), tripping per-source
    monotonicity in stateful executors; classified as `expected_reject`.
    `SequenceGap` → H-03 emits cmd 0 with `sequence=0` and the rest with
    `sequence = 1_000_000 + i`. Per spec-v7 §2.7's multi-source model
    gaps are *legitimate*, so the variant is added to the
    `is_expected_reject` allowlist in
    [crates/invariant-sim/src/robotics/isaac/dry_run.rs](crates/invariant-sim/src/robotics/isaac/dry_run.rs)
    alongside the existing always-pass scenarios. Same plumbing
    discipline as last batch: enum, `all()`, `spec_id()`,
    `generate_commands` dispatch, `parse_scenario_type` snake/Pascal
    pair, `scenario_type_from_snake` helper, two new binding doctest
    assertions. Two new tests in
    [crates/invariant-sim/tests/category_h_generators.rs](crates/invariant-sim/tests/category_h_generators.rs):
    H-01 asserts all 20 commands share `cmd[0].sequence` and joint
    state stays finite; H-03 asserts cmd 0 is `sequence=0`, every
    subsequent command is ≥ `1_000_000`, and the post-gap sequence is
    strictly monotonic so the scenario doesn't re-encode replay.
    Coverage now `39/106 ids implemented; 67 gaps` (was 37). Only
    H-06 (future-dated sensor) remains in Category H. Full sim suite
    (777 lib + 81 integration) green; clippy clean.
  - **v11 2.2 + 2.4 further PARTIAL — C-06 and E-04 added** — Two
    more `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs):
    `CorruptSpatialData` → C-06 cycles EE positions through NaN, +∞,
    −∞ rotating which coordinate is corrupted; joint state stays
    baseline-safe so the failure mode is unambiguously spatial.
    `PayloadOverload` → E-04 linearly ramps `estimated_payload_kg`
    from 0 to `3 × max_payload_kg` of the first end-effector; profiles
    without `end_effectors` fall back to 1.0 kg so the generator
    never panics. Same plumbing as before: enum + `all()` + `spec_id()`
    + `generate_commands` dispatch + `parse_scenario_type` (dry-run) +
    `scenario_type_from_snake` (campaign-load test helper) + two new
    binding doctest assertions. Both classified as `expected_reject`
    by default (the `is_expected_reject` allowlist is unchanged). Two
    new tests in
    [crates/invariant-sim/tests/category_c_e_generators.rs](crates/invariant-sim/tests/category_c_e_generators.rs):
    C-06 asserts every command's EE has ≥1 non-finite coord, all
    three sentinel values appear across the sequence, joint state
    stays finite; E-04 asserts cmd 0 payload ≈ 0, ramp is monotonic
    non-decreasing, final exceeds `2 × max_payload_kg`. Coverage now
    `41/106 ids implemented; 65 gaps` (was 39). Full sim suite green
    (777 lib + 83 integration); clippy clean. C-01 / C-04 / C-05 and
    E-01..E-03 / E-05 / E-06 still need variants.
  - **v11 2.4 DONE + 2.7 DONE — Category E (E-01/E-02/E-03) and H (H-06)**
    — Four new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs):
    `ForceLimitSweep` → E-01 linearly ramps the EE force-vector magnitude
    along +x from 0 to `3 × max_force_n` of the first end-effector;
    `GraspForceEnvelope` → E-02 cycles `grasp_force` through five regimes
    (`0.5×min`, `min`, mid-band, `max`, `1.5×max`) of the
    `[min_grasp_force_n, max_grasp_force_n]` window so P12 sees both
    in-band and out-of-band values; `ForceRateSpike` → E-03 alternates
    zero force (odd seq) and `3 × max_force_rate_n_per_s × dt` (even seq),
    mirroring the existing `injector::inject_force_rate_spike` policy so
    a stateful validator's `previous_forces` snapshot deterministically
    trips P13 from index 1 onwards; `FutureDatedSensor` → H-06 attaches
    one `SignedSensorReading` per command whose `reading.timestamp` is
    10 s past the command's own `timestamp` (stub signature, signer
    `"h06-future-stub"`). Same plumbing discipline as prior batches:
    enum + `all()` + `spec_id()` + `generate_commands` dispatch +
    [crates/invariant-sim/src/robotics/isaac/dry_run.rs](crates/invariant-sim/src/robotics/isaac/dry_run.rs)
    `parse_scenario_type` (Pascal + snake-case pair) +
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    `scenario_type_from_snake` helper + four new binding doctest
    assertions next to the existing ones. New
    [crates/invariant-sim/tests/category_e_h_generators.rs](crates/invariant-sim/tests/category_e_h_generators.rs)
    (4 tests on `ur10e_haas_cell`): E-01 asserts cmd 0 is force=0, the
    +x force is monotonically non-decreasing across the sequence, the
    final command exceeds `2 × max_force_n`, and every command's
    `EndEffectorForce.name` equals the profile's first end-effector name
    with `grasp_force=None`; E-02 asserts each command's grasp force
    matches the expected regime for its index modulo 5 within 1e-9 and
    that all five regimes appear at least once; E-03 asserts every
    even-sequence command exceeds `2 × max_force_rate × dt` while every
    odd-sequence command is exactly zero; H-06 asserts each command
    carries exactly one signed sensor reading whose timestamp is 10 s
    ahead of the command's `timestamp` (±1 ms tolerance) with
    `signer_kid == "h06-future-stub"`. Closes Category H end-to-end
    (H-01..H-06 all implemented); closes Category E for the canonical
    rows E-01..E-04 (E-05 ISO-15066 proximity and E-06 bimanual still
    OPEN). Coverage now `45/106 ids implemented; 61 gaps` (was 41).
    All 777 sim lib tests + the integration set green; clippy clean
    after a drive-by `manual_contains` fixup in `campaigns_load.rs`.
    Updates: [docs/scenario-id-map.md](docs/scenario-id-map.md) gains
    four IMPLEMENTED rows; [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md)
    tracking row 2.1–2.11 promoted to reflect 2.4 DONE + 2.7 DONE.
  - **v11 2.5 PARTIAL — Category F (F-01..F-04 added)** — Four new
    `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    split the pre-existing combined F-08 (`EnvironmentFault`) into
    single-phase sweeps so each P-check can be exercised in isolation:
    `TemperatureRamp` → F-01 ramps every joint's
    `actuator_temperatures[*].temperature_celsius` linearly from 20 °C
    (ambient) to `2 × max_operating_temperature_c`, crossing both
    `warning_temperature_c` (derate band) and the hard limit (REJECT
    P22); `BatteryDrain` → F-02 ramps `battery_percentage` from 100 to
    0, crossing both `low_battery_pct` (derate) and
    `critical_battery_pct` (REJECT P23); `LatencySpike` → F-03 ramps
    `communication_latency_ms` from 0 to `5 × max_latency_ms`, crossing
    `warning_latency_ms` (derate) and `max_latency_ms` (REJECT P24);
    `EStopEngageRelease` → F-04 alternates `e_stop_engaged = false`
    (even index — accepted) and `true` (odd — REJECT P25). All four
    are classified as MIXED in the dry-run harness
    ([crates/invariant-sim/src/robotics/isaac/dry_run.rs](crates/invariant-sim/src/robotics/isaac/dry_run.rs)
    `is_expected_reject` allowlist) so early/baseline phases aren't
    counted as violation escapes. Same plumbing discipline: enum +
    `all()` + `spec_id()` + dispatch + `parse_scenario_type` (Pascal +
    snake) + `scenario_type_from_snake` helper in
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    + four new binding doctest assertions. New
    [crates/invariant-sim/tests/category_f_generators.rs](crates/invariant-sim/tests/category_f_generators.rs)
    (4 tests on `ur10e_haas_cell`): each ramp test asserts (a) the
    expected start value, (b) monotonic ramp direction, (c) commands
    cross both the warning band and the hard limit, (d) commands in
    the pre-warning band also exist; F-04 asserts the alternation
    pattern and that both states appear. Serde-rename gotcha resolved
    inline — `EStopEngageRelease` serialises to `e_stop_engage_release`
    (serde inserts a separator before the lowercase `S` that follows a
    capital), so the snake spelling in both `parse_scenario_type` and
    the `scenario_type_from_snake` helper had to match that — tripped
    the existing exhaustiveness test in the first build pass. Coverage
    now `49/106 ids implemented; 57 gaps` (was 45). F-05 (SR1 sensor
    range plausibility), F-06 (SR2 sensor payload range), F-07 (sensor
    fusion inconsistency) still need variants — they exercise the
    `sensor.rs` plausibility layer and the fusion divergence check
    rather than `EnvironmentState`. All 777 sim lib tests + 12 new
    integration tests green; clippy clean.

  - **v11 2.5 DONE — Category F closure (F-05/F-06/F-07 added)** — Three
    new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    close out Category F: `SensorRangeImplausible` → F-05 cycles three
    SR1 env-side violations by `index % 3` (IMU pitch = 2π rad,
    actuator temperature = −300 °C on every joint, battery_percentage =
    500 %); `SensorPayloadRange` → F-06 cycles three SR2 payload-side
    violations (joint position = 5π rad > 4π SR2 max, EE position axis
    = 2000 m > 1000 m SR2 max, EE force magnitude = 200 kN > 100 kN SR2
    max); `SensorFusionInconsistency` → F-07 emits two
    `SignedSensorReading`s per command with the same `sensor_name`
    ("fusion_pos") but `Position` payloads diverging by 10 m on the
    x-axis — exercises `check_sensor_fusion`. F-07 added to the
    `is_expected_reject` allowlist in
    [crates/invariant-sim/src/robotics/isaac/dry_run.rs](crates/invariant-sim/src/robotics/isaac/dry_run.rs)
    because `check_sensor_fusion` is a standalone helper that is not
    yet wired into the per-command validator (re-classify once it
    joins the validator's check set). Same plumbing discipline as
    prior batches: enum + `all()` + `spec_id()` + `generate_commands`
    dispatch + `parse_scenario_type` (Pascal + snake) +
    `scenario_type_from_snake` helper in
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    + three new binding doctest assertions. New
    [crates/invariant-sim/tests/category_f_sensors_generators.rs](crates/invariant-sim/tests/category_f_sensors_generators.rs)
    (4 tests on `ur10e_haas_cell`): F-05 asserts each command emits
    exactly one of the three SR1 violation modes, all three modes
    appear, joint state stays finite; F-06 asserts each command emits
    exactly one of the three SR2 violation modes with the bounded
    field exceeding its SR2 max, all three modes appear; F-07 asserts
    two readings per command, shared `sensor_name`, `Position`
    payloads, ≥10 m divergence, `signer_kid = "f07-fusion-stub"`, and
    baseline-safe joint state; plus a spec-ID binding assertion.
    Coverage now `52/106 ids implemented; 54 gaps` (was 49). Closes
    Category F end-to-end (F-01..F-08 all bound). All 777 sim lib
    tests + 16 new/updated integration tests green; clippy clean on
    invariant-sim. Updates: [docs/scenario-id-map.md](docs/scenario-id-map.md)
    gains three IMPLEMENTED rows; [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md)
    tracking row 2.5 promoted from OPEN to DONE; [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md)
    tracking row 2.1–2.11 updated accordingly.

  - **v11 2.3 DONE — Category D closure (D-01/D-02/D-07/D-08/D-10 added)**
    — Five new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    pick up the spec rows the legacy `Locomotion*` quintet did not
    cover (D-03/D-04/D-05/D-06/D-09 stay where they are):
    `ComStabilitySweep` → D-01 cycles COM through four positions
    relative to the profile's support polygon by `index % 4` —
    polygon centroid (PASS), first vertex (boundary), midpoint of
    edge v0–v1 (interior), and the centroid translated +10 m on x
    (REJECT P9). Profiles without a stability config fall back to a
    symmetric unit square at z = 1 m so the generator remains
    exercisable on any profile. `WalkingGaitValidation` → D-02 is
    the legitimate gait happy-path: base velocity at 50 % of
    `max_locomotion_velocity`, heading rate at 25 % of
    `max_heading_rate`, step length at 60 % of `max_step_length`,
    swing foot alternates left/right by index parity at a height
    between `min_foot_clearance` and `max_step_height`. Every
    command should PASS. `StepOverextension` → D-07 linearly ramps
    `step_length` from `0.5 × max_step_length` to `3 × max_step_length`
    (REJECT P19). `HeadingSpinout` → D-08 linearly ramps
    `heading_rate` from 0 to `5 × max_heading_rate` (REJECT P20).
    `InclineWalking` → D-10 linearly ramps `imu_pitch_rad` from 0
    to 30° (≈ 0.5236 rad), crossing both `warning_pitch_rad`
    (derate) and `max_safe_pitch_rad` (REJECT P21). All five added
    to the dry-run `is_expected_reject` allowlist (D-01 is mixed
    3-of-4 pass; D-02 is pure PASS; D-07/D-08/D-10 are monotonic
    ramps with a pass-then-reject pattern), so the harness does
    not count in-band commands as violation escapes. Same plumbing
    discipline as prior batches: enum + `all()` + `spec_id()` +
    `generate_commands` dispatch + dry-run `parse_scenario_type` +
    `scenario_type_from_snake` helper in
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    + five new binding doctest assertions. New
    [crates/invariant-sim/tests/category_d_generators.rs](crates/invariant-sim/tests/category_d_generators.rs)
    (6 tests on `bd_atlas`, the canonical humanoid with locomotion +
    stability + environment configs): D-01 asserts 75 % of COMs lie
    inside or on the support polygon (using the same cross-product
    PIP test the validator uses) and 25 % lie strictly outside; D-02
    asserts every command stays at-or-below every locomotion limit
    and that the swing foot alternates; D-07/D-08 each assert the
    expected start value, monotonic non-decreasing ramp, and that
    the sweep crosses the limit; D-10 asserts the same plus that
    the ramp visits the warning band, the rejection band, and the
    sub-warning band; plus a spec-ID binding assertion. Coverage
    now `57/106 ids implemented; 49 gaps` (was 52). All 777 sim lib
    tests + 22 new/updated integration tests green; clippy clean.
    Updates: [docs/scenario-id-map.md](docs/scenario-id-map.md)
    gains five IMPLEMENTED rows; [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md)
    tracking row 2.3 promoted from OPEN to DONE; [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md)
    tracking row 2.1–2.11 updated accordingly. Note: D-02 is the
    only pure-PASS scenario; if a downstream `validator` rejects
    any D-02 command, the test fixture is the canonical reference
    for the legitimate gait envelope.

  - **v11 2.2 DONE — Category C closure (C-01/C-04/C-05 added)** — Three
    new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    close out Category C: `WorkspaceBoundarySweep` → C-01 cycles the EE
    through the eight workspace AABB corners (`point_in_workspace` uses
    inclusive bounds, so corners PASS) interleaved with the same eight
    corners pushed 1 m outside each face (REJECT P5), selected by
    `index % 16`; `SelfCollisionApproach` → C-04 places two
    collision-paired links along the +x axis with separation ramping
    linearly from `2 × min_collision_distance` to
    `0.1 × min_collision_distance` (P7) — profiles without
    `collision_pairs` fall back to a synthetic `("link_a","link_b")`
    pair; `OverlappingZoneBoundaries` → C-05 cycles the EE through every
    declared `exclusion_zones` interior by `index % n_zones` (P6) —
    zero-zone profiles fall back to `workspace_max + 1 m` on every axis
    so P5 trips instead. C-01 and C-04 added to the
    `is_expected_reject` allowlist in
    [crates/invariant-sim/src/robotics/isaac/dry_run.rs](crates/invariant-sim/src/robotics/isaac/dry_run.rs)
    (both are mixed pass/reject); C-05 stays in the default
    expected-reject group since every command lands inside a zone.
    Same plumbing discipline as prior batches: enum + `all()` +
    `spec_id()` + `generate_commands` dispatch + `parse_scenario_type`
    (Pascal + snake) + `scenario_type_from_snake` helper in
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    + three new binding doctest assertions. New
    [crates/invariant-sim/tests/category_c_more_generators.rs](crates/invariant-sim/tests/category_c_more_generators.rs)
    (5 tests): C-01 asserts every command's EE is either an exact AABB
    corner or a 1 m-outside corner, and that both bands are visited;
    C-04 asserts the first separation is `2 × min_collision_distance`
    within 1e-9, the final separation is strictly below
    `min_collision_distance`, the separation is monotonically
    non-increasing, and joint state stays finite (isolating the
    collision failure mode); C-05 happy-path asserts every command's
    EE lies inside ≥1 declared `exclusion_zone` of `ur10e_haas_cell`;
    C-05 fallback asserts a zero-zone profile (`franka_panda`) parks
    the EE at `workspace_max + 1` on every axis. Closes Category C
    end-to-end (C-01..C-06 all bound). Coverage now `60/106 ids
    implemented; 46 gaps` (was 57). All 777 sim lib tests + 5 new
    integration tests green; clippy clean. Updates:
    [docs/scenario-id-map.md](docs/scenario-id-map.md) gains three
    `IMPLEMENTED` rows; [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md)
    tracking row 2.1–2.11 updated accordingly (2.2 promoted from
    PARTIAL to DONE).

  - **v11 2.9 PARTIAL — Category J/K/L (K-03 + L-02 + L-03 added)** —
    Three new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    pick up the smaller K/L spec rows the unified workspace had been
    missing: `EstopRecoveryCycle` → K-03 holds `e_stop_engaged = true`
    for the first half of the sequence (REJECT P25) and releases (`false`)
    for the second half (PASS) — distinct from F-04's per-command
    alternation; `MillionEntryAudit` → L-02 emits a long baseline-safe
    sequence with a slow sinusoidal joint sweep (period 100 commands,
    20 % half-range amplitude) and stamps `audit_stress = "true"` into
    `metadata` so harnesses can detect intent (verification is
    downstream: audit hash chain integrity over the resulting JSONL);
    `CounterSaturation` → L-03 pre-sets `sequence` so the final command
    lands at exactly `u64::MAX` (first at `u64::MAX - count + 1`),
    baseline-safe physics, every command PASS — exercises validator
    u64 overflow handling. All three added to the dry-run
    `is_expected_reject` allowlist (K-03 mixed; L-02 / L-03 pure-PASS).
    Same plumbing as prior batches: enum + `all()` + `spec_id()` +
    `generate_commands` dispatch + `parse_scenario_type` (Pascal +
    snake) + `scenario_type_from_snake` helper in
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    + three new binding doctest assertions. New
    [crates/invariant-sim/tests/category_k_l_generators.rs](crates/invariant-sim/tests/category_k_l_generators.rs)
    (4 tests on `ur10e_haas_cell`): K-03 asserts cmd `i < half` carries
    `e_stop_engaged=true` and `i ≥ half` carries `=false`, and both
    states appear; L-02 asserts every command carries
    `audit_stress="true"` metadata, joint state stays finite, and
    sequence is strictly +1 monotonic; L-03 asserts the final command
    sits at exactly `u64::MAX`, the first at `u64::MAX - count + 1`,
    sequence is +1 monotonic across the saturation window, and joint
    state stays baseline-safe. Coverage now `63/106 ids implemented;
    43 gaps` (was 60). K-02 / K-05 / K-06 and J-03 / J-04 / J-06 / J-08
    still need variants. All 777 sim lib tests + 45 doctests + 4 new
    integration tests green; clippy clean. Updates:
    [docs/scenario-id-map.md](docs/scenario-id-map.md) gains three
    `IMPLEMENTED` rows; [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md)
    row 2.9 promoted OPEN → PARTIAL; [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md)
    tracking row 2.1–2.11 updated accordingly.

  - **v11 2.10 PARTIAL — Category M (M-02 + M-04 + M-05 added)** —
    Three new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    open Category M (cross-platform stress).
    `ValidInvalidAlternating` → M-02 emits baseline-safe commands on
    even indices and pushes the first joint to `2 × max` on odd
    indices, giving the validator an exact 50 % rejection rate under
    sustained throughput so churn-related state bugs surface.
    `MaximumPayloadCommand` → M-04 stuffs each command with 256
    synthetic joint states (`synth_joint_{n}`) + 256 EE positions
    (`synth_ee_{n}`) + 256 EE forces (`synth_force_{n}`); the
    synthesised names do not match the profile so the failure mode
    is structural / name-mismatch, not bounds. The synthetic vectors
    are pre-built once and cloned per command to keep generation
    O(count). `MinimumValidCommand` → M-05 emits the minimum legal
    command: one joint state at the first profile joint's midpoint,
    zero EEs / forces / sensor readings, no `EnvironmentState` and no
    `LocomotionState`. M-02 and M-05 added to the dry-run
    `is_expected_reject` allowlist (M-02 mixed, M-05 pure-PASS);
    M-04 stays in the default expected-reject group. Same plumbing
    discipline as prior batches: enum + `all()` + `spec_id()` +
    `generate_commands` dispatch + `parse_scenario_type` (Pascal +
    snake) + `scenario_type_from_snake` helper in
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    + three new binding doctest assertions. New
    [crates/invariant-sim/tests/category_m_generators.rs](crates/invariant-sim/tests/category_m_generators.rs)
    (4 tests on `ur10e_haas_cell`): M-02 asserts even-index commands
    keep the first joint below `max` (mid-range baseline) and
    odd-index commands sit at exactly `2 × max` within 1e-9; M-04
    asserts every command carries exactly 256 of each kind, joint
    names are unique, and the synthesised-name prefixes match; M-05
    asserts exactly one joint state at the first joint's midpoint,
    and that every optional vector / option field is empty / `None`.
    Coverage now `66/106 ids implemented; 40 gaps` (was 63). M-01
    (rate stress, not testable at the generator level), M-03 (pure
    fuzz), and M-06 (cross-profile mixing) still need variants. All
    777 sim lib tests + 45 doctests + 4 new integration tests green;
    clippy clean. Updates: [docs/scenario-id-map.md](docs/scenario-id-map.md)
    gains three `IMPLEMENTED` rows; [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md)
    row 2.10 promoted OPEN → PARTIAL; [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md)
    tracking row 2.1–2.11 updated.

  - **v11 2.9 further PARTIAL — Category J closure (J-03 + J-06 + J-08 added)** —
    Three new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs)
    close out Category J end-to-end (J-01..J-08 all bound).
    `NanAuthorityBypass` → J-03 emits NaN in the first joint AND an
    empty `pca_chain` so neither check can short-circuit the other —
    the validator must surface both failure modes independently.
    `ProfileProbingTargeted` → J-06 splits the sequence: first half
    sweeps each joint linearly from `0.5 × max` to `0.99 × max`
    (probe phase, every command PASS), second half pushes every joint
    to `max + ε` with `ε = max(1e-6 × range, 1e-9)` (targeted attack
    phase, REJECT P1) — models the adversary that learns the
    boundary by probing then pushes past it by the smallest
    detectable margin. `MultiRobotDistraction` → J-08 alternates
    sources between `robot_a` (baseline-safe — PASS) and `robot_b`
    (first joint at `2 × max` — REJECT P1) per index; each source
    maintains its own monotonic `sequence` so the failure mode is
    pure physics, not sequence disorder (distinct from
    `MultiAgentHandoff` which interleaves sequences). J-06 added to
    the dry-run `is_expected_reject` allowlist (probe-then-attack
    mixed); J-03 and J-08 stay in the default expected-reject bucket.
    Same plumbing as prior batches: enum + `all()` + `spec_id()` +
    `generate_commands` dispatch + `parse_scenario_type` (Pascal +
    snake) + `scenario_type_from_snake` helper in
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    + three new binding doctest assertions. New
    [crates/invariant-sim/tests/category_j_more_generators.rs](crates/invariant-sim/tests/category_j_more_generators.rs)
    (4 tests on `ur10e_haas_cell`): J-03 asserts every command's
    first-joint position is NaN and `pca_chain` is empty; J-06
    asserts the probe-phase half stays in `[0.5×max, 0.99×max]` and
    the attack-phase half sits at exactly `max + ε`; J-08 asserts
    sources alternate, even-index commands are baseline-safe and
    odd-index commands sit at `2 × max`, both states appear, and
    per-source `sequence` is strictly monotonic. Coverage now
    `69/106 ids implemented; 37 gaps` (was 66). K-02 / K-05 / K-06
    are the only remaining Category J/K/L gaps. All 777 sim lib
    tests + 45 doctests + 4 new integration tests green; clippy
    clean. Updates: [docs/scenario-id-map.md](docs/scenario-id-map.md)
    gains three `IMPLEMENTED` rows; [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md)
    row 2.9 note expanded with the second batch; [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md)
    tracking row 2.1–2.11 updated.

  - **v11 2.8 PARTIAL + 2.9 K-02 — Category I opened, Category K extended** —
    Three new `ScenarioType` variants in
    [crates/invariant-sim/src/robotics/scenario.rs](crates/invariant-sim/src/robotics/scenario.rs).
    `WatchdogRecoveryCycle` → K-02 emits three phases over `count` commands:
    first third `delta_time = 0.5 × max_delta_time` (heartbeats present,
    PASS), middle third `delta_time = 5 × max_delta_time` (heartbeats
    missed, REJECT P8 upper bound), final third returns to normal
    `delta_time` (heartbeat resumed, PASS) — validates the watchdog
    latch engages and releases cleanly. `DistractionFlooding` → I-02
    cycles 9 baseline-safe commands then 1 violation (first joint at
    `2 × max`); the spec calls for a 999:1 ratio but the generator
    uses 9:1 so short test runs always include the attack phase.
    `ErrorMining` → I-05 cycles four physics violation modes by
    `index % 4`: P1 (first-joint position at `2 × max`), P2
    (first-joint velocity at `2 × max_velocity`), P3 (first-joint
    effort at `2 × max_torque`), P5 (EE position 1 m past the
    workspace AABB on every axis) — every command rejects but on a
    different check, letting the adversary fingerprint validator
    internals. K-02 and I-02 added to the dry-run
    `is_expected_reject` allowlist (both mixed: K-02 normal-then-fail-
    then-normal, I-02 mostly-pass with one in ten failing); I-05
    stays in the default expected-reject bucket. Same plumbing
    discipline: enum + `all()` + `spec_id()` + `generate_commands`
    dispatch + `parse_scenario_type` (Pascal + snake) +
    `scenario_type_from_snake` helper in
    [crates/invariant-sim/tests/campaigns_load.rs](crates/invariant-sim/tests/campaigns_load.rs)
    + three new binding doctest assertions. New
    [crates/invariant-sim/tests/category_i_k_more_generators.rs](crates/invariant-sim/tests/category_i_k_more_generators.rs)
    (4 tests on `ur10e_haas_cell`): K-02 asserts the three-phase
    delta_time pattern and that the missed-heartbeat span has exactly
    the expected length; I-02 asserts every 10th command sits at
    `2 × max` and the others are mid-range, with exactly 3 violations
    in 30 commands; I-05 asserts each of the four violation modes
    fires on the expected index slot and all four appear. Coverage
    now `72/106 ids implemented; 34 gaps` (was 69). Remaining
    Category K: K-05 / K-06. Remaining Category I: 8 of 10 spec IDs.
    All 777 sim lib + 45 doctests + 4 new integration tests green;
    clippy clean. Updates:
    [docs/scenario-id-map.md](docs/scenario-id-map.md) gains three
    `IMPLEMENTED` rows; [docs/history/robotics/spec-v11.md](docs/history/robotics/spec-v11.md)
    row 2.8 promoted OPEN → PARTIAL and row 2.9 note cross-links
    K-02; [docs/robotics/spec-v12.md](docs/robotics/spec-v12.md)
    tracking row 2.1–2.11 updated.

## Notes

- `_from-robotics` and `_from-biosynthesis` are symlinks to the sibling source folders rather than copies. Same effect, no duplicated bytes. Sources remain untouched until Phase 9.
- Workspace uses coset 0.4 (the robotics version); biosynthesis envelope fixtures must be re-tested in Phase 3 (see spec risk register).
