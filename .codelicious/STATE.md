# Invariant — Build State

## Current Status
Phase 1, Step 5 complete and reviewed. **5 P1, 12 P2, 14 P3 findings** identified across validator.rs, actuator.rs, and cross-module integration. Key P1 issues: signer_kid not in actuation signature, empty required_ops bypasses authority, no size cap on PCA chain input, non-canonical verdict signature, unverified origin extraction (carry-forward). 150 tests passing, clippy clean. Ready for Step 5a (fix P1 findings).

## Completed Tasks

### Phase 1: Core
- [x] **Step 1 — Workspace init**: Cargo workspace, 4 crates (`invariant-core`, `invariant-cli`, `invariant-sim`, `invariant-eval`), all module stubs, 4 robot profile JSON files.
- [x] **Step 2 — Core types**: All model structs with serde + validation. Newtypes for safety. Fixed all 6 P1 and all 15 P2 findings from Step 2 review.
- [x] **Step 3 — Physics checks (10)**: All 10 pure functions (P1-P10) implemented in `physics/` with `run_all_checks()` orchestrator and 64 passing tests.
- [x] **Step 3a — Fix P1 review findings**: NaN/Inf guards in all 10 physics checks, clippy fix, unbounded collection caps, reqwest removed, R2-01..R2-07 silent-skip fixes. 20 new tests (84 total).
- [x] **Step 4 — Authority validation**: Ed25519 COSE_Sign1 chain verification (crypto.rs), wildcard operation matching + subset checks (operations.rs), full PCA chain verification with A1/A2/A3 invariants + temporal constraints (chain.rs). AuthorityError enum with typed variants. 38 new tests (122 total).
- [x] **Step 4a — Fix P1 review findings**: Use decoded COSE payload (P1-01), verify_strict (P1-02), private AuthorityChain (P1-03), Operation structural validation (P1-04), sign_pca returns Result (P1-05), wildcard prefix fix (P1-06). Also ChainTooLong variant (P2-04), pub(crate) decode_pca_payload (P2-05), PartialEq on AuthorityError (P2-08). 16 new tests (138 total).
- [x] **Step 5 — Validator orchestrator**: Full validation pipeline in `validator.rs` (ValidatorConfig, validate(), signed verdicts with 11 checks) and signed actuation command generator in `actuator.rs` (ActuationPayload signing, M1 invariant). Fail-closed, deterministic, SHA-256 hashing. 12 new tests (150 total).

---

## Review Findings — Step 5 Quality Review (2026-03-23)

Reviewed: `validator.rs`, `actuator.rs`, cross-module integration with all models (verdict.rs, actuation.rs, command.rs, authority.rs, audit.rs, trace.rs), authority modules (chain.rs, operations.rs, crypto.rs), physics modules (10 checks + orchestrator), `lib.rs`, and spec compliance (sections 2.3, 3.3, 3.4).

Build: PASS. Tests: 150/150 PASS. Clippy: PASS.

### New P1 — Blocking / Security

| ID | File:Line | Issue |
|----|-----------|-------|
| S5-P1-01 | `actuator.rs:18-23` | **`signer_kid` not covered by `actuation_signature`.** `ActuationPayload` omits `signer_kid`, so the signed payload does not bind the signature to a key identity. An attacker who intercepts a `SignedActuationCommand` can swap `signer_kid` to point to a different key. The motor controller cannot verify which key signed the payload from the payload alone. Fix: add `signer_kid` to `ActuationPayload`. |
| S5-P1-02 | `validator.rs:200-212`, `276-281` | **No size cap on `pca_chain_b64` before decode — memory DoS.** An attacker can supply a megabyte-scale base64 string. `STANDARD.decode` and `serde_json::from_slice` allocate unbounded memory before the `MAX_HOPS=16` guard runs. Fix: add `const MAX_PCA_CHAIN_B64_BYTES: usize = 65_536` and reject before decode. |
| S5-P1-03 | `validator.rs:run_authority`, `chain.rs:126` | **Empty `required_ops` bypasses all operation authorization.** A command with `required_ops: []` passes `check_required_ops` via vacuous truth and passes authority, producing an approved command with no operation constraints. Fix: reject empty `required_ops` in `run_authority` with `passed: false`. |
| S5-P1-04 | `validator.rs:255-268`, `296-308` | **Verdict signed over non-canonical `operations_required` ordering.** `operations_required` is built from caller-supplied `Vec<Operation>` order. Two semantically identical commands with different `required_ops` ordering produce different `verdict_signature` values. Signature verification becomes order-dependent. Fix: sort `operations_required` and `operations_granted` before building `AuthoritySummary`. |
| S5-P1-05 | `chain.rs:47-48` | **Origin extracted from unverified hop 0 before signature check (carry-forward S4a-P1-01).** `decode_pca_payload(&hops[0].raw, 0)` is called before the loop verifies hop 0's signature. Untrusted data shapes the A1 provenance baseline. Fix: move origin extraction to after hop 0 signature verification inside the loop. |

### New P2 — Important / Correctness

| ID | File:Line | Issue |
|----|-----------|-------|
| S5-P2-01 | `validator.rs:129-134` | **`command_hash` non-deterministic across processes.** `Command.metadata` is `HashMap<String, String>` — iteration order is non-deterministic. Two validator instances hashing the same logical command may produce different hashes. Fix: use `BTreeMap` for metadata or sort keys before hashing. |
| S5-P2-02 | `validator.rs:75-80` | **`profile_hash` non-deterministic across processes.** `SafeStopProfile.target_joint_positions` is `HashMap<String, f64>`. Same problem as S5-P2-01. Fix: use `BTreeMap` or sort keys. |
| S5-P2-03 | `validator.rs:128-134` | **`Command` has no `Validate` call before hashing/physics (carry-forward S4a-P2-10).** NaN fields, unbounded collections, negative `delta_time` reach physics checks unchecked. Unbounded `joint_states` / `metadata` / `required_ops` enable CPU/memory DoS. Fix: implement `Validate` for `Command` and call it at pipeline start. |
| S5-P2-04 | `validator.rs:68-88` | **`signer_kid` accepts empty string.** Empty `signer_kid` propagates into `SignedVerdict` and `SignedActuationCommand`, defeating L3 (authenticity) invariant and motor controller key lookup. Fix: validate non-empty in `ValidatorConfig::new`. |
| S5-P2-05 | `validator.rs:122-189` | **`command.timestamp` never validated against `now`.** Replay attacks: a command timestamped 10 seconds ago may reference a position that was safe then but not now. No staleness window enforced. Fix: reject `|now - command.timestamp| > max_command_age`. |
| S5-P2-06 | `actuator.rs:31-63` | **NaN/Infinity in `JointState` reaches signing without guard.** `build_signed_actuation_command` is `pub` — a direct caller (bypassing `validate()`) can pass NaN joints, causing `serde_json::to_vec` to error. Fix: add finite-check guard at function entry. |
| S5-P2-07 | `actuator.rs:39-44`, `validator.rs:173-183` | **Actuation `timestamp` uses validator `now`, not `command.timestamp`.** Motor controller cannot bind the actuation to the original command time. Replay defense relies on sequence number alone. Fix: include both `command_timestamp` and `validated_at` in `ActuationPayload`, or document design choice. |
| S5-P2-08 | `verdict.rs:37-42` | **`#[serde(flatten)]` on `SignedVerdict` — key collision risk.** If `Verdict` ever gains a field named `verdict_signature` or `signer_kid`, serde silently drops one value. Also creates ambiguity for audit `entry_hash` scope. Fix: nest `Verdict` under explicit key or document constraint. |
| S5-P2-09 | `validator.rs:147` | **No assertion that `run_all_checks` returns exactly 10 results.** If a physics check is added/removed, the count silently changes. A missing check could allow a malformed command. Fix: add `debug_assert_eq!(physics_checks.len(), 10)` and a constant `PHYSICS_CHECK_COUNT`. |
| S5-P2-10 | `chain.rs:126`, `operations.rs:60-66` | **`required_ops` length unbounded — O(n*m) CPU DoS (carry-forward S4a-P2-05).** An attacker can supply thousands of `required_ops`. `check_required_ops` and `ops_are_subset` have quadratic complexity. Fix: cap `required_ops.len()` at 256. |
| S5-P2-11 | `physics/stability.rs:45-52` | **Degenerate polygon (< 3 vertices) silently passes stability check (carry-forward).** A 2-vertex "polygon" makes P9 a no-op. Fix: reject degenerate polygons in profile validation or return `passed: false`. |
| S5-P2-12 | `physics/acceleration.rs:63-69` | **Docstring contradicts implementation on missing previous joint state (carry-forward).** Doc says "skipped" but code flags as violation. Fix: align doc with implementation (violation is the safer choice). |

### New P3 — Quality / Future-Proofing

| ID | File:Line | Issue |
|----|-----------|-------|
| S5-P3-01 | `actuator.rs:13` | **Actuator imports `ValidatorError` — inverted dependency.** Leaf module depends on orchestrator solely for `Serialization` variant. Fix: move error to `models/error.rs`. |
| S5-P3-02 | `validator.rs:40-47` | **Three separate error hierarchies** (`ValidatorError`, `AuthorityError`, `ValidationError`). No unified error type for downstream consumers. Fix: consolidate or re-export from `lib.rs`. |
| S5-P3-03 | `lib.rs:1` | **`#![allow(dead_code)]` blanket suppression (carry-forward S4a-P3-05).** Hides dead safety code. Fix: remove and apply targeted allows. |
| S5-P3-04 | `validator.rs:445+` | **Tests use `Utc::now()` instead of fixed timestamp.** Non-deterministic under clock skew. Fix: use fixed `DateTime` constants in all tests. |
| S5-P3-05 | `validator.rs:154-155`, `289-309` | **Rejected verdict leaks `operations_granted`.** Info disclosure: attacker learns which ops their chain grants. Fix: omit granted ops on rejection. |
| S5-P3-06 | `validator.rs:200-212` | **Internal decode error details exposed in verdict `details`.** Aids attackers in crafting payloads. Fix: use generic message externally, log detail internally. |
| S5-P3-07 | `validator.rs:315-664` | **No test for empty `joint_states`.** Empty list passes all joint-based physics checks trivially, producing approved command with no joints. Fix: add test. |
| S5-P3-08 | `validator.rs:315-664` | **No test for expired PCA at validator pipeline level.** Only tested at authority layer. Fix: add validator-level test. |
| S5-P3-09 | `actuator.rs:73-105` | **No negative test for signature tampering.** No test mutates fields and asserts verification failure. Fix: add tampering test. |
| S5-P3-10 | `actuator.rs:52`, `validator.rs:261` | **`use ed25519_dalek::Signer` inside function body.** Inconsistent with module-level imports. Fix: move to top. |
| S5-P3-11 | `validator.rs:601` | **Verdict verification test uses `verify()` not `verify_strict()`.** Inconsistent with `crypto.rs` security posture. Fix: use `verify_strict()`. |
| S5-P3-12 | `validator.rs:276-281` | **`decode_pca_chain` allocates unbounded `Vec<SignedPca>` before `MAX_HOPS` cap.** Pre-auth memory amplification. Fix: check `hops.len()` immediately after deserialize. |
| S5-P3-13 | `validator.rs:107-110` | **`ValidationResult` has no audit entry slot.** API must be extended for Step 6. Fix: decide pattern now to avoid breaking changes. |
| S5-P3-14 | `verdict.rs:28-34` | **`AuthoritySummary` uses `Vec<String>` instead of `Vec<Operation>` (carry-forward S4a-P3-13).** Newtype lost, ordering not guaranteed. Fix: change to `Vec<Operation>`. |

---

## Review Findings — Step 4a Post-Fix Quality Review (2026-03-23)

Reviewed: all authority modules (crypto.rs, operations.rs, chain.rs, tests.rs, mod.rs), all models (authority.rs, profile.rs, command.rs, verdict.rs, actuation.rs, audit.rs, trace.rs, error.rs), all physics modules (10 checks + orchestrator + tests), workspace config (Cargo.toml), stub crates.

Build: PASS. Tests: 138/138 PASS. Clippy: PASS.

**Step 4 P1 fix verification:** All 6 P1 fixes (P1-01 through P1-06) are correctly applied. No bypass vectors found.

### New P1 — Blocking / Security

| ID | File:Line | Issue |
|----|-----------|-------|
| S4a-P1-01 | `chain.rs:47-48` | **Origin extracted from unverified hop 0 before signature check.** `decode_pca_payload(&hops[0].raw, 0)` is called before the loop verifies hop 0's signature. The `origin` variable is set from an unverified payload. While the loop later re-verifies hop 0's signature and re-decodes its payload for the A1 check (which trivially passes since `origin` came from the same hop), this means: (a) error messages from a malformed-but-unsigned hop 0 leak payload structure before authentication, and (b) there is no enforcement that hop 0's `p_0` matches a known/trusted root identity — any holder of a trusted key can self-issue a chain with arbitrary `p_0`. Fix: move origin extraction to after hop 0 verification completes, or document that root principal validation is the caller's responsibility. |
| S4a-P1-02 | `crypto.rs:87` | **Unbounded `kid` length in COSE protected header causes pre-auth memory DoS.** `extract_kid` clones `key_id` bytes with no length cap before signature verification. An attacker-supplied COSE blob with a multi-megabyte `kid` causes unbounded allocation on every hop. Carry-forward from S4-P3-10, elevated to P1 as pre-auth DoS. Fix: add `if kid_bytes.len() > 256 { return Err(...) }`. |

### New P2 — Important / Correctness

| ID | File:Line | Issue |
|----|-----------|-------|
| S4a-P2-01 | `chain.rs:54-66`, `authority.rs:119` | **COSE header `kid` not cross-checked against payload `Pca.kid`.** After verification, the `kid` from the COSE protected header (used for key lookup) is not compared to `claim.kid` from the decoded payload. An issuer can sign with header `kid="key-A"` but include `kid="key-B"` in the JSON payload, poisoning audit trails. Fix: assert `claim.kid == kid` after decode. |
| S4a-P2-02 | `chain.rs:78-91` | **A2 error reporting uses inline traversal with `unwrap_or_default("")`.** Redundant re-traversal for error reporting; empty fallback string misleading in audit logs. Should use `first_uncovered_op`. Carry-forward S4-P2-10. |
| S4a-P2-03 | `authority.rs:115,119` | **`Pca.p_0` and `Pca.kid` not validated as non-empty.** Empty values make A1 trivially pass and key lookup ambiguous. Carry-forward S4-P2-01/02. |
| S4a-P2-04 | `authority.rs:120-123` | **No `nbf < exp` consistency check on `Pca`.** Inverted/zero-width windows accepted. Carry-forward S4-P2-03. |
| S4a-P2-05 | `authority.rs:117` | **`Pca.ops` unbounded `BTreeSet`.** No max size cap; O(n^2) monotonicity check enables CPU exhaustion via large ops sets. Carry-forward R2-10. |
| S4a-P2-06 | `profile.rs:182-216` | **NaN/Inf not rejected in `JointDefinition` f64 fields.** `NaN >= NaN` is false, bypassing inverted-limits check. `NaN <= 0.0` is false, bypassing positivity checks. NaN profile values silently disable P1/P2/P3 physics checks. Carry-forward S3a-P1-03. |
| S4a-P2-07 | `profile.rs:146-151` | **NaN `global_velocity_scale` bypasses range check.** Both `NaN <= 0.0` and `NaN > 1.0` are false. `max_delta_time` and `min_collision_distance` have no validation. Carry-forward S3a-P1-04. |
| S4a-P2-08 | `profile.rs:247-276` | **`ExclusionZone`/`ProximityZone` geometry not validated.** NaN radius/bounds silently bypass P6/P10. Carry-forward S3a-P1-02. |
| S4a-P2-09 | `profile.rs:226-239` | **`WorkspaceBounds::validate()` does not check NaN/Inf.** NaN bounds pass validation; P5 silently passes all positions. Carry-forward S3a-P2-01. |
| S4a-P2-10 | `command.rs:7-48` | **`Command` has no `Validate` impl.** Primary ingress type has unbounded collections, unchecked `delta_time`, uncapped `metadata`. Carry-forward S3a-P1-05. |
| S4a-P2-11 | `exclusion_zones.rs:92`, `proximity.rs:158`, `self_collision.rs:89` | **Squared-distance overflow for large-but-finite coordinates.** Coordinates near `f64::MAX/2` cause `dx*dx` to overflow to `+Inf`, treating points as outside zones. Bypasses P6/P7/P10. Carry-forward S3a-P1-06/07. |
| S4a-P2-12 | `tests.rs` (authority) | **No test for payload-swap attack vector (original P1-01 scenario).** Tampered-raw test only flips bytes; no test constructs a semantically different payload. Also: no test distinguishes `verify_strict` from `verify`; `extract_kid` non-UTF-8 path untested; `decode_pca_payload` detached-payload path untested. Carry-forward S4-P3-01/06. |
| S4a-P2-13 | `tests.rs` (physics) | **`run_all_checks` integration tests never trigger P4 or P10 failures.** `previous_joints=None` causes P4 to pass trivially; no proximity zones configured for P10. Carry-forward R3-03/S3a-P3-04. |

### New P3 — Quality / Future-Proofing

| ID | File:Line | Issue |
|----|-----------|-------|
| S4a-P3-01 | `crypto.rs:59-64` | Signature error type lost — both parse and verify errors collapse to `String`. Carry-forward S4-P2-09. |
| S4a-P3-02 | `error.rs:6,78` | Duplicate error messages for `EmptyChain` / `EmptyAuthorityChain`. Carry-forward S4-P3-08. |
| S4a-P3-03 | `error.rs:15-19,28-30` | `p_0` and `kid` leaked verbatim in error messages — enumeration risk if exposed externally. Carry-forward S4-P3-09. |
| S4a-P3-04 | `operations.rs:43-47` | O(n*m) complexity undocumented, no size bound enforced on ops sets. Carry-forward S4-P3-11. |
| S4a-P3-05 | `lib.rs:1` | Crate-wide `#![allow(dead_code)]` masks unused variants and dead code. Carry-forward R3-11. |
| S4a-P3-06 | `profile.rs:17-21` | `BoundsType` enum is dead code, never referenced. Carry-forward S3a-P3-05. |
| S4a-P3-07 | `profile.rs:298-308` | `StabilityConfig` has no `Validate` impl. `com_height_estimate` and polygon vertices unchecked. Carry-forward S3a-P2-02. |
| S4a-P3-08 | `profile.rs:310-333` | `SafeStopProfile` has no `Validate` impl. `max_deceleration` can be NaN/zero/negative. Carry-forward S3a-P2-03. |
| S4a-P3-09 | `acceleration.rs:14-16` | Stale doc comment says missing previous joint is "skipped" but implementation flags it as violation. Carry-forward S3a-P2-13. |
| S4a-P3-10 | `exclusion_zones.rs:89-98`, `proximity.rs:156-163` | `point_in_sphere` copy-pasted in two modules. Carry-forward S3a-P3-03/R3-05. |
| S4a-P3-11 | `joint_limits.rs:19` (and 4 others) | O(n*m) linear-scan joint lookup in all 5 per-joint checks. Carry-forward S3a-P3-10. |
| S4a-P3-12 | `delta_time.rs:17,23` | Misleading error messages: "not finite" for zero delta_time; "exceeds" for NaN max_delta_time. Carry-forward S3a-P3-11. |
| S4a-P3-13 | `verdict.rs:29-33` | `AuthoritySummary` uses `Vec<String>` instead of `Vec<Operation>` — newtype lost. Carry-forward S3a-P3-06. |
| S4a-P3-14 | `tests.rs` (physics) | Missing tests: `NEG_INFINITY` delta_time, `max_delta_time=0.0`, self-referential `CollisionPair`, P4 unknown joint, P9 NaN in `com[1]`/`com[2]` individually. Carry-forward S3a-P3-12. |

---

## Review Findings — Step 4 Quality Review (2026-03-23)

Reviewed: all authority modules (crypto.rs, operations.rs, chain.rs, tests.rs), authority model types, error types, workspace config, test suite (122 tests), clippy, build.

Build: PASS. Tests: 122/122 PASS. Clippy: PASS.

### New P1 — Blocking / Security

| ID | File:Line | Issue |
|----|-----------|-------|
| S4-P1-01 | `chain.rs:44-110` | **Chain validation uses unverified `signed.claim` instead of decoded COSE payload.** `verify_signed_pca` verifies `signed.raw`, but every subsequent decision (A1 provenance at :59, A2 monotonicity at :69, temporal at :87/:95, key lookup at :50, final_ops construction at :107-110) reads from `signed.claim` — a serde-deserialized field that an attacker can forge independently of `raw`. The function `decode_pca_payload` exists in crypto.rs:72 but is never called by chain.rs. An attacker who supplies a `SignedPca` with valid `raw` from one PCA but forged `claim` from another bypasses all three invariants simultaneously. This is the most critical finding. |
| S4-P1-02 | `crypto.rs:60` | **`verify` used instead of `verify_strict`.** `ed25519-dalek 2.x` `verify()` accepts small-order and non-canonical points/signatures. `verify_strict()` rejects them. In a safety-critical firewall, signature malleability must be prevented. One-line fix: replace `verifying_key.verify(data, &sig)` with `verifying_key.verify_strict(data, &sig)`. |
| S4-P1-03 | `authority.rs:120-128` | **`AuthorityChain` has all-pub fields and derives `Deserialize`.** Any caller can struct-literal or deserialize an `AuthorityChain` with arbitrary `hops`, `origin_principal`, `final_ops` — bypassing `verify_chain` entirely. The type should have private fields with a constructor that only `verify_chain` can call. |
| S4-P1-04 | `authority.rs:45-50` | **`Operation::new` accepts structurally invalid operations.** The character allowlist permits `*` anywhere (e.g., `"act*uate"`, `"actuate:*:shoulder"`), consecutive colons (`"::"`), leading/trailing colons (`":arm"`, `"arm:"`), and critically `":*"` which `strip_suffix(":*")` converts to empty prefix — making `":*"` equivalent to bare `"*"` (universal wildcard). An attacker can smuggle `":*"` into a PCA to grant universal authority while appearing non-obvious to a human reviewer. |
| S4-P1-05 | `crypto.rs:17,33` | **`sign_pca` panics via `expect` on serialization.** `serde_json::to_vec(claim).expect(...)` and `cose.to_vec().expect(...)` will panic if serialization fails. In a safety-critical library, panic = denial of service. Should return `Result<SignedPca, AuthorityError>`. |
| S4-P1-06 | `operations.rs:31-35` | **`"prefix:*"` wildcard matches bare prefix itself.** `"actuate:arm:*"` covers `"actuate:arm"` (the prefix without a trailing segment) because `rest.is_empty()` returns true. If `"actuate:arm"` is a distinct capability (e.g., "enumerate arm joints"), a PCA granting `"actuate:arm:*"` (intended: sub-operations only) silently also covers it. Monotonicity reasoning is undermined: a parent granting `"actuate:arm:shoulder"` and a child claiming `"actuate:arm"` should be a violation but would depend on whether `"actuate:arm"` is wildcarded. Ambiguous semantics in a safety-critical authority model. |

### New P2 — Important / Correctness

| ID | File:Line | Issue |
|----|-----------|-------|
| S4-P2-01 | `authority.rs:93` | **`p_0` not validated as non-empty.** Empty `p_0` makes A1 provenance check trivially pass if all hops also carry `""`. Cannot be meaningfully audited. (Carry-forward from S3a-P2-07.) |
| S4-P2-02 | `authority.rs:97` | **`kid` not validated as non-empty.** `trusted_keys` HashMap with `""` key matches any PCA with `kid = ""`. (Carry-forward from S3a-P2-07.) |
| S4-P2-03 | `authority.rs:99-101` | **`nbf`/`exp` consistency not validated.** A PCA with `nbf >= exp` is accepted — zero-width or inverted validity window produces confusing errors, never valid. |
| S4-P2-04 | `chain.rs:38-41` | **`MAX_HOPS` error uses `CoseError` variant.** Chain-length policy violation misclassified as COSE decode error. Needs dedicated `ChainTooLong` variant for correct audit logging and error routing. |
| S4-P2-05 | `crypto.rs:72-85` | **`decode_pca_payload` is `pub` and skips verification.** Doc says "call `verify_signed_pca` first" but nothing enforces it. Should be `pub(crate)` at minimum. |
| S4-P2-06 | `authority.rs:113` | **`SignedPca.claim` is a `pub` mutable field.** Any code can overwrite `claim` without touching `raw`, trivially creating the mismatch exploited by S4-P1-01. Field should be private or `claim` should be removed from the struct entirely. |
| S4-P2-07 | `chain.rs:24` | **Temporal boundary doc/code mismatch.** Comment documents valid window as `[nbf, exp]` (inclusive both ends), but code uses `now >= exp` (exclusive exp). JWT convention (RFC 7519) uses exclusive `exp`, making the code likely correct but the comment wrong. Must align. |
| S4-P2-08 | `error.rs:4` | **`AuthorityError` does not derive `PartialEq`.** Forces verbose `matches!` + destructuring in tests. All inner types support `PartialEq`. Should derive it. |
| S4-P2-09 | `crypto.rs:57-62` | **Verification closure converts errors to `String`.** Original error type lost — cannot distinguish malformed signature encoding from wrong-key failure in structured error handling or audit. |
| S4-P2-10 | `chain.rs:71-81` | **Redundant traversal for error reporting after `ops_are_subset` returns false.** `find` re-iterates with `operation_matches` to locate offending op. `unwrap_or_default()` produces empty string if logic bug causes no match. Should use `first_uncovered_op` from operations.rs instead. |

### New P3 — Quality / Future-Proofing

| ID | File:Line | Issue |
|----|-----------|-------|
| S4-P3-01 | `tests.rs` | **No test for tampered `claim` field.** The most critical vulnerability (S4-P1-01) has zero test coverage. No test constructs a `SignedPca` where `claim` differs from COSE payload and verifies rejection. |
| S4-P3-02 | `tests.rs` | **No test for `exp == now` boundary.** `temporal_expired` uses `now - 10s`. The exact boundary (exp equals now) is untested — determines inclusive/exclusive semantics. |
| S4-P3-03 | `tests.rs` | **No test for `nbf == now` boundary.** `temporal_not_yet_valid` uses `now + 3600s`. Exact boundary untested. |
| S4-P3-04 | `tests.rs` | **No test for wildcard escalation via child wildcard.** Parent `"actuate:arm:shoulder"`, child `"actuate:arm:*"` — child wildcard is broader than parent specific op. Currently correctly rejected, but no test guards against regression. |
| S4-P3-05 | `tests.rs` | **No test for exactly `MAX_HOPS` (16 hops) succeeding.** Only 17-hop failure is tested. Off-by-one boundary at 16 is untested. Error variant in `max_hops_exceeded` test is not asserted (just `is_err()`). |
| S4-P3-06 | `tests.rs` | **No test for `decode_pca_payload` with missing/invalid payload.** COSE envelope with `None` payload or non-JSON bytes — both error paths in crypto.rs:77-84 are untested. |
| S4-P3-07 | `tests.rs` | **No test for deep wildcard nesting.** `"actuate:arm:*"` vs `"actuate:arm:shoulder:joint:alpha"` (5+ segments) untested. |
| S4-P3-08 | `error.rs:36-37,71-72` | **Duplicate error messages.** `ValidationError::EmptyAuthorityChain` and `AuthorityError::EmptyChain` both say "authority chain must have at least one hop". Confusing for callers. |
| S4-P3-09 | `error.rs:9,22` | **Error messages leak `p_0` and `kid` values.** `ProvenanceMismatch` and `UnknownKeyId` include internal identifiers verbatim — aids enumeration if exposed to network callers. |
| S4-P3-10 | `crypto.rs:21` | **No length bound on `kid` in COSE protected header.** Arbitrarily long `kid` causes oversized protected header and memory amplification. Should cap at ~256 bytes. |
| S4-P3-11 | `operations.rs:43-56` | **O(|child| * |parent|) complexity for wildcard matching.** `BTreeSet` sorted structure not exploited. Acceptable at current scale (small ops sets) but should be documented as a known bound. |
| S4-P3-12 | `operations.rs:33` | **Misleading comment.** "Must be exactly the prefix or have more segments" does not explain why matching the bare prefix (no trailing colon) is intended. Comment should clarify or be removed if behavior is wrong (see S4-P1-06). |

---

## Review Findings — Step 3a Quality Review (2026-03-23)

Reviewed: all physics modules (10 checks + orchestrator + tests), all model types, CLI/sim/eval crates, workspace config, 4 robot profiles, test suite (84 tests), clippy, build.

Build: PASS. Tests: 84/84 PASS. Clippy: PASS.

### Step 3 Review Findings — Resolution Status

| Prior ID | Status | Notes |
|----------|--------|-------|
| R1-01..R1-09 | **FIXED** | NaN/Inf guards added to all 10 physics checks with `is_finite()` |
| R1-10 | **FIXED** | `SafeStopStrategy` uses `#[derive(Default)]` + `#[default]` |
| R1-11 | **FIXED** | Collection caps: joints 256, zones 256, collision_pairs 1024 |
| R1-12 | **FIXED** | `reqwest` removed from workspace `[dependencies]` |
| R2-01 | **FIXED** | Self-collision flags missing links as violations |
| R2-02 | **FIXED** | Acceleration flags missing previous joints as violations |
| R2-03 | **FIXED** | Proximity flags unknown joints as violations |
| R2-04 | **FIXED** | `min_collision_distance` configurable per-profile (default 0.01m) |
| R2-05..R2-07 | **FIXED** | Addressed by R2-01 — missing links no longer silent |
| R2-08..R2-18 | Deferred | To be addressed in Steps 9, 20 |
| R3-01 | **FIXED** | 20 NaN/Inf tests added (84 total) |
| R3-02..R3-14 | Deferred | To be addressed in Steps 20, 21 |

### New P1 — Blocking / Security

| ID | File:Line | Issue |
|----|-----------|-------|
| S3a-P1-01 | `models/profile.rs:82-84` | **`min_collision_distance` not validated**: no finiteness or positivity check in `validate()`. If profile sets `min_collision_distance: NaN`, then `dist < NaN` is always false (IEEE 754) — P7 collision check silently passes for ALL pairs. If negative or zero, same effect. New field added by R2-04 fix but missing validation. |
| S3a-P1-02 | `models/profile.rs:244-258` | **`ExclusionZone` geometry not validated**: sphere `radius` can be NaN, 0, or negative; AABB min/max can be NaN. `point_in_sphere` with NaN radius returns false — zone never triggers. `point_in_aabb` with NaN bounds returns false — zone bypassed. Same applies to `ProximityZone::Sphere` radius. |
| S3a-P1-03 | `models/profile.rs:182-216` | **NaN/Inf not rejected in `JointDefinition` f64 fields**: `min`, `max`, `max_velocity`, `max_torque`, `max_acceleration` not checked for finiteness. `NaN >= NaN` is false → validation passes. NaN in joint limits would bypass all physics checks despite NaN guards on command data. |
| S3a-P1-04 | `models/profile.rs:147,82` | **NaN bypass in `global_velocity_scale`**: `NaN <= 0.0` is false, `NaN > 1.0` is false → NaN passes range check. `max_delta_time` has no validation at all. Both can poison downstream physics checks. |
| S3a-P1-05 | `models/command.rs:7-48` | **`Command` has no `Validate` impl**: the primary ingress type (crosses network boundary) has no defensive validation. `joint_states`/`end_effector_positions` unbounded, `delta_time` not checked, `metadata` key/value lengths unbounded, `pca_chain` length unbounded. |
| S3a-P1-06 | `exclusion_zones.rs:90`, `proximity.rs:162` | **Squared-distance overflow in `point_in_sphere`**: `dx*dx + dy*dy + dz*dz` overflows to `+Inf` for coordinate differences > ~1.34e154. `+Inf <= radius*radius` is false → point treated as outside sphere → exclusion zone bypassed. Affects P6 and P10. |
| S3a-P1-07 | `self_collision.rs:93` | **Same overflow in `euclidean_distance`**: `(+Inf).sqrt()` yields `+Inf`, `+Inf < min_collision_distance` is false → collision check passes for extreme coordinates. |

### New P2 — Important / Correctness

| ID | File:Line | Issue |
|----|-----------|-------|
| S3a-P2-01 | `models/profile.rs:228-235` | `WorkspaceBounds::validate()` does not check min/max for NaN/Inf. Workspace bounds with NaN allow all positions to pass. (Carry-forward from R2-18.) |
| S3a-P2-02 | `models/profile.rs:298-308` | `StabilityConfig` has no `Validate` impl. `support_polygon` vertices not validated for finiteness. `com_height_estimate` can be NaN/negative. |
| S3a-P2-03 | `models/profile.rs:310-333` | `SafeStopProfile` has no `Validate` impl. `max_deceleration` can be 0/negative/NaN. `target_joint_positions` unbounded and values not checked for finiteness. |
| S3a-P2-04 | `models/profile.rs:70-71` | `RobotProfile::name`/`version` not validated as non-empty. Empty `name` breaks audit log correlation. (Carry-forward from R2-15.) |
| S3a-P2-05 | `models/profile.rs:40-64` | `CollisionPair` link names unvalidated — can be empty or identical (self-pair makes no physical sense). |
| S3a-P2-06 | `models/authority.rs:120-128` | `AuthorityChain` has no `Validate` impl. Empty `hops` vec accepted. `hops` length unbounded. `EmptyAuthorityChain` error variant exists but is unused. |
| S3a-P2-07 | `models/authority.rs:91-102` | `Pca::p_0` and `kid` not validated as non-empty. Empty `p_0` breaks A1 cross-hop origin invariant. |
| S3a-P2-08 | `models/verdict.rs:4-42` | `Verdict`/`SignedVerdict` have no `Validate` impl. `command_hash`, `profile_hash` can be empty. `checks` Vec unbounded. |
| S3a-P2-09 | `models/actuation.rs:9-17` | `SignedActuationCommand` has no `Validate` impl. `joint_states` unbounded. Hash/signature fields can be empty. |
| S3a-P2-10 | `models/audit.rs:9-16` | `AuditEntry` hash fields `previous_hash`/`entry_hash` can be empty strings — would corrupt hash-chain integrity. |
| S3a-P2-11 | `models/authority.rs:45` | Bare `*` is a valid `Operation` — could grant universal authority. Should restrict `*` to trailing segment only. |
| S3a-P2-12 | `physics/self_collision.rs:53`, `physics/exclusion_zones.rs:31` | NaN guard inconsistency: `self_collision.rs` uses `pos.iter().all()` while `exclusion_zones.rs` uses explicit index checks. Both correct, but inconsistent. |
| S3a-P2-13 | `physics/acceleration.rs:14-17` | Doc comment says missing previous joint is "skipped (treated as first observation)" but implementation now flags as violation (R2-02 fix). Stale documentation. |
| S3a-P2-14 | `physics/stability.rs:102` | CoM exactly on polygon edge has undocumented, untested classification. Half-open interval technique may return either true or false depending on edge orientation. |

### New P3 — Quality / Future-Proofing

| ID | File:Line | Issue |
|----|-----------|-------|
| S3a-P3-01 | `physics/tests.rs` | No test for NaN/Inf in profile definitions (as opposed to command data). Tests only verify NaN in joint states and end-effector positions, not in joint limits or zone geometry. |
| S3a-P3-02 | `physics/tests.rs` | No test for `min_collision_distance: 0.0` or `min_collision_distance: NaN` — the new configurable parameter has no validation test coverage. |
| S3a-P3-03 | `exclusion_zones.rs:84-91`, `proximity.rs:157-163` | `point_in_sphere` still copy-pasted in two modules (carry-forward from R3-05). Should extract to shared utility. |
| S3a-P3-04 | `physics/tests.rs` | `run_all_checks` integration tests still do not trigger P4 (acceleration) or P10 (proximity) failures (carry-forward from R3-03). |
| S3a-P3-05 | `models/profile.rs:17-21` | `BoundsType` enum is defined but never used — dead code hidden by `#![allow(dead_code)]`. |
| S3a-P3-06 | `models/verdict.rs:32-33` | `AuthoritySummary::operations_granted/required` are `Vec<String>` not `Vec<Operation>` — newtypes lost at verdict boundary. (Carry-forward from R2-12.) |
| S3a-P3-07 | `models/verdict.rs:37`, `models/audit.rs:18` | `#[serde(flatten)]` used for signed types — signing byte canonicalization undocumented. Different serializers may produce different key orderings. |
| S3a-P3-08 | `models/trace.rs:16,31` | `Trace::metadata` uses `serde_json::Value` (arbitrary nesting, stack-overflow DoS). `TraceStep::simulation_state` same risk. (Carry-forward from R2-09.) |
| S3a-P3-09 | `models/profile.rs:33` | Extra blank line after removed `impl Default for SafeStopStrategy` — cosmetic. |
| S3a-P3-10 | `physics/joint_limits.rs:19` et al. | O(n*m) linear scan joint lookup in all 5 per-joint checks. With MAX_JOINTS=256 at 1kHz, wasteful. Should build a HashMap once. |
| S3a-P3-11 | `physics/delta_time.rs:17` | Error message "not finite and positive" is misleading when delta_time is zero (zero is finite). Should say "must be strictly positive and finite". |
| S3a-P3-12 | `physics/tests.rs` | Missing tests: NEG_INFINITY delta_time, max_delta_time=0.0, self-referential CollisionPair (link_a==link_b), empty definitions slice, CoM on polygon vertex/edge. |
| S3a-P3-13 | `physics/stability.rs:45-52` | Degenerate polygon (< 3 vertices) passes silently instead of flagging as a config error. Should be a failed result, not a silent pass. |

---

## Review Findings — Step 3 Quality Review (2026-03-23)

Reviewed: all physics modules, all model types, CLI/sim/eval crates, workspace config, 4 robot profiles, test suite (64 tests), clippy, build.

Build: PASS. Tests: 64/64 PASS. Clippy: FAIL (1 lint error).

### P1 — Blocking / Security

| ID | File:Line | Issue |
|----|-----------|-------|
| R1-01 | `physics/joint_limits.rs:27` | **NaN bypass**: `NaN < def.min` and `NaN > def.max` both return `false` (IEEE 754). A NaN joint position silently passes P1. Same pattern in P2-P8, P10 |
| R1-02 | `physics/velocity.rs:30` | NaN velocity: `NaN.abs()` is NaN, `NaN > limit` is `false` — silently passes P2 |
| R1-03 | `physics/torque.rs:27` | NaN effort silently passes P3 (same IEEE 754 pattern) |
| R1-04 | `physics/acceleration.rs:39,68` | NaN delta_time passes the `<= 0.0` guard; NaN velocities produce NaN accel; `NaN > max_accel` is `false` — P4 silently passes |
| R1-05 | `physics/workspace.rs:32-34` | NaN end-effector position passes all 6 AABB comparisons — silently passes P5 |
| R1-06 | `physics/exclusion_zones.rs:73-79,85-90` | NaN coordinates: `point_in_aabb` and `point_in_sphere` both return `false` for NaN — end-effector treated as "outside" every zone, silently passes P6 |
| R1-07 | `physics/self_collision.rs:72-76` | `euclidean_distance` returns NaN for NaN input; `NaN < MIN_DIST` is `false` — collision check silently passes P7 |
| R1-08 | `physics/delta_time.rs:11` | NaN delta_time: `NaN <= 0.0` false, `NaN > max` false — P8 silently passes. This also poisons P4 (acceleration depends on dt) |
| R1-09 | `physics/proximity.rs:130` | NaN position in `point_in_sphere` treated as "outside" all zones — proximity velocity scaling skipped entirely, P10 passes |
| R1-10 | `models/profile.rs:32` | **Clippy error**: manual `impl Default for SafeStopStrategy` triggers `derivable_impls` lint — `cargo clippy -D warnings` fails, blocks CI |
| R1-11 | `models/profile.rs:73-93,276` | Unbounded `Vec`/`HashMap` in `RobotProfile` (joints, zones, collision_pairs) and `SafeStopProfile` — no length caps in `validate()`, enables memory exhaustion DoS |
| R1-12 | `Cargo.toml:33` | `reqwest = "0.12"` still declared in workspace `[dependencies]` — P2-13 only partially fixed (removed from sim but not workspace). Any future crate can silently adopt it |

### P2 — Important / Correctness

| ID | File:Line | Issue |
|----|-----------|-------|
| R2-01 | `physics/self_collision.rs:37-42` | Missing link in `end_effectors` causes pair to be **silently skipped** — misconfigured profile gets zero collision checking with no error |
| R2-02 | `physics/acceleration.rs:64-66` | Joint absent from `previous_joints` is silently skipped — new joint name in command bypasses acceleration check |
| R2-03 | `physics/proximity.rs:52-55` | Unknown joints (no definition) silently skipped with `continue` — inconsistent with P1/P2/P3 which flag unknown joints as violations |
| R2-04 | `physics/self_collision.rs:9` | `MIN_SELF_COLLISION_DIST` hardcoded to 0.01m — not configurable per-profile or per-pair; different robots need different clearances |
| R2-05 | `profiles/humanoid_28dof.json:71` | Collision pairs reference `"left_hand"`/`"right_hand"` — names absent from joint defs. P7 silently no-ops for all 5 pairs in this profile |
| R2-06 | `profiles/quadruped_12dof.json:41` | Collision pairs reference `"fl_foot"` etc. — absent from joint defs. All pairs silently skipped |
| R2-07 | `profiles/franka_panda.json:43`, `profiles/ur10.json:49` | Collision pairs use URDF link names not joint names — P7 would silently no-op unless end-effector positions match link names |
| R2-08 | `models/command.rs:15,25` | `Command.joint_states` unbounded Vec, `metadata` unbounded HashMap — no size cap against profile joint count |
| R2-09 | `models/trace.rs:16,31` | `Trace.metadata` is `HashMap<String, serde_json::Value>`, `TraceStep.simulation_state` is `Option<serde_json::Value>` — arbitrary nesting depth, stack-overflow DoS risk |
| R2-10 | `models/authority.rs:91-102,121-128` | `Pca.ops` unbounded `BTreeSet`, `AuthorityChain.hops` unbounded Vec — no max ops/hops cap |
| R2-11 | `models/verdict.rs:22-24` | `CheckResult.category` is raw String — should be enum to prevent unknown categories in audit |
| R2-12 | `models/verdict.rs:29-33` | `AuthoritySummary.operations_granted/required` are `Vec<String>` not `Vec<Operation>` — newtypes lost at verdict boundary |
| R2-13 | `models/profile.rs:258-263` | `StabilityConfig.support_polygon` accepts fewer than 3 points — degenerate polygon not validated |
| R2-14 | `models/profile.rs:103-127` | `ExclusionZone` variants never validated — sphere radius can be 0 or negative |
| R2-15 | `models/profile.rs:73,86-87` | `name`/`version` accept empty strings; `watchdog_timeout_ms` has no min (0 disables watchdog); `max_delta_time` no positive check |
| R2-16 | `commands/validate.rs:18-23` | Neither `--command` nor `--batch` is `required_unless_present` — bare invocation silently accepted |
| R2-17 | `invariant-cli/main.rs:40-48` | All stubs return exit code 2 (POSIX "usage error") — should be 1 for "not implemented" |
| R2-18 | `models/profile.rs:186` | `WorkspaceBounds::Aabb` min/max not checked for finiteness — `Infinity`/`NaN` in bounds passes validation |

### P3 — Quality / Future-Proofing

| ID | File:Line | Issue |
|----|-----------|-------|
| R3-01 | `physics/tests.rs` | **Zero NaN/Inf tests** across all 10 checks — the most safety-critical input class has no coverage |
| R3-02 | `physics/tests.rs` | No `-0.0` tests for position/velocity/effort |
| R3-03 | `physics/tests.rs:686` | `run_all_checks` integration tests never trigger P4 or P10 failures |
| R3-04 | `physics/tests.rs:542` | No test for 0-vertex or 1-vertex support polygon in P9 |
| R3-05 | `exclusion_zones.rs:85-90`, `proximity.rs:126-131` | `point_in_sphere` copy-pasted in two modules — future fix won't propagate |
| R3-06 | `stability.rs:18` | Parameter named `center_of_mass` but docs say ZMP — CoM and ZMP are different physical quantities for moving robots |
| R3-07 | `physics/joint_limits.rs:11-12` | Empty `joints` + empty `end_effectors` trivially passes all 10 checks — a completely empty command passes the entire firewall |
| R3-08 | `Cargo.toml:31` | `tokio` workspace declaration has no features — maintenance trap for new crates |
| R3-09 | `Cargo.toml:25` | `rand = "0.8"` in crypto-adjacent code; 0.9 series has CSPRNG improvements |
| R3-10 | `commands/keygen.rs:6` | `--kid` accepts arbitrary string — path separators or shell chars could cause injection |
| R3-11 | `invariant-core/src/lib.rs:1` | `#![allow(dead_code)]` crate-wide suppresses all dead-code warnings — hides legitimate issues |
| R3-12 | `models/authority.rs:36` | `Pca`, `SignedPca`, `AuthorityChain` have fully `pub` fields — construction bypasses future chain-invariant checks |
| R3-13 | `crates/invariant-sim/`, `crates/invariant-eval/` | Stub crates declare `serde_yaml`, `regex`, `reqwest` deps but use none — dead compile-time and supply-chain weight |
| R3-14 | `Cargo.toml:19` | `coset = "0.3"` declared at workspace level but only used by `invariant-core` — should be crate-local |

---

## Prior Step 2 Review Findings — Status

| Prior ID | Status | Notes |
|----------|--------|-------|
| P1-1 through P1-6 | FIXED | All 6 P1 items resolved in Step 2 |
| P2-1 through P2-7 | FIXED | All 7 P2 items resolved in Step 2 |
| P2-8 | FIXED | `Cli::parse()` result now used for dispatch |
| P2-9 | FIXED | `try_init()` used |
| P2-10 | PARTIAL | `conflicts_with` added but `required_unless_present` missing (see R2-16) |
| P2-11 | FIXED | `ValidationMode` is a `ValueEnum` |
| P2-12 | Not verified | Low priority |
| P2-13 | PARTIAL | Removed from sim but `reqwest` remains in workspace manifest (see R1-12) |
| P2-14 | FIXED | Tokio features minimized per-crate |
| P2-15 | FIXED | `diff.rs` and `DiffArgs` present |
| P3-1 through P3-7 | FIXED | All resolved in Step 2 |
| P3-8 | FIXED | All file-path args use `PathBuf` |
| P3-9 through P3-18 | Various | Most remain; some are deferred to Steps 9/20 |

---

## Pending Tasks

### Phase 1: Core
- [x] **Step 2 — Core types**: All model structs with serde + validation. Newtypes for safety. Fixed all 6 P1 and all 15 P2 findings.
- [x] **Step 3 — Physics checks (10)**: Pure functions, zero allocation, extensively tested.
- [x] **Step 3a — Fix P1 review findings**: NaN/Inf guards in all physics checks, clippy fix, unbounded collection caps. All R1-* and R2-01 through R2-07 fixed.
- [x] **Step 4 — Authority validation**: Ed25519 COSE_Sign1 chain verification, monotonicity, provenance.
- [x] **Step 4a — Fix P1 review findings**: Use decoded COSE payload instead of `claim` field, `verify_strict`, private `AuthorityChain` fields, `Operation::new` structural validation, remove `expect` panics, wildcard prefix semantics. **Fixed S4-P1-01 through S4-P1-06.**
- [ ] **Step 5 — Validator orchestrator**: Authority + physics -> signed verdict + optional signed actuation.
- [ ] **Step 6 — Signed audit logger**: Append-only, hash-chained, Ed25519-signed JSONL.
- [ ] **Step 7 — Watchdog**: Heartbeat monitor, safe-stop command generation.
- [ ] **Step 8 — Profile library**: 4 validated profiles (humanoid 28-DOF, Franka, quadruped, UR10).

### Phase 2: CLI
- [ ] **Step 9 — CLI**: clap-based, all subcommands. **Fix R2-16, R2-17, R3-10.**
- [ ] **Step 10 — Embedded Trust Plane**: `invariant serve` mode using axum.
- [ ] **Step 11 — Key management**: `invariant keygen`, key file format.

### Phase 3: Eval
- [ ] **Step 12 — Eval presets**: safety-check, completeness-check, regression-check.
- [ ] **Step 13 — Custom rubrics**: YAML/JSON loader with pattern matching. **Apply P3-13 YAML-bomb mitigations.**
- [ ] **Step 14 — Guardrail engine**: Policy-based pattern matching with actions. **Apply P3-14 regex size limits.**
- [ ] **Step 15 — Trace differ**: Step-by-step comparison with divergence detection.

### Phase 4: Simulation
- [ ] **Step 16 — Campaign config**: YAML parser, validation. **Apply P3-13 YAML-bomb mitigations.**
- [ ] **Step 17 — Scenarios**: 7 built-in scenarios.
- [ ] **Step 18 — Fault injector**: Velocity overshoot, position violation, authority escalation, chain forgery, metadata attack.
- [ ] **Step 19 — Orchestrator**: Isaac Lab bridge + DryRunOrchestrator + campaign reporter. **Remove reqwest (R1-12).**

### Phase 5: Hardening and Proof
- [ ] **Step 20 — Security hardening**: Input validation, numeric safety, file safety, identifier validation. **Fix remaining R2-* and R3-*.**
- [ ] **Step 21 — Property-based tests**: proptest for all invariants.
- [ ] **Step 22 — Adversarial integration tests**: All 12 attacks as test cases.
- [ ] **Step 23 — Documentation**: README, architecture, authority model, simulation guide, etc.
