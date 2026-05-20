# Error-Type Stability Catalog (v11-5.13)

`invariant-core` exposes nine public error enums to downstream crates and to
operators inspecting the audit log / CLI exit codes. This document is the
canonical inventory: which enum, which variant, what its `Display` string is,
and where downstream tooling (audit consumers, CI parsers, runbooks) is
allowed to depend on a stable shape.

**Change-detector:** the snapshot test at
[crates/invariant-core/tests/error_stability.rs](../crates/invariant-core/tests/error_stability.rs)
materialises one representative instance of every variant listed below and
snapshots its `Display` output. A PR that changes an error message must
update the snapshot constants in that test alongside the table here.

**Marking `#[non_exhaustive]`:** the four most-extended enums —
`AuthorityError` and `ValidationError` (in
[crates/invariant-core/src/models/error.rs](../crates/invariant-core/src/models/error.rs)),
`AuditError` and `AuditVerifyError` (in
[crates/invariant-core/src/audit.rs](../crates/invariant-core/src/audit.rs)) —
carry `#[non_exhaustive]` as of 2026-05-17 (v11 5.13 step 1). Adding a
variant to any of them is therefore **not** a breaking change for
downstream callers: external `match` statements must already include a
catch-all `_ => …` arm, and existing internal call sites either use
`matches!(_, Variant { .. })` patterns or specific-variant destructuring
with `..` (both of which are unaffected by the annotation). `cargo build
--workspace`, `cargo test --workspace`, and `cargo clippy --workspace
--lib` all stay green after the annotation.

## Tables

### `AuditError` — `crates/invariant-core/src/audit.rs`

| Variant | Introduced | Display | Audit / CLI references |
|---------|------------|---------|------------------------|
| `Serialization { reason }` | Phase 1b | `serialization failed: {reason}` | Exit 2 from `invariant validate --audit-log` |
| `Io { reason }` | Phase 1b | `I/O error: {reason}` | `--fail-on-audit-error` 503 trigger |
| `LogFull { entry_bytes, current_bytes, max_bytes }` | Phase 1b | `audit log full: writing {entry_bytes} bytes would exceed {max_bytes} byte limit (current size: {current_bytes})` | Operator runbook: rotate |

### `AuditVerifyError` — `crates/invariant-core/src/audit.rs`

| Variant | Display |
|---------|---------|
| `HashChainBroken { sequence }` | `entry {sequence}: hash-chain broken` |
| `EntryHashMismatch { sequence }` | `entry {sequence}: hash mismatch` |
| `SignatureInvalid { sequence }` | `entry {sequence}: signature verification failed` |
| `SequenceGap { sequence, expected, got }` | `entry {sequence}: expected sequence {expected}, got {got}` |
| `NonEmptyGenesisPreviousHash` | `entry 0: previous_hash must be empty for the first entry` |
| `Deserialization { line, reason }` | `deserialization failed at line {line}: {reason}` |

### `AlertError` — `crates/invariant-core/src/incident.rs`

| Variant | Display |
|---------|---------|
| `DeliveryFailed { reason }` | `alert delivery failed: {reason}` |
| `Unavailable { reason }` | `alert sink unavailable: {reason}` |

### `KeyFileError` — `crates/invariant-core/src/keys.rs`

| Variant | Display |
|---------|---------|
| `EmptyKid` | `kid must not be empty` |
| `UnsupportedAlgorithm(s)` | `unsupported algorithm "{s}", expected "Ed25519"` |
| `SigningKeyLength(n)` | `signing_key must be exactly 32 bytes, got {n}` |
| `VerifyingKeyLength(n)` | `verifying_key must be exactly 32 bytes, got {n}` |
| `InvalidVerifyingKey(s)` | `invalid verifying key: {s}` |
| `KeypairMismatch` | `signing_key and verifying_key do not form a valid keypair` |

Other `KeyFileError` variants wrap underlying `std::io` / `serde_json` /
`base64` errors; their `Display` is delegated and not snapshot-tested.

### `KeyStoreError` — `crates/invariant-core/src/keys.rs`

| Variant | Display |
|---------|---------|
| `SigningFailed { reason }` | `signing failed: {reason}` |
| `Unavailable { reason }` | `key store unavailable: {reason}` |
| `KeyNotFound { kid }` | `key not found: {kid}` |
| `UnsupportedBackend { backend }` | `backend not supported: {backend}` |

`Unavailable` is the canonical "stub backend" message returned by the
TPM / YubiHSM / OS-keyring stubs (see v12-N-13 keygen fail-fast).

### `ReplicationError` — `crates/invariant-core/src/replication.rs`

| Variant | Display |
|---------|---------|
| `Io { reason }` | `I/O error: {reason}` |
| `Unavailable { reason }` | `backend unavailable: {reason}` |

### `IntentError` — `crates/invariant-core/src/intent.rs`

| Variant | Display |
|---------|---------|
| `UnknownTemplate { name }` | `unknown template: {name}` |
| `MissingParameter { template, param }` | `missing parameter: {param} (required by template {template})` |
| `InvalidOperation { reason }` | `invalid operation: {reason}` |
| `EmptyOperations` | `empty operations: at least one operation must be specified` |
| `InvalidDuration { seconds }` | `invalid duration: {seconds}s (must be positive and finite)` |

### `AuthorityError` — `crates/invariant-core/src/models/error.rs`

| Variant | Display (truncated for cell width) |
|---------|------------------------------------|
| `EmptyChain` | `authority chain must have at least one hop` |
| `ChainTooLong { len, max }` | `chain has {len} hops, exceeding maximum of {max}` |
| `ProvenanceMismatch { hop, expected, got }` | `A1 provenance violation: p_0 differs at hop {hop} (expected <redacted>, got <redacted>)` |
| `MonotonicityViolation { hop, op }` | `A2 monotonicity violation: hop {hop} operation {op:?} is not covered by parent ops` |
| `SignatureInvalid { hop, reason }` | `A3 continuity: signature verification failed at hop {hop}: {reason}` |
| `UnknownKeyId { hop }` | `A3 continuity: unknown key id <redacted> at hop {hop}` |
| `Expired { hop, exp }` | `PCA at hop {hop} has expired (exp={exp})` |
| `NotYetValid { hop, nbf }` | `PCA at hop {hop} is not yet valid (nbf={nbf})` |
| `CoseError { hop, reason }` | `COSE decoding error at hop {hop}: {reason}` |
| `CoseDecode { hop, reason: CoseDecodeReason }` | `COSE decoding error at hop {hop}: {reason}` (reason is typed — see `CoseDecodeReason` below) |
| `InsufficientOps { op }` | `required operation {op:?} is not covered by granted ops` |

`UnknownKeyId` redacts the key id by design (avoid leaking attacker-supplied
strings into the audit log). Downstream parsers must not depend on the
redacted token.

`CoseError` is kept for backwards compatibility with consumers that may
still pattern-match it; every internal `authority/crypto.rs` call site
now produces `CoseDecode` with a typed `CoseDecodeReason` (v10-14,
2026-05-17).

### `CoseDecodeReason` — `crates/invariant-core/src/models/error.rs`

Carried inside `AuthorityError::CoseDecode { hop, reason }`. The full
`AuthorityError` display string formats as
`"COSE decoding error at hop {hop}: {reason}"`, where `{reason}` is the
inner variant's own `Display`. Forensic auditors can match on the inner
variant directly rather than parsing a free-form string.

| Variant | Display |
|---------|---------|
| `CborInvalid(String)` | `CBOR/COSE envelope invalid: {0}` |
| `MissingProtectedHeader` | `missing COSE protected header` |
| `MissingKid` | `missing key id in protected header` |
| `InvalidKidEncoding(String)` | `invalid key id encoding: {0}` |
| `MissingPayload` | `missing COSE payload` |
| `PayloadDecode(String)` | `payload deserialization failed: {0}` |
| `SignatureSlotEmpty` | `COSE signature slot is empty` |
| `WrongTag { expected, got }` | `wrong COSE tag: expected {expected}, got {got}` |
| `Other(String)` | `{0}` |

`MissingProtectedHeader`, `SignatureSlotEmpty`, and `WrongTag` are
reserved for forensic completeness — the `coset` crate currently
surfaces those cases through `CborInvalid`. New COSE-decode failure
classes that emerge in the wild should get their own variant rather
than ride under `Other`.

### `ValidationError` — `crates/invariant-core/src/models/error.rs`

| Variant | Display |
|---------|---------|
| `InvalidOperation(s)` | `operation string is invalid (empty, whitespace, or disallowed characters): {s:?}` |
| `JointLimitsInverted { name, min, max }` | `joint '{name}': min ({min}) must be strictly less than max ({max})` |
| `JointLimitNotPositive { name, field, value }` | `joint '{name}': {field} must be positive, got {value}` |
| `VelocityScaleOutOfRange(s)` | `global_velocity_scale {s} is out of range — must be in (0.0, 1.0]` |
| `EmptyAuthorityChain` | `authority chain must have at least one hop` |
| `DuplicateJointName { name }` | `profile contains duplicate joint name: '{name}'` |

The full `ValidationError` enum has ~20 additional profile-shape variants
(`WorkspaceBoundsInverted`, `ProximityRadiusInvalid`, …) covered by the
existing per-variant unit tests in `crates/invariant-core/src/models/`;
the snapshot test covers the handful above as representative anchors.

## Snapshot test coverage

The snapshot test exercises every variant listed in the tables above by
constructing one minimal instance per variant and asserting its `to_string()`
output exactly matches a frozen constant. The constants live next to each
table cell so a single PR can update both in lockstep.

When extending an existing enum:

1. Add the new variant + `#[error]` attribute in the source.
2. Add a row in the appropriate table above.
3. Add the variant's expected `Display` to the snapshot constants in
   `tests/error_stability.rs`.
4. CI catches mismatches via the snapshot test.

When intentionally changing an existing message:

1. Update the source attribute.
2. Update the table cell here.
3. Update the snapshot constant in the test.
4. Note the change in `CHANGELOG.md` under "Changed"; downstream consumers
   may have parsed the old string.
