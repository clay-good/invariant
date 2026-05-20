//! Snapshot test for public `invariant-core` error types (v11-5.13).
//!
//! Constructs one minimal instance per variant catalogued in
//! [`docs/error-stability.md`](../../../../docs/error-stability.md) and asserts
//! `to_string()` matches a frozen snapshot. Updating an error's `#[error]`
//! attribute requires updating the corresponding constant here in the same
//! PR — that is the entire point of the test.
//!
//! Variants that wrap `std::io::Error` / `serde_json::Error` / `base64::DecodeError`
//! delegate to the inner error's `Display`, which we do not own and cannot
//! freeze. Those variants are documented in the catalog but skipped here.

use invariant_core::audit::{AuditError, AuditVerifyError};
use invariant_core::incident::AlertError;
use invariant_core::intent::IntentError;
use invariant_core::keys::{KeyFileError, KeyStoreError};
use invariant_core::models::error::{AuthorityError, CoseDecodeReason, ValidationError};
use invariant_core::replication::ReplicationError;

/// Compact helper: assert that an error's `to_string()` matches an expected
/// frozen string. Failure messages include both sides so the diff is obvious.
fn snap<E: std::fmt::Display + std::fmt::Debug>(e: E, expected: &str) {
    let got = e.to_string();
    assert_eq!(
        got, expected,
        "\n  variant {e:?}\n  expected: {expected}\n  actual:   {got}\n"
    );
}

#[test]
fn audit_error_display_snapshot() {
    snap(
        AuditError::Serialization {
            reason: "missing field".into(),
        },
        "serialization failed: missing field",
    );
    snap(
        AuditError::Io {
            reason: "disk full".into(),
        },
        "I/O error: disk full",
    );
    snap(
        AuditError::LogFull {
            current_bytes: 1000,
            entry_bytes: 500,
            max_bytes: 1024,
        },
        "audit log full: writing 500 bytes would exceed 1024 byte limit (current size: 1000)",
    );
}

#[test]
fn audit_verify_error_display_snapshot() {
    snap(
        AuditVerifyError::HashChainBroken {
            sequence: 7,
            expected: "abc".into(),
            got: "def".into(),
        },
        "entry 7: hash chain broken (expected previous_hash \"abc\", got \"def\")",
    );
    snap(
        AuditVerifyError::EntryHashMismatch {
            sequence: 9,
            expected: "abc".into(),
            computed: "xyz".into(),
        },
        "entry 9: entry_hash mismatch (expected \"abc\", computed \"xyz\")",
    );
    snap(
        AuditVerifyError::SignatureInvalid { sequence: 12 },
        "entry 12: signature verification failed",
    );
    snap(
        AuditVerifyError::SequenceGap {
            sequence: 5,
            expected: 4,
            got: 5,
        },
        "entry 5: expected sequence 4, got 5",
    );
    snap(
        AuditVerifyError::NonEmptyGenesisPreviousHash,
        "entry 0: previous_hash must be empty for the first entry",
    );
    snap(
        AuditVerifyError::Deserialization {
            line: 42,
            reason: "bad JSON".into(),
        },
        "deserialization failed at line 42: bad JSON",
    );
}

#[test]
fn alert_error_display_snapshot() {
    snap(
        AlertError::DeliveryFailed {
            reason: "timeout".into(),
        },
        "alert delivery failed: timeout",
    );
    snap(
        AlertError::Unavailable {
            reason: "no sink configured".into(),
        },
        "alert sink unavailable: no sink configured",
    );
}

#[test]
fn key_file_error_display_snapshot() {
    snap(KeyFileError::EmptyKid, "kid must not be empty");
    snap(
        KeyFileError::UnsupportedAlgorithm("RSA".into()),
        "unsupported algorithm \"RSA\", expected \"Ed25519\"",
    );
    snap(
        KeyFileError::SigningKeyLength(31),
        "signing_key must be exactly 32 bytes, got 31",
    );
    snap(
        KeyFileError::VerifyingKeyLength(33),
        "verifying_key must be exactly 32 bytes, got 33",
    );
    snap(
        KeyFileError::InvalidVerifyingKey("not on curve".into()),
        "invalid verifying key: not on curve",
    );
    snap(
        KeyFileError::KeypairMismatch,
        "signing_key and verifying_key do not form a valid keypair",
    );
}

#[test]
fn key_store_error_display_snapshot() {
    snap(
        KeyStoreError::SigningFailed {
            reason: "HSM offline".into(),
        },
        "signing failed: HSM offline",
    );
    snap(
        KeyStoreError::Unavailable {
            reason: "TPM 2.0 backend not yet implemented".into(),
        },
        "key store unavailable: TPM 2.0 backend not yet implemented",
    );
    snap(
        KeyStoreError::KeyNotFound {
            kid: "alice".into(),
        },
        "key not found: alice",
    );
    snap(
        KeyStoreError::UnsupportedBackend {
            backend: "foobar".into(),
        },
        "backend not supported: foobar",
    );
}

#[test]
fn replication_error_display_snapshot() {
    snap(
        ReplicationError::Io {
            reason: "S3 timeout".into(),
        },
        "I/O error: S3 timeout",
    );
    snap(
        ReplicationError::Unavailable {
            reason: "S3 backend not yet implemented".into(),
        },
        "backend unavailable: S3 backend not yet implemented",
    );
}

#[test]
fn intent_error_display_snapshot() {
    snap(
        IntentError::UnknownTemplate {
            name: "nope".into(),
        },
        "unknown template: nope",
    );
    snap(
        IntentError::MissingParameter {
            template: "pick_and_place".into(),
            param: "limb".into(),
        },
        "missing parameter: limb (required by template pick_and_place)",
    );
    snap(
        IntentError::InvalidOperation {
            reason: "empty".into(),
        },
        "invalid operation: empty",
    );
    snap(
        IntentError::EmptyOperations,
        "empty operations: at least one operation must be specified",
    );
    snap(
        IntentError::InvalidDuration { seconds: -1.0 },
        "invalid duration: -1s (must be positive and finite)",
    );
}

#[test]
fn authority_error_display_snapshot() {
    snap(
        AuthorityError::EmptyChain,
        "authority chain must have at least one hop",
    );
    snap(
        AuthorityError::ChainTooLong { len: 50, max: 32 },
        "chain has 50 hops, exceeding maximum of 32",
    );
    snap(
        AuthorityError::SerializationError {
            reason: "bad JSON".into(),
        },
        "serialization failed: bad JSON",
    );
    snap(
        AuthorityError::ProvenanceMismatch {
            hop: 2,
            expected: "alice".into(),
            got: "mallory".into(),
        },
        "A1 provenance violation: p_0 differs at hop 2 (expected <redacted>, got <redacted>)",
    );
    snap(
        AuthorityError::MonotonicityViolation {
            hop: 1,
            op: "actuate:*".into(),
        },
        "A2 monotonicity violation: hop 1 operation \"actuate:*\" is not covered by parent ops",
    );
    snap(
        AuthorityError::SignatureInvalid {
            hop: 3,
            reason: "Ed25519 verify failed".into(),
        },
        "A3 continuity: signature verification failed at hop 3: Ed25519 verify failed",
    );
    snap(
        AuthorityError::UnknownKeyId {
            hop: 2,
            kid: "secret-leaked".into(),
        },
        "A3 continuity: unknown key id <redacted> at hop 2",
    );
    snap(
        AuthorityError::Expired {
            hop: 0,
            exp: "2020-01-01T00:00:00Z".into(),
        },
        "PCA at hop 0 has expired (exp=2020-01-01T00:00:00Z)",
    );
    snap(
        AuthorityError::NotYetValid {
            hop: 0,
            nbf: "2099-01-01T00:00:00Z".into(),
        },
        "PCA at hop 0 is not yet valid (nbf=2099-01-01T00:00:00Z)",
    );
    snap(
        AuthorityError::CoseError {
            hop: 1,
            reason: "malformed tag".into(),
        },
        "COSE decoding error at hop 1: malformed tag",
    );
    // v10-14: granular CoseDecodeReason variants. The outer
    // `AuthorityError::CoseDecode` display format is `"COSE decoding error
    // at hop {hop}: {reason}"`, where `{reason}` delegates to the
    // `CoseDecodeReason` `Display` impl. Anchor the six variants whose
    // shape downstream code is allowed to depend on.
    snap(
        AuthorityError::CoseDecode {
            hop: 1,
            reason: CoseDecodeReason::CborInvalid("EOF while parsing".into()),
        },
        "COSE decoding error at hop 1: CBOR/COSE envelope invalid: EOF while parsing",
    );
    snap(
        AuthorityError::CoseDecode {
            hop: 0,
            reason: CoseDecodeReason::MissingProtectedHeader,
        },
        "COSE decoding error at hop 0: missing COSE protected header",
    );
    snap(
        AuthorityError::CoseDecode {
            hop: 2,
            reason: CoseDecodeReason::MissingKid,
        },
        "COSE decoding error at hop 2: missing key id in protected header",
    );
    snap(
        AuthorityError::CoseDecode {
            hop: 2,
            reason: CoseDecodeReason::InvalidKidEncoding(
                "invalid utf-8 sequence of 1 bytes from index 0".into(),
            ),
        },
        "COSE decoding error at hop 2: invalid key id encoding: \
         invalid utf-8 sequence of 1 bytes from index 0",
    );
    snap(
        AuthorityError::CoseDecode {
            hop: 0,
            reason: CoseDecodeReason::MissingPayload,
        },
        "COSE decoding error at hop 0: missing COSE payload",
    );
    snap(
        AuthorityError::CoseDecode {
            hop: 0,
            reason: CoseDecodeReason::PayloadDecode("expected map".into()),
        },
        "COSE decoding error at hop 0: payload deserialization failed: expected map",
    );
    snap(
        AuthorityError::CoseDecode {
            hop: 3,
            reason: CoseDecodeReason::SignatureSlotEmpty,
        },
        "COSE decoding error at hop 3: COSE signature slot is empty",
    );
    snap(
        AuthorityError::CoseDecode {
            hop: 1,
            reason: CoseDecodeReason::WrongTag {
                expected: 18,
                got: 96,
            },
        },
        "COSE decoding error at hop 1: wrong COSE tag: expected 18, got 96",
    );
    snap(
        AuthorityError::CoseDecode {
            hop: 0,
            reason: CoseDecodeReason::Other("unexpected end-of-stream".into()),
        },
        "COSE decoding error at hop 0: unexpected end-of-stream",
    );
    snap(
        AuthorityError::InsufficientOps {
            op: "actuate:base:wheel".into(),
        },
        "required operation \"actuate:base:wheel\" is not covered by granted ops",
    );
}

#[test]
fn validation_error_display_snapshot() {
    // The full enum has ~20 profile-shape variants; we anchor the most
    // load-bearing ones. The rest are exercised by their per-module
    // unit tests under `crates/invariant-core/src/models/`.
    snap(
        ValidationError::InvalidOperation("".into()),
        "operation string is invalid (empty, whitespace, or disallowed characters): \"\"",
    );
    snap(
        ValidationError::JointLimitsInverted {
            name: "j1".into(),
            min: 1.0,
            max: 0.5,
        },
        "joint 'j1': min (1) must be strictly less than max (0.5)",
    );
    snap(
        ValidationError::JointLimitNotPositive {
            name: "j1".into(),
            field: "velocity",
            value: -1.0,
        },
        "joint 'j1': velocity must be positive, got -1",
    );
    snap(
        ValidationError::VelocityScaleOutOfRange(1.5),
        "global_velocity_scale 1.5 is out of range — must be in (0.0, 1.0]",
    );
    snap(
        ValidationError::EmptyAuthorityChain,
        "authority chain must have at least one hop",
    );
    snap(
        ValidationError::DuplicateJointName {
            name: "shoulder".into(),
        },
        "profile contains duplicate joint name: 'shoulder'",
    );
}
