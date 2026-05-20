//! Append-only signed JSONL audit logger.
//!
//! Thin biosynthesis shim over [`invariant_core::audit`]. The hash-chain and
//! signature logic now lives in `invariant-core` so it can be shared with
//! the robotics domain (Phase 1b). This module fixes the generic parameters
//! to biosynthesis's [`SynthesisBundle`] and [`SignedVerdict`] so the
//! existing public API surface (and on-disk JSONL format) is unchanged —
//! both tools can still read each other's logs.

use crate::models::bundle::SynthesisBundle;
use crate::models::verdict::SignedVerdict;

pub use invariant_core::audit::{AuditError, AuditVerifyError};

/// Append-only audit logger for the biosynthesis domain.
///
/// Generic over `W: Write` so it can target a file (with O_APPEND) or an
/// in-memory buffer for testing. The input/verdict types are bound to
/// [`SynthesisBundle`] and [`SignedVerdict`].
pub type AuditLogger<W> =
    invariant_core::audit::AuditLogger<W, SynthesisBundle, SignedVerdict>;

/// Verify an audit log's integrity: hash chain continuity (L2), entry hash
/// correctness, signature validity (L3), and sequence monotonicity.
///
/// Returns the number of verified entries on success, or the first error.
pub fn verify_log(
    jsonl: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<u64, AuditVerifyError> {
    invariant_core::audit::verify_log::<SynthesisBundle, SignedVerdict>(jsonl, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::crypto::generate_keypair;
    use crate::models::bundle::{BundleAuthority, SynthesisBundle, SynthesisPayload};
    use crate::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    fn make_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn make_simple_bundle() -> SynthesisBundle {
        SynthesisBundle {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            payload: SynthesisPayload::Dna {
                sequence: "ATGC".into(),
            },
            delta_time: 0.01,
            authority: BundleAuthority {
                pca_chain: String::new(),
                required_ops: vec![],
            },
            metadata: HashMap::new(),
        }
    }

    fn make_simple_signed_verdict() -> (SignedVerdict, SigningKey) {
        let (sign_sk, _) = make_keypair();
        let fixed_ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let verdict = Verdict {
            approved: true,
            command_hash: "sha256:abc123".into(),
            command_sequence: 1,
            timestamp: fixed_ts,
            checks: vec![CheckResult::new("test", "test", true, "ok")],
            profile_name: "university_bsl2_dna".into(),
            profile_hash: "sha256:def456".into(),
            threat_analysis: None,
            authority_summary: AuthoritySummary {
                origin_principal: "alice".into(),
                hop_count: 1,
                operations_granted: vec!["synthesize:*".into()],
                operations_required: vec!["synthesize:dna:fragment".into()],
            },
        };

        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        use ed25519_dalek::Signer;
        let signature = sign_sk.sign(&verdict_json);

        let signed = SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(signature.to_bytes()),
            signer_kid: "invariant-test".into(),
        };

        (signed, sign_sk)
    }

    #[test]
    fn single_entry_log_and_verify() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_bundle();
        let (verdict, _) = make_simple_signed_verdict();

        let entry = logger.log(&cmd, &verdict).unwrap();

        assert_eq!(entry.entry.sequence, 0);
        assert!(entry.entry.previous_hash.is_empty());
        assert!(entry.entry.entry_hash.starts_with("sha256:"));
        assert!(!entry.entry_signature.is_empty());
        assert_eq!(entry.signer_kid, "invariant-001");

        assert_eq!(logger.sequence(), 1);
        assert_eq!(logger.previous_hash(), &entry.entry.entry_hash);

        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn multi_entry_hash_chain() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_bundle();
        let (verdict, _) = make_simple_signed_verdict();

        let e0 = logger.log(&cmd, &verdict).unwrap();
        let e1 = logger.log(&cmd, &verdict).unwrap();
        let e2 = logger.log(&cmd, &verdict).unwrap();

        assert!(e0.entry.previous_hash.is_empty());
        assert_eq!(e1.entry.previous_hash, e0.entry.entry_hash);
        assert_eq!(e2.entry.previous_hash, e1.entry.entry_hash);

        assert_eq!(e0.entry.sequence, 0);
        assert_eq!(e1.entry.sequence, 1);
        assert_eq!(e2.entry.sequence, 2);

        assert_ne!(e0.entry.entry_hash, e1.entry.entry_hash);
        assert_ne!(e1.entry.entry_hash, e2.entry.entry_hash);

        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn tampered_entry_hash_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_bundle();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        let jsonl = String::from_utf8(buf).unwrap();
        let tampered = jsonl.replace(
            r#""entry_hash":"sha256:"#,
            r#""entry_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000_REPLACED_"#,
        );

        let result = verify_log(&tampered, &sign_vk);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_signature_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_bundle();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        let jsonl = String::from_utf8(buf).unwrap();
        let entry: serde_json::Value = serde_json::from_str(jsonl.trim()).unwrap();
        let mut tampered_entry = entry.clone();
        tampered_entry["entry_signature"] = serde_json::Value::String(STANDARD.encode([0u8; 64]));
        let tampered_jsonl = serde_json::to_string(&tampered_entry).unwrap() + "\n";

        let result = verify_log(&tampered_jsonl, &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::SignatureInvalid { sequence } => assert_eq!(sequence, 0),
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let (sign_sk, _) = make_keypair();
        let (_, wrong_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_bundle();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        let jsonl = String::from_utf8(buf).unwrap();
        let result = verify_log(&jsonl, &wrong_vk);
        assert!(result.is_err());
    }

    #[test]
    fn broken_hash_chain_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_bundle();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();
        logger.log(&cmd, &verdict).unwrap();

        let jsonl = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);

        let swapped = format!("{}\n{}\n", lines[1], lines[0]);
        let result = verify_log(&swapped, &sign_vk);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_gap_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let cmd = make_simple_bundle();
        let (verdict, _) = make_simple_signed_verdict();
        logger1.log(&cmd, &verdict).unwrap();

        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::resume(
            &mut buf2,
            sign_sk,
            "test".into(),
            2,
            logger1.previous_hash().to_string(),
        );
        logger2.log(&cmd, &verdict).unwrap();

        let jsonl = format!(
            "{}{}\n",
            String::from_utf8(buf1).unwrap(),
            String::from_utf8(buf2).unwrap().trim()
        );
        let result = verify_log(&jsonl, &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::SequenceGap { expected, got, .. } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("expected SequenceGap, got {other:?}"),
        }
    }
}
