use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as FmtWrite;
use std::path::Path;

/// An Ed25519 key file holding a key-identifier, a base64-encoded public key,
/// and an optional base64-encoded secret (signing) key.
///
/// The `secret_key` field is omitted from JSON when it is `None`, making the
/// same type suitable for both full key pairs and public-key-only files.
///
/// # Examples
///
/// ```
/// use base64::{engine::general_purpose::STANDARD, Engine};
/// use ed25519_dalek::SigningKey;
/// use invariant_robotics::key_file::KeyFile;
///
/// // Build a key file from raw Ed25519 key material.
/// let sk_bytes = [0x42u8; 32];
/// let sk = SigningKey::from_bytes(&sk_bytes);
/// let vk = sk.verifying_key();
///
/// let kf = KeyFile {
///     kid: "robot-validator-1".to_string(),
///     public_key: STANDARD.encode(vk.as_bytes()),
///     secret_key: Some(STANDARD.encode(&sk_bytes)),
/// };
///
/// assert_eq!(kf.kid, "robot-validator-1");
/// assert!(kf.secret_key.is_some());
///
/// // Round-trip through JSON serialization.
/// let json = serde_json::to_string(&kf).unwrap();
/// let kf2: KeyFile = serde_json::from_str(&json).unwrap();
/// assert_eq!(kf2.kid, kf.kid);
/// assert_eq!(kf2.public_key, kf.public_key);
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyFile {
    pub kid: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
}

/// Validate that a KID string is safe for use as a filename and identifier.
///
/// Rules:
/// - Non-empty
/// - At most 128 bytes
/// - Contains only ASCII alphanumeric characters, hyphens (`-`), underscores (`_`),
///   dots (`.`), and colons (`:`)
///
/// # Examples
///
/// ```
/// use invariant_robotics::key_file::validate_kid;
///
/// // Valid KIDs.
/// assert!(validate_kid("my-key-1").is_ok());
/// assert!(validate_kid("ns:service_key.v2").is_ok());
/// assert!(validate_kid("UPPER_LOWER-123").is_ok());
///
/// // Empty string is rejected.
/// assert!(validate_kid("").is_err());
///
/// // Spaces are rejected.
/// assert!(validate_kid("bad kid").is_err());
///
/// // Slashes are rejected (would allow path traversal).
/// assert!(validate_kid("path/key").is_err());
///
/// // KIDs longer than 128 bytes are rejected.
/// let too_long = "a".repeat(129);
/// assert!(validate_kid(&too_long).is_err());
/// ```
pub fn validate_kid(kid: &str) -> Result<(), String> {
    if kid.is_empty() {
        return Err("KID must not be empty".to_string());
    }
    if kid.len() > 128 {
        return Err(format!("KID must be at most 128 bytes, got {}", kid.len()));
    }
    for ch in kid.chars() {
        if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | ':') {
            return Err(format!(
                "KID contains invalid character {:?}; only ASCII alphanumeric, '-', '_', '.', ':' are allowed",
                ch
            ));
        }
    }
    Ok(())
}

/// Compute a SHA-256 fingerprint of the raw public key bytes.
///
/// Returns the hex-encoded first 16 bytes (32 hex characters) of the SHA-256
/// digest, prefixed with `"SHA256:"`.
///
/// Example: `"SHA256:abcdef0123456789abcdef0123456789"`
///
/// # Examples
///
/// ```
/// use base64::{engine::general_purpose::STANDARD, Engine};
/// use ed25519_dalek::SigningKey;
/// use invariant_robotics::key_file::{fingerprint, KeyFile};
///
/// let sk = SigningKey::from_bytes(&[0x42u8; 32]);
/// let vk = sk.verifying_key();
///
/// let kf = KeyFile {
///     kid: "fp-test".to_string(),
///     public_key: STANDARD.encode(vk.as_bytes()),
///     secret_key: None,
/// };
///
/// let fp = fingerprint(&kf).expect("valid key produces a fingerprint");
///
/// // Fingerprint always starts with "SHA256:" followed by 32 lowercase hex chars.
/// assert!(fp.starts_with("SHA256:"));
/// assert_eq!(fp.len(), 39);
/// let hex_part = &fp[7..];
/// assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
///
/// // Fingerprint is deterministic: same key → same fingerprint.
/// assert_eq!(fingerprint(&kf).unwrap(), fp);
///
/// // Different keys produce different fingerprints.
/// let sk2 = SigningKey::from_bytes(&[0x99u8; 32]);
/// let kf2 = KeyFile {
///     kid: "fp-test-2".to_string(),
///     public_key: STANDARD.encode(sk2.verifying_key().as_bytes()),
///     secret_key: None,
/// };
/// assert_ne!(fingerprint(&kf2).unwrap(), fp);
/// ```
pub fn fingerprint(kf: &KeyFile) -> Result<String, String> {
    let pk_bytes = STANDARD
        .decode(&kf.public_key)
        .map_err(|e| format!("base64 decode public_key: {e}"))?;
    let digest = Sha256::digest(&pk_bytes);
    let mut hex = String::with_capacity(7 + 32); // "SHA256:" + 32 hex chars (16 bytes)
    hex.push_str("SHA256:");
    for b in &digest[..16] {
        write!(hex, "{b:02x}").unwrap();
    }
    Ok(hex)
}

/// Create a new KeyFile containing only the public key (secret_key set to None).
///
/// This is the safe way to share a key file with a third party: all signing
/// key material is removed while the public key and KID are preserved.
///
/// # Examples
///
/// ```
/// use base64::{engine::general_purpose::STANDARD, Engine};
/// use ed25519_dalek::SigningKey;
/// use invariant_robotics::key_file::{export_public_key, KeyFile};
///
/// let sk_bytes = [0x7Fu8; 32];
/// let sk = SigningKey::from_bytes(&sk_bytes);
/// let vk = sk.verifying_key();
///
/// let full_kf = KeyFile {
///     kid: "signing-key".to_string(),
///     public_key: STANDARD.encode(vk.as_bytes()),
///     secret_key: Some(STANDARD.encode(&sk_bytes)),
/// };
///
/// assert!(full_kf.secret_key.is_some());
///
/// let pub_kf = export_public_key(&full_kf);
///
/// // The secret key is removed.
/// assert!(pub_kf.secret_key.is_none());
/// // The KID and public key are preserved exactly.
/// assert_eq!(pub_kf.kid, full_kf.kid);
/// assert_eq!(pub_kf.public_key, full_kf.public_key);
///
/// // Calling export_public_key on a public-key-only file is a no-op.
/// let already_pub = export_public_key(&pub_kf);
/// assert!(already_pub.secret_key.is_none());
/// assert_eq!(already_pub.kid, full_kf.kid);
/// ```
pub fn export_public_key(kf: &KeyFile) -> KeyFile {
    KeyFile {
        kid: kf.kid.clone(),
        public_key: kf.public_key.clone(),
        secret_key: None,
    }
}

/// Write a key file to disk.
///
/// On Unix, if the key file contains a `secret_key`, the file is created
/// directly with mode `0600` (owner read/write only) via `OpenOptions::mode`
/// so that restricted permissions are established atomically — there is no
/// window between file creation and `chmod` where another process could read
/// the private key.  On non-Unix platforms, or for public-key-only files,
/// falls back to the regular [`write_key_file`] behaviour.
pub fn write_key_file_secure(path: &Path, kf: &KeyFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(kf)
        .map_err(|e| format!("failed to serialize key file: {e}"))?;

    #[cfg(unix)]
    if kf.secret_key.is_some() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("failed to write key file {}: {e}", path.display()))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("failed to write key file {}: {e}", path.display()))?;
        return Ok(());
    }

    std::fs::write(path, json)
        .map_err(|e| format!("failed to write key file {}: {e}", path.display()))
}

/// Load and parse a key file from disk.
///
/// Returns an error if the KID in the file does not pass [`validate_kid`].
pub fn load_key_file(path: &Path) -> Result<KeyFile, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read key file {}: {e}", path.display()))?;
    let kf: KeyFile = serde_json::from_str(&data)
        .map_err(|e| format!("failed to parse key file {}: {e}", path.display()))?;
    validate_kid(&kf.kid)
        .map_err(|e| format!("invalid KID in key file {}: {e}", path.display()))?;
    Ok(kf)
}

/// Extract a SigningKey + VerifyingKey + kid from a key file with a secret_key.
pub fn load_signing_key(kf: &KeyFile) -> Result<(SigningKey, VerifyingKey, String), String> {
    let sk_b64 = kf.secret_key.as_ref().ok_or("key file has no secret_key")?;
    let sk_bytes = STANDARD
        .decode(sk_b64)
        .map_err(|e| format!("base64 decode secret_key: {e}"))?;
    let sk_arr: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| "secret_key must be 32 bytes")?;
    let sk = SigningKey::from_bytes(&sk_arr);
    let vk = sk.verifying_key();
    Ok((sk, vk, kf.kid.clone()))
}

/// Extract a VerifyingKey + kid from a key file (only public_key needed).
pub fn load_verifying_key(kf: &KeyFile) -> Result<(VerifyingKey, String), String> {
    let pk_bytes = STANDARD
        .decode(&kf.public_key)
        .map_err(|e| format!("base64 decode public_key: {e}"))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| "public_key must be 32 bytes")?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("invalid public key: {e}"))?;
    Ok((vk, kf.kid.clone()))
}

/// Write a key file to disk.
pub fn write_key_file(path: &Path, kf: &KeyFile) -> Result<(), String> {
    let json = serde_json::to_string_pretty(kf)
        .map_err(|e| format!("failed to serialize key file: {e}"))?;
    std::fs::write(path, json)
        .map_err(|e| format!("failed to write key file {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_signing_key_bytes() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn make_key_file_with_secret() -> KeyFile {
        let sk_arr = make_signing_key_bytes();
        let sk = SigningKey::from_bytes(&sk_arr);
        let vk = sk.verifying_key();
        KeyFile {
            kid: "test-key-1".to_string(),
            public_key: STANDARD.encode(vk.as_bytes()),
            secret_key: Some(STANDARD.encode(sk_arr)),
        }
    }

    fn make_key_file_pubkey_only() -> KeyFile {
        let sk_arr = make_signing_key_bytes();
        let sk = SigningKey::from_bytes(&sk_arr);
        let vk = sk.verifying_key();
        KeyFile {
            kid: "test-key-pub".to_string(),
            public_key: STANDARD.encode(vk.as_bytes()),
            secret_key: None,
        }
    }

    fn write_to_tempfile(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    // --- load_key_file ---

    #[test]
    fn load_key_file_round_trips_full() {
        let kf = make_key_file_with_secret();
        let json = serde_json::to_string_pretty(&kf).unwrap();
        let tmp = write_to_tempfile(&json);
        let loaded = load_key_file(tmp.path()).unwrap();
        assert_eq!(loaded.kid, kf.kid);
        assert_eq!(loaded.public_key, kf.public_key);
        assert_eq!(loaded.secret_key, kf.secret_key);
    }

    #[test]
    fn load_key_file_round_trips_pubkey_only() {
        let kf = make_key_file_pubkey_only();
        let json = serde_json::to_string_pretty(&kf).unwrap();
        let tmp = write_to_tempfile(&json);
        let loaded = load_key_file(tmp.path()).unwrap();
        assert_eq!(loaded.kid, kf.kid);
        assert!(loaded.secret_key.is_none());
    }

    #[test]
    fn load_key_file_missing_file_returns_err() {
        let result = load_key_file(std::path::Path::new("/nonexistent/path/key.json"));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("failed to read key file"));
    }

    #[test]
    fn load_key_file_invalid_json_returns_err() {
        let tmp = write_to_tempfile("not json at all {{{");
        let result = load_key_file(tmp.path());
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("failed to parse key file"));
    }

    #[test]
    fn load_key_file_rejects_invalid_kid() {
        // A key file whose KID contains an invalid character (space) must be
        // rejected even though the JSON itself is valid.
        let kf_json =
            r#"{"kid":"bad kid here","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
        let tmp = write_to_tempfile(kf_json);
        let result = load_key_file(tmp.path());
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("invalid KID"));
    }

    #[test]
    fn load_key_file_rejects_empty_kid() {
        let kf_json = r#"{"kid":"","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
        let tmp = write_to_tempfile(kf_json);
        let result = load_key_file(tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid KID"));
    }

    // --- load_signing_key ---

    #[test]
    fn load_signing_key_succeeds_with_valid_key() {
        let kf = make_key_file_with_secret();
        let (sk, vk, kid) = load_signing_key(&kf).unwrap();
        assert_eq!(kid, "test-key-1");
        // The verifying key derived from loaded sk must match the stored public key.
        assert_eq!(
            STANDARD.encode(sk.verifying_key().as_bytes()),
            kf.public_key
        );
        assert_eq!(STANDARD.encode(vk.as_bytes()), kf.public_key);
    }

    #[test]
    fn load_signing_key_returns_err_when_no_secret_key() {
        let kf = make_key_file_pubkey_only();
        let result = load_signing_key(&kf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "key file has no secret_key");
    }

    #[test]
    fn load_signing_key_returns_err_on_bad_base64() {
        let kf = KeyFile {
            kid: "k".to_string(),
            public_key: STANDARD.encode([0u8; 32]),
            secret_key: Some("!!!not-valid-base64!!!".to_string()),
        };
        let result = load_signing_key(&kf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("base64 decode secret_key"));
    }

    #[test]
    fn load_signing_key_returns_err_on_wrong_length() {
        // Encode 16 bytes (not 32) as a valid base64 string.
        let kf = KeyFile {
            kid: "k".to_string(),
            public_key: STANDARD.encode([0u8; 32]),
            secret_key: Some(STANDARD.encode([0u8; 16])),
        };
        let result = load_signing_key(&kf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "secret_key must be 32 bytes");
    }

    // --- load_verifying_key ---

    #[test]
    fn load_verifying_key_succeeds_with_valid_key() {
        let kf = make_key_file_with_secret();
        let (vk, kid) = load_verifying_key(&kf).unwrap();
        assert_eq!(kid, "test-key-1");
        assert_eq!(STANDARD.encode(vk.as_bytes()), kf.public_key);
    }

    #[test]
    fn load_verifying_key_works_on_pubkey_only_file() {
        let kf = make_key_file_pubkey_only();
        let (vk, kid) = load_verifying_key(&kf).unwrap();
        assert_eq!(kid, "test-key-pub");
        assert_eq!(STANDARD.encode(vk.as_bytes()), kf.public_key);
    }

    #[test]
    fn load_verifying_key_returns_err_on_bad_base64() {
        let kf = KeyFile {
            kid: "k".to_string(),
            public_key: "!!!not-valid-base64!!!".to_string(),
            secret_key: None,
        };
        let result = load_verifying_key(&kf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("base64 decode public_key"));
    }

    #[test]
    fn load_verifying_key_returns_err_on_wrong_length() {
        let kf = KeyFile {
            kid: "k".to_string(),
            public_key: STANDARD.encode([0u8; 16]),
            secret_key: None,
        };
        let result = load_verifying_key(&kf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "public_key must be 32 bytes");
    }

    #[test]
    fn load_verifying_key_returns_err_on_invalid_point() {
        // Find a 32-byte pattern that ed25519-dalek v2 rejects as an invalid
        // compressed Edwards point.  Not all 32-byte values decode to a curve
        // point, so we scan until we find one that VerifyingKey::from_bytes
        // rejects, then assert that load_verifying_key surfaces the right error.
        let mut invalid_bytes: Option<[u8; 32]> = None;
        'outer: for hi in 0u8..=127u8 {
            for lo in 0u8..=255u8 {
                let mut b = [lo; 32];
                b[31] = hi; // high byte sets y and the sign bit
                if VerifyingKey::from_bytes(&b).is_err() {
                    invalid_bytes = Some(b);
                    break 'outer;
                }
            }
        }
        let invalid_bytes = invalid_bytes.expect(
            "should find at least one invalid compressed Ed25519 point in the search space",
        );
        let kf = KeyFile {
            kid: "k".to_string(),
            public_key: STANDARD.encode(invalid_bytes),
            secret_key: None,
        };
        let result = load_verifying_key(&kf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid public key"));
    }

    // --- write_key_file ---

    #[test]
    fn write_key_file_produces_readable_file() {
        let kf = make_key_file_with_secret();
        let tmp = NamedTempFile::new().unwrap();
        write_key_file(tmp.path(), &kf).unwrap();
        let loaded = load_key_file(tmp.path()).unwrap();
        assert_eq!(loaded.kid, kf.kid);
        assert_eq!(loaded.public_key, kf.public_key);
        assert_eq!(loaded.secret_key, kf.secret_key);
    }

    #[test]
    fn write_key_file_omits_secret_key_field_when_none() {
        let kf = make_key_file_pubkey_only();
        let tmp = NamedTempFile::new().unwrap();
        write_key_file(tmp.path(), &kf).unwrap();
        let raw = std::fs::read_to_string(tmp.path()).unwrap();
        // The `skip_serializing_if` annotation must suppress the field entirely.
        assert!(!raw.contains("secret_key"));
    }

    #[test]
    fn write_key_file_bad_path_returns_err() {
        let kf = make_key_file_pubkey_only();
        let result = write_key_file(std::path::Path::new("/nonexistent/dir/key.json"), &kf);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("failed to write key file"));
    }

    // --- validate_kid ---

    #[test]
    fn validate_kid_accepts_valid_kids() {
        let valid = [
            "my-key",
            "key_1",
            "key.v2",
            "ns:key-id_01",
            "A",
            "z9",
            "UPPER-lower-123",
            // Exactly 128 bytes
            &"a".repeat(128),
        ];
        for kid in &valid {
            assert!(
                validate_kid(kid).is_ok(),
                "expected valid KID {:?} to pass",
                kid
            );
        }
    }

    #[test]
    fn validate_kid_rejects_empty_string() {
        let result = validate_kid("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must not be empty"));
    }

    #[test]
    fn validate_kid_rejects_kid_over_128_bytes() {
        let long_kid = "a".repeat(129);
        let result = validate_kid(&long_kid);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("128 bytes"));
    }

    #[test]
    fn validate_kid_rejects_space() {
        let result = validate_kid("bad kid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid character"));
    }

    #[test]
    fn validate_kid_rejects_slash() {
        let result = validate_kid("path/to/key");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid character"));
    }

    #[test]
    fn validate_kid_rejects_at_sign() {
        let result = validate_kid("user@domain");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid character"));
    }

    #[test]
    fn validate_kid_rejects_non_ascii() {
        let result = validate_kid("kéy");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid character"));
    }

    #[test]
    fn validate_kid_rejects_null_byte() {
        let result = validate_kid("key\0id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid character"));
    }

    // --- fingerprint ---

    #[test]
    fn fingerprint_returns_sha256_prefixed_hex() {
        let kf = make_key_file_with_secret();
        let fp = fingerprint(&kf).unwrap();
        assert!(
            fp.starts_with("SHA256:"),
            "fingerprint should start with 'SHA256:': {fp}"
        );
        // Prefix (7 chars) + 32 hex chars = 39 total
        assert_eq!(fp.len(), 39, "fingerprint should be 39 chars long: {fp}");
        // Hex portion must be lowercase hex
        let hex_part = &fp[7..];
        assert!(
            hex_part
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "hex portion must be lowercase hex: {hex_part}"
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let kf = make_key_file_with_secret();
        let fp1 = fingerprint(&kf).unwrap();
        let fp2 = fingerprint(&kf).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_differs_for_different_keys() {
        let kf1 = make_key_file_with_secret();
        // Build a second key file with different key material.
        let sk2 = SigningKey::from_bytes(&[0x99u8; 32]);
        let vk2 = sk2.verifying_key();
        let kf2 = KeyFile {
            kid: "other-key".to_string(),
            public_key: STANDARD.encode(vk2.as_bytes()),
            secret_key: None,
        };
        assert_ne!(fingerprint(&kf1).unwrap(), fingerprint(&kf2).unwrap());
    }

    #[test]
    fn fingerprint_returns_err_on_bad_base64() {
        let kf = KeyFile {
            kid: "k".to_string(),
            public_key: "!!!not-valid-base64!!!".to_string(),
            secret_key: None,
        };
        let result = fingerprint(&kf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("base64 decode public_key"));
    }

    #[test]
    fn fingerprint_known_value() {
        // Compute expected fingerprint independently: SHA-256 of the 32 zero bytes,
        // take first 16 bytes as lowercase hex, prefix with "SHA256:".
        let pk_bytes = [0u8; 32];
        let digest = Sha256::digest(pk_bytes);
        let expected_hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
        let expected = format!("SHA256:{expected_hex}");

        let kf = KeyFile {
            kid: "k".to_string(),
            public_key: STANDARD.encode(pk_bytes),
            secret_key: None,
        };
        assert_eq!(fingerprint(&kf).unwrap(), expected);
    }

    // --- export_public_key ---

    #[test]
    fn export_public_key_strips_secret_key() {
        let kf = make_key_file_with_secret();
        assert!(kf.secret_key.is_some());
        let exported = export_public_key(&kf);
        assert!(exported.secret_key.is_none());
    }

    #[test]
    fn export_public_key_preserves_kid_and_public_key() {
        let kf = make_key_file_with_secret();
        let exported = export_public_key(&kf);
        assert_eq!(exported.kid, kf.kid);
        assert_eq!(exported.public_key, kf.public_key);
    }

    #[test]
    fn export_public_key_idempotent_on_pubkey_only_file() {
        let kf = make_key_file_pubkey_only();
        let exported = export_public_key(&kf);
        assert!(exported.secret_key.is_none());
        assert_eq!(exported.kid, kf.kid);
        assert_eq!(exported.public_key, kf.public_key);
    }

    // --- write_key_file_secure ---

    #[test]
    fn write_key_file_secure_produces_readable_file() {
        let kf = make_key_file_with_secret();
        let tmp = NamedTempFile::new().unwrap();
        write_key_file_secure(tmp.path(), &kf).unwrap();
        let loaded = load_key_file(tmp.path()).unwrap();
        assert_eq!(loaded.kid, kf.kid);
        assert_eq!(loaded.public_key, kf.public_key);
        assert_eq!(loaded.secret_key, kf.secret_key);
    }

    #[cfg(unix)]
    #[test]
    fn write_key_file_secure_sets_0600_for_secret_key() {
        use std::os::unix::fs::PermissionsExt;
        let kf = make_key_file_with_secret();
        let tmp = NamedTempFile::new().unwrap();
        write_key_file_secure(tmp.path(), &kf).unwrap();
        let meta = std::fs::metadata(tmp.path()).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600 permissions, got {:o}", mode);
    }

    #[cfg(unix)]
    #[test]
    fn write_key_file_secure_does_not_force_0600_for_pubkey_only() {
        // For a pubkey-only file, write_key_file_secure should NOT restrict
        // permissions (it only applies 0600 when secret_key is present).
        // We just verify the file is written successfully and is readable.
        let kf = make_key_file_pubkey_only();
        let tmp = NamedTempFile::new().unwrap();
        write_key_file_secure(tmp.path(), &kf).unwrap();
        let loaded = load_key_file(tmp.path()).unwrap();
        assert_eq!(loaded.kid, kf.kid);
    }

    #[test]
    fn write_key_file_secure_bad_path_returns_err() {
        let kf = make_key_file_pubkey_only();
        let result = write_key_file_secure(std::path::Path::new("/nonexistent/dir/key.json"), &kf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to write key file"));
    }
}
