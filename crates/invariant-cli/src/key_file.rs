use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyFile {
    pub kid: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
}

/// Load and parse a key file from disk.
pub fn load_key_file(path: &Path) -> Result<KeyFile, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read key file {}: {e}", path.display()))?;
    serde_json::from_str(&data)
        .map_err(|e| format!("failed to parse key file {}: {e}", path.display()))
}

/// Extract a SigningKey + VerifyingKey + kid from a key file with a secret_key.
pub fn load_signing_key(kf: &KeyFile) -> Result<(SigningKey, VerifyingKey, String), String> {
    let sk_b64 = kf.secret_key.as_ref().ok_or("key file has no secret_key")?;
    let sk_bytes = STANDARD.decode(sk_b64).map_err(|e| format!("base64 decode secret_key: {e}"))?;
    let sk_arr: [u8; 32] = sk_bytes.try_into().map_err(|_| "secret_key must be 32 bytes")?;
    let sk = SigningKey::from_bytes(&sk_arr);
    let vk = sk.verifying_key();
    Ok((sk, vk, kf.kid.clone()))
}

/// Extract a VerifyingKey + kid from a key file (only public_key needed).
pub fn load_verifying_key(kf: &KeyFile) -> Result<(VerifyingKey, String), String> {
    let pk_bytes = STANDARD.decode(&kf.public_key).map_err(|e| format!("base64 decode public_key: {e}"))?;
    let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| "public_key must be 32 bytes")?;
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
        let invalid_bytes = invalid_bytes
            .expect("should find at least one invalid compressed Ed25519 point in the search space");
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
}
