//! Key file management: load, save, validate, and decode Ed25519 key files.
//!
//! The canonical key file format is JSON:
//! ```json
//! {
//!   "kid": "invariant-001",
//!   "algorithm": "Ed25519",
//!   "signing_key": "<base64-encoded 32-byte Ed25519 signing key>",
//!   "verifying_key": "<base64-encoded 32-byte Ed25519 verifying key>"
//! }
//! ```

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// On-disk JSON key file format for Ed25519 keypairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    /// Key identifier — used for key lookup in trusted key maps and audit trails.
    pub kid: String,
    /// Algorithm identifier. Must be `"Ed25519"`.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Base64-encoded 32-byte Ed25519 signing (private) key.
    pub signing_key: String,
    /// Base64-encoded 32-byte Ed25519 verifying (public) key.
    pub verifying_key: String,
}

fn default_algorithm() -> String {
    "Ed25519".to_string()
}

/// Decoded key material ready for cryptographic operations.
pub struct DecodedKeyFile {
    pub kid: String,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

/// Custom Debug implementation that redacts signing key bytes.
impl std::fmt::Debug for DecodedKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedKeyFile")
            .field("kid", &self.kid)
            .field("signing_key", &"[REDACTED]")
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

impl DecodedKeyFile {
    /// Build a trusted key map containing just this key, suitable for passing
    /// to `ValidatorConfig::new`.
    pub fn trusted_keys(&self) -> HashMap<String, VerifyingKey> {
        let mut map = HashMap::new();
        map.insert(self.kid.clone(), self.verifying_key);
        map
    }
}

/// Errors that can occur when loading or validating a key file.
#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error("failed to read key file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse key file JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("kid must not be empty")]
    EmptyKid,

    #[error("unsupported algorithm {0:?}, expected \"Ed25519\"")]
    UnsupportedAlgorithm(String),

    #[error("failed to base64-decode signing_key: {0}")]
    SigningKeyBase64(base64::DecodeError),

    #[error("signing_key must be exactly 32 bytes, got {0}")]
    SigningKeyLength(usize),

    #[error("failed to base64-decode verifying_key: {0}")]
    VerifyingKeyBase64(base64::DecodeError),

    #[error("verifying_key must be exactly 32 bytes, got {0}")]
    VerifyingKeyLength(usize),

    #[error("invalid verifying key: {0}")]
    InvalidVerifyingKey(String),

    #[error("signing_key and verifying_key do not form a valid keypair")]
    KeypairMismatch,

    #[error("failed to serialize key file: {0}")]
    Serialization(serde_json::Error),

    #[error("failed to write key file: {0}")]
    WriteIo(std::io::Error),
}

impl KeyFile {
    /// Create a new `KeyFile` from a signing key and key identifier.
    pub fn from_signing_key(kid: &str, signing_key: &SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        KeyFile {
            kid: kid.to_string(),
            algorithm: "Ed25519".to_string(),
            signing_key: STANDARD.encode(signing_key.to_bytes()),
            verifying_key: STANDARD.encode(verifying_key.to_bytes()),
        }
    }

    /// Load a key file from disk.
    pub fn load(path: &Path) -> Result<Self, KeyFileError> {
        let data = std::fs::read_to_string(path)?;
        let key_file: KeyFile = serde_json::from_str(&data)?;
        Ok(key_file)
    }

    /// Save the key file to disk. Refuses to overwrite an existing file.
    pub fn save(&self, path: &Path) -> Result<(), KeyFileError> {
        if path.exists() {
            return Err(KeyFileError::WriteIo(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("file already exists: {}", path.display()),
            )));
        }
        let json = serde_json::to_string_pretty(self).map_err(KeyFileError::Serialization)?;
        std::fs::write(path, json).map_err(KeyFileError::WriteIo)
    }

    /// Validate the key file format and decode the key material.
    ///
    /// Checks:
    /// - `kid` is non-empty
    /// - `algorithm` is `"Ed25519"`
    /// - `signing_key` is valid base64 encoding 32 bytes
    /// - `verifying_key` is valid base64 encoding 32 bytes and a valid Ed25519 point
    /// - The signing key and verifying key form a matching keypair
    pub fn decode(&self) -> Result<DecodedKeyFile, KeyFileError> {
        if self.kid.is_empty() {
            return Err(KeyFileError::EmptyKid);
        }

        if self.algorithm != "Ed25519" {
            return Err(KeyFileError::UnsupportedAlgorithm(self.algorithm.clone()));
        }

        let sk_bytes = STANDARD
            .decode(&self.signing_key)
            .map_err(KeyFileError::SigningKeyBase64)?;
        let sk_array: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|v: Vec<u8>| KeyFileError::SigningKeyLength(v.len()))?;
        let signing_key = SigningKey::from_bytes(&sk_array);

        let vk_bytes = STANDARD
            .decode(&self.verifying_key)
            .map_err(KeyFileError::VerifyingKeyBase64)?;
        let vk_array: [u8; 32] = vk_bytes
            .try_into()
            .map_err(|v: Vec<u8>| KeyFileError::VerifyingKeyLength(v.len()))?;
        let verifying_key = VerifyingKey::from_bytes(&vk_array)
            .map_err(|e| KeyFileError::InvalidVerifyingKey(e.to_string()))?;

        // Verify the keypair is consistent.
        if signing_key.verifying_key() != verifying_key {
            return Err(KeyFileError::KeypairMismatch);
        }

        Ok(DecodedKeyFile {
            kid: self.kid.clone(),
            signing_key,
            verifying_key,
        })
    }

    /// Load a key file from disk and decode it in one step.
    pub fn load_and_decode(path: &Path) -> Result<DecodedKeyFile, KeyFileError> {
        Self::load(path)?.decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn gen_key_file() -> KeyFile {
        let sk = SigningKey::generate(&mut OsRng);
        KeyFile::from_signing_key("test-key-001", &sk)
    }

    #[test]
    fn roundtrip_from_signing_key() {
        let kf = gen_key_file();
        assert_eq!(kf.kid, "test-key-001");
        assert_eq!(kf.algorithm, "Ed25519");
        let decoded = kf.decode().unwrap();
        assert_eq!(decoded.kid, "test-key-001");
    }

    #[test]
    fn decode_validates_keypair_consistency() {
        let kf = gen_key_file();
        let decoded = kf.decode().unwrap();
        assert_eq!(decoded.signing_key.verifying_key(), decoded.verifying_key);
    }

    #[test]
    fn decode_rejects_empty_kid() {
        let mut kf = gen_key_file();
        kf.kid = "".to_string();
        let err = kf.decode().unwrap_err();
        assert!(matches!(err, KeyFileError::EmptyKid));
    }

    #[test]
    fn decode_rejects_unsupported_algorithm() {
        let mut kf = gen_key_file();
        kf.algorithm = "RSA".to_string();
        let err = kf.decode().unwrap_err();
        assert!(matches!(err, KeyFileError::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn decode_rejects_invalid_base64_signing_key() {
        let mut kf = gen_key_file();
        kf.signing_key = "not valid base64!!!".to_string();
        let err = kf.decode().unwrap_err();
        assert!(matches!(err, KeyFileError::SigningKeyBase64(_)));
    }

    #[test]
    fn decode_rejects_wrong_length_signing_key() {
        let mut kf = gen_key_file();
        kf.signing_key = STANDARD.encode(vec![0u8; 16]);
        let err = kf.decode().unwrap_err();
        assert!(matches!(err, KeyFileError::SigningKeyLength(16)));
    }

    #[test]
    fn decode_rejects_invalid_base64_verifying_key() {
        let mut kf = gen_key_file();
        kf.verifying_key = "%%%bad%%%".to_string();
        let err = kf.decode().unwrap_err();
        assert!(matches!(err, KeyFileError::VerifyingKeyBase64(_)));
    }

    #[test]
    fn decode_rejects_wrong_length_verifying_key() {
        let mut kf = gen_key_file();
        kf.verifying_key = STANDARD.encode(vec![0u8; 48]);
        let err = kf.decode().unwrap_err();
        assert!(matches!(err, KeyFileError::VerifyingKeyLength(48)));
    }

    #[test]
    fn decode_rejects_mismatched_keypair() {
        let mut kf = gen_key_file();
        // Replace verifying key with one from a different keypair
        let other = SigningKey::generate(&mut OsRng);
        kf.verifying_key = STANDARD.encode(other.verifying_key().to_bytes());
        let err = kf.decode().unwrap_err();
        assert!(matches!(err, KeyFileError::KeypairMismatch));
    }

    #[test]
    fn json_roundtrip() {
        let kf = gen_key_file();
        let json = serde_json::to_string_pretty(&kf).unwrap();
        let parsed: KeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kid, kf.kid);
        assert_eq!(parsed.algorithm, kf.algorithm);
        assert_eq!(parsed.signing_key, kf.signing_key);
        assert_eq!(parsed.verifying_key, kf.verifying_key);
    }

    #[test]
    fn json_without_algorithm_uses_default() {
        let kf = gen_key_file();
        // Serialize, remove algorithm field, deserialize
        let json = format!(
            r#"{{"kid":"{}","signing_key":"{}","verifying_key":"{}"}}"#,
            kf.kid, kf.signing_key, kf.verifying_key,
        );
        let parsed: KeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.algorithm, "Ed25519");
        parsed.decode().unwrap();
    }

    #[test]
    fn trusted_keys_map() {
        let kf = gen_key_file();
        let decoded = kf.decode().unwrap();
        let map = decoded.trusted_keys();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("test-key-001"));
        assert_eq!(map["test-key-001"], decoded.verifying_key);
    }

    #[test]
    fn save_refuses_overwrite() {
        let kf = gen_key_file();
        let dir = std::env::temp_dir().join("invariant_key_test_overwrite");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("existing.json");
        std::fs::write(&path, "existing").unwrap();
        let err = kf.save(&path).unwrap_err();
        assert!(matches!(err, KeyFileError::WriteIo(_)));
        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let kf = gen_key_file();
        let dir = std::env::temp_dir().join("invariant_key_test_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_keys.json");
        let _ = std::fs::remove_file(&path); // ensure clean
        kf.save(&path).unwrap();
        let loaded = KeyFile::load(&path).unwrap();
        assert_eq!(loaded.kid, kf.kid);
        assert_eq!(loaded.algorithm, kf.algorithm);
        assert_eq!(loaded.signing_key, kf.signing_key);
        assert_eq!(loaded.verifying_key, kf.verifying_key);
        loaded.decode().unwrap();
        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_and_decode_shortcut() {
        let kf = gen_key_file();
        let dir = std::env::temp_dir().join("invariant_key_test_shortcut");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("shortcut_keys.json");
        let _ = std::fs::remove_file(&path);
        kf.save(&path).unwrap();
        let decoded = KeyFile::load_and_decode(&path).unwrap();
        assert_eq!(decoded.kid, "test-key-001");
        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
