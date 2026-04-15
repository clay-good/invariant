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
///
/// # Security note
/// The `signing_key` field is excluded from all normal serde serializations
/// (`#[serde(skip_serializing)]`) to prevent the private key from being
/// accidentally included in logs, API responses, or debug output.
/// The only legitimate write path is [`KeyFile::save`], which uses
/// [`KeyFile::to_disk_json`] to produce a JSON string that explicitly
/// includes the signing key for on-disk storage.
///
/// `Clone` is intentionally NOT derived. `KeyFile` should be loaded,
/// decoded, and saved — never cloned — to limit the number of in-memory
/// copies of private key material.
#[derive(Serialize, Deserialize)]
pub struct KeyFile {
    /// Key identifier — used for key lookup in trusted key maps and audit trails.
    pub kid: String,
    /// Algorithm identifier. Must be `"Ed25519"`.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Base64-encoded 32-byte Ed25519 signing (private) key.
    ///
    /// Excluded from normal serialization. Use [`KeyFile::to_disk_json`] for
    /// the one legitimate path that needs to write this to persistent storage.
    #[serde(skip_serializing)]
    pub signing_key: String,
    /// Base64-encoded 32-byte Ed25519 verifying (public) key.
    pub verifying_key: String,
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("signing_key", &"[REDACTED]")
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

fn default_algorithm() -> String {
    "Ed25519".to_string()
}

/// Decoded key material ready for cryptographic operations.
pub struct DecodedKeyFile {
    /// Key identifier matching the source `KeyFile::kid`.
    pub kid: String,
    /// Ed25519 signing (private) key.
    pub signing_key: SigningKey,
    /// Ed25519 verifying (public) key corresponding to `signing_key`.
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
    /// The key file could not be read from disk.
    #[error("failed to read key file: {0}")]
    Io(#[from] std::io::Error),

    /// The file contents could not be deserialized as JSON.
    #[error("failed to parse key file JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// The `kid` field is an empty string.
    #[error("kid must not be empty")]
    EmptyKid,

    /// The `algorithm` field is not `"Ed25519"`.
    #[error("unsupported algorithm {0:?}, expected \"Ed25519\"")]
    UnsupportedAlgorithm(String),

    /// The `signing_key` field is not valid base64.
    #[error("failed to base64-decode signing_key: {0}")]
    SigningKeyBase64(base64::DecodeError),

    /// The `signing_key` decoded to a byte slice that is not 32 bytes.
    #[error("signing_key must be exactly 32 bytes, got {0}")]
    SigningKeyLength(usize),

    /// The `verifying_key` field is not valid base64.
    #[error("failed to base64-decode verifying_key: {0}")]
    VerifyingKeyBase64(base64::DecodeError),

    /// The `verifying_key` decoded to a byte slice that is not 32 bytes.
    #[error("verifying_key must be exactly 32 bytes, got {0}")]
    VerifyingKeyLength(usize),

    /// The `verifying_key` bytes do not represent a valid Ed25519 point.
    #[error("invalid verifying key: {0}")]
    InvalidVerifyingKey(String),

    /// The signing key and verifying key do not form a matching keypair.
    #[error("signing_key and verifying_key do not form a valid keypair")]
    KeypairMismatch,

    /// The key file could not be serialized to JSON for writing.
    #[error("failed to serialize key file: {0}")]
    Serialization(serde_json::Error),

    /// Writing the serialized JSON to disk failed.
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

    /// Serialize this key file to a JSON string suitable for writing to disk.
    ///
    /// Unlike the standard [`serde_json::to_string`] path (which omits
    /// `signing_key` due to `#[serde(skip_serializing)]`), this method
    /// explicitly includes the signing key. It must only be called from
    /// [`KeyFile::save`] or equivalent on-disk write paths.
    pub fn to_disk_json(&self) -> Result<String, serde_json::Error> {
        // Build a temporary value that captures all four fields explicitly,
        // bypassing the skip_serializing attribute.
        let map = serde_json::json!({
            "kid": self.kid,
            "algorithm": self.algorithm,
            "signing_key": self.signing_key,
            "verifying_key": self.verifying_key,
        });
        serde_json::to_string_pretty(&map)
    }

    /// Save the key file to disk. Refuses to overwrite an existing file.
    ///
    /// Uses `create_new(true)` to atomically prevent overwriting an existing
    /// file, eliminating the TOCTOU race that a separate exists()-then-write
    /// pattern would introduce. On Unix the file is created with mode 0o600
    /// so it is readable only by the owning user.
    pub fn save(&self, path: &Path) -> Result<(), KeyFileError> {
        let json = self.to_disk_json().map_err(KeyFileError::Serialization)?;

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(KeyFileError::WriteIo)?;
            file.write_all(json.as_bytes())
                .map_err(KeyFileError::WriteIo)?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(KeyFileError::WriteIo)?;
            file.write_all(json.as_bytes())
                .map_err(KeyFileError::WriteIo)?;
        }

        Ok(())
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

// ---------------------------------------------------------------------------
// KeyStore trait — abstract key storage (Step 32)
// ---------------------------------------------------------------------------

/// Errors from key store operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// The signing operation itself failed.
    #[error("signing failed: {reason}")]
    SigningFailed {
        /// Human-readable description of why signing failed.
        reason: String,
    },

    /// The key store backend is not available (e.g. hardware not present).
    #[error("key store unavailable: {reason}")]
    Unavailable {
        /// Human-readable description of why the backend is unavailable.
        reason: String,
    },

    /// No key with the requested identifier was found in the store.
    #[error("key not found: {kid}")]
    KeyNotFound {
        /// The key identifier that was not found.
        kid: String,
    },

    /// The requested backend name is not recognized.
    #[error("backend not supported: {backend}")]
    UnsupportedBackend {
        /// The unrecognized backend name.
        backend: String,
    },
}

/// Abstract key storage backend (Section 8.3, Step 32).
///
/// Implementations provide Ed25519 signing and public key retrieval.
/// The private key may reside in memory (file backend), in the OS keyring
/// (staging), or in a hardware security module (production).
///
/// The trait is object-safe so it can be used as `Box<dyn KeyStore>`.
pub trait KeyStore: Send + Sync + std::fmt::Debug {
    /// Key identifier for this key store.
    fn kid(&self) -> &str;

    /// Sign `payload` with the stored private key.
    ///
    /// Returns the raw Ed25519 signature bytes (64 bytes).
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, KeyStoreError>;

    /// Return the Ed25519 verifying (public) key.
    fn verifying_key(&self) -> Result<VerifyingKey, KeyStoreError>;

    /// Backend name for diagnostics (e.g. "file", "os-keyring", "tpm", "yubihsm").
    fn backend_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// FileKeyStore — file-based implementation (Development / Forge mode)
// ---------------------------------------------------------------------------

/// File-based key store that holds the Ed25519 signing key in memory.
///
/// This is the default backend for development and testing (Forge mode).
/// The private key is loaded from a JSON file and held in process memory.
pub struct FileKeyStore {
    kid: String,
    signing_key: SigningKey,
    vk: VerifyingKey,
}

impl FileKeyStore {
    /// Create from a decoded key file.
    pub fn from_decoded(decoded: DecodedKeyFile) -> Self {
        let vk = decoded.verifying_key;
        Self {
            kid: decoded.kid,
            signing_key: decoded.signing_key,
            vk,
        }
    }

    /// Create from a raw signing key and key identifier.
    pub fn from_signing_key(kid: String, signing_key: SigningKey) -> Self {
        let vk = signing_key.verifying_key();
        Self {
            kid,
            signing_key,
            vk,
        }
    }

    /// Load from a key file on disk.
    pub fn load(path: &Path) -> Result<Self, KeyFileError> {
        let decoded = KeyFile::load_and_decode(path)?;
        Ok(Self::from_decoded(decoded))
    }
}

impl KeyStore for FileKeyStore {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(payload);
        Ok(sig.to_bytes().to_vec())
    }

    fn verifying_key(&self) -> Result<VerifyingKey, KeyStoreError> {
        Ok(self.vk)
    }

    fn backend_name(&self) -> &str {
        "file"
    }
}

impl std::fmt::Debug for FileKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeyStore")
            .field("kid", &self.kid)
            .field("backend", &"file")
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// OsKeyringStore — OS keyring backend (Staging / Shadow mode)
// ---------------------------------------------------------------------------

/// OS keyring key store stub (macOS Keychain, Linux kernel keyring).
///
/// This backend stores the signing key in the operating system's credential
/// manager rather than a plaintext file. It provides OS-level access control.
///
/// **Status**: Stub implementation. Returns `Unavailable` for all operations.
/// A full implementation would use platform-specific APIs:
/// - macOS: Security.framework / `security` CLI
/// - Linux: kernel keyring (`keyctl`) or libsecret
/// - Windows: Windows Credential Manager
#[derive(Debug)]
pub struct OsKeyringStore {
    kid: String,
}

impl OsKeyringStore {
    /// Create a reference to an OS keyring entry.
    pub fn new(kid: String) -> Self {
        Self { kid }
    }
}

impl KeyStore for OsKeyringStore {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        Err(KeyStoreError::Unavailable {
            reason: "OS keyring backend not yet implemented — use file backend for development"
                .into(),
        })
    }

    fn verifying_key(&self) -> Result<VerifyingKey, KeyStoreError> {
        Err(KeyStoreError::Unavailable {
            reason: "OS keyring backend not yet implemented".into(),
        })
    }

    fn backend_name(&self) -> &str {
        "os-keyring"
    }
}

// ---------------------------------------------------------------------------
// TpmKeyStore — TPM 2.0 backend (Production / Guardian mode)
// ---------------------------------------------------------------------------

/// TPM 2.0 hardware security module key store stub.
///
/// In production, the signing key is generated inside the TPM and never
/// leaves the hardware. Signing operations are performed by the TPM.
///
/// **Status**: Stub implementation. Returns `Unavailable` for all operations.
/// A full implementation would use the `tss-esapi` crate for TPM 2.0 access.
#[derive(Debug)]
pub struct TpmKeyStore {
    kid: String,
}

impl TpmKeyStore {
    /// Create a reference to a TPM-stored key.
    pub fn new(kid: String) -> Self {
        Self { kid }
    }
}

impl KeyStore for TpmKeyStore {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        Err(KeyStoreError::Unavailable {
            reason:
                "TPM 2.0 backend not yet implemented — requires tss-esapi crate and TPM hardware"
                    .into(),
        })
    }

    fn verifying_key(&self) -> Result<VerifyingKey, KeyStoreError> {
        Err(KeyStoreError::Unavailable {
            reason: "TPM 2.0 backend not yet implemented".into(),
        })
    }

    fn backend_name(&self) -> &str {
        "tpm"
    }
}

// ---------------------------------------------------------------------------
// YubiHsmKeyStore — YubiHSM 2 backend (Production / Guardian mode)
// ---------------------------------------------------------------------------

/// YubiHSM 2 hardware security module key store stub.
///
/// The YubiHSM is a USB-attached HSM commonly used in server environments.
/// Keys are generated on-device and signing operations never expose the
/// private key to the host.
///
/// **Status**: Stub implementation. Returns `Unavailable` for all operations.
/// A full implementation would use the `yubihsm` crate.
#[derive(Debug)]
pub struct YubiHsmKeyStore {
    kid: String,
}

impl YubiHsmKeyStore {
    /// Create a reference to a YubiHSM-stored key.
    pub fn new(kid: String) -> Self {
        Self { kid }
    }
}

impl KeyStore for YubiHsmKeyStore {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        Err(KeyStoreError::Unavailable {
            reason:
                "YubiHSM backend not yet implemented — requires yubihsm crate and YubiHSM 2 device"
                    .into(),
        })
    }

    fn verifying_key(&self) -> Result<VerifyingKey, KeyStoreError> {
        Err(KeyStoreError::Unavailable {
            reason: "YubiHSM backend not yet implemented".into(),
        })
    }

    fn backend_name(&self) -> &str {
        "yubihsm"
    }
}

// ---------------------------------------------------------------------------
// Factory: create a KeyStore from a backend name
// ---------------------------------------------------------------------------

/// Create a `Box<dyn KeyStore>` from a backend name and key identifier.
///
/// Supported backends:
/// - `"file"`: Load from a JSON key file at `path` (requires `path`).
/// - `"os-keyring"`: OS keyring stub (not yet implemented).
/// - `"tpm"`: TPM 2.0 stub (not yet implemented).
/// - `"yubihsm"`: YubiHSM 2 stub (not yet implemented).
pub fn open_key_store(
    backend: &str,
    kid: &str,
    path: Option<&Path>,
) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    match backend {
        "file" => {
            let p = path.ok_or_else(|| KeyStoreError::Unavailable {
                reason: "file backend requires a key file path".into(),
            })?;
            let store = FileKeyStore::load(p).map_err(|e| KeyStoreError::Unavailable {
                reason: e.to_string(),
            })?;
            Ok(Box::new(store))
        }
        "os-keyring" => Ok(Box::new(OsKeyringStore::new(kid.to_string()))),
        "tpm" => Ok(Box::new(TpmKeyStore::new(kid.to_string()))),
        "yubihsm" => Ok(Box::new(YubiHsmKeyStore::new(kid.to_string()))),
        other => Err(KeyStoreError::UnsupportedBackend {
            backend: other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

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
        // Use to_disk_json() — the only serialization path that includes
        // the private signing_key field.
        let kf = gen_key_file();
        let json = kf.to_disk_json().unwrap();
        let parsed: KeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kid, kf.kid);
        assert_eq!(parsed.algorithm, kf.algorithm);
        assert_eq!(parsed.signing_key, kf.signing_key);
        assert_eq!(parsed.verifying_key, kf.verifying_key);
    }

    #[test]
    fn normal_serialization_omits_signing_key() {
        // Verify that the skip_serializing attribute works: a standard
        // serde_json serialization must NOT include the signing_key field.
        let kf = gen_key_file();
        let json = serde_json::to_string(&kf).unwrap();
        assert!(
            !json.contains("signing_key"),
            "signing_key must not appear in standard serde output: {json}"
        );
        assert!(json.contains("verifying_key"));
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
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("existing.json");
        std::fs::write(&path, "existing").unwrap();
        let err = kf.save(&path).unwrap_err();
        assert!(matches!(err, KeyFileError::WriteIo(_)));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let kf = gen_key_file();
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("test_keys.json");
        kf.save(&path).unwrap();
        let loaded = KeyFile::load(&path).unwrap();
        assert_eq!(loaded.kid, kf.kid);
        assert_eq!(loaded.algorithm, kf.algorithm);
        assert_eq!(loaded.signing_key, kf.signing_key);
        assert_eq!(loaded.verifying_key, kf.verifying_key);
        loaded.decode().unwrap();
    }

    #[test]
    fn load_and_decode_shortcut() {
        let kf = gen_key_file();
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("shortcut_keys.json");
        kf.save(&path).unwrap();
        let decoded = KeyFile::load_and_decode(&path).unwrap();
        assert_eq!(decoded.kid, "test-key-001");
    }

    // -----------------------------------------------------------------------
    // KeyStore trait tests (Step 32)
    // -----------------------------------------------------------------------

    #[test]
    fn file_key_store_signs_and_verifies() {
        use ed25519_dalek::Verifier;

        let sk = SigningKey::generate(&mut OsRng);
        let store = FileKeyStore::from_signing_key("fks-kid".into(), sk);

        assert_eq!(store.kid(), "fks-kid");
        assert_eq!(store.backend_name(), "file");

        let payload = b"test payload for signing";
        let sig_bytes = store.sign(payload).unwrap();
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature must be 64 bytes");

        let vk = store.verifying_key().unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        assert!(
            vk.verify(payload, &sig).is_ok(),
            "signature must verify with the store's verifying key"
        );
    }

    #[test]
    fn file_key_store_from_decoded() {
        let kf = gen_key_file();
        let decoded = kf.decode().unwrap();
        let store = FileKeyStore::from_decoded(decoded);
        assert_eq!(store.kid(), "test-key-001");
        store.sign(b"hello").unwrap();
    }

    #[test]
    fn file_key_store_load_from_disk() {
        let kf = gen_key_file();
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("store_test.json");
        kf.save(&path).unwrap();

        let store = FileKeyStore::load(&path).unwrap();
        assert_eq!(store.kid(), "test-key-001");
        let sig = store.sign(b"payload").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn os_keyring_store_returns_unavailable() {
        let store = OsKeyringStore::new("kr-kid".into());
        assert_eq!(store.kid(), "kr-kid");
        assert_eq!(store.backend_name(), "os-keyring");
        assert!(store.sign(b"x").is_err());
        assert!(store.verifying_key().is_err());
    }

    #[test]
    fn tpm_store_returns_unavailable() {
        let store = TpmKeyStore::new("tpm-kid".into());
        assert_eq!(store.backend_name(), "tpm");
        assert!(store.sign(b"x").is_err());
        assert!(store.verifying_key().is_err());
    }

    #[test]
    fn yubihsm_store_returns_unavailable() {
        let store = YubiHsmKeyStore::new("hsm-kid".into());
        assert_eq!(store.backend_name(), "yubihsm");
        assert!(store.sign(b"x").is_err());
        assert!(store.verifying_key().is_err());
    }

    #[test]
    fn open_key_store_file_backend() {
        let kf = gen_key_file();
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("factory_test.json");
        kf.save(&path).unwrap();

        let store = open_key_store("file", "test-key-001", Some(&path)).unwrap();
        assert_eq!(store.kid(), "test-key-001");
        assert_eq!(store.backend_name(), "file");
        store.sign(b"test").unwrap();
    }

    #[test]
    fn open_key_store_stubs() {
        let store = open_key_store("os-keyring", "k", None).unwrap();
        assert_eq!(store.backend_name(), "os-keyring");

        let store = open_key_store("tpm", "k", None).unwrap();
        assert_eq!(store.backend_name(), "tpm");

        let store = open_key_store("yubihsm", "k", None).unwrap();
        assert_eq!(store.backend_name(), "yubihsm");
    }

    #[test]
    fn open_key_store_unknown_backend() {
        let err = open_key_store("quantum", "k", None).unwrap_err();
        assert!(matches!(err, KeyStoreError::UnsupportedBackend { .. }));
    }

    #[test]
    fn open_key_store_file_requires_path() {
        let err = open_key_store("file", "k", None).unwrap_err();
        assert!(matches!(err, KeyStoreError::Unavailable { .. }));
    }

    #[test]
    fn key_store_is_object_safe() {
        // Verify the trait can be used as Box<dyn KeyStore>.
        let sk = SigningKey::generate(&mut OsRng);
        let store: Box<dyn KeyStore> =
            Box::new(FileKeyStore::from_signing_key("dyn-kid".into(), sk));
        assert_eq!(store.kid(), "dyn-kid");
        store.sign(b"object safety test").unwrap();
    }
}
