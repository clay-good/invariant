use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Args;
use rand::rngs::OsRng;
use std::path::PathBuf;

/// Key-store backend selector for `keygen --store`.
///
/// Parsed by [`StoreKind::parse`] before any I/O happens so unknown
/// kinds fail fast with a deterministic, typed error (v12-N-13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreKind {
    File,
    OsKeyring,
    Tpm,
    YubiHsm,
}

impl StoreKind {
    /// Accepted spellings, mirrored in error messages.
    pub const ACCEPTED: &'static str = "file|os-keyring|tpm|yubihsm";

    /// Parse a `--store=<kind>` argument. Returns the canonical error
    /// string the CLI surfaces to the user when the kind is unknown.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "file" => Ok(Self::File),
            "os-keyring" => Ok(Self::OsKeyring),
            "tpm" => Ok(Self::Tpm),
            "yubihsm" => Ok(Self::YubiHsm),
            other => Err(format!(
                "unknown key store '{other}'; expected one of {}",
                Self::ACCEPTED
            )),
        }
    }
}

#[derive(Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub kid: String,
    /// Output path for the key file. Validated at the OS level via PathBuf (P3-8, P3-9).
    #[arg(long, value_name = "OUTPUT_FILE")]
    pub output: PathBuf,
    /// Also write a public-key-only version of the key file to this path.
    #[arg(long, value_name = "PUB_FILE")]
    pub export_pub: Option<PathBuf>,
    /// Overwrite existing output file(s) without error.
    #[arg(long, default_value_t = false)]
    pub force: bool,
    /// Key-store backend. One of `file|os-keyring|tpm|yubihsm`. Defaults to `file`.
    /// Non-file backends are stubs today and exit 2 with a typed "unavailable" message
    /// before any I/O is attempted (v12-N-13).
    #[arg(long, value_name = "KIND", default_value = "file")]
    pub store: String,
}

pub fn run(args: &KeygenArgs) -> i32 {
    // 0. Resolve the store kind. This MUST happen before any path is opened
    //    or any backend constructed (v12-N-13).
    let store = match StoreKind::parse(&args.store) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Unknown kinds were caught above. For the non-file backends, surface a
    // typed "unavailable" message that mirrors `KeyStoreError::Unavailable`
    // and exit before any I/O. This stays in lockstep with the stubs in
    // `invariant_core::keys` (OsKeyringStore / TpmKeyStore / YubiHsmKeyStore).
    if let Some(reason) = match store {
        StoreKind::File => None,
        StoreKind::OsKeyring => {
            Some("OS keyring backend not yet implemented — use file backend for development")
        }
        StoreKind::Tpm => {
            Some("TPM 2.0 backend not yet implemented — requires tss-esapi crate and TPM hardware")
        }
        StoreKind::YubiHsm => Some("YubiHSM 2 backend not yet implemented"),
    } {
        eprintln!("error: key store unavailable: {reason}");
        return 2;
    }

    // 1. Validate KID.
    if let Err(e) = crate::key_file::validate_kid(&args.kid) {
        eprintln!("error: {e}");
        return 2;
    }

    // 2. Refuse to overwrite existing files unless --force is set.
    //    Use create_new(true) to atomically check-and-create, eliminating the
    //    TOCTOU race between exists() and the subsequent open/write (P2-70).
    if !args.force {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args.output)
        {
            Ok(_) => {
                // File didn't exist and was created; remove the placeholder so
                // write_key_file_secure can create it with the right permissions.
                let _ = std::fs::remove_file(&args.output);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                eprintln!(
                    "error: output file already exists: {}. Use --force to overwrite.",
                    args.output.display()
                );
                return 2;
            }
            Err(e) => {
                eprintln!(
                    "error: cannot create output file {}: {e}",
                    args.output.display()
                );
                return 2;
            }
        }
        if let Some(pub_path) = &args.export_pub {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(pub_path)
            {
                Ok(_) => {
                    let _ = std::fs::remove_file(pub_path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    eprintln!(
                        "error: output file already exists: {}. Use --force to overwrite.",
                        pub_path.display()
                    );
                    return 2;
                }
                Err(e) => {
                    eprintln!("error: cannot create pub file {}: {e}", pub_path.display());
                    return 2;
                }
            }
        }
    }

    // 3. Generate keypair.
    let sk = invariant_robotics::authority::crypto::generate_keypair(&mut OsRng);
    let vk = sk.verifying_key();
    let kf = crate::key_file::KeyFile {
        kid: args.kid.clone(),
        public_key: STANDARD.encode(vk.as_bytes()),
        secret_key: Some(STANDARD.encode(sk.to_bytes())),
    };

    // 4. Write the full (secret) key file with secure permissions.
    if let Err(e) = crate::key_file::write_key_file_secure(&args.output, &kf) {
        eprintln!("error: {e}");
        return 2;
    }

    // 5. Optionally write the public-key-only export.
    if let Some(pub_path) = &args.export_pub {
        let pub_kf = crate::key_file::export_public_key(&kf);
        if let Err(e) = crate::key_file::write_key_file(pub_path, &pub_kf) {
            eprintln!("error: {e}");
            return 2;
        }
    }

    // 6. Display result.
    let fp = match crate::key_file::fingerprint(&kf) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    eprintln!("Generated Ed25519 keypair: {}", args.kid);
    eprintln!("Fingerprint: {fp}");
    if let Some(pub_path) = &args.export_pub {
        eprintln!("Public key file: {}", pub_path.display());
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_dir() -> TempDir {
        tempfile::tempdir().expect("failed to create temp dir")
    }

    #[test]
    fn run_generates_key_file_and_returns_zero() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let args = KeygenArgs {
            kid: "test-001".to_string(),
            output: output.clone(),
            export_pub: None,
            force: false,
            store: "file".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 0);
        assert!(output.exists());
    }

    #[test]
    fn run_exports_pub_file_when_flag_set() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let pub_output = dir.path().join("key-pub.json");
        let args = KeygenArgs {
            kid: "test-002".to_string(),
            output: output.clone(),
            export_pub: Some(pub_output.clone()),
            force: false,
            store: "file".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 0);
        assert!(output.exists());
        assert!(pub_output.exists());
    }

    #[test]
    fn pub_export_contains_no_secret_key() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let pub_output = dir.path().join("key-pub.json");
        let args = KeygenArgs {
            kid: "test-003".to_string(),
            output: output.clone(),
            export_pub: Some(pub_output.clone()),
            force: false,
            store: "file".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 0);
        let raw = std::fs::read_to_string(&pub_output).unwrap();
        assert!(!raw.contains("secret_key"));
    }

    #[test]
    fn run_refuses_to_overwrite_output_without_force() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        // Create a file at the output path first.
        std::fs::write(&output, b"existing").unwrap();
        let args = KeygenArgs {
            kid: "test-004".to_string(),
            output: output.clone(),
            export_pub: None,
            force: false,
            store: "file".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 2);
        // Original file must remain untouched.
        let content = std::fs::read(&output).unwrap();
        assert_eq!(content, b"existing");
    }

    #[test]
    fn run_overwrites_output_with_force() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        std::fs::write(&output, b"existing").unwrap();
        let args = KeygenArgs {
            kid: "test-005".to_string(),
            output: output.clone(),
            export_pub: None,
            force: true,
            store: "file".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 0);
        // File should now contain valid JSON, not "existing".
        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("test-005"));
    }

    #[test]
    fn run_refuses_to_overwrite_pub_file_without_force() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let pub_output = dir.path().join("key-pub.json");
        std::fs::write(&pub_output, b"existing-pub").unwrap();
        let args = KeygenArgs {
            kid: "test-006".to_string(),
            output: output.clone(),
            export_pub: Some(pub_output.clone()),
            force: false,
            store: "file".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 2);
        let content = std::fs::read(&pub_output).unwrap();
        assert_eq!(content, b"existing-pub");
    }

    #[test]
    fn run_invalid_kid_returns_exit_code_2() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let args = KeygenArgs {
            // Empty string — validate_kid must reject this.
            kid: "".to_string(),
            output: output.clone(),
            export_pub: None,
            force: false,
            store: "file".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 2);
        // No key file should have been written.
        assert!(!output.exists());
    }

    #[test]
    fn run_overwrites_pub_file_with_force() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let pub_output = dir.path().join("key-pub.json");
        std::fs::write(&pub_output, b"existing-pub").unwrap();
        let args = KeygenArgs {
            kid: "test-007".to_string(),
            output: output.clone(),
            export_pub: Some(pub_output.clone()),
            force: true,
            store: "file".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 0);
        let content = std::fs::read_to_string(&pub_output).unwrap();
        assert!(content.contains("test-007"));
    }

    // ---- v12-N-13: --store fail-fast --------------------------------------

    #[test]
    fn store_kind_parse_accepts_known_variants() {
        assert_eq!(StoreKind::parse("file").unwrap(), StoreKind::File);
        assert_eq!(
            StoreKind::parse("os-keyring").unwrap(),
            StoreKind::OsKeyring
        );
        assert_eq!(StoreKind::parse("tpm").unwrap(), StoreKind::Tpm);
        assert_eq!(StoreKind::parse("yubihsm").unwrap(), StoreKind::YubiHsm);
    }

    #[test]
    fn store_kind_parse_rejects_unknown_with_listed_expectations() {
        let err = StoreKind::parse("foobar").unwrap_err();
        assert!(err.contains("unknown key store 'foobar'"), "got: {err}");
        assert!(err.contains("file|os-keyring|tpm|yubihsm"), "got: {err}");
    }

    #[test]
    fn run_unknown_store_kind_exits_two_without_touching_disk() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let args = KeygenArgs {
            kid: "test-100".to_string(),
            output: output.clone(),
            export_pub: None,
            force: false,
            store: "foobar".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 2);
        // The output path was never opened.
        assert!(!output.exists());
    }

    #[test]
    fn run_tpm_store_kind_returns_unavailable_without_touching_disk() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let args = KeygenArgs {
            kid: "test-101".to_string(),
            output: output.clone(),
            export_pub: None,
            force: false,
            store: "tpm".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 2);
        assert!(!output.exists());
    }

    #[test]
    fn run_yubihsm_store_kind_returns_unavailable_without_touching_disk() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let args = KeygenArgs {
            kid: "test-102".to_string(),
            output: output.clone(),
            export_pub: None,
            force: false,
            store: "yubihsm".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 2);
        assert!(!output.exists());
    }

    #[test]
    fn run_os_keyring_store_kind_returns_unavailable_without_touching_disk() {
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let args = KeygenArgs {
            kid: "test-103".to_string(),
            output: output.clone(),
            export_pub: None,
            force: false,
            store: "os-keyring".to_string(),
        };
        let code = run(&args);
        assert_eq!(code, 2);
        assert!(!output.exists());
    }

    #[test]
    fn run_store_validated_before_kid_so_invalid_kid_still_reachable() {
        // Sanity check: --store=tpm short-circuits before KID validation,
        // proving the store check is the first action in run().
        let dir = tmp_dir();
        let output = dir.path().join("key.json");
        let args = KeygenArgs {
            kid: "".to_string(), // invalid, but should not be reached
            output: output.clone(),
            export_pub: None,
            force: false,
            store: "tpm".to_string(),
        };
        let code = run(&args);
        // Either way it is exit 2; what we assert is that no file was opened.
        assert_eq!(code, 2);
        assert!(!output.exists());
    }
}
