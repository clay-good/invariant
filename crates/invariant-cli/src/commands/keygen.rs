use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Args;
use rand::rngs::OsRng;
use std::path::PathBuf;

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
}

pub fn run(args: &KeygenArgs) -> i32 {
    // 1. Validate KID.
    if let Err(e) = crate::key_file::validate_kid(&args.kid) {
        eprintln!("error: {e}");
        return 2;
    }

    // 2. Refuse to overwrite existing files unless --force is set.
    if !args.force {
        if args.output.exists() {
            eprintln!(
                "error: output file already exists: {}. Use --force to overwrite.",
                args.output.display()
            );
            return 2;
        }
        if let Some(pub_path) = &args.export_pub {
            if pub_path.exists() {
                eprintln!(
                    "error: output file already exists: {}. Use --force to overwrite.",
                    pub_path.display()
                );
                return 2;
            }
        }
    }

    // 3. Generate keypair.
    let sk = invariant_core::authority::crypto::generate_keypair(&mut OsRng);
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
        };
        let code = run(&args);
        assert_eq!(code, 0);
        let content = std::fs::read_to_string(&pub_output).unwrap();
        assert!(content.contains("test-007"));
    }
}
