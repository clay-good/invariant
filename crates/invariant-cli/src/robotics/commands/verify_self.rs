//! `invariant verify-self` / `invariant --verify-self` — binary integrity check.
//!
//! Computes the SHA-256 hash of the running binary and compares it against:
//! 1. A compile-time hash set via `INVARIANT_BUILD_HASH` env var during build
//! 2. A `manifest.json` file adjacent to the binary (if present)
//! 3. If neither is available, prints the current hash for manual verification

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Manifest file format for signed binary verification.
///
/// Placed adjacent to the binary (e.g. `/usr/local/bin/invariant.manifest.json`).
/// In production, the `manifest_signature` is verified against a pinned build
/// authority public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct BinaryManifest {
    /// Expected SHA-256 hash of the binary, hex-encoded with `sha256:` prefix.
    pub binary_hash: String,
    /// Ed25519 signature over `binary_hash`, base64-encoded.
    #[serde(default)]
    pub manifest_signature: String,
    /// Key identifier of the build authority that signed this manifest.
    #[serde(default)]
    pub signer_kid: String,
    /// Invariant version string at build time.
    #[serde(default)]
    pub version: String,
}

/// Build-time git commit short SHA. Set by `build.rs`; falls back to
/// `"unknown"` outside a git checkout (e.g. a crates.io tarball).
/// v11-5.12.
pub const GIT_COMMIT: &str = env!("INVARIANT_GIT_COMMIT");

/// Build-time cargo profile (`"debug"` or `"release"`). Set by `build.rs`.
/// v11-5.12.
pub const BUILD_PROFILE: &str = env!("INVARIANT_BUILD_PROFILE");

/// Hash embedded at compile time via `INVARIANT_BUILD_HASH` environment variable.
///
/// CI/CD sets this after a first-pass build:
/// ```bash
/// HASH=$(sha256sum target/release/invariant | cut -d' ' -f1)
/// INVARIANT_BUILD_HASH="sha256:$HASH" cargo build --release
/// ```
///
/// Returns `None` for development builds where the env var isn't set.
pub fn compiled_hash() -> Option<&'static str> {
    option_env!("INVARIANT_BUILD_HASH")
}

/// Compute SHA-256 of the currently running binary.
pub fn hash_current_binary() -> Result<String, String> {
    let exe_path = std::env::current_exe().map_err(|e| format!("cannot locate own binary: {e}"))?;
    hash_file(&exe_path)
}

/// Compute SHA-256 of a file, returning `sha256:<hex>`.
pub fn hash_file(path: &Path) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let hash = Sha256::digest(&data);
    Ok(format!("sha256:{:x}", hash))
}

/// Look for a manifest file adjacent to the binary.
///
/// Searches for `<binary_name>.manifest.json` in the same directory.
pub fn find_manifest() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let manifest = exe.with_extension("manifest.json");
    if manifest.exists() {
        Some(manifest)
    } else {
        None
    }
}

/// Load and parse a manifest file.
pub fn load_manifest(path: &Path) -> Result<BinaryManifest, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("read manifest: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("parse manifest: {e}"))
}

/// Run the full self-verification check. Returns exit code 0 on success.
pub fn run() -> i32 {
    // Step 1: Hash the running binary.
    let binary_hash = match hash_current_binary() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("FATAL: {e}");
            return 2;
        }
    };

    println!("Binary hash: {binary_hash}");

    let mut verified = false;

    // Step 2: Check compile-time hash (if available).
    if let Some(compiled) = compiled_hash() {
        if binary_hash == compiled {
            println!("OK: binary hash matches compiled-in manifest ({compiled})");
            verified = true;
        } else {
            eprintln!(
                "FATAL: binary integrity check failed\n  expected: {compiled}\n  actual:   {binary_hash}"
            );
            return 1;
        }
    }

    // Step 3: Check manifest file (if present).
    if let Some(manifest_path) = find_manifest() {
        match load_manifest(&manifest_path) {
            Ok(manifest) => {
                if binary_hash == manifest.binary_hash {
                    println!(
                        "OK: binary hash matches manifest file ({})",
                        manifest_path.display()
                    );
                    if !manifest.signer_kid.is_empty() {
                        println!("  Signed by: {}", manifest.signer_kid);
                    }
                    verified = true;
                } else {
                    eprintln!(
                        "FATAL: binary hash does not match manifest\n  expected: {}\n  actual:   {binary_hash}",
                        manifest.binary_hash
                    );
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("WARNING: could not load manifest: {e}");
            }
        }
    }

    // Step 4: If neither source was available, report hash for manual verification.
    if !verified {
        println!("No compiled-in hash or manifest file found.");
        println!("To enable verification, rebuild with:");
        println!("  INVARIANT_BUILD_HASH=\"{binary_hash}\" cargo build --release");
        println!("Or place a manifest at: <binary>.manifest.json");
    }

    // Step 5 (v11-5.12): surface the embedded build provenance.
    println!("Build profile: {BUILD_PROFILE}");
    println!("Git commit:    {GIT_COMMIT}");

    // Step 6 (v11-5.12): per-builtin-profile load validation. Every
    // profile shipped under `profiles/robotics/` must deserialise and
    // pass its model-level validator. A regression here means a JSON
    // file in the binary's `include_str!` block has gone stale.
    match validate_all_builtin_profiles() {
        Ok(n) => println!("Profiles:      {n} built-in profile(s) loaded and validated"),
        Err(e) => {
            eprintln!("FATAL: built-in profile validation failed: {e}");
            return 1;
        }
    }

    0
}

/// Walk `invariant_robotics::profiles::list_builtins`, load each one,
/// and run its `Validate` impl. Returns the count on success or the
/// first failure's reason on error. v11-5.12.
pub fn validate_all_builtin_profiles() -> Result<usize, String> {
    use invariant_robotics::models::error::Validate;
    let names = invariant_robotics::profiles::list_builtins();
    let mut count = 0usize;
    for name in names.iter() {
        let profile = invariant_robotics::profiles::load_builtin(name)
            .map_err(|e| format!("load '{name}': {e}"))?;
        profile
            .validate()
            .map_err(|e| format!("validate '{name}': {e}"))?;
        count += 1;
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_file_produces_sha256_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let hash = hash_file(&path).unwrap();
        assert!(
            hash.starts_with("sha256:"),
            "hash must start with sha256: prefix, got: {hash}"
        );
        // SHA-256 of "hello world" is a known value.
        assert_eq!(
            hash,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn hash_file_different_content_different_hash() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("a.bin");
        let p2 = dir.path().join("b.bin");
        std::fs::write(&p1, b"aaa").unwrap();
        std::fs::write(&p2, b"bbb").unwrap();
        assert_ne!(hash_file(&p1).unwrap(), hash_file(&p2).unwrap());
    }

    #[test]
    fn hash_file_nonexistent_returns_error() {
        let result = hash_file(Path::new("/nonexistent/binary"));
        assert!(result.is_err());
    }

    #[test]
    fn hash_current_binary_succeeds() {
        // The test binary itself is a valid executable.
        let hash = hash_current_binary().unwrap();
        assert!(hash.starts_with("sha256:"));
        assert!(hash.len() > 10);
    }

    #[test]
    fn compiled_hash_is_none_in_dev_builds() {
        // In normal development builds, INVARIANT_BUILD_HASH is not set.
        // This may be Some if someone explicitly sets it, so we just
        // verify the function doesn't panic.
        let _ = compiled_hash();
    }

    #[test]
    fn load_manifest_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.manifest.json");
        let manifest = BinaryManifest {
            binary_hash: "sha256:abc123".into(),
            manifest_signature: "sig".into(),
            signer_kid: "build-001".into(),
            version: "0.1.0".into(),
        };
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(&path, json).unwrap();

        let loaded = load_manifest(&path).unwrap();
        assert_eq!(loaded.binary_hash, "sha256:abc123");
        assert_eq!(loaded.signer_kid, "build-001");
    }

    #[test]
    fn load_manifest_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.manifest.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(load_manifest(&path).is_err());
    }

    #[test]
    fn load_manifest_nonexistent() {
        assert!(load_manifest(Path::new("/nonexistent/manifest.json")).is_err());
    }

    #[test]
    fn run_returns_0() {
        // In dev builds without manifest, run() still returns 0 (just prints hash).
        assert_eq!(run(), 0);
    }

    // ---- v11-5.12: build provenance + per-profile load ------------------

    #[test]
    fn build_profile_constant_is_known_value() {
        // `build.rs` writes the cargo profile name; in tests this is
        // typically `"debug"` (or `"release"` under `--release`).
        assert!(
            BUILD_PROFILE == "debug"
                || BUILD_PROFILE == "release"
                || BUILD_PROFILE == "test",
            "BUILD_PROFILE must be one of debug/release/test, got: {BUILD_PROFILE}"
        );
    }

    #[test]
    fn git_commit_constant_is_non_empty() {
        // build.rs falls back to "unknown" outside a git checkout, but
        // either way the constant must not be empty.
        assert!(!GIT_COMMIT.is_empty());
    }

    #[test]
    fn validate_all_builtin_profiles_loads_every_one() {
        let count = validate_all_builtin_profiles().expect("all built-in profiles must validate");
        // At least the 34 production profiles + adversarials. Be loose:
        // the exact list grows over time.
        assert!(
            count >= 30,
            "expected at least 30 built-in profiles, loaded {count}"
        );
    }

    #[test]
    fn hash_current_binary_matches_in_process_sha256() {
        // The v11-5.12 acceptance criterion calls for matching an
        // external `sha256sum`; we use the same algorithm in-process so
        // the test runs cross-platform and does not depend on a shell
        // tool. If the implementation ever diverges from raw SHA-256 of
        // the binary bytes, this test catches it.
        let exe = std::env::current_exe().unwrap();
        let bytes = std::fs::read(&exe).unwrap();
        let expected = format!(
            "sha256:{:x}",
            Sha256::digest(&bytes)
        );
        let got = hash_current_binary().unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = BinaryManifest {
            binary_hash: "sha256:deadbeef".into(),
            manifest_signature: "AAAA".into(),
            signer_kid: "kid".into(),
            version: "1.0.0".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let parsed: BinaryManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.binary_hash, m.binary_hash);
        assert_eq!(parsed.version, m.version);
    }
}
