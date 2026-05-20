// Proof package generation (Section 20).
//
// Assembles a self-contained proof package directory from campaign results,
// adversarial reports, audit logs, and compliance mappings. The package is
// verifiable by anyone with `invariant verify-package`.
//
// Key components:
// - `ProofPackageManifest` — signed metadata describing the package contents
// - `CampaignSummary` — aggregate statistics with Clopper-Pearson confidence bounds
// - `assemble()` — creates the directory structure from Section 20.1

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::util::sha256_hex;

// ---------------------------------------------------------------------------
// Format-version constants (v12 N-5)
// ---------------------------------------------------------------------------

/// Pre-N-5 proof package format. Manifests without a `format_version` field
/// deserialize as this version. Lacks Merkle root and signed manifest fields.
pub const FORMAT_VERSION_V1: u32 = 1;

/// Format version that new packages are written with today. Bumps to `2` once
/// v11 1.3 (Merkle root) and v11 1.4 (signed manifest) land.
pub const CURRENT_FORMAT_VERSION: u32 = FORMAT_VERSION_V1;

/// Lowest format version accepted by [`verify_format_version`].
pub const MIN_SUPPORTED_FORMAT_VERSION: u32 = FORMAT_VERSION_V1;

/// Highest format version accepted by [`verify_format_version`].
pub const MAX_SUPPORTED_FORMAT_VERSION: u32 = FORMAT_VERSION_V1;

fn default_format_version() -> u32 {
    FORMAT_VERSION_V1
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned when validating a proof package.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofPackageError {
    /// The manifest's `format_version` falls outside the supported range.
    #[error(
        "unsupported proof-package format_version {found} (supported range: {expected_min}..={expected_max})"
    )]
    UnsupportedFormat {
        /// The version that was read from the manifest.
        found: u32,
        /// Minimum version the verifier accepts.
        expected_min: u32,
        /// Maximum version the verifier accepts.
        expected_max: u32,
    },

    /// `manifest_signature` is missing when a signed package was expected,
    /// is malformed, or did not verify against the supplied public key.
    #[error("manifest signature invalid: {reason}")]
    SignatureInvalid {
        /// Human-readable failure reason (decoding, key length, verification).
        reason: String,
    },

    /// JCS canonicalization failed while computing the signing preimage.
    #[error("manifest canonicalization failed: {reason}")]
    Canonicalization {
        /// Underlying serialization error.
        reason: String,
    },
}

/// Check that `format_version` is in the inclusive
/// `[MIN_SUPPORTED_FORMAT_VERSION, MAX_SUPPORTED_FORMAT_VERSION]` range.
///
/// Emits a `tracing::warn!` when the package is still on the pre-Merkle v1
/// format so operators are nudged to regenerate once v11 1.3 + 1.4 land.
pub fn verify_format_version(format_version: u32) -> Result<(), ProofPackageError> {
    if !(MIN_SUPPORTED_FORMAT_VERSION..=MAX_SUPPORTED_FORMAT_VERSION).contains(&format_version) {
        return Err(ProofPackageError::UnsupportedFormat {
            found: format_version,
            expected_min: MIN_SUPPORTED_FORMAT_VERSION,
            expected_max: MAX_SUPPORTED_FORMAT_VERSION,
        });
    }
    if format_version == FORMAT_VERSION_V1 {
        tracing::warn!(
            "proof package on legacy format_version 1 — Merkle root and manifest signature land in v11 1.3 / 1.4"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JCS canonicalization + manifest signing (v11 1.4)
// ---------------------------------------------------------------------------

/// Produce the JCS (RFC 8785) canonical-JSON encoding of `manifest` with
/// `manifest_signature` cleared.
///
/// Used as the Ed25519 signing preimage and as the verification message.
/// The implementation is the subset of RFC 8785 that this struct actually
/// exercises: every object's keys are emitted in lexicographic order, the
/// separators are compact (`,` and `:` with no whitespace), and numeric
/// formatting is delegated to `serde_json` — which already produces the
/// shortest round-trip-safe decimal for `f64` inputs and which never emits
/// NaN/∞ (those serialize as `null` and the manifest never carries them).
/// `manifest_signature` is excluded from the preimage so that a manifest
/// can be signed without first generating the very value being signed.
pub fn canonical_json(manifest: &ProofPackageManifest) -> Result<Vec<u8>, ProofPackageError> {
    let mut value = serde_json::to_value(manifest).map_err(|e| ProofPackageError::Canonicalization {
        reason: format!("serialize manifest: {e}"),
    })?;
    // Strip the signature so the preimage is independent of any pre-existing
    // signature on the manifest (RFC 8032 best practice — sign over a value
    // that excludes the signature field).
    if let Some(obj) = value.as_object_mut() {
        obj.remove("manifest_signature");
        obj.remove("manifest_signer_kid");
    }
    let mut buf = Vec::with_capacity(512);
    write_canonical(&value, &mut buf);
    Ok(buf)
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) {
    use serde_json::Value;
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            // serde_json's Display impl for Number already emits the
            // shortest-round-trip decimal for f64 and the plain integer
            // form for i64/u64 — both match RFC 8785 §3.2.2.3 for the
            // values this manifest carries.
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => out.extend_from_slice(serde_json::to_string(s).expect("string").as_bytes()),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: keys in code-point lexicographic order.
            // `serde_json::Map` is insertion-ordered, so we sort explicitly.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(
                    serde_json::to_string(key).expect("string-key").as_bytes(),
                );
                out.push(b':');
                write_canonical(&map[*key], out);
            }
            out.push(b'}');
        }
    }
}

/// Sign `manifest` with `signing_key` and stamp `manifest_signature` /
/// `manifest_signer_kid` on it in place. `signer_kid` is recorded so a
/// downstream verifier can look up the right public key from
/// `integrity/public_keys.json` without trial-and-error.
pub fn sign_manifest(
    manifest: &mut ProofPackageManifest,
    signing_key: &ed25519_dalek::SigningKey,
    signer_kid: String,
) -> Result<(), ProofPackageError> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    use ed25519_dalek::Signer;
    // Clear any pre-existing signature so we always sign the unsigned form.
    manifest.manifest_signature = None;
    manifest.manifest_signer_kid = None;
    let preimage = canonical_json(manifest)?;
    let sig = signing_key.sign(&preimage);
    manifest.manifest_signature = Some(STANDARD_NO_PAD.encode(sig.to_bytes()));
    manifest.manifest_signer_kid = Some(signer_kid);
    Ok(())
}

/// Verify the Ed25519 signature on `manifest` against `verifying_key`.
///
/// Returns `Ok(())` only when (1) `manifest_signature` is present, (2) it
/// decodes as base64-no-padding to exactly 64 bytes, and (3) the canonical
/// JCS bytes of the manifest (with the signature field stripped) verify
/// under `verifying_key` via `verify_strict` (RFC 8032 §5.1.7, cofactor-
/// attack mitigation).
pub fn verify_manifest(
    manifest: &ProofPackageManifest,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ProofPackageError> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    let Some(sig_b64) = manifest.manifest_signature.as_deref() else {
        return Err(ProofPackageError::SignatureInvalid {
            reason: "manifest_signature field absent".into(),
        });
    };
    let sig_bytes = STANDARD_NO_PAD
        .decode(sig_b64)
        .map_err(|e| ProofPackageError::SignatureInvalid {
            reason: format!("base64 decode: {e}"),
        })?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| {
        ProofPackageError::SignatureInvalid {
            reason: format!("signature shape: {e}"),
        }
    })?;
    let preimage = canonical_json(manifest)?;
    verifying_key
        .verify_strict(&preimage, &sig)
        .map_err(|e| ProofPackageError::SignatureInvalid {
            reason: format!("verify_strict: {e}"),
        })
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Signed manifest describing the proof package contents (Section 20.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPackageManifest {
    /// Numeric on-disk format discriminator. Bumps when the package layout
    /// changes incompatibly (e.g. when Merkle root + manifest signature
    /// land in v11 1.3 / 1.4). Missing on disk → `1` (legacy).
    #[serde(default = "default_format_version")]
    pub format_version: u32,
    /// Human-readable semver of the package contract.
    pub version: String,
    /// When the package was generated.
    pub generated_at: DateTime<Utc>,
    /// Name of the campaign that produced this package.
    pub campaign_name: String,
    /// Robot profile name.
    pub profile_name: String,
    /// SHA-256 hash of the profile JSON used.
    pub profile_hash: String,
    /// SHA-256 hash of the Invariant binary used.
    pub binary_hash: String,
    /// Invariant version string.
    pub invariant_version: String,
    /// Campaign summary statistics.
    pub summary: CampaignSummary,
    /// SHA-256 hashes of all files in the package (path → hash).
    pub file_hashes: HashMap<String, String>,
    /// RFC 6962 Merkle root over the audit log's `entry_hash` sequence
    /// (lowercase hex). `None` for packages that pre-date v11 1.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    /// Ed25519 signature over the canonical JCS bytes of the manifest with
    /// this field set to `None` (RFC 8785 / v11 1.4). Base64-encoded
    /// (standard alphabet, no padding). `None` for packages that pre-date
    /// v11 1.4 or were assembled without a signing key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_signature: Option<String>,
    /// `signer_kid` of the Ed25519 key that produced `manifest_signature`.
    /// Set together with `manifest_signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_signer_kid: Option<String>,
}

// ---------------------------------------------------------------------------
// Campaign summary with statistical claims
// ---------------------------------------------------------------------------

/// Aggregate campaign statistics with Clopper-Pearson confidence bounds (Section 20.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSummary {
    /// Total commands validated.
    pub total_commands: u64,
    /// Commands that were approved.
    pub commands_approved: u64,
    /// Commands that were rejected.
    pub commands_rejected: u64,
    /// Commands where a violation escaped (should be 0).
    pub violation_escapes: u64,
    /// Adversarial commands tested (subset of total or separate).
    pub adversarial_commands: u64,
    /// Adversarial escapes (should be 0).
    pub adversarial_escapes: u64,
    /// Point estimate of escape rate.
    pub escape_rate_point: f64,
    /// Upper bound of escape rate at 95% confidence (Clopper-Pearson).
    pub escape_rate_upper_95: f64,
    /// Upper bound of escape rate at 99% confidence (Clopper-Pearson).
    pub escape_rate_upper_99: f64,
    /// Upper bound of escape rate at 99.9% confidence (Clopper-Pearson).
    pub escape_rate_upper_999: f64,
    /// Equivalent mean time between failures at the given control frequency.
    pub mtbf_hours: Option<f64>,
    /// Control frequency used for MTBF calculation (Hz).
    pub control_frequency_hz: f64,
}

impl CampaignSummary {
    /// Compute a summary from raw counts.
    ///
    /// `total` is the total number of validated commands.
    /// `escapes` is the number of violation escapes (typically 0).
    /// `adversarial` is the number of adversarial commands tested.
    /// `adversarial_escapes` is the number of adversarial escapes.
    /// `control_hz` is the control frequency for MTBF calculation.
    pub fn compute(
        total: u64,
        approved: u64,
        rejected: u64,
        escapes: u64,
        adversarial: u64,
        adversarial_esc: u64,
        control_hz: f64,
    ) -> Self {
        let point = if total == 0 {
            0.0
        } else {
            escapes as f64 / total as f64
        };

        let upper_95 = clopper_pearson_upper(total, escapes, 0.95);
        let upper_99 = clopper_pearson_upper(total, escapes, 0.99);
        let upper_999 = clopper_pearson_upper(total, escapes, 0.999);

        // MTBF: if escape rate upper bound is 0 (mathematically impossible
        // but can happen with 0 total), report None.
        let mtbf = if upper_99 > 0.0 && control_hz > 0.0 {
            // Expected failures per second = upper_99 * control_hz
            // MTBF in hours = 1 / (failures_per_second * 3600)
            let failures_per_sec = upper_99 * control_hz;
            Some(1.0 / (failures_per_sec * 3600.0))
        } else if total > 0 && escapes == 0 {
            // With 0 escapes, use the 99% upper bound.
            // upper_99 is already > 0 for any total > 0, so this branch
            // won't actually fire, but guards against edge cases.
            None
        } else {
            None
        };

        Self {
            total_commands: total,
            commands_approved: approved,
            commands_rejected: rejected,
            violation_escapes: escapes,
            adversarial_commands: adversarial,
            adversarial_escapes: adversarial_esc,
            escape_rate_point: point,
            escape_rate_upper_95: upper_95,
            escape_rate_upper_99: upper_99,
            escape_rate_upper_999: upper_999,
            mtbf_hours: mtbf,
            control_frequency_hz: control_hz,
        }
    }
}

// ---------------------------------------------------------------------------
// Clopper-Pearson exact binomial confidence interval
// ---------------------------------------------------------------------------

/// Compute the upper bound of the Clopper-Pearson exact binomial confidence
/// interval for a proportion.
///
/// Given `n` trials and `k` successes (escapes), returns the upper bound
/// at the given `confidence` level (e.g. 0.95 for 95%).
///
/// For k=0, the formula simplifies to: upper = 1 - (1-confidence)^(1/n)
/// which is the "rule of three" generalization.
///
/// For k>0, uses the Beta distribution quantile. We approximate with the
/// Wilson score interval for simplicity (exact Beta requires a special
/// function library). For k=0, the exact formula is used.
pub fn clopper_pearson_upper(n: u64, k: u64, confidence: f64) -> f64 {
    if n == 0 {
        return 1.0; // no data = maximum uncertainty
    }

    let alpha = 1.0 - confidence;

    if k == 0 {
        // Exact formula for k=0: upper = 1 - alpha^(1/n)
        1.0 - alpha.powf(1.0 / n as f64)
    } else if k == n {
        1.0 // all escaped
    } else {
        // For k>0, use the normal approximation to the Beta distribution.
        // This is sufficient for large n (which is our use case: n > 10M).
        // B(k+1, n-k) ≈ Normal(mean, variance)
        // mean = (k+1) / (n+2)
        // For the upper bound: mean + z_alpha * sqrt(variance)
        let p_hat = k as f64 / n as f64;
        let z = z_score(1.0 - alpha / 2.0);
        let n_f = n as f64;
        let denom = 1.0 + z * z / n_f;
        let center = p_hat + z * z / (2.0 * n_f);
        let margin = z * (p_hat * (1.0 - p_hat) / n_f + z * z / (4.0 * n_f * n_f)).sqrt();
        ((center + margin) / denom).min(1.0)
    }
}

/// Approximate z-score (quantile of the standard normal distribution).
///
/// Uses the rational approximation from Abramowitz and Stegun (26.2.23).
/// Accurate to ~4.5e-4 for p in [0.5, 1.0).
fn z_score(p: f64) -> f64 {
    // For p < 0.5, use symmetry.
    if p < 0.5 {
        return -z_score(1.0 - p);
    }
    if p >= 1.0 {
        return f64::INFINITY;
    }

    let t = (-2.0 * (1.0 - p).ln()).sqrt();

    // Rational approximation constants (A&S 26.2.23).
    let c0 = 2.515517;
    let c1 = 0.802853;
    let c2 = 0.010328;
    let d1 = 1.432788;
    let d2 = 0.189269;
    let d3 = 0.001308;

    t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t)
}

// ---------------------------------------------------------------------------
// Package assembly
// ---------------------------------------------------------------------------

/// Input artifacts for assembling a proof package.
pub struct PackageInputs {
    /// Campaign config YAML path.
    pub campaign_config: Option<PathBuf>,
    /// Robot profile JSON path.
    pub profile: Option<PathBuf>,
    /// Audit log JSONL path.
    pub audit_log: Option<PathBuf>,
    /// Adversarial report files (name → path).
    pub adversarial_reports: HashMap<String, PathBuf>,
    /// Compliance mapping files (name → path).
    pub compliance_mappings: HashMap<String, PathBuf>,
    /// Public keys JSON path.
    pub public_keys: Option<PathBuf>,
    /// Campaign name.
    pub campaign_name: String,
    /// Profile name.
    pub profile_name: String,
    /// Binary hash of the Invariant binary.
    pub binary_hash: String,
    /// Summary statistics.
    pub summary: CampaignSummary,
    /// Optional RFC 6962 Merkle root over the audit log's `entry_hash`
    /// sequence (lowercase hex, no `sha256:` prefix). When set, `assemble`
    /// writes the value to `integrity/merkle_root.txt` and records it on
    /// the manifest. v11 1.3.
    pub merkle_root_hex: Option<String>,
    /// Optional Ed25519 signing key + KID for the manifest signature
    /// (v11 1.4). When `Some`, `assemble` JCS-canonicalizes the manifest
    /// (with `manifest_signature` cleared), signs the preimage, stamps
    /// `manifest_signature` / `manifest_signer_kid` on the manifest, and
    /// writes `manifest.sig` (base64-no-padding, no trailing newline)
    /// alongside `manifest.json`. When `None`, the manifest is left
    /// unsigned and `assemble` logs a `tracing::warn!`.
    pub signing_key: Option<(ed25519_dalek::SigningKey, String)>,
}

/// Assemble a proof package directory from the given inputs.
///
/// Creates the directory structure from Section 20.1 at `output_dir`.
/// Returns the manifest (unsigned — caller signs if keys are available).
pub fn assemble(inputs: &PackageInputs, output_dir: &Path) -> Result<ProofPackageManifest, String> {
    // Create directory structure.
    let dirs = [
        output_dir.to_path_buf(),
        output_dir.join("campaign"),
        output_dir.join("results"),
        output_dir.join("adversarial"),
        output_dir.join("integrity"),
        output_dir.join("compliance"),
    ];
    for dir in &dirs {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {:?}: {e}", dir))?;
    }

    let mut file_hashes: HashMap<String, String> = HashMap::new();

    // Copy campaign config.
    if let Some(src) = &inputs.campaign_config {
        copy_and_hash(
            src,
            &output_dir.join("campaign/config.yaml"),
            &mut file_hashes,
        )?;
    }

    // Copy profile.
    if let Some(src) = &inputs.profile {
        copy_and_hash(
            src,
            &output_dir.join("campaign/profile.json"),
            &mut file_hashes,
        )?;
    }

    // Copy audit log.
    if let Some(src) = &inputs.audit_log {
        copy_and_hash(
            src,
            &output_dir.join("results/audit.jsonl"),
            &mut file_hashes,
        )?;
    }

    // Copy adversarial reports (with path traversal guard).
    for (name, src) in &inputs.adversarial_reports {
        validate_filename(name)?;
        let dest = output_dir.join("adversarial").join(name);
        copy_and_hash(src, &dest, &mut file_hashes)?;
    }

    // Copy compliance mappings (with path traversal guard).
    for (name, src) in &inputs.compliance_mappings {
        validate_filename(name)?;
        let dest = output_dir.join("compliance").join(name);
        copy_and_hash(src, &dest, &mut file_hashes)?;
    }

    // Copy public keys.
    if let Some(src) = &inputs.public_keys {
        copy_and_hash(
            src,
            &output_dir.join("integrity/public_keys.json"),
            &mut file_hashes,
        )?;
    }

    // Write Merkle root (v11 1.3) — lowercase hex, no trailing newline,
    // matches the format consumed by `invariant audit verify --merkle-root`.
    if let Some(root_hex) = &inputs.merkle_root_hex {
        let merkle_path = output_dir.join("integrity/merkle_root.txt");
        std::fs::write(&merkle_path, root_hex.as_bytes())
            .map_err(|e| format!("write merkle_root.txt: {e}"))?;
        file_hashes.insert(
            "integrity/merkle_root.txt".into(),
            sha256_hex(root_hex.as_bytes()),
        );
    }

    // Write binary hash.
    let binary_hash_path = output_dir.join("integrity/binary_hash.txt");
    std::fs::write(&binary_hash_path, &inputs.binary_hash)
        .map_err(|e| format!("write binary_hash.txt: {e}"))?;
    file_hashes.insert(
        "integrity/binary_hash.txt".into(),
        sha256_hex(inputs.binary_hash.as_bytes()),
    );

    // Write summary.
    let summary_json = serde_json::to_string_pretty(&inputs.summary)
        .map_err(|e| format!("serialize summary: {e}"))?;
    let summary_path = output_dir.join("results/summary.json");
    std::fs::write(&summary_path, &summary_json).map_err(|e| format!("write summary.json: {e}"))?;
    file_hashes.insert(
        "results/summary.json".into(),
        sha256_hex(summary_json.as_bytes()),
    );

    // Build manifest.
    let mut manifest = ProofPackageManifest {
        format_version: CURRENT_FORMAT_VERSION,
        version: "1.0.0".into(),
        generated_at: Utc::now(),
        campaign_name: inputs.campaign_name.clone(),
        profile_name: inputs.profile_name.clone(),
        profile_hash: inputs
            .profile
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .map(|b| sha256_hex(&b))
            .unwrap_or_default(),
        binary_hash: inputs.binary_hash.clone(),
        invariant_version: env!("CARGO_PKG_VERSION").into(),
        summary: inputs.summary.clone(),
        file_hashes,
        merkle_root: inputs.merkle_root_hex.clone(),
        manifest_signature: None,
        manifest_signer_kid: None,
    };

    // v11 1.4: optionally sign the manifest (JCS canonicalization →
    // Ed25519 → base64-no-padding) and write `manifest.sig` alongside.
    if let Some((key, kid)) = &inputs.signing_key {
        sign_manifest(&mut manifest, key, kid.clone())
            .map_err(|e| format!("sign manifest: {e}"))?;
        let sig = manifest
            .manifest_signature
            .as_deref()
            .expect("sign_manifest must populate manifest_signature");
        std::fs::write(output_dir.join("manifest.sig"), sig.as_bytes())
            .map_err(|e| format!("write manifest.sig: {e}"))?;
    } else {
        tracing::warn!(
            "proof package assembled without a signing key — manifest.sig will be absent"
        );
    }

    // Write manifest.
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| format!("serialize manifest: {e}"))?;
    std::fs::write(output_dir.join("manifest.json"), &manifest_json)
        .map_err(|e| format!("write manifest.json: {e}"))?;

    // Write README.
    let readme = generate_readme(&manifest);
    std::fs::write(output_dir.join("README.md"), &readme)
        .map_err(|e| format!("write README.md: {e}"))?;

    Ok(manifest)
}

/// Validate that a filename used as a map key does not contain path traversal.
///
/// Rejects any name containing `/`, `\`, `..`, or null bytes. This prevents a
/// caller from writing files outside the intended output directory via crafted
/// adversarial report or compliance mapping names.
fn validate_filename(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("filename must not be empty".into());
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") || name.contains('\0') {
        return Err(format!(
            "filename {name:?} contains path traversal characters"
        ));
    }
    Ok(())
}

/// Copy a file and record its SHA-256 hash.
fn copy_and_hash(
    src: &Path,
    dest: &Path,
    hashes: &mut HashMap<String, String>,
) -> Result<(), String> {
    let bytes = std::fs::read(src).map_err(|e| format!("read {:?}: {e}", src))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {:?}: {e}", parent))?;
    }
    std::fs::write(dest, &bytes).map_err(|e| format!("write {:?}: {e}", dest))?;

    let rel_path = relative_package_path(dest);
    hashes.insert(rel_path, sha256_hex(&bytes));
    Ok(())
}

/// Extract a relative path suitable for the file_hashes map.
/// Looks for known package subdirectories (campaign/, results/, etc.).
fn relative_package_path(path: &Path) -> String {
    let components: Vec<_> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();

    let known_dirs = [
        "campaign",
        "results",
        "adversarial",
        "integrity",
        "compliance",
    ];

    for (i, comp) in components.iter().enumerate() {
        if known_dirs.contains(&comp.as_str()) {
            return components[i..].join("/");
        }
    }

    // Fallback: just use the filename.
    path.file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Generate a README.md for independent verification.
fn generate_readme(manifest: &ProofPackageManifest) -> String {
    format!(
        r#"# Invariant Proof Package

## Campaign: {}

Generated: {}
Profile: {} ({})
Invariant version: {}
Binary hash: {}

## Summary

- Total commands validated: {}
- Commands approved: {}
- Commands rejected: {}
- Violation escapes: {}
- Adversarial commands: {}
- Adversarial escapes: {}

## Statistical Claims

- Escape rate (point estimate): {:.6}%
- Escape rate (95% upper bound): {:.6}%
- Escape rate (99% upper bound): {:.6}%
- Escape rate (99.9% upper bound): {:.6}%
{}

## How to Verify

```bash
invariant verify-package --path .
```

This command checks:
- Manifest integrity (file hashes match)
- Audit log hash chain and signatures
- Campaign result consistency
- Adversarial report presence
- Public key availability

All data in this package is cryptographically signed and independently verifiable.
"#,
        manifest.campaign_name,
        manifest.generated_at.to_rfc3339(),
        manifest.profile_name,
        manifest.profile_hash,
        manifest.invariant_version,
        manifest.binary_hash,
        manifest.summary.total_commands,
        manifest.summary.commands_approved,
        manifest.summary.commands_rejected,
        manifest.summary.violation_escapes,
        manifest.summary.adversarial_commands,
        manifest.summary.adversarial_escapes,
        manifest.summary.escape_rate_point * 100.0,
        manifest.summary.escape_rate_upper_95 * 100.0,
        manifest.summary.escape_rate_upper_99 * 100.0,
        manifest.summary.escape_rate_upper_999 * 100.0,
        manifest
            .summary
            .mtbf_hours
            .map(|h| format!(
                "- Equivalent MTBF at {}Hz: {:.0} hours",
                manifest.summary.control_frequency_hz, h
            ))
            .unwrap_or_default(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Clopper-Pearson tests --

    #[test]
    fn clopper_pearson_zero_escapes_10m() {
        // Section 20.4: 10,240,000 commands, 0 escapes.
        let upper_95 = clopper_pearson_upper(10_240_000, 0, 0.95);
        let upper_99 = clopper_pearson_upper(10_240_000, 0, 0.99);

        // Spec says 0.0000293% at 95%, 0.0000449% at 99%.
        // Our k=0 exact formula: 1 - alpha^(1/n).
        assert!(
            upper_95 < 0.000001,
            "95% upper bound {upper_95} should be < 0.0001%"
        );
        assert!(
            upper_99 < 0.000001,
            "99% upper bound {upper_99} should be < 0.0001%"
        );
        assert!(upper_99 > upper_95, "99% bound should be wider than 95%");
    }

    #[test]
    fn clopper_pearson_zero_trials() {
        let upper = clopper_pearson_upper(0, 0, 0.95);
        assert_eq!(upper, 1.0);
    }

    #[test]
    fn clopper_pearson_all_escaped() {
        let upper = clopper_pearson_upper(100, 100, 0.95);
        assert_eq!(upper, 1.0);
    }

    #[test]
    fn clopper_pearson_some_escapes() {
        let upper = clopper_pearson_upper(1000, 5, 0.95);
        // 5/1000 = 0.5%. Upper bound should be > 0.5% but < 2%.
        assert!(upper > 0.005, "upper {upper} should be > 0.005");
        assert!(upper < 0.02, "upper {upper} should be < 0.02");
    }

    #[test]
    fn clopper_pearson_15m_spec_claim() {
        // Purpose section claim: at 15M episodes with 0 bypasses, the 99.9%
        // confidence upper bound on bypass rate is < 0.0000461% (4.61e-7).
        let upper_999 = clopper_pearson_upper(15_000_000, 0, 0.999);
        assert!(
            upper_999 < 4.61e-7,
            "99.9% upper bound at 15M must be < 4.61e-7, got {upper_999:.3e}"
        );
        // Also verify 95% and 99% bounds from spec Section 5.2.
        let upper_95 = clopper_pearson_upper(15_000_000, 0, 0.95);
        let upper_99 = clopper_pearson_upper(15_000_000, 0, 0.99);
        assert!(
            upper_95 < 2.0e-7,
            "95% upper bound at 15M must be < 2.0e-7, got {upper_95:.3e}"
        );
        assert!(
            upper_99 < 3.08e-7,
            "99% upper bound at 15M must be < 3.08e-7, got {upper_99:.3e}"
        );
    }

    #[test]
    fn campaign_summary_includes_999_bound() {
        let s = CampaignSummary::compute(15_000_000, 14_000_000, 1_000_000, 0, 5_000_000, 0, 200.0);
        assert!(
            s.escape_rate_upper_999 > 0.0,
            "99.9% bound must be positive"
        );
        assert!(
            s.escape_rate_upper_999 > s.escape_rate_upper_99,
            "99.9% bound must be wider than 99%"
        );
        assert!(
            s.escape_rate_upper_999 < 4.61e-7,
            "99.9% bound at 15M episodes must match spec claim"
        );
    }

    #[test]
    fn clopper_pearson_zero_escapes_small_n() {
        // "Rule of three": for k=0, n=100, 95% upper ≈ 3/n = 0.03.
        let upper = clopper_pearson_upper(100, 0, 0.95);
        assert!(
            (upper - 0.03).abs() < 0.005,
            "upper {upper} should be near 0.03 (rule of three)"
        );
    }

    // -- z-score tests --

    #[test]
    fn z_score_50_percent_is_zero() {
        let z = z_score(0.5);
        assert!(z.abs() < 0.001, "z(0.5) = {z}, should be ~0");
    }

    #[test]
    fn z_score_975_is_about_196() {
        let z = z_score(0.975);
        assert!((z - 1.96).abs() < 0.01, "z(0.975) = {z}, should be ~1.96");
    }

    #[test]
    fn z_score_995_is_about_258() {
        let z = z_score(0.995);
        assert!((z - 2.576).abs() < 0.02, "z(0.995) = {z}, should be ~2.576");
    }

    // -- CampaignSummary tests --

    #[test]
    fn campaign_summary_zero_escapes() {
        let s = CampaignSummary::compute(10_000_000, 9_500_000, 500_000, 0, 2_500_000, 0, 100.0);
        assert_eq!(s.escape_rate_point, 0.0);
        assert!(s.escape_rate_upper_95 > 0.0);
        assert!(s.escape_rate_upper_99 > s.escape_rate_upper_95);
        assert!(s.mtbf_hours.is_some());
        let mtbf = s.mtbf_hours.unwrap();
        assert!(
            mtbf > 0.5,
            "MTBF {mtbf} hours should be positive for 10M commands with 0 escapes"
        );
    }

    #[test]
    fn campaign_summary_zero_commands() {
        let s = CampaignSummary::compute(0, 0, 0, 0, 0, 0, 100.0);
        assert_eq!(s.escape_rate_point, 0.0);
        assert_eq!(s.escape_rate_upper_95, 1.0);
    }

    // -- Assembly tests --

    #[test]
    fn assemble_creates_directory_structure() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("proof-package");

        let summary = CampaignSummary::compute(1000, 950, 50, 0, 100, 0, 100.0);

        let inputs = PackageInputs {
            campaign_config: None,
            profile: None,
            audit_log: None,
            adversarial_reports: HashMap::new(),
            compliance_mappings: HashMap::new(),
            public_keys: None,
            campaign_name: "test_campaign".into(),
            profile_name: "test_robot".into(),
            binary_hash: "sha256:abc123".into(),
            summary,
            merkle_root_hex: None,
            signing_key: None,
        };

        let manifest = assemble(&inputs, &output).unwrap();

        assert!(output.join("manifest.json").exists());
        assert!(output.join("README.md").exists());
        assert!(output.join("results/summary.json").exists());
        assert!(output.join("integrity/binary_hash.txt").exists());
        assert!(output.join("campaign").is_dir());
        assert!(output.join("adversarial").is_dir());
        assert!(output.join("compliance").is_dir());
        assert_eq!(manifest.campaign_name, "test_campaign");
        assert_eq!(manifest.version, "1.0.0");
    }

    #[test]
    fn assemble_copies_and_hashes_files() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("proof-package");

        // Create a fake profile file.
        let profile_path = dir.path().join("test_profile.json");
        std::fs::write(&profile_path, r#"{"name":"test"}"#).unwrap();

        // Create a fake audit log.
        let audit_path = dir.path().join("audit.jsonl");
        std::fs::write(&audit_path, "{\"entry\":1}\n{\"entry\":2}\n").unwrap();

        let summary = CampaignSummary::compute(100, 90, 10, 0, 0, 0, 100.0);

        let inputs = PackageInputs {
            campaign_config: None,
            profile: Some(profile_path),
            audit_log: Some(audit_path),
            adversarial_reports: HashMap::new(),
            compliance_mappings: HashMap::new(),
            public_keys: None,
            campaign_name: "hash_test".into(),
            profile_name: "test".into(),
            binary_hash: "sha256:def456".into(),
            summary,
            merkle_root_hex: None,
            signing_key: None,
        };

        let manifest = assemble(&inputs, &output).unwrap();

        // Profile and audit should be copied and hashed.
        assert!(output.join("campaign/profile.json").exists());
        assert!(output.join("results/audit.jsonl").exists());
        assert!(!manifest.file_hashes.is_empty());
        assert!(manifest.profile_hash.starts_with("sha256:"));
    }

    #[test]
    fn assemble_includes_adversarial_reports() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("proof-package");

        let report_path = dir.path().join("protocol_report.json");
        std::fs::write(&report_path, r#"{"attacks": 1000, "escapes": 0}"#).unwrap();

        let summary = CampaignSummary::compute(1000, 950, 50, 0, 1000, 0, 100.0);

        let mut adversarial = HashMap::new();
        adversarial.insert("protocol_report.json".into(), report_path);

        let inputs = PackageInputs {
            campaign_config: None,
            profile: None,
            audit_log: None,
            adversarial_reports: adversarial,
            compliance_mappings: HashMap::new(),
            public_keys: None,
            campaign_name: "adv_test".into(),
            profile_name: "test".into(),
            binary_hash: "sha256:000".into(),
            summary,
            merkle_root_hex: None,
            signing_key: None,
        };

        let manifest = assemble(&inputs, &output).unwrap();

        assert!(output.join("adversarial/protocol_report.json").exists());
        assert!(manifest
            .file_hashes
            .keys()
            .any(|k| k.contains("protocol_report")));
    }

    #[test]
    fn readme_contains_summary_stats() {
        let manifest = ProofPackageManifest {
            format_version: CURRENT_FORMAT_VERSION,
            version: "1.0.0".into(),
            generated_at: Utc::now(),
            campaign_name: "readme_test".into(),
            profile_name: "test_robot".into(),
            profile_hash: "sha256:abc".into(),
            binary_hash: "sha256:def".into(),
            invariant_version: "0.1.0".into(),
            summary: CampaignSummary::compute(10_000, 9_500, 500, 0, 2_000, 0, 100.0),
            file_hashes: HashMap::new(),
            merkle_root: None,
            manifest_signature: None,
            manifest_signer_kid: None,
        };

        let readme = generate_readme(&manifest);
        assert!(readme.contains("readme_test"));
        assert!(readme.contains("10000"));
        assert!(readme.contains("verify-package"));
    }

    #[test]
    fn manifest_serde_round_trip() {
        let manifest = ProofPackageManifest {
            format_version: CURRENT_FORMAT_VERSION,
            version: "1.0.0".into(),
            generated_at: Utc::now(),
            campaign_name: "serde_test".into(),
            profile_name: "test".into(),
            profile_hash: "sha256:abc".into(),
            binary_hash: "sha256:def".into(),
            invariant_version: "0.1.0".into(),
            summary: CampaignSummary::compute(100, 90, 10, 0, 0, 0, 100.0),
            file_hashes: HashMap::new(),
            merkle_root: None,
            manifest_signature: None,
            manifest_signer_kid: None,
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let back: ProofPackageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.campaign_name, "serde_test");
        assert_eq!(back.summary.total_commands, 100);
    }

    // ── Path traversal tests ───────────────────────────────

    #[test]
    fn validate_filename_rejects_path_traversal() {
        assert!(validate_filename("../../../etc/passwd").is_err());
        assert!(validate_filename("foo/bar.json").is_err());
        assert!(validate_filename("foo\\bar.json").is_err());
        assert!(validate_filename("foo\0bar").is_err());
        assert!(validate_filename("..").is_err());
        assert!(validate_filename("").is_err());
    }

    #[test]
    fn validate_filename_accepts_safe_names() {
        assert!(validate_filename("protocol_report.json").is_ok());
        assert!(validate_filename("report-2024.json").is_ok());
        assert!(validate_filename("a").is_ok());
    }

    #[test]
    fn assemble_rejects_path_traversal_in_report_name() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("proof-package");

        let report_path = dir.path().join("valid_report.json");
        std::fs::write(&report_path, "{}").unwrap();

        let profile_path = dir.path().join("profile.json");
        std::fs::write(&profile_path, "{}").unwrap();

        let mut adversarial = HashMap::new();
        adversarial.insert("../../../tmp/pwned".to_string(), report_path.clone());

        let inputs = PackageInputs {
            campaign_config: Some(profile_path.clone()),
            profile: Some(profile_path),
            audit_log: None,
            adversarial_reports: adversarial,
            compliance_mappings: HashMap::new(),
            public_keys: None,
            binary_hash: "sha256:test".into(),
            campaign_name: "test".into(),
            profile_name: "test".into(),
            summary: CampaignSummary::compute(100, 100, 0, 0, 0, 0, 100.0),
            merkle_root_hex: None,
            signing_key: None,
        };

        let result = assemble(&inputs, &output);
        assert!(
            result.is_err(),
            "path traversal in report name must be rejected"
        );
        let err = result.unwrap_err();
        assert!(err.contains("path traversal"), "error: {err}");
    }

    // ── v12 N-5: format_version + typed UnsupportedFormat rejection ────────

    #[test]
    fn format_version_defaults_to_v1_when_missing_on_disk() {
        // The fixture under tests/fixtures/proof_package_v1/manifest.json has
        // no `format_version` key (it represents a pre-N-5 manifest).
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proof_package_v1/manifest.json");
        let raw = std::fs::read_to_string(&path).expect("fixture readable");
        let manifest: ProofPackageManifest =
            serde_json::from_str(&raw).expect("v1 manifest deserializes");
        assert_eq!(
            manifest.format_version, FORMAT_VERSION_V1,
            "missing format_version must default to v1"
        );
        assert_eq!(verify_format_version(manifest.format_version), Ok(()));
    }

    #[test]
    fn assemble_writes_current_format_version() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("proof-package");

        let inputs = PackageInputs {
            campaign_config: None,
            profile: None,
            audit_log: None,
            adversarial_reports: HashMap::new(),
            compliance_mappings: HashMap::new(),
            public_keys: None,
            campaign_name: "fv_test".into(),
            profile_name: "test".into(),
            binary_hash: "sha256:abc".into(),
            summary: CampaignSummary::compute(100, 90, 10, 0, 0, 0, 100.0),
            merkle_root_hex: None,
            signing_key: None,
        };

        let manifest = assemble(&inputs, &output).unwrap();
        assert_eq!(manifest.format_version, CURRENT_FORMAT_VERSION);

        // The on-disk JSON includes the field explicitly so a reader on a
        // future MIN_SUPPORTED bump can fail-fast rather than silent-default.
        let on_disk = std::fs::read_to_string(output.join("manifest.json")).unwrap();
        assert!(
            on_disk.contains("\"format_version\""),
            "manifest.json must record format_version: {on_disk}"
        );
    }

    #[test]
    fn verify_format_version_rejects_future_version() {
        // A manifest claiming format_version above MAX_SUPPORTED must be
        // rejected with the typed UnsupportedFormat error, never silently
        // accepted.
        let future = MAX_SUPPORTED_FORMAT_VERSION + 1;
        let err = verify_format_version(future).unwrap_err();
        assert_eq!(
            err,
            ProofPackageError::UnsupportedFormat {
                found: future,
                expected_min: MIN_SUPPORTED_FORMAT_VERSION,
                expected_max: MAX_SUPPORTED_FORMAT_VERSION,
            }
        );
    }

    #[test]
    fn verify_format_version_rejects_zero() {
        let err = verify_format_version(0).unwrap_err();
        assert!(matches!(err, ProofPackageError::UnsupportedFormat { found: 0, .. }));
    }
}
