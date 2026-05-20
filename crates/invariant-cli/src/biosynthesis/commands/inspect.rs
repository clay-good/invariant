//! `inspect` subcommand: read-only introspection of bundles, profiles,
//! verdicts, and audit logs.
//!
//! The user passes one of `--bundle`, `--profile`, `--verdict`, or
//! `--audit-log`. The corresponding loader runs, signatures are verified
//! where present, and the structured summary is printed to stdout.
//!
//! Exit codes:
//! - 0 — load and (where applicable) signature verification succeeded
//! - 1 — file loaded but a signature was present and invalid
//! - 2 — usage error (no input flag, multiple input flags)
//! - 3 — internal error (I/O, parse, etc.)

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Args;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use invariant_biosynthesis::models::audit::SignedAuditEntry;
use invariant_biosynthesis::models::bundle::{SynthesisBundle, SynthesisPayload};
use invariant_biosynthesis::models::profile::BioProfile;
use invariant_biosynthesis::models::verdict::SignedVerdict;
use invariant_biosynthesis::util::sha256_hex_json;

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Path to a synthesis bundle JSON.
    #[arg(long, value_name = "BUNDLE", group = "input")]
    pub bundle: Option<PathBuf>,
    /// Path to a bio profile JSON.
    #[arg(long, value_name = "PROFILE", group = "input")]
    pub profile: Option<PathBuf>,
    /// Path to a signed verdict JSON.
    #[arg(long, value_name = "VERDICT", group = "input")]
    pub verdict: Option<PathBuf>,
    /// Path to a JSONL audit log.
    #[arg(long, value_name = "AUDIT_LOG", group = "input")]
    pub audit_log: Option<PathBuf>,
    /// Optional public-key file used to verify signatures (verdict /
    /// audit-log entries). When omitted, signatures are reported as
    /// `signed (unverified)` rather than verified.
    #[arg(long, value_name = "PUB")]
    pub verify_with: Option<PathBuf>,
}

pub fn run(args: &InspectArgs) -> i32 {
    let chosen: Vec<&str> = [
        args.bundle.as_ref().map(|_| "bundle"),
        args.profile.as_ref().map(|_| "profile"),
        args.verdict.as_ref().map(|_| "verdict"),
        args.audit_log.as_ref().map(|_| "audit-log"),
    ]
    .into_iter()
    .flatten()
    .collect();

    if chosen.is_empty() {
        eprintln!("error: pass exactly one of --bundle, --profile, --verdict, --audit-log");
        return 2;
    }
    if chosen.len() > 1 {
        eprintln!(
            "error: pass exactly one input flag (got {})",
            chosen.join(", ")
        );
        return 2;
    }

    // Load the optional verifying key once.
    let verifier = match args.verify_with.as_ref() {
        None => None,
        Some(path) => match load_pub(path) {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("error: load --verify-with: {e}");
                return 3;
            }
        },
    };

    if let Some(p) = &args.bundle {
        return inspect_bundle(p);
    }
    if let Some(p) = &args.profile {
        return inspect_profile(p);
    }
    if let Some(p) = &args.verdict {
        return inspect_verdict(p, verifier.as_ref());
    }
    if let Some(p) = &args.audit_log {
        return inspect_audit_log(p, verifier.as_ref());
    }
    unreachable!("group constraint enforced above");
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

fn load_pub(path: &Path) -> Result<HashMap<String, VerifyingKey>, String> {
    let kf = crate::key_file::load_key_file(path)?;
    let (vk, kid) = crate::key_file::load_verifying_key(&kf)?;
    let mut m = HashMap::new();
    m.insert(kid, vk);
    Ok(m)
}

// ---------------------------------------------------------------------------
// Inspect: bundle
// ---------------------------------------------------------------------------

fn inspect_bundle(path: &Path) -> i32 {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read bundle: {e}");
            return 3;
        }
    };
    let bundle: SynthesisBundle = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: parse bundle: {e}");
            return 3;
        }
    };
    println!("bundle:");
    println!("  source: {}", bundle.source);
    println!("  timestamp: {}", bundle.timestamp.to_rfc3339());
    println!("  sequence: {}", bundle.sequence);
    println!("  payload: {}", payload_summary(&bundle.payload));
    println!(
        "  pca_chain: {}",
        if bundle.authority.pca_chain.is_empty() {
            "<empty>".to_string()
        } else {
            format!("{} bytes (b64)", bundle.authority.pca_chain.len())
        }
    );
    println!(
        "  required_ops: [{}]",
        bundle
            .authority
            .required_ops
            .iter()
            .map(|o| o.as_str().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  metadata_keys: {}", bundle.metadata.len());
    println!("  signature: unsigned (bundles carry only the embedded PCA chain)");
    0
}

fn payload_summary(p: &SynthesisPayload) -> String {
    match p {
        SynthesisPayload::Dna { sequence } => format!("dna ({} bases)", sequence.len()),
        SynthesisPayload::Peptide { sequence } => format!("peptide ({} AA)", sequence.len()),
        SynthesisPayload::Chemical { smiles } => {
            format!("chemical ({} chars SMILES)", smiles.len())
        }
        SynthesisPayload::Protocol { steps } => format!("protocol ({} steps)", steps.len()),
    }
}

// ---------------------------------------------------------------------------
// Inspect: profile
// ---------------------------------------------------------------------------

fn inspect_profile(path: &Path) -> i32 {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read profile: {e}");
            return 3;
        }
    };
    let profile: BioProfile = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: parse profile: {e}");
            return 3;
        }
    };
    println!("profile:");
    println!("  name: {}", profile.name);
    println!("  version: {}", profile.version);
    println!("  bsl_level: {}", profile.bsl_level);
    println!("  allowed_substrates: {:?}", profile.allowed_substrates);
    println!(
        "  max_synthesis_volume_ml: {}",
        profile.max_synthesis_volume_ml
    );
    println!("  export_controlled: {}", profile.export_controlled);
    match (&profile.profile_signature, &profile.profile_signer_kid) {
        (Some(_), Some(kid)) => println!("  signature: signed (unverified) by kid={kid}"),
        _ => println!("  signature: unsigned"),
    }
    0
}

// ---------------------------------------------------------------------------
// Inspect: verdict
// ---------------------------------------------------------------------------

fn inspect_verdict(path: &Path, verifier: Option<&HashMap<String, VerifyingKey>>) -> i32 {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read verdict: {e}");
            return 3;
        }
    };
    let signed: SignedVerdict = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: parse verdict: {e}");
            return 3;
        }
    };
    let v = &signed.verdict;
    println!("verdict:");
    println!("  approved: {}", v.approved);
    println!("  command_hash: {}", v.command_hash);
    println!("  command_sequence: {}", v.command_sequence);
    println!("  timestamp: {}", v.timestamp.to_rfc3339());
    println!("  profile: {} ({})", v.profile_name, v.profile_hash);
    println!(
        "  origin_principal: {}",
        v.authority_summary.origin_principal
    );
    println!("  hop_count: {}", v.authority_summary.hop_count);
    println!("  checks ({}):", v.checks.len());
    for c in &v.checks {
        println!(
            "    [{}] {} {}: {}",
            c.category,
            if c.passed { "PASS" } else { "FAIL" },
            c.name,
            c.details
        );
    }
    let sig_status = verify_verdict_sig(&signed, verifier);
    println!("  signature: {sig_status}");
    if matches!(sig_status, SigStatus::Invalid) {
        return 1;
    }
    0
}

#[derive(Debug)]
enum SigStatus {
    UnverifiedHasSignature,
    Verified,
    Invalid,
    UnknownKid,
}

impl std::fmt::Display for SigStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigStatus::UnverifiedHasSignature => {
                f.write_str("signed (unverified — pass --verify-with)")
            }
            SigStatus::Verified => f.write_str("signed and verified"),
            SigStatus::Invalid => f.write_str("signed but INVALID"),
            SigStatus::UnknownKid => f.write_str("signed but signer kid not in --verify-with"),
        }
    }
}

fn verify_verdict_sig(
    signed: &SignedVerdict,
    verifier: Option<&HashMap<String, VerifyingKey>>,
) -> SigStatus {
    let Some(map) = verifier else {
        return SigStatus::UnverifiedHasSignature;
    };
    let Some(vk) = map.get(&signed.signer_kid) else {
        return SigStatus::UnknownKid;
    };
    let canonical = match sha256_hex_json(&signed.verdict) {
        Ok(s) => s,
        Err(_) => return SigStatus::Invalid,
    };
    let Ok(raw) = STANDARD.decode(signed.verdict_signature.as_bytes()) else {
        return SigStatus::Invalid;
    };
    let Ok(arr): Result<[u8; 64], _> = raw.as_slice().try_into() else {
        return SigStatus::Invalid;
    };
    let sig = Signature::from_bytes(&arr);
    if vk.verify(canonical.as_bytes(), &sig).is_ok() {
        SigStatus::Verified
    } else {
        SigStatus::Invalid
    }
}

// ---------------------------------------------------------------------------
// Inspect: audit log
// ---------------------------------------------------------------------------

fn inspect_audit_log(path: &Path, verifier: Option<&HashMap<String, VerifyingKey>>) -> i32 {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: open audit log: {e}");
            return 3;
        }
    };
    let mut count = 0usize;
    let mut signers: HashMap<String, usize> = HashMap::new();
    let mut bad_signatures = 0usize;
    let mut head_hash: Option<String> = None;
    let mut last_seq: Option<u64> = None;
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: read line {i}: {e}");
                return 3;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let entry: SignedAuditEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: parse line {i}: {e}");
                return 3;
            }
        };
        count += 1;
        *signers.entry(entry.signer_kid.clone()).or_default() += 1;
        last_seq = Some(entry.entry.sequence);
        head_hash = Some(entry.entry.entry_hash.clone());
        if let Some(map) = verifier {
            if !verify_audit_entry_sig(&entry, map) {
                bad_signatures += 1;
            }
        }
    }
    println!("audit log:");
    println!("  entries: {count}");
    println!(
        "  last_sequence: {}",
        last_seq.map(|s| s.to_string()).unwrap_or("<none>".into())
    );
    println!("  head_hash: {}", head_hash.as_deref().unwrap_or("<none>"));
    println!("  signers:");
    let mut sigs: Vec<_> = signers.iter().collect();
    sigs.sort();
    for (kid, n) in sigs {
        println!("    {kid}: {n}");
    }
    match verifier {
        Some(_) => {
            println!(
                "  signatures: {} valid, {} invalid",
                count.saturating_sub(bad_signatures),
                bad_signatures
            );
            if bad_signatures > 0 {
                return 1;
            }
        }
        None => println!("  signatures: present (unverified — pass --verify-with)"),
    }
    0
}

fn verify_audit_entry_sig(
    entry: &SignedAuditEntry,
    verifier: &HashMap<String, VerifyingKey>,
) -> bool {
    let Some(vk) = verifier.get(&entry.signer_kid) else {
        return false;
    };
    let canonical = match sha256_hex_json(&entry.entry) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let Ok(raw) = STANDARD.decode(entry.entry_signature.as_bytes()) else {
        return false;
    };
    let Ok(arr): Result<[u8; 64], _> = raw.as_slice().try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&arr);
    vk.verify(canonical.as_bytes(), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn safe_bundle_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/biosynthesis/safe-bundle.json")
    }

    fn university_profile_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("profiles/biosynthesis/university_bsl2_dna.json")
    }

    #[test]
    fn no_input_flag_returns_usage_error() {
        let args = InspectArgs {
            bundle: None,
            profile: None,
            verdict: None,
            audit_log: None,
            verify_with: None,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn multiple_input_flags_returns_usage_error() {
        let args = InspectArgs {
            bundle: Some(safe_bundle_path()),
            profile: Some(university_profile_path()),
            verdict: None,
            audit_log: None,
            verify_with: None,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn inspect_bundle_succeeds() {
        let args = InspectArgs {
            bundle: Some(safe_bundle_path()),
            profile: None,
            verdict: None,
            audit_log: None,
            verify_with: None,
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn inspect_profile_succeeds() {
        let args = InspectArgs {
            bundle: None,
            profile: Some(university_profile_path()),
            verdict: None,
            audit_log: None,
            verify_with: None,
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn inspect_missing_file_returns_internal_error() {
        let args = InspectArgs {
            bundle: Some(PathBuf::from("/nonexistent/bundle.json")),
            profile: None,
            verdict: None,
            audit_log: None,
            verify_with: None,
        };
        assert_eq!(run(&args), 3);
    }

    #[test]
    fn inspect_verdict_with_tampered_signature_reports_invalid() {
        // Build a real signed verdict and then mangle the signature.
        use chrono::Utc;
        use ed25519_dalek::SigningKey;
        use invariant_biosynthesis::models::verdict::{
            AuthoritySummary, SignedVerdict, Verdict,
        };
        use rand::rngs::OsRng;
        let dir = TempDir::new().unwrap();
        let v = Verdict {
            approved: true,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks: vec![],
            profile_name: "p".into(),
            profile_hash: "sha256:p".into(),
            authority_summary: AuthoritySummary {
                origin_principal: "x".into(),
                hop_count: 0,
                operations_granted: vec![],
                operations_required: vec![],
            },
            threat_analysis: None,
        };
        let sk = SigningKey::generate(&mut OsRng);
        let canonical = sha256_hex_json(&v).unwrap();
        use ed25519_dalek::Signer;
        let sig = sk.sign(canonical.as_bytes());
        let signed = SignedVerdict {
            verdict: v,
            verdict_signature: STANDARD.encode(sig.to_bytes()),
            signer_kid: "kid-1".into(),
        };
        // Tamper the signature.
        let mut tampered = signed.clone();
        tampered.verdict_signature = STANDARD.encode([0u8; 64]);
        let v_path = dir.path().join("v.json");
        fs::write(&v_path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
        // Pub key file
        let pub_path = dir.path().join("pub.json");
        let pub_kf = crate::key_file::KeyFile {
            kid: "kid-1".into(),
            public_key: STANDARD.encode(sk.verifying_key().as_bytes()),
            secret_key: None,
        };
        fs::write(&pub_path, serde_json::to_vec_pretty(&pub_kf).unwrap()).unwrap();
        let args = InspectArgs {
            bundle: None,
            profile: None,
            verdict: Some(v_path),
            audit_log: None,
            verify_with: Some(pub_path),
        };
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn inspect_verdict_unverified_when_no_pub_key_provided() {
        // Build a real signed verdict and inspect without --verify-with.
        use chrono::Utc;
        use ed25519_dalek::SigningKey;
        use invariant_biosynthesis::models::verdict::{
            AuthoritySummary, SignedVerdict, Verdict,
        };
        use rand::rngs::OsRng;
        let dir = TempDir::new().unwrap();
        let v = Verdict {
            approved: true,
            command_hash: "sha256:abc".into(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks: vec![],
            profile_name: "p".into(),
            profile_hash: "sha256:p".into(),
            authority_summary: AuthoritySummary {
                origin_principal: "x".into(),
                hop_count: 0,
                operations_granted: vec![],
                operations_required: vec![],
            },
            threat_analysis: None,
        };
        let sk = SigningKey::generate(&mut OsRng);
        use ed25519_dalek::Signer;
        let sig = sk.sign(sha256_hex_json(&v).unwrap().as_bytes());
        let signed = SignedVerdict {
            verdict: v,
            verdict_signature: STANDARD.encode(sig.to_bytes()),
            signer_kid: "kid-1".into(),
        };
        let v_path = dir.path().join("v.json");
        fs::write(&v_path, serde_json::to_vec_pretty(&signed).unwrap()).unwrap();
        let args = InspectArgs {
            bundle: None,
            profile: None,
            verdict: Some(v_path),
            audit_log: None,
            verify_with: None,
        };
        assert_eq!(run(&args), 0);
    }
}
