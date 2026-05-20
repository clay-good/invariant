//! `invariant robotics assemble` — assemble a proof package from one or more
//! campaign shard subdirectories. v11 1.5.
//!
//! A "shard" is a subdirectory under `--shards` that contains the artifacts
//! produced by a single campaign shard:
//!
//! - `audit.jsonl`   — audit log fragment (one JSON entry per line)
//! - `summary.json`  — optional [`CampaignSummary`] for the shard
//! - any other files are ignored
//!
//! The shards are read in sorted order by file name (so `shard-000`,
//! `shard-001`, … assemble deterministically). Audit logs are concatenated
//! into a single `results/audit.jsonl`; summaries are summed; the RFC 6962
//! Merkle root is recomputed over every `entry_hash` from the merged log;
//! finally [`proof_package::assemble`] is invoked to materialise the
//! package directory.
//!
//! When `--key` is supplied the manifest is JCS-canonicalised and signed
//! (Ed25519, base64-no-padding). When `--public-key` is supplied the
//! assembled manifest is re-loaded and the signature verified; a mismatch
//! exits with status 1.

use clap::Args;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use invariant_robotics::proof_package::{
    assemble, verify_manifest, CampaignSummary, PackageInputs, ProofPackageManifest,
};

/// Sidecar state schema (v12 N-6). Persisted as
/// `<output_dir>.assemble-state.json` next to the package output. The file is
/// fsynced after every shard is folded into the merge so a SIGTERM/SIGINT mid-
/// run leaves a recoverable marker. `--resume` will not consume a sidecar
/// whose `output_dir` does not match the current `--output`, guarding against
/// accidental reuse across destinations.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct AssembleState {
    /// Schema version. Bump when fields are added/removed; old states are
    /// rejected with a typed error so partial assemblies cannot be misread.
    version: u32,
    /// Absolute path of the output directory this state belongs to. Used as
    /// a sanity check on resume.
    output_dir: String,
    /// Ordered list of shards that have been folded into the merge. The list
    /// is appended one entry at a time and persisted after every push.
    consumed: Vec<ConsumedShard>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ConsumedShard {
    /// Absolute path to the shard directory.
    path: String,
    /// SHA-256 of the shard's `audit.jsonl` (lowercase hex). Empty string if
    /// the shard had no audit log.
    audit_sha256: String,
    /// Number of non-empty lines folded from this shard's `audit.jsonl`.
    audit_line_count: u64,
    /// Summary fields summed from this shard (mirror of `CampaignSummary`
    /// inputs — never the computed aggregate). One per shard so a corrupt
    /// shard can be re-detected on resume.
    summary_total: u64,
    summary_approved: u64,
    summary_rejected: u64,
    summary_escapes: u64,
    summary_adv: u64,
    summary_adv_esc: u64,
    control_hz: Option<f64>,
}

const ASSEMBLE_STATE_VERSION: u32 = 1;

#[cfg(test)]
thread_local! {
    /// Test-only panic injector. When set to N>0 by a test, the merge loop
    /// panics after folding the Nth fresh shard. Cleared automatically by
    /// the [`PanicAfter`] RAII guard.
    static TEST_PANIC_AFTER_SHARD: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn sidecar_path(output: &Path) -> PathBuf {
    let mut s = output.as_os_str().to_owned();
    s.push(".assemble-state.json");
    PathBuf::from(s)
}

#[derive(Args)]
pub struct AssembleArgs {
    /// Directory containing per-shard subdirectories. Each subdirectory
    /// should contain an `audit.jsonl` and optionally `summary.json`.
    #[arg(long, value_name = "DIR")]
    pub shards: PathBuf,

    /// Where to write the assembled proof package directory.
    #[arg(long, value_name = "DIR")]
    pub output: PathBuf,

    /// Ed25519 signing key (same JSON shape as `keygen --output`).
    /// When omitted, the manifest is left unsigned and a warning is
    /// printed to stderr.
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Public key file used for the post-write self-verify step.
    /// Required if `--key` is supplied; without `--key` it is a no-op
    /// (the manifest is unsigned so there is nothing to verify).
    #[arg(long = "public-key", value_name = "PATH")]
    pub public_key: Option<PathBuf>,

    /// Passthrough metadata `KEY=VALUE`. May be repeated. Stored in the
    /// manifest under `extra.<KEY>`. Reserved characters in KEY: only
    /// `[A-Za-z0-9_-]` are accepted; VALUE is taken verbatim.
    #[arg(long = "metadata", value_name = "KEY=VALUE")]
    pub metadata: Vec<String>,

    /// Campaign name to embed in the manifest. Defaults to the basename
    /// of `--shards`.
    #[arg(long, value_name = "NAME")]
    pub campaign_name: Option<String>,

    /// Profile name to embed in the manifest. Defaults to `"unknown"`.
    #[arg(long, value_name = "NAME")]
    pub profile_name: Option<String>,

    /// Binary hash to embed in the manifest. Defaults to the SHA-256 of
    /// the running binary (matches `verify-self`).
    #[arg(long, value_name = "HEX")]
    pub binary_hash: Option<String>,

    /// Path to a `public_keys.json` to embed at `integrity/public_keys.json`.
    /// Required for `verify-package` to pass the "Public keys" check.
    #[arg(long = "public-keys", value_name = "PATH")]
    pub public_keys: Option<PathBuf>,

    /// Adversarial report file(s) to embed under `adversarial/<filename>`.
    /// May be repeated. `verify-package` rejects packages whose
    /// `adversarial/` directory is empty.
    #[arg(long = "adversarial", value_name = "PATH")]
    pub adversarial: Vec<PathBuf>,

    /// Resume a previously-interrupted assembly. Reads
    /// `<output>.assemble-state.json` (the sidecar fsynced after every
    /// shard) and skips shards already folded into the merge. Re-verifies
    /// the digest of each already-consumed shard's `audit.jsonl` to catch
    /// source-tree tampering between runs. Without this flag, a pre-existing
    /// sidecar causes the command to exit 2 with a "pass --resume or remove"
    /// message rather than silently overwriting an in-progress assembly.
    #[arg(long)]
    pub resume: bool,
}

pub fn run(args: &AssembleArgs) -> i32 {
    // 1. Validate the shards directory.
    if !args.shards.is_dir() {
        eprintln!(
            "error: --shards directory does not exist: {}",
            args.shards.display()
        );
        return 2;
    }

    // 2a. Sidecar handling (v12 N-6): if `<output>.assemble-state.json`
    //     exists from a prior interrupted run, only proceed when `--resume`
    //     is supplied. Without it, refuse to overwrite an in-progress
    //     assembly.
    let sidecar = sidecar_path(&args.output);
    let mut prior_state: Option<AssembleState> = None;
    if sidecar.exists() {
        if !args.resume {
            eprintln!(
                "error: existing assembly state at {} — pass --resume or remove the sidecar",
                sidecar.display()
            );
            return 2;
        }
        match load_state(&sidecar, &args.output) {
            Ok(s) => prior_state = Some(s),
            Err(e) => {
                eprintln!("error: failed to load assembly state: {e}");
                return 2;
            }
        }
    } else if args.resume {
        // Allowed: --resume on a fresh output is treated as a normal run.
        eprintln!(
            "note: --resume passed but no sidecar at {}; starting fresh.",
            sidecar.display()
        );
    }

    // 2b. Refuse to clobber an existing non-empty output directory, *unless*
    //     we are resuming a prior run (in which case the output dir likely
    //     contains partial artifacts that will be overwritten by the final
    //     `assemble` call).
    if args.output.exists() && prior_state.is_none() {
        match std::fs::read_dir(&args.output) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    eprintln!(
                        "error: --output {} already exists and is not empty",
                        args.output.display()
                    );
                    return 2;
                }
            }
            Err(e) => {
                eprintln!("error: cannot read --output {}: {e}", args.output.display());
                return 2;
            }
        }
    }

    // 3. Parse metadata key=value pairs.
    let metadata = match parse_metadata(&args.metadata) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: --metadata: {e}");
            return 2;
        }
    };

    // 4. Enumerate shard subdirectories in sorted order.
    let shards = match enumerate_shards(&args.shards) {
        Ok(s) if s.is_empty() => {
            eprintln!(
                "error: --shards {} contains no shard subdirectories",
                args.shards.display()
            );
            return 2;
        }
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to enumerate shards: {e}");
            return 2;
        }
    };

    // 5. Merge audit logs + summaries, persisting sidecar state after each
    //    shard so a SIGTERM mid-run leaves a recoverable marker.
    let merged = match merge_shards_with_state(&shards, &args.output, prior_state.as_ref()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: failed to merge shards: {e}");
            return 2;
        }
    };

    // 6. Compute the RFC 6962 Merkle root over the merged log's
    //    `entry_hash` sequence. Empty log → MTH({}).
    let merkle_root_hex = match merkle_root_hex(&merged.audit_jsonl) {
        Ok(hex) => hex,
        Err(e) => {
            eprintln!("error: failed to compute merkle root: {e}");
            return 2;
        }
    };

    // 7. Optionally load the signing key.
    let signing_key = match args.key.as_deref() {
        Some(path) => match load_signing_key(path) {
            Ok(pair) => Some(pair),
            Err(e) => {
                eprintln!("error: --key: {e}");
                return 2;
            }
        },
        None => None,
    };
    if signing_key.is_none() {
        eprintln!("warning: --key not supplied; manifest will be unsigned.");
    }

    // 8. Write the merged audit log to a temp file so `assemble` can copy
    //    it into the package's `results/audit.jsonl`.
    let temp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: failed to create temp dir: {e}");
            return 2;
        }
    };
    let merged_audit_path = temp_dir.path().join("audit.jsonl");
    if let Err(e) = std::fs::write(&merged_audit_path, &merged.audit_jsonl) {
        eprintln!("error: failed to write merged audit log: {e}");
        return 2;
    }

    // 9. Build inputs and call `assemble`.
    let binary_hash = args
        .binary_hash
        .clone()
        .unwrap_or_else(default_binary_hash);

    let campaign_name = args
        .campaign_name
        .clone()
        .unwrap_or_else(|| basename(&args.shards).unwrap_or_else(|| "campaign".into()));

    let profile_name = args
        .profile_name
        .clone()
        .unwrap_or_else(|| "unknown".into());

    // Materialise adversarial reports under `<basename>` keys (with
    // path-traversal validation handled by `proof_package::assemble`).
    let mut adversarial_reports: HashMap<String, PathBuf> = HashMap::new();
    for path in &args.adversarial {
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => {
                eprintln!(
                    "error: --adversarial {} has no usable filename",
                    path.display()
                );
                return 2;
            }
        };
        if adversarial_reports.contains_key(&name) {
            eprintln!(
                "error: duplicate adversarial report filename {name:?} (rename one of the inputs)"
            );
            return 2;
        }
        adversarial_reports.insert(name, path.clone());
    }

    let inputs = PackageInputs {
        campaign_config: None,
        profile: None,
        audit_log: Some(merged_audit_path.clone()),
        adversarial_reports,
        compliance_mappings: HashMap::new(),
        public_keys: args.public_keys.clone(),
        campaign_name,
        profile_name,
        binary_hash,
        summary: merged.summary,
        merkle_root_hex: Some(merkle_root_hex.clone()),
        signing_key,
    };

    let manifest = match assemble(&inputs, &args.output) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: assemble failed: {e}");
            return 2;
        }
    };

    // 10. If metadata was supplied, write it as a sidecar at
    //     `<output>/integrity/metadata.json` and surface a one-line note.
    //     The manifest itself does not currently carry an `extra` map
    //     (planned for a future format-version bump); the sidecar keeps
    //     the data colocated with the package without breaking the
    //     existing JCS canonical form / signature.
    if !metadata.is_empty() {
        let path = args.output.join("integrity").join("metadata.json");
        match serde_json::to_string_pretty(&metadata) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json.as_bytes()) {
                    eprintln!("error: failed to write metadata sidecar: {e}");
                    return 2;
                }
            }
            Err(e) => {
                eprintln!("error: failed to serialize metadata: {e}");
                return 2;
            }
        }
    }

    // 11. Self-verify: if `--public-key` was supplied and the manifest is
    //     signed, reload it and verify the signature end-to-end.
    if let Some(pub_path) = &args.public_key {
        if manifest.manifest_signature.is_none() {
            eprintln!(
                "warning: --public-key supplied but manifest is unsigned (no --key); skipping self-verify."
            );
        } else {
            match self_verify(&args.output, pub_path) {
                Ok(()) => {
                    eprintln!("Self-verify: manifest signature OK.");
                }
                Err(e) => {
                    eprintln!("error: self-verify failed: {e}");
                    return 1;
                }
            }
        }
    }

    // 12. On successful assembly remove the sidecar so a future re-run
    //     without `--resume` against the same `--output` is not blocked.
    //     (A clean output dir is still required by step 2b on any fresh run.)
    if sidecar.exists() {
        if let Err(e) = std::fs::remove_file(&sidecar) {
            eprintln!(
                "warning: failed to remove sidecar {}: {e}",
                sidecar.display()
            );
        }
    }

    // 13. Print a one-line success summary.
    println!(
        "Assembled proof package at {} ({} shards, {} audit entries, merkle_root={}).",
        args.output.display(),
        shards.len(),
        merged.entry_count,
        &merkle_root_hex[..16.min(merkle_root_hex.len())],
    );

    0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_metadata(items: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for item in items {
        let (k, v) = item
            .split_once('=')
            .ok_or_else(|| format!("expected KEY=VALUE, got {item:?}"))?;
        if k.is_empty() {
            return Err(format!("empty key in {item:?}"));
        }
        if !k
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "key {k:?} contains characters outside [A-Za-z0-9_-]"
            ));
        }
        if out.insert(k.to_string(), v.to_string()).is_some() {
            return Err(format!("duplicate key {k:?}"));
        }
    }
    Ok(out)
}

fn enumerate_shards(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut subdirs: Vec<PathBuf> = std::fs::read_dir(root)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    subdirs.sort();
    Ok(subdirs)
}

struct MergedShards {
    audit_jsonl: String,
    summary: CampaignSummary,
    entry_count: u64,
}

#[cfg(test)]
fn merge_shards(shards: &[PathBuf]) -> Result<MergedShards, String> {
    let mut audit = String::new();
    let mut entry_count: u64 = 0;

    // Accumulators for summary fields we sum across shards.
    let mut total: u64 = 0;
    let mut approved: u64 = 0;
    let mut rejected: u64 = 0;
    let mut escapes: u64 = 0;
    let mut adv: u64 = 0;
    let mut adv_esc: u64 = 0;
    // Use the first shard's control_frequency_hz; warn if shards disagree.
    let mut control_hz: Option<f64> = None;

    for shard in shards {
        let shard_name = shard
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unnamed>")
            .to_string();

        let audit_path = shard.join("audit.jsonl");
        if audit_path.exists() {
            let content = std::fs::read_to_string(&audit_path)
                .map_err(|e| format!("shard {shard_name}: read audit.jsonl: {e}"))?;
            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                audit.push_str(line);
                audit.push('\n');
                entry_count += 1;
            }
        }

        let summary_path = shard.join("summary.json");
        if summary_path.exists() {
            let s: CampaignSummary = serde_json::from_str(
                &std::fs::read_to_string(&summary_path)
                    .map_err(|e| format!("shard {shard_name}: read summary.json: {e}"))?,
            )
            .map_err(|e| format!("shard {shard_name}: parse summary.json: {e}"))?;
            total += s.total_commands;
            approved += s.commands_approved;
            rejected += s.commands_rejected;
            escapes += s.violation_escapes;
            adv += s.adversarial_commands;
            adv_esc += s.adversarial_escapes;
            match control_hz {
                None => control_hz = Some(s.control_frequency_hz),
                Some(existing) if (existing - s.control_frequency_hz).abs() > f64::EPSILON => {
                    eprintln!(
                        "warning: shard {shard_name} reports control_frequency_hz={}, expected {existing}; using {existing}",
                        s.control_frequency_hz
                    );
                }
                Some(_) => {}
            }
        }
    }

    let summary = CampaignSummary::compute(
        total,
        approved,
        rejected,
        escapes,
        adv,
        adv_esc,
        control_hz.unwrap_or(0.0),
    );

    Ok(MergedShards {
        audit_jsonl: audit,
        summary,
        entry_count,
    })
}

/// Hash the bytes of a file (or return an empty string for missing files).
/// Used to fingerprint each shard's `audit.jsonl` in the sidecar.
fn sha256_file_hex(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    if !path.exists() {
        return Ok(String::new());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(format!("{:x}", h.finalize()))
}

fn load_state(sidecar: &Path, output: &Path) -> Result<AssembleState, String> {
    let bytes =
        std::fs::read(sidecar).map_err(|e| format!("read {}: {e}", sidecar.display()))?;
    let state: AssembleState = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse {}: {e}", sidecar.display()))?;
    if state.version != ASSEMBLE_STATE_VERSION {
        return Err(format!(
            "sidecar version {} does not match expected {}",
            state.version, ASSEMBLE_STATE_VERSION
        ));
    }
    let want = output.to_string_lossy().to_string();
    if state.output_dir != want {
        return Err(format!(
            "sidecar output_dir {:?} does not match --output {:?}",
            state.output_dir, want
        ));
    }
    Ok(state)
}

fn write_state_durable(sidecar: &Path, state: &AssembleState) -> Result<(), String> {
    // Write to a temp file in the same directory, fsync, then atomic rename.
    let parent = sidecar.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    let tmp = sidecar.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| format!("serialize state: {e}"))?;
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("open {}: {e}", tmp.display()))?;
        std::io::Write::write_all(&mut f, &json)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, sidecar)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), sidecar.display()))?;
    Ok(())
}

/// Shard-aware merge with optional resume. Walks `shards` in sorted order;
/// for each shard that already appears in `prior` (matched by absolute path)
/// re-verifies the `audit.jsonl` digest and re-folds the cached counts.
/// Shards not in `prior` are processed fresh and appended to the sidecar
/// state, which is fsynced after each push.
///
/// Returns the same shape as the legacy [`merge_shards`] so the rest of the
/// pipeline (Merkle root computation, `assemble`, self-verify) is unchanged.
fn merge_shards_with_state(
    shards: &[PathBuf],
    output: &Path,
    prior: Option<&AssembleState>,
) -> Result<MergedShards, String> {
    let sidecar = sidecar_path(output);
    let prior_map: HashMap<&str, &ConsumedShard> = prior
        .map(|s| s.consumed.iter().map(|c| (c.path.as_str(), c)).collect())
        .unwrap_or_default();

    let mut state = AssembleState {
        version: ASSEMBLE_STATE_VERSION,
        output_dir: output.to_string_lossy().to_string(),
        consumed: Vec::with_capacity(shards.len()),
    };

    let mut audit = String::new();
    let mut entry_count: u64 = 0;
    let mut total: u64 = 0;
    let mut approved: u64 = 0;
    let mut rejected: u64 = 0;
    let mut escapes: u64 = 0;
    let mut adv: u64 = 0;
    let mut adv_esc: u64 = 0;
    let mut control_hz: Option<f64> = None;

    // `idx` is only consumed by the cfg(test) panic-injection hook below;
    // suppress the unused-variable warning in non-test builds.
    #[allow(unused_variables)]
    for (idx, shard) in shards.iter().enumerate() {
        let shard_key = shard.to_string_lossy().to_string();
        let shard_name = shard
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unnamed>")
            .to_string();

        let audit_path = shard.join("audit.jsonl");
        let current_digest = sha256_file_hex(&audit_path)
            .map_err(|e| format!("shard {shard_name}: {e}"))?;

        if let Some(prev) = prior_map.get(shard_key.as_str()) {
            if prev.audit_sha256 != current_digest {
                return Err(format!(
                    "shard {shard_name}: audit.jsonl digest changed since last run \
                     (cached {}, current {}); source tampering or out-of-band edit",
                    prev.audit_sha256, current_digest
                ));
            }
            // Replay cached content from disk (still need the JSONL bytes for
            // the final Merkle pass) and re-fold cached counts.
            if audit_path.exists() {
                let content = std::fs::read_to_string(&audit_path)
                    .map_err(|e| format!("shard {shard_name}: read audit.jsonl: {e}"))?;
                for line in content.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    audit.push_str(line);
                    audit.push('\n');
                    entry_count += 1;
                }
            }
            total += prev.summary_total;
            approved += prev.summary_approved;
            rejected += prev.summary_rejected;
            escapes += prev.summary_escapes;
            adv += prev.summary_adv;
            adv_esc += prev.summary_adv_esc;
            if let Some(hz) = prev.control_hz {
                control_hz.get_or_insert(hz);
            }
            state.consumed.push((*prev).clone());
        } else {
            // Fresh shard: fold and persist sidecar.
            let mut shard_line_count: u64 = 0;
            if audit_path.exists() {
                let content = std::fs::read_to_string(&audit_path)
                    .map_err(|e| format!("shard {shard_name}: read audit.jsonl: {e}"))?;
                for line in content.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    audit.push_str(line);
                    audit.push('\n');
                    entry_count += 1;
                    shard_line_count += 1;
                }
            }

            let mut shard_total = 0u64;
            let mut shard_approved = 0u64;
            let mut shard_rejected = 0u64;
            let mut shard_escapes = 0u64;
            let mut shard_adv = 0u64;
            let mut shard_adv_esc = 0u64;
            let mut shard_hz: Option<f64> = None;
            let summary_path = shard.join("summary.json");
            if summary_path.exists() {
                let s: CampaignSummary = serde_json::from_str(
                    &std::fs::read_to_string(&summary_path)
                        .map_err(|e| format!("shard {shard_name}: read summary.json: {e}"))?,
                )
                .map_err(|e| format!("shard {shard_name}: parse summary.json: {e}"))?;
                shard_total = s.total_commands;
                shard_approved = s.commands_approved;
                shard_rejected = s.commands_rejected;
                shard_escapes = s.violation_escapes;
                shard_adv = s.adversarial_commands;
                shard_adv_esc = s.adversarial_escapes;
                shard_hz = Some(s.control_frequency_hz);
                total += shard_total;
                approved += shard_approved;
                rejected += shard_rejected;
                escapes += shard_escapes;
                adv += shard_adv;
                adv_esc += shard_adv_esc;
                match control_hz {
                    None => control_hz = Some(s.control_frequency_hz),
                    Some(existing)
                        if (existing - s.control_frequency_hz).abs() > f64::EPSILON =>
                    {
                        eprintln!(
                            "warning: shard {shard_name} reports control_frequency_hz={}, expected {existing}; using {existing}",
                            s.control_frequency_hz
                        );
                    }
                    Some(_) => {}
                }
            }

            state.consumed.push(ConsumedShard {
                path: shard_key,
                audit_sha256: current_digest,
                audit_line_count: shard_line_count,
                summary_total: shard_total,
                summary_approved: shard_approved,
                summary_rejected: shard_rejected,
                summary_escapes: shard_escapes,
                summary_adv: shard_adv,
                summary_adv_esc: shard_adv_esc,
                control_hz: shard_hz,
            });
            write_state_durable(&sidecar, &state)?;

            // Test hook (v12 N-6): allow integration tests to simulate a
            // SIGTERM mid-run after a configurable shard count. Uses a
            // thread-local so parallel test execution does not leak the
            // trigger into unrelated tests.
            #[cfg(test)]
            {
                let after = TEST_PANIC_AFTER_SHARD.with(|c| c.get());
                if after > 0 && (idx + 1) >= after {
                    panic!(
                        "TEST_PANIC_AFTER_SHARD={after}: simulated abort after shard {idx}"
                    );
                }
            }
        }
    }

    let summary = CampaignSummary::compute(
        total,
        approved,
        rejected,
        escapes,
        adv,
        adv_esc,
        control_hz.unwrap_or(0.0),
    );

    Ok(MergedShards {
        audit_jsonl: audit,
        summary,
        entry_count,
    })
}

fn merkle_root_hex(jsonl: &str) -> Result<String, String> {
    use invariant_core::merkle::{leaf_hash, MerkleAccumulator};
    let mut acc = MerkleAccumulator::new();
    for (idx, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("audit line {}: parse: {e}", idx + 1))?;
        let entry_hash = value
            .get("entry_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("audit line {}: missing entry_hash", idx + 1))?;
        acc.push_leaf_hash(leaf_hash(entry_hash.as_bytes()));
    }
    let root = acc.root();
    let mut hex = String::with_capacity(64);
    for b in root {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(hex)
}

fn load_signing_key(path: &Path) -> Result<(ed25519_dalek::SigningKey, String), String> {
    let kf = crate::key_file::load_key_file(path)?;
    let (sk, _vk, kid) = crate::key_file::load_signing_key(&kf)?;
    Ok((sk, kid))
}

fn self_verify(package_dir: &Path, pubkey_path: &Path) -> Result<(), String> {
    let manifest_json = std::fs::read_to_string(package_dir.join("manifest.json"))
        .map_err(|e| format!("read manifest.json: {e}"))?;
    let manifest: ProofPackageManifest = serde_json::from_str(&manifest_json)
        .map_err(|e| format!("parse manifest.json: {e}"))?;
    let kf = crate::key_file::load_key_file(pubkey_path)?;
    let (vk, _kid) = crate::key_file::load_verifying_key(&kf)?;
    verify_manifest(&manifest, &vk).map_err(|e| format!("verify_manifest: {e}"))?;
    Ok(())
}

fn basename(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
}

fn default_binary_hash() -> String {
    // Match the verify-self behaviour: hash the current executable.
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return "sha256:unknown".into(),
    };
    let bytes = match std::fs::read(&exe) {
        Ok(b) => b,
        Err(_) => return "sha256:unknown".into(),
    };
    format!("sha256:{}", invariant_robotics::util::sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;
    use std::io::Write;
    use tempfile::TempDir;

    fn make_signed_audit_line(
        sk: &ed25519_dalek::SigningKey,
        kid: &str,
        seq: u64,
        prev: &str,
    ) -> String {
        // Build a minimal entry that the assembler will accept: it only
        // needs a top-level `entry_hash` field for the Merkle stream. We
        // populate a few extra fields so the resulting JSONL looks like a
        // real audit record without requiring the full robotics envelope.
        use sha2::{Digest, Sha256};
        let body = format!(r#"{{"seq":{seq},"prev":"{prev}"}}"#);
        let mut h = Sha256::new();
        h.update(body.as_bytes());
        let entry_hash = format!("{:x}", h.finalize());
        let sig_payload = format!("{kid}:{entry_hash}");
        let sig = sk.sign(sig_payload.as_bytes());
        let sig_b64 = STANDARD.encode(sig.to_bytes());
        format!(
            r#"{{"sequence":{seq},"entry_hash":"{entry_hash}","previous_hash":"{prev}","signature":"{sig_b64}","kid":"{kid}"}}"#
        )
    }

    fn write_shard(dir: &Path, name: &str, lines: &[String], summary: &CampaignSummary) {
        let shard = dir.join(name);
        std::fs::create_dir_all(&shard).unwrap();
        let mut audit = std::fs::File::create(shard.join("audit.jsonl")).unwrap();
        for l in lines {
            writeln!(audit, "{l}").unwrap();
        }
        let summary_json = serde_json::to_string_pretty(summary).unwrap();
        std::fs::write(shard.join("summary.json"), summary_json.as_bytes()).unwrap();
    }

    fn keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = invariant_robotics::authority::crypto::generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn write_key_file(path: &Path, kid: &str, sk: &ed25519_dalek::SigningKey) {
        let kf = crate::key_file::KeyFile {
            kid: kid.into(),
            public_key: STANDARD.encode(sk.verifying_key().as_bytes()),
            secret_key: Some(STANDARD.encode(sk.to_bytes())),
        };
        crate::key_file::write_key_file(path, &kf).unwrap();
    }

    fn write_pub_key_file(path: &Path, kid: &str, vk: &ed25519_dalek::VerifyingKey) {
        let kf = crate::key_file::KeyFile {
            kid: kid.into(),
            public_key: STANDARD.encode(vk.as_bytes()),
            secret_key: None,
        };
        crate::key_file::write_key_file(path, &kf).unwrap();
    }

    fn setup_shards(temp: &TempDir, n: usize) -> PathBuf {
        let shards = temp.path().join("shards");
        std::fs::create_dir_all(&shards).unwrap();
        let (sk, _vk) = keypair();
        let mut prev = "0".repeat(64);
        for s in 0..n {
            let mut lines = Vec::new();
            for i in 0..3 {
                let seq = (s * 3 + i) as u64;
                let line = make_signed_audit_line(&sk, "test-kid", seq, &prev);
                // Snapshot entry_hash for the next prev.
                let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                prev = v["entry_hash"].as_str().unwrap().to_string();
                lines.push(line);
            }
            let summary = CampaignSummary::compute(100, 95, 5, 0, 10, 0, 100.0);
            write_shard(&shards, &format!("shard-{s:03}"), &lines, &summary);
        }
        shards
    }

    #[test]
    fn missing_shards_dir_returns_2() {
        let args = AssembleArgs {
            shards: PathBuf::from("/nonexistent/shards"),
            output: PathBuf::from("/tmp/out"),
            key: None,
            public_key: None,
            metadata: vec![],
            campaign_name: None,
            profile_name: None,
            binary_hash: None,
            public_keys: None,
            adversarial: vec![],
            resume: false,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn empty_shards_dir_returns_2() {
        let temp = tempfile::tempdir().unwrap();
        let shards = temp.path().join("shards");
        std::fs::create_dir_all(&shards).unwrap();
        let args = AssembleArgs {
            shards,
            output: temp.path().join("out"),
            key: None,
            public_key: None,
            metadata: vec![],
            campaign_name: None,
            profile_name: None,
            binary_hash: None,
            public_keys: None,
            adversarial: vec![],
            resume: false,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn nonempty_output_dir_returns_2() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 1);
        let output = temp.path().join("out");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("preexisting"), b"x").unwrap();
        let args = AssembleArgs {
            shards,
            output,
            key: None,
            public_key: None,
            metadata: vec![],
            campaign_name: None,
            profile_name: None,
            binary_hash: None,
            public_keys: None,
            adversarial: vec![],
            resume: false,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn assembles_unsigned_package_from_two_shards() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 2);
        let output = temp.path().join("out");
        let args = AssembleArgs {
            shards,
            output: output.clone(),
            key: None,
            public_key: None,
            metadata: vec![],
            campaign_name: Some("test_campaign".into()),
            profile_name: Some("ur10".into()),
            binary_hash: Some("sha256:test".into()),
            public_keys: None,
            adversarial: vec![],
            resume: false,
        };
        assert_eq!(run(&args), 0);
        assert!(output.join("manifest.json").exists());
        assert!(output.join("results/audit.jsonl").exists());
        assert!(output.join("integrity/merkle_root.txt").exists());
        // Two shards × three entries = six audit lines.
        let merged = std::fs::read_to_string(output.join("results/audit.jsonl")).unwrap();
        assert_eq!(merged.lines().filter(|l| !l.is_empty()).count(), 6);
        // No signature because --key was not supplied.
        assert!(!output.join("manifest.sig").exists());
    }

    #[test]
    fn assembles_signed_package_and_self_verifies() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 2);
        let output = temp.path().join("out");
        let (sk, vk) = keypair();
        let key_path = temp.path().join("signer.json");
        let pub_path = temp.path().join("signer.pub.json");
        write_key_file(&key_path, "signer-1", &sk);
        write_pub_key_file(&pub_path, "signer-1", &vk);
        let args = AssembleArgs {
            shards,
            output: output.clone(),
            key: Some(key_path),
            public_key: Some(pub_path),
            metadata: vec!["run_id=abc-123".into(), "operator=ci".into()],
            campaign_name: None,
            profile_name: None,
            binary_hash: Some("sha256:test".into()),
            public_keys: None,
            adversarial: vec![],
            resume: false,
        };
        assert_eq!(run(&args), 0);
        assert!(output.join("manifest.sig").exists());
        assert!(output.join("integrity/metadata.json").exists());
        let metadata: BTreeMap<String, String> = serde_json::from_str(
            &std::fs::read_to_string(output.join("integrity/metadata.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(metadata.get("run_id").map(String::as_str), Some("abc-123"));
        assert_eq!(metadata.get("operator").map(String::as_str), Some("ci"));
    }

    #[test]
    fn self_verify_fails_with_wrong_public_key() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 1);
        let output = temp.path().join("out");
        let (sk, _vk) = keypair();
        let (_, vk_other) = keypair();
        let key_path = temp.path().join("signer.json");
        let pub_path = temp.path().join("wrong.pub.json");
        write_key_file(&key_path, "signer-1", &sk);
        write_pub_key_file(&pub_path, "signer-1", &vk_other);
        let args = AssembleArgs {
            shards,
            output,
            key: Some(key_path),
            public_key: Some(pub_path),
            metadata: vec![],
            campaign_name: None,
            profile_name: None,
            binary_hash: Some("sha256:test".into()),
            public_keys: None,
            adversarial: vec![],
            resume: false,
        };
        // assemble succeeds; self-verify fails → exit 1.
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn merge_shards_is_deterministic_in_sorted_order() {
        // Two shards with distinguishable first lines; assert the merged
        // log preserves shard-000 entries before shard-001 entries.
        let temp = tempfile::tempdir().unwrap();
        let shards = temp.path().join("shards");
        std::fs::create_dir_all(&shards).unwrap();
        let (sk, _vk) = keypair();
        // Build shard-001 first, then shard-000, to confirm sort order
        // wins over insertion order.
        let mut prev = "0".repeat(64);
        let l1 = make_signed_audit_line(&sk, "kid", 0, &prev);
        prev = serde_json::from_str::<serde_json::Value>(&l1).unwrap()["entry_hash"]
            .as_str()
            .unwrap()
            .to_string();
        write_shard(
            &shards,
            "shard-001",
            std::slice::from_ref(&l1),
            &CampaignSummary::compute(1, 1, 0, 0, 0, 0, 100.0),
        );
        let l0 = make_signed_audit_line(&sk, "kid", 1, &prev);
        write_shard(
            &shards,
            "shard-000",
            std::slice::from_ref(&l0),
            &CampaignSummary::compute(1, 1, 0, 0, 0, 0, 100.0),
        );

        let listed = enumerate_shards(&shards).unwrap();
        assert!(listed[0].ends_with("shard-000"));
        assert!(listed[1].ends_with("shard-001"));

        let merged = merge_shards(&listed).unwrap();
        let lines: Vec<&str> = merged.audit_jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], l0);
        assert_eq!(lines[1], l1);
        assert_eq!(merged.summary.total_commands, 2);
    }

    #[test]
    fn parse_metadata_rejects_bad_keys() {
        assert!(parse_metadata(&["bad key=v".into()]).is_err());
        assert!(parse_metadata(&["=v".into()]).is_err());
        assert!(parse_metadata(&["nokvp".into()]).is_err());
        assert!(parse_metadata(&["dup=1".into(), "dup=2".into()]).is_err());
        let ok = parse_metadata(&["good_key-1=hello world".into()]).unwrap();
        assert_eq!(ok.get("good_key-1").map(String::as_str), Some("hello world"));
    }

    #[test]
    fn merkle_root_hex_matches_verify_helper() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 1);
        let merged = merge_shards(&enumerate_shards(&shards).unwrap()).unwrap();
        let hex = merkle_root_hex(&merged.audit_jsonl).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ------------------------------------------------------------------
    // v12 N-6: --resume sidecar tests
    // ------------------------------------------------------------------

    /// RAII guard that arms the thread-local panic injector while the test
    /// is executing and clears it on drop. Each `run()` invocation runs on
    /// the test's own thread (we use `catch_unwind` rather than spawning a
    /// child thread), so the thread-local is naturally scoped.
    struct PanicAfter;
    impl PanicAfter {
        fn arm(n: usize) -> Self {
            TEST_PANIC_AFTER_SHARD.with(|c| c.set(n));
            Self
        }
    }
    impl Drop for PanicAfter {
        fn drop(&mut self) {
            TEST_PANIC_AFTER_SHARD.with(|c| c.set(0));
        }
    }

    fn args_for(shards: PathBuf, output: PathBuf, resume: bool) -> AssembleArgs {
        AssembleArgs {
            shards,
            output,
            key: None,
            public_key: None,
            metadata: vec![],
            campaign_name: Some("test_campaign".into()),
            profile_name: Some("ur10".into()),
            binary_hash: Some("sha256:test".into()),
            public_keys: None,
            adversarial: vec![],
            resume,
        }
    }

    #[test]
    fn pre_existing_sidecar_without_resume_returns_2() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 1);
        let output = temp.path().join("out");
        // Hand-write a sidecar to simulate an interrupted prior run.
        let state = AssembleState {
            version: ASSEMBLE_STATE_VERSION,
            output_dir: output.to_string_lossy().to_string(),
            consumed: vec![],
        };
        let sc = sidecar_path(&output);
        std::fs::write(&sc, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        assert_eq!(run(&args_for(shards, output, false)), 2);
    }

    #[test]
    fn resume_without_prior_sidecar_is_a_normal_run() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 1);
        let output = temp.path().join("out");
        assert_eq!(run(&args_for(shards, output.clone(), true)), 0);
        // Sidecar is cleaned up on success.
        assert!(!sidecar_path(&output).exists());
        assert!(output.join("manifest.json").exists());
    }

    /// Run assemble to completion against a clean output and capture the
    /// final Merkle root for byte-identity comparisons.
    fn assemble_oneshot(shards: PathBuf, output: PathBuf) -> String {
        assert_eq!(run(&args_for(shards, output.clone(), false)), 0);
        std::fs::read_to_string(output.join("integrity/merkle_root.txt")).unwrap()
    }

    #[test]
    fn resume_after_simulated_abort_produces_identical_merkle_root() {
        // Build four shards.
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 4);

        // 1. One-shot run into output-A; capture the Merkle root.
        let out_a = temp.path().join("out-a");
        let root_oneshot = assemble_oneshot(shards.clone(), out_a);

        // 2. Drive a partial run into output-B that aborts after fold #2.
        //    The env var trips a panic deep inside merge_shards_with_state;
        //    catch_unwind contains the panic so the test process survives.
        let out_b = temp.path().join("out-b");
        let shards_b = shards.clone();
        let out_b_clone = out_b.clone();
        let guard = PanicAfter::arm(2);
        let aborted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(&args_for(shards_b, out_b_clone, false))
        }));
        drop(guard);
        assert!(
            aborted.is_err(),
            "expected panic from INVARIANT_ASSEMBLE_PANIC_AFTER_SHARD"
        );
        // Sidecar must survive the panic (was fsynced after shard 0 and 1).
        assert!(sidecar_path(&out_b).exists());
        let saved: AssembleState =
            serde_json::from_slice(&std::fs::read(sidecar_path(&out_b)).unwrap()).unwrap();
        assert_eq!(saved.consumed.len(), 2);

        // 3. Resume against the same output dir; final Merkle root must
        //    equal the one-shot root byte-for-byte.
        assert_eq!(run(&args_for(shards, out_b.clone(), true)), 0);
        let root_resumed =
            std::fs::read_to_string(out_b.join("integrity/merkle_root.txt")).unwrap();
        assert_eq!(root_resumed, root_oneshot);
        assert!(!sidecar_path(&out_b).exists(), "sidecar removed on success");
    }

    #[test]
    fn resume_detects_source_shard_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 3);
        let output = temp.path().join("out");

        // Abort after shard 1 to leave a sidecar with one consumed shard.
        let shards_clone = shards.clone();
        let out_clone = output.clone();
        let guard = PanicAfter::arm(1);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(&args_for(shards_clone, out_clone, false))
        }));
        drop(guard);
        assert!(sidecar_path(&output).exists());

        // Tamper with the already-consumed shard's audit.jsonl.
        let consumed_path = {
            let st: AssembleState =
                serde_json::from_slice(&std::fs::read(sidecar_path(&output)).unwrap()).unwrap();
            PathBuf::from(&st.consumed[0].path)
        };
        let audit_path = consumed_path.join("audit.jsonl");
        let mut content = std::fs::read_to_string(&audit_path).unwrap();
        content.push_str(r#"{"entry_hash":"deadbeef","sequence":999}"#);
        content.push('\n');
        std::fs::write(&audit_path, content).unwrap();

        // Resume must fail (exit 2) with the typed tamper message.
        assert_eq!(run(&args_for(shards, output, true)), 2);
    }

    #[test]
    fn sidecar_with_mismatched_output_dir_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 1);
        let output = temp.path().join("out");
        // Sidecar that thinks it belongs to a different output dir.
        let state = AssembleState {
            version: ASSEMBLE_STATE_VERSION,
            output_dir: temp.path().join("out-elsewhere").to_string_lossy().to_string(),
            consumed: vec![],
        };
        let sc = sidecar_path(&output);
        std::fs::write(&sc, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        assert_eq!(run(&args_for(shards, output, true)), 2);
    }

    #[test]
    fn sidecar_with_unknown_version_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let shards = setup_shards(&temp, 1);
        let output = temp.path().join("out");
        let state = serde_json::json!({
            "version": 9999,
            "output_dir": output.to_string_lossy(),
            "consumed": []
        });
        let sc = sidecar_path(&output);
        std::fs::write(&sc, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        assert_eq!(run(&args_for(shards, output, true)), 2);
    }
}
