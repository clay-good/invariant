//! Append-only signed JSONL audit logger.
//!
//! Enforces the four audit invariants:
//! - L1 Completeness: every input/verdict pair is logged
//! - L2 Ordering: SHA-256 hash chain links each entry to its predecessor
//! - L3 Authenticity: each entry is Ed25519-signed by the Invariant instance
//! - L4 Immutability: append-only writes (O_APPEND when file-backed)
//!
//! Generic over the input type `I` (e.g. robotics `Command` or biosynthesis
//! `SynthesisBundle`) and the verdict type `V` (each domain's
//! `SignedVerdict`). Domain crates re-export with concrete type aliases.

use std::collections::HashMap;
use std::io::Write;
use std::marker::PhantomData;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::merkle::{leaf_hash, Hash, MerkleAccumulator};
use crate::models::audit::{
    schema_version_is_v1, u64_is_zero, AuditEntry, BindingContext, SignedAuditEntry,
    CURRENT_SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur while writing to or operating the audit logger.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuditError {
    /// A JSON serialization step failed while building an audit entry.
    #[error("serialization failed: {reason}")]
    Serialization {
        /// Human-readable description of the serialization failure.
        reason: String,
    },

    /// A write or flush to the underlying `Writer` failed.
    #[error("I/O error: {reason}")]
    Io {
        /// Human-readable description of the I/O failure.
        reason: String,
    },

    /// The audit log has reached its configured maximum size.
    /// The entry was NOT written. External log rotation is required
    /// before new entries can be written.
    #[error("audit log full: writing {entry_bytes} bytes would exceed {max_bytes} byte limit (current size: {current_bytes})")]
    LogFull {
        /// Current file size in bytes.
        current_bytes: u64,
        /// Size of the entry that was rejected.
        entry_bytes: u64,
        /// Configured maximum file size.
        max_bytes: u64,
    },

    /// The monotonic-clock reading (B3) for an executor moved backwards.
    /// Spec.md §3.3 requires per-executor monotonicity; appending a record
    /// with `monotonic_nanos < last_monotonic_nanos[executor_id]` is
    /// refused. The entry was NOT written.
    #[error(
        "executor {executor:?}: monotonic clock regression (last={last}, attempted={attempted})"
    )]
    ClockRegression {
        /// Executor identifier whose clock went backwards.
        executor: String,
        /// Last monotonic-clock reading recorded for this executor.
        last: u64,
        /// Monotonic-clock reading the writer attempted to append.
        attempted: u64,
    },
}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        AuditError::Io {
            reason: e.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Verification error
// ---------------------------------------------------------------------------

/// Errors returned by [`verify_log`] when an audit log fails integrity checks.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum AuditVerifyError {
    /// The `previous_hash` of an entry does not match the `entry_hash` of its predecessor.
    #[error(
        "entry {sequence}: hash chain broken (expected previous_hash {expected:?}, got {got:?})"
    )]
    HashChainBroken {
        /// Sequence number of the entry with the broken chain link.
        sequence: u64,
        /// The `entry_hash` of the previous entry that was expected.
        expected: String,
        /// The `previous_hash` actually present in this entry.
        got: String,
    },

    /// The stored `entry_hash` does not match the hash recomputed from the entry body.
    #[error(
        "entry {sequence}: entry_hash mismatch (expected {expected:?}, computed {computed:?})"
    )]
    EntryHashMismatch {
        /// Sequence number of the entry whose hash could not be verified.
        sequence: u64,
        /// The `entry_hash` stored in the entry.
        expected: String,
        /// The hash freshly computed from the entry contents.
        computed: String,
    },

    /// The Ed25519 signature on the entry could not be verified.
    #[error("entry {sequence}: signature verification failed")]
    SignatureInvalid {
        /// Sequence number of the entry with the invalid signature.
        sequence: u64,
    },

    /// The sequence numbers are not monotonically increasing by one.
    #[error("entry {sequence}: expected sequence {expected}, got {got}")]
    SequenceGap {
        /// The sequence number found in the entry.
        sequence: u64,
        /// The sequence number that was expected at this position.
        expected: u64,
        /// The sequence number actually present in the entry.
        got: u64,
    },

    /// The first entry (genesis) has a non-empty `previous_hash`.
    #[error("entry 0: previous_hash must be empty for the first entry")]
    NonEmptyGenesisPreviousHash,

    /// A JSONL line could not be deserialized as a `SignedAuditEntry`.
    #[error("deserialization failed at line {line}: {reason}")]
    Deserialization {
        /// One-based line number in the JSONL stream where parsing failed.
        line: usize,
        /// Human-readable description of the parse error.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/// Append-only audit logger that maintains hash chain state.
///
/// Generic over `W: Write` so it can target a file (with O_APPEND) or an
/// in-memory buffer for testing, and over the input/verdict types `I`/`V`.
pub struct AuditLogger<W: Write, I, V> {
    writer: W,
    signing_key: SigningKey,
    signer_kid: String,
    sequence: u64,
    previous_hash: String,
    /// Optional maximum file size in bytes. When set, `log()` returns
    /// `AuditError::LogFull` instead of writing if the entry would push
    /// the total bytes written past this limit. This does NOT implement
    /// rotation — external tools (e.g. logrotate) are responsible for that.
    max_file_bytes: Option<u64>,
    /// Tracks total bytes written through this logger instance.
    bytes_written: u64,
    /// RFC 6962 Merkle accumulator over the entry-hash sequence (v11 1.3).
    /// Each successful `log()` call pushes `leaf_hash(entry_hash_bytes)`.
    merkle: MerkleAccumulator,
    /// B1–B4 execution-binding context stamped onto every entry written
    /// through this logger (v11 1.1). Defaults to the empty context, which
    /// suppresses the B1–B4 fields entirely so legacy callers stay
    /// byte-compatible.
    binding: BindingContext,
    /// Per-executor most-recent monotonic-clock reading (B3). Used to
    /// detect clock regression across `log()` calls that share an
    /// `executor_id`. Only populated when the configured binding context
    /// supplies a non-empty `executor_id`.
    last_monotonic_per_executor: HashMap<String, u64>,
    _phantom: PhantomData<fn() -> (I, V)>,
}

impl<W: Write, I, V> AuditLogger<W, I, V>
where
    I: Serialize + Clone,
    V: Serialize + Clone,
{
    /// Create a new audit logger starting at sequence 0 with an empty
    /// previous_hash (genesis).
    pub fn new(writer: W, signing_key: SigningKey, signer_kid: String) -> Self {
        Self {
            writer,
            signing_key,
            signer_kid,
            sequence: 0,
            previous_hash: String::new(),
            max_file_bytes: None,
            bytes_written: 0,
            merkle: MerkleAccumulator::new(),
            binding: BindingContext::default(),
            last_monotonic_per_executor: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    /// Resume an audit logger from a known state.
    ///
    /// Use this when replaying an existing log file to continue appending
    /// from the correct sequence number and hash chain position.
    pub fn resume(
        writer: W,
        signing_key: SigningKey,
        signer_kid: String,
        next_sequence: u64,
        last_entry_hash: String,
    ) -> Self {
        Self {
            writer,
            signing_key,
            signer_kid,
            sequence: next_sequence,
            previous_hash: last_entry_hash,
            max_file_bytes: None,
            bytes_written: 0,
            merkle: MerkleAccumulator::new(),
            binding: BindingContext::default(),
            last_monotonic_per_executor: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    /// Log an input/verdict pair. Produces a `SignedAuditEntry`, writes it
    /// as a single JSONL line, and advances the hash chain.
    pub fn log(
        &mut self,
        input: &I,
        signed_verdict: &V,
    ) -> Result<SignedAuditEntry<I, V>, AuditError> {
        // B3 — per-executor monotonic-clock check. Fires only when the
        // installed binding context names a non-empty executor and supplies
        // a non-zero monotonic reading; legacy callers (empty context) are
        // unaffected.
        if !self.binding.executor_id.is_empty() && self.binding.monotonic_nanos != 0 {
            if let Some(&last) = self
                .last_monotonic_per_executor
                .get(&self.binding.executor_id)
            {
                if self.binding.monotonic_nanos < last {
                    return Err(AuditError::ClockRegression {
                        executor: self.binding.executor_id.clone(),
                        last,
                        attempted: self.binding.monotonic_nanos,
                    });
                }
            }
        }

        let (entry, entry_bytes) = self.build_entry(input, signed_verdict)?;
        let signed = self.sign_entry(&entry, &entry_bytes)?;

        // Write as a single JSONL line.
        let json = serde_json::to_string(&signed).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;

        // Check max file size before writing. The +1 accounts for the newline.
        let write_len = json.len() as u64 + 1;
        if let Some(max) = self.max_file_bytes {
            if self.bytes_written + write_len > max {
                return Err(AuditError::LogFull {
                    current_bytes: self.bytes_written,
                    entry_bytes: write_len,
                    max_bytes: max,
                });
            }
        }

        writeln!(self.writer, "{json}")?;
        // Flush to ensure the write is fully committed through any buffering
        // layer before advancing hash chain state.
        self.writer.flush()?;

        // Only advance hash chain state after confirmed write.
        self.bytes_written += write_len;
        self.merkle
            .push_leaf_hash(leaf_hash(entry.entry_hash.as_bytes()));
        self.previous_hash = entry.entry_hash.clone();
        self.sequence += 1;

        // Record this executor's monotonic reading after a successful
        // append. Pre-write check above already established that the new
        // reading is ≥ the previous one for this executor.
        if !self.binding.executor_id.is_empty() && self.binding.monotonic_nanos != 0 {
            self.last_monotonic_per_executor.insert(
                self.binding.executor_id.clone(),
                self.binding.monotonic_nanos,
            );
        }

        Ok(signed)
    }

    /// Current RFC 6962 Merkle root over the entry-hash sequence (v11 1.3).
    ///
    /// The leaves are `leaf_hash(entry_hash_bytes)` for each entry written
    /// through this logger. Returns `merkle::empty_tree_hash()` when no
    /// entries have been written yet.
    ///
    /// Note: resuming an existing on-disk log (via [`resume`] or
    /// [`open_file`]) starts the accumulator fresh — the persisted
    /// `previous_hash` chains the new entries to the old ones for L2
    /// integrity, but the Merkle root reported by this method covers only
    /// entries written by *this* logger instance. The off-line
    /// [`crate::merkle::tree_root`] function reconstructs the full-log root
    /// from a parsed JSONL file when needed.
    pub fn merkle_root(&self) -> Hash {
        self.merkle.root()
    }

    /// Current sequence number (the next entry will have this sequence).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Install a [`BindingContext`] that will be stamped onto every
    /// subsequent entry written through this logger (v11 1.1). Pass the
    /// default-constructed context to clear binding (legacy mode).
    ///
    /// When the context's `executor_id` is non-empty and `monotonic_nanos`
    /// is non-zero, [`AuditLogger::log`] enforces per-executor monotonicity
    /// (B3) by comparing against the last reading recorded for that
    /// executor.
    pub fn set_binding_context(&mut self, ctx: BindingContext) {
        self.binding = ctx;
    }

    /// Returns the currently installed [`BindingContext`].
    pub fn binding_context(&self) -> &BindingContext {
        &self.binding
    }

    /// Returns the last monotonic-clock reading seen for `executor_id`,
    /// or `None` if this executor has not appeared in a successfully
    /// written entry yet.
    pub fn last_monotonic_for(&self, executor_id: &str) -> Option<u64> {
        self.last_monotonic_per_executor.get(executor_id).copied()
    }

    /// The hash of the last written entry (empty string if no entries yet).
    pub fn previous_hash(&self) -> &str {
        &self.previous_hash
    }

    /// Set the maximum file size in bytes. When set, `log()` returns
    /// `AuditError::LogFull` if writing the entry would exceed this limit.
    /// Pass `None` to disable the limit (default).
    pub fn set_max_file_bytes(&mut self, max: Option<u64>) {
        self.max_file_bytes = max;
    }

    /// Set the initial byte count (e.g., from the current file size when
    /// resuming an existing log). This is used together with `max_file_bytes`
    /// to track total log size.
    pub fn set_initial_bytes(&mut self, bytes: u64) {
        self.bytes_written = bytes;
    }

    fn build_entry(
        &self,
        input: &I,
        signed_verdict: &V,
    ) -> Result<(AuditEntry<I, V>, Vec<u8>), AuditError> {
        let mut entry = AuditEntry {
            sequence: self.sequence,
            previous_hash: self.previous_hash.clone(),
            command: input.clone(),
            verdict: signed_verdict.clone(),
            entry_hash: String::new(),
            schema_version: CURRENT_SCHEMA_VERSION,
            session_id: self.binding.session_id.clone(),
            executor_id: self.binding.executor_id.clone(),
            monotonic_nanos: self.binding.monotonic_nanos,
            wall_clock_rfc3339: self.binding.wall_clock_rfc3339.clone(),
        };

        let pre_hash_bytes = serde_json::to_vec(&entry).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;
        entry.entry_hash = crate::util::sha256_hex(&pre_hash_bytes);

        let entry_bytes = serde_json::to_vec(&entry).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;

        Ok((entry, entry_bytes))
    }

    fn sign_entry(
        &self,
        entry: &AuditEntry<I, V>,
        entry_bytes: &[u8],
    ) -> Result<SignedAuditEntry<I, V>, AuditError> {
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(entry_bytes);

        Ok(SignedAuditEntry {
            entry: entry.clone(),
            entry_signature: STANDARD.encode(signature.to_bytes()),
            signer_kid: self.signer_kid.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// File-backed constructor
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "unknown"))]
impl<I, V> AuditLogger<std::fs::File, I, V>
where
    I: Serialize + Clone + DeserializeOwned,
    V: Serialize + Clone + DeserializeOwned,
{
    /// Open an audit log file and create an audit logger for it.
    ///
    /// The file is opened with `read + append + create` (O_RDWR | O_APPEND |
    /// O_CREAT). If the file already has entries the last line is read from
    /// the same descriptor (avoiding a TOCTOU race) and the logger resumes the
    /// hash chain from that last entry (L2). All subsequent writes are
    /// append-only via O_APPEND (L4).
    ///
    /// # SECURITY: chain state is recovered without re-verifying signatures
    ///
    /// Only the last non-empty line is parsed to determine sequence and hash.
    /// Full integrity verification (`verify_log`) is a separate, operator-
    /// invoked operation. If the file has been tampered with, new entries
    /// will chain onto the tampered state and a subsequent `verify_log` call
    /// will detect the break.
    ///
    /// Concurrent writers are NOT supported.
    pub fn open_file(
        path: &std::path::Path,
        signing_key: SigningKey,
        signer_kid: String,
    ) -> Result<Self, AuditError> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;

        let (next_sequence, last_entry_hash) = read_last_line::<I, V>(&mut file)?;

        let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);

        if next_sequence == 0 {
            let mut logger = Self::new(file, signing_key, signer_kid);
            logger.bytes_written = file_size;
            Ok(logger)
        } else {
            let mut logger = Self::resume(
                file,
                signing_key,
                signer_kid,
                next_sequence,
                last_entry_hash,
            );
            logger.bytes_written = file_size;
            Ok(logger)
        }
    }
}

/// Size of the trailing chunk read from EOF. 128 KiB is large enough to
/// contain even very large audit entries while keeping memory usage bounded.
#[cfg(not(target_os = "unknown"))]
const TAIL_READ_BYTES: u64 = 128 * 1024;

#[cfg(not(target_os = "unknown"))]
fn read_last_line<I, V>(file: &mut std::fs::File) -> Result<(u64, String), AuditError>
where
    I: DeserializeOwned,
    V: DeserializeOwned,
{
    use std::io::{Read, Seek};

    let file_len = file.seek(std::io::SeekFrom::End(0))?;
    if file_len == 0 {
        return Ok((0, String::new()));
    }

    let read_start = file_len.saturating_sub(TAIL_READ_BYTES);
    let read_len = (file_len - read_start) as usize;
    file.seek(std::io::SeekFrom::Start(read_start))?;
    let mut buf = vec![0u8; read_len];
    file.read_exact(&mut buf)?;

    let mut end = buf.len();
    while end > 0 && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
        end -= 1;
    }
    if end == 0 {
        return Ok((0, String::new()));
    }

    let start = match buf[..end].iter().rposition(|&b| b == b'\n') {
        Some(pos) => pos + 1,
        None => 0,
    };

    let line = std::str::from_utf8(&buf[start..end]).map_err(|e| AuditError::Serialization {
        reason: format!("last audit log line is not valid UTF-8: {e}"),
    })?;

    let signed: SignedAuditEntry<I, V> = serde_json::from_str(line.trim()).map_err(|e| {
        AuditError::Serialization {
            reason: format!("failed to parse last audit log entry: {e}"),
        }
    })?;

    Ok((signed.entry.sequence + 1, signed.entry.entry_hash.clone()))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify an audit log's integrity: hash chain continuity (L2), entry hash
/// correctness, signature validity (L3), and sequence monotonicity.
///
/// Returns the number of verified entries on success, or the first error.
///
/// Generic over the input/verdict types — callers in domain crates pass
/// concrete types via type aliases.
pub fn verify_log<I, V>(
    jsonl: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<u64, AuditVerifyError>
where
    I: Serialize + DeserializeOwned,
    V: Serialize + DeserializeOwned,
{
    let mut previous_hash = String::new();
    let mut expected_sequence: u64 = 0;
    let mut first_schema_version: Option<u32> = None;
    let mut mixed_schema_warned = false;

    for (line_idx, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let signed: SignedAuditEntry<I, V> =
            serde_json::from_str(line).map_err(|e| AuditVerifyError::Deserialization {
                line: line_idx + 1,
                reason: e.to_string(),
            })?;

        let entry = &signed.entry;

        match first_schema_version {
            None => first_schema_version = Some(entry.schema_version),
            Some(v) if v != entry.schema_version && !mixed_schema_warned => {
                // v12 N-4: emit a warning when a single audit log contains
                // records of multiple schema versions. Until the v11 1.3
                // Merkle-tree integration lands this is advisory; afterwards
                // the verifier will return a typed `MixedSchemaVersions`
                // error from the same site.
                tracing::warn!(
                    "audit log mixes schema_version {} and {} (line {})",
                    v,
                    entry.schema_version,
                    line_idx + 1
                );
                mixed_schema_warned = true;
            }
            _ => {}
        }

        if entry.sequence != expected_sequence {
            return Err(AuditVerifyError::SequenceGap {
                sequence: entry.sequence,
                expected: expected_sequence,
                got: entry.sequence,
            });
        }

        if entry.sequence == 0 {
            if !entry.previous_hash.is_empty() {
                return Err(AuditVerifyError::NonEmptyGenesisPreviousHash);
            }
        } else if entry.previous_hash != previous_hash {
            return Err(AuditVerifyError::HashChainBroken {
                sequence: entry.sequence,
                expected: previous_hash,
                got: entry.previous_hash.clone(),
            });
        }

        // Recompute entry_hash over a borrowing view (no clone of the entry).
        // The `schema_version` field is serialized only when non-default so
        // pre-v12 records (whose stored hash was computed without the field)
        // continue to verify.
        let entry_json = {
            #[derive(Serialize)]
            struct HashableEntryView<'a, I, V> {
                sequence: u64,
                previous_hash: &'a str,
                #[serde(rename = "command")]
                command: &'a I,
                verdict: &'a V,
                entry_hash: &'static str,
                #[serde(skip_serializing_if = "schema_version_is_v1")]
                schema_version: u32,
                #[serde(skip_serializing_if = "str::is_empty")]
                session_id: &'a str,
                #[serde(skip_serializing_if = "str::is_empty")]
                executor_id: &'a str,
                #[serde(skip_serializing_if = "u64_is_zero")]
                monotonic_nanos: u64,
                #[serde(skip_serializing_if = "str::is_empty")]
                wall_clock_rfc3339: &'a str,
            }
            let view = HashableEntryView::<I, V> {
                sequence: entry.sequence,
                previous_hash: &entry.previous_hash,
                command: &entry.command,
                verdict: &entry.verdict,
                entry_hash: "",
                schema_version: entry.schema_version,
                session_id: &entry.session_id,
                executor_id: &entry.executor_id,
                monotonic_nanos: entry.monotonic_nanos,
                wall_clock_rfc3339: &entry.wall_clock_rfc3339,
            };
            serde_json::to_vec(&view).map_err(|e| AuditVerifyError::Deserialization {
                line: line_idx + 1,
                reason: e.to_string(),
            })?
        };
        let computed_hash = crate::util::sha256_hex(&entry_json);
        if computed_hash != entry.entry_hash {
            return Err(AuditVerifyError::EntryHashMismatch {
                sequence: entry.sequence,
                expected: entry.entry_hash.clone(),
                computed: computed_hash,
            });
        }

        let signed_json =
            serde_json::to_vec(entry).map_err(|e| AuditVerifyError::Deserialization {
                line: line_idx + 1,
                reason: e.to_string(),
            })?;
        let sig_bytes = STANDARD.decode(&signed.entry_signature).map_err(|_| {
            AuditVerifyError::SignatureInvalid {
                sequence: entry.sequence,
            }
        })?;
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|_| {
            AuditVerifyError::SignatureInvalid {
                sequence: entry.sequence,
            }
        })?;
        // Use verify_strict to reject small-order points and non-canonical
        // signatures (cofactor attack mitigation, RFC 8032 §5.1.7).
        verifying_key
            .verify_strict(&signed_json, &signature)
            .map_err(|_| AuditVerifyError::SignatureInvalid {
                sequence: entry.sequence,
            })?;

        previous_hash = entry.entry_hash.clone();
        expected_sequence += 1;
    }

    Ok(expected_sequence)
}

// ---------------------------------------------------------------------------
// canonical_bytes (v11 1.1)
// ---------------------------------------------------------------------------

/// Length-prefixed framing tag for the `canonical_bytes` preimage.
///
/// `Tag::String(name)` emits `0x01 ‖ name_len_u32_be ‖ name_bytes ‖
/// value_len_u64_be ‖ value_bytes`.
/// `Tag::U64(name)` emits `0x02 ‖ name_len_u32_be ‖ name_bytes ‖ value_u64_be`.
/// `Tag::Json(name)` emits `0x03 ‖ name_len_u32_be ‖ name_bytes ‖
/// json_len_u64_be ‖ json_bytes` (used for the input + verdict payloads,
/// whose internal structure is domain-specific).
fn encode_string(out: &mut Vec<u8>, name: &str, value: &str) {
    out.push(0x01);
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn encode_u64(out: &mut Vec<u8>, name: &str, value: u64) {
    out.push(0x02);
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_json(out: &mut Vec<u8>, name: &str, json: &[u8]) {
    out.push(0x03);
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(json.len() as u64).to_be_bytes());
    out.extend_from_slice(json);
}

/// Build the length-prefixed canonical preimage of an audit entry (v11 1.1).
///
/// Field order is fixed and documented here. Reordering, adding, or removing
/// a field is a hash-preimage change and must coincide with a
/// `schema_version` bump. Empty strings and zero u64s are encoded *literally*
/// (length 0 / value 0) rather than skipped — the goal is unambiguous
/// framing, not byte-compactness.
///
/// Field order (top to bottom of the preimage byte stream):
///
/// 1. `schema_version` — u64
/// 2. `sequence` — u64
/// 3. `previous_hash` — string (hex)
/// 4. `session_id` — string (B1)
/// 5. `executor_id` — string (B2)
/// 6. `monotonic_nanos` — u64 (B3)
/// 7. `wall_clock_rfc3339` — string (B4)
/// 8. `command` — JSON (serde_json::to_vec, deterministic given struct layout)
/// 9. `verdict` — JSON (serde_json::to_vec)
///
/// `entry_hash` and `entry_signature` are explicitly excluded.
///
/// **This helper is the v11 1.1 contract for callers that want a
/// hash preimage that does not depend on serde's JSON whitespace or
/// field-ordering rules.** The default in-tree `AuditLogger` still hashes
/// via `serde_json::to_vec` for backward compatibility with pre-v11-1.1
/// on-disk records; `canonical_bytes` is the forward-compatible preimage
/// that downstream attestation tools should adopt.
pub fn canonical_bytes<I, V>(entry: &AuditEntry<I, V>) -> Result<Vec<u8>, AuditError>
where
    I: Serialize,
    V: Serialize,
{
    let command_json = serde_json::to_vec(&entry.command).map_err(|e| AuditError::Serialization {
        reason: format!("command serialization failed: {e}"),
    })?;
    let verdict_json = serde_json::to_vec(&entry.verdict).map_err(|e| AuditError::Serialization {
        reason: format!("verdict serialization failed: {e}"),
    })?;

    let mut out = Vec::with_capacity(
        128 + entry.session_id.len()
            + entry.executor_id.len()
            + entry.wall_clock_rfc3339.len()
            + command_json.len()
            + verdict_json.len(),
    );
    encode_u64(&mut out, "schema_version", entry.schema_version as u64);
    encode_u64(&mut out, "sequence", entry.sequence);
    encode_string(&mut out, "previous_hash", &entry.previous_hash);
    encode_string(&mut out, "session_id", &entry.session_id);
    encode_string(&mut out, "executor_id", &entry.executor_id);
    encode_u64(&mut out, "monotonic_nanos", entry.monotonic_nanos);
    encode_string(&mut out, "wall_clock_rfc3339", &entry.wall_clock_rfc3339);
    encode_json(&mut out, "command", &command_json);
    encode_json(&mut out, "verdict", &verdict_json);
    Ok(out)
}
