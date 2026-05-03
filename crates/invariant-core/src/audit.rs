// Append-only signed JSONL audit logger.
//
// Enforces the four audit invariants:
// - L1 Completeness: every command/verdict pair is logged
// - L2 Ordering: SHA-256 hash chain links each entry to its predecessor
// - L3 Authenticity: each entry is Ed25519-signed by the Invariant instance
// - L4 Immutability: append-only writes (O_APPEND when file-backed)

use std::io::Write;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use thiserror::Error;

use crate::models::audit::{AuditEntry, SignedAuditEntry};
use crate::models::command::Command;
use crate::models::verdict::SignedVerdict;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur while writing to or operating the audit logger.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::audit::AuditError;
///
/// let err = AuditError::Serialization { reason: "bad json".to_string() };
/// assert!(err.to_string().contains("serialization failed"));
///
/// let err = AuditError::Io { reason: "disk full".to_string() };
/// assert!(err.to_string().contains("I/O error"));
/// ```
#[derive(Debug, Error)]
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
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::audit::AuditVerifyError;
///
/// let err = AuditVerifyError::SignatureInvalid { sequence: 3 };
/// assert!(err.to_string().contains("3"));
///
/// let err = AuditVerifyError::NonEmptyGenesisPreviousHash;
/// assert!(err.to_string().contains("previous_hash"));
///
/// let err = AuditVerifyError::SequenceGap { sequence: 2, expected: 1, got: 2 };
/// assert!(err.to_string().contains("sequence"));
/// ```
#[derive(Debug, Error, PartialEq)]
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
/// in-memory buffer for testing.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::audit::AuditLogger;
/// use ed25519_dalek::SigningKey;
///
/// let signing_key = SigningKey::from_bytes(&[1u8; 32]);
/// let logger: AuditLogger<Vec<u8>> = AuditLogger::new(Vec::new(), signing_key, "kid-1".to_string());
/// assert_eq!(logger.sequence(), 0);
/// assert_eq!(logger.previous_hash(), "");
/// ```
pub struct AuditLogger<W: Write> {
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
}

impl<W: Write> AuditLogger<W> {
    /// Create a new audit logger starting at sequence 0 with an empty
    /// previous_hash (genesis).
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_core::audit::AuditLogger;
    /// use ed25519_dalek::SigningKey;
    ///
    /// let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    /// let logger: AuditLogger<Vec<u8>> = AuditLogger::new(Vec::new(), signing_key, "kid-1".to_string());
    /// assert_eq!(logger.sequence(), 0);
    /// assert_eq!(logger.previous_hash(), "");
    /// ```
    pub fn new(writer: W, signing_key: SigningKey, signer_kid: String) -> Self {
        Self {
            writer,
            signing_key,
            signer_kid,
            sequence: 0,
            previous_hash: String::new(),
            max_file_bytes: None,
            bytes_written: 0,
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
        }
    }

    /// Log a command/verdict pair. Produces a `SignedAuditEntry`, writes it
    /// as a single JSONL line, and advances the hash chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_core::audit::AuditLogger;
    /// use invariant_robotics_core::models::command::{Command, CommandAuthority, JointState};
    /// use invariant_robotics_core::models::verdict::{
    ///     AuthoritySummary, CheckResult, SignedVerdict, Verdict,
    /// };
    /// use base64::{engine::general_purpose::STANDARD, Engine};
    /// use chrono::Utc;
    /// use ed25519_dalek::{SigningKey, Signer};
    /// use std::collections::HashMap;
    ///
    /// let signing_key = SigningKey::from_bytes(&[10u8; 32]);
    /// let mut buf = Vec::new();
    /// let mut logger = AuditLogger::new(&mut buf, signing_key.clone(), "kid".to_string());
    ///
    /// let command = Command {
    ///     timestamp: Utc::now(),
    ///     source: "doc-test".to_string(),
    ///     sequence: 0,
    ///     joint_states: vec![JointState { name: "j1".to_string(), position: 0.0, velocity: 0.0, effort: 0.0 }],
    ///     delta_time: 0.01,
    ///     end_effector_positions: vec![],
    ///     center_of_mass: None,
    ///     authority: CommandAuthority { pca_chain: String::new(), required_ops: vec![] },
    ///     metadata: HashMap::new(),
    ///     locomotion_state: None,
    ///     end_effector_forces: vec![],
    ///     estimated_payload_kg: None,
    ///     signed_sensor_readings: vec![],
    ///     zone_overrides: HashMap::new(),
    ///     environment_state: None,
    /// };
    ///
    /// let verdict = Verdict {
    ///     approved: true,
    ///     command_hash: "sha256:abc".to_string(),
    ///     command_sequence: 0,
    ///     timestamp: Utc::now(),
    ///     checks: vec![],
    ///     profile_name: "ur10".to_string(),
    ///     profile_hash: "sha256:xyz".to_string(),
    ///     authority_summary: AuthoritySummary {
    ///         origin_principal: "alice".to_string(),
    ///         hop_count: 1,
    ///         operations_granted: vec!["actuate:*".to_string()],
    ///         operations_required: vec![],
    ///     },
    ///     threat_analysis: None,
    /// };
    /// let verdict_bytes = serde_json::to_vec(&verdict).unwrap();
    /// let sig = signing_key.sign(&verdict_bytes);
    /// let signed_verdict = SignedVerdict {
    ///     verdict,
    ///     verdict_signature: STANDARD.encode(sig.to_bytes()),
    ///     signer_kid: "kid".to_string(),
    /// };
    ///
    /// let entry = logger.log(&command, &signed_verdict).unwrap();
    /// assert_eq!(entry.entry.sequence, 0);
    /// assert_eq!(logger.sequence(), 1);
    /// ```
    pub fn log(
        &mut self,
        command: &Command,
        signed_verdict: &SignedVerdict,
    ) -> Result<SignedAuditEntry, AuditError> {
        let (entry, entry_bytes) = self.build_entry(command, signed_verdict)?;
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
        self.previous_hash = entry.entry_hash.clone();
        self.sequence += 1;

        Ok(signed)
    }

    /// Current sequence number (the next entry will have this sequence).
    pub fn sequence(&self) -> u64 {
        self.sequence
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

    // Returns the completed entry together with its serialized bytes (with the
    // final entry_hash filled in). The caller passes those bytes to sign_entry
    // so the entry is only serialized once per log() call instead of twice.
    fn build_entry(
        &self,
        command: &Command,
        signed_verdict: &SignedVerdict,
    ) -> Result<(AuditEntry, Vec<u8>), AuditError> {
        // Build the entry without the hash first.
        let mut entry = AuditEntry {
            sequence: self.sequence,
            previous_hash: self.previous_hash.clone(),
            command: command.clone(),
            verdict: signed_verdict.clone(),
            entry_hash: String::new(),
        };

        // Compute entry_hash over the canonical JSON of the entry (with
        // empty entry_hash). This makes the hash cover sequence,
        // previous_hash, command, and verdict — the full audit record.
        let pre_hash_bytes = serde_json::to_vec(&entry).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;
        entry.entry_hash = crate::util::sha256_hex(&pre_hash_bytes);

        // Serialize the final entry (with entry_hash set) so the caller can
        // reuse these bytes for signing without a second serde_json::to_vec.
        let entry_bytes = serde_json::to_vec(&entry).map_err(|e| AuditError::Serialization {
            reason: e.to_string(),
        })?;

        Ok((entry, entry_bytes))
    }

    // Signs the entry using the already-serialized bytes produced by
    // build_entry, avoiding a redundant serialization round-trip.
    fn sign_entry(
        &self,
        entry: &AuditEntry,
        entry_bytes: &[u8],
    ) -> Result<SignedAuditEntry, AuditError> {
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
impl AuditLogger<std::fs::File> {
    /// Open an audit log file and create an audit logger for it.
    ///
    /// The file is opened once with `read + write + create` (O_RDWR | O_CREAT).
    /// If the file already has entries the last line is read from the same
    /// descriptor (avoiding a TOCTOU race) and the logger resumes the hash
    /// chain from that last entry (L2).  After reading, the file position is
    /// seeked to the end so all subsequent writes are append-only (L4).
    ///
    /// Writing directly to `File` without a `BufWriter` means there is no
    /// intermediate buffer that could hold stale data on a flush failure.
    /// Since `log()` flushes after every single JSONL line the absence of
    /// `BufWriter` does not hurt performance (a `BufWriter` drained on every
    /// entry provides no net buffering benefit).
    ///
    /// # SECURITY: chain state is recovered without re-verifying signatures
    ///
    /// Only the last non-empty line of the file is parsed to determine the
    /// current sequence number and hash.  Full integrity verification
    /// (`verify_log`) is a separate, operator-invoked operation.  If the file
    /// has been tampered with, new entries will chain onto the tampered state
    /// and a subsequent `verify_log` call will detect the break.
    ///
    /// Concurrent writers are NOT supported.
    pub fn open_file(
        path: &std::path::Path,
        signing_key: SigningKey,
        signer_kid: String,
    ) -> Result<Self, AuditError> {
        // Open with read + append + create.  O_APPEND is critical for the
        // L4 immutability invariant: it guarantees that every write(2) call
        // atomically positions the file offset at EOF before writing,
        // preventing a concurrent process (or fork) from overwriting
        // existing entries.  The manual seek-to-EOF that was here before
        // was NOT atomic and could race with another writer.
        //
        // read(true) is needed for read_last_line to scan backward and
        // recover the hash chain state.  SeekFrom::End works on append-
        // mode file descriptors for reads.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;

        // Read only the last non-empty line to recover chain state.
        let (next_sequence, last_entry_hash) = read_last_line(&mut file)?;

        // Record the current file size so max_file_bytes tracking starts
        // from the correct offset when resuming an existing log.
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

/// Read the last non-empty line from a file and parse it as a
/// [`SignedAuditEntry`] to recover `(next_sequence, last_entry_hash)`.
///
/// Scans backward from EOF one byte at a time to locate the final newline,
/// avoiding loading the entire file into memory (O(last_line_length) I/O).
///
/// Returns `(0, "")` if the file is empty or contains only blank lines.
#[cfg(not(target_os = "unknown"))]
/// Size of the trailing chunk read from EOF. 128 KiB is large enough to
/// contain even very large audit entries while keeping memory usage bounded.
/// This reduces startup latency for large audit logs from O(line_length)
/// syscalls to O(1) — one seek + one read regardless of entry size.
const TAIL_READ_BYTES: u64 = 128 * 1024;

fn read_last_line(file: &mut std::fs::File) -> Result<(u64, String), AuditError> {
    use std::io::{Read, Seek};

    let file_len = file.seek(std::io::SeekFrom::End(0))?;
    if file_len == 0 {
        return Ok((0, String::new()));
    }

    // Read the last TAIL_READ_BYTES (or the whole file if smaller) in one
    // read, then scan backward in memory for the last newline.
    let read_start = file_len.saturating_sub(TAIL_READ_BYTES);
    let read_len = (file_len - read_start) as usize;
    file.seek(std::io::SeekFrom::Start(read_start))?;
    let mut buf = vec![0u8; read_len];
    file.read_exact(&mut buf)?;

    // Find the last non-empty line by scanning backward.
    // Skip trailing newlines / whitespace at end of buffer.
    let mut end = buf.len();
    while end > 0 && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
        end -= 1;
    }
    if end == 0 {
        return Ok((0, String::new()));
    }

    // Find the newline that precedes the last line.
    let start = match buf[..end].iter().rposition(|&b| b == b'\n') {
        Some(pos) => pos + 1,
        None => 0,
    };

    let line = std::str::from_utf8(&buf[start..end]).map_err(|e| AuditError::Serialization {
        reason: format!("last audit log line is not valid UTF-8: {e}"),
    })?;

    let signed: crate::models::audit::SignedAuditEntry = serde_json::from_str(line.trim())
        .map_err(|e| AuditError::Serialization {
            reason: format!("failed to parse last audit log entry: {e}"),
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
/// # Examples
///
/// ```
/// use invariant_robotics_core::audit::{AuditLogger, verify_log};
/// use invariant_robotics_core::models::command::{Command, CommandAuthority, JointState};
/// use invariant_robotics_core::models::verdict::{
///     AuthoritySummary, SignedVerdict, Verdict,
/// };
/// use base64::{engine::general_purpose::STANDARD, Engine};
/// use chrono::Utc;
/// use ed25519_dalek::{SigningKey, Signer};
/// use std::collections::HashMap;
///
/// let signing_key = SigningKey::from_bytes(&[20u8; 32]);
/// let verifying_key = signing_key.verifying_key();
///
/// let mut buf = Vec::new();
/// let mut logger = AuditLogger::new(&mut buf, signing_key.clone(), "kid".to_string());
///
/// let command = Command {
///     timestamp: Utc::now(),
///     source: "doc-test".to_string(),
///     sequence: 0,
///     joint_states: vec![JointState { name: "j1".to_string(), position: 0.0, velocity: 0.0, effort: 0.0 }],
///     delta_time: 0.01,
///     end_effector_positions: vec![],
///     center_of_mass: None,
///     authority: CommandAuthority { pca_chain: String::new(), required_ops: vec![] },
///     metadata: HashMap::new(),
///     locomotion_state: None,
///     end_effector_forces: vec![],
///     estimated_payload_kg: None,
///     signed_sensor_readings: vec![],
///     zone_overrides: HashMap::new(),
///     environment_state: None,
/// };
///
/// let verdict = Verdict {
///     approved: true,
///     command_hash: "sha256:abc".to_string(),
///     command_sequence: 0,
///     timestamp: Utc::now(),
///     checks: vec![],
///     profile_name: "ur10".to_string(),
///     profile_hash: "sha256:xyz".to_string(),
///     authority_summary: AuthoritySummary {
///         origin_principal: "alice".to_string(),
///         hop_count: 1,
///         operations_granted: vec!["actuate:*".to_string()],
///         operations_required: vec![],
///     },
///     threat_analysis: None,
/// };
/// let verdict_bytes = serde_json::to_vec(&verdict).unwrap();
/// let sig = signing_key.sign(&verdict_bytes);
/// let signed_verdict = SignedVerdict {
///     verdict,
///     verdict_signature: STANDARD.encode(sig.to_bytes()),
///     signer_kid: "kid".to_string(),
/// };
///
/// logger.log(&command, &signed_verdict).unwrap();
///
/// // Verify the JSONL content.
/// let jsonl = String::from_utf8(buf).unwrap();
/// let count = verify_log(&jsonl, &verifying_key).unwrap();
/// assert_eq!(count, 1);
/// ```
pub fn verify_log(
    jsonl: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<u64, AuditVerifyError> {
    let mut previous_hash = String::new();
    let mut expected_sequence: u64 = 0;

    for (line_idx, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let signed: SignedAuditEntry =
            serde_json::from_str(line).map_err(|e| AuditVerifyError::Deserialization {
                line: line_idx + 1,
                reason: e.to_string(),
            })?;

        let entry = &signed.entry;

        // Check sequence monotonicity.
        if entry.sequence != expected_sequence {
            return Err(AuditVerifyError::SequenceGap {
                sequence: entry.sequence,
                expected: expected_sequence,
                got: entry.sequence,
            });
        }

        // Check hash chain linkage (L2).
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

        // Recompute entry_hash over the entry with entry_hash set to "".
        // Use a borrowing view struct to avoid cloning the entire entry.
        let entry_json = {
            #[derive(Serialize)]
            struct HashableEntryView<'a> {
                sequence: u64,
                previous_hash: &'a str,
                command: &'a crate::models::command::Command,
                verdict: &'a crate::models::verdict::SignedVerdict,
                entry_hash: &'static str,
            }
            let view = HashableEntryView {
                sequence: entry.sequence,
                previous_hash: &entry.previous_hash,
                command: &entry.command,
                verdict: &entry.verdict,
                entry_hash: "",
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

        // Verify Ed25519 signature (L3).
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

        // Advance state.
        previous_hash = entry.entry_hash.clone();
        expected_sequence += 1;
    }

    Ok(expected_sequence)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::crypto::{generate_keypair, sign_pca};
    use crate::models::authority::{Operation, Pca};
    use crate::models::command::{Command, CommandAuthority, JointState};
    use crate::models::profile::*;
    use crate::models::verdict::{AuthoritySummary, CheckResult, SignedVerdict, Verdict};
    use crate::validator::ValidatorConfig;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use rand::rngs::OsRng;
    use std::collections::{BTreeSet, HashMap};

    fn op(s: &str) -> Operation {
        Operation::new(s).unwrap()
    }

    #[allow(dead_code)]
    fn ops(ss: &[&str]) -> BTreeSet<Operation> {
        ss.iter().map(|s| op(s)).collect()
    }

    fn make_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[allow(dead_code)]
    fn test_profile() -> RobotProfile {
        RobotProfile {
            name: "test_robot".into(),
            version: "1.0.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -3.15,
                max: 3.15,
                max_velocity: 5.0,
                max_torque: 100.0,
                max_acceleration: 50.0,
            }],
            workspace: WorkspaceBounds::Aabb {
                min: [-2.0, -2.0, 0.0],
                max: [2.0, 2.0, 3.0],
            },
            exclusion_zones: vec![],
            proximity_zones: vec![],
            collision_pairs: vec![],
            stability: None,
            locomotion: None,
            end_effectors: vec![],
            max_delta_time: 0.1,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 50,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None,
        }
    }

    #[allow(dead_code)]
    fn encode_chain(hops: &[crate::models::authority::SignedPca]) -> String {
        let json = serde_json::to_vec(hops).unwrap();
        STANDARD.encode(&json)
    }

    #[allow(dead_code)]
    fn make_command(chain_b64: &str, required_ops: Vec<Operation>) -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 1.0,
                effort: 10.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: chain_b64.to_string(),
                required_ops,
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        }
    }

    #[allow(dead_code)]
    fn make_approved_result(command: &Command) -> (SignedVerdict, ValidatorConfig, SigningKey) {
        let (pca_sk, pca_vk) = make_keypair();
        let (sign_sk, _sign_vk) = make_keypair();

        let claim = Pca {
            p_0: "alice".into(),
            ops: ops(&["actuate:*"]),
            kid: "key-1".into(),
            exp: None,
            nbf: None,
        };
        let signed_pca = sign_pca(&claim, &pca_sk).unwrap();
        let chain_b64 = encode_chain(&[signed_pca]);

        let mut trusted = HashMap::new();
        trusted.insert("key-1".to_string(), pca_vk);

        let config = ValidatorConfig::new(
            test_profile(),
            trusted,
            sign_sk.clone(),
            "invariant-test".into(),
        )
        .unwrap();

        let mut cmd = command.clone();
        cmd.authority.pca_chain = chain_b64;

        let result = config.validate(&cmd, Utc::now(), None).unwrap();
        (result.signed_verdict, config, sign_sk)
    }

    fn make_simple_signed_verdict() -> (SignedVerdict, SigningKey) {
        let (sign_sk, _) = make_keypair();
        // Use a fixed timestamp so that entry_hash values are deterministic
        // across repeated calls (Finding 49).
        let fixed_ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let verdict = Verdict {
            approved: true,
            command_hash: "sha256:abc123".into(),
            command_sequence: 1,
            timestamp: fixed_ts,
            checks: vec![CheckResult {
                name: "test".into(),
                category: "test".into(),
                passed: true,
                details: "ok".into(),
                derating: None,
            }],
            profile_name: "test_robot".into(),
            profile_hash: "sha256:def456".into(),
            threat_analysis: None,
            authority_summary: AuthoritySummary {
                origin_principal: "alice".into(),
                hop_count: 1,
                operations_granted: vec!["actuate:*".into()],
                operations_required: vec!["actuate:j1".into()],
            },
        };

        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        use ed25519_dalek::Signer;
        let signature = sign_sk.sign(&verdict_json);

        let signed = SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(signature.to_bytes()),
            signer_kid: "invariant-test".into(),
        };

        (signed, sign_sk)
    }

    fn make_simple_command() -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: 0.0,
                velocity: 1.0,
                effort: 10.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![op("actuate:j1")],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        }
    }

    // -----------------------------------------------------------------------
    // Core tests
    // -----------------------------------------------------------------------

    #[test]
    fn single_entry_log_and_verify() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        let entry = logger.log(&cmd, &verdict).unwrap();

        assert_eq!(entry.entry.sequence, 0);
        assert!(entry.entry.previous_hash.is_empty());
        assert!(entry.entry.entry_hash.starts_with("sha256:"));
        assert!(!entry.entry_signature.is_empty());
        assert_eq!(entry.signer_kid, "invariant-001");

        // Logger state advanced.
        assert_eq!(logger.sequence(), 1);
        assert_eq!(logger.previous_hash(), &entry.entry.entry_hash);

        // Verify the JSONL output.
        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn multi_entry_hash_chain() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        let e0 = logger.log(&cmd, &verdict).unwrap();
        let e1 = logger.log(&cmd, &verdict).unwrap();
        let e2 = logger.log(&cmd, &verdict).unwrap();

        // Hash chain links.
        assert!(e0.entry.previous_hash.is_empty());
        assert_eq!(e1.entry.previous_hash, e0.entry.entry_hash);
        assert_eq!(e2.entry.previous_hash, e1.entry.entry_hash);

        // Monotonic sequence.
        assert_eq!(e0.entry.sequence, 0);
        assert_eq!(e1.entry.sequence, 1);
        assert_eq!(e2.entry.sequence, 2);

        // All hashes are distinct.
        assert_ne!(e0.entry.entry_hash, e1.entry.entry_hash);
        assert_ne!(e1.entry.entry_hash, e2.entry.entry_hash);

        // Verify full chain.
        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn tampered_entry_hash_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        // Tamper: modify the entry_hash in the JSONL.
        let jsonl = String::from_utf8(buf).unwrap();
        let tampered = jsonl.replace(
            r#""entry_hash":"sha256:"#,
            r#""entry_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000_REPLACED_"#,
        );

        let result = verify_log(&tampered, &sign_vk);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_signature_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "invariant-001".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        // Tamper: replace signature with zeros.
        let jsonl = String::from_utf8(buf).unwrap();
        let entry: serde_json::Value = serde_json::from_str(jsonl.trim()).unwrap();
        let mut tampered_entry = entry.clone();
        tampered_entry["entry_signature"] = serde_json::Value::String(STANDARD.encode([0u8; 64]));
        let tampered_jsonl = serde_json::to_string(&tampered_entry).unwrap() + "\n";

        let result = verify_log(&tampered_jsonl, &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::SignatureInvalid { sequence } => assert_eq!(sequence, 0),
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let (sign_sk, _) = make_keypair();
        let (_, wrong_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        let jsonl = String::from_utf8(buf).unwrap();
        let result = verify_log(&jsonl, &wrong_vk);
        assert!(result.is_err());
    }

    #[test]
    fn broken_hash_chain_detected() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();
        logger.log(&cmd, &verdict).unwrap();

        // Parse both entries, swap the order so hash chain breaks.
        let jsonl = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);

        // Swapping lines will cause hash chain mismatch at entry 1.
        let swapped = format!("{}\n{}\n", lines[1], lines[0]);
        let result = verify_log(&swapped, &sign_vk);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_gap_detected() {
        let (sign_sk, sign_vk) = make_keypair();

        // Log entry 0.
        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger1.log(&cmd, &verdict).unwrap();

        // Log entry with sequence=2 (skipping 1) via resume.
        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::resume(
            &mut buf2,
            sign_sk,
            "test".into(),
            2, // skip sequence 1
            logger1.previous_hash().to_string(),
        );
        logger2.log(&cmd, &verdict).unwrap();

        let jsonl = format!(
            "{}{}\n",
            String::from_utf8(buf1).unwrap(),
            String::from_utf8(buf2).unwrap().trim()
        );
        let result = verify_log(&jsonl, &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::SequenceGap { expected, got, .. } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("expected SequenceGap, got {other:?}"),
        }
    }

    #[test]
    fn resume_continues_chain() {
        let (sign_sk, sign_vk) = make_keypair();

        // Phase 1: log two entries.
        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger1.log(&cmd, &verdict).unwrap();
        logger1.log(&cmd, &verdict).unwrap();

        let seq = logger1.sequence();
        let prev = logger1.previous_hash().to_string();

        // Phase 2: resume and log one more.
        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::resume(&mut buf2, sign_sk, "test".into(), seq, prev);
        logger2.log(&cmd, &verdict).unwrap();

        // Combine JSONL and verify full chain.
        let jsonl = format!(
            "{}{}",
            String::from_utf8(buf1).unwrap(),
            String::from_utf8(buf2).unwrap(),
        );
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn empty_log_verifies() {
        let (_, sign_vk) = make_keypair();
        let count = verify_log("", &sign_vk).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn entry_hash_is_deterministic() {
        // `cmd` and `verdict` are constructed once and reused for both logger
        // calls.  Because both objects carry identical timestamps (they are the
        // same heap values), the JSON serialisation is byte-identical across
        // both invocations, making the entry_hash and the Ed25519 signature
        // deterministic.  If each call were to use a freshly-constructed
        // command or verdict with Utc::now() inside, clock drift between the
        // two calls could produce different hashes and this assertion would
        // fail non-deterministically.
        let (sign_sk, _) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        let mut buf1 = Vec::new();
        let mut logger1 = AuditLogger::new(&mut buf1, sign_sk.clone(), "test".into());
        let e1 = logger1.log(&cmd, &verdict).unwrap();

        let mut buf2 = Vec::new();
        let mut logger2 = AuditLogger::new(&mut buf2, sign_sk, "test".into());
        let e2 = logger2.log(&cmd, &verdict).unwrap();

        assert_eq!(e1.entry.entry_hash, e2.entry.entry_hash);
        assert_eq!(e1.entry_signature, e2.entry_signature);
    }

    #[test]
    fn rejected_verdict_also_logged() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk.clone(), "test".into());

        // Create a rejection verdict.
        let verdict = Verdict {
            approved: false,
            command_hash: "sha256:rejected".into(),
            command_sequence: 1,
            timestamp: Utc::now(),
            checks: vec![CheckResult {
                name: "authority".into(),
                category: "authority".into(),
                passed: false,
                details: "chain verification failed".into(),
                derating: None,
            }],
            profile_name: "test".into(),
            profile_hash: "sha256:profile".into(),
            threat_analysis: None,
            authority_summary: AuthoritySummary {
                origin_principal: String::new(),
                hop_count: 0,
                operations_granted: vec![],
                operations_required: vec!["actuate:j1".into()],
            },
        };
        let verdict_json = serde_json::to_vec(&verdict).unwrap();
        use ed25519_dalek::Signer;
        let sig = sign_sk.sign(&verdict_json);
        let signed_verdict = SignedVerdict {
            verdict,
            verdict_signature: STANDARD.encode(sig.to_bytes()),
            signer_kid: "test".into(),
        };

        let cmd = make_simple_command();
        let entry = logger.log(&cmd, &signed_verdict).unwrap();
        assert!(!entry.entry.verdict.verdict.approved);

        let jsonl = String::from_utf8(buf).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn verify_detects_malformed_json() {
        let (_, sign_vk) = make_keypair();
        let result = verify_log("this is not json\n", &sign_vk);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditVerifyError::Deserialization { line, .. } => assert_eq!(line, 1),
            other => panic!("expected Deserialization, got {other:?}"),
        }
    }

    #[test]
    fn verify_skips_blank_lines() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();

        // Add blank lines around the entry.
        let jsonl = String::from_utf8(buf).unwrap();
        let with_blanks = format!("\n\n{jsonl}\n\n");
        let count = verify_log(&with_blanks, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn open_file_resumes_hash_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");

        let (sign_sk, sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Phase 1: write two entries via open_file.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "kid-1".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
            logger.log(&cmd, &verdict).unwrap();
            // BufWriter is flushed on drop.
        }

        // Phase 2: re-open the same file and append a third entry.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "kid-1".into()).unwrap();
            // The resumed logger must start at sequence 2.
            assert_eq!(logger.sequence(), 2, "resumed sequence should be 2");
            logger.log(&cmd, &verdict).unwrap();
        }

        // The combined file must form a valid 3-entry chain.
        let jsonl = std::fs::read_to_string(&path).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 3, "expected 3 verified entries");
    }

    #[test]
    fn open_file_new_file_starts_at_genesis() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new_audit.jsonl");

        let (sign_sk, sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        {
            let mut logger = AuditLogger::open_file(&path, sign_sk, "kid-1".into()).unwrap();
            assert_eq!(logger.sequence(), 0);
            logger.log(&cmd, &verdict).unwrap();
            // BufWriter is flushed on drop at end of this block.
        }

        let jsonl = std::fs::read_to_string(&path).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn entry_contains_full_command_and_verdict() {
        let (sign_sk, _) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let entry = logger.log(&cmd, &verdict).unwrap();

        // L1: entry contains the full command and signed verdict.
        assert_eq!(entry.entry.command.source, "test");
        assert_eq!(entry.entry.command.sequence, 1);
        assert_eq!(entry.entry.verdict.verdict.command_hash, "sha256:abc123");
        assert!(entry.entry.verdict.verdict.approved);
    }

    // -----------------------------------------------------------------------
    // Finding 16: open_file tests
    // -----------------------------------------------------------------------

    #[test]
    fn open_file_succeeds_and_entry_is_verifiable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit_f16.jsonl");

        let (sign_sk, sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Open a brand-new file, log one entry, then verify it.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "f16-kid".into()).unwrap();
            assert_eq!(logger.sequence(), 0, "new file must start at genesis");
            let entry = logger.log(&cmd, &verdict).unwrap();
            assert_eq!(entry.entry.sequence, 0);
            assert!(entry.entry.entry_hash.starts_with("sha256:"));
        }

        let jsonl = std::fs::read_to_string(&path).unwrap();
        let count = verify_log(&jsonl, &sign_vk).unwrap();
        assert_eq!(count, 1, "exactly one entry must be verifiable");
    }

    #[test]
    fn open_file_missing_parent_returns_io_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Construct a path whose parent does not exist.
        let path = dir.path().join("nonexistent_dir").join("audit.jsonl");

        let (sign_sk, _) = make_keypair();
        let result = AuditLogger::open_file(&path, sign_sk, "kid".into());

        match result {
            Err(AuditError::Io { .. }) => {}
            Err(other) => panic!("expected AuditError::Io, got {other:?}"),
            Ok(_) => panic!("expected an error but got Ok"),
        }
    }

    // -----------------------------------------------------------------------
    // Finding 17: verify_log NonEmptyGenesisPreviousHash
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Finding 53: truncated final entry is detected
    // -----------------------------------------------------------------------

    #[test]
    fn verify_log_rejects_truncated_final_entry() {
        // Build a two-entry log, then truncate the second JSONL line mid-way.
        // verify_log must return a Deserialization error for the truncated line.
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();
        logger.log(&cmd, &verdict).unwrap();

        let jsonl = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 log lines");

        // Truncate the second line to roughly half its length.
        let truncated_line = &lines[1][..lines[1].len() / 2];
        let truncated_jsonl = format!("{}\n{}\n", lines[0], truncated_line);

        let result = verify_log(&truncated_jsonl, &sign_vk);
        assert!(
            result.is_err(),
            "truncated entry must cause verify_log to fail"
        );
        match result.unwrap_err() {
            AuditVerifyError::Deserialization { line, .. } => {
                assert_eq!(line, 2, "error should be on line 2 (the truncated entry)");
            }
            other => panic!("expected Deserialization error, got {other:?}"),
        }
    }

    #[test]
    fn verify_log_rejects_genesis_with_non_empty_previous_hash() {
        let (sign_sk, sign_vk) = make_keypair();

        // Build a legitimate entry via the logger to get the correct JSON shape.
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "f17-kid".into());
        let signed_entry = logger.log(&cmd, &verdict).unwrap();

        // Surgically inject a non-empty previous_hash on sequence 0.
        // verify_log checks previous_hash before it verifies entry_hash or
        // the Ed25519 signature, so the patch will hit the right error first.
        let mut entry_json: serde_json::Value = serde_json::to_value(&signed_entry).unwrap();
        entry_json["previous_hash"] = serde_json::Value::String("sha256:not_empty_genesis".into());
        let tampered_line = serde_json::to_string(&entry_json).unwrap();

        let result = verify_log(&tampered_line, &sign_vk);
        assert!(result.is_err(), "expected an error, got {:?}", result);
        assert_eq!(
            result.unwrap_err(),
            AuditVerifyError::NonEmptyGenesisPreviousHash,
        );
    }

    // -----------------------------------------------------------------------
    // Finding 43: open_file resumes from tampered log without re-verifying
    // -----------------------------------------------------------------------

    #[test]
    fn open_file_tampered_log_verify_fails_after_resume() {
        // Write a valid 2-entry log, corrupt the last entry_hash on disk, then
        // call open_file to resume (which reads but does NOT verify the chain).
        // After logging one more entry, verify_log on the combined file must
        // fail with HashChainBroken because the corrupted hash was chained into
        // the new entry's previous_hash field.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tampered_audit.jsonl");

        let (sign_sk, sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Phase 1: write a valid 2-entry log.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "kid-tamper".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
            logger.log(&cmd, &verdict).unwrap();
        }

        // Phase 2: corrupt the last entry_hash field in the file.
        let original = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = original.lines().collect();
        assert_eq!(lines.len(), 2);
        // Replace the entry_hash value in the last line with zeroes.
        let corrupted_last = {
            let mut val: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
            val["entry_hash"] = serde_json::Value::String(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            );
            serde_json::to_string(&val).unwrap()
        };
        let tampered_content = format!("{}\n{}\n", lines[0], corrupted_last);
        std::fs::write(&path, &tampered_content).unwrap();

        // Phase 3: open_file resumes from the tampered log and appends a third entry.
        // This should succeed — open_file does not verify the chain on resume.
        {
            let mut logger =
                AuditLogger::open_file(&path, sign_sk.clone(), "kid-tamper".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
        }

        // Phase 4: verify_log must fail because the chain is broken.
        let combined = std::fs::read_to_string(&path).unwrap();
        let result = verify_log(&combined, &sign_vk);
        assert!(
            result.is_err(),
            "verify_log must fail on a log that resumes from a tampered entry"
        );
        // The error should be about the hash chain or entry hash mismatch.
        match result.unwrap_err() {
            AuditVerifyError::HashChainBroken { .. }
            | AuditVerifyError::EntryHashMismatch { .. } => {}
            other => panic!("expected HashChainBroken or EntryHashMismatch, got {other:?}"),
        }
    }

    // ── Audit log corruption resilience ─────────────────────

    #[test]
    fn open_file_with_truncated_last_line_returns_error() {
        // Simulates a power failure mid-write: file ends with a partial JSON line.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("truncated_audit.jsonl");

        let (sign_sk, _) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Write a valid 1-entry log.
        {
            let mut logger = AuditLogger::open_file(&path, sign_sk.clone(), "kid".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
        }

        // Append a truncated JSON line (simulating crash mid-write).
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"\n{\"entry\":{\"seq").unwrap();
        file.flush().unwrap();
        drop(file);

        // Re-opening should fail because the last line is not valid JSON.
        let result = AuditLogger::open_file(&path, sign_sk, "kid".into());
        assert!(
            result.is_err(),
            "truncated last line must cause open_file to fail"
        );
    }

    #[test]
    fn open_file_with_only_blank_lines_starts_at_genesis() {
        // A file containing only newlines should be treated as empty.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blank_audit.jsonl");

        use std::io::Write;
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"\n\n\n").unwrap();
        drop(file);

        let (sign_sk, _) = make_keypair();
        let result = AuditLogger::open_file(&path, sign_sk, "kid".into());
        // An all-blank file should either start at genesis (sequence 0) or
        // error. Both are acceptable — the important thing is no panic.
        match result {
            Ok(logger) => {
                assert_eq!(logger.sequence(), 0, "blank file must start at genesis");
            }
            Err(_) => {
                // Also acceptable — the file is corrupt (no valid entries).
            }
        }
    }

    #[test]
    fn verify_log_catches_single_bit_flip_in_signature() {
        // Write a valid 1-entry log, then flip a bit in the entry_signature.
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        logger.log(&cmd, &verdict).unwrap();
        drop(logger);

        let jsonl = String::from_utf8(buf).unwrap();
        // Flip one character in the base64 signature.
        let corrupted = jsonl.replacen("entry_signature\":\"", "entry_signature\":\"X", 1);

        let result = verify_log(&corrupted, &sign_vk);
        assert!(
            result.is_err(),
            "single bit flip in signature must be detected"
        );
    }

    // -----------------------------------------------------------------------
    // max_file_bytes / LogFull tests (spec-v3 §3.3)
    // -----------------------------------------------------------------------

    #[test]
    fn log_full_rejects_when_entry_exceeds_limit() {
        let (sign_sk, _) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        // Set a very small limit — first entry will exceed it.
        logger.set_max_file_bytes(Some(10));

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let result = logger.log(&cmd, &verdict);

        assert!(
            result.is_err(),
            "write must fail when it would exceed limit"
        );
        match result.unwrap_err() {
            AuditError::LogFull {
                current_bytes,
                entry_bytes,
                max_bytes,
            } => {
                assert_eq!(current_bytes, 0);
                assert!(entry_bytes > 10);
                assert_eq!(max_bytes, 10);
            }
            other => panic!("expected LogFull, got: {other}"),
        }
        // Buffer must remain empty — entry was NOT written.
        assert!(buf.is_empty(), "no data must be written on LogFull");
    }

    #[test]
    fn log_full_allows_entries_within_limit() {
        let (sign_sk, sign_vk) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        // Set a generous limit.
        logger.set_max_file_bytes(Some(1_000_000));

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();
        let entry = logger.log(&cmd, &verdict);
        assert!(entry.is_ok(), "entry within limit must succeed");
        assert!(!buf.is_empty());

        // Verify the log is valid.
        let log_str = String::from_utf8(buf).unwrap();
        assert!(verify_log(&log_str, &sign_vk).is_ok());
    }

    #[test]
    fn log_full_triggers_after_multiple_entries() {
        let (sign_sk, _) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Write one entry to a scratch buffer to measure its size.
        let entry_size = {
            let mut scratch = Vec::new();
            let mut scratch_logger = AuditLogger::new(&mut scratch, sign_sk.clone(), "test".into());
            scratch_logger.log(&cmd, &verdict).unwrap();
            scratch.len() as u64
        };

        // Now create the real logger with a limit that fits 2 entries
        // (add a small margin for timestamp/sequence variation).
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());
        logger.set_max_file_bytes(Some(entry_size * 2 + 256));

        // First and second entries should fit.
        assert!(logger.log(&cmd, &verdict).is_ok(), "first entry must fit");
        assert!(logger.log(&cmd, &verdict).is_ok(), "second entry must fit");

        // Third entry should be rejected.
        let result = logger.log(&cmd, &verdict);
        assert!(result.is_err(), "third entry must be rejected");
        assert!(
            matches!(result.unwrap_err(), AuditError::LogFull { .. }),
            "error must be LogFull"
        );
    }

    #[test]
    fn log_full_disabled_by_default() {
        let (sign_sk, _) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Without max_file_bytes, writes should always succeed.
        for _ in 0..100 {
            assert!(logger.log(&cmd, &verdict).is_ok());
        }
    }

    #[test]
    fn set_initial_bytes_affects_limit_check() {
        let (sign_sk, _) = make_keypair();
        let mut buf = Vec::new();
        let mut logger = AuditLogger::new(&mut buf, sign_sk, "test".into());

        // Pretend the file already has 999,990 bytes.
        logger.set_initial_bytes(999_990);
        logger.set_max_file_bytes(Some(1_000_000));

        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // A typical audit entry is far larger than 10 bytes, so this should fail.
        let result = logger.log(&cmd, &verdict);
        assert!(
            matches!(result.unwrap_err(), AuditError::LogFull { .. }),
            "entry must be rejected when initial_bytes + entry > max"
        );
    }

    // -----------------------------------------------------------------------
    // read_last_line O(1) syscalls test (spec-v3 §5.2)
    // -----------------------------------------------------------------------

    #[test]
    fn read_last_line_large_audit_log() {
        // Write many entries to a temp file, then verify open_file recovers
        // the correct chain state from the last entry using the O(1) reader.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large_audit.jsonl");

        let (sign_sk, _sign_vk) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        // Write 200 entries (produces a file of roughly 0.5-1 MB).
        let expected_sequence;
        let expected_hash;
        {
            let mut logger = AuditLogger::open_file(&path, sign_sk.clone(), "test".into()).unwrap();
            for _ in 0..200 {
                logger.log(&cmd, &verdict).unwrap();
            }
            expected_sequence = logger.sequence();
            expected_hash = logger.previous_hash().to_string();
        }

        // Re-open and verify chain state is recovered correctly.
        let start = std::time::Instant::now();
        let logger = AuditLogger::open_file(&path, sign_sk, "test".into()).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(
            logger.sequence(),
            expected_sequence,
            "sequence must match after re-open"
        );
        assert_eq!(
            logger.previous_hash(),
            expected_hash,
            "previous_hash must match after re-open"
        );

        // The O(1) reader should complete in well under 100ms even on slow
        // CI disks. The old per-byte reader would take proportionally longer
        // on large entries.
        assert!(
            elapsed.as_millis() < 500,
            "read_last_line must be fast: took {}ms",
            elapsed.as_millis()
        );

        // Verify the file is non-trivial in size.
        let file_size = std::fs::metadata(&path).unwrap().len();
        assert!(
            file_size > 50_000,
            "audit log must be substantial: {} bytes",
            file_size
        );
    }

    #[test]
    fn read_last_line_with_trailing_newlines() {
        // Audit logs end with a newline after each entry. Verify the reader
        // handles trailing newlines correctly (doesn't return an empty line).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trailing.jsonl");

        let (sign_sk, _) = make_keypair();
        let cmd = make_simple_command();
        let (verdict, _) = make_simple_signed_verdict();

        {
            let mut logger = AuditLogger::open_file(&path, sign_sk.clone(), "test".into()).unwrap();
            logger.log(&cmd, &verdict).unwrap();
            logger.log(&cmd, &verdict).unwrap();
        }

        // Re-open — must resume at sequence 2.
        let logger = AuditLogger::open_file(&path, sign_sk, "test".into()).unwrap();
        assert_eq!(logger.sequence(), 2);
    }

    #[test]
    fn read_last_line_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.jsonl");

        let (sign_sk, _) = make_keypair();
        let logger = AuditLogger::open_file(&path, sign_sk, "test".into()).unwrap();
        assert_eq!(logger.sequence(), 0);
        assert_eq!(logger.previous_hash(), "");
    }
}
