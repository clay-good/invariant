//! Audit log replication and Merkle root witness (Section 10.4, Step 35).
//!
//! Provides:
//! - `AuditReplicator` trait — abstract audit log replication backend
//! - `FileReplicator` — copies entries to a second local file
//! - `MerkleTree` — computes Merkle root from audit entry hashes
//! - `WitnessRecord` — data structure for Merkle root publication
//! - Stub backends for S3 and webhook witnesses

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// Computes a Merkle root from a set of leaf hashes.
///
/// The tree is built bottom-up: pairs of adjacent hashes are concatenated
/// and SHA-256'd.  If the number of leaves is odd, the last leaf is
/// duplicated to form a complete pair.
///
/// Returns `None` for an empty leaf set.
pub fn merkle_root(leaves: &[String]) -> Option<String> {
    if leaves.is_empty() {
        return None;
    }

    let mut current: Vec<Vec<u8>> = leaves
        .iter()
        .map(|h| Sha256::digest(h.as_bytes()).to_vec())
        .collect();

    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&pair[0]);
            if pair.len() == 2 {
                hasher.update(&pair[1]);
            } else {
                // Odd leaf: duplicate.
                hasher.update(&pair[0]);
            }
            next.push(hasher.finalize().to_vec());
        }
        current = next;
    }

    Some(format!("sha256:{:x}", Sha256::digest(&current[0])))
}

/// Compute Merkle root from an audit log JSONL file.
///
/// Extracts `entry_hash` from each line and builds the tree.
pub fn merkle_root_from_log(jsonl: &str) -> Option<String> {
    let hashes: Vec<String> = jsonl
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            v.get("entry_hash")?.as_str().map(|s| s.to_string())
        })
        .collect();

    merkle_root(&hashes)
}

// ---------------------------------------------------------------------------
// Witness record
// ---------------------------------------------------------------------------

/// A Merkle root witness record for external publication (RFC 9162 pattern).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WitnessRecord {
    /// Merkle root hash over all audit entry hashes.
    pub merkle_root: String,
    /// Number of audit entries included in this root.
    pub entry_count: u64,
    /// ISO 8601 timestamp of the witness computation.
    pub timestamp: String,
    /// The source audit log file or identifier.
    pub log_source: String,
    /// Ed25519 signature over the canonical JSON of this record (optional).
    #[serde(default)]
    pub signature: String,
    /// Signer key identifier.
    #[serde(default)]
    pub signer_kid: String,
}

// ---------------------------------------------------------------------------
// AuditReplicator trait
// ---------------------------------------------------------------------------

/// Errors from replication operations.
#[derive(Debug, thiserror::Error)]
pub enum ReplicationError {
    #[error("I/O error: {reason}")]
    Io { reason: String },

    #[error("backend unavailable: {reason}")]
    Unavailable { reason: String },
}

/// Abstract audit log replication backend.
///
/// Implementations stream audit entries to a secondary store for
/// tamper-proofing against local disk destruction.
pub trait AuditReplicator: Send + Sync {
    /// Replicate a single JSONL audit entry.
    fn replicate_entry(&mut self, jsonl_line: &str) -> Result<(), ReplicationError>;

    /// Flush/commit any buffered entries.
    fn flush(&mut self) -> Result<(), ReplicationError>;

    /// Backend name for diagnostics.
    fn backend_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// FileReplicator — local file copy
// ---------------------------------------------------------------------------

/// Replicates audit entries to a second local file.
///
/// This is the simplest replicator — suitable for development and as a
/// reference implementation. Production would use S3 or blockchain.
pub struct FileReplicator {
    writer: std::io::BufWriter<std::fs::File>,
}

impl FileReplicator {
    /// Open (or create) a replica file at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self, ReplicationError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| ReplicationError::Io {
                reason: format!("{}: {e}", path.display()),
            })?;
        Ok(Self {
            writer: std::io::BufWriter::new(file),
        })
    }
}

impl AuditReplicator for FileReplicator {
    fn replicate_entry(&mut self, jsonl_line: &str) -> Result<(), ReplicationError> {
        use std::io::Write;
        writeln!(self.writer, "{jsonl_line}").map_err(|e| ReplicationError::Io {
            reason: e.to_string(),
        })
    }

    fn flush(&mut self) -> Result<(), ReplicationError> {
        use std::io::Write;
        self.writer.flush().map_err(|e| ReplicationError::Io {
            reason: e.to_string(),
        })
    }

    fn backend_name(&self) -> &str {
        "file"
    }
}

// ---------------------------------------------------------------------------
// S3Replicator — stub
// ---------------------------------------------------------------------------

/// S3 replication stub (requires `aws-sdk-s3` crate and AWS credentials).
pub struct S3Replicator {
    bucket: String,
    prefix: String,
}

impl S3Replicator {
    pub fn new(bucket: String, prefix: String) -> Self {
        Self { bucket, prefix }
    }
}

impl AuditReplicator for S3Replicator {
    fn replicate_entry(&mut self, _jsonl_line: &str) -> Result<(), ReplicationError> {
        Err(ReplicationError::Unavailable {
            reason: format!(
                "S3 replicator not yet implemented — target: s3://{}/{}",
                self.bucket, self.prefix
            ),
        })
    }

    fn flush(&mut self) -> Result<(), ReplicationError> {
        Ok(())
    }

    fn backend_name(&self) -> &str {
        "s3"
    }
}

// ---------------------------------------------------------------------------
// WebhookWitness — stub for Merkle root publication
// ---------------------------------------------------------------------------

/// Webhook witness stub — publishes Merkle roots to an HTTP endpoint.
pub struct WebhookWitness {
    url: String,
}

impl WebhookWitness {
    pub fn new(url: String) -> Self {
        Self { url }
    }

    /// Publish a witness record (stub — returns Unavailable).
    pub fn publish(&self, _record: &WitnessRecord) -> Result<(), ReplicationError> {
        Err(ReplicationError::Unavailable {
            reason: format!("webhook witness not yet implemented — target: {}", self.url),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Merkle tree ---

    #[test]
    fn merkle_root_empty_returns_none() {
        assert!(merkle_root(&[]).is_none());
    }

    #[test]
    fn merkle_root_single_leaf() {
        let root = merkle_root(&["sha256:aaa".into()]);
        assert!(root.is_some());
        assert!(root.unwrap().starts_with("sha256:"));
    }

    #[test]
    fn merkle_root_two_leaves() {
        let root = merkle_root(&["sha256:aaa".into(), "sha256:bbb".into()]);
        assert!(root.is_some());
    }

    #[test]
    fn merkle_root_deterministic() {
        let leaves = vec!["a".into(), "b".into(), "c".into()];
        let r1 = merkle_root(&leaves).unwrap();
        let r2 = merkle_root(&leaves).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_different_inputs_differ() {
        let r1 = merkle_root(&["a".into(), "b".into()]).unwrap();
        let r2 = merkle_root(&["a".into(), "c".into()]).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn merkle_root_order_matters() {
        let r1 = merkle_root(&["a".into(), "b".into()]).unwrap();
        let r2 = merkle_root(&["b".into(), "a".into()]).unwrap();
        assert_ne!(r1, r2, "Merkle tree is order-sensitive");
    }

    #[test]
    fn merkle_root_odd_leaves() {
        // 3 leaves: last one is duplicated internally.
        let root = merkle_root(&["a".into(), "b".into(), "c".into()]);
        assert!(root.is_some());
    }

    #[test]
    fn merkle_root_from_log_valid() {
        let log = r#"{"entry_hash":"sha256:aaa","sequence":0}
{"entry_hash":"sha256:bbb","sequence":1}
{"entry_hash":"sha256:ccc","sequence":2}"#;
        let root = merkle_root_from_log(log);
        assert!(root.is_some());
    }

    #[test]
    fn merkle_root_from_log_empty() {
        assert!(merkle_root_from_log("").is_none());
        assert!(merkle_root_from_log("\n\n").is_none());
    }

    #[test]
    fn merkle_root_from_log_ignores_invalid_lines() {
        let log = "not json\n{\"entry_hash\":\"sha256:aaa\"}\nmore garbage";
        let root = merkle_root_from_log(log);
        assert!(root.is_some()); // one valid entry
    }

    // --- WitnessRecord ---

    #[test]
    fn witness_record_serde_roundtrip() {
        let record = WitnessRecord {
            merkle_root: "sha256:abc".into(),
            entry_count: 100,
            timestamp: "2026-03-30T00:00:00Z".into(),
            log_source: "audit.jsonl".into(),
            signature: "sig".into(),
            signer_kid: "kid".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: WitnessRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, record);
    }

    // --- FileReplicator ---

    #[test]
    fn file_replicator_writes_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replica.jsonl");

        let mut repl = FileReplicator::open(&path).unwrap();
        assert_eq!(repl.backend_name(), "file");

        repl.replicate_entry(r#"{"sequence":0}"#).unwrap();
        repl.replicate_entry(r#"{"sequence":1}"#).unwrap();
        repl.flush().unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"sequence\":0"));
        assert!(lines[1].contains("\"sequence\":1"));
    }

    #[test]
    fn file_replicator_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("append.jsonl");

        // First writer.
        {
            let mut repl = FileReplicator::open(&path).unwrap();
            repl.replicate_entry("line1").unwrap();
            repl.flush().unwrap();
        }
        // Second writer.
        {
            let mut repl = FileReplicator::open(&path).unwrap();
            repl.replicate_entry("line2").unwrap();
            repl.flush().unwrap();
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
    }

    // --- S3Replicator stub ---

    #[test]
    fn s3_replicator_returns_unavailable() {
        let mut repl = S3Replicator::new("bucket".into(), "prefix/".into());
        assert_eq!(repl.backend_name(), "s3");
        let err = repl.replicate_entry("test").unwrap_err();
        assert!(matches!(err, ReplicationError::Unavailable { .. }));
    }

    // --- WebhookWitness stub ---

    #[test]
    fn webhook_witness_returns_unavailable() {
        let w = WebhookWitness::new("https://witness.example.com".into());
        let record = WitnessRecord {
            merkle_root: "sha256:test".into(),
            entry_count: 0,
            timestamp: "2026-01-01T00:00:00Z".into(),
            log_source: "test".into(),
            signature: String::new(),
            signer_kid: String::new(),
        };
        let err = w.publish(&record).unwrap_err();
        assert!(matches!(err, ReplicationError::Unavailable { .. }));
    }
}
