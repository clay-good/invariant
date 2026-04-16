//! Runtime integrity monitors (Section 10.5).
//!
//! Six self-check functions that run continuously to detect compromise:
//!
//! | Monitor               | Frequency | Action on Failure              |
//! |-----------------------|-----------|--------------------------------|
//! | Binary hash           | 60s       | Immediate shutdown + alert     |
//! | Profile hash          | 60s       | Reject all commands + alert    |
//! | Audit tail verify     | 10s       | Switch to backup log + alert   |
//! | HSM connectivity      | 5s        | Fail-closed + alert            |
//! | Memory canary         | 1s        | Immediate shutdown + alert     |
//! | Clock drift           | 10s       | Switch to hardware timer       |
//!
//! Each monitor function returns a `MonitorResult`. The caller (e.g. the
//! `serve` command's tokio runtime) is responsible for scheduling checks at
//! the appropriate frequency and acting on failures.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Severity of a monitor failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorSeverity {
    /// Check passed — no action needed.
    Ok,
    /// Non-critical warning (e.g. minor clock drift).
    Warning,
    /// Critical failure — reject commands / shutdown.
    Critical,
}

/// Recommended action when a monitor fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorAction {
    /// No action needed.
    None,
    /// Reject all incoming commands (fail-closed).
    RejectAll,
    /// Issue safe-stop and shut down.
    Shutdown,
    /// Switch to a backup resource (e.g. backup audit log).
    SwitchToBackup,
    /// Alert the operator but continue.
    AlertOnly,
}

/// Result of a single monitor check.
#[derive(Debug, Clone)]
pub struct MonitorResult {
    /// Name of the monitor that produced this result.
    pub monitor: &'static str,
    /// Severity classification of this result.
    pub severity: MonitorSeverity,
    /// Recommended action the caller should take.
    pub action: MonitorAction,
    /// Human-readable detail string (describes the failure or "ok").
    pub detail: String,
}

impl MonitorResult {
    fn ok(monitor: &'static str) -> Self {
        Self {
            monitor,
            severity: MonitorSeverity::Ok,
            action: MonitorAction::None,
            detail: "ok".into(),
        }
    }

    fn critical(monitor: &'static str, action: MonitorAction, detail: String) -> Self {
        Self {
            monitor,
            severity: MonitorSeverity::Critical,
            action,
            detail,
        }
    }

    fn warning(monitor: &'static str, detail: String) -> Self {
        Self {
            monitor,
            severity: MonitorSeverity::Warning,
            action: MonitorAction::AlertOnly,
            detail,
        }
    }

    /// True if the check passed.
    pub fn is_ok(&self) -> bool {
        self.severity == MonitorSeverity::Ok
    }
}

// ---------------------------------------------------------------------------
// Monitor 1: Binary hash self-check
// ---------------------------------------------------------------------------

/// Verify the running binary hasn't been modified since startup.
///
/// At init time, compute SHA-256 of the binary and store it as
/// `baseline_hash`. On each check, recompute and compare.
pub fn check_binary_hash(baseline_hash: &str) -> MonitorResult {
    let current = match hash_file_at_current_exe() {
        Ok(h) => h,
        Err(e) => {
            return MonitorResult::critical(
                "binary_hash",
                MonitorAction::Shutdown,
                format!("cannot read own binary: {e}"),
            );
        }
    };

    if current == baseline_hash {
        MonitorResult::ok("binary_hash")
    } else {
        MonitorResult::critical(
            "binary_hash",
            MonitorAction::Shutdown,
            format!("binary modified: expected {baseline_hash}, got {current}"),
        )
    }
}

fn hash_file_at_current_exe() -> Result<String, String> {
    let path = std::env::current_exe().map_err(|e| e.to_string())?;
    hash_file(&path)
}

/// SHA-256 a file, returning `sha256:<hex>`.
pub fn hash_file(path: &Path) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let h = Sha256::digest(&data);
    Ok(format!("sha256:{h:x}"))
}

// ---------------------------------------------------------------------------
// Monitor 2: Profile hash verification
// ---------------------------------------------------------------------------

/// Verify the in-memory profile hash still matches the on-disk profile.
///
/// `profile_hash` is the SHA-256 computed at startup from the serialized
/// profile JSON. `profile_path` points to the on-disk file to re-read.
pub fn check_profile_hash(profile_hash: &str, profile_path: &Path) -> MonitorResult {
    let current = match hash_file(profile_path) {
        Ok(h) => h,
        Err(e) => {
            return MonitorResult::critical(
                "profile_hash",
                MonitorAction::RejectAll,
                format!("cannot read profile: {e}"),
            );
        }
    };

    if current == profile_hash {
        MonitorResult::ok("profile_hash")
    } else {
        MonitorResult::critical(
            "profile_hash",
            MonitorAction::RejectAll,
            format!("profile modified on disk: expected {profile_hash}, got {current}"),
        )
    }
}

// ---------------------------------------------------------------------------
// Monitor 3: Audit log tail verification
// ---------------------------------------------------------------------------

/// Verify the last `tail_lines` of the audit log have a valid hash chain.
///
/// Reads the last N lines of the file, parses each as a `SignedAuditEntry`,
/// and checks that `previous_hash` links are consistent.
pub fn check_audit_tail(audit_path: &Path, tail_lines: usize) -> MonitorResult {
    let data = match std::fs::read_to_string(audit_path) {
        Ok(d) => d,
        Err(e) => {
            return MonitorResult::critical(
                "audit_tail",
                MonitorAction::SwitchToBackup,
                format!("cannot read audit log: {e}"),
            );
        }
    };

    let lines: Vec<&str> = data.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return MonitorResult::ok("audit_tail");
    }

    let start = lines.len().saturating_sub(tail_lines);
    let tail = &lines[start..];

    // Parse entries and verify hash chain linkage.
    let mut previous_hash = String::new();
    let mut first = true;

    for (i, line) in tail.iter().enumerate() {
        let entry: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return MonitorResult::critical(
                    "audit_tail",
                    MonitorAction::SwitchToBackup,
                    format!("cannot parse audit line {}: {e}", start + i),
                );
            }
        };

        let entry_prev = entry
            .get("previous_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let entry_hash = entry
            .get("entry_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if !first && entry_prev != previous_hash {
            return MonitorResult::critical(
                "audit_tail",
                MonitorAction::SwitchToBackup,
                format!(
                    "hash chain broken at tail offset {i}: expected previous_hash={previous_hash}, got={entry_prev}"
                ),
            );
        }

        previous_hash = entry_hash.to_string();
        first = false;
    }

    MonitorResult::ok("audit_tail")
}

// ---------------------------------------------------------------------------
// Monitor 4: HSM connectivity check
// ---------------------------------------------------------------------------

/// Verify the key store is reachable by requesting the verifying key.
pub fn check_hsm_connectivity(key_store: &dyn crate::keys::KeyStore) -> MonitorResult {
    match key_store.verifying_key() {
        Ok(_) => MonitorResult::ok("hsm_connectivity"),
        Err(e) => MonitorResult::critical(
            "hsm_connectivity",
            MonitorAction::RejectAll,
            format!("key store unreachable: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Monitor 5: Memory canary
// ---------------------------------------------------------------------------

/// A memory canary: a known bit pattern written at init and checked periodically.
///
/// If the pattern has been corrupted, memory safety has been compromised
/// (e.g. buffer overflow, use-after-free in unsafe code, hardware bit flip).
pub struct MemoryCanary {
    /// The canary value — a fixed pattern written at construction.
    canary: [u64; 4],
}

/// The expected canary pattern (arbitrary but recognizable in memory dumps).
const CANARY_PATTERN: [u64; 4] = [
    0xDEAD_BEEF_CAFE_BABE,
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
    0xA5A5_A5A5_5A5A_5A5A,
];

impl MemoryCanary {
    /// Create a new canary with the expected pattern.
    pub fn new() -> Self {
        Self {
            canary: CANARY_PATTERN,
        }
    }

    /// Check that the canary pattern is intact.
    pub fn check(&self) -> MonitorResult {
        if self.canary == CANARY_PATTERN {
            MonitorResult::ok("memory_canary")
        } else {
            MonitorResult::critical(
                "memory_canary",
                MonitorAction::Shutdown,
                "memory canary corrupted — possible memory safety violation".into(),
            )
        }
    }
}

impl Default for MemoryCanary {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Monitor 6: Monotonic clock drift detection
// ---------------------------------------------------------------------------

/// Detect anomalous drift between the monotonic clock and wall clock.
///
/// At init, record both `Instant::now()` and wall-clock time. On each check,
/// compute elapsed time from both sources. If they diverge beyond
/// `max_drift_ms`, the wall clock may have been manipulated.
pub struct ClockMonitor {
    mono_baseline: Instant,
    wall_baseline_ms: i64,
    max_drift_ms: u64,
}

impl ClockMonitor {
    /// Create a new clock monitor.
    ///
    /// `wall_now_ms` is the current wall-clock time in milliseconds since epoch.
    /// `max_drift_ms` is the maximum allowed divergence (default: 1000ms).
    pub fn new(wall_now_ms: i64, max_drift_ms: u64) -> Self {
        Self {
            mono_baseline: Instant::now(),
            wall_baseline_ms: wall_now_ms,
            max_drift_ms,
        }
    }

    /// Check for clock drift.
    ///
    /// `wall_now_ms` is the current wall-clock time in milliseconds since epoch.
    pub fn check(&self, wall_now_ms: i64) -> MonitorResult {
        let mono_elapsed_ms = self.mono_baseline.elapsed().as_millis() as i64;
        let wall_elapsed_ms = wall_now_ms - self.wall_baseline_ms;

        let drift = (mono_elapsed_ms - wall_elapsed_ms).unsigned_abs();

        if drift <= self.max_drift_ms {
            MonitorResult::ok("clock_drift")
        } else {
            MonitorResult::warning(
                "clock_drift",
                format!(
                    "clock drift {drift}ms exceeds threshold {}ms (mono_elapsed={mono_elapsed_ms}ms, wall_elapsed={wall_elapsed_ms}ms)",
                    self.max_drift_ms
                ),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// MonitorSuite — runs all monitors
// ---------------------------------------------------------------------------

/// Aggregated results from running all monitors.
pub struct MonitorSuiteResults {
    /// Individual results from each monitor in the suite.
    pub results: Vec<MonitorResult>,
}

impl MonitorSuiteResults {
    /// True if all monitors passed.
    pub fn all_ok(&self) -> bool {
        self.results.iter().all(|r| r.is_ok())
    }

    /// Return only failed monitors.
    pub fn failures(&self) -> Vec<&MonitorResult> {
        self.results.iter().filter(|r| !r.is_ok()).collect()
    }

    /// The most severe action recommended.
    pub fn worst_action(&self) -> MonitorAction {
        if self
            .results
            .iter()
            .any(|r| r.action == MonitorAction::Shutdown)
        {
            MonitorAction::Shutdown
        } else if self
            .results
            .iter()
            .any(|r| r.action == MonitorAction::RejectAll)
        {
            MonitorAction::RejectAll
        } else if self
            .results
            .iter()
            .any(|r| r.action == MonitorAction::SwitchToBackup)
        {
            MonitorAction::SwitchToBackup
        } else if self
            .results
            .iter()
            .any(|r| r.action == MonitorAction::AlertOnly)
        {
            MonitorAction::AlertOnly
        } else {
            MonitorAction::None
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Binary hash ---

    #[test]
    fn binary_hash_check_passes_with_matching_hash() {
        let hash = hash_file_at_current_exe().unwrap();
        let result = check_binary_hash(&hash);
        assert!(result.is_ok(), "binary hash should match itself");
    }

    #[test]
    fn binary_hash_check_fails_with_wrong_hash() {
        let result = check_binary_hash("sha256:0000000000000000");
        assert!(!result.is_ok());
        assert_eq!(result.action, MonitorAction::Shutdown);
        assert!(result.detail.contains("modified"));
    }

    // --- Profile hash ---

    #[test]
    fn profile_hash_check_passes_with_matching_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        std::fs::write(&path, r#"{"test": true}"#).unwrap();
        let hash = hash_file(&path).unwrap();
        let result = check_profile_hash(&hash, &path);
        assert!(result.is_ok());
    }

    #[test]
    fn profile_hash_check_fails_after_modification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        std::fs::write(&path, r#"{"version": 1}"#).unwrap();
        let hash = hash_file(&path).unwrap();

        // Modify the file.
        std::fs::write(&path, r#"{"version": 2}"#).unwrap();
        let result = check_profile_hash(&hash, &path);
        assert!(!result.is_ok());
        assert_eq!(result.action, MonitorAction::RejectAll);
    }

    #[test]
    fn profile_hash_check_fails_if_file_missing() {
        let result = check_profile_hash("sha256:abc", Path::new("/nonexistent/profile.json"));
        assert!(!result.is_ok());
        assert_eq!(result.action, MonitorAction::RejectAll);
    }

    // --- Audit tail ---

    #[test]
    fn audit_tail_check_passes_on_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "").unwrap();
        let result = check_audit_tail(&path, 10);
        assert!(result.is_ok());
    }

    #[test]
    fn audit_tail_check_passes_on_valid_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Two entries with valid hash chain linkage.
        let lines = [
            r#"{"sequence":0,"previous_hash":"","entry_hash":"sha256:aaa","command":{},"verdict":{},"entry_signature":"","signer_kid":""}"#,
            r#"{"sequence":1,"previous_hash":"sha256:aaa","entry_hash":"sha256:bbb","command":{},"verdict":{},"entry_signature":"","signer_kid":""}"#,
        ];
        std::fs::write(&path, lines.join("\n")).unwrap();
        let result = check_audit_tail(&path, 10);
        assert!(result.is_ok());
    }

    #[test]
    fn audit_tail_check_detects_broken_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let lines = [
            r#"{"sequence":0,"previous_hash":"","entry_hash":"sha256:aaa","command":{},"verdict":{},"entry_signature":"","signer_kid":""}"#,
            r#"{"sequence":1,"previous_hash":"sha256:WRONG","entry_hash":"sha256:bbb","command":{},"verdict":{},"entry_signature":"","signer_kid":""}"#,
        ];
        std::fs::write(&path, lines.join("\n")).unwrap();
        let result = check_audit_tail(&path, 10);
        assert!(!result.is_ok());
        assert_eq!(result.action, MonitorAction::SwitchToBackup);
    }

    #[test]
    fn audit_tail_check_fails_if_missing() {
        let result = check_audit_tail(Path::new("/nonexistent/audit.jsonl"), 10);
        assert!(!result.is_ok());
    }

    // --- HSM connectivity ---

    #[test]
    fn hsm_connectivity_passes_with_file_key_store() {
        use crate::keys::FileKeyStore;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let store = FileKeyStore::from_signing_key("test".into(), sk);
        let result = check_hsm_connectivity(&store);
        assert!(result.is_ok());
    }

    #[test]
    fn hsm_connectivity_fails_with_unavailable_store() {
        use crate::keys::TpmKeyStore;
        let store = TpmKeyStore::new("tpm-kid".into());
        let result = check_hsm_connectivity(&store);
        assert!(!result.is_ok());
        assert_eq!(result.action, MonitorAction::RejectAll);
    }

    // --- Memory canary ---

    #[test]
    fn canary_passes_when_intact() {
        let canary = MemoryCanary::new();
        let result = canary.check();
        assert!(result.is_ok());
    }

    #[test]
    fn canary_detects_corruption() {
        let mut canary = MemoryCanary::new();
        // Simulate corruption by flipping a bit.
        canary.canary[0] ^= 1;
        let result = canary.check();
        assert!(!result.is_ok());
        assert_eq!(result.action, MonitorAction::Shutdown);
        assert!(result.detail.contains("corrupted"));
    }

    // --- Clock drift ---

    #[test]
    fn clock_drift_passes_when_clocks_agree() {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let monitor = ClockMonitor::new(now_ms, 2000);
        // Check immediately — drift should be ~0.
        let result = monitor.check(chrono::Utc::now().timestamp_millis());
        assert!(result.is_ok());
    }

    #[test]
    fn clock_drift_warns_on_large_skew() {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let monitor = ClockMonitor::new(now_ms, 100); // tight threshold
                                                      // Simulate wall clock jumping 10 seconds ahead.
        let result = monitor.check(now_ms + 10_000);
        assert!(!result.is_ok());
        assert_eq!(result.severity, MonitorSeverity::Warning);
        assert!(result.detail.contains("drift"));
    }

    // --- MonitorSuiteResults ---

    #[test]
    fn suite_results_all_ok() {
        let results = MonitorSuiteResults {
            results: vec![MonitorResult::ok("a"), MonitorResult::ok("b")],
        };
        assert!(results.all_ok());
        assert!(results.failures().is_empty());
        assert_eq!(results.worst_action(), MonitorAction::None);
    }

    #[test]
    fn suite_results_worst_action_shutdown() {
        let results = MonitorSuiteResults {
            results: vec![
                MonitorResult::ok("a"),
                MonitorResult::critical("b", MonitorAction::Shutdown, "bad".into()),
                MonitorResult::critical("c", MonitorAction::RejectAll, "also bad".into()),
            ],
        };
        assert!(!results.all_ok());
        assert_eq!(results.failures().len(), 2);
        assert_eq!(results.worst_action(), MonitorAction::Shutdown);
    }

    #[test]
    fn suite_results_worst_action_reject() {
        let results = MonitorSuiteResults {
            results: vec![
                MonitorResult::ok("a"),
                MonitorResult::critical("b", MonitorAction::RejectAll, "fail".into()),
            ],
        };
        assert_eq!(results.worst_action(), MonitorAction::RejectAll);
    }

    // --- hash_file ---

    #[test]
    fn hash_file_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"deterministic content").unwrap();
        let h1 = hash_file(&path).unwrap();
        let h2 = hash_file(&path).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_file_changes_with_content() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("a.bin");
        let p2 = dir.path().join("b.bin");
        std::fs::write(&p1, b"content-a").unwrap();
        std::fs::write(&p2, b"content-b").unwrap();
        assert_ne!(hash_file(&p1).unwrap(), hash_file(&p2).unwrap());
    }
}
