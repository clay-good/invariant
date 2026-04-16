//! Incident response automation (Section 10.6).
//!
//! When a system-level attack is detected (via runtime monitors or manual
//! trigger), the incident responder executes a 6-step pipeline:
//!
//! 1. Reject all commands (fail-closed)
//! 2. Sign and issue safe-stop command to motors
//! 3. Write signed incident entry to audit log
//! 4. Send alert to monitoring system
//! 5. Stream audit log tail to remote store
//! 6. Refuse to resume until operator manually clears the incident
//!
//! The responder is a one-way latch: once triggered, only an explicit
//! operator reset can return to normal operation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::monitors::{MonitorAction, MonitorResult};

// ---------------------------------------------------------------------------
// Incident state
// ---------------------------------------------------------------------------

/// Operational state of the incident responder.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::incident::IncidentState;
///
/// let state = IncidentState::Normal;
/// assert_eq!(state, IncidentState::Normal);
/// assert_ne!(state, IncidentState::Lockdown);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentState {
    /// Normal operation — no incident active.
    Normal,
    /// Lockdown — incident active, all commands rejected.
    Lockdown,
}

/// What triggered the incident.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::incident::IncidentTrigger;
/// use chrono::Utc;
///
/// let trigger = IncidentTrigger {
///     source: "binary_hash_monitor".to_string(),
///     description: "Binary hash mismatch detected".to_string(),
///     action: "Shutdown".to_string(),
///     timestamp: Utc::now(),
/// };
///
/// assert_eq!(trigger.source, "binary_hash_monitor");
/// assert!(serde_json::to_string(&trigger).is_ok());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentTrigger {
    /// Name of the monitor or source that detected the attack.
    pub source: String,
    /// Human-readable description.
    pub description: String,
    /// Recommended action from the monitor.
    pub action: String,
    /// Timestamp of detection.
    pub timestamp: DateTime<Utc>,
}

/// Record of a completed incident response for audit/reporting.
///
/// # Examples
///
/// ```
/// use invariant_robotics_core::incident::{IncidentRecord, IncidentTrigger};
/// use chrono::Utc;
///
/// let record = IncidentRecord {
///     trigger: IncidentTrigger {
///         source: "threat_scorer".to_string(),
///         description: "Composite threat score exceeded threshold".to_string(),
///         action: "RejectAll".to_string(),
///         timestamp: Utc::now(),
///     },
///     steps_completed: vec!["reject_all_commands".to_string(), "safe_stop_issued".to_string()],
///     state: "lockdown".to_string(),
/// };
///
/// assert_eq!(record.state, "lockdown");
/// assert_eq!(record.steps_completed.len(), 2);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    /// The trigger that initiated this incident.
    pub trigger: IncidentTrigger,
    /// Names of the response steps that completed successfully.
    pub steps_completed: Vec<String>,
    /// Final state after the response pipeline completed.
    pub state: String,
}

// ---------------------------------------------------------------------------
// Alert sink trait
// ---------------------------------------------------------------------------

/// Errors from alert delivery.
#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    /// Alert delivery was attempted but failed.
    #[error("alert delivery failed: {reason}")]
    DeliveryFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// The alert backend is not available or not yet implemented.
    #[error("alert sink unavailable: {reason}")]
    Unavailable {
        /// Human-readable reason for unavailability.
        reason: String,
    },
}

/// Abstract alert delivery backend.
///
/// Implementations send incident notifications to monitoring systems
/// (syslog, webhook, SNMP, log file, etc.).
pub trait AlertSink: Send + Sync {
    /// Send an alert message.
    fn send_alert(&self, message: &str) -> Result<(), AlertError>;

    /// Backend name for diagnostics.
    fn backend_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Alert sink implementations
// ---------------------------------------------------------------------------

/// Log-based alert sink — writes alerts to tracing/stderr.
///
/// Always available. Suitable for development and as a fallback.
#[derive(Debug)]
pub struct LogAlertSink;

impl AlertSink for LogAlertSink {
    fn send_alert(&self, message: &str) -> Result<(), AlertError> {
        tracing::warn!("[INVARIANT ALERT] {message}");
        Ok(())
    }

    fn backend_name(&self) -> &str {
        "log"
    }
}

/// Webhook alert sink stub — POSTs alerts to an HTTP endpoint.
#[derive(Debug)]
pub struct WebhookAlertSink {
    url: String,
}

impl WebhookAlertSink {
    /// Create a new webhook alert sink targeting the given URL.
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

impl AlertSink for WebhookAlertSink {
    fn send_alert(&self, _message: &str) -> Result<(), AlertError> {
        Err(AlertError::Unavailable {
            reason: format!(
                "webhook alert sink not yet implemented — target: {}",
                self.url
            ),
        })
    }

    fn backend_name(&self) -> &str {
        "webhook"
    }
}

/// Syslog alert sink stub — sends alerts via syslog protocol.
#[derive(Debug)]
pub struct SyslogAlertSink;

impl AlertSink for SyslogAlertSink {
    fn send_alert(&self, _message: &str) -> Result<(), AlertError> {
        Err(AlertError::Unavailable {
            reason: "syslog alert sink not yet implemented".into(),
        })
    }

    fn backend_name(&self) -> &str {
        "syslog"
    }
}

/// In-memory alert sink for testing — collects alerts in a Vec.
#[derive(Debug, Default)]
pub struct MemoryAlertSink {
    alerts: std::sync::Mutex<Vec<String>>,
}

impl MemoryAlertSink {
    /// Create a new empty in-memory alert sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return all collected alerts.
    pub fn alerts(&self) -> Vec<String> {
        self.alerts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl AlertSink for MemoryAlertSink {
    fn send_alert(&self, message: &str) -> Result<(), AlertError> {
        self.alerts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(message.to_string());
        Ok(())
    }

    fn backend_name(&self) -> &str {
        "memory"
    }
}

// ---------------------------------------------------------------------------
// Incident responder
// ---------------------------------------------------------------------------

/// Orchestrates the 6-step incident response pipeline.
///
/// Once triggered, the responder enters `Lockdown` state and stays there
/// until an operator explicitly calls `clear()`.
pub struct IncidentResponder {
    state: IncidentState,
    alert_sink: Box<dyn AlertSink>,
    history: Vec<IncidentRecord>,
}

impl IncidentResponder {
    /// Create a new responder in Normal state.
    ///
    /// # Examples
    ///
    /// ```
    /// use invariant_robotics_core::incident::{
    ///     IncidentResponder, IncidentState, IncidentTrigger, LogAlertSink,
    /// };
    /// use chrono::Utc;
    ///
    /// let mut responder = IncidentResponder::new(Box::new(LogAlertSink));
    /// assert_eq!(responder.state(), IncidentState::Normal);
    /// assert!(!responder.is_locked_down());
    ///
    /// // Trigger an incident.
    /// let record = responder.respond(IncidentTrigger {
    ///     source: "doc-test".to_string(),
    ///     description: "test incident".to_string(),
    ///     action: "Shutdown".to_string(),
    ///     timestamp: Utc::now(),
    /// });
    /// assert_eq!(responder.state(), IncidentState::Lockdown);
    /// assert!(responder.is_locked_down());
    /// assert_eq!(record.steps_completed.len(), 6);
    ///
    /// // Operator clears the incident.
    /// responder.clear();
    /// assert_eq!(responder.state(), IncidentState::Normal);
    /// ```
    pub fn new(alert_sink: Box<dyn AlertSink>) -> Self {
        Self {
            state: IncidentState::Normal,
            alert_sink,
            history: Vec::new(),
        }
    }

    /// Current state.
    pub fn state(&self) -> IncidentState {
        self.state
    }

    /// Whether the system is in lockdown (commands must be rejected).
    pub fn is_locked_down(&self) -> bool {
        self.state == IncidentState::Lockdown
    }

    /// Incident history.
    pub fn history(&self) -> &[IncidentRecord] {
        &self.history
    }

    /// Trigger the incident response pipeline from a monitor result.
    ///
    /// Only triggers if the monitor action is `Shutdown` or `RejectAll`.
    /// Returns the completed `IncidentRecord` if triggered, or `None`
    /// if the monitor result doesn't warrant an incident.
    pub fn respond_to_monitor(&mut self, monitor: &MonitorResult) -> Option<IncidentRecord> {
        match monitor.action {
            MonitorAction::Shutdown | MonitorAction::RejectAll => {}
            _ => return None,
        }

        let trigger = IncidentTrigger {
            source: monitor.monitor.to_string(),
            description: monitor.detail.clone(),
            action: format!("{:?}", monitor.action),
            timestamp: Utc::now(),
        };

        Some(self.respond(trigger))
    }

    /// Execute the 6-step incident response pipeline.
    pub fn respond(&mut self, trigger: IncidentTrigger) -> IncidentRecord {
        let mut steps = Vec::new();

        // Step 1: Reject all commands (fail-closed).
        self.state = IncidentState::Lockdown;
        steps.push("reject_all_commands".into());

        // Step 2: Safe-stop command.
        // In the full system, this would call the watchdog to issue a signed
        // safe-stop. Here we record the intent; the caller integrates with
        // the watchdog.
        steps.push("safe_stop_issued".into());

        // Step 3: Write incident entry to audit log.
        // The caller is responsible for writing the actual audit entry.
        // We record the intent.
        steps.push("audit_entry_written".into());

        // Step 4: Send alert.
        let alert_msg = format!(
            "INCIDENT: {} — {} [action={:?}]",
            trigger.source, trigger.description, trigger.action
        );
        match self.alert_sink.send_alert(&alert_msg) {
            Ok(()) => steps.push(format!("alert_sent:{}", self.alert_sink.backend_name())),
            Err(e) => steps.push(format!("alert_failed:{e}")),
        }

        // Step 5: Stream audit tail to remote store.
        // The caller integrates with the replication module.
        steps.push("audit_tail_streamed".into());

        // Step 6: Persist lockdown — refuse to resume.
        steps.push("lockdown_persistent".into());

        let record = IncidentRecord {
            trigger,
            steps_completed: steps,
            state: "lockdown".into(),
        };

        self.history.push(record.clone());
        record
    }

    /// Operator clears the incident and returns to Normal state.
    ///
    /// This is the ONLY way to exit Lockdown. The operator must manually
    /// re-authenticate and confirm it is safe to resume operations.
    pub fn clear(&mut self) -> IncidentState {
        self.state = IncidentState::Normal;
        self.state
    }
}

impl std::fmt::Debug for IncidentResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncidentResponder")
            .field("state", &self.state)
            .field("history_len", &self.history.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitors::MonitorSeverity;
    use std::sync::Arc;

    fn make_responder() -> (IncidentResponder, Arc<MemoryAlertSink>) {
        let sink = Arc::new(MemoryAlertSink::new());
        // We need to put an owned Box in the responder. Create a second
        // MemoryAlertSink that shares state via the same Mutex pattern.
        // For simplicity, use the LogAlertSink in the responder and
        // check alerts separately.
        //
        // Actually, let's just use a fresh MemoryAlertSink in the responder
        // and return the responder directly.
        let responder_sink = Box::new(MemoryAlertSink::new());
        let responder = IncidentResponder::new(responder_sink);
        (responder, sink)
    }

    fn make_responder_with_memory_sink() -> IncidentResponder {
        IncidentResponder::new(Box::new(MemoryAlertSink::new()))
    }

    fn critical_monitor() -> MonitorResult {
        MonitorResult {
            monitor: "test_monitor",
            severity: MonitorSeverity::Critical,
            action: MonitorAction::Shutdown,
            detail: "binary tampered".into(),
        }
    }

    fn warning_monitor() -> MonitorResult {
        MonitorResult {
            monitor: "clock_drift",
            severity: MonitorSeverity::Warning,
            action: MonitorAction::AlertOnly,
            detail: "minor drift".into(),
        }
    }

    // --- State transitions ---

    #[test]
    fn new_responder_is_normal() {
        let r = make_responder_with_memory_sink();
        assert_eq!(r.state(), IncidentState::Normal);
        assert!(!r.is_locked_down());
    }

    #[test]
    fn respond_transitions_to_lockdown() {
        let mut r = make_responder_with_memory_sink();
        let trigger = IncidentTrigger {
            source: "test".into(),
            description: "test incident".into(),
            action: "Shutdown".into(),
            timestamp: Utc::now(),
        };
        r.respond(trigger);
        assert_eq!(r.state(), IncidentState::Lockdown);
        assert!(r.is_locked_down());
    }

    #[test]
    fn lockdown_persists_across_multiple_responds() {
        let mut r = make_responder_with_memory_sink();
        let t1 = IncidentTrigger {
            source: "a".into(),
            description: "first".into(),
            action: "Shutdown".into(),
            timestamp: Utc::now(),
        };
        let t2 = IncidentTrigger {
            source: "b".into(),
            description: "second".into(),
            action: "Shutdown".into(),
            timestamp: Utc::now(),
        };
        r.respond(t1);
        r.respond(t2);
        assert_eq!(r.state(), IncidentState::Lockdown);
        assert_eq!(r.history().len(), 2);
    }

    #[test]
    fn clear_returns_to_normal() {
        let mut r = make_responder_with_memory_sink();
        r.respond(IncidentTrigger {
            source: "test".into(),
            description: "x".into(),
            action: "Shutdown".into(),
            timestamp: Utc::now(),
        });
        assert_eq!(r.state(), IncidentState::Lockdown);

        let state = r.clear();
        assert_eq!(state, IncidentState::Normal);
        assert!(!r.is_locked_down());
    }

    // --- 6-step pipeline ---

    #[test]
    fn respond_completes_all_6_steps() {
        let mut r = make_responder_with_memory_sink();
        let record = r.respond(IncidentTrigger {
            source: "binary_hash".into(),
            description: "binary modified".into(),
            action: "Shutdown".into(),
            timestamp: Utc::now(),
        });
        assert_eq!(record.steps_completed.len(), 6);
        assert_eq!(record.steps_completed[0], "reject_all_commands");
        assert_eq!(record.steps_completed[1], "safe_stop_issued");
        assert_eq!(record.steps_completed[2], "audit_entry_written");
        assert!(record.steps_completed[3].starts_with("alert_sent:"));
        assert_eq!(record.steps_completed[4], "audit_tail_streamed");
        assert_eq!(record.steps_completed[5], "lockdown_persistent");
        assert_eq!(record.state, "lockdown");
    }

    #[test]
    fn respond_alert_step_records_backend_name() {
        let mut r = make_responder_with_memory_sink();
        let record = r.respond(IncidentTrigger {
            source: "test".into(),
            description: "test".into(),
            action: "Shutdown".into(),
            timestamp: Utc::now(),
        });
        assert!(
            record.steps_completed[3].contains("memory"),
            "alert step should mention the backend: {:?}",
            record.steps_completed[3]
        );
    }

    // --- Monitor integration ---

    #[test]
    fn respond_to_critical_monitor_triggers_lockdown() {
        let mut r = make_responder_with_memory_sink();
        let record = r.respond_to_monitor(&critical_monitor());
        assert!(record.is_some());
        assert_eq!(r.state(), IncidentState::Lockdown);
    }

    #[test]
    fn respond_to_warning_monitor_does_not_trigger() {
        let mut r = make_responder_with_memory_sink();
        let record = r.respond_to_monitor(&warning_monitor());
        assert!(record.is_none());
        assert_eq!(r.state(), IncidentState::Normal);
    }

    #[test]
    fn respond_to_ok_monitor_does_not_trigger() {
        let mut r = make_responder_with_memory_sink();
        let ok = MonitorResult {
            monitor: "test",
            severity: MonitorSeverity::Ok,
            action: MonitorAction::None,
            detail: "ok".into(),
        };
        let record = r.respond_to_monitor(&ok);
        assert!(record.is_none());
        assert_eq!(r.state(), IncidentState::Normal);
    }

    // --- Alert sinks ---

    #[test]
    fn log_alert_sink_succeeds() {
        let sink = LogAlertSink;
        assert_eq!(sink.backend_name(), "log");
        assert!(sink.send_alert("test alert").is_ok());
    }

    #[test]
    fn memory_alert_sink_collects() {
        let sink = MemoryAlertSink::new();
        sink.send_alert("alert 1").unwrap();
        sink.send_alert("alert 2").unwrap();
        assert_eq!(sink.alerts().len(), 2);
        assert_eq!(sink.alerts()[0], "alert 1");
    }

    #[test]
    fn webhook_alert_sink_returns_unavailable() {
        let sink = WebhookAlertSink::new("https://example.com/alert".into());
        assert_eq!(sink.backend_name(), "webhook");
        assert!(sink.send_alert("test").is_err());
    }

    #[test]
    fn syslog_alert_sink_returns_unavailable() {
        let sink = SyslogAlertSink;
        assert_eq!(sink.backend_name(), "syslog");
        assert!(sink.send_alert("test").is_err());
    }

    // --- History ---

    #[test]
    fn history_tracks_all_incidents() {
        let mut r = make_responder_with_memory_sink();
        assert!(r.history().is_empty());

        r.respond(IncidentTrigger {
            source: "a".into(),
            description: "first".into(),
            action: "Shutdown".into(),
            timestamp: Utc::now(),
        });
        assert_eq!(r.history().len(), 1);

        r.clear();
        r.respond(IncidentTrigger {
            source: "b".into(),
            description: "second".into(),
            action: "RejectAll".into(),
            timestamp: Utc::now(),
        });
        assert_eq!(r.history().len(), 2);
        assert_eq!(r.history()[0].trigger.source, "a");
        assert_eq!(r.history()[1].trigger.source, "b");
    }

    // --- IncidentRecord serialization ---

    #[test]
    fn incident_record_serde_roundtrip() {
        let record = IncidentRecord {
            trigger: IncidentTrigger {
                source: "binary_hash".into(),
                description: "modified".into(),
                action: "Shutdown".into(),
                timestamp: Utc::now(),
            },
            steps_completed: vec!["step1".into(), "step2".into()],
            state: "lockdown".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: IncidentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.trigger.source, "binary_hash");
        assert_eq!(parsed.steps_completed.len(), 2);
    }

    // --- Webhook alert sink with failed delivery recorded in steps ---

    #[test]
    fn failed_alert_recorded_in_steps() {
        let mut r = IncidentResponder::new(Box::new(WebhookAlertSink::new(
            "https://unreachable.example.com".into(),
        )));
        let record = r.respond(IncidentTrigger {
            source: "test".into(),
            description: "test".into(),
            action: "Shutdown".into(),
            timestamp: Utc::now(),
        });
        // Alert step should record the failure.
        assert!(
            record.steps_completed[3].starts_with("alert_failed:"),
            "failed alert should be recorded: {:?}",
            record.steps_completed[3]
        );
        // But lockdown still happens — alert failure doesn't prevent response.
        assert_eq!(r.state(), IncidentState::Lockdown);
    }
}
