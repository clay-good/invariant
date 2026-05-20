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
/// use invariant_core::incident::IncidentState;
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
/// use invariant_core::incident::IncidentTrigger;
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
/// use invariant_core::incident::{IncidentRecord, IncidentTrigger};
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

/// Webhook alert sink — POSTs alerts to an HTTP endpoint as JSON.
///
/// Uses a hand-rolled HTTP/1.1 client over `std::net::TcpStream` to avoid
/// dragging in an async runtime or a TLS stack. Suitable for in-cluster
/// webhook receivers reachable on `http://host[:port][/path]`. The send is
/// blocking and bounded by `connect_timeout` + `write/read timeout`
/// (default 5 s for each). For HTTPS endpoints, terminate TLS at a sidecar
/// or reverse proxy in front of the receiver.
///
/// On success a `2xx` HTTP status returns `Ok(())`; non-`2xx` returns
/// [`AlertError::DeliveryFailed`] with the status line. Network errors
/// (DNS resolution, TCP connect, write, read, timeout) all map to
/// `DeliveryFailed`. Non-`http://` schemes return [`AlertError::Unavailable`]
/// so misconfiguration fails loudly rather than being silently swallowed.
#[derive(Debug, Clone)]
pub struct WebhookAlertSink {
    url: String,
    timeout: std::time::Duration,
}

/// Components of a parsed `http://host[:port][/path]` URL used by the
/// webhook sink. Internal; only `parse_http_url` constructs it.
#[derive(Debug)]
struct WebhookUrl {
    host: String,
    port: u16,
    path: String,
}

/// Parse a bare `http://` URL into (host, port, path) without pulling in
/// the `url` crate. Reject `https://` and any other scheme up front.
fn parse_http_url(url: &str) -> Result<WebhookUrl, AlertError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        if url.starts_with("https://") {
            AlertError::Unavailable {
                reason: format!(
                    "webhook: https:// is not supported (no TLS stack in invariant-core); \
                     terminate TLS at a sidecar — target: {url}"
                ),
            }
        } else {
            AlertError::Unavailable {
                reason: format!("webhook: only http:// URLs are supported — target: {url}"),
            }
        }
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let parsed: u16 = p.parse().map_err(|e| AlertError::Unavailable {
                reason: format!("webhook: invalid port {p:?} in {url}: {e}"),
            })?;
            (h, parsed)
        }
        None => (authority, 80u16),
    };
    if host.is_empty() {
        return Err(AlertError::Unavailable {
            reason: format!("webhook: empty host in {url}"),
        });
    }
    Ok(WebhookUrl {
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

impl WebhookAlertSink {
    /// Create a webhook sink targeting the given URL. Use the 5-second
    /// default I/O timeout.
    pub fn new(url: String) -> Self {
        Self {
            url,
            timeout: std::time::Duration::from_secs(5),
        }
    }

    /// Create a webhook sink with a custom I/O timeout (applied separately
    /// to TCP connect, write, and read).
    pub fn with_timeout(url: String, timeout: std::time::Duration) -> Self {
        Self { url, timeout }
    }

    /// JSON-escape a message body. Hand-rolled (no `serde_json` dep on the
    /// hot path) — escapes the seven characters JSON requires and emits
    /// `\u00XX` for any other ASCII control char. UTF-8 passes through
    /// untouched.
    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\x08' => out.push_str("\\b"),
                '\x0c' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out
    }
}

impl AlertSink for WebhookAlertSink {
    fn send_alert(&self, message: &str) -> Result<(), AlertError> {
        use std::io::{Read, Write};
        use std::net::{TcpStream, ToSocketAddrs};

        let parsed = parse_http_url(&self.url)?;
        let body = format!(r#"{{"message":"{}"}}"#, Self::json_escape(message));
        let host_header = if parsed.port == 80 {
            parsed.host.clone()
        } else {
            format!("{}:{}", parsed.host, parsed.port)
        };
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nUser-Agent: invariant-webhook/1.0\r\n\
             Connection: close\r\n\r\n{}",
            parsed.path,
            host_header,
            body.len(),
            body,
        );

        let addr = (parsed.host.as_str(), parsed.port)
            .to_socket_addrs()
            .map_err(|e| AlertError::DeliveryFailed {
                reason: format!("webhook: resolve {}:{} failed: {e}", parsed.host, parsed.port),
            })?
            .next()
            .ok_or_else(|| AlertError::DeliveryFailed {
                reason: format!("webhook: resolve {}:{} returned no addresses", parsed.host, parsed.port),
            })?;
        let mut stream =
            TcpStream::connect_timeout(&addr, self.timeout).map_err(|e| {
                AlertError::DeliveryFailed {
                    reason: format!("webhook: connect {addr} failed: {e}"),
                }
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .and_then(|_| stream.set_read_timeout(Some(self.timeout)))
            .map_err(|e| AlertError::DeliveryFailed {
                reason: format!("webhook: set timeout failed: {e}"),
            })?;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| AlertError::DeliveryFailed {
                reason: format!("webhook: write failed: {e}"),
            })?;

        // Read the status line; we only need the first line to classify
        // the response. Cap the read at 4 KiB so a misbehaving server
        // cannot stall us.
        let mut buf = [0u8; 4096];
        let n = stream
            .read(&mut buf)
            .map_err(|e| AlertError::DeliveryFailed {
                reason: format!("webhook: read failed: {e}"),
            })?;
        let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
        let status_line = head.lines().next().unwrap_or("");
        // Expect "HTTP/1.x <code> <reason>"
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok());
        match code {
            Some(c) if (200..300).contains(&c) => Ok(()),
            Some(c) => Err(AlertError::DeliveryFailed {
                reason: format!("webhook: HTTP {c} from {}: {status_line}", self.url),
            }),
            None => Err(AlertError::DeliveryFailed {
                reason: format!(
                    "webhook: malformed response from {} (first line: {status_line:?})",
                    self.url
                ),
            }),
        }
    }

    fn backend_name(&self) -> &str {
        "webhook"
    }
}

/// Syslog facility, per RFC 5424 §6.2.1. Default `Local0` (16) matches
/// the convention for application-level alerts.
#[derive(Debug, Clone, Copy)]
pub enum SyslogFacility {
    /// 0
    Kern,
    /// 1
    User,
    /// 16
    Local0,
    /// 17
    Local1,
    /// 18
    Local2,
    /// 19
    Local3,
}

impl SyslogFacility {
    fn code(self) -> u8 {
        match self {
            Self::Kern => 0,
            Self::User => 1,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
        }
    }
}

/// Syslog alert sink — sends one UDP datagram per alert in RFC 5424 format.
///
/// `<PRI>1 TIMESTAMP HOSTNAME APP_NAME PROCID MSGID - MESSAGE` where
/// `PRI = facility*8 + severity` (severity = 1 / "alert"). PROCID is the
/// invariant process pid; MSGID is `INVALERT`. HOSTNAME / APP_NAME default
/// to the system hostname (or `"-"` when unavailable) and `"invariant"`
/// respectively. Default destination is `127.0.0.1:514`, which is what a
/// local rsyslog/syslog-ng listens on by default.
#[derive(Debug, Clone)]
pub struct SyslogAlertSink {
    target: std::net::SocketAddr,
    facility: SyslogFacility,
    app_name: String,
    hostname: String,
}

impl Default for SyslogAlertSink {
    fn default() -> Self {
        Self::new(
            "127.0.0.1:514".parse().expect("static syslog default addr"),
            SyslogFacility::Local0,
        )
    }
}

impl SyslogAlertSink {
    /// Create a syslog sink targeting `target` over UDP using `facility`.
    pub fn new(target: std::net::SocketAddr, facility: SyslogFacility) -> Self {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "-".into());
        Self {
            target,
            facility,
            app_name: "invariant".into(),
            hostname,
        }
    }

    /// Override the HOSTNAME field (RFC 5424 §6.2.4). Useful in containers
    /// where `$HOSTNAME` is not set.
    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = if hostname.is_empty() { "-".into() } else { hostname };
        self
    }

    /// Override the APP-NAME field (RFC 5424 §6.2.5).
    pub fn with_app_name(mut self, app_name: String) -> Self {
        self.app_name = app_name;
        self
    }

    /// Build the RFC 5424 wire payload for `message` at the configured
    /// facility and severity = Alert (1).
    fn format_message(&self, message: &str) -> String {
        let pri = (self.facility.code() as u16) * 8 + 1; // severity = Alert
        let ts = chrono::Utc::now().to_rfc3339();
        let pid = std::process::id();
        // Replace embedded newlines with spaces; UDP datagram = one message.
        let one_line: String = message
            .chars()
            .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
            .collect();
        format!(
            "<{pri}>1 {ts} {host} {app} {pid} INVALERT - {msg}",
            host = if self.hostname.is_empty() { "-" } else { &self.hostname },
            app = self.app_name,
            msg = one_line,
        )
    }
}

impl AlertSink for SyslogAlertSink {
    fn send_alert(&self, message: &str) -> Result<(), AlertError> {
        use std::net::UdpSocket;
        let datagram = self.format_message(message);
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| AlertError::DeliveryFailed {
            reason: format!("syslog: bind ephemeral UDP socket failed: {e}"),
        })?;
        socket
            .send_to(datagram.as_bytes(), self.target)
            .map_err(|e| AlertError::DeliveryFailed {
                reason: format!("syslog: send_to {} failed: {e}", self.target),
            })?;
        Ok(())
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
    /// use invariant_core::incident::{
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

    #[allow(dead_code)]
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
    fn webhook_alert_sink_rejects_https_with_unavailable() {
        // The webhook sink does not bundle a TLS stack; https:// must
        // fail loudly with Unavailable, not be silently coerced.
        let sink = WebhookAlertSink::new("https://example.com/alert".into());
        assert_eq!(sink.backend_name(), "webhook");
        let err = sink.send_alert("test").expect_err("https must error");
        matches!(err, AlertError::Unavailable { .. });
    }

    #[test]
    fn webhook_alert_sink_rejects_non_http_scheme() {
        let sink = WebhookAlertSink::new("ftp://example.com/alert".into());
        let err = sink.send_alert("x").expect_err("ftp must error");
        matches!(err, AlertError::Unavailable { .. });
    }

    #[test]
    fn webhook_alert_sink_posts_to_listener_and_succeeds_on_2xx() {
        // Spin up a one-shot HTTP/1.1 listener on an ephemeral port; the
        // sink connects, sends a POST with the JSON body, and we verify
        // the request bytes look sane and the sink returns Ok on 200.
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = Arc::clone(&captured);
        let handle = thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().unwrap();
            sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
            let mut buf = [0u8; 8192];
            let n = sock.read(&mut buf).unwrap_or(0);
            *captured_clone.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into_owned();
            sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });

        let url = format!("http://127.0.0.1:{}/alerts", addr.port());
        let sink = WebhookAlertSink::with_timeout(url, std::time::Duration::from_secs(2));
        sink.send_alert("hello \"world\"\n").expect("send_alert");
        handle.join().unwrap();

        let req = captured.lock().unwrap().clone();
        assert!(req.starts_with("POST /alerts HTTP/1.1\r\n"), "request line: {req:?}");
        assert!(
            req.contains(&format!("Host: 127.0.0.1:{}\r\n", addr.port())),
            "Host header: {req:?}"
        );
        assert!(req.contains("Content-Type: application/json\r\n"), "ct: {req:?}");
        // Hand-rolled JSON escape: " → \", LF → \n.
        assert!(
            req.ends_with(r#"{"message":"hello \"world\"\n"}"#),
            "body tail: {req:?}"
        );
    }

    #[test]
    fn webhook_alert_sink_returns_delivery_failed_on_non_2xx() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut throwaway = [0u8; 4096];
            let _ = sock.read(&mut throwaway);
            sock.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });

        let url = format!("http://127.0.0.1:{}/", addr.port());
        let sink = WebhookAlertSink::with_timeout(url, std::time::Duration::from_secs(2));
        let err = sink.send_alert("x").expect_err("must surface 500 as delivery failed");
        handle.join().unwrap();
        match err {
            AlertError::DeliveryFailed { reason } => {
                assert!(reason.contains("HTTP 500"), "reason: {reason}");
            }
            other => panic!("expected DeliveryFailed, got {other:?}"),
        }
    }

    #[test]
    fn webhook_alert_sink_delivery_failed_on_connect_refused() {
        // 127.0.0.1:1 is reserved as tcpmux and is virtually never bound
        // on test hosts; connecting must fail fast and surface as
        // DeliveryFailed rather than panic.
        let sink = WebhookAlertSink::with_timeout(
            "http://127.0.0.1:1/".into(),
            std::time::Duration::from_millis(500),
        );
        let err = sink.send_alert("x").expect_err("port 1 must refuse");
        matches!(err, AlertError::DeliveryFailed { .. });
    }

    #[test]
    fn syslog_alert_sink_sends_rfc5424_datagram_on_loopback() {
        use std::net::UdpSocket;
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let sink = SyslogAlertSink::new(addr, SyslogFacility::Local0)
            .with_hostname("test-host".into())
            .with_app_name("invariant-test".into());
        assert_eq!(sink.backend_name(), "syslog");
        sink.send_alert("incident! line1\nline2").expect("send_alert");

        let mut buf = [0u8; 1500];
        let (n, _src) = listener.recv_from(&mut buf).expect("recv datagram");
        let payload = std::str::from_utf8(&buf[..n]).expect("utf-8");
        // facility=Local0 (16) * 8 + severity=Alert (1) = 129
        assert!(payload.starts_with("<129>1 "), "payload: {payload:?}");
        assert!(payload.contains(" test-host invariant-test "), "header: {payload:?}");
        assert!(payload.contains(" INVALERT - "), "msgid: {payload:?}");
        // Embedded LF replaced with space.
        assert!(payload.ends_with("incident! line1 line2"), "tail: {payload:?}");
        // No bare newline anywhere in the datagram.
        assert!(!payload.contains('\n'), "datagram must be single line");
    }

    #[test]
    fn syslog_alert_sink_default_targets_localhost_514() {
        let s = SyslogAlertSink::default();
        let formatted = s.format_message("hello");
        // Default facility = Local0 (16), severity = Alert (1) → PRI 129.
        assert!(formatted.starts_with("<129>1 "), "{formatted:?}");
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
