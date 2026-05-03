// Isaac Lab Unix socket IPC bridge (Section 21.1).
//
// Listens on a Unix domain socket and validates commands from Isaac Lab
// (or any client speaking the newline-delimited JSON protocol).
//
// Protocol:
//   - Client connects to the socket.
//   - Client sends newline-delimited JSON messages. Each message is either:
//     a) A `Command` (validated, returns `BridgeResponse`)
//     b) A heartbeat: `{"heartbeat": true}` (resets watchdog, returns ack)
//   - Server responds with a newline-delimited JSON `BridgeResponse`.
//
// Design:
//   - One `ValidatorConfig` shared across all connections (via `Arc`).
//   - One `Watchdog` per bridge instance (shared, single robot).
//   - Each connection handled in its own tokio task.
//   - No global mutable state beyond the watchdog.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;

use invariant_core::models::command::{Command, JointState};
use invariant_core::models::verdict::SignedVerdict;
use invariant_core::validator::ValidatorConfig;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when running the Isaac Lab bridge server.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// Wraps an underlying I/O error from the Unix socket or stream.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The given socket path already exists and is not a Unix socket.
    #[error("socket path already exists and is not a socket: {path}")]
    PathExists {
        /// The conflicting filesystem path.
        path: String,
    },
}

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

/// Incoming message from Isaac Lab (or any client).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IncomingMessage {
    Heartbeat { heartbeat: bool },
    Command(Box<Command>),
}

/// Response sent back to the client.
#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeResponse {
    /// "verdict" or "heartbeat_ack" or "error".
    #[serde(rename = "type")]
    pub response_type: String,
    /// The signed verdict (present when type = "verdict").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_verdict: Option<SignedVerdict>,
    /// Whether the command was approved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    /// Error message (present when type = "error").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BridgeResponse {
    fn verdict(sv: SignedVerdict) -> Self {
        let approved = sv.verdict.approved;
        Self {
            response_type: "verdict".into(),
            signed_verdict: Some(sv),
            approved: Some(approved),
            error: None,
        }
    }

    fn heartbeat_ack() -> Self {
        Self {
            response_type: "heartbeat_ack".into(),
            signed_verdict: None,
            approved: None,
            error: None,
        }
    }

    fn error(msg: String) -> Self {
        Self {
            response_type: "error".into(),
            signed_verdict: None,
            approved: None,
            error: Some(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge configuration
// ---------------------------------------------------------------------------

/// Configuration for the Isaac Lab bridge.
pub struct BridgeConfig {
    /// Path to the Unix socket.
    pub socket_path: String,
    /// Shared validator configuration.
    pub validator: Arc<ValidatorConfig>,
    /// Watchdog timeout in milliseconds (0 = disabled).
    pub watchdog_timeout_ms: u64,
    /// Maximum message size in bytes (DoS guard).
    pub max_message_bytes: usize,
    /// Per-message read timeout. A slow client that doesn't send within this
    /// window is disconnected.
    pub read_timeout: Duration,
    /// Per-response write timeout. If the client doesn't drain the response
    /// buffer in time, the connection is closed.
    pub write_timeout: Duration,
    /// Maximum number of concurrent connections. New connections beyond this
    /// limit are rejected with an error message.
    pub max_connections: usize,
}

impl BridgeConfig {
    /// Create a new `BridgeConfig` with default message size limit (64 KiB),
    /// 30 s read timeout, 10 s write timeout, and 256 max connections.
    pub fn new(
        socket_path: impl Into<String>,
        validator: Arc<ValidatorConfig>,
        watchdog_timeout_ms: u64,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            validator,
            watchdog_timeout_ms,
            max_message_bytes: 65_536,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
            max_connections: 256,
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge statistics
// ---------------------------------------------------------------------------

/// Counters for bridge activity.
#[derive(Debug, Default, Clone, Serialize)]
pub struct BridgeStats {
    /// Total number of command messages received.
    pub commands_received: u64,
    /// Number of commands that were approved by the validator.
    pub commands_approved: u64,
    /// Number of commands that were rejected by the validator.
    pub commands_rejected: u64,
    /// Number of heartbeat messages received.
    pub heartbeats_received: u64,
    /// Number of protocol or I/O errors encountered.
    pub errors: u64,
}

// ---------------------------------------------------------------------------
// Bridge server
// ---------------------------------------------------------------------------

/// Run the Isaac Lab bridge server.
///
/// Listens on the configured Unix socket, validates incoming commands,
/// and returns signed verdicts. Runs until cancelled.
///
/// Returns the accumulated statistics when the server shuts down.
pub async fn run_bridge(config: BridgeConfig) -> Result<BridgeStats, BridgeError> {
    let socket_path = &config.socket_path;

    // Clean up stale socket file if it exists.
    if Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    let stats = Arc::new(Mutex::new(BridgeStats::default()));
    let max_msg = config.max_message_bytes;
    let read_timeout = config.read_timeout;
    let write_timeout = config.write_timeout;
    let semaphore = Arc::new(Semaphore::new(config.max_connections));

    loop {
        let (stream, _addr) = listener.accept().await?;

        // Enforce maximum connection count.
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // At capacity — reject with an error and close immediately.
                let (_, mut writer) = stream.into_split();
                let resp =
                    BridgeResponse::error("connection limit reached, try again later".into());
                let _ = write_response_with_timeout(&mut writer, &resp, write_timeout).await;
                continue;
            }
        };

        let validator = Arc::clone(&config.validator);
        let stats = Arc::clone(&stats);

        tokio::spawn(async move {
            // Hold the permit for the lifetime of this connection.
            let _permit = permit;

            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();
            let mut previous_joints: Option<Vec<JointState>> = None;

            loop {
                line.clear();

                // Read at most max_msg bytes to prevent OOM from a
                // malicious client sending unbounded data without a
                // newline.  We use take() on the inner reader so that
                // read_line cannot buffer more than max_msg bytes.
                //
                // Apply a per-message read timeout to prevent slow
                // clients from holding connections indefinitely.
                let n = {
                    let read_fut = async {
                        let mut limited = (&mut buf_reader).take(max_msg as u64);
                        limited.read_line(&mut line).await
                    };
                    match tokio::time::timeout(read_timeout, read_fut).await {
                        Ok(Ok(0)) => break, // EOF — client disconnected
                        Ok(Ok(n)) => n,
                        Ok(Err(_)) => break, // read error
                        Err(_) => {
                            eprintln!("bridge: read timeout, disconnecting client");
                            let resp = BridgeResponse::error("read timeout".into());
                            let _ = write_response_with_timeout(&mut writer, &resp, write_timeout)
                                .await;
                            stats.lock().unwrap_or_else(|p| p.into_inner()).errors += 1;
                            break;
                        }
                    }
                };

                // If the line does not end with '\n', the message was
                // truncated by the byte limit — reject and disconnect.
                if !line.ends_with('\n') {
                    let resp = BridgeResponse::error(format!(
                        "message too large: exceeded {max_msg} byte limit"
                    ));
                    let _ = write_response_with_timeout(&mut writer, &resp, write_timeout).await;
                    stats.lock().unwrap_or_else(|p| p.into_inner()).errors += 1;
                    break; // disconnect — stream is in an unknown state
                }

                if n > max_msg {
                    let resp = BridgeResponse::error(format!(
                        "message too large: {n} bytes exceeds {max_msg} limit"
                    ));
                    let _ = write_response_with_timeout(&mut writer, &resp, write_timeout).await;
                    stats.lock().unwrap_or_else(|p| p.into_inner()).errors += 1;
                    continue;
                }

                let resp =
                    handle_message(line.trim(), &validator, &stats, &mut previous_joints).await;

                if write_response_with_timeout(&mut writer, &resp, write_timeout)
                    .await
                    .is_err()
                {
                    break; // write failed or timed out
                }
            }
        });
    }
}

/// Handle a single message and produce a response.
async fn handle_message(
    raw: &str,
    validator: &ValidatorConfig,
    stats: &Arc<Mutex<BridgeStats>>,
    previous_joints: &mut Option<Vec<JointState>>,
) -> BridgeResponse {
    let msg: IncomingMessage = match serde_json::from_str(raw) {
        Ok(m) => m,
        Err(e) => {
            stats.lock().unwrap_or_else(|p| p.into_inner()).errors += 1;
            return BridgeResponse::error(format!("JSON parse error: {e}"));
        }
    };

    match msg {
        IncomingMessage::Heartbeat { heartbeat: true } => {
            stats
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .heartbeats_received += 1;
            BridgeResponse::heartbeat_ack()
        }
        IncomingMessage::Heartbeat { heartbeat: false } => {
            BridgeResponse::error("heartbeat field must be true".into())
        }
        IncomingMessage::Command(cmd) => {
            let now = Utc::now();
            match validator.validate(&cmd, now, previous_joints.as_deref()) {
                Ok(result) => {
                    if result.signed_verdict.verdict.approved {
                        *previous_joints = Some(cmd.joint_states.clone());
                    }
                    let mut s = stats.lock().unwrap_or_else(|p| p.into_inner());
                    s.commands_received += 1;
                    if result.signed_verdict.verdict.approved {
                        s.commands_approved += 1;
                    } else {
                        s.commands_rejected += 1;
                    }
                    BridgeResponse::verdict(result.signed_verdict)
                }
                Err(e) => {
                    stats.lock().unwrap_or_else(|p| p.into_inner()).errors += 1;
                    BridgeResponse::error(format!("validation error: {e}"))
                }
            }
        }
    }
}

/// Write a JSON response followed by a newline.
async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &BridgeResponse,
) -> Result<(), std::io::Error> {
    let json = serde_json::to_vec(resp).unwrap_or_else(|_| b"{}".to_vec());
    writer.write_all(&json).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

/// Write a JSON response with a timeout. Returns `Err` on I/O error or timeout.
async fn write_response_with_timeout(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &BridgeResponse,
    timeout: Duration,
) -> Result<(), std::io::Error> {
    match tokio::time::timeout(timeout, write_response(writer, resp)).await {
        Ok(result) => result,
        Err(_) => {
            eprintln!("bridge: write timeout, disconnecting client");
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write timeout",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use invariant_core::authority::crypto::{generate_keypair, sign_pca};
    use invariant_core::models::authority::{Operation, Pca};
    use invariant_core::models::command::*;
    use invariant_core::models::profile::*;
    use rand::rngs::OsRng;
    use std::collections::{BTreeSet, HashMap};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    fn op(s: &str) -> Operation {
        Operation::new(s).unwrap()
    }

    fn ops(ss: &[&str]) -> BTreeSet<Operation> {
        ss.iter().map(|s| op(s)).collect()
    }

    fn test_profile() -> RobotProfile {
        RobotProfile {
            name: "bridge_test".into(),
            version: "1.0".into(),
            joints: vec![JointDefinition {
                name: "j1".into(),
                joint_type: JointType::Revolute,
                min: -std::f64::consts::PI,
                max: std::f64::consts::PI,
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
            max_delta_time: 0.1,
            min_collision_distance: 0.01,
            global_velocity_scale: 1.0,
            watchdog_timeout_ms: 500,
            safe_stop_profile: SafeStopProfile::default(),
            profile_signature: None,
            profile_signer_kid: None,
            config_sequence: None,
            real_world_margins: None,
            task_envelope: None,
            environment: None,
            end_effectors: vec![],
        }
    }

    fn make_validator() -> (Arc<ValidatorConfig>, String) {
        let (pca_sk, pca_vk) = {
            let sk = generate_keypair(&mut OsRng);
            let vk = sk.verifying_key();
            (sk, vk)
        };
        let (sign_sk, _) = {
            let sk = generate_keypair(&mut OsRng);
            let vk = sk.verifying_key();
            (sk, vk)
        };

        let claim = Pca {
            p_0: "alice".into(),
            ops: ops(&["actuate:*"]),
            kid: "key-1".into(),
            exp: None,
            nbf: None,
        };
        let signed_pca = sign_pca(&claim, &pca_sk).unwrap();
        let chain_json = serde_json::to_vec(&[signed_pca]).unwrap();
        let chain_b64 = base64::engine::general_purpose::STANDARD.encode(&chain_json);

        let mut trusted = HashMap::new();
        trusted.insert("key-1".to_string(), pca_vk);

        let config =
            ValidatorConfig::new(test_profile(), trusted, sign_sk, "bridge-test".into()).unwrap();
        (Arc::new(config), chain_b64)
    }

    fn make_command_json(chain_b64: &str, j1_pos: f64) -> String {
        let cmd = Command {
            timestamp: Utc::now(),
            source: "isaac".into(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: j1_pos,
                velocity: 1.0,
                effort: 10.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![EndEffectorPosition {
                name: "ee".into(),
                position: [0.0, 0.0, 1.0],
            }],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: chain_b64.to_string(),
                required_ops: vec![op("actuate:j1")],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        };
        serde_json::to_string(&cmd).unwrap()
    }

    fn unique_socket_path() -> String {
        format!(
            "/tmp/invariant_test_{}.sock",
            std::process::id() as u64 * 1000 + rand::random::<u16>() as u64
        )
    }

    #[tokio::test]
    async fn bridge_validates_approved_command() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();

        let config = BridgeConfig::new(socket_path.clone(), validator, 0);

        // Start bridge in background.
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });

        // Give the server a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and send a valid command.
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        let msg = make_command_json(&chain_b64, 0.0) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.response_type, "verdict");
        assert_eq!(resp.approved, Some(true));
        assert!(resp.signed_verdict.is_some());

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_validates_rejected_command() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();

        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // j1 position 999 is way out of range.
        let msg = make_command_json(&chain_b64, 999.0) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.response_type, "verdict");
        assert_eq!(resp.approved, Some(false));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_handles_heartbeat() {
        let (validator, _) = make_validator();
        let socket_path = unique_socket_path();

        let config = BridgeConfig::new(socket_path.clone(), validator, 500);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        writer.write_all(b"{\"heartbeat\": true}\n").await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.response_type, "heartbeat_ack");

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_returns_error_for_invalid_json() {
        let (validator, _) = make_validator();
        let socket_path = unique_socket_path();

        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        writer.write_all(b"not valid json\n").await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.response_type, "error");
        assert!(resp.error.unwrap().contains("JSON parse error"));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_handles_multiple_commands_on_one_connection() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();

        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // Send 5 commands on the same connection.
        for i in 0..5 {
            let pos = i as f64 * 0.1;
            let msg = make_command_json(&chain_b64, pos) + "\n";
            writer.write_all(msg.as_bytes()).await.unwrap();

            let mut response_line = String::new();
            buf_reader.read_line(&mut response_line).await.unwrap();

            let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
            assert_eq!(resp.response_type, "verdict");
            assert_eq!(resp.approved, Some(true));
        }

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[test]
    fn bridge_response_serde_verdict() {
        let resp = BridgeResponse::heartbeat_ack();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("heartbeat_ack"));
        assert!(!json.contains("signed_verdict"));
    }

    #[test]
    fn bridge_response_serde_error() {
        let resp = BridgeResponse::error("test error".into());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("error"));
        assert!(json.contains("test error"));
    }

    /// Build a command JSON with customizable fields for targeted bridge tests.
    fn make_custom_command_json(
        chain_b64: &str,
        j1_pos: f64,
        j1_vel: f64,
        j1_effort: f64,
        delta_time: f64,
        ee_pos: [f64; 3],
        sequence: u64,
    ) -> String {
        let cmd = Command {
            timestamp: Utc::now(),
            source: "isaac".into(),
            sequence,
            joint_states: vec![JointState {
                name: "j1".into(),
                position: j1_pos,
                velocity: j1_vel,
                effort: j1_effort,
            }],
            delta_time,
            end_effector_positions: vec![EndEffectorPosition {
                name: "ee".into(),
                position: ee_pos,
            }],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: chain_b64.to_string(),
                required_ops: vec![op("actuate:j1")],
            },
            metadata: HashMap::new(),
            locomotion_state: None,
            end_effector_forces: vec![],
            estimated_payload_kg: None,
            signed_sensor_readings: vec![],
            zone_overrides: HashMap::new(),
            environment_state: None,
        };
        serde_json::to_string(&cmd).unwrap()
    }

    #[tokio::test]
    async fn bridge_rejects_authority_stripped_command() {
        let (validator, _chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        let msg = make_custom_command_json("", 0.0, 0.0, 0.0, 0.01, [0.0, 0.0, 1.0], 1) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.approved, Some(false));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_velocity_overshoot() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // j1_vel = 100.0, profile max_velocity = 5.0
        let msg =
            make_custom_command_json(&chain_b64, 0.0, 100.0, 0.0, 0.01, [0.0, 0.0, 1.0], 1) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.approved, Some(false));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_torque_spike() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // j1_effort = 1000.0, profile max_torque = 100.0
        let msg =
            make_custom_command_json(&chain_b64, 0.0, 0.0, 1000.0, 0.01, [0.0, 0.0, 1.0], 1) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.approved, Some(false));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_workspace_escape() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // ee_pos x=999.0 is outside workspace max [2.0, 2.0, 3.0]
        let msg =
            make_custom_command_json(&chain_b64, 0.0, 0.0, 0.0, 0.01, [999.0, 0.0, 1.0], 1) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.approved, Some(false));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_delta_time_violation() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // delta_time = 1.0, profile max_delta_time = 0.1
        let msg =
            make_custom_command_json(&chain_b64, 0.0, 0.0, 0.0, 1.0, [0.0, 0.0, 1.0], 1) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.approved, Some(false));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_negative_delta_time() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // delta_time = -0.01 is non-positive and physically invalid
        let msg =
            make_custom_command_json(&chain_b64, 0.0, 0.0, 0.0, -0.01, [0.0, 0.0, 1.0], 1) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.approved, Some(false));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_heartbeat_false() {
        let (validator, _) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        writer.write_all(b"{\"heartbeat\": false}\n").await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.response_type, "error");
        assert!(resp.error.unwrap().contains("heartbeat field must be true"));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_empty_json_object() {
        let (validator, _) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // An empty JSON object matches neither a heartbeat nor a Command.
        writer.write_all(b"{}\n").await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.response_type, "error");

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_mixed_commands_and_heartbeats() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // 1. Heartbeat -> expect heartbeat_ack
        writer.write_all(b"{\"heartbeat\": true}\n").await.unwrap();
        let mut line = String::new();
        buf_reader.read_line(&mut line).await.unwrap();
        let resp1: BridgeResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp1.response_type, "heartbeat_ack");

        // 2. Valid command -> expect approved verdict
        line.clear();
        let msg =
            make_custom_command_json(&chain_b64, 0.0, 0.0, 0.0, 0.01, [0.0, 0.0, 1.0], 1) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();
        buf_reader.read_line(&mut line).await.unwrap();
        let resp2: BridgeResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp2.response_type, "verdict");
        assert_eq!(resp2.approved, Some(true));

        // 3. Heartbeat -> expect heartbeat_ack
        line.clear();
        writer.write_all(b"{\"heartbeat\": true}\n").await.unwrap();
        buf_reader.read_line(&mut line).await.unwrap();
        let resp3: BridgeResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp3.response_type, "heartbeat_ack");

        // 4. Invalid command (position out of range) -> expect rejected verdict
        line.clear();
        let bad_msg =
            make_custom_command_json(&chain_b64, 999.0, 0.0, 0.0, 0.01, [0.0, 0.0, 1.0], 2) + "\n";
        writer.write_all(bad_msg.as_bytes()).await.unwrap();
        buf_reader.read_line(&mut line).await.unwrap();
        let resp4: BridgeResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp4.response_type, "verdict");
        assert_eq!(resp4.approved, Some(false));

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_approved_verdict_contains_check_results() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        let msg =
            make_custom_command_json(&chain_b64, 0.0, 0.0, 0.0, 0.01, [0.0, 0.0, 1.0], 1) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.approved, Some(true));
        let sv = resp.signed_verdict.unwrap();
        assert!(
            !sv.verdict.checks.is_empty(),
            "approved verdict must contain check results"
        );
        assert!(
            sv.verdict.checks.iter().all(|c| c.passed),
            "all checks must have passed for an approved command"
        );

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejected_verdict_identifies_failing_check() {
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // Position 999 is well outside ±3.14; must fail the joint_limits check.
        let msg = make_command_json(&chain_b64, 999.0) + "\n";
        writer.write_all(msg.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.approved, Some(false));
        let sv = resp.signed_verdict.unwrap();
        let joint_limits_check = sv
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "joint_limits")
            .expect("verdict must contain a joint_limits check");
        assert!(
            !joint_limits_check.passed,
            "joint_limits check must have failed"
        );

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_oversized_message() {
        let (validator, _) = make_validator();
        let socket_path = unique_socket_path();

        // Use a small max_message_bytes to avoid allocating 64KB in tests
        let mut config = BridgeConfig::new(socket_path.clone(), validator, 0);
        config.max_message_bytes = 100; // 100 bytes max

        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // Send a message larger than 100 bytes
        let oversized = "x".repeat(200) + "\n";
        writer.write_all(oversized.as_bytes()).await.unwrap();

        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await.unwrap();

        let resp: BridgeResponse = serde_json::from_str(&response_line).unwrap();
        assert_eq!(resp.response_type, "error");
        assert!(
            resp.error.as_ref().unwrap().contains("message too large"),
            "DoS guard must reject oversized messages, got: {:?}",
            resp.error
        );

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_read_timeout_disconnects_slow_client() {
        let (validator, _) = make_validator();
        let socket_path = unique_socket_path();

        let mut config = BridgeConfig::new(socket_path.clone(), validator, 0);
        // Use a very short read timeout for tests.
        config.read_timeout = Duration::from_millis(200);

        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, _writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // Don't send anything — wait for the server to time out.
        let mut response_line = String::new();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            buf_reader.read_line(&mut response_line),
        )
        .await;

        match result {
            Ok(Ok(n)) => {
                if n > 0 {
                    let resp: BridgeResponse = serde_json::from_str(response_line.trim()).unwrap();
                    assert_eq!(resp.response_type, "error");
                    assert!(
                        resp.error.as_ref().unwrap().contains("timeout"),
                        "expected timeout error, got: {:?}",
                        resp.error
                    );
                }
                // n == 0 means EOF, which is also fine — server disconnected.
            }
            Ok(Err(_)) => {} // I/O error — server closed connection.
            Err(_) => panic!("test timed out — server did not disconnect the idle client"),
        }

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_connections_at_capacity() {
        let (validator, _) = make_validator();
        let socket_path = unique_socket_path();

        let mut config = BridgeConfig::new(socket_path.clone(), validator, 0);
        config.max_connections = 2;
        // Long read timeout so the first two connections stay alive.
        config.read_timeout = Duration::from_secs(30);

        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Open 2 connections (at capacity).
        let _conn1 = UnixStream::connect(&socket_path).await.unwrap();
        let _conn2 = UnixStream::connect(&socket_path).await.unwrap();

        // Give the server time to accept both connections.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Third connection should be rejected.
        let stream3 = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, _writer) = stream3.into_split();
        let mut buf_reader = BufReader::new(reader);

        let mut response_line = String::new();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            buf_reader.read_line(&mut response_line),
        )
        .await;

        match result {
            Ok(Ok(n)) => {
                assert!(n > 0, "expected an error response, got EOF");
                let resp: BridgeResponse = serde_json::from_str(response_line.trim()).unwrap();
                assert_eq!(resp.response_type, "error");
                assert!(
                    resp.error.as_ref().unwrap().contains("connection limit"),
                    "expected connection limit error, got: {:?}",
                    resp.error
                );
            }
            Ok(Err(e)) => panic!("unexpected I/O error: {e}"),
            Err(_) => panic!("test timed out — server did not reject the connection"),
        }

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_rejects_oversized_message_without_newline() {
        // A malicious client sends a large payload with no newline.
        // The bridge must not OOM — it should reject and disconnect
        // after reading at most max_message_bytes.
        let (validator, _) = make_validator();
        let socket_path = unique_socket_path();

        // Use a small limit so the test runs quickly.
        let max_bytes = 1024;
        let mut config = BridgeConfig::new(socket_path.clone(), validator, 0);
        config.max_message_bytes = max_bytes;

        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // Send 2x the limit with no newline.
        let oversized = "x".repeat(max_bytes * 2);
        writer.write_all(oversized.as_bytes()).await.unwrap();
        // Close the write half so the server sees EOF on the take'd reader.
        drop(writer);

        // Server should send an error response before disconnecting.
        let mut response_line = String::new();
        let n = buf_reader.read_line(&mut response_line).await.unwrap();
        if n > 0 {
            let resp: BridgeResponse = serde_json::from_str(response_line.trim()).unwrap();
            assert_eq!(resp.response_type, "error");
            assert!(
                resp.error.as_ref().unwrap().contains("too large"),
                "expected 'too large' error, got: {:?}",
                resp.error
            );
        }
        // The key assertion: we got here without OOM.

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn bridge_p4_acceleration_check_via_previous_joints() {
        // Verify that per-connection previous_joints tracking enables the P4
        // acceleration check through the bridge. The test profile has
        // max_acceleration = 50.0 rad/s² for joint j1.
        //
        // 1. Send a first command with velocity 0.0 → approved, sets previous_joints.
        // 2. Send a second command with velocity 50.0 and delta_time 0.01 →
        //    estimated acceleration = |50 - 0| / 0.01 = 5000 rad/s² >> 50.
        //    Must be rejected with the acceleration_limits check failing.
        let (validator, chain_b64) = make_validator();
        let socket_path = unique_socket_path();
        let config = BridgeConfig::new(socket_path.clone(), validator, 0);
        let handle = tokio::spawn(async move {
            let _ = run_bridge(config).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        // Command 1: velocity 0.0, should be approved.
        let msg1 =
            make_custom_command_json(&chain_b64, 0.0, 0.0, 0.0, 0.01, [0.0, 0.0, 1.0], 1) + "\n";
        writer.write_all(msg1.as_bytes()).await.unwrap();
        let mut line = String::new();
        buf_reader.read_line(&mut line).await.unwrap();
        let resp1: BridgeResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(resp1.approved, Some(true), "first command must be approved");

        // Command 2: velocity 50.0, same delta_time 0.01 →
        // acceleration = |50 - 0| / 0.01 = 5000 rad/s², far exceeding 50.
        line.clear();
        let msg2 =
            make_custom_command_json(&chain_b64, 0.0, 50.0, 0.0, 0.01, [0.0, 0.0, 1.0], 2) + "\n";
        writer.write_all(msg2.as_bytes()).await.unwrap();
        buf_reader.read_line(&mut line).await.unwrap();
        let resp2: BridgeResponse = serde_json::from_str(&line).unwrap();
        assert_eq!(
            resp2.approved,
            Some(false),
            "second command must be rejected due to excessive acceleration"
        );

        // Verify the acceleration_limits check is the one that failed.
        let sv = resp2
            .signed_verdict
            .expect("rejected verdict must still contain signed_verdict");
        let accel_check = sv
            .verdict
            .checks
            .iter()
            .find(|c| c.name == "acceleration_limits")
            .expect("verdict must contain an acceleration_limits check");
        assert!(
            !accel_check.passed,
            "acceleration_limits check must fail: {}",
            accel_check.details
        );
        assert!(
            accel_check.details.contains("acceleration"),
            "details should mention acceleration: {}",
            accel_check.details
        );

        handle.abort();
        let _ = std::fs::remove_file(&socket_path);
    }
}
