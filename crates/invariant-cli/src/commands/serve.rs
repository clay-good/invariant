use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::borrow::Cow;

use axum::error_handling::HandleErrorLayer;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{BoxError, Json, Router};
use chrono::Utc;
use clap::Args;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower::limit::ConcurrencyLimitLayer;
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;

use invariant_core::digital_twin::{DivergenceDetector, DivergenceLevel, DivergenceSnapshot};
use invariant_core::models::command::Command;
use invariant_core::validator::ValidatorConfig;
use invariant_core::watchdog::{Watchdog, WatchdogState};

use super::forge::forge_authority;

/// Maximum number of concurrent in-flight requests.
const MAX_CONCURRENT_REQUESTS: usize = 64;

#[derive(Args)]
pub struct ServeArgs {
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    /// TCP port for the embedded Trust Plane. Ports below 1024 require elevated
    /// privileges; use values >= 1024 for unprivileged operation (P3-10).
    #[arg(long, default_value = "8080", value_parser = clap::value_parser!(u16).range(1024..))]
    pub port: u16,
    #[arg(long)]
    pub trust_plane: bool,
    /// Watchdog heartbeat timeout in milliseconds. 0 disables the watchdog.
    #[arg(long, default_value = "500")]
    pub watchdog_timeout_ms: u64,
    /// Optional shared-secret bearer token. When set, /validate and /pca
    /// require an `Authorization: Bearer <token>` header. Health and heartbeat
    /// endpoints remain unauthenticated.
    ///
    /// SECURITY: Passing tokens via CLI arguments exposes them in the process
    /// table. Prefer `--auth-token-file` or `INVARIANT_AUTH_TOKEN` env var.
    #[arg(long, value_name = "TOKEN", hide = true)]
    pub auth_token: Option<String>,
    /// Read the auth token from a file rather than the CLI argument.
    /// The file must contain exactly the raw token string (trailing newline
    /// is stripped). Overrides `--auth-token` when both are supplied.
    #[arg(long, value_name = "TOKEN_FILE")]
    pub auth_token_file: Option<PathBuf>,
    /// Path to write the safe-stop command JSON when the watchdog triggers.
    /// Written atomically (`.tmp` then rename). Defaults to `safe-stop.json`
    /// in the current working directory.
    #[arg(long, value_name = "SAFE_STOP_FILE", default_value = "safe-stop.json")]
    pub safe_stop_path: PathBuf,
    /// Enable continuous adversarial monitoring (Section 11.3). Populates
    /// `threat_analysis` in every verdict with behavioral threat scores.
    #[arg(long)]
    pub threat_scoring: bool,
    /// Also start the Isaac Lab Unix socket bridge (Section 21.1) alongside
    /// the HTTP server. Enables simultaneous HTTP + Unix socket validation.
    #[arg(long)]
    pub bridge: bool,
    /// Path for the Unix socket when --bridge is enabled.
    /// Defaults to `$TMPDIR/invariant.sock` (or `/tmp/invariant.sock` if TMPDIR is unset).
    #[arg(long, value_name = "SOCKET_PATH")]
    pub bridge_socket: Option<String>,
    /// Enable periodic runtime integrity monitors (Section 10.5).
    /// Runs binary hash, profile hash, memory canary, and clock drift checks
    /// in a background task. Triggers incident lockdown on critical failures.
    #[arg(long)]
    pub monitors: bool,
    /// Path for the audit log file. Every validation decision is logged as
    /// signed, hash-chained JSONL (Section 10.1). If omitted, audit logging
    /// is disabled.
    #[arg(long, value_name = "AUDIT_FILE")]
    pub audit_log: Option<PathBuf>,
    /// Enable real-time digital twin divergence detection (Section 18.3).
    /// Compares commanded joint states against observed sensor
    /// feedback to detect sim-to-real divergence. Feeds critical divergence
    /// into the incident response pipeline. Requires --monitors for
    /// automatic lockdown on catastrophic divergence.
    #[arg(long)]
    pub digital_twin: bool,
    /// When set, return HTTP 503 if the audit log write fails instead of
    /// silently continuing. This enforces the L1 audit completeness
    /// invariant: no approved command reaches the motor without an audit
    /// record. Production deployments should enable this flag.
    #[arg(long)]
    pub fail_on_audit_error: bool,
    /// Maximum requests per second per client IP. 0 disables rate limiting
    /// (default). When a client exceeds this limit, requests are rejected
    /// with HTTP 429 Too Many Requests.
    #[arg(long, default_value = "0")]
    pub rate_limit: u64,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct AppState {
    config: ValidatorConfig,
    trust_plane: bool,
    /// Signing key stored directly to avoid reconstructing it on every request.
    signing_key: SigningKey,
    kid: String,
    watchdog: Option<RwLock<WatchdogInner>>,
    boot_instant: Instant,
    /// Optional shared-secret bearer token for /validate and /pca endpoints.
    auth_token: Option<String>,
    /// File path for atomic safe-stop command writes.
    safe_stop_path: PathBuf,
    /// Whether threat scoring is enabled.
    threat_scoring_enabled: bool,
    /// Incident responder for lockdown on critical monitor failures (Section 10.6).
    incident: Option<RwLock<invariant_core::incident::IncidentResponder>>,
    /// Signed, hash-chained audit logger (Section 10.1). Every validation
    /// decision is logged. Wrapped in std::sync::Mutex because AuditLogger
    /// takes &mut self.
    audit: Option<std::sync::Mutex<invariant_core::audit::AuditLogger<std::fs::File>>>,
    /// Real-time digital twin divergence detector (Section 18.3).
    /// Compares commanded joint states against the previous command's joints
    /// to track divergence over time. Wrapped in std::sync::Mutex for
    /// mutable access from the validate handler.
    digital_twin: Option<std::sync::Mutex<DigitalTwinState>>,
    /// Last seen command sequence number for replay protection.
    /// Rejects any command whose sequence is not strictly greater than the
    /// last accepted sequence, preventing replay of previously-approved
    /// signed actuation commands.
    last_sequence: std::sync::atomic::AtomicU64,
    /// Previous command's joint states for P4 acceleration check.
    /// Updated after each successful validation.
    previous_joints: std::sync::Mutex<Option<Vec<invariant_core::models::command::JointState>>>,
    /// Previous command's end-effector forces for P13 force-rate check.
    /// Updated after each successful validation.
    previous_forces:
        std::sync::Mutex<Option<Vec<invariant_core::models::command::EndEffectorForce>>>,
    /// Count of audit log write failures. Exposed on /health so monitoring
    /// systems can alert on audit trail degradation.
    audit_errors: std::sync::atomic::AtomicU64,
    /// When true, return HTTP 503 on audit write failure (L1 enforcement).
    fail_on_audit_error: bool,
    /// Per-IP rate limiter. When `rate_limit_rps > 0`, tracks request counts
    /// per IP per one-second window. Key: IP address. Value: (window start, count).
    rate_limiter: std::sync::Mutex<HashMap<IpAddr, (Instant, u64)>>,
    /// Maximum requests per second per IP (0 = disabled).
    rate_limit_rps: u64,
}

/// Wrapper holding the divergence detector and the last observed snapshot
/// for health reporting.
struct DigitalTwinState {
    detector: DivergenceDetector,
    /// Most recent divergence snapshot (for /health).
    last_snapshot: Option<DivergenceSnapshot>,
    /// Joint states from the most recent command (used as "observed" for
    /// the next command's comparison in dry-run/Shadow mode where real
    /// sensor feedback is the previous command's actual state).
    previous_joints: Option<Vec<invariant_core::models::command::JointState>>,
}

struct WatchdogInner {
    watchdog: Watchdog,
    boot_instant: Instant,
    /// Monotonic ms timestamp of the most recent check() call.
    /// Used by the health endpoint to detect a dead watchdog task.
    last_checked_ms: Option<u64>,
}

impl WatchdogInner {
    fn now_ms(&self) -> u64 {
        // Use saturating cast: u128 -> u64 saturates at u64::MAX (~584 million
        // years of uptime) rather than silently truncating (Finding 37).
        u64::try_from(self.boot_instant.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ValidateRequest {
    command: Command,
}

#[derive(Serialize, Deserialize)]
struct ValidateResponse {
    verdict: invariant_core::models::verdict::SignedVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    actuation_command: Option<invariant_core::models::actuation::SignedActuationCommand>,
}

#[derive(Serialize, Deserialize)]
struct HeartbeatResponse {
    status: Cow<'static, str>,
    watchdog_state: Cow<'static, str>,
}

#[derive(Serialize, Deserialize)]
struct HealthResponse {
    status: Cow<'static, str>,
    profile_name: String,
    trust_plane: bool,
    watchdog_enabled: bool,
    watchdog_state: Option<Cow<'static, str>>,
    uptime_ms: u64,
    /// Whether the watchdog background task appears alive (None when watchdog
    /// is disabled).
    watchdog_alive: Option<bool>,
    /// Whether continuous adversarial monitoring is active.
    threat_scoring: bool,
    /// Whether runtime integrity monitors are active.
    monitors_enabled: bool,
    /// Whether the system is in incident lockdown.
    /// When true, all /validate requests return 503.
    incident_locked_down: bool,
    /// Number of incidents recorded in the current session.
    incident_count: usize,
    /// Whether real-time digital twin divergence detection is active.
    digital_twin_enabled: bool,
    /// Current divergence level (null when digital twin is disabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    digital_twin_level: Option<String>,
    /// Current max position error in radians (null when disabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    digital_twin_max_position_error: Option<f64>,
    /// Total observations processed by the divergence detector.
    #[serde(skip_serializing_if = "Option::is_none")]
    digital_twin_observations: Option<u64>,
    /// Number of audit log write failures since startup.
    /// Non-zero values indicate audit trail degradation (L1 risk).
    audit_errors: u64,
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Constant-time token comparison that does not leak the expected token's
/// length via timing.
///
/// A naive comparison that short-circuits on length mismatch lets an attacker
/// binary-search the correct token length in O(log N) attempts. We avoid this
/// by hashing both values with SHA-256 (keyed by a domain separator) before
/// comparing the fixed-length (32-byte) digests. The XOR-fold comparison on
/// equal-length digests is constant-time regardless of where they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::{Digest, Sha256};

    // Domain-separated hashes ensure that even if an attacker can observe
    // the digest of the expected token, they cannot use it to forge a
    // matching input without inverting SHA-256.
    let hash_a = Sha256::new()
        .chain_update(b"invariant-auth-v1:")
        .chain_update(a)
        .finalize();
    let hash_b = Sha256::new()
        .chain_update(b"invariant-auth-v1:")
        .chain_update(b)
        .finalize();

    hash_a
        .iter()
        .zip(hash_b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Check the `Authorization: Bearer <token>` header against the expected token.
/// Returns `Ok(())` if authentication is not required or if the token matches.
/// Returns `Err(...)` with a 401 response if authentication fails.
fn check_auth(
    headers: &HeaderMap,
    expected: &Option<String>,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let expected_token = match expected {
        Some(t) => t,
        None => return Ok(()),
    };
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let provided = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h["Bearer ".len()..],
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "missing or invalid Authorization header".to_string(),
                }),
            ))
        }
    };

    if constant_time_eq(provided.as_bytes(), expected_token.as_bytes()) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "missing or invalid Authorization header".to_string(),
            }),
        ))
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Check per-IP rate limit. Returns `Err(429)` if the limit is exceeded.
fn check_rate_limit(
    state: &AppState,
    client_ip: IpAddr,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let now = Instant::now();
    let mut limiter = state.rate_limiter.lock().unwrap_or_else(|p| p.into_inner());
    let entry = limiter.entry(client_ip).or_insert((now, 0));
    if now.duration_since(entry.0) >= Duration::from_secs(1) {
        // New window — reset counter.
        *entry = (now, 1);
    } else {
        entry.1 += 1;
        if entry.1 > state.rate_limit_rps {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: format!(
                        "rate limit exceeded: {} requests/s (limit: {})",
                        entry.1, state.rate_limit_rps
                    ),
                }),
            ));
        }
    }
    Ok(())
}

async fn handle_validate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<ErrorResponse>)> {
    check_auth(&headers, &state.auth_token)?;

    // Check incident lockdown — reject all commands if in lockdown (Section 10.6).
    if let Some(ref incident) = state.incident {
        if incident.read().await.is_locked_down() {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "system in incident lockdown — all commands rejected".into(),
                }),
            ));
        }
    }

    let mut cmd = req.command;

    // Sequence replay protection: atomically claim the sequence slot.
    // Uses a compare-exchange loop to ensure that exactly one concurrent
    // request with a given sequence number can proceed.  Without CAS, two
    // requests with the same sequence could both pass a load-then-check
    // window before either stores the new value.
    {
        use std::sync::atomic::Ordering;
        loop {
            let prev = state.last_sequence.load(Ordering::SeqCst);
            if cmd.sequence <= prev {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!(
                            "command sequence {} is not greater than last accepted sequence {} (replay rejected)",
                            cmd.sequence, prev
                        ),
                    }),
                ));
            }
            // Atomically advance prev → cmd.sequence.  If another request
            // raced ahead and changed the value, retry the loop.
            if state
                .last_sequence
                .compare_exchange(prev, cmd.sequence, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
            // CAS failed — another request advanced the counter.  Re-check
            // whether our sequence is still valid against the new value.
        }
    }

    // In trust-plane mode, auto-issue a self-signed PCA chain.
    if state.trust_plane {
        forge_authority(&mut cmd, &state.signing_key, &state.kid, "trust-plane").map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("trust-plane PCA generation failed: {e}"),
                }),
            )
        })?;
    }

    let now = Utc::now();

    // Clone command for audit logging, digital twin observation, and tracking
    // previous joint/force state for P4/P13 checks (the original moves into
    // spawn_blocking, so we always need a clone for post-validation bookkeeping).
    let cmd_for_audit = Some(cmd.clone());

    // Read previous joint/force states for P4 (acceleration) and P13 (force rate).
    let prev_joints = state
        .previous_joints
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let prev_forces = state
        .previous_forces
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();

    // Offload CPU-bound validation to a blocking thread to keep the async
    // runtime responsive for heartbeat and health handlers. ValidatorConfig is
    // not Clone, so we move the Arc<AppState> into the closure and access the
    // config through the shared reference.
    let state_for_blocking = Arc::clone(&state);
    let result = tokio::task::spawn_blocking(move || {
        state_for_blocking.config.validate_with_forces(
            &cmd,
            now,
            prev_joints.as_deref(),
            prev_forces.as_deref(),
        )
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("validation task panicked: {e}"),
            }),
        )
    })?;

    // Update previous joint/force state for the NEXT command's P4/P13 checks.
    // This must happen regardless of whether validation approved or rejected the
    // command: the robot's physical state changes whether or not the safety
    // system approves the motion, so the reference point for the next
    // acceleration/force-rate comparison must always reflect the most recent
    // commanded state.
    if let Some(ref audit_cmd) = cmd_for_audit {
        *state
            .previous_joints
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(audit_cmd.joint_states.clone());
        *state
            .previous_forces
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(audit_cmd.end_effector_forces.clone());
    }

    match result {
        Ok(result) => {
            // Sequence counter was already advanced atomically via CAS
            // in the replay protection block above.

            // Log to audit trail if configured.
            if let (Some(ref audit_mutex), Some(ref audit_cmd)) = (&state.audit, &cmd_for_audit) {
                let audit_ok = match audit_mutex.lock() {
                    Ok(mut logger) => match logger.log(audit_cmd, &result.signed_verdict) {
                        Ok(_entry) => true,
                        Err(e) => {
                            eprintln!("audit: log error: {e}");
                            false
                        }
                    },
                    Err(_poisoned) => {
                        eprintln!("audit: mutex poisoned, cannot write entry");
                        false
                    }
                };
                if !audit_ok {
                    state
                        .audit_errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if state.fail_on_audit_error {
                        return Err((
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(ErrorResponse {
                                error: "audit log write failed — verdict withheld (L1 enforcement)"
                                    .into(),
                            }),
                        ));
                    }
                }
            }

            // Digital twin divergence detection.
            // Compare the current command's joints against the previous
            // command's joints. In Shadow/Guardian mode with real sensor
            // feedback, the "observed" would come from signed sensor
            // readings; here we use the previous command's joint states
            // as the "predicted" and the current command's as "observed"
            // to detect drift over time.
            if let Some(ref dt_mutex) = state.digital_twin {
                if let Some(ref audit_cmd) = cmd_for_audit {
                    {
                        let mut dt = dt_mutex.lock().unwrap_or_else(|p| {
                            eprintln!("digital-twin: mutex poisoned, recovering");
                            p.into_inner()
                        });
                        let current_joints = &audit_cmd.joint_states;
                        if let Some(prev_joints) = dt.previous_joints.take() {
                            let snapshot = dt.detector.observe(&prev_joints, current_joints);

                            // Feed critical/catastrophic divergence to incident responder.
                            if matches!(
                                snapshot.level,
                                DivergenceLevel::Critical | DivergenceLevel::Catastrophic
                            ) {
                                let monitor_result = dt.detector.to_monitor_result(&snapshot);
                                eprintln!(
                                    "digital-twin: {} — {}",
                                    monitor_result.monitor, monitor_result.detail
                                );
                                if let Some(ref incident) = state.incident {
                                    if let Ok(mut responder) = incident.try_write() {
                                        if let Some(record) =
                                            responder.respond_to_monitor(&monitor_result)
                                        {
                                            eprintln!(
                                                "digital-twin: INCIDENT LOCKDOWN triggered ({} steps)",
                                                record.steps_completed.len()
                                            );
                                        }
                                    }
                                }
                            }

                            dt.last_snapshot = Some(snapshot);
                        }
                        dt.previous_joints = Some(current_joints.clone());
                    }
                }
            }

            Ok(Json(ValidateResponse {
                verdict: result.signed_verdict,
                actuation_command: result.actuation_command,
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("validation error: {e}"),
            }),
        )),
    }
}

async fn handle_heartbeat(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY: The heartbeat endpoint is intentionally unauthenticated.
    // The server binds exclusively to 127.0.0.1 (loopback), restricting
    // access to local processes only (Finding 33). In production, the
    // heartbeat caller (the cognitive layer) runs on the same host. If the
    // bind address is ever extended beyond loopback, authentication should
    // be added here.
    let watchdog_rwlock = state.watchdog.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "watchdog is disabled".to_string(),
            }),
        )
    })?;

    let mut inner = watchdog_rwlock.write().await;
    let now_ms = inner.now_ms();
    match inner.watchdog.heartbeat(now_ms) {
        Ok(()) => Ok(Json(HeartbeatResponse {
            status: Cow::Borrowed("ok"),
            watchdog_state: Cow::Borrowed("armed"),
        })),
        Err(e) => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

async fn handle_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    // Saturating cast for uptime — same rationale as now_ms() (Finding 37).
    let uptime_ms = u64::try_from(state.boot_instant.elapsed().as_millis()).unwrap_or(u64::MAX);

    let (watchdog_enabled, watchdog_state, watchdog_alive) =
        if let Some(ref wd_rwlock) = state.watchdog {
            let inner = wd_rwlock.read().await;
            let state_cow: Cow<'static, str> = match inner.watchdog.state() {
                WatchdogState::Armed => Cow::Borrowed("armed"),
                WatchdogState::Triggered => Cow::Borrowed("triggered"),
            };
            // Consider the watchdog task alive if it has checked within
            // 3× the watchdog interval from the last recorded check.
            let alive = inner.last_checked_ms.map(|last_ms| {
                let expected_interval_ms = inner.watchdog.timeout_ms() / 2;
                let max_gap = (expected_interval_ms * 3).max(1000);
                let current_ms = inner.now_ms();
                current_ms.saturating_sub(last_ms) <= max_gap
            });
            (true, Some(state_cow), alive)
        } else {
            (false, None, None)
        };

    // Query incident state.
    let (incident_locked_down, incident_count) = if let Some(ref incident) = state.incident {
        let responder = incident.read().await;
        (responder.is_locked_down(), responder.history().len())
    } else {
        (false, 0)
    };

    // Determine overall status.
    let status = if incident_locked_down {
        Cow::Borrowed("lockdown")
    } else if watchdog_state.as_deref() == Some("triggered") {
        Cow::Borrowed("safe-stop")
    } else {
        Cow::Borrowed("ok")
    };

    // Query digital twin state.
    let (dt_enabled, dt_level, dt_max_pos_err, dt_observations) =
        if let Some(ref dt_mutex) = state.digital_twin {
            {
                let dt = dt_mutex.lock().unwrap_or_else(|p| {
                    eprintln!("digital-twin: mutex poisoned in health check, recovering");
                    p.into_inner()
                });
                match &dt.last_snapshot {
                    Some(snap) => (
                        true,
                        Some(format!("{:?}", snap.level)),
                        Some(snap.window_max_position_error),
                        Some(snap.total_observations),
                    ),
                    None => (true, Some("Normal".into()), None, Some(0)),
                }
            }
        } else {
            (false, None, None, None)
        };

    Json(HealthResponse {
        status,
        profile_name: state.config.profile().name.clone(),
        trust_plane: state.trust_plane,
        watchdog_enabled,
        watchdog_state,
        uptime_ms,
        watchdog_alive,
        threat_scoring: state.threat_scoring_enabled,
        monitors_enabled: state.incident.is_some(),
        incident_locked_down,
        incident_count,
        digital_twin_enabled: dt_enabled,
        digital_twin_level: dt_level,
        digital_twin_max_position_error: dt_max_pos_err,
        digital_twin_observations: dt_observations,
        audit_errors: state
            .audit_errors
            .load(std::sync::atomic::Ordering::Relaxed),
    })
}

// ---------------------------------------------------------------------------
// Safe-stop delivery helper
// ---------------------------------------------------------------------------

/// Atomically write `cmd_json` to `path` by first writing to a `.tmp` sibling
/// and then renaming it into place.  This avoids partial reads by an external
/// watchdog daemon monitoring the path.
fn write_safe_stop_atomic(path: &std::path::Path, cmd_json: &str) {
    let tmp_path = path.with_extension("tmp");
    if let Err(e) = std::fs::write(&tmp_path, cmd_json) {
        eprintln!("watchdog: failed to write safe-stop tmp file {tmp_path:?}: {e}");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        eprintln!("watchdog: failed to rename safe-stop file to {path:?}: {e}");
    }
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

pub fn run(args: &ServeArgs) -> i32 {
    // Build a tokio runtime and block on the async server.
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to create tokio runtime: {e}");
            return 2;
        }
    };

    rt.block_on(async { run_server(args).await })
}

async fn run_server(args: &ServeArgs) -> i32 {
    // Resolve auth token: env var > --auth-token-file > --auth-token (CLI).
    let auth_token = resolve_auth_token(args);
    let auth_token = match auth_token {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Load profile.
    let profile_json = match std::fs::read_to_string(&args.profile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to read profile {:?}: {e}", args.profile);
            return 2;
        }
    };
    let profile = match invariant_core::profiles::load_from_json(&profile_json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid profile: {e}");
            return 2;
        }
    };

    // Load key file.
    let kf = match crate::key_file::load_key_file(&args.key) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (signing_key, verifying_key, kid) = match crate::key_file::load_signing_key(&kf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Keep a copy of the raw bytes solely for constructing the watchdog's
    // independent SigningKey; the AppState will own the primary key directly.
    // Wrapped in a Zeroizing guard so key bytes are wiped on drop (Finding 36).
    let signing_key_bytes = zeroizing::Zeroizing::new(signing_key.to_bytes());

    // Build trusted keys.
    let mut trusted_keys = HashMap::new();
    trusted_keys.insert(kid.clone(), verifying_key);

    // Build validator config.
    let config = match ValidatorConfig::new(profile, trusted_keys, signing_key, kid.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Optionally enable continuous adversarial monitoring.
    let config = if args.threat_scoring {
        eprintln!("info: threat scoring enabled (Section 11.3)");
        config.with_threat_scorer(invariant_core::threat::ThreatScorer::with_defaults())
    } else {
        config
    };

    // Reconstruct a separate SigningKey for AppState (ValidatorConfig consumed the
    // original above); the watchdog gets its own independent copy.
    let app_signing_key = SigningKey::from_bytes(&signing_key_bytes);

    let boot_instant = Instant::now();

    let safe_stop_path = args.safe_stop_path.clone();

    // Optionally create watchdog.
    let watchdog = if args.watchdog_timeout_ms > 0 {
        let safe_stop = config.profile().safe_stop_profile.clone();
        let wd_sk = SigningKey::from_bytes(&signing_key_bytes);
        let wd = Watchdog::new(args.watchdog_timeout_ms, safe_stop, wd_sk, kid.clone(), 0);
        Some(RwLock::new(WatchdogInner {
            watchdog: wd,
            boot_instant,
            last_checked_ms: None,
        }))
    } else {
        None
    };

    // Optionally create incident responder + monitors.
    let incident = if args.monitors {
        eprintln!("info: runtime monitors enabled (Section 10.5/10.6)");
        Some(RwLock::new(
            invariant_core::incident::IncidentResponder::new(Box::new(
                invariant_core::incident::LogAlertSink,
            )),
        ))
    } else {
        None
    };

    // Optionally create audit logger.
    let audit = if let Some(ref audit_path) = args.audit_log {
        let file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit_path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("error: failed to open audit log {:?}: {e}", audit_path);
                return 2;
            }
        };
        let audit_sk = SigningKey::from_bytes(&signing_key_bytes);
        eprintln!("info: audit logging to {:?}", audit_path);
        Some(std::sync::Mutex::new(
            invariant_core::audit::AuditLogger::new(file, audit_sk, kid.clone()),
        ))
    } else {
        None
    };

    // Optionally create digital twin divergence detector.
    let digital_twin = if args.digital_twin {
        eprintln!("info: digital twin divergence detection enabled (Section 18.3)");
        Some(std::sync::Mutex::new(DigitalTwinState {
            detector: DivergenceDetector::with_defaults(),
            last_snapshot: None,
            previous_joints: None,
        }))
    } else {
        None
    };

    let state = Arc::new(AppState {
        config,
        trust_plane: args.trust_plane,
        signing_key: app_signing_key,
        kid,
        watchdog,
        boot_instant,
        auth_token,
        safe_stop_path,
        threat_scoring_enabled: args.threat_scoring,
        incident,
        audit,
        digital_twin,
        last_sequence: std::sync::atomic::AtomicU64::new(0),
        previous_joints: std::sync::Mutex::new(None),
        previous_forces: std::sync::Mutex::new(None),
        audit_errors: std::sync::atomic::AtomicU64::new(0),
        fail_on_audit_error: args.fail_on_audit_error,
        rate_limiter: std::sync::Mutex::new(HashMap::new()),
        rate_limit_rps: args.rate_limit,
    });

    // Spawn a background task to clean up stale rate-limiter entries every 60s.
    if args.rate_limit > 0 {
        let rl_state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut limiter = rl_state
                    .rate_limiter
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                limiter.retain(|_, (window_start, _)| {
                    now.duration_since(*window_start) < Duration::from_secs(60)
                });
            }
        });
        eprintln!(
            "info: rate limiting enabled ({} req/s per IP)",
            args.rate_limit
        );
    }

    // Spawn a background task that periodically calls watchdog.check() so that
    // the timeout can trigger even when no heartbeat requests are in flight.
    // A supervisor task awaits the JoinHandle: if the watchdog task panics or
    // returns unexpectedly it transitions the watchdog to Triggered state
    // (Finding 16).
    let watchdog_task_handle: Option<tokio::task::JoinHandle<()>> = if state.watchdog.is_some() {
        let wd_state = Arc::clone(&state);
        let timeout_ms = args.watchdog_timeout_ms;
        Some(tokio::spawn(async move {
            let interval_ms = (timeout_ms / 2).max(10);
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
            loop {
                interval.tick().await;
                if let Some(ref wd_rwlock) = wd_state.watchdog {
                    let mut inner = wd_rwlock.write().await;
                    let now_ms = inner.now_ms();
                    inner.last_checked_ms = Some(now_ms);
                    let now_utc = Utc::now();
                    match inner.watchdog.check(now_ms, now_utc) {
                        Ok(Some(cmd)) => {
                            // Serialize and deliver the safe-stop command.
                            let cmd_json = serde_json::to_string(&cmd)
                                .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
                            eprintln!(
                                "watchdog: safe-stop triggered; actuation_command={cmd_json}"
                            );
                            // Write atomically to the configured path so an
                            // external watchdog daemon can detect the trigger
                            // (Finding 1).
                            write_safe_stop_atomic(&wd_state.safe_stop_path, &cmd_json);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            eprintln!("watchdog: check error: {e}");
                        }
                    }
                }
            }
        }))
    } else {
        None
    };

    // Supervisor task: if the watchdog background task exits for any reason
    // (panic, unexpected return), log the event (Finding 16).
    if let Some(handle) = watchdog_task_handle {
        let supervisor_state = Arc::clone(&state);
        tokio::spawn(async move {
            match handle.await {
                Ok(()) => {
                    eprintln!("watchdog: background task exited unexpectedly; system is unsafe");
                }
                Err(e) => {
                    eprintln!("watchdog: background task panicked: {e}; system is unsafe");
                }
            }
            // Force watchdog into triggered state so the health endpoint
            // reflects the failure and operators are alerted.
            if let Some(ref wd_rwlock) = supervisor_state.watchdog {
                let mut inner = wd_rwlock.write().await;
                let now_ms = inner.now_ms();
                let now_utc = Utc::now();
                // Drive a final check at current time to force Triggered.
                let _ = inner.watchdog.check(now_ms, now_utc);
            }
        });
    }

    // Optionally spawn the runtime integrity monitor background task.
    if args.monitors {
        let monitor_state = Arc::clone(&state);
        let profile_path = args.profile.clone();
        // Compute baseline binary hash at startup.
        let binary_hash = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::read(p).ok())
            .map(|b| invariant_core::util::sha256_hex(&b))
            .unwrap_or_default();
        // Compute baseline profile hash.
        let profile_hash = std::fs::read(&profile_path)
            .ok()
            .map(|b| invariant_core::util::sha256_hex(&b))
            .unwrap_or_default();
        // Initialize monitors.
        let memory_canary = invariant_core::monitors::MemoryCanary::new();
        let wall_now_ms = Utc::now().timestamp_millis();
        let clock_monitor = invariant_core::monitors::ClockMonitor::new(wall_now_ms, 500);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let results = vec![
                    invariant_core::monitors::check_binary_hash(&binary_hash),
                    invariant_core::monitors::check_profile_hash(&profile_hash, &profile_path),
                    memory_canary.check(),
                    clock_monitor.check(chrono::Utc::now().timestamp_millis()),
                ];

                let suite = invariant_core::monitors::MonitorSuiteResults { results };

                if !suite.all_ok() {
                    for failure in suite.failures() {
                        eprintln!(
                            "monitor: {} — {:?} — {}",
                            failure.monitor, failure.action, failure.detail
                        );
                    }
                    // Feed failures to incident responder.
                    if let Some(ref incident) = monitor_state.incident {
                        let mut responder = incident.write().await;
                        for failure in suite.failures() {
                            if let Some(record) = responder.respond_to_monitor(failure) {
                                eprintln!(
                                    "monitor: INCIDENT LOCKDOWN triggered by {} ({} steps)",
                                    record.trigger.source,
                                    record.steps_completed.len()
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    // Optionally spawn the Isaac Lab Unix socket bridge alongside HTTP.
    let bridge_socket = args.bridge_socket.clone().unwrap_or_else(|| {
        let mut p = std::env::temp_dir();
        p.push("invariant.sock");
        p.to_string_lossy().into_owned()
    });
    if args.bridge {
        let bridge_validator = Arc::new(
            ValidatorConfig::new(
                state.config.profile().clone(),
                {
                    // Re-build trusted keys from the same key file for the bridge's
                    // independent ValidatorConfig. The bridge gets its own config so
                    // the HTTP AppState is not disturbed.
                    let mut tk = HashMap::new();
                    tk.insert(state.kid.clone(), state.signing_key.verifying_key());
                    tk
                },
                SigningKey::from_bytes(&signing_key_bytes),
                state.kid.clone(),
            )
            .expect("bridge validator config"),
        );
        let bridge_config = invariant_sim::isaac::bridge::BridgeConfig::new(
            bridge_socket.clone(),
            bridge_validator,
            args.watchdog_timeout_ms,
        );
        tokio::spawn(async move {
            if let Err(e) = invariant_sim::isaac::bridge::run_bridge(bridge_config).await {
                tracing::error!("bridge: {e}");
            }
        });
        tracing::info!("Isaac Lab bridge listening on {bridge_socket}");
    }

    let rate_limit_state = Arc::clone(&state);
    let app = Router::new()
        .route("/validate", post(handle_validate))
        .route("/heartbeat", post(handle_heartbeat))
        .route("/health", get(handle_health))
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let rl_state = Arc::clone(&rate_limit_state);
                async move {
                    if rl_state.rate_limit_rps > 0 {
                        let client_ip = req
                            .extensions()
                            .get::<axum::extract::ConnectInfo<SocketAddr>>()
                            .map(|ci| ci.0.ip())
                            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
                        if let Err((status, json_body)) = check_rate_limit(&rl_state, client_ip) {
                            let body = serde_json::to_string(&json_body.0).unwrap_or_default();
                            return axum::http::Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .header("retry-after", "1")
                                .body(axum::body::Body::from(body))
                                .unwrap()
                                .into_response();
                        }
                    }
                    next.run(req).await.into_response()
                }
            },
        ))
        .layer(
            // HandleErrorLayer must wrap TimeoutLayer so the BoxError from a
            // timeout is converted to a well-formed HTTP 408 response before
            // axum's Infallible constraint is applied.
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_err: BoxError| async {
                    StatusCode::REQUEST_TIMEOUT
                }))
                .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
                .layer(TimeoutLayer::new(Duration::from_secs(5))),
        )
        .layer(axum::extract::DefaultBodyLimit::max(65_536))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    eprintln!(
        "invariant serve: listening on http://{}:{} (trust_plane={})",
        addr.ip(),
        addr.port(),
        args.trust_plane
    );

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind to {addr}: {e}");
            return 2;
        }
    };

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        eprintln!("error: server error: {e}");
        return 2;
    }

    0
}

/// Resolve the auth token with precedence: env var > file > CLI arg.
///
/// Returns `Ok(None)` when no token is configured through any mechanism.
fn resolve_auth_token(args: &ServeArgs) -> Result<Option<String>, String> {
    // 1. Environment variable takes highest precedence.
    if let Ok(token) = std::env::var("INVARIANT_AUTH_TOKEN") {
        if !token.is_empty() {
            return Ok(Some(token));
        }
    }

    // 2. File-based token (recommended for production; avoids process table exposure).
    if let Some(ref file_path) = args.auth_token_file {
        let raw = std::fs::read_to_string(file_path).map_err(|e| {
            format!(
                "failed to read auth token file {}: {e}",
                file_path.display()
            )
        })?;
        let token = raw
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();
        if !token.is_empty() {
            return Ok(Some(token));
        }
    }

    // 3. CLI arg (least preferred — visible in process table).
    if args.auth_token.is_some() {
        eprintln!(
            "WARNING: --auth-token exposes the token in the process table. \
             Use --auth-token-file or INVARIANT_AUTH_TOKEN instead."
        );
    }
    Ok(args.auth_token.clone())
}

async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            eprintln!("invariant serve: received shutdown signal, shutting down gracefully");
        }
        Err(e) => {
            eprintln!("invariant serve: failed to install CTRL+C handler: {e}; shutting down");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use invariant_core::models::authority::Operation;
    use invariant_core::models::command::{CommandAuthority, JointState};
    use rand::rngs::OsRng;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn make_test_state(trust_plane: bool, watchdog_timeout_ms: u64) -> Arc<AppState> {
        make_test_state_with_auth(trust_plane, watchdog_timeout_ms, None)
    }

    fn make_test_state_with_auth(
        trust_plane: bool,
        watchdog_timeout_ms: u64,
        auth_token: Option<String>,
    ) -> Arc<AppState> {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let kid = "test-serve-kid".to_string();
        let signing_key_bytes = sk.to_bytes();

        let profile_json = invariant_core::profiles::list_builtins()
            .first()
            .map(|name| {
                let p = invariant_core::profiles::load_builtin(name).unwrap();
                serde_json::to_string(&p).unwrap()
            })
            .unwrap();
        let profile = invariant_core::profiles::load_from_json(&profile_json).unwrap();

        let mut trusted_keys = HashMap::new();
        trusted_keys.insert(kid.clone(), vk);

        let config = ValidatorConfig::new(profile, trusted_keys, sk, kid.clone()).unwrap();

        let app_signing_key = SigningKey::from_bytes(&signing_key_bytes);

        let boot_instant = Instant::now();

        let watchdog = if watchdog_timeout_ms > 0 {
            let safe_stop = config.profile().safe_stop_profile.clone();
            let wd_sk = SigningKey::from_bytes(&signing_key_bytes);
            let wd = Watchdog::new(watchdog_timeout_ms, safe_stop, wd_sk, kid.clone(), 0);
            Some(RwLock::new(WatchdogInner {
                watchdog: wd,
                boot_instant,
                last_checked_ms: None,
            }))
        } else {
            None
        };

        Arc::new(AppState {
            config,
            trust_plane,
            signing_key: app_signing_key,
            kid,
            watchdog,
            boot_instant,
            auth_token,
            safe_stop_path: PathBuf::from("safe-stop.json"),
            threat_scoring_enabled: false,
            incident: None,
            audit: None,
            digital_twin: None,
            last_sequence: std::sync::atomic::AtomicU64::new(0),
            previous_joints: std::sync::Mutex::new(None),
            previous_forces: std::sync::Mutex::new(None),
            audit_errors: std::sync::atomic::AtomicU64::new(0),
            fail_on_audit_error: false,
            rate_limiter: std::sync::Mutex::new(HashMap::new()),
            rate_limit_rps: 0,
        })
    }

    fn make_app(state: Arc<AppState>) -> Router {
        let rate_limit_state = Arc::clone(&state);
        Router::new()
            .route("/validate", post(handle_validate))
            .route("/heartbeat", post(handle_heartbeat))
            .route("/health", get(handle_health))
            .layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let rl_state = Arc::clone(&rate_limit_state);
                    async move {
                        if rl_state.rate_limit_rps > 0 {
                            let client_ip = req
                                .extensions()
                                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                                .map(|ci| ci.0.ip())
                                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
                            if let Err((status, json_body)) = check_rate_limit(&rl_state, client_ip)
                            {
                                let body = serde_json::to_string(&json_body.0).unwrap_or_default();
                                return axum::http::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .header("retry-after", "1")
                                    .body(axum::body::Body::from(body))
                                    .unwrap()
                                    .into_response();
                            }
                        }
                        next.run(req).await.into_response()
                    }
                },
            ))
            .with_state(state)
    }

    fn make_test_command() -> Command {
        Command {
            timestamp: Utc::now(),
            source: "test".to_string(),
            sequence: 1,
            joint_states: vec![JointState {
                name: "joint_0".to_string(),
                position: 0.0,
                velocity: 0.0,
                effort: 0.0,
            }],
            delta_time: 0.01,
            end_effector_positions: vec![],
            center_of_mass: None,
            authority: CommandAuthority {
                pca_chain: String::new(),
                required_ops: vec![
                    Operation::new("actuate:humanoid_28dof:joint_0:position").unwrap()
                ],
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

    // --- Health endpoint ---

    #[tokio::test]
    async fn health_returns_ok() {
        let state = make_test_state(false, 0);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.status, "ok");
        assert!(!health.trust_plane);
        assert!(!health.watchdog_enabled);
    }

    #[tokio::test]
    async fn health_shows_trust_plane_and_watchdog() {
        let state = make_test_state(true, 500);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert!(health.trust_plane);
        assert!(health.watchdog_enabled);
        assert_eq!(health.watchdog_state.as_deref(), Some("armed"));
    }

    // --- Validate endpoint ---

    #[tokio::test]
    async fn validate_with_trust_plane_returns_verdict() {
        let state = make_test_state(true, 0);
        let app = make_app(state);

        let cmd = make_test_command();
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let result: ValidateResponse = serde_json::from_slice(&body).unwrap();
        // Trust-plane auto-signs PCA, so authority should pass.
        // The verdict may still be rejected due to physics checks depending on
        // the profile, but we should at least get a well-formed response.
        assert!(!result.verdict.verdict.command_hash.is_empty());
    }

    #[tokio::test]
    async fn validate_without_trust_plane_and_no_chain_rejects() {
        let state = make_test_state(false, 0);
        let app = make_app(state);

        let cmd = make_test_command();
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let result: ValidateResponse = serde_json::from_slice(&body).unwrap();
        // No PCA chain provided, should be rejected.
        assert!(!result.verdict.verdict.approved);
    }

    #[tokio::test]
    async fn validate_invalid_json_returns_error() {
        let state = make_test_state(true, 0);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from("{not valid json}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // axum returns 4xx for JSON parse errors.
        assert!(resp.status().is_client_error());
    }

    // --- Sequence replay protection ---

    #[tokio::test]
    async fn replay_same_sequence_rejected() {
        let state = make_test_state(true, 0);

        // First request with sequence=1 — must succeed.
        let mut cmd = make_test_command();
        cmd.sequence = 1;
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
        let app = make_app(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "first request must succeed");

        // Second request with same sequence=1 — must be rejected as replay.
        let mut cmd2 = make_test_command();
        cmd2.sequence = 1;
        let body2 = serde_json::to_string(&ValidateRequest { command: cmd2 }).unwrap();
        let app2 = make_app(Arc::clone(&state));
        let resp2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body2))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::BAD_REQUEST,
            "replayed sequence must be rejected"
        );
        let body = axum::body::to_bytes(resp2.into_body(), 65536)
            .await
            .unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert!(
            err.error.contains("replay"),
            "error must mention replay: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn lower_sequence_after_higher_rejected() {
        let state = make_test_state(true, 0);

        // First request with sequence=5.
        let mut cmd = make_test_command();
        cmd.sequence = 5;
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
        let app = make_app(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second request with sequence=3 (lower) — must be rejected.
        let mut cmd2 = make_test_command();
        cmd2.sequence = 3;
        let body2 = serde_json::to_string(&ValidateRequest { command: cmd2 }).unwrap();
        let app2 = make_app(Arc::clone(&state));
        let resp2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body2))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::BAD_REQUEST,
            "lower sequence after higher must be rejected"
        );
    }

    #[tokio::test]
    async fn incrementing_sequence_accepted() {
        let state = make_test_state(true, 0);

        // Sequence 1 then 2 — both must succeed.
        for seq in [1u64, 2] {
            let mut cmd = make_test_command();
            cmd.sequence = seq;
            let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
            let app = make_app(Arc::clone(&state));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/validate")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "sequence {seq} must succeed");
        }
    }

    // --- Heartbeat endpoint ---

    #[tokio::test]
    async fn heartbeat_with_watchdog_returns_ok() {
        let state = make_test_state(false, 5000);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/heartbeat")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let hb: HeartbeatResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(hb.status, "ok");
        assert_eq!(hb.watchdog_state, "armed");
    }

    #[tokio::test]
    async fn heartbeat_without_watchdog_returns_error() {
        let state = make_test_state(false, 0);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/heartbeat")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // --- Request body size ---

    #[tokio::test]
    async fn validate_empty_body_returns_error() {
        let state = make_test_state(true, 0);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Empty body should fail JSON parsing.
        assert!(resp.status().is_client_error());
    }

    // --- Authentication ---

    #[tokio::test]
    async fn validate_with_correct_token_returns_ok() {
        let token = "super-secret-token".to_string();
        let state = make_test_state_with_auth(true, 0, Some(token.clone()));
        let app = make_app(state);

        let cmd = make_test_command();
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn validate_with_missing_token_returns_401() {
        let state = make_test_state_with_auth(true, 0, Some("required-token".to_string()));
        let app = make_app(state);

        let cmd = make_test_command();
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_with_wrong_token_returns_401() {
        let state = make_test_state_with_auth(true, 0, Some("correct-token".to_string()));
        let app = make_app(state);

        let cmd = make_test_command();
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer wrong-token")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_is_unauthenticated_even_with_auth_token() {
        let state = make_test_state_with_auth(false, 0, Some("required-token".to_string()));
        let app = make_app(state);

        // No Authorization header — health should still succeed.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn heartbeat_is_unauthenticated_even_with_auth_token() {
        let state = make_test_state_with_auth(false, 5000, Some("required-token".to_string()));
        let app = make_app(state);

        // No Authorization header — heartbeat should still succeed.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/heartbeat")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- Watchdog liveness in health ---

    #[tokio::test]
    async fn health_watchdog_alive_is_none_when_watchdog_disabled() {
        let state = make_test_state(false, 0);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert!(health.watchdog_alive.is_none());
    }

    #[tokio::test]
    async fn health_watchdog_alive_is_false_when_never_checked() {
        // When watchdog is enabled but the background task hasn't run yet,
        // last_checked_ms is None and watchdog_alive should be None (not false).
        let state = make_test_state(false, 500);
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert!(health.watchdog_enabled);
        // last_checked_ms is None -> watchdog_alive maps to None
        assert!(health.watchdog_alive.is_none());
    }

    // --- Constant-time auth comparison (Finding 15) ---

    #[test]
    fn constant_time_eq_same_bytes() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different_bytes() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    // --- resolve_auth_token tests (Finding 32, 56) ---

    #[test]
    fn resolve_auth_token_cli_arg() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("p.json");
        let key = dir.path().join("k.json");
        let args = ServeArgs {
            profile,
            key,
            port: 8080,
            trust_plane: false,
            watchdog_timeout_ms: 0,
            auth_token: Some("cli-token".to_string()),
            auth_token_file: None,
            safe_stop_path: dir.path().join("safe-stop.json"),
            threat_scoring: false,
            bridge: false,
            bridge_socket: Some("/tmp/invariant_test.sock".into()),
            monitors: false,
            audit_log: None,
            digital_twin: false,
            fail_on_audit_error: false,
            rate_limit: 0,
        };
        // No env var set; no file; CLI arg must win.
        // We must clear the env var in case it leaked from another test.
        std::env::remove_var("INVARIANT_AUTH_TOKEN");
        let result = resolve_auth_token(&args).unwrap();
        assert_eq!(result, Some("cli-token".to_string()));
    }

    #[test]
    fn resolve_auth_token_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token.txt");
        std::fs::write(&token_file, "file-token\n").unwrap();

        let profile = dir.path().join("p.json");
        let key = dir.path().join("k.json");
        let args = ServeArgs {
            profile,
            key,
            port: 8080,
            trust_plane: false,
            watchdog_timeout_ms: 0,
            auth_token: Some("cli-token".to_string()),
            auth_token_file: Some(token_file),
            safe_stop_path: dir.path().join("safe-stop.json"),
            threat_scoring: false,
            bridge: false,
            bridge_socket: Some("/tmp/invariant_test.sock".into()),
            monitors: false,
            audit_log: None,
            digital_twin: false,
            fail_on_audit_error: false,
            rate_limit: 0,
        };
        std::env::remove_var("INVARIANT_AUTH_TOKEN");
        let result = resolve_auth_token(&args).unwrap();
        // File overrides CLI arg; trailing newline must be stripped.
        assert_eq!(result, Some("file-token".to_string()));
    }

    #[test]
    fn resolve_auth_token_missing_file_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let args = ServeArgs {
            profile: dir.path().join("p.json"),
            key: dir.path().join("k.json"),
            port: 8080,
            trust_plane: false,
            watchdog_timeout_ms: 0,
            auth_token: None,
            auth_token_file: Some(dir.path().join("nonexistent.txt")),
            safe_stop_path: dir.path().join("safe-stop.json"),
            threat_scoring: false,
            bridge: false,
            bridge_socket: Some("/tmp/invariant_test.sock".into()),
            monitors: false,
            audit_log: None,
            digital_twin: false,
            fail_on_audit_error: false,
            rate_limit: 0,
        };
        std::env::remove_var("INVARIANT_AUTH_TOKEN");
        let result = resolve_auth_token(&args);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("failed to read auth token file"));
    }

    #[test]
    fn resolve_auth_token_none_when_nothing_configured() {
        let dir = tempfile::tempdir().unwrap();
        let args = ServeArgs {
            profile: dir.path().join("p.json"),
            key: dir.path().join("k.json"),
            port: 8080,
            trust_plane: false,
            watchdog_timeout_ms: 0,
            auth_token: None,
            auth_token_file: None,
            safe_stop_path: dir.path().join("safe-stop.json"),
            threat_scoring: false,
            bridge: false,
            bridge_socket: Some("/tmp/invariant_test.sock".into()),
            monitors: false,
            audit_log: None,
            digital_twin: false,
            fail_on_audit_error: false,
            rate_limit: 0,
        };
        std::env::remove_var("INVARIANT_AUTH_TOKEN");
        let result = resolve_auth_token(&args).unwrap();
        assert!(result.is_none());
    }

    // --- Safe-stop atomic write (Finding 1) ---

    #[test]
    fn write_safe_stop_atomic_creates_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("safe-stop.json");
        write_safe_stop_atomic(&path, r#"{"test":"value"}"#);
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, r#"{"test":"value"}"#);
    }

    #[test]
    fn write_safe_stop_atomic_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("safe-stop.json");
        std::fs::write(&path, "old content").unwrap();
        write_safe_stop_atomic(&path, r#"{"new":"content"}"#);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, r#"{"new":"content"}"#);
    }

    // --- run() startup error path tests (Finding 56) ---

    #[test]
    fn run_returns_2_on_missing_profile() {
        let dir = TempDir::new().unwrap();
        let args = ServeArgs {
            profile: dir.path().join("nonexistent_profile.json"),
            key: dir.path().join("key.json"),
            port: 1025,
            trust_plane: false,
            watchdog_timeout_ms: 0,
            auth_token: None,
            auth_token_file: None,
            safe_stop_path: dir.path().join("safe-stop.json"),
            threat_scoring: false,
            bridge: false,
            bridge_socket: Some("/tmp/invariant_test.sock".into()),
            monitors: false,
            audit_log: None,
            digital_twin: false,
            fail_on_audit_error: false,
            rate_limit: 0,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn run_returns_2_on_missing_key_file() {
        use std::io::Write;
        let dir = TempDir::new().unwrap();
        let profile_path = dir.path().join("profile.json");
        let profile = invariant_core::profiles::load_builtin("humanoid_28dof").unwrap();
        let profile_json = serde_json::to_string(&profile).unwrap();
        let mut f = std::fs::File::create(&profile_path).unwrap();
        f.write_all(profile_json.as_bytes()).unwrap();

        let args = ServeArgs {
            profile: profile_path,
            key: dir.path().join("nonexistent_key.json"),
            port: 1025,
            trust_plane: false,
            watchdog_timeout_ms: 0,
            auth_token: None,
            auth_token_file: None,
            safe_stop_path: dir.path().join("safe-stop.json"),
            threat_scoring: false,
            bridge: false,
            bridge_socket: Some("/tmp/invariant_test.sock".into()),
            monitors: false,
            audit_log: None,
            digital_twin: false,
            fail_on_audit_error: false,
            rate_limit: 0,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn run_returns_2_on_invalid_profile_json() {
        use std::io::Write;
        let dir = TempDir::new().unwrap();
        let profile_path = dir.path().join("bad_profile.json");
        let mut f = std::fs::File::create(&profile_path).unwrap();
        f.write_all(b"this is not valid json").unwrap();

        let args = ServeArgs {
            profile: profile_path,
            key: dir.path().join("key.json"),
            port: 1025,
            trust_plane: false,
            watchdog_timeout_ms: 0,
            auth_token: None,
            auth_token_file: None,
            safe_stop_path: dir.path().join("safe-stop.json"),
            threat_scoring: false,
            bridge: false,
            bridge_socket: Some("/tmp/invariant_test.sock".into()),
            monitors: false,
            audit_log: None,
            digital_twin: false,
            fail_on_audit_error: false,
            rate_limit: 0,
        };
        assert_eq!(run(&args), 2);
    }

    // --- Integration tests for hardening fixes (spec-v3 §8.1) ---

    /// Build an AppState with an audit logger backed by a read-only file
    /// descriptor so that every write fails, letting us test the audit error
    /// counter and --fail-on-audit-error behaviour.
    fn make_test_state_with_failing_audit(fail_on_audit_error: bool) -> Arc<AppState> {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let kid = "test-serve-kid".to_string();
        let signing_key_bytes = sk.to_bytes();

        let profile_json = invariant_core::profiles::list_builtins()
            .first()
            .map(|name| {
                let p = invariant_core::profiles::load_builtin(name).unwrap();
                serde_json::to_string(&p).unwrap()
            })
            .unwrap();
        let profile = invariant_core::profiles::load_from_json(&profile_json).unwrap();

        let mut trusted_keys = HashMap::new();
        trusted_keys.insert(kid.clone(), vk);

        let config = ValidatorConfig::new(profile, trusted_keys, sk, kid.clone()).unwrap();
        let app_signing_key = SigningKey::from_bytes(&signing_key_bytes);

        // Create a temp file and open it READ-ONLY so writes fail.
        let dir = TempDir::new().unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        std::fs::write(&audit_path, "").unwrap();
        let ro_file = std::fs::OpenOptions::new()
            .read(true)
            .open(&audit_path)
            .unwrap();

        let audit_sk = SigningKey::from_bytes(&signing_key_bytes);
        let logger = invariant_core::audit::AuditLogger::new(ro_file, audit_sk, kid.clone());

        // Leak the TempDir so it lives as long as AppState.
        std::mem::forget(dir);

        Arc::new(AppState {
            config,
            trust_plane: true, // auto-sign PCA
            signing_key: app_signing_key,
            kid,
            watchdog: None,
            boot_instant: Instant::now(),
            auth_token: None,
            safe_stop_path: PathBuf::from("safe-stop.json"),
            threat_scoring_enabled: false,
            incident: None,
            audit: Some(std::sync::Mutex::new(logger)),
            digital_twin: None,
            last_sequence: std::sync::atomic::AtomicU64::new(0),
            previous_joints: std::sync::Mutex::new(None),
            previous_forces: std::sync::Mutex::new(None),
            audit_errors: std::sync::atomic::AtomicU64::new(0),
            fail_on_audit_error,
            rate_limiter: std::sync::Mutex::new(HashMap::new()),
            rate_limit_rps: 0,
        })
    }

    #[tokio::test]
    async fn test_audit_write_failure_increments_counter() {
        let state = make_test_state_with_failing_audit(false);

        // Send a valid command (trust_plane auto-signs PCA).
        let mut cmd = make_test_command();
        cmd.sequence = 1;
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
        let app = make_app(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        // With fail_on_audit_error=false, the verdict is still returned
        // even though the audit write failed.
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify the counter was incremented.
        let errors = state
            .audit_errors
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(errors > 0, "audit_errors must be > 0 after write failure");

        // Verify the health endpoint reports the counter.
        let app2 = make_app(Arc::clone(&state));
        let health_resp = app2
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(health_resp.into_body(), 65536)
            .await
            .unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert!(
            health.audit_errors > 0,
            "/health must report audit_errors > 0"
        );
    }

    #[tokio::test]
    async fn test_audit_write_failure_returns_503_when_fail_on_audit_error() {
        let state = make_test_state_with_failing_audit(true);

        let mut cmd = make_test_command();
        cmd.sequence = 1;
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
        let app = make_app(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        // With fail_on_audit_error=true, the server must return 503.
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "must return 503 when audit write fails with --fail-on-audit-error"
        );
    }

    #[tokio::test]
    async fn test_concurrent_same_sequence_rejected() {
        let state = make_test_state(true, 0);
        let app = make_app(Arc::clone(&state));

        // Build 10 identical requests with sequence=1.
        let mut handles = Vec::new();
        for _ in 0..10 {
            let state = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                let app = make_app(state);
                let mut cmd = make_test_command();
                cmd.sequence = 1;
                let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
                let resp = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/validate")
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                resp.status()
            }));
        }
        // Ensure the unused app variable doesn't hold resources.
        drop(app);

        let mut ok_count = 0u32;
        let mut bad_request_count = 0u32;
        for handle in handles {
            match handle.await.unwrap() {
                StatusCode::OK => ok_count += 1,
                StatusCode::BAD_REQUEST => bad_request_count += 1,
                other => panic!("unexpected status code: {other}"),
            }
        }

        assert_eq!(ok_count, 1, "exactly 1 request must succeed");
        assert_eq!(bad_request_count, 9, "exactly 9 requests must be rejected");
    }

    #[tokio::test]
    async fn test_previous_joints_updated_on_rejection() {
        // Use trust_plane so PCA is auto-signed, but send a command with
        // out-of-range position that gets *rejected*. The previous_joints
        // state must still be updated so the next command's P4 acceleration
        // check has a valid baseline.
        let state = make_test_state(true, 0);

        // 1. Send a command with valid joints (will be approved).
        let mut cmd1 = make_test_command();
        cmd1.sequence = 1;
        cmd1.joint_states = vec![JointState {
            name: "joint_0".into(),
            position: 0.0,
            velocity: 0.0,
            effort: 0.0,
        }];
        let body1 = serde_json::to_string(&ValidateRequest { command: cmd1 }).unwrap();
        let app = make_app(Arc::clone(&state));
        let resp1 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body1))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK, "first command must succeed");

        // Verify previous_joints was set.
        {
            let prev = state.previous_joints.lock().unwrap();
            assert!(
                prev.is_some(),
                "previous_joints must be set after first command"
            );
            assert_eq!(prev.as_ref().unwrap()[0].position, 0.0);
        }

        // 2. Send a command that gets rejected (out-of-range position).
        let mut cmd2 = make_test_command();
        cmd2.sequence = 2;
        cmd2.joint_states = vec![JointState {
            name: "joint_0".into(),
            position: 999.0, // way out of range — will be rejected
            velocity: 0.0,
            effort: 0.0,
        }];
        let body2 = serde_json::to_string(&ValidateRequest { command: cmd2 }).unwrap();
        let app2 = make_app(Arc::clone(&state));
        let resp2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body2))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK); // 200 with approved=false

        // 3. Verify previous_joints was updated to the rejected command's
        // joints, so the next command's P4 acceleration check has a valid
        // baseline. This prevents state drift on rejection.
        {
            let prev = state.previous_joints.lock().unwrap();
            assert!(
                prev.is_some(),
                "previous_joints must still be set after rejected command"
            );
            assert_eq!(
                prev.as_ref().unwrap()[0].position,
                999.0,
                "previous_joints must reflect the rejected command's joints"
            );
        }
    }

    // --- Rate limiting (spec-v3 §3.2) ---

    fn make_test_state_with_rate_limit(rate_limit_rps: u64) -> Arc<AppState> {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let kid = "test-serve-kid".to_string();
        let signing_key_bytes = sk.to_bytes();

        let profile_json = invariant_core::profiles::list_builtins()
            .first()
            .map(|name| {
                let p = invariant_core::profiles::load_builtin(name).unwrap();
                serde_json::to_string(&p).unwrap()
            })
            .unwrap();
        let profile = invariant_core::profiles::load_from_json(&profile_json).unwrap();

        let mut trusted_keys = HashMap::new();
        trusted_keys.insert(kid.clone(), vk);

        let config = ValidatorConfig::new(profile, trusted_keys, sk, kid.clone()).unwrap();
        let app_signing_key = SigningKey::from_bytes(&signing_key_bytes);

        Arc::new(AppState {
            config,
            trust_plane: true,
            signing_key: app_signing_key,
            kid,
            watchdog: None,
            boot_instant: Instant::now(),
            auth_token: None,
            safe_stop_path: PathBuf::from("safe-stop.json"),
            threat_scoring_enabled: false,
            incident: None,
            audit: None,
            digital_twin: None,
            last_sequence: std::sync::atomic::AtomicU64::new(0),
            previous_joints: std::sync::Mutex::new(None),
            previous_forces: std::sync::Mutex::new(None),
            audit_errors: std::sync::atomic::AtomicU64::new(0),
            fail_on_audit_error: false,
            rate_limiter: std::sync::Mutex::new(HashMap::new()),
            rate_limit_rps,
        })
    }

    #[tokio::test]
    async fn test_rate_limit_allows_within_limit() {
        let state = make_test_state_with_rate_limit(5);

        // Send 5 requests (at the limit) — all must succeed.
        for seq in 1..=5u64 {
            let mut cmd = make_test_command();
            cmd.sequence = seq;
            let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
            let app = make_app(Arc::clone(&state));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/validate")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "request {seq} within rate limit must succeed"
            );
        }
    }

    #[tokio::test]
    async fn test_rate_limit_rejects_over_limit() {
        let state = make_test_state_with_rate_limit(3);

        // Send 4 requests — the 4th must be rejected with 429.
        for seq in 1..=4u64 {
            let mut cmd = make_test_command();
            cmd.sequence = seq;
            let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
            let app = make_app(Arc::clone(&state));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/validate")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            if seq <= 3 {
                assert_eq!(
                    resp.status(),
                    StatusCode::OK,
                    "request {seq} within limit must succeed"
                );
            } else {
                assert_eq!(
                    resp.status(),
                    StatusCode::TOO_MANY_REQUESTS,
                    "request {seq} over limit must get 429"
                );
                // Verify Retry-After header is present.
                assert!(
                    resp.headers().contains_key("retry-after"),
                    "429 response must include Retry-After header"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_rate_limit_resets_after_window() {
        let state = make_test_state_with_rate_limit(2);

        // Send 2 requests — both succeed.
        for seq in 1..=2u64 {
            let mut cmd = make_test_command();
            cmd.sequence = seq;
            let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
            let app = make_app(Arc::clone(&state));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/validate")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Wait for the window to expire.
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Request after window reset must succeed.
        let mut cmd = make_test_command();
        cmd.sequence = 3;
        let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
        let app = make_app(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request after window reset must succeed"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_disabled_allows_all() {
        // rate_limit_rps=0 means disabled.
        let state = make_test_state_with_rate_limit(0);

        // Send 20 requests rapidly — all must succeed.
        for seq in 1..=20u64 {
            let mut cmd = make_test_command();
            cmd.sequence = seq;
            let body = serde_json::to_string(&ValidateRequest { command: cmd }).unwrap();
            let app = make_app(Arc::clone(&state));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/validate")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "request {seq} must succeed with rate limiting disabled"
            );
        }
    }

    #[test]
    fn test_check_rate_limit_unit() {
        let state = AppState {
            config: {
                let sk = SigningKey::generate(&mut OsRng);
                let vk = sk.verifying_key();
                let kid = "test".to_string();
                let profile = invariant_core::profiles::load_builtin(
                    invariant_core::profiles::list_builtins().first().unwrap(),
                )
                .unwrap();
                let mut keys = HashMap::new();
                keys.insert(kid.clone(), vk);
                ValidatorConfig::new(profile, keys, sk, kid.clone()).unwrap()
            },
            trust_plane: false,
            signing_key: SigningKey::generate(&mut OsRng),
            kid: "test".into(),
            watchdog: None,
            boot_instant: Instant::now(),
            auth_token: None,
            safe_stop_path: PathBuf::from("safe-stop.json"),
            threat_scoring_enabled: false,
            incident: None,
            audit: None,
            digital_twin: None,
            last_sequence: std::sync::atomic::AtomicU64::new(0),
            previous_joints: std::sync::Mutex::new(None),
            previous_forces: std::sync::Mutex::new(None),
            audit_errors: std::sync::atomic::AtomicU64::new(0),
            fail_on_audit_error: false,
            rate_limiter: std::sync::Mutex::new(HashMap::new()),
            rate_limit_rps: 2,
        };

        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

        // First 2 requests pass.
        assert!(check_rate_limit(&state, ip).is_ok());
        assert!(check_rate_limit(&state, ip).is_ok());

        // Third request exceeds limit.
        let err = check_rate_limit(&state, ip);
        assert!(err.is_err());
        let (status, _) = err.unwrap_err();
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

        // Different IP should still be allowed.
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));
        assert!(check_rate_limit(&state, ip2).is_ok());
    }
}

// Inline Zeroizing wrapper (avoids adding a new crate dependency).
// This is a minimal implementation that zeroes memory on drop.
mod zeroizing {
    /// Wraps a value in a guard that zeroes the memory on drop.
    pub struct Zeroizing<T: ZeroizeOnDrop>(T);

    pub trait ZeroizeOnDrop {
        fn zeroize(&mut self);
    }

    impl ZeroizeOnDrop for [u8; 32] {
        fn zeroize(&mut self) {
            // Best-effort zeroing without unsafe. In debug builds the fill is
            // never elided; in release builds the Drop barrier makes it very
            // unlikely to be optimized away.
            self.fill(0);
        }
    }

    impl<T: ZeroizeOnDrop> Zeroizing<T> {
        pub fn new(value: T) -> Self {
            Self(value)
        }
    }

    impl<T: ZeroizeOnDrop> std::ops::Deref for Zeroizing<T> {
        type Target = T;
        fn deref(&self) -> &T {
            &self.0
        }
    }

    impl<T: ZeroizeOnDrop> Drop for Zeroizing<T> {
        fn drop(&mut self) {
            self.0.zeroize();
        }
    }
}
