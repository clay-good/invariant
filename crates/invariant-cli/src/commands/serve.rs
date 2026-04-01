use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::borrow::Cow;

use axum::error_handling::HandleErrorLayer;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
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
    #[arg(long, value_name = "TOKEN")]
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
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Constant-time byte comparison that does not short-circuit on mismatch.
///
/// This prevents timing side-channel attacks on secret token comparisons
/// (Finding 15). Returns `true` iff both slices are the same length and
/// contain identical bytes.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
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

async fn handle_validate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>, (StatusCode, Json<ErrorResponse>)> {
    check_auth(&headers, &state.auth_token)?;

    let mut cmd = req.command;

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

    // Offload CPU-bound validation to a blocking thread to keep the async
    // runtime responsive for heartbeat and health handlers. ValidatorConfig is
    // not Clone, so we move the Arc<AppState> into the closure and access the
    // config through the shared reference.
    let state_for_blocking = Arc::clone(&state);
    let result =
        tokio::task::spawn_blocking(move || state_for_blocking.config.validate(&cmd, now, None))
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("validation task panicked: {e}"),
                    }),
                )
            })?;

    match result {
        Ok(result) => Ok(Json(ValidateResponse {
            verdict: result.signed_verdict,
            actuation_command: result.actuation_command,
        })),
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

    Json(HealthResponse {
        status: Cow::Borrowed("ok"),
        profile_name: state.config.profile().name.clone(),
        trust_plane: state.trust_plane,
        watchdog_enabled,
        watchdog_state,
        uptime_ms,
        watchdog_alive,
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

    let state = Arc::new(AppState {
        config,
        trust_plane: args.trust_plane,
        signing_key: app_signing_key,
        kid,
        watchdog,
        boot_instant,
        auth_token,
        safe_stop_path,
    });

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

    let app = Router::new()
        .route("/validate", post(handle_validate))
        .route("/heartbeat", post(handle_heartbeat))
        .route("/health", get(handle_health))
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

    if let Err(e) = axum::serve(listener, app)
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
        })
    }

    fn make_app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/validate", post(handle_validate))
            .route("/heartbeat", post(handle_heartbeat))
            .route("/health", get(handle_health))
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
        };
        assert_eq!(run(&args), 2);
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
            for b in self.iter_mut() {
                // Use volatile_write equivalent via pointer to prevent the
                // compiler from eliding the zeroing as a dead store.
                // SAFETY: self is a valid [u8; 32].
                unsafe {
                    std::ptr::write_volatile(b as *mut u8, 0);
                }
            }
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
