//! `invariant robotics fleet status` — render a coordinator [`FleetSnapshot`]
//! into a human- or machine-readable summary. v11 5.5.
//!
//! The live monitor process (long-running, typically inside `invariant
//! robotics serve` or an external orchestrator) is the source of truth for
//! per-robot state. This subcommand operates **off-line** against a snapshot
//! JSON that the monitor exports — the spec calls this out explicitly: "do
//! not duplicate state". The snapshot type lives in `invariant-coordinator`
//! ([`FleetSnapshot`]) and is sorted by `robot_id` so the JSON bytes are
//! reproducible across runs with the same inputs.
//!
//! Output formats:
//! - `--format text` (default): one-line-per-robot summary plus a separation-
//!   alerts section listing any end-effector pair whose pairwise distance
//!   falls below the snapshot's configured `min_separation_m`. Stable enough
//!   to snapshot-test.
//! - `--format json`: emits an [`FleetStatusReport`] structure with the same
//!   information plus pairwise distances; intended for piping into other
//!   tooling.
//!
//! Exit codes:
//! - `0` — snapshot loaded and rendered; no separation violations.
//! - `1` — snapshot loaded and rendered; at least one violation present
//!   (so operators can wire `fleet status` into `set -e` health checks).
//! - `2` — usage error (missing file, bad JSON, …).

use clap::{Args, Subcommand};
use invariant_coordinator::{FleetSnapshot, RobotState};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Args)]
pub struct FleetArgs {
    #[command(subcommand)]
    cmd: FleetSubcommand,
}

#[derive(Subcommand)]
enum FleetSubcommand {
    /// Render a coordinator state snapshot.
    Status(StatusArgs),
}

#[derive(Args)]
pub struct StatusArgs {
    /// Path to a [`FleetSnapshot`] JSON file (as written by
    /// `CoordinationMonitor::snapshot` + `serde_json::to_writer`).
    #[arg(long, value_name = "PATH")]
    pub state: PathBuf,

    /// Output format. `text` is the default human-readable rendering;
    /// `json` emits the structured [`FleetStatusReport`] for piping.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Suppress the per-robot table and print only the alert lines.
    #[arg(long, default_value_t = false)]
    pub alerts_only: bool,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    /// Stable human-readable rendering (snapshot-friendly).
    Text,
    /// Machine-readable [`FleetStatusReport`] JSON.
    Json,
}

/// Machine-readable status output. Stable shape so downstream consumers
/// can pin against it; bumps require a follow-up note in `docs/error-
/// stability.md` (or a future fleet-stability catalog).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStatusReport {
    /// `as_of` from the snapshot.
    pub as_of: String,
    /// Number of registered robots.
    pub robot_count: usize,
    /// Number of robots whose `active` flag is true.
    pub active_count: usize,
    /// Configured minimum separation in metres.
    pub min_separation_m: f64,
    /// Configured stale-state timeout in milliseconds.
    pub stale_timeout_ms: u64,
    /// Per-robot summaries (sorted by `robot_id`).
    pub robots: Vec<RobotSummary>,
    /// Pairs whose pairwise EE distance is below the configured minimum.
    /// Empty list means the snapshot is geometrically safe at this instant.
    pub alerts: Vec<SeparationAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotSummary {
    pub robot_id: String,
    pub active: bool,
    pub end_effector_count: usize,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeparationAlert {
    pub robot_a: String,
    pub robot_b: String,
    pub ee_a: String,
    pub ee_b: String,
    pub distance_m: f64,
    pub min_separation_m: f64,
}

pub fn run(args: &FleetArgs) -> i32 {
    match &args.cmd {
        FleetSubcommand::Status(s) => run_status(s),
    }
}

fn run_status(args: &StatusArgs) -> i32 {
    let bytes = match std::fs::read(&args.state) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: failed to read --state {}: {e}", args.state.display());
            return 2;
        }
    };
    let snapshot: FleetSnapshot = match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to parse FleetSnapshot JSON: {e}");
            return 2;
        }
    };

    let report = build_report(&snapshot);

    match args.format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)
                .expect("FleetStatusReport always serializes");
            println!("{json}");
        }
        OutputFormat::Text => {
            print_text_report(&report, args.alerts_only);
        }
    }

    if report.alerts.is_empty() {
        0
    } else {
        1
    }
}

/// Pure helper: project a [`FleetSnapshot`] into a stable
/// [`FleetStatusReport`]. Exposed at `pub(crate)` so the integration
/// tests can hit it without a subprocess hop.
pub(crate) fn build_report(snapshot: &FleetSnapshot) -> FleetStatusReport {
    let robots: Vec<RobotSummary> = snapshot
        .states
        .iter()
        .map(|s| RobotSummary {
            robot_id: s.robot_id.clone(),
            active: s.active,
            end_effector_count: s.end_effector_positions.len(),
            timestamp: s.timestamp.to_rfc3339(),
        })
        .collect();

    let active_count = snapshot.states.iter().filter(|s| s.active).count();
    let alerts = compute_separation_alerts(&snapshot.states, snapshot.config.min_separation_m);

    FleetStatusReport {
        as_of: snapshot.as_of.to_rfc3339(),
        robot_count: snapshot.states.len(),
        active_count,
        min_separation_m: snapshot.config.min_separation_m,
        stale_timeout_ms: snapshot.config.stale_timeout_ms,
        robots,
        alerts,
    }
}

fn compute_separation_alerts(states: &[RobotState], min_sep: f64) -> Vec<SeparationAlert> {
    let mut out: Vec<SeparationAlert> = Vec::new();
    for i in 0..states.len() {
        for j in (i + 1)..states.len() {
            let (a, b) = (&states[i], &states[j]);
            // Active-vs-active is the conservative interpretation; if either
            // is inactive we still report (an inactive robot at an unsafe
            // distance is a setup issue worth surfacing).
            for ee_a in &a.end_effector_positions {
                for ee_b in &b.end_effector_positions {
                    let d = euclid(&ee_a.position, &ee_b.position);
                    if d < min_sep {
                        out.push(SeparationAlert {
                            robot_a: a.robot_id.clone(),
                            robot_b: b.robot_id.clone(),
                            ee_a: ee_a.name.clone(),
                            ee_b: ee_b.name.clone(),
                            distance_m: d,
                            min_separation_m: min_sep,
                        });
                    }
                }
            }
        }
    }
    // Deterministic order so snapshot tests are stable.
    out.sort_by(|x, y| {
        x.robot_a
            .cmp(&y.robot_a)
            .then(x.robot_b.cmp(&y.robot_b))
            .then(x.ee_a.cmp(&y.ee_a))
            .then(x.ee_b.cmp(&y.ee_b))
    });
    out
}

fn euclid(a: &[f64; 3], b: &[f64; 3]) -> f64 {
    let dx = a[0] - b[0];
    let dy = a[1] - b[1];
    let dz = a[2] - b[2];
    (dx * dx + dy * dy + dz * dz).sqrt()
}

fn print_text_report(report: &FleetStatusReport, alerts_only: bool) {
    if !alerts_only {
        println!("Fleet status @ {}", report.as_of);
        println!(
            "  robots: {} ({} active), min_separation: {:.3}m, stale_timeout: {}ms",
            report.robot_count, report.active_count, report.min_separation_m, report.stale_timeout_ms
        );
        println!();
        println!("  Robot                Status   EE   Last update");
        println!("  -------------------- -------- ---- -------------------------");
        for r in &report.robots {
            let status = if r.active { "active" } else { "idle" };
            println!(
                "  {:<20} {:<8} {:>4} {}",
                r.robot_id, status, r.end_effector_count, r.timestamp
            );
        }
        println!();
    }

    if report.alerts.is_empty() {
        println!("Alerts: none (all pairwise separations >= {:.3}m).", report.min_separation_m);
    } else {
        println!(
            "Alerts: {} separation violation(s) (threshold {:.3}m):",
            report.alerts.len(),
            report.min_separation_m
        );
        for a in &report.alerts {
            println!(
                "  {} ({}) <-> {} ({}): {:.3}m < {:.3}m",
                a.robot_a, a.ee_a, a.robot_b, a.ee_b, a.distance_m, a.min_separation_m
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use invariant_coordinator::monitor::{CoordinationConfig, EndEffectorState};

    fn snapshot_with(states: Vec<RobotState>, min_sep: f64) -> FleetSnapshot {
        FleetSnapshot {
            config: CoordinationConfig {
                min_separation_m: min_sep,
                stale_timeout_ms: 200,
                stale_policy: invariant_coordinator::StaleRobotPolicy::TreatAsObstacle,
                max_robots: 32,
            },
            as_of: Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
            states,
        }
    }

    fn robot(id: &str, ee: Vec<(&str, [f64; 3])>, active: bool) -> RobotState {
        RobotState {
            robot_id: id.into(),
            timestamp: Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
            end_effector_positions: ee
                .into_iter()
                .map(|(n, p)| EndEffectorState {
                    name: n.into(),
                    position: p,
                })
                .collect(),
            active,
        }
    }

    #[test]
    fn report_counts_robots_and_active_state() {
        let snap = snapshot_with(
            vec![
                robot("a", vec![("tcp", [0.0, 0.0, 0.0])], true),
                robot("b", vec![("tcp", [5.0, 0.0, 0.0])], false),
                robot("c", vec![("tcp", [10.0, 0.0, 0.0])], true),
            ],
            0.5,
        );
        let rep = build_report(&snap);
        assert_eq!(rep.robot_count, 3);
        assert_eq!(rep.active_count, 2);
        assert!(rep.alerts.is_empty(), "well-separated fleet must have no alerts");
    }

    #[test]
    fn report_emits_separation_alert_when_pair_below_threshold() {
        let snap = snapshot_with(
            vec![
                robot("a", vec![("tcp", [0.0, 0.0, 0.0])], true),
                // 0.2 m away — below the 0.5 m threshold.
                robot("b", vec![("tcp", [0.2, 0.0, 0.0])], true),
            ],
            0.5,
        );
        let rep = build_report(&snap);
        assert_eq!(rep.alerts.len(), 1);
        let a = &rep.alerts[0];
        assert_eq!(a.robot_a, "a");
        assert_eq!(a.robot_b, "b");
        assert!((a.distance_m - 0.2).abs() < 1e-9);
    }

    #[test]
    fn report_enumerates_every_ee_pair_for_multi_ee_robots() {
        // Robot a has 2 EEs, robot b has 2 EEs → 4 pairs total; all should
        // be inside the 0.1 m threshold so every pair shows up.
        let snap = snapshot_with(
            vec![
                robot(
                    "a",
                    vec![("l", [0.0, 0.0, 0.0]), ("r", [0.01, 0.0, 0.0])],
                    true,
                ),
                robot(
                    "b",
                    vec![("l", [0.05, 0.0, 0.0]), ("r", [0.06, 0.0, 0.0])],
                    true,
                ),
            ],
            0.1,
        );
        let rep = build_report(&snap);
        assert_eq!(rep.alerts.len(), 4);
    }

    #[test]
    fn run_status_returns_exit_1_on_alerts_and_0_on_clean() {
        let temp = tempfile::tempdir().unwrap();
        let clean = snapshot_with(
            vec![
                robot("a", vec![("tcp", [0.0, 0.0, 0.0])], true),
                robot("b", vec![("tcp", [5.0, 0.0, 0.0])], true),
            ],
            0.5,
        );
        let dirty = snapshot_with(
            vec![
                robot("a", vec![("tcp", [0.0, 0.0, 0.0])], true),
                robot("b", vec![("tcp", [0.2, 0.0, 0.0])], true),
            ],
            0.5,
        );
        let clean_path = temp.path().join("clean.json");
        let dirty_path = temp.path().join("dirty.json");
        std::fs::write(&clean_path, serde_json::to_vec_pretty(&clean).unwrap()).unwrap();
        std::fs::write(&dirty_path, serde_json::to_vec_pretty(&dirty).unwrap()).unwrap();

        assert_eq!(
            run_status(&StatusArgs {
                state: clean_path,
                format: OutputFormat::Json,
                alerts_only: false,
            }),
            0
        );
        assert_eq!(
            run_status(&StatusArgs {
                state: dirty_path,
                format: OutputFormat::Text,
                alerts_only: true,
            }),
            1
        );
    }

    #[test]
    fn run_status_returns_exit_2_on_missing_or_malformed_state() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("nope.json");
        assert_eq!(
            run_status(&StatusArgs {
                state: missing,
                format: OutputFormat::Text,
                alerts_only: false,
            }),
            2
        );
        let bad = temp.path().join("bad.json");
        std::fs::write(&bad, b"{not-json}").unwrap();
        assert_eq!(
            run_status(&StatusArgs {
                state: bad,
                format: OutputFormat::Text,
                alerts_only: false,
            }),
            2
        );
    }
}
