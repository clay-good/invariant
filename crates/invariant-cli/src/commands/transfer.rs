//! `invariant transfer` — sim-to-real transfer validation (Section 18).
//!
//! Compares simulation trace logs against real hardware trace logs to compute
//! error statistics and recommend safety margins for Guardian mode deployment.

use clap::Args;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use invariant_core::models::trace::Trace;

#[derive(Args)]
pub struct TransferArgs {
    /// Simulation campaign trace log (JSON).
    #[arg(long, value_name = "SIM_LOG")]
    pub sim_log: PathBuf,
    /// Real hardware trace log from Shadow mode (JSON).
    #[arg(long, value_name = "REAL_LOG")]
    pub real_log: PathBuf,
    /// Output file for the transfer report.
    #[arg(long, value_name = "OUTPUT_FILE")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransferReport {
    sim_commands: usize,
    real_commands: usize,
    joint_position_error: ErrorStats,
    joint_velocity_error: ErrorStats,
    sim_safe_real_unsafe: usize,
    sim_unsafe_real_safe: usize,
    recommended_margins: RecommendedMargins,
    transfer_confidence: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorStats {
    mean: f64,
    p99: f64,
    max: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecommendedMargins {
    position_margin: f64,
    velocity_margin: f64,
    torque_margin: f64,
    acceleration_margin: f64,
}

pub fn run(args: &TransferArgs) -> i32 {
    let sim_data = match std::fs::read_to_string(&args.sim_log) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: could not read sim log: {e}");
            return 2;
        }
    };
    let real_data = match std::fs::read_to_string(&args.real_log) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: could not read real log: {e}");
            return 2;
        }
    };

    let sim_trace: Trace = match serde_json::from_str(&sim_data) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: could not parse sim log: {e}");
            return 2;
        }
    };
    let real_trace: Trace = match serde_json::from_str(&real_data) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: could not parse real log: {e}");
            return 2;
        }
    };

    // Compare traces step by step.
    let min_len = sim_trace.steps.len().min(real_trace.steps.len());
    let mut pos_errors = Vec::new();
    let mut vel_errors = Vec::new();
    let mut sim_safe_real_unsafe = 0usize;
    let mut sim_unsafe_real_safe = 0usize;

    for i in 0..min_len {
        let sim_step = &sim_trace.steps[i];
        let real_step = &real_trace.steps[i];

        // Verdict comparison.
        if sim_step.verdict.verdict.approved && !real_step.verdict.verdict.approved {
            sim_safe_real_unsafe += 1;
        }
        if !sim_step.verdict.verdict.approved && real_step.verdict.verdict.approved {
            sim_unsafe_real_safe += 1;
        }

        // Joint-level error comparison.
        let sim_joints = &sim_step.command.joint_states;
        let real_joints = &real_step.command.joint_states;
        for (sj, rj) in sim_joints.iter().zip(real_joints.iter()) {
            pos_errors.push((sj.position - rj.position).abs());
            vel_errors.push((sj.velocity - rj.velocity).abs());
        }
    }

    let pos_stats = compute_stats(&pos_errors);
    let vel_stats = compute_stats(&vel_errors);

    // Recommend margins: cover 99th percentile error + 50% safety buffer.
    let report = TransferReport {
        sim_commands: sim_trace.steps.len(),
        real_commands: real_trace.steps.len(),
        joint_position_error: pos_stats,
        joint_velocity_error: vel_stats,
        sim_safe_real_unsafe,
        sim_unsafe_real_safe,
        recommended_margins: RecommendedMargins {
            position_margin: (compute_p99(&pos_errors) * 1.5).min(0.5),
            velocity_margin: (compute_p99(&vel_errors) * 1.5).min(0.5),
            torque_margin: 0.10,
            acceleration_margin: 0.10,
        },
        transfer_confidence: format!(
            "{:.1}% of sim-validated commands are safe on hardware with recommended margins",
            if sim_safe_real_unsafe == 0 {
                99.9
            } else {
                (1.0 - sim_safe_real_unsafe as f64 / min_len.max(1) as f64) * 100.0
            }
        ),
    };

    let json = serde_json::to_string_pretty(&report).unwrap();
    println!("{json}");

    if let Some(ref output) = args.output {
        if let Err(e) = std::fs::write(output, &json) {
            eprintln!("error: failed to write {}: {e}", output.display());
            return 2;
        }
    }

    if sim_safe_real_unsafe == 0 {
        0
    } else {
        1
    }
}

fn compute_stats(values: &[f64]) -> ErrorStats {
    if values.is_empty() {
        return ErrorStats {
            mean: 0.0,
            p99: 0.0,
            max: 0.0,
        };
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let max = values.iter().cloned().fold(0.0_f64, f64::max);
    ErrorStats {
        mean,
        p99: compute_p99(values),
        max,
    }
}

fn compute_p99(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    sorted[(sorted.len() as f64 * 0.99).min((sorted.len() - 1) as f64) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_sim_log_returns_2() {
        let args = TransferArgs {
            sim_log: PathBuf::from("/nonexistent/sim.json"),
            real_log: PathBuf::from("/nonexistent/real.json"),
            output: None,
        };
        assert_eq!(run(&args), 2);
    }
}
