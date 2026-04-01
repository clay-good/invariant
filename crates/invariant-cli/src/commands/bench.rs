//! `invariant bench` — WCET benchmarking for the validation pipeline.
//!
//! Measures worst-case execution time by running the validator in a tight loop
//! and reporting mean, p50, p99, p99.9, and max latency.

use clap::Args;
use std::path::PathBuf;
use std::time::Instant;

use invariant_core::models::command::{Command, CommandAuthority, EndEffectorPosition, JointState};
use invariant_core::validator::ValidatorConfig;

#[derive(Args)]
pub struct BenchArgs {
    /// Path to the robot profile JSON file.
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
    /// Number of validation iterations.
    #[arg(long, default_value = "10000")]
    pub iterations: u64,
    /// Path to the key file (secret key required).
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
}

pub fn run(args: &BenchArgs) -> i32 {
    let profile_json = match std::fs::read_to_string(&args.profile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not read profile: {e}");
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

    let kf = match crate::key_file::load_key_file(&args.key) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (sk, vk, kid) = match crate::key_file::load_signing_key(&kf) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let mut trusted = std::collections::HashMap::new();
    trusted.insert(kid.clone(), vk);

    let config = match ValidatorConfig::new(profile.clone(), trusted, sk, kid) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Build a simple valid command from the profile.
    let joint_states: Vec<JointState> = profile
        .joints
        .iter()
        .map(|j| JointState {
            name: j.name.clone(),
            position: (j.min + j.max) / 2.0,
            velocity: 0.0,
            effort: 0.0,
        })
        .collect();

    let cmd = Command {
        timestamp: chrono::Utc::now(),
        source: "bench".into(),
        sequence: 0,
        joint_states,
        delta_time: profile.max_delta_time * 0.5,
        end_effector_positions: vec![EndEffectorPosition {
            name: "ee".into(),
            position: [0.0, 0.0, 1.0],
        }],
        center_of_mass: None,
        authority: CommandAuthority {
            pca_chain: String::new(),
            required_ops: vec![],
        },
        metadata: std::collections::HashMap::new(),
        locomotion_state: None,
        end_effector_forces: vec![],
        estimated_payload_kg: None,
    };

    let now = chrono::Utc::now();
    let n = args.iterations as usize;
    let mut latencies = Vec::with_capacity(n);

    for _ in 0..n {
        let start = Instant::now();
        let _ = config.validate(&cmd, now, None);
        latencies.push(start.elapsed().as_micros() as f64);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let mean = latencies.iter().sum::<f64>() / n as f64;
    let p50 = latencies[n / 2];
    let p99 = latencies[(n as f64 * 0.99) as usize];
    let p999 = latencies[(n as f64 * 0.999).min((n - 1) as f64) as usize];
    let max = latencies[n - 1];

    println!("Iterations: {n}");
    println!("Mean:   {mean:.0} us");
    println!("P50:    {p50:.0} us");
    println!("P99:    {p99:.0} us");
    println!("P99.9:  {p999:.0} us");
    println!("Max:    {max:.0} us");
    println!("Deadline (1kHz): 1000 us");
    let pct = latencies.iter().filter(|&&l| l <= 1000.0).count() as f64 / n as f64 * 100.0;
    println!("Deadline met: {pct:.2}%");

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_profile_returns_2() {
        let args = BenchArgs {
            profile: PathBuf::from("/nonexistent/profile.json"),
            iterations: 1,
            key: PathBuf::from("/nonexistent/key.json"),
        };
        assert_eq!(run(&args), 2);
    }
}
