/// Benchmark: measures validation latency, throughput, and runs a dry campaign.
///
/// Run with: cargo run --release --example benchmark -p invariant-sim
use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use invariant_core::authority::crypto::{generate_keypair, sign_pca};
use invariant_core::models::authority::{Operation, Pca};
use invariant_core::models::command::{Command, CommandAuthority, JointState};
use invariant_core::models::profile::RobotProfile;
use invariant_core::profiles;
use invariant_core::validator::ValidatorConfig;

use invariant_robotics_sim::campaign::{CampaignConfig, ScenarioConfig, SuccessCriteria};
use invariant_robotics_sim::isaac::dry_run::run_dry_campaign;

fn make_chain(sk: &SigningKey, kid: &str, ops: &[&str]) -> String {
    let op_set: BTreeSet<Operation> = ops.iter().map(|s| Operation::new(*s).unwrap()).collect();
    let pca = Pca {
        p_0: "bench".into(),
        ops: op_set,
        kid: kid.into(),
        exp: None,
        nbf: None,
    };
    let signed = sign_pca(&pca, sk).unwrap();
    let json = serde_json::to_vec(&vec![signed]).unwrap();
    STANDARD.encode(&json)
}

fn make_valid_command(profile: &RobotProfile, chain: &str, seq: u64) -> Command {
    let joints: Vec<JointState> = profile
        .joints
        .iter()
        .map(|j| {
            let mid = (j.min + j.max) / 2.0;
            JointState {
                name: j.name.clone(),
                position: mid,
                velocity: 0.0,
                effort: 0.0,
            }
        })
        .collect();

    let ops = vec![Operation::new("actuate:*").unwrap()];

    Command {
        timestamp: Utc::now(),
        source: "bench".into(),
        sequence: seq,
        joint_states: joints,
        delta_time: profile.max_delta_time * 0.5,
        end_effector_positions: vec![],
        center_of_mass: None,
        authority: CommandAuthority {
            pca_chain: chain.to_string(),
            required_ops: ops,
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

fn benchmark_latency() {
    eprintln!("=== Validation Latency Benchmark ===\n");

    for profile_name in profiles::list_builtins() {
        let profile = profiles::load_builtin(profile_name).unwrap();
        let sk = generate_keypair(&mut OsRng);
        let vk = sk.verifying_key();
        let sign_sk = generate_keypair(&mut OsRng);
        let kid = "bench-key";

        let mut trusted = HashMap::new();
        trusted.insert(kid.to_string(), vk);

        let config =
            ValidatorConfig::new(profile.clone(), trusted, sign_sk, "bench-signer".into()).unwrap();

        let chain = make_chain(&sk, kid, &["actuate:*"]);

        // Warmup — pre-build a template and clone it to avoid re-allocating
        // joint state strings on every iteration.
        let warmup_template = make_valid_command(&profile, &chain, 0);
        for i in 0..100 {
            let mut cmd = warmup_template.clone();
            cmd.sequence = i;
            let _ = config.validate(&cmd, Utc::now(), None);
        }

        // Benchmark
        let n = 100_000;
        let mut latencies = Vec::with_capacity(n);

        // Pre-build a command template; only the sequence field varies per
        // iteration so we clone the template and stamp the sequence in the
        // loop instead of re-allocating all joint state strings each time.
        let cmd_template = make_valid_command(&profile, &chain, 0);

        for i in 0..n {
            let mut cmd = cmd_template.clone();
            cmd.sequence = i as u64;
            let now = Utc::now();
            let start = Instant::now();
            let _ = config.validate(&cmd, now, None);
            latencies.push(start.elapsed());
        }

        latencies.sort();

        let p50 = latencies[n / 2];
        let p99 = latencies[n * 99 / 100];
        let p999 = latencies[n * 999 / 1000];
        let total: std::time::Duration = latencies.iter().sum();
        let mean = total / n as u32;
        let throughput = n as f64 / total.as_secs_f64();

        eprintln!("Profile: {profile_name} ({} joints)", profile.joints.len());
        eprintln!("  Commands: {n}");
        eprintln!("  Mean:     {:.1}us", mean.as_nanos() as f64 / 1000.0);
        eprintln!("  p50:      {:.1}us", p50.as_nanos() as f64 / 1000.0);
        eprintln!("  p99:      {:.1}us", p99.as_nanos() as f64 / 1000.0);
        eprintln!("  p999:     {:.1}us", p999.as_nanos() as f64 / 1000.0);
        eprintln!("  Throughput: {throughput:.0} cmd/sec");
        eprintln!();
    }
}

fn benchmark_campaign() {
    eprintln!("=== Dry-Run Campaign (10K commands across 4 profiles) ===\n");

    for profile_name in profiles::list_builtins() {
        let config = CampaignConfig {
            name: format!("bench-{profile_name}"),
            profile: profile_name.to_string(),
            environments: 4,
            episodes_per_env: 5,
            steps_per_episode: 500,
            scenarios: vec![
                ScenarioConfig {
                    scenario_type: "baseline".into(),
                    weight: 0.3,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "aggressive".into(),
                    weight: 0.2,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "exclusion_zone".into(),
                    weight: 0.1,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "authority_escalation".into(),
                    weight: 0.1,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "chain_forgery".into(),
                    weight: 0.1,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "prompt_injection".into(),
                    weight: 0.1,
                    injections: vec![],
                },
                ScenarioConfig {
                    scenario_type: "multi_agent_handoff".into(),
                    weight: 0.1,
                    injections: vec![],
                },
            ],
            success_criteria: SuccessCriteria::default(),
        };

        let start = Instant::now();
        let report = run_dry_campaign(&config, None).unwrap();
        let elapsed = start.elapsed();

        eprintln!("Profile: {profile_name}");
        eprintln!("  Total commands:      {}", report.total_commands);
        eprintln!("  Approved:            {}", report.total_approved);
        eprintln!("  Rejected:            {}", report.total_rejected);
        eprintln!(
            "  Approval rate:       {:.1}%",
            report.approval_rate * 100.0
        );
        eprintln!("  Violation escapes:   {}", report.violation_escape_count);
        eprintln!("  False rejections:    {}", report.false_rejection_count);
        eprintln!("  Criteria met:        {}", report.criteria_met);
        eprintln!("  Elapsed:             {elapsed:.2?}");
        eprintln!(
            "  Confidence (95% UB): {:.6}%",
            report.confidence.upper_bound_95 * 100.0
        );
        eprintln!();

        // Per-scenario breakdown
        for (scenario, stats) in &report.per_scenario {
            eprintln!(
                "  Scenario '{scenario}': {} total, {} approved, {} rejected",
                stats.total, stats.approved, stats.rejected
            );
        }
        eprintln!();
    }
}

fn main() {
    benchmark_latency();
    benchmark_campaign();

    // Memory footprint
    eprintln!("=== Memory & Binary Info ===\n");
    eprintln!("  Profiles embedded: {}", profiles::list_builtins().len());
    eprintln!("  Profile names: {:?}", profiles::list_builtins());
}
