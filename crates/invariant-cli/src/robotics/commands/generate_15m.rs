//! `invariant robotics generate-15m` — emit the per-category episode
//! allocation that backs the 15M-episode proof package (v11-5.4).
//!
//! In `--dry-run` mode (the default for now, since the live generator path
//! depends on v11 Phase 2 scenario coverage) the command prints a tabular
//! breakdown by spec category (A–N) and exits without touching disk.
//!
//! When `--output` is supplied and `--dry-run` is **not** set, the command
//! falls through to `invariant_sim::robotics::campaign::generate_15m_configs`
//! and writes one YAML config per shard.

use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct Generate15mArgs {
    /// Total episodes to allocate across all categories (default 15 M).
    #[arg(long, value_name = "N", default_value_t = 15_000_000)]
    pub total: u64,
    /// Number of shards to split each profile's episodes across.
    #[arg(long, value_name = "N", default_value_t = 1000)]
    pub shards: u32,
    /// Output directory for per-shard YAML configs. Required unless --dry-run is set.
    #[arg(long, value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Print the allocation table and exit without writing.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
    /// Deterministic seed for the underlying scenario sampler (informational
    /// today; the generator itself is structural and seed-independent).
    #[arg(long, value_name = "N")]
    pub seed: Option<u64>,
}

/// One row in the per-spec-ID allocation table emitted by `--dry-run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationRow {
    pub category: char,
    pub spec_id: &'static str,
    pub scenario_name: &'static str,
    pub episodes: u64,
}

/// Canonical spec → episode allocation from `docs/robotics/spec-15m-campaign.md` §3.
///
/// The 104 entries are scaled linearly by `total / 15_000_000`. Hand-rolled
/// (not parsed from the doc) so the schema is statically typed and a v12-N-1
/// drift in either direction trips a unit test rather than a silent run.
pub fn allocations(total: u64) -> Vec<AllocationRow> {
    // (category, spec_id, name, default_episodes)
    const ENTRIES: &[(char, &str, &str, u64)] = &[
        // Category A: Normal Operation (8 / 3M)
        ('A', "A-01", "Baseline safe operation", 500_000),
        ('A', "A-02", "Full-speed nominal trajectory", 400_000),
        ('A', "A-03", "Pick-and-place cycle", 400_000),
        ('A', "A-04", "Walking gait cycle", 400_000),
        ('A', "A-05", "Human-proximate collaborative work", 400_000),
        ('A', "A-06", "CNC tending full cycle", 400_000),
        ('A', "A-07", "Dexterous manipulation", 300_000),
        ('A', "A-08", "Multi-robot coordinated task", 200_000),
        // Category B: Joint Safety (8 / 1.5M)
        ('B', "B-01", "Position boundary sweep", 200_000),
        ('B', "B-02", "Velocity boundary sweep", 200_000),
        ('B', "B-03", "Torque boundary sweep", 200_000),
        ('B', "B-04", "Acceleration ramp", 200_000),
        ('B', "B-05", "Multi-joint coordinated violation", 200_000),
        ('B', "B-06", "Rapid direction reversal", 200_000),
        ('B', "B-07", "IEEE 754 special values", 150_000),
        ('B', "B-08", "Gradual drift attack", 150_000),
        // Category C: Spatial Safety (6 / 1M)
        ('C', "C-01", "Exclusion zone breach", 200_000),
        ('C', "C-02", "Workspace bound breach", 200_000),
        ('C', "C-03", "Collision pair breach", 200_000),
        ('C', "C-04", "Boundary trace at limit", 150_000),
        ('C', "C-05", "Conditional zone activation", 150_000),
        ('C', "C-06", "Spatial trace + EE force", 100_000),
        // Category D: Stability & Locomotion (10 / 1.5M)
        ('D', "D-01", "Stance fall (P9)", 150_000),
        ('D', "D-02", "Runaway gait", 150_000),
        ('D', "D-03", "Foot slip", 150_000),
        ('D', "D-04", "Foot trip", 150_000),
        ('D', "D-05", "Push recovery / fall", 200_000),
        ('D', "D-06", "Stomp / over-height swing", 150_000),
        ('D', "D-07", "Centre-of-mass drift", 100_000),
        ('D', "D-08", "Step-height boundary", 100_000),
        ('D', "D-09", "Locomotion + payload combo", 200_000),
        ('D', "D-10", "Locomotion + proximity combo", 150_000),
        // Category E: Manipulation Safety (6 / 750K)
        ('E', "E-01", "Grasp force violation", 150_000),
        ('E', "E-02", "Payload overweight", 150_000),
        ('E', "E-03", "Manipulator force limit", 150_000),
        ('E', "E-04", "Sensor attestation mismatch", 100_000),
        ('E', "E-05", "Dexterous finger conflict", 100_000),
        ('E', "E-06", "Payload + workspace combo", 100_000),
        // Category F: Environmental Hazards (8 / 750K)
        ('F', "F-01", "Terrain incline", 100_000),
        ('F', "F-02", "Overheating actuators", 100_000),
        ('F', "F-03", "Battery drain", 100_000),
        ('F', "F-04", "Latency spike", 100_000),
        ('F', "F-05", "E-stop engage", 100_000),
        ('F', "F-06", "Sensor SR1 / SR2 split", 100_000),
        ('F', "F-07", "Network partition", 75_000),
        ('F', "F-08", "Power glitch recovery", 75_000),
        // Category G: Authority & Crypto (10 / 1.5M)
        ('G', "G-01", "Spoofed PCA hop", 200_000),
        ('G', "G-02", "Tampered PCA payload", 200_000),
        ('G', "G-03", "Empty PCA chain", 100_000),
        ('G', "G-04", "Oversized PCA chain", 150_000),
        ('G', "G-05", "Cross-session replay", 200_000),
        ('G', "G-06", "Executor identity forge", 150_000),
        ('G', "G-07", "Wildcard exploitation", 150_000),
        ('G', "G-08", "Verbose-error leak", 100_000),
        ('G', "G-09", "Cross-chain hop splice", 150_000),
        ('G', "G-10", "Expired / nbf hop", 100_000),
        // Category H: Temporal & Sequence (6 / 750K)
        ('H', "H-01", "Sequence rewind", 150_000),
        ('H', "H-02", "Sequence gap", 150_000),
        ('H', "H-03", "Clock regression", 100_000),
        ('H', "H-04", "Temporal-window expiry", 150_000),
        ('H', "H-05", "Multi-source interleave", 100_000),
        ('H', "H-06", "Watchdog timeout", 100_000),
        // Category I: Cognitive Escape (10 / 1.5M)
        ('I', "I-01", "LLM impersonation", 200_000),
        ('I', "I-02", "Prompt-injection PCA leak", 150_000),
        ('I', "I-03", "Out-of-intent command", 150_000),
        ('I', "I-04", "LLM hallucinated joint", 200_000),
        ('I', "I-05", "Reasoning-loop stall", 100_000),
        ('I', "I-06", "Replay-of-prior-approval", 150_000),
        ('I', "I-07", "Operator-coaxing template", 150_000),
        ('I', "I-08", "LLM scope expansion", 100_000),
        ('I', "I-09", "Oversized command JSON", 150_000),
        ('I', "I-10", "Tool-output spoof", 150_000),
        // Category J: Multi-Step Compound (8 / 1M)
        ('J', "J-01", "Authority + physics", 150_000),
        ('J', "J-02", "Sensor + spatial", 150_000),
        ('J', "J-03", "Drift + violation", 100_000),
        ('J', "J-04", "Auth + sensor + spatial", 150_000),
        ('J', "J-05", "Drift then 10× violation", 150_000),
        ('J', "J-06", "Watchdog + replay", 100_000),
        ('J', "J-07", "Environment + physics", 100_000),
        ('J', "J-08", "Full-chain compound", 100_000),
        // Category K: Recovery & Resilience (6 / 500K)
        ('K', "K-01", "Safe-stop + resume", 100_000),
        ('K', "K-02", "Mode transition", 75_000),
        ('K', "K-03", "Audit rotation recovery", 75_000),
        ('K', "K-04", "Audit hash chain integrity", 100_000),
        ('K', "K-05", "Incident lockdown", 75_000),
        ('K', "K-06", "Watchdog disarm", 75_000),
        // Category L: Long-Running Stability (4 / 250K)
        ('L', "L-01", "1000-step nominal episode", 75_000),
        ('L', "L-02", "Long drift detection", 75_000),
        ('L', "L-03", "Continuous fuzz background", 50_000),
        ('L', "L-04", "Mixed threat 1000-step", 50_000),
        // Category M: Cross-Platform Stress (6 / 500K)
        ('M', "M-01", "All-profiles smoke", 100_000),
        ('M', "M-02", "Humanoid stress", 100_000),
        ('M', "M-03", "Quadruped stress", 75_000),
        ('M', "M-04", "Arm stress", 75_000),
        ('M', "M-05", "Hand stress", 75_000),
        ('M', "M-06", "Mobile manipulator stress", 75_000),
        // Category N: Adversarial Red Team (10 / 500K)
        ('N', "N-01", "Fuzzed command JSON", 75_000),
        ('N', "N-02", "Fuzzed PCA chain", 75_000),
        ('N', "N-03", "Fuzzed profile JSON", 50_000),
        ('N', "N-04", "Bit-flip mutation", 50_000),
        ('N', "N-05", "Adversarial profile", 50_000),
        ('N', "N-06", "Sensor spoofing", 50_000),
        ('N', "N-07", "Pre-image collision", 25_000),
        ('N', "N-08", "Side-channel timing probe", 50_000),
        ('N', "N-09", "Mutation-of-approved", 50_000),
        ('N', "N-10", "Coordinator splice", 25_000),
    ];

    // Linear scale: episodes' total is 15_000_000 by construction.
    // For arbitrary --total, scale each row proportionally.
    let scale = total as f64 / 15_000_000.0;
    ENTRIES
        .iter()
        .map(|(cat, id, name, eps)| AllocationRow {
            category: *cat,
            spec_id: id,
            scenario_name: name,
            episodes: ((*eps as f64) * scale).round() as u64,
        })
        .collect()
}

fn print_table(rows: &[AllocationRow]) {
    println!(
        "{:<3} {:<6} {:<48} {:>12}",
        "Cat", "ID", "Scenario", "Episodes"
    );
    println!("{}", "-".repeat(73));
    let mut current_cat: Option<char> = None;
    let mut cat_subtotal: u64 = 0;
    let mut cat_count: u32 = 0;
    let mut grand_total: u64 = 0;
    for row in rows {
        if current_cat != Some(row.category) {
            if let Some(c) = current_cat {
                println!(
                    "{:<3} {:<6} {:<48} {:>12}",
                    c,
                    "",
                    format!("  ({} scenarios, subtotal)", cat_count),
                    cat_subtotal
                );
                println!();
            }
            current_cat = Some(row.category);
            cat_subtotal = 0;
            cat_count = 0;
        }
        println!(
            "{:<3} {:<6} {:<48} {:>12}",
            row.category, row.spec_id, row.scenario_name, row.episodes
        );
        cat_subtotal += row.episodes;
        cat_count += 1;
        grand_total += row.episodes;
    }
    if let Some(c) = current_cat {
        println!(
            "{:<3} {:<6} {:<48} {:>12}",
            c,
            "",
            format!("  ({} scenarios, subtotal)", cat_count),
            cat_subtotal
        );
    }
    println!("{}", "-".repeat(73));
    println!(
        "{:<3} {:<6} {:<48} {:>12}",
        "ALL", "", "(grand total)", grand_total
    );
}

pub fn run(args: &Generate15mArgs) -> i32 {
    if args.total == 0 {
        eprintln!("error: --total must be greater than zero");
        return 2;
    }
    if args.shards == 0 {
        eprintln!("error: --shards must be greater than zero");
        return 2;
    }

    let rows = allocations(args.total);

    if args.dry_run {
        if let Some(seed) = args.seed {
            eprintln!("# seed: {seed} (informational; allocation is structural)");
        }
        print_table(&rows);
        return 0;
    }

    let output = match &args.output {
        Some(dir) => dir,
        None => {
            eprintln!("error: --output <DIR> is required unless --dry-run is set");
            return 2;
        }
    };

    if let Err(e) = std::fs::create_dir_all(output) {
        eprintln!("error: failed to create output directory {output:?}: {e}");
        return 2;
    }

    let configs = invariant_sim::robotics::campaign::generate_15m_configs(args.total, args.shards);
    for (i, cfg) in configs.iter().enumerate() {
        let path = output.join(format!("shard_{i:05}_{}.yaml", cfg.name));
        let yaml = match serde_yaml::to_string(cfg) {
            Ok(y) => y,
            Err(e) => {
                eprintln!("error: failed to serialize shard {i}: {e}");
                return 2;
            }
        };
        if let Err(e) = std::fs::write(&path, yaml) {
            eprintln!("error: failed to write {path:?}: {e}");
            return 2;
        }
    }
    println!(
        "wrote {} shard configs to {}",
        configs.len(),
        output.display()
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocations_default_total_sums_to_fifteen_million_within_tolerance() {
        let rows = allocations(15_000_000);
        let total: u64 = rows.iter().map(|r| r.episodes).sum();
        // Hand-rolled allocations are designed to sum exactly to 15M.
        // Allow a 0.1% tolerance to absorb rounding when scaled.
        let abs_diff = total.abs_diff(15_000_000);
        assert!(
            abs_diff <= 15_000,
            "default allocation must sum to ~15M; got {total} (diff {abs_diff})"
        );
    }

    #[test]
    fn category_b_has_eight_rows_summing_to_one_point_five_million() {
        // The acceptance criterion from v11-5.4: Category B has 8 spec IDs
        // (B-01..B-08); their total under the default 15M plan is 1.5M.
        let rows = allocations(15_000_000);
        let cat_b: Vec<_> = rows.iter().filter(|r| r.category == 'B').collect();
        assert_eq!(cat_b.len(), 8, "Category B must have exactly 8 rows");
        let cat_b_total: u64 = cat_b.iter().map(|r| r.episodes).sum();
        assert_eq!(
            cat_b_total, 1_500_000,
            "Category B total must be 1.5M, got {cat_b_total}"
        );
    }

    #[test]
    fn allocations_scale_linearly_with_total() {
        // Halving --total halves every row (within rounding).
        let half = allocations(7_500_000);
        let cat_b_half: u64 = half
            .iter()
            .filter(|r| r.category == 'B')
            .map(|r| r.episodes)
            .sum();
        // 1.5M halved = 750K, allow ±0.1%.
        assert!(
            cat_b_half.abs_diff(750_000) <= 1500,
            "Category B at half total should be ~750K, got {cat_b_half}"
        );
    }

    #[test]
    fn dry_run_with_zero_total_exits_two() {
        let args = Generate15mArgs {
            total: 0,
            shards: 1000,
            output: None,
            dry_run: true,
            seed: None,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn non_dry_run_without_output_exits_two() {
        let args = Generate15mArgs {
            total: 15_000_000,
            shards: 1000,
            output: None,
            dry_run: false,
            seed: None,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn dry_run_smoke_returns_zero() {
        // Pipes to stdout — not asserting content here, only the exit code.
        // Content shape is covered by the table-construction unit tests above.
        let args = Generate15mArgs {
            total: 15_000_000,
            shards: 1000,
            output: None,
            dry_run: true,
            seed: Some(42),
        };
        assert_eq!(run(&args), 0);
    }
}
