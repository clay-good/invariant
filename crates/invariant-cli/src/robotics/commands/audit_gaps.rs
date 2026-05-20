//! `invariant audit-gaps` — detect sequence number gaps in audit logs (Section 10.4).

use clap::Args;
use std::path::PathBuf;

use invariant_robotics::models::audit::SignedAuditEntry;

#[derive(Args)]
pub struct AuditGapsArgs {
    /// Path to the audit log JSONL file.
    #[arg(long, value_name = "LOG_FILE")]
    pub log: PathBuf,
}

pub fn run(args: &AuditGapsArgs) -> i32 {
    let data = match std::fs::read_to_string(&args.log) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: could not read audit log: {e}");
            return 2;
        }
    };

    let mut entries: Vec<SignedAuditEntry> = Vec::new();
    for (i, line) in data.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<SignedAuditEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                eprintln!("error: failed to parse line {}: {e}", i + 1);
                return 2;
            }
        }
    }

    if entries.is_empty() {
        println!("Audit log is empty.");
        return 0;
    }

    // Partition by executor_id (B2 binding, v11 1.1). Spec-v7 §2.7 multi-
    // source model: sequence is monotonic *per executor*; gaps within one
    // executor's stream are errors, gaps across executors are expected.
    // Pre-v11-1.1 entries have empty `executor_id` and all land in the
    // same `""` bucket — behaviour equivalent to the previous global walk.
    use std::collections::BTreeMap;
    let mut per_executor: BTreeMap<
        &str,
        Vec<&invariant_robotics::models::audit::SignedAuditEntry>,
    > = BTreeMap::new();
    for entry in &entries {
        per_executor
            .entry(entry.entry.executor_id.as_str())
            .or_default()
            .push(entry);
    }

    let mut total_gaps: usize = 0;
    let mut report_lines: Vec<String> = Vec::new();
    for (executor, stream) in &per_executor {
        for window in stream.windows(2) {
            let prev_seq = window[0].entry.sequence;
            let curr_seq = window[1].entry.sequence;
            if curr_seq != prev_seq + 1 && curr_seq != prev_seq {
                total_gaps += 1;
                let label = if executor.is_empty() {
                    "<unbound>".to_string()
                } else {
                    (*executor).to_string()
                };
                report_lines.push(format!(
                    "  executor {label}: gap between sequence {prev_seq} and {curr_seq}"
                ));
            }
        }
    }

    println!(
        "Audit log: {} entries examined across {} executor(s)",
        entries.len(),
        per_executor.len()
    );

    if total_gaps == 0 {
        println!("No sequence gaps detected.");
        0
    } else {
        println!("{total_gaps} gap(s) detected:");
        for line in &report_lines {
            println!("{line}");
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_returns_2() {
        let args = AuditGapsArgs {
            log: PathBuf::from("/nonexistent/audit.jsonl"),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn empty_file_returns_0() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "").unwrap();
        let args = AuditGapsArgs { log: path };
        assert_eq!(run(&args), 0);
    }
}
