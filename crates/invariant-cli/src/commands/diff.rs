use clap::Args;
use std::path::PathBuf;

use invariant_core::models::trace::Trace;
use invariant_eval::differ::diff_traces;

/// Compare two trace files step-by-step and report divergence points (P2-15).
#[derive(Args)]
pub struct DiffArgs {
    /// First trace file.
    #[arg(value_name = "TRACE_A")]
    pub trace_a: PathBuf,
    /// Second trace file.
    #[arg(value_name = "TRACE_B")]
    pub trace_b: PathBuf,
}

pub fn run(args: &DiffArgs) -> i32 {
    let data_a = match std::fs::read_to_string(&args.trace_a) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: could not read {}: {}", args.trace_a.display(), e);
            return 2;
        }
    };

    let data_b = match std::fs::read_to_string(&args.trace_b) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: could not read {}: {}", args.trace_b.display(), e);
            return 2;
        }
    };

    let baseline: Trace = match serde_json::from_str(&data_a) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: could not parse {}: {}", args.trace_a.display(), e);
            return 2;
        }
    };

    let candidate: Trace = match serde_json::from_str(&data_b) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: could not parse {}: {}", args.trace_b.display(), e);
            return 2;
        }
    };

    let diffs = diff_traces(&baseline, &candidate);

    if diffs.is_empty() {
        println!("no divergences found");
        return 0;
    }

    for d in &diffs {
        println!(
            "step {}: {} baseline={} candidate={}",
            d.step, d.field, d.baseline, d.candidate
        );
    }

    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // A minimal Trace JSON with one all-approved step.
    const MINIMAL_TRACE_JSON: &str = r#"{
        "id": "trace-001",
        "episode": 0,
        "environment_id": 0,
        "scenario": "test",
        "profile_name": "test_robot",
        "steps": [
            {
                "step": 0,
                "timestamp": "2026-01-01T00:00:00Z",
                "command": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "source": "test",
                    "sequence": 0,
                    "joint_states": [
                        {"name": "j1", "position": 0.0, "velocity": 0.0, "effort": 0.0}
                    ],
                    "delta_time": 0.01,
                    "authority": {"pca_chain": "", "required_ops": []}
                },
                "verdict": {
                    "approved": true,
                    "command_hash": "sha256:abc",
                    "command_sequence": 0,
                    "timestamp": "2026-01-01T00:00:00Z",
                    "checks": [
                        {"name": "authority",           "category": "authority", "passed": true, "details": "ok"},
                        {"name": "joint_limits",         "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "velocity_limits",      "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "torque_limits",        "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "acceleration_limits",  "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "workspace_bounds",     "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "exclusion_zones",      "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "self_collision",       "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "delta_time",           "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "stability",            "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "proximity_velocity",   "category": "physics",   "passed": true, "details": "ok"}
                    ],
                    "profile_name": "test_robot",
                    "profile_hash": "sha256:def",
                    "authority_summary": {
                        "origin_principal": "alice",
                        "hop_count": 1,
                        "operations_granted": ["actuate:*"],
                        "operations_required": ["actuate:j1"]
                    },
                    "verdict_signature": "AAAA",
                    "signer_kid": "test-kid"
                }
            }
        ],
        "metadata": {}
    }"#;

    // Same as MINIMAL_TRACE_JSON but with approved=false on step 0.
    const REJECTED_TRACE_JSON: &str = r#"{
        "id": "trace-002",
        "episode": 0,
        "environment_id": 0,
        "scenario": "test",
        "profile_name": "test_robot",
        "steps": [
            {
                "step": 0,
                "timestamp": "2026-01-01T00:00:00Z",
                "command": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "source": "test",
                    "sequence": 0,
                    "joint_states": [
                        {"name": "j1", "position": 0.0, "velocity": 0.0, "effort": 0.0}
                    ],
                    "delta_time": 0.01,
                    "authority": {"pca_chain": "", "required_ops": []}
                },
                "verdict": {
                    "approved": false,
                    "command_hash": "sha256:abc",
                    "command_sequence": 0,
                    "timestamp": "2026-01-01T00:00:00Z",
                    "checks": [
                        {"name": "authority",           "category": "authority", "passed": false, "details": "denied"},
                        {"name": "joint_limits",         "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "velocity_limits",      "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "torque_limits",        "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "acceleration_limits",  "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "workspace_bounds",     "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "exclusion_zones",      "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "self_collision",       "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "delta_time",           "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "stability",            "category": "physics",   "passed": true, "details": "ok"},
                        {"name": "proximity_velocity",   "category": "physics",   "passed": true, "details": "ok"}
                    ],
                    "profile_name": "test_robot",
                    "profile_hash": "sha256:def",
                    "authority_summary": {
                        "origin_principal": "alice",
                        "hop_count": 1,
                        "operations_granted": ["actuate:*"],
                        "operations_required": ["actuate:j1"]
                    },
                    "verdict_signature": "AAAA",
                    "signer_kid": "test-kid"
                }
            }
        ],
        "metadata": {}
    }"#;

    fn write_tempfile(content: &str) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    #[test]
    fn nonexistent_trace_a_returns_2() {
        let tmp_b = write_tempfile(MINIMAL_TRACE_JSON);
        let args = DiffArgs {
            trace_a: PathBuf::from("/nonexistent/trace_a.json"),
            trace_b: tmp_b.path().to_path_buf(),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn nonexistent_trace_b_returns_2() {
        let tmp_a = write_tempfile(MINIMAL_TRACE_JSON);
        let args = DiffArgs {
            trace_a: tmp_a.path().to_path_buf(),
            trace_b: PathBuf::from("/nonexistent/trace_b.json"),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn invalid_json_trace_a_returns_2() {
        let tmp_a = write_tempfile("not valid json");
        let tmp_b = write_tempfile(MINIMAL_TRACE_JSON);
        let args = DiffArgs {
            trace_a: tmp_a.path().to_path_buf(),
            trace_b: tmp_b.path().to_path_buf(),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn invalid_json_trace_b_returns_2() {
        let tmp_a = write_tempfile(MINIMAL_TRACE_JSON);
        let tmp_b = write_tempfile("not valid json");
        let args = DiffArgs {
            trace_a: tmp_a.path().to_path_buf(),
            trace_b: tmp_b.path().to_path_buf(),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn identical_traces_return_0() {
        let tmp_a = write_tempfile(MINIMAL_TRACE_JSON);
        let tmp_b = write_tempfile(MINIMAL_TRACE_JSON);
        let args = DiffArgs {
            trace_a: tmp_a.path().to_path_buf(),
            trace_b: tmp_b.path().to_path_buf(),
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn traces_with_divergence_return_1() {
        let tmp_a = write_tempfile(MINIMAL_TRACE_JSON);
        let tmp_b = write_tempfile(REJECTED_TRACE_JSON);
        let args = DiffArgs {
            trace_a: tmp_a.path().to_path_buf(),
            trace_b: tmp_b.path().to_path_buf(),
        };
        assert_eq!(run(&args), 1);
    }
}
