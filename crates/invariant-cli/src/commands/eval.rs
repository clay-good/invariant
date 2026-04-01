use clap::Args;
use std::path::PathBuf;

use invariant_core::models::trace::Trace;
use invariant_eval::presets;

#[derive(Args)]
pub struct EvalArgs {
    /// Path to the trace JSON file to evaluate (P2-12: explicit value_name).
    #[arg(value_name = "TRACE_FILE")]
    pub trace: PathBuf,

    /// Eval preset to run (safety-check, completeness-check, regression-check)
    #[arg(long)]
    pub preset: Option<String>,

    /// Path to a custom rubric YAML/JSON file
    #[arg(long, value_name = "RUBRIC_FILE")]
    pub rubric: Option<PathBuf>,

    /// List available presets and exit
    #[arg(long)]
    pub list_presets: bool,
}

pub fn run(args: &EvalArgs) -> i32 {
    if args.list_presets {
        println!("Available presets:");
        for name in presets::list_presets() {
            println!("  {}", name);
        }
        return 0;
    }

    if args.preset.is_none() && args.rubric.is_none() {
        eprintln!("invariant eval: specify --preset or --rubric");
        eprintln!("Available presets: {}", presets::list_presets().join(", "));
        return 2;
    }

    // Read trace file
    let trace_data = match std::fs::read_to_string(&args.trace) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("error: could not read trace file: {}", e);
            return 2;
        }
    };

    let trace: Trace = match serde_json::from_str(&trace_data) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: could not parse trace file: {}", e);
            return 2;
        }
    };

    // Run rubric or preset
    let report = if let Some(rubric_path) = &args.rubric {
        let rubric_data = match std::fs::read_to_string(rubric_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("error: could not read rubric file: {}", e);
                return 2;
            }
        };
        let rubric = match invariant_eval::rubric::load_rubric_json(&rubric_data) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {}", e);
                return 2;
            }
        };
        invariant_eval::rubric::run_rubric(&rubric, &trace)
    } else {
        let preset_name = args.preset.as_deref().unwrap();
        match presets::run_preset(preset_name, &trace) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {}", e);
                return 2;
            }
        }
    };

    // Output as JSON
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("error: could not serialize report: {}", e);
            return 2;
        }
    }

    if report.passed {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // A minimal Trace JSON with one all-passing step so that safety-check returns exit 0.
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

    fn write_tempfile(content: &str) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    fn args_with(trace: PathBuf, preset: Option<&str>, list_presets: bool) -> EvalArgs {
        EvalArgs {
            trace,
            preset: preset.map(|s| s.to_string()),
            rubric: None,
            list_presets,
        }
    }

    #[test]
    fn list_presets_returns_0() {
        // list_presets=true exits immediately without reading any file.
        let args = EvalArgs {
            trace: PathBuf::from("/nonexistent"),
            preset: None,
            rubric: None,
            list_presets: true,
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn unknown_preset_returns_2() {
        let tmp = write_tempfile(MINIMAL_TRACE_JSON);
        let args = args_with(tmp.path().to_path_buf(), Some("no-such-preset"), false);
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn missing_trace_file_returns_2() {
        let args = args_with(
            PathBuf::from("/nonexistent/trace.json"),
            Some("safety-check"),
            false,
        );
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn valid_trace_safety_check_returns_0() {
        let tmp = write_tempfile(MINIMAL_TRACE_JSON);
        let args = args_with(tmp.path().to_path_buf(), Some("safety-check"), false);
        // All checks pass in the minimal trace, so the report is passing -> exit 0.
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn no_preset_and_no_rubric_returns_2() {
        let tmp = write_tempfile(MINIMAL_TRACE_JSON);
        let args = EvalArgs {
            trace: tmp.path().to_path_buf(),
            preset: None,
            rubric: None,
            list_presets: false,
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn invalid_trace_json_returns_2() {
        let tmp = write_tempfile("not valid json");
        let args = args_with(tmp.path().to_path_buf(), Some("safety-check"), false);
        assert_eq!(run(&args), 2);
    }
}
