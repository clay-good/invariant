use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct CampaignArgs {
    #[arg(long, value_name = "CONFIG_FILE")]
    pub config: PathBuf,
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(args: &CampaignArgs) -> i32 {
    // Load the campaign config YAML file.
    let config = match invariant_sim::campaign::load_config_file(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to load campaign config: {e}");
            return 2;
        }
    };

    if !args.dry_run {
        eprintln!("Live Isaac Lab campaigns require --dry-run for now");
        return 2;
    }

    // Run the dry campaign with a non-deterministic seed.
    let report = match invariant_sim::orchestrator::run_dry_campaign(&config, None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: campaign failed: {e}");
            return 2;
        }
    };

    // Serialize and print the full report as JSON.
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("error: failed to serialize campaign report: {e}");
            return 2;
        }
    }

    let outcome = if report.criteria_met {
        "PASSED"
    } else {
        "FAILED"
    };
    println!("Campaign '{}': {}", report.campaign_name, outcome);

    if report.criteria_met {
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

    const MINIMAL_YAML: &str = "\
name: test_campaign
profile: franka_panda
environments: 1
episodes_per_env: 1
steps_per_episode: 10
scenarios:
  - scenario_type: Baseline
    weight: 1.0
";

    fn args_with(config: &std::path::Path, key: &std::path::Path, dry_run: bool) -> CampaignArgs {
        CampaignArgs {
            config: config.to_path_buf(),
            key: key.to_path_buf(),
            dry_run,
        }
    }

    fn dummy_key_file() -> NamedTempFile {
        // The key file is not used by the dry-run path, but the field is
        // required by CampaignArgs.  A temp file path is sufficient.
        NamedTempFile::new().unwrap()
    }

    fn write_yaml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn missing_config_file_returns_2() {
        let key = dummy_key_file();
        let args = args_with(
            std::path::Path::new("/nonexistent/campaign.yaml"),
            key.path(),
            true,
        );
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn non_dry_run_returns_2() {
        let config = write_yaml(MINIMAL_YAML);
        let key = dummy_key_file();
        let args = args_with(config.path(), key.path(), false);
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn dry_run_with_valid_config_returns_0_or_1() {
        let config = write_yaml(MINIMAL_YAML);
        let key = dummy_key_file();
        let args = args_with(config.path(), key.path(), true);
        let code = run(&args);
        // A successful dry campaign returns 0 (passed) or 1 (failed), never 2.
        assert!(
            code == 0 || code == 1,
            "expected exit code 0 or 1, got {code}"
        );
    }
}
