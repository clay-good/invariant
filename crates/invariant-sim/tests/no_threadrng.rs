//! Guard test: the load-bearing campaign modules must not reach for ambient
//! (non-deterministic) randomness or wall-clock-as-randomness sources.
//!
//! Spec: `docs/robotics/spec-v11.md` §2.0. The 15M campaign claim depends on
//! `(seed, config) → byte-identical output`. Any `thread_rng`, `OsRng`,
//! `SystemTime::now`, or `Instant::now` call inside scenario / campaign /
//! orchestrator / collector code silently breaks that property.
//!
//! This test scans the four modules named in the spec and fails on any
//! forbidden substring outside `#[cfg(test)]` / `#[test]` blocks. Doc
//! comments (`///` and `//!`) are stripped before scanning so that prose
//! examples don't trigger the guard.
//!
//! To intentionally add such a call (e.g. a new keypair generation site
//! at process boundary), prefer plumbing a `CampaignRng` through; only
//! exempt with a `// spec-v11-2.0 allow: <reason>` comment on the same
//! line if no plumbing is feasible.

use std::fs;
use std::path::PathBuf;

const SCANNED_FILES: &[&str] = &[
    "src/robotics/scenario.rs",
    "src/robotics/campaign.rs",
    "src/robotics/orchestrator.rs",
    "src/robotics/collector.rs",
];

const FORBIDDEN: &[&str] = &["thread_rng", "OsRng", "SystemTime::now", "Instant::now"];

const ALLOW_MARKER: &str = "spec-v11-2.0 allow";

#[test]
fn campaign_modules_have_no_ambient_randomness() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut violations: Vec<String> = Vec::new();

    for rel in SCANNED_FILES {
        let path = crate_dir.join(rel);
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));

        let mut in_test_module = false;
        let mut test_brace_depth: i32 = 0;
        let mut prev_was_cfg_test = false;

        for (idx, raw_line) in src.lines().enumerate() {
            let line = raw_line.trim_start();
            let lineno = idx + 1;

            // Strip line/doc comments before scanning so prose examples
            // don't trigger.
            let scan_target = match line.find("//") {
                Some(p) => &line[..p],
                None => line,
            };

            // Track entry into / exit from #[cfg(test)] mod blocks.
            if !in_test_module {
                if line.starts_with("#[cfg(test)]") || line.starts_with("#[cfg(all(test") {
                    prev_was_cfg_test = true;
                    continue;
                }
                if prev_was_cfg_test
                    && (line.starts_with("mod ")
                        || line.starts_with("pub(crate) mod ")
                        || line.starts_with("pub mod "))
                {
                    in_test_module = true;
                    test_brace_depth = 0;
                    // count braces on this line too
                    test_brace_depth += scan_target.matches('{').count() as i32;
                    test_brace_depth -= scan_target.matches('}').count() as i32;
                    prev_was_cfg_test = false;
                    continue;
                }
                prev_was_cfg_test = false;
            } else {
                test_brace_depth += scan_target.matches('{').count() as i32;
                test_brace_depth -= scan_target.matches('}').count() as i32;
                if test_brace_depth <= 0 {
                    in_test_module = false;
                }
                continue;
            }

            // Per-function #[test] gate: scan-skip the immediately
            // following fn body.
            if line.starts_with("#[test]") {
                in_test_module = true;
                test_brace_depth = 0;
                continue;
            }

            if scan_target.contains(ALLOW_MARKER) || raw_line.contains(ALLOW_MARKER) {
                continue;
            }

            for needle in FORBIDDEN {
                if scan_target.contains(needle) {
                    violations.push(format!(
                        "{}:{}: forbidden `{}` in non-test code:\n    {}",
                        rel,
                        lineno,
                        needle,
                        raw_line.trim_end()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "spec-v11 §2.0 determinism contract violated:\n{}\n\n\
         Plumb a `CampaignRng` instead, or add `// {ALLOW_MARKER}: <reason>` \
         on the offending line if unavoidable.",
        violations.join("\n"),
        ALLOW_MARKER = ALLOW_MARKER,
    );
}
