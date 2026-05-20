//! `intent` subcommand: list / show / expand built-in task templates.
//!
//! - `intent list` — print all built-in templates with their descriptions.
//! - `intent show --name X` — print one template's parameter schema.
//! - `intent expand --name X --param k=v --principal alice --kid k-1`
//!   — instantiate a template into a `ResolvedIntent` and the matching
//!   `Pca` claim, emitting JSON for downstream signing.
//!
//! Exit codes:
//! - 0 — success
//! - 1 — semantic error (unknown template, missing parameter, invalid op)
//! - 2 — usage error (malformed `--param` value, etc.)
//! - 3 — internal error (I/O, serialization)

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde::Serialize;

use invariant_biosynthesis::intent::{
    builtin_templates, find_template, intent_to_pca, resolve_template, IntentError, ResolvedIntent,
};
use invariant_biosynthesis::models::authority::Pca;

#[derive(Args, Debug)]
pub struct IntentArgs {
    #[command(subcommand)]
    pub command: IntentCommand,
}

#[derive(Subcommand, Debug)]
pub enum IntentCommand {
    /// List all built-in templates.
    List,
    /// Show one template's schema.
    Show(ShowArgs),
    /// Expand a template into a draft intent + Pca claim.
    Expand(ExpandArgs),
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Template name.
    #[arg(long)]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct ExpandArgs {
    /// Template name.
    #[arg(long)]
    pub name: String,
    /// Repeated `--param key=value` flags. Each parameter required by the
    /// template must be supplied.
    #[arg(long = "param", value_name = "KEY=VALUE")]
    pub params: Vec<String>,
    /// Principal (operator identity) recorded in the resolved intent.
    #[arg(long)]
    pub principal: String,
    /// Key id of the operator's signing key (recorded in the Pca claim).
    #[arg(long)]
    pub kid: String,
    /// Override the template's default duration (seconds).
    #[arg(long)]
    pub duration_s: Option<f64>,
    /// Optional output path for the JSON. Stdout when omitted.
    #[arg(long, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct ExpandOutput {
    intent: ResolvedIntent,
    pca: Pca,
}

pub fn run(args: &IntentArgs) -> i32 {
    match &args.command {
        IntentCommand::List => run_list(),
        IntentCommand::Show(a) => run_show(a),
        IntentCommand::Expand(a) => run_expand(a),
    }
}

fn run_list() -> i32 {
    let templates = builtin_templates();
    println!("templates ({} total):", templates.len());
    for t in &templates {
        println!("  {} — {}", t.name, t.description);
    }
    0
}

fn run_show(args: &ShowArgs) -> i32 {
    let Some(t) = find_template(&args.name) else {
        eprintln!("error: unknown template: {}", args.name);
        return 1;
    };
    println!("template: {}", t.name);
    println!("  description: {}", t.description);
    println!("  required_params: [{}]", t.required_params.join(", "));
    println!("  operation_patterns:");
    for p in &t.operation_patterns {
        println!("    {p}");
    }
    println!("  default_duration_s: {}", t.default_duration_s);
    0
}

fn run_expand(args: &ExpandArgs) -> i32 {
    match run_expand_inner(args) {
        Ok(()) => 0,
        Err(ExpandFail::Usage(msg)) => {
            eprintln!("error: {msg}");
            2
        }
        Err(ExpandFail::Semantic(msg)) => {
            eprintln!("error: {msg}");
            1
        }
        Err(ExpandFail::Internal(msg)) => {
            eprintln!("error: {msg}");
            3
        }
    }
}

enum ExpandFail {
    Usage(String),
    Semantic(String),
    Internal(String),
}

fn run_expand_inner(args: &ExpandArgs) -> Result<(), ExpandFail> {
    let template = find_template(&args.name)
        .ok_or_else(|| ExpandFail::Semantic(format!("unknown template: {}", args.name)))?;

    // Parse --param key=value pairs.
    let mut params: HashMap<String, String> = HashMap::new();
    for raw in &args.params {
        let Some((k, v)) = raw.split_once('=') else {
            return Err(ExpandFail::Usage(format!(
                "malformed --param {raw:?} (expected KEY=VALUE)"
            )));
        };
        if k.is_empty() {
            return Err(ExpandFail::Usage(format!("empty key in --param {raw:?}")));
        }
        params.insert(k.to_string(), v.to_string());
    }

    let intent = resolve_template(
        &template,
        &params,
        &args.principal,
        &args.kid,
        args.duration_s,
    )
    .map_err(|e| match e {
        IntentError::MissingParameter { .. }
        | IntentError::UnknownTemplate { .. }
        | IntentError::InvalidOperation { .. }
        | IntentError::EmptyOperations
        | IntentError::InvalidDuration { .. } => ExpandFail::Semantic(e.to_string()),
    })?;

    let pca = intent_to_pca(&intent).map_err(|e| ExpandFail::Semantic(e.to_string()))?;

    let out = ExpandOutput { intent, pca };
    let json = serde_json::to_string_pretty(&out)
        .map_err(|e| ExpandFail::Internal(format!("serialize: {e}")))?;
    match &args.output {
        Some(p) => fs::write(p, &json)
            .map_err(|e| ExpandFail::Internal(format!("write {}: {e}", p.display())))?,
        None => println!("{json}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn list_succeeds() {
        let args = IntentArgs {
            command: IntentCommand::List,
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn show_known_template_succeeds() {
        let args = IntentArgs {
            command: IntentCommand::Show(ShowArgs {
                name: "synthesize_dna_fragment".into(),
            }),
        };
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn show_unknown_template_returns_one() {
        let args = IntentArgs {
            command: IntentCommand::Show(ShowArgs {
                name: "not-a-template".into(),
            }),
        };
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn expand_succeeds_and_writes_file() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("intent.json");
        let args = IntentArgs {
            command: IntentCommand::Expand(ExpandArgs {
                name: "synthesize_dna_fragment".into(),
                params: vec!["platform=twist".into()],
                principal: "alice".into(),
                kid: "key-1".into(),
                duration_s: Some(60.0),
                output: Some(out.clone()),
            }),
        };
        assert_eq!(run(&args), 0);
        let raw = fs::read_to_string(&out).unwrap();
        assert!(raw.contains("\"principal\": \"alice\""));
        assert!(raw.contains("synthesize:dna:twist"));
    }

    #[test]
    fn expand_missing_param_returns_one() {
        let args = IntentArgs {
            command: IntentCommand::Expand(ExpandArgs {
                name: "synthesize_dna_fragment".into(),
                params: vec![],
                principal: "alice".into(),
                kid: "key-1".into(),
                duration_s: None,
                output: None,
            }),
        };
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn expand_unknown_template_returns_one() {
        let args = IntentArgs {
            command: IntentCommand::Expand(ExpandArgs {
                name: "not-a-template".into(),
                params: vec![],
                principal: "alice".into(),
                kid: "key-1".into(),
                duration_s: None,
                output: None,
            }),
        };
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn expand_malformed_param_returns_two() {
        let args = IntentArgs {
            command: IntentCommand::Expand(ExpandArgs {
                name: "synthesize_dna_fragment".into(),
                // No '=' sign.
                params: vec!["bareflag".into()],
                principal: "alice".into(),
                kid: "key-1".into(),
                duration_s: None,
                output: None,
            }),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn expand_for_each_new_template() {
        // Ensures each of the 4 newly-added templates expands cleanly with
        // a single `platform=...` parameter.
        for name in [
            "prepare_chemical_compound",
            "assemble_plasmid",
            "screen_library",
            "purify_product",
        ] {
            let args = IntentArgs {
                command: IntentCommand::Expand(ExpandArgs {
                    name: name.into(),
                    params: vec!["platform=tecan".into()],
                    principal: "p".into(),
                    kid: "k".into(),
                    duration_s: None,
                    output: None,
                }),
            };
            assert_eq!(run(&args), 0, "expand failed for {name}");
        }
    }
}
