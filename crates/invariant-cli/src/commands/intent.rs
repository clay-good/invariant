//! `invariant intent` — Intent-to-operations pipeline.
//!
//! Generates a signed PCA_0 from human intent using template-based or direct
//! specification modes. Outputs the signed PCA chain as base64 JSON (ready to
//! embed in a command's `authority.pca_chain` field).

use clap::{Args, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine};

use invariant_core::authority::crypto::sign_pca;
use invariant_core::intent;

#[derive(Args)]
pub struct IntentArgs {
    #[command(subcommand)]
    pub mode: IntentMode,
}

#[derive(Subcommand)]
pub enum IntentMode {
    /// Generate PCA from a task template with parameters.
    Template(TemplateArgs),
    /// Generate PCA from directly-specified operations.
    Direct(DirectArgs),
    /// List available built-in task templates.
    ListTemplates,
}

#[derive(Args)]
pub struct TemplateArgs {
    /// Template name (e.g., "pick_and_place").
    #[arg(long)]
    pub template: String,
    /// Parameters as key=value pairs (e.g., --param limb=left_arm).
    #[arg(long = "param", value_name = "KEY=VALUE")]
    pub params: Vec<String>,
    /// Operator principal name.
    #[arg(long, default_value = "operator")]
    pub principal: String,
    /// Path to the key file for signing.
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    /// Duration override in seconds (default from template).
    #[arg(long)]
    pub duration: Option<f64>,
}

#[derive(Args)]
pub struct DirectArgs {
    /// Operations to grant (can be specified multiple times).
    #[arg(long = "op", value_name = "OPERATION")]
    pub ops: Vec<String>,
    /// Operator principal name.
    #[arg(long, default_value = "operator")]
    pub principal: String,
    /// Path to the key file for signing.
    #[arg(long, value_name = "KEY_FILE")]
    pub key: PathBuf,
    /// Duration in seconds (None = no expiry).
    #[arg(long)]
    pub duration: Option<f64>,
}

pub fn run(args: &IntentArgs) -> i32 {
    match &args.mode {
        IntentMode::Template(targs) => run_template(targs),
        IntentMode::Direct(dargs) => run_direct(dargs),
        IntentMode::ListTemplates => run_list_templates(),
    }
}

fn run_list_templates() -> i32 {
    let templates = intent::builtin_templates();
    println!("Built-in task templates:");
    for t in &templates {
        println!(
            "  {} — {} (params: [{}], duration: {}s)",
            t.name,
            t.description,
            t.required_params.join(", "),
            t.default_duration_s
        );
    }
    println!("\n{} templates available.", templates.len());
    0
}

fn run_template(args: &TemplateArgs) -> i32 {
    // Load template.
    let template = match intent::find_template(&args.template) {
        Some(t) => t,
        None => {
            eprintln!("error: unknown template '{}'. Use 'intent list-templates' to see available templates.", args.template);
            return 2;
        }
    };

    // Parse key=value params.
    let mut params = HashMap::new();
    for kv in &args.params {
        let parts: Vec<&str> = kv.splitn(2, '=').collect();
        if parts.len() != 2 {
            eprintln!("error: invalid parameter format '{kv}'. Expected KEY=VALUE.");
            return 2;
        }
        params.insert(parts[0].to_string(), parts[1].to_string());
    }

    // Resolve intent.
    let resolved = match intent::resolve_template(
        &template,
        &params,
        &args.principal,
        "", // kid filled after key load
        args.duration,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    sign_and_output(resolved, &args.key)
}

fn run_direct(args: &DirectArgs) -> i32 {
    let resolved = match intent::resolve_direct(
        &args.ops,
        &args.principal,
        "", // kid filled after key load
        args.duration,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    sign_and_output(resolved, &args.key)
}

fn sign_and_output(mut resolved: intent::ResolvedIntent, key_path: &std::path::Path) -> i32 {
    // Load signing key.
    let kf = match crate::key_file::load_key_file(key_path) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let (sk, _vk, kid) = match crate::key_file::load_signing_key(&kf) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Set the kid from the loaded key.
    resolved.kid = kid;

    // Convert to PCA.
    let pca = match intent::intent_to_pca(&resolved) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    // Sign.
    let signed = match sign_pca(&pca, &sk) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: signing failed: {e}");
            return 2;
        }
    };

    // Encode as base64 chain (array of one SignedPca).
    let chain = vec![signed];
    let chain_json = match serde_json::to_vec(&chain) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: serialization failed: {e}");
            return 2;
        }
    };
    let chain_b64 = STANDARD.encode(&chain_json);

    // Output.
    println!("{chain_b64}");

    // Also print human-readable summary to stderr.
    eprintln!("intent: principal={}", resolved.principal);
    eprintln!("intent: operations={:?}", resolved.operations);
    eprintln!(
        "intent: expiry={}",
        resolved
            .expiry
            .map(|e| e.to_rfc3339())
            .unwrap_or_else(|| "none".into())
    );
    eprintln!("intent: source={:?}", resolved.source);

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_key_returns_2() {
        let args = IntentArgs {
            mode: IntentMode::Direct(DirectArgs {
                ops: vec!["actuate:j1".into()],
                principal: "test".into(),
                key: PathBuf::from("/nonexistent/key.json"),
                duration: None,
            }),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn unknown_template_returns_2() {
        let args = IntentArgs {
            mode: IntentMode::Template(TemplateArgs {
                template: "nonexistent".into(),
                params: vec![],
                principal: "test".into(),
                key: PathBuf::from("/nonexistent/key.json"),
                duration: None,
            }),
        };
        assert_eq!(run(&args), 2);
    }

    #[test]
    fn list_templates_returns_0() {
        let args = IntentArgs {
            mode: IntentMode::ListTemplates,
        };
        assert_eq!(run(&args), 0);
    }
}
