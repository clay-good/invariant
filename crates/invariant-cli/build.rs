//! Build script for `invariant-cli` (v11-5.12).
//!
//! Embeds two strings at compile time so `verify-self` can surface them:
//!
//! * `INVARIANT_GIT_COMMIT` — the short SHA of HEAD at build time, or
//!   `"unknown"` if we are not in a git checkout.
//! * `INVARIANT_BUILD_PROFILE` — `"debug"` or `"release"` per `$PROFILE`.
//!
//! These are best-effort: the build still succeeds when `git` is absent
//! (e.g. building from a published crates.io tarball).

use std::process::Command;

fn main() {
    // ---- build profile -----------------------------------------------------
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=INVARIANT_BUILD_PROFILE={profile}");

    // ---- git commit (short SHA, with -dirty suffix when applicable) -------
    let commit = git_short_sha().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=INVARIANT_GIT_COMMIT={commit}");

    // ---- rebuild triggers --------------------------------------------------
    // Rerun this build script when HEAD changes, so the embedded commit
    // stays current without a clean build.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
    // Always re-run if the env var is forced (e.g. CI rebuild on tag push).
    println!("cargo:rerun-if-env-changed=INVARIANT_FORCE_REBUILD");
}

fn git_short_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if sha.is_empty() {
        return None;
    }
    // Append "-dirty" if the worktree has uncommitted changes.
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false);
    if dirty {
        Some(format!("{sha}-dirty"))
    } else {
        Some(sha)
    }
}
