# Contributing to Invariant

Thanks for your interest in contributing. This document covers the
development workflow, the workspace layout, and how to add new physics
checks, profiles, or whole new domains.

## Getting Started

```sh
git clone https://github.com/clay-good/invariant.git
cd invariant
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

## Development Workflow

1. **Fork** the repository and create a feature branch from `main`.
2. **Write code** following the conventions below.
3. **Run checks** before pushing:
   ```sh
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo fmt --all
   cargo doc --workspace --no-deps
   ```
4. **Open a pull request** against `main`. CI runs fmt, version-drift,
   profile-sync, clippy, doc, MSRV (1.75), cargo-deny, the full test
   suite, the validate-profiles strict pass, and the Python isaac
   bridge tests. All must pass.

## Conventions

- **One commit per logical unit of work.** Atomic, reviewable.
- **Never push directly to `main`.** All changes go through PRs.
- **Read before modifying.** Understand existing code before changing
  it.
- **`#![forbid(unsafe_code)]`** is enforced in every crate.
- **Zero clippy warnings.** All code passes
  `cargo clippy --workspace --all-targets -- -D warnings`.
- **Doc-tests for public API.** Public functions, structs, and enums
  should have a `/// # Examples` doc-test that compiles. (Rustdoc
  intra-doc-link strictness is a follow-up — see
  [docs/spec-doc-link-cleanup.md](docs/spec-doc-link-cleanup.md).)
- **No emoji.** Source, docs, CLI output, commit messages — keep them
  out unless a reviewer asks otherwise.

## Workspace Layout

| Crate | crates.io name | Purpose |
|-------|---------------|---------|
| `invariant-core` | `invariant-protocol` | Shared protocol core: PCA authority chain, COSE-signed audit log, keys, intent narrowing, `ValidationInput` / `DomainCheck` / `DomainProfile` traits. |
| `invariant-robotics` | `invariant-robotics` | Robotics domain: 25 physics checks (P1–P25), URDF kinematics, robot profiles, sensor attestation, threat scoring, validator. |
| `invariant-biosynthesis` | `invariant-biosynthesis` | Biosynthesis domain: D/P/C invariants, hazard screening, BSL2/3/4 profile gating, attestation. |
| `invariant-cli` | `invariant-firewall` | Single binary (executable named `invariant`); top-level dispatch `invariant <domain> <subcommand>`. |
| `invariant-sim` | `invariant-sim` | Simulation harness, scenario generation, fault injection (per-domain modules). |
| `invariant-eval` | `invariant-eval` | Trace evaluation: presets, rubrics, guardrails. |
| `invariant-fuzz` | `invariant-fuzz` | Adversarial testing: protocol, system, cognitive attacks. |
| `invariant-coordinator` | `invariant-coordinator` | Robotics multi-robot coordination (separation, partitioning). |

Two of the published names differ from their workspace aliases
(`invariant-core` → `invariant-protocol`, `invariant-cli` →
`invariant-firewall`) because the natural names — and `invariant`
itself — were already claimed by other crates.io owners. Source
code keeps using the workspace aliases; the binary installed by
`cargo install invariant-firewall` is just `invariant`.

## Adding a New Physics Check (robotics)

1. Create a new module in `crates/invariant-robotics/src/physics/`.
2. Implement a function with signature:
   ```rust
   pub fn check_xxx(command: &Command, profile: &RobotProfile) -> CheckResult
   ```
3. Wire it into `physics::run_all_checks()`.
4. Add unit tests in the module and an integration test under
   `crates/invariant-robotics/tests/` (or
   `crates/invariant-cli/tests/` for a full CLI round-trip).
5. Document the check in [docs/robotics/spec.md](docs/robotics/spec.md)
   and add it to the README check table.

## Adding a New Domain Invariant (biosynthesis)

Mirror the same shape, but under `crates/invariant-biosynthesis/src/`:

- `models/` for any new schema additions
- `invariants/` for D / P / C check modules
- `screening/` for hazard-list integration

Then wire into the validator entry-point and update
[docs/biosynthesis/spec.md](docs/biosynthesis/spec.md).

## Adding a New Robot Profile

1. Create a JSON file under `profiles/robotics/` **and** an identical
   copy under `crates/invariant-robotics/profiles/`. CI enforces that
   the two trees match (profile-sync job) because the crate ships its
   own copy so that `cargo publish` produces a self-contained tarball.
2. Add the `include_str!` constant and `OnceLock` cache in
   `crates/invariant-robotics/src/profiles.rs`.
3. Wire it into `load_builtin()` and `list_builtin()`.
4. Add integration tests that validate the profile and run the
   adversarial suite against it.
5. The `validate-profiles --strict` CI job will run automatically.

## Adding a New Biosynthesis Profile

Same shape, under `profiles/biosynthesis/` +
`crates/invariant-biosynthesis/profiles/`, wiring through
`crates/invariant-biosynthesis/src/profiles.rs`.

## Adding a Whole New Domain

Invariant is designed to fan out across physical domains. To add one:

1. Add a new workspace crate `crates/invariant-<domain>/`.
2. Define an input type that implements `invariant_core::ValidationInput`.
3. Define a profile type that implements
   `invariant_core::DomainProfile`.
4. Implement your domain's checks against `invariant_core::DomainCheck`.
5. Add a `pub mod <domain>;` module to `invariant-sim`,
   `invariant-eval`, and `invariant-fuzz` if you want simulation,
   evaluation, and adversarial coverage.
6. Wire CLI dispatch in `crates/invariant-cli/src/main.rs` so
   `invariant <domain> <subcommand>` routes to your handlers.

No protocol changes required — the cryptographic substrate, audit log,
and policy engine are domain-agnostic.

## Reporting Issues

- [GitHub Issues](https://github.com/clay-good/invariant/issues) for
  bugs and feature requests.
- Security vulnerabilities: see [SECURITY.md](SECURITY.md). Do **not**
  open public issues for them.

## License

By contributing, you agree that your contributions will be licensed
under the [MIT License](LICENSE).
