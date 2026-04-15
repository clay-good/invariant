# Contributing to Invariant

Thank you for your interest in contributing to Invariant! This document covers
the development workflow, coding standards, and pull request process.

## Getting Started

```sh
# Clone and build
git clone https://github.com/clay-good/invariant.git
cd invariant
cargo build

# Run the full test suite
cargo test

# Run lints
cargo clippy -- -D warnings
cargo fmt --check
```

## Development Workflow

1. **Fork** the repository and create a feature branch from `main`.
2. **Write code** following the conventions below.
3. **Run checks** before pushing:
   ```sh
   cargo test
   cargo clippy -- -D warnings
   cargo fmt
   cargo doc --no-deps
   ```
4. **Open a pull request** against `main`. The CI pipeline runs tests, clippy,
   and formatting checks automatically.

## Conventions

- **One commit per logical unit of work.** Keep commits focused and atomic.
- **Never push directly to `main`.** All changes go through pull requests.
- **Read before modifying.** Understand existing code before changing it.
- **`#![forbid(unsafe_code)]`** is enforced in all crates. Do not add `unsafe` blocks.
- **Zero clippy warnings.** All code must pass `cargo clippy -- -D warnings`.
- **Doc-tests for public API.** Every public function, struct, and enum should
  have a `/// # Examples` doc-test that compiles and runs.

## Project Layout

| Crate | Purpose |
|-------|---------|
| `invariant-core` | Safety engine: physics checks, authority chain, crypto, validator |
| `invariant-cli` | CLI binary with all subcommands |
| `invariant-sim` | Simulation campaigns, scenario generation, fault injection |
| `invariant-eval` | Trace evaluation: presets, rubrics, guardrails, differ |
| `invariant-fuzz` | Adversarial testing: protocol, system, cognitive attacks |
| `invariant-coordinator` | Multi-robot coordination safety |

## Adding a New Physics Check

1. Create a new module in `crates/invariant-core/src/physics/`.
2. Implement a function with signature:
   ```rust
   pub fn check_xxx(command: &Command, profile: &RobotProfile) -> CheckResult
   ```
3. Wire it into `physics::run_all_checks()`.
4. Add unit tests in the module and integration tests in `invariant-cli/tests/`.
5. Add the check to the README table and spec.

## Adding a New Robot Profile

1. Create a JSON file in `profiles/`.
2. Add the `include_str!` constant and `OnceLock` cache in `profiles.rs`.
3. Wire it into `load_builtin()` and `list_builtin()`.
4. Add integration tests that validate the profile and run the adversarial suite.

## Reporting Issues

- Use [GitHub Issues](https://github.com/clay-good/invariant/issues) for bugs and feature requests.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
