# Invariant

A Rust workspace with six crates. Binary: `invariant` (from `invariant-cli`).

## Build & Test

```sh
cargo build
cargo test
cargo clippy -- -D warnings
```

## Project Layout

- `crates/invariant-core` — models, physics checks, authority (PIC) chain, validator, differential, intent, audit, watchdog
- `crates/invariant-cli` — CLI binary with subcommands (validate, audit, verify, inspect, eval, diff, differential, intent, campaign, keygen, serve)
- `crates/invariant-sim` — simulation harness (Isaac Lab bridge, dry-run campaigns)
- `crates/invariant-eval` — trace evaluation engine (presets, rubrics, guardrails, differ)
- `crates/invariant-fuzz` — adversarial testing framework (protocol, system, cognitive attacks)
- `crates/invariant-coordinator` — multi-robot coordination safety (separation, partitioning)
- `profiles/` — built-in robot profile JSON files

## Conventions

- Read existing files before modifying them.
- Run `cargo test` and `cargo clippy` after changes.
- One commit per logical unit of work.
- Never push directly to main.
