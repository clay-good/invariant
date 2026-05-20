# Eval Pipeline (v11-5.15.4)

`invariant-eval` evaluates simulation traces against named presets, custom
rubrics, and pairwise differs. This document explains the four pieces and
walks through a runnable example. Cross-references
`docs/robotics/spec.md` §6 (campaign) and v9 §5.11 (eval contract).

## Pipeline

```
Trace ──► preset (safety-check, completeness-check, regression-check) ──► EvalReport
   │
   └───► rubric (custom RubricRule[] over verdict fields) ──► EvalReport

Trace + Trace ──► differ (run_regression) ──► EvalReport (regression-only)
```

### Trace

A `Trace` (`invariant_robotics::models::trace::Trace`) is one episode of
simulation output. It carries a stable `id`, the `profile_name` used,
and an ordered `Vec<TraceStep>`. Each step has the original `Command`,
the validator's `SignedVerdict`, and an optional `simulation_state`. The
shape is JSON-serialisable end-to-end (see
[crates/invariant-eval/tests/fixtures/](../crates/invariant-eval/tests/fixtures/)).

### Preset

Built-in evaluation rules dispatched by string name. `list_presets()`
returns the catalogue at startup; `run_preset(name, &trace)` runs one:

- **`safety-check`** — every verdict must be `approved == true` AND every
  per-check entry must `passed == true`. Any rejection produces an
  `Error`-severity `EvalFinding` pointing at the failing step + named
  check.
- **`completeness-check`** — trace is non-empty, sequence is monotonic,
  no step has an empty `checks` vector.
- **`regression-check`** — degenerate one-trace mode of the differ; useful
  for spotting verdict surprises in a single shard.

### Rubric

A `Rubric` is a list of `RubricRule`s loaded from JSON; each rule has a
name, a predicate over the trace step, and a severity. Used when the
built-in presets don't capture the policy under test. See
[crates/invariant-eval/src/robotics/rubric.rs](../crates/invariant-eval/src/robotics/rubric.rs)
for the predicate grammar.

### Guardrail

In this codebase "guardrail" is the named failing check inside a
verdict — e.g. `joint_limits` (physics) or `authority` (PCA chain). The
preset surfaces guardrails as `EvalFinding`s; downstream tooling parses
the `message` for the guardrail name. The N-16 e2e test locks down this
contract.

### Differ

`run_regression(&baseline, &candidate)` compares two traces step-by-step.
A divergence in `verdict.approved` or in any individual check's `passed`
flag becomes an `Error`. A length mismatch is flagged. The differ is the
backbone of the shadow-deployment runbook
([docs/shadow-deployment.md](shadow-deployment.md) §4.4): replay the
captured command + PCA under dry-run and `run_regression` against the
shadowed trace.

## Runnable example

End-to-end on the committed fixtures (v12-N-16):

```sh
cargo test -p invariant-eval --test pipeline_e2e
```

In code:

```rust
use invariant_eval::robotics::presets::run_preset;
use invariant_robotics::models::trace::Trace;

let text = std::fs::read_to_string("crates/invariant-eval/tests/fixtures/bad_trace.jsonl")?;
let trace: Trace = serde_json::from_str(&text)?;

let report = run_preset("safety-check", &trace)?;
assert!(!report.passed);
for f in &report.findings {
    println!("[{:?}] step={} {}", f.severity, f.step, f.message);
}
```

Expected output:

```text
[Error] step=1 check 'joint_limits' (physics) failed: j1 at 1.500 rad exceeds max 1.200 rad
```

The `joint_limits` token in the message is the guardrail; downstream
parsers grep for it. Stability of this exact string is held by the
v11-5.13 error-stability catalog applied to `Verdict` check messages —
the eval pipeline never rewrites those strings, only formats them.

## When to use which

| Question | Tool |
|----------|------|
| "Did this shard ever produce an unsafe verdict?" | `safety-check` preset |
| "Is this shard usable at all?" | `completeness-check` preset |
| "Did my refactor change validator behaviour on this trace?" | `run_regression(&old, &new)` |
| "Custom policy: every approved command must have a `proximity` check" | hand-written `Rubric` |

## Limitations

- The preset catalogue is closed (three entries). Adding a new preset
  requires a code change; rubrics are the extension point for one-off
  policies.
- The differ compares verdicts but not commands; if a sim shard mutates
  command bytes step-by-step, regression-check will not flag it. Use the
  audit Merkle root (v11 1.3) for command-level integrity.
