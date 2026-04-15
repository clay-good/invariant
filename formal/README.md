# Formal Specification

Lean 4 formalization of all 34 Invariant safety invariants with proof sketches.

## Structure

| File | Contents |
|------|----------|
| `Invariant.lean` | Master safety theorem: `CommandIsApproved` requires all invariants |
| `Invariant/Types.lean` | Domain types (joints, commands, profiles, verdicts) |
| `Invariant/Physics.lean` | P1-P25: physical safety invariants |
| `Invariant/Authority.lean` | A1-A3: PIC authority chain invariants |
| `Invariant/Audit.lean` | L1-L4: audit log, M1: signed actuation, W1: watchdog liveness |

## Key Theorems

- **`CommandIsApproved`** - A command passes the firewall iff all 5 invariant classes hold simultaneously (physics, authority, audit, actuation, liveness)
- **`safety_guarantee`** - If a command is rejected, no actuation signature is produced
- **`fail_closed_empty_chain`** - An empty authority chain always results in rejection
- **`tamper_breaks_chain`** - Modifying any audit entry breaks the hash chain (L2)
- **`timeout_implies_safe_stop`** - Heartbeat timeout guarantees safe-stop

## Building

Requires [Lean 4](https://leanprover.github.io/lean4/doc/setup.html) (v4.8.0+).

```sh
cd formal
lake build
```

## Status

The formalization covers the complete invariant set with proof sketches. The physics invariants (P1-P25) use `sorry` placeholders for arithmetic lemmas that depend on IEEE 754 floating-point semantics outside Lean's native `Float` type. The authority and audit proofs are complete.
