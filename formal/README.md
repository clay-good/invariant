# Formal Specification

Lean 4 formalization of the Invariant safety invariants with proof sketches.

Refactored in **Phase 6b** to mirror the unified Rust workspace (`invariant-core`,
`invariant-robotics`, `invariant-biosynthesis`). The trait surface in
`invariant-core::traits` (`ValidationInput`, `DomainCheck`, `DomainProfile`)
is reflected in `Invariant/Core.lean` as a Lean typeclass surface.

## Structure

| File | Mirrors | Contents |
|------|---------|----------|
| `Invariant.lean` | — | Master safety theorem (robotics): `CommandIsApproved` requires all invariants |
| `Invariant/Core.lean` | `invariant-core::traits` | `ValidationInput`, `DomainProfile`, `DomainCheck`, `VerdictView`, `CheckView` typeclasses |
| `Invariant/Types.lean` | `invariant-robotics::models::*` | Robotics domain types (joints, commands, profiles, verdicts) + `ValidationInput`/`DomainProfile` instances |
| `Invariant/Physics.lean` | `invariant-robotics::physics` | P1–P25: robotics physical safety invariants |
| `Invariant/Authority.lean` | `invariant-core::authority` | A1–A3: PIC authority chain invariants (domain-agnostic) |
| `Invariant/Audit.lean` | `invariant-core::audit` | L1–L4: audit log invariants (domain-generic); M1 (actuation, robotics-only); W1 (watchdog, robotics-only) |
| `Invariant/Biosynthesis.lean` | `invariant-biosynthesis` | Bio domain types stub + `ValidationInput`/`DomainProfile` instances. Full D/P/C proofs deferred. |

## Key Theorems

- **`CommandIsApproved`** — A robotics command passes the firewall iff all 5 invariant classes hold simultaneously (physics, authority, audit, actuation, liveness).
- **`safety_guarantee`** — If a command is rejected, no actuation signature is produced.
- **`fail_closed_empty_chain`** — An empty authority chain always results in rejection.
- **`tamper_breaks_chain`** — Modifying any audit entry breaks the hash chain (L2). Domain-generic — applies to both robotics and bio audit logs (same on-disk JSONL schema).
- **`timeout_implies_safe_stop`** — Heartbeat timeout guarantees safe-stop (robotics-only).
- **`monotonicity_transitive`** — A2 chain narrowing is transitive (`sorry` placeholder).

## Building

Requires [Lean 4](https://leanprover.github.io/lean4/doc/setup.html) (v4.8.0+).

```sh
cd formal
lake build
```

## Status

The formalization covers the complete robotics invariant set with proof sketches.
Physics invariants (P1–P25) use `sorry` placeholders for arithmetic lemmas that
depend on IEEE 754 floating-point semantics outside Lean's native `Float` type.
Authority and audit proofs are complete.

The biosynthesis domain (D1–D10, P1–P10, C1–C10) has 30 invariants with 355
passing Rust unit tests; full Lean formalization of those is deferred. The bio
module here establishes the type-level instances against the shared `Core` trait
surface so the existing audit/authority proofs apply unchanged to bio audit logs.
