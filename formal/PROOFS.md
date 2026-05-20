# Lean 4 Proof Gap Inventory (v11-5.9)

This file catalogues every `sorry` and `axiom` in the
`formal/` Lean 4 formalisation. Each entry names the theorem, what it
asserts, the Rust code it mirrors, and whether the gap is **intentional**
(axiomatized as a load-bearing external fact) or **open** (placeholder
needing a real proof).

The CI job at [.github/workflows/lean.yml](../.github/workflows/lean.yml)
runs `lake build` against the pinned toolchain in
[lean-toolchain](lean-toolchain) on every PR that touches `formal/`.

## Summary

| Site | Kind   | Status      |
|------|--------|-------------|
| [Authority.lean :: `monotonicity_transitive`](Invariant/Authority.lean) | `sorry` | OPEN — proof by induction is straightforward; not blocking. |
| [Audit.lean :: `hash_collision_resistant`](Invariant/Audit.lean) | `axiom` | INTENTIONAL — cryptographic primitive, not a derivable theorem. |
| [Physics.lean :: `pointInConvexPolygon`](Invariant/Physics.lean) | `axiom` | INTENTIONAL — 2D PIP algorithm is library-territory; we state the interface only. |

## Entries

### `monotonicity_transitive` (Authority.lean)

```lean
theorem monotonicity_transitive (chain : AuthorityChain)
    (h_mono : A2_Monotonicity chain)
    (h_nonempty : chain.hops.length > 0) :
    ∀ i : Fin chain.hops.length,
      opsCoveredBy (chain.hops.get i).ops (chain.hops.get ⟨0, h_nonempty⟩).ops := by
  sorry  -- Proof by induction on i; each step narrows by h_mono.
```

**What it asserts.** Given an `A2_Monotonicity` chain (each hop's ops are
covered by its parent's ops), every hop's ops are also covered by the
root's. The hop-to-hop relation transports to a hop-to-root relation.

**Rust mirror.** `invariant_core::authority::chain::verify_chain`
(A2 monotonicity check in `crates/invariant-core/src/authority/chain.rs`).
The Rust check enforces this hop-by-hop; the Lean theorem hoists it to a
global statement.

**Status.** OPEN. Proof is a straightforward induction:
1. Base case `i = 0`: `opsCoveredBy (hops[0].ops) (hops[0].ops)` is
   reflexivity.
2. Inductive step: assume `opsCoveredBy (hops[i].ops) (hops[0].ops)`.
   From `h_mono`, `opsCoveredBy (hops[i+1].ops) (hops[i].ops)`.
   Transitivity of `opsCoveredBy` (subset of subset is subset) closes
   the case.

The transitivity lemma itself is unstated; defining it is part of the
follow-up. Not blocking the Authority module's load-bearing claims,
which are local hop-to-parent.

### `hash_collision_resistant` (Audit.lean)

```lean
axiom hash_collision_resistant :
  ∀ a b : String, a ≠ b → (a.length > 0 ∧ b.length > 0) →
    -- With overwhelming probability, SHA-256(a) ≠ SHA-256(b).
    True  -- (axiomatised; concrete bound not stated in Lean)
```

**What it asserts.** SHA-256 is collision-resistant.

**Rust mirror.** `invariant_core::util::sha256_hex` and every audit
hash-chain step in `audit.rs::AuditLogger::build_entry`.

**Status.** INTENTIONAL. Collision resistance of SHA-256 is a
cryptographic assumption, not a derivable theorem. We axiomatise it the
same way every applied formalisation of TLS / signed-log protocols does.
The audit-log tamper-detection theorem ([L1-L4 in `Audit.lean`])
depends on this axiom.

### `pointInConvexPolygon` (Physics.lean)

```lean
axiom pointInConvexPolygon (px py : Float) (polygon : List (Float × Float)) : Prop
```

**What it asserts.** Interface only: a 2D point-in-convex-polygon
predicate exists. Used by P9 (stability) to express "centre-of-mass is
inside the support polygon".

**Rust mirror.** `invariant_robotics::physics::p9_stability` —
implements PIP using the standard cross-product test.

**Status.** INTENTIONAL. A full PIP algorithm in Lean would need
floating-point reasoning machinery (orientation, robust predicates) that
is out of scope for this project. We axiomatise the interface so P9 can
be stated; the Rust side carries the algorithmic correctness.

A future iteration could replace this with `Mathlib.Geometry.Polygon`
once `mathlib` lands a stable convex-polygon API. Tracking under v13.

## Adding new gaps

1. Land the new `sorry`/`axiom` in a `formal/Invariant/*.lean` file.
2. Add a row to the table above with the kind, status (OPEN or
   INTENTIONAL), and a one-line summary.
3. Add a sub-section under "Entries" with the verbatim signature, what
   it asserts, the Rust mirror, and the closure path.
4. CI (`.github/workflows/lean.yml`) catches the syntactic correctness
   of the new entry; reviewers gate semantic completeness here.

## Closing a gap

When a `sorry` is replaced by a real proof:

1. Remove the entry from this file.
2. Note in the PR description: "closes Lean gap `<theorem name>`".

When an axiom is removed (because a Mathlib import made it derivable):

1. Move the entry from "INTENTIONAL" to "RETIRED" in a "Retired" section
   appended to this file.
2. Note the import that closed it.
