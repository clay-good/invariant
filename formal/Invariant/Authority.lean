/-
  Invariant — Formal Specification: Authority Invariants A1–A3
  Step 42: Lean 4 formalization.

  The PIC (Provenance, Identity, Continuity) authority model ensures that
  every motor command traces back to a human operator through a
  cryptographically signed chain of capability assertions.
-/

import Invariant.Types

namespace Invariant.Authority

open Invariant

-- ════════════════════════════════════════════════════════════════════
-- A1: Provenance — p_0 immutable across all hops
-- The origin principal must be identical at every hop in the chain.
-- ════════════════════════════════════════════════════════════════════

def A1_Provenance (chain : AuthorityChain) : Prop :=
  match chain.hops.head? with
  | none => False  -- empty chain is invalid
  | some first => ∀ hop ∈ chain.hops, hop.p0 = first.p0

-- ════════════════════════════════════════════════════════════════════
-- A2: Monotonicity — operations only narrow at each hop
-- ops_{i+1} ⊆ ops_i — each hop's operations must be a subset of
-- its predecessor's operations.
-- ════════════════════════════════════════════════════════════════════

/-- Operation `child` is covered by `parent` accounting for wildcards.
    "actuate:left_arm:shoulder" is covered by "actuate:left_arm:*".
    "actuate:*" covers everything starting with "actuate:". -/
def operationCoveredBy (child parent : Operation) : Prop :=
  child = parent ∨
  parent.endsWith ":*" ∧ child.startsWith (parent.dropRight 1) ∨
  parent = "*"

def opsCoveredBy (childOps parentOps : List Operation) : Prop :=
  ∀ cop ∈ childOps, ∃ pop ∈ parentOps, operationCoveredBy cop pop

def A2_Monotonicity (chain : AuthorityChain) : Prop :=
  ∀ i : Fin chain.hops.length,
    i.val + 1 < chain.hops.length →
      opsCoveredBy
        (chain.hops.get ⟨i.val + 1, by omega⟩).ops
        (chain.hops.get i).ops

-- ════════════════════════════════════════════════════════════════════
-- A3: Continuity — Ed25519 signature valid at every hop
-- Every hop's COSE_Sign1 signature must verify against a trusted key.
-- ════════════════════════════════════════════════════════════════════

def A3_Continuity (chain : AuthorityChain) : Prop :=
  ∀ hop ∈ chain.hops, hop.signatureValid = true

-- ════════════════════════════════════════════════════════════════════
-- Required operations coverage
-- The command's required_ops must all be covered by the chain's
-- final hop's granted ops.
-- ════════════════════════════════════════════════════════════════════

def RequiredOpsCovered (chain : AuthorityChain) (requiredOps : List Operation) : Prop :=
  match chain.hops.getLast? with
  | none => False
  | some lastHop => opsCoveredBy requiredOps lastHop.ops

-- ════════════════════════════════════════════════════════════════════
-- Combined authority predicate
-- ════════════════════════════════════════════════════════════════════

def AllAuthorityInvariantsHold (cmd : Command) : Prop :=
  A1_Provenance cmd.authority ∧
  A2_Monotonicity cmd.authority ∧
  A3_Continuity cmd.authority ∧
  RequiredOpsCovered cmd.authority cmd.requiredOps

-- ════════════════════════════════════════════════════════════════════
-- Key theorem: monotonicity is transitive
-- If ops narrow at each hop, then the final hop's ops are a subset
-- of the first hop's ops (the human operator's stated intent).
-- ════════════════════════════════════════════════════════════════════

theorem monotonicity_transitive (chain : AuthorityChain)
    (h_mono : A2_Monotonicity chain)
    (h_nonempty : chain.hops.length > 0) :
    ∀ i : Fin chain.hops.length,
      opsCoveredBy (chain.hops.get i).ops (chain.hops.get ⟨0, h_nonempty⟩).ops := by
  sorry  -- Proof by induction on i; each step narrows by h_mono.

end Invariant.Authority
