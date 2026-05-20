/-
  Invariant — Formal Specification: Domain-Agnostic Trait Surface
  Phase 6b: Lean 4 mirror of `invariant-core::traits`.

  The Rust workspace was unified in 0.1.0 around three keystone traits:
  `ValidationInput`, `DomainCheck`, `DomainProfile`. This Lean module
  states the same abstraction as a typeclass surface so the generic
  validator pipeline (`invariant-core::validator`) and the generic audit
  log (`invariant-core::audit::AuditLogger<W, I, V>`) can be reasoned
  about independently of any specific domain.

  Status: this is the abstract surface. The robotics formalization in
  `Invariant/Types.lean` + `Invariant/Physics.lean` predates Phase 6b and
  remains the concrete instance for the robotics domain. A parallel
  biosynthesis instance is sketched in `Invariant/Biosynthesis.lean`.
-/

namespace Invariant.Core

-- ════════════════════════════════════════════════════════════════════
-- An abstract operation string (mirrors `invariant_core::models::authority::Operation`).
-- ════════════════════════════════════════════════════════════════════

abbrev Operation := String

-- ════════════════════════════════════════════════════════════════════
-- ValidationInput typeclass
--
-- Mirrors the Rust trait:
--   pub trait ValidationInput: Serialize + DeserializeOwned + Send + Sync {
--       fn domain(&self) -> &'static str;
--       fn operations(&self) -> Vec<Operation>;
--       fn content_hash(&self) -> [u8; 32];
--       fn summary(&self) -> String { ... }
--   }
-- ════════════════════════════════════════════════════════════════════

class ValidationInput (I : Type) where
  domain      : I → String
  operations  : I → List Operation
  contentHash : I → String   -- hex of SHA-256 in the Rust impl

-- ════════════════════════════════════════════════════════════════════
-- DomainProfile typeclass
--
-- Mirrors:
--   pub trait DomainProfile: Send + Sync {
--       fn id(&self) -> &str;
--       fn domain(&self) -> &'static str;
--       fn as_any(&self) -> &dyn std::any::Any;
--   }
-- ════════════════════════════════════════════════════════════════════

class DomainProfile (P : Type) where
  id     : P → String
  domain : P → String

-- ════════════════════════════════════════════════════════════════════
-- CheckResult — the outcome of one domain-specific check.
-- Mirrors `invariant_core::traits::CheckResult`.
-- ════════════════════════════════════════════════════════════════════

inductive CheckResult where
  | pass
  | fail (reason : String)
  | skip (reason : String)
  deriving Repr

-- ════════════════════════════════════════════════════════════════════
-- DomainCheck typeclass
--
-- Mirrors:
--   pub trait DomainCheck<I: ValidationInput>: Send + Sync {
--       fn id(&self) -> &'static str;
--       fn name(&self) -> &'static str;
--       fn run(&self, input: &I, ctx: &CheckContext) -> CheckResult;
--   }
-- ════════════════════════════════════════════════════════════════════

class DomainCheck (C I : Type) where
  id   : C → String
  name : C → String
  run  : C → I → CheckResult

-- ════════════════════════════════════════════════════════════════════
-- Generic verdict view, used by the differential validator.
-- Mirrors `invariant_core::differential::{VerdictView, CheckView}`.
-- ════════════════════════════════════════════════════════════════════

class CheckView (C : Type) where
  name     : C → String
  category : C → String
  passed   : C → Bool
  details  : C → String

class VerdictView (V C : Type) [CheckView C] where
  approved        : V → Bool
  commandHash     : V → String
  commandSequence : V → Nat
  checks          : V → List C

end Invariant.Core
