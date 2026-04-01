import Lake
open Lake DSL

package «invariant-formal» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Invariant where
  srcDir := "Invariant"
