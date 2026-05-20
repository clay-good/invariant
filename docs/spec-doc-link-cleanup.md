# Spec — restore `RUSTDOCFLAGS=-Dwarnings` on the docs CI gate

**Status:** open
**Tracking:** introduced in v0.0.3 release prep (commit landing the rename to `invariant-protocol`)
**Owner:** unassigned

## Background

The `doc` job in `.github/workflows/ci.yml` used to fail the build on any
rustdoc warning via `RUSTDOCFLAGS: -Dwarnings`. It was relaxed during the
v0.0.3 release prep because the workspace has accumulated broken
intra-doc links that would have blocked the release.

This spec lays out the work needed to clean those up so the gate can be
restored, plus the policy we'll keep afterward to prevent regressions.

## Concrete failures observed (2026-05-19)

Running:

```sh
RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps --document-private-items
```

produces approximately 20+ unresolved-link errors across three crates:

### `invariant-protocol` (formerly `invariant-core`)

- `crates/invariant-core/src/audit.rs:318` — unresolved link `resume`
- `crates/invariant-core/src/audit.rs:319` — unresolved link `open_file`
- `crates/invariant-core/src/authority/chain.rs:19` — public doc on
  `DEFAULT_MAX_HOPS` links to private item `MAX_HOPS`
- `crates/invariant-core/src/incident.rs` — unresolved links `VerdictView`,
  `CheckView`, `compare_verdicts`
- `crates/invariant-core/src/merkle.rs` — unresolved links `leaf_hash`,
  `inner_hash`, `MerkleAccumulator`, `inclusion_proof`, `verify_inclusion`
- `crates/invariant-core/src/intent.rs` — unresolved link `Command`
- `crates/invariant-core/src/proof_package.rs` — unresolved link
  `SignedVerdict`
- `crates/invariant-core/src/lib.rs` — additional unresolved references

### `invariant-robotics`

- Unresolved links: `super::molecule::CWC_RULES`,
  `super::molecule::EXPLOSIVE_RULES`, `super::molecule::Molecule`,
  `HomologyEngine`, `KmerHomologyEngine`

### `invariant-biosynthesis`

- Unresolved links: `SynthesisBundle`, `SignedVerdict`, plus several
  intra-domain refs

(Run the command above for the authoritative current list — line numbers
will drift as code is edited.)

## Categories of fix

Each broken link falls into one of three buckets, in increasing effort:

1. **Stale rename.** The doc comment names an item that was later
   renamed or moved during the unification refactor. Fix: update the
   link to the current canonical path. Most cases.

2. **Private-from-public.** A `pub`-documented item links to a
   `pub(crate)` or private sibling, which rustdoc rejects. Fix: either
   make the target `pub` (if it's part of the surface anyway), drop the
   link and inline a plain-text reference, or escape the brackets
   (`\[name\]`).

3. **Dead reference.** The linked item no longer exists at all. Fix:
   delete the link or replace it with the new equivalent.

## Plan

1. Land this spec first (no behavior change).
2. Open one PR per crate, working in the order
   `invariant-protocol` → `invariant-robotics` → `invariant-biosynthesis`.
   Each PR runs `cargo doc --workspace --no-deps --document-private-items`
   locally with `RUSTDOCFLAGS=-Dwarnings` and posts the before/after
   warning count in the PR description.
3. Once all three are green, flip `.github/workflows/ci.yml` `doc` job
   back to the strict form:

   ```yaml
     doc:
       name: Docs
       runs-on: ubuntu-latest
       env:
         RUSTDOCFLAGS: -Dwarnings
       steps:
         - uses: actions/checkout@v4
         - uses: dtolnay/rust-toolchain@stable
         - uses: Swatinem/rust-cache@v2
         - run: cargo doc --workspace --no-deps --document-private-items
   ```

4. Add a regression note to `CONTRIBUTING.md` reminding contributors to
   run `cargo doc` locally and that warnings will fail CI.

## Non-goals

- This spec does **not** propose adding new prose docs or examples.
  Scope is limited to fixing existing broken links.
- We are **not** turning on `missing_docs` lints workspace-wide; that's
  a much bigger undertaking and not blocking the release pipeline.

## Acceptance criteria

- `cargo doc --workspace --no-deps --document-private-items` runs
  cleanly with `RUSTDOCFLAGS=-Dwarnings` (zero warnings, zero errors).
- `.github/workflows/ci.yml` `doc` job sets `RUSTDOCFLAGS: -Dwarnings`
  and fails on regressions.
- A note in `CONTRIBUTING.md` tells contributors how to reproduce the
  doc check locally.
