# docs/history/

Archive of superseded specs. Read [docs/robotics/spec.md](../robotics/spec.md)
for the current authoritative robotics protocol description, and
[docs/biosynthesis/spec.md](../biosynthesis/spec.md) for biosynthesis.

This directory was created on 2026-05-19 by v12 N-9 (spec consolidation).
Each archived file carries a `> Superseded by …` redirect on its first
line. Cross-links inside archived files are intentionally **not**
rewritten — they reflect the workspace layout at the time the file was
authored.

## Layout

- `robotics/spec-v1.md` … `robotics/spec-v11.md` — the iterative
  protocol gap-closure lineage that produced the current
  `docs/robotics/spec.md`. Read v1 for the original surface and v11
  for the most-recent gap-closure pass before consolidation.
- `robotics/spec-v12.md` — the v12 tracking-table document. The
  closure roll-up is at
  [`docs/spec-v12-verification.md`](../spec-v12-verference.md) (kept
  outside the archive because it is the public-facing closure record
  and is still cross-linked from the verification reports). v12's
  remaining carry-forwards are enumerated there.
- `robotics/spec-gaps.md` — pre-v11 gap log. Already marked
  `SUPERSEDED` in v11 5.16; moved here in v12 N-9 for tidiness.

## When to read history

You generally should not. The current spec at
[docs/robotics/spec.md](../robotics/spec.md) supersedes everything in
this folder. Open a history file only when you need to understand the
historical motivation for an invariant id, a scenario id, or a design
choice — e.g. tracing why P25 (the e-stop check) is non-disableable
back to v1's safety rationale.

If you find yourself citing a `spec-vN.md` from new code or new docs,
cite [docs/robotics/spec.md](../robotics/spec.md) instead and link to
the history file only as a "see also" reference for archaeology.

## Biosynthesis

The biosynthesis spec lineage is archived under
[`biosynthesis/`](biosynthesis/). The current authoritative biosynthesis
spec is [`docs/biosynthesis/spec.md`](../biosynthesis/spec.md); the
domain-specific design notes (`step1-reuse-map.md`, `step3-bio-invariants.md`,
… `step10-community-ecosystem.md`, `threat-model.md`) remain alongside
`spec.md` because they are reference material, not superseded spec
versions.

This sibling archive pass was completed on 2026-05-19 as a follow-up
to v12 N-9. The fifteen files moved:

- **Versioned specs:** `spec v1.md`, `spec-v2.md`, `spec-v3.md`,
  `spec-v5-gap-closure.md`, `spec-v6-gap-remediation.md`,
  `spec-v7-deep-gap-remediation.md`,
  `spec-v8-deep-gap-remediation.md`,
  `spec-v9-deep-gap-remediation.md`,
  `spec-v10-deep-gap-remediation.md`.
- **Phase notes:** `spec-phase1-gap-closure.md`,
  `spec-phase2-operational.md`.
- **Gap analyses:** `spec-gap-analysis.md`,
  `spec-gap-analysis-part-3.md`, `spec-gap-analysis-part-4.md`,
  `spec-remediation.md`.

Each archived file carries the same `> Superseded by …` redirect on
line 1 as the robotics archive. The biosynthesis lineage was not part
of v12 N-9's formal scope (N-9's prompt body called out the robotics
specs that powered the 15 M campaign), but consolidating it here
mirrors N-9's intent and keeps `docs/biosynthesis/` at the top level
of `docs/` to just `spec.md` plus the step notes.
