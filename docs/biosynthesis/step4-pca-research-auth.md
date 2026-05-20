# Step 4 — PCA Chain for Research Authorization

**Status:** v0.1 design. Implements `spec.md` Step 4.
**Prereqs:** `authority/chain.rs`, `authority/operations.rs`, `authority/crypto.rs` (copied verbatim from invariant-robotics in Step 0 and test-green).

This document specifies how the substrate-agnostic PCA chain already in the core crate is parameterized for biosynthesis authority workflows. Code lives at `crates/invariant-biosynthesis-core/src/authority/`; this doc names the *policy* on top of the existing cryptographic primitives.

---

## 1. Chain Structure

Six levels. Each level is one Ed25519-signed hop; the signature covers the child's subject key, declared ops, time bounds, and a monotonically-narrowing scope assertion proven by the `operations.rs` subset algebra.

```
L0  INSTITUTION_ROOT         (air-gapped HSM, institution key)
 |
 v
L1  IBC_IRB_APPROVER         (oversight body — biosafety committee, IRB)
 |
 v
L2  PRINCIPAL_INVESTIGATOR   (project-scoped; per-protocol key)
 |
 v
L3  LAB_MEMBER               (human operator; per-lab-member key, long TTL)
 |
 v
L4  AI_AGENT                 (ephemeral, short-TTL, per-session key)
 |
 v
L5  SYNTHESIS_PLATFORM       (device key; verifies ExecutionTokens)
```

### Cardinality

- One L0 per institution. Multi-institution collaboration uses cross-certification (§6).
- One L1 per oversight body per institution (usually one IBC + one IRB).
- One L2 per approved protocol (not per PI — a PI running three protocols holds three L2 keys).
- L3/L4 may be many-to-one under an L2.
- L5 is independent of L0–L4 (the platform has its own root of trust — see `platform-integration.md`).

### Certificate format

Uses the `Pca` type already in `models/authority.rs`. Each certificate contains:

```
{
  "issuer_kid": "...",
  "subject_kid": "...",
  "level": "IBC_IRB_APPROVER",
  "ops": [ ... ],              // narrowed op set
  "scope_tags": { ... },       // policy-layer metadata (see §3)
  "valid_from": "...",
  "valid_until": "...",
  "serial": "...",
  "issuer_signature": "..."    // Ed25519 over canonical bytes
}
```

No new fields beyond what the robotics verifier already parses. `scope_tags` is a new string-map used for bio-specific policy that is opaque to the crypto layer.

---

## 2. Operation Vocabulary

`authority/operations.rs` already implements the subset algebra (`op_is_subset(child, parent)`). We extend the *vocabulary* — the set of valid op strings — for biosynthesis.

Op strings use the existing colon-separated hierarchy. Wildcards (`*`) are legal only for intermediate components; the leaf component must be concrete at L4 (AI agent) and may be concrete or wildcard above.

Grammar:

```
op     := verb ":" substrate ":" target [":" qualifier]*
verb   := synthesize | assemble | modify | screen | dispense | order
substrate := dna | peptide | small_mol | plasmid | cell_line | reagent
target := <concrete id> | *
qualifier := vol_leq:<ml> | bsl_leq:<n> | schedule_leq:<n>
```

### Representative ops

```
# DNA
synthesize:dna:fragment_lt_200bp:vol_leq:1.0
synthesize:dna:gene_lt_3kbp:vol_leq:0.5:bsl_leq:2
assemble:plasmid:puc19_derivative
modify:dna:crispr_guide_lt_25nt

# Peptide
synthesize:peptide:linear_lt_30aa:vol_leq:0.1
modify:peptide:amide_cap

# Small molecule
synthesize:small_mol:catalog:schedule_leq:0
synthesize:small_mol:novel:bsl_leq:1

# Order (sent to external synthesis vendor)
order:dna:twist:*
order:small_mol:sigma:*

# Screening (read-only, no execution)
screen:dna:*
screen:peptide:*
```

### Subset algebra examples

Parent: `synthesize:dna:gene_lt_3kbp:vol_leq:0.5:bsl_leq:2`
Child-legal: `synthesize:dna:gene_lt_3kbp:vol_leq:0.1:bsl_leq:1`
Child-illegal: `synthesize:dna:gene_lt_3kbp:vol_leq:0.5:bsl_leq:3` (bsl expanded)
Child-illegal: `synthesize:dna:plasmid` (verb/target mismatch)
Child-illegal: `synthesize:dna:*` (leaf widened)

All cases already handled by the robotics-copied `op_is_subset` — the bio extension is purely new op strings, no new algebra.

---

## 3. Scope Tags (Policy Metadata)

`scope_tags` is a free-form map consulted by **policy-layer** validators after the crypto-layer chain verifies. Keys defined for biosynthesis:

| Key | Type | Meaning | Enforced at |
|---|---|---|---|
| `bsl_max` | `1..=4` | Max biosafety level the subject may operate at | Profile check |
| `organism_allowlist` | `[string]` | ICTV taxa + NCBI taxids the subject may synthesize for | D1–D4 invariants |
| `chemical_hazard_allowlist` | `[string]` | GHS hazard class codes | C-series invariants |
| `schedule_max` | `0..=3` | CWC schedule the subject may touch (0 = non-scheduled) | C1 invariant + PCA multi-sig |
| `export_jurisdiction` | string | `US`, `EU`, `JP`, etc. — for deemed-export tracking | Jurisdiction monitor |
| `durc_authorized` | bool | Whether subject may initiate DURC-flagged work | DURC audit trail |
| `multisig_required` | bool | Whether this subject's bundles require M-of-N co-signatures | Validator gate |
| `multisig_m` | u8 | M in M-of-N | Validator gate |
| `multisig_n` | u8 | N in M-of-N | Validator gate |

**Narrowing rule for scope tags.** Unlike ops, scope tags narrow *per-field*. A child certificate may not widen `bsl_max`, may not add items to `organism_allowlist` not in the parent's, may not raise `schedule_max`. The validator enforces narrowing in the same pass as op subset.

---

## 4. Time Bounds and TTLs

Recommended defaults, per level. Profiles may shorten but not lengthen.

| Level | Default TTL | Max TTL |
|---|---|---|
| L0 INSTITUTION_ROOT | 10 years | 10 years |
| L1 IBC_IRB_APPROVER | 2 years | 3 years |
| L2 PRINCIPAL_INVESTIGATOR | 1 year (= protocol approval window) | 3 years |
| L3 LAB_MEMBER | 90 days | 1 year |
| L4 AI_AGENT | 4 hours | 7 days |
| L5 SYNTHESIS_PLATFORM | 90 days (re-provisioned) | 1 year |

Short L4 TTLs are the dominant defense against compromised agent keys — see threat model §AV-3.

---

## 5. Multi-Signature Requirements

High-risk operations must be co-signed by M-of-N L1 or L2 authorities. The validator checks `multisig_required` on the leaf's effective policy (inherited from any ancestor that sets it) and demands M distinct valid PCA chains terminating in different L1/L2 subjects for the same bundle.

### Trigger rules (evaluated against the bundle payload)

```
IF C1 invariant flags CWC Schedule 1          -> M=3, N=5, requires 2x L1 + 1x L2
IF D1 invariant flags Select Agent            -> M=2, N=3, requires L1 + L2
IF bundle.scope_tags.bsl_max >= 3             -> M=2, N=3
IF bundle involves DURC-flagged organism      -> M=2, N=3, at least one L1 must be IBC
IF aggregate session volume crosses threshold -> M=2, N=2
Else                                          -> single signature sufficient
```

Rules are configured at the institution level in `profiles/*.json` and enforced in `validator.rs`. Implementation bridges existing PCA chain verification to a new `multisig` module to be added in Step 4 implementation.

---

## 6. Cross-Institutional Collaboration

Two institutions (A and B) collaborating on a joint protocol:

1. Institution A's L0 signs a **cross-certificate** establishing B's L0 as a trusted peer for specific op scopes.
2. B's L0 does the reciprocal.
3. Bundles originating from B's AI agent and targeting A's synthesizer verify both chains: B's L0→L1→L2→L3→L4 *and* A's cross-cert for B's L0.
4. Scope is the *intersection* of the two institutions' permitted scopes.

The existing op-subset algebra is used twice (once per chain). No new crypto; pure policy composition.

Cross-jurisdiction collaboration (US lab + EU lab) additionally requires:
- Both cross-certs declare `export_jurisdiction`.
- Deemed-export monitor logs every bundle that crosses jurisdictions.
- Some ops (e.g., Australia Group controlled items) are refused if jurisdictions mismatch.

---

## 7. Emergency Revocation

Revocation is **reissuance-based**, not CRL-based — simpler and avoids a DoS-susceptible distribution channel.

1. Parent observes/suspects compromise of a child subject key.
2. Parent signs a new certificate for the sibling tree *without* the compromised subject, with a fresh serial.
3. Parent updates the trust-root advertisement on the audit log.
4. The firewall refreshes its trust root from the audit log (signature-verified).
5. Bundles signed by the revoked key will fail because the parent no longer vouches for it in the current chain view.

### Freshness enforcement

The validator pins the trust root to a max-age (configurable, default 1 hour). If the trust root advertisement is older, the validator fails closed. This prevents a network partition from letting a revoked child continue operating past revocation.

---

## 8. Operational Key Ceremonies

### L0 generation
- Air-gapped ceremony. ≥3 witnesses from IBC/IRB/security. Entropy source tested (NIST SP 800-90B).
- Key generated inside FIPS-140 Level 3 HSM or equivalent. Never leaves the HSM.
- Public key published to institutional PKI and recorded in audit log bootstrap entry.
- Full-text ceremony script in `docs/ceremonies/L0-generation.md` (Step 7 deliverable).

### L1/L2 issuance
- Human approver at HSM. Two-person integrity (signer + witness).
- Issuance batch per quarter to reduce ceremony overhead; individual issuance for urgent cases.

### L3/L4 provisioning
- L3 provisioned by PI at project onboarding. Runs on operator's authenticated workstation with OS keychain or hardware token.
- L4 generated per-session by the agent runtime; issuance requested from L3 via a signed request. L4 private key lives only in the agent process memory.

### L5 platform keys
- See `docs/platform-integration.md` — vendor-specific provisioning with vendor-attested hardware.

---

## 9. Code Templates

### University research lab
`profiles/university_bsl2_dna.json` (already stubbed in Step 0) will be fleshed out to reference:
- `bsl_max: 2`
- `organism_allowlist`: standard lab organisms (E. coli K-12, S. cerevisiae, basic cell lines)
- `multisig_required: false` for routine work, `true` override via invariant triggers.

### Pharma R&D
`profiles/pharma_rd_peptide.json` (to be created in Step 4 implementation):
- `bsl_max: 2`
- Tight `organism_allowlist` limited to therapeutic targets.
- `export_jurisdiction` per site.
- `multisig_m: 2, multisig_n: 4` by default across all ops (pharma likes audit trails).

### Government lab
`profiles/gov_bsl3_pathogen.json`:
- `bsl_max: 3`
- `durc_authorized: true`
- `multisig_m: 3, multisig_n: 5`.
- Classified-data export-control flags.

### Cloud lab provider
`profiles/cloud_lab_tenant.json`:
- Tenant-scoped L1 issued by the cloud lab to the research institution.
- Cross-certificate pattern (§6) for the institution's internal chain.
- Platform (L5) key held by the cloud lab; tenant never sees private key.

### Multi-institutional consortium
`profiles/consortium_cross_cert.json`:
- Cross-cert manifest: list of trusted peer L0s.
- Shared op scope: the intersection of all members' declared scopes.

---

## 10. Implementation Plan

1. **(existing)** `authority/chain.rs`, `authority/operations.rs`, `authority/crypto.rs` — done.
2. **Step 4a** — extend `models/authority.rs::Pca` to carry `scope_tags` typed map. Add test cases to `authority/tests.rs` for every narrowing rule in §3.
3. **Step 4b** — implement `authority/multisig.rs` with the M-of-N chain collector and the threshold verifier.
4. **Step 4c** — implement `authority/revocation.rs` reading the trust-root advertisement from the audit log.
5. **Step 4d** — populate the five profile templates in §9 with real data.
6. **Step 4e** — write the `ceremonies/` subdirectory under `docs/` for L0/L1/L2 procedures.

No step here requires new crypto primitives. Everything composes on Ed25519 + the subset algebra we already ship.
