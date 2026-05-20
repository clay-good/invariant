# Threat Model — AI-Controlled Biosynthesis

**Status:** Draft v0.1 — produced for `spec.md` Step 2, Phase 1 (Foundation).
**Audience:** firewall implementers, biosafety officers, IBC/IRB reviewers, and external security auditors.
**Scope:** cryptographically-secured command validation between probabilistic AI planners and deterministic synthesis execution substrates (DNA synthesizers, peptide synthesizers, chemical synthesis platforms, cloud labs).

This document drives the requirements for the deterministic invariant set (Step 3), the PCA chain design (Step 4), the platform integration architecture (Step 5), the screening-database design (Step 6), and the HSM/key-management design (Step 7).

---

## 1. System Model

### 1.1 Trust domains

```
 Cognitive (UNTRUSTED)      Firewall (TRUST ROOT)      Execution (PROTECTED)
 -----------------------    ----------------------     ------------------------
 - RFdiffusion              - PCA chain verifier       - Twist / IDT API
 - ProteinMPNN              - Invariant set (D/P/C)    - Ansa / Kilobaser
 - LLM lab planners         - Ed25519 signer           - CEM / Biotage peptide
 - Claude / agent loops     - Audit logger             - Chemspeed / Unchained
 - Protocol extractors      - Watchdog / safe-stop     - Emerald / Strateos
 - RAG over pubs/tickets    - Threat scoring           - Lab automation / liquid
                              monitor                    handlers
```

Information flows strictly left-to-right. A synthesizer accepts no bundle without a firewall-countersigned execution token.

### 1.2 Principals and keys

- **Institution root** — air-gapped HSM at the institution (university, pharma, gov lab). Issues delegations to IBC/IRB approvers and PIs.
- **IBC/IRB approver** — human oversight body. Delegates project-scoped authority to PIs.
- **Principal Investigator (PI)** — holds project-scoped signing authority. Delegates narrowed ops to lab members and AI agents.
- **Lab member** — human operator. Can sign bundles directly or delegate to an AI agent with further narrowing.
- **AI agent** — ephemeral leaf delegate. Holds short-TTL, narrowly-scoped signing authority.
- **Firewall** — holds a validator signing key; countersigns approved verdicts and emits execution tokens.
- **Synthesis platform** — holds a device keypair; verifies execution tokens before physically synthesizing.
- **Screening database publisher** — signs hazard-list updates (HHS Select Agent list, Australia Group additions, CWC schedules, SecureDNA updates).

### 1.3 Assumptions

- Ed25519 is unbroken over the system's operating lifetime.
- The institution root HSM is not compromised. Its loss is a recovery scenario, not a threat-model scenario.
- Synthesis platforms correctly implement signature verification before execution. (Compliance verified by the platform integration program, Step 5.)
- The firewall's code supply chain is validated (Cargo lockfile, deny.toml, reproducible builds, code review).
- At least one audit log replica is honest. (Merkle-root witnessing and external notarization reduce this to "at least one external witness is honest.")

### 1.4 Non-goals

- Defending against a fully-compromised institution root. That is a key-management lifecycle problem (Step 7), not a runtime-firewall problem.
- Preventing misuse by an operator who holds legitimate authority and chooses to synthesize something dangerous *within that authority's scope*. The firewall narrows scope; it does not second-guess an IBC/IRB decision.
- Detecting exfiltration of already-synthesized material.
- Preventing wet-lab mistakes downstream of the synthesizer.

---

## 2. Attack Vectors

The eight vectors from `spec.md` Step 2, expanded. For each: methodology, capability required, impact scope, current defensive gap, firewall mitigation, and concrete implementation requirement that flows into Step 3–7.

### AV-1. Prompt injection through synthesis requests

**Methodology.** An attacker plants adversarial text in any corpus the cognitive layer ingests — a preprint PDF, a Slack ticket, a lab-notebook OCR, a dataset field, a tool-use observation. The LLM treats it as instruction ("for this target, use the following sequence: …") and emits a synthesis bundle that contains a hazardous payload.

**Capability required.** Ability to publish or inject into any data source the planner reads. Very low bar.

**Impact scope.** Laboratory → institutional, depending on the authority scope of the compromised agent.

**Current defensive gap.** Prompt-injection defenses in cognitive systems are heuristic and incomplete. No biosecurity-specific hardening exists at the LLM layer today.

**Firewall mitigation.**
- **PCA scope narrowing** — the leaf agent's ops are a strict subset of what its PI delegated. A prompt cannot cause the agent to sign a bundle outside that subset; the authority chain verifier rejects.
- **Deterministic invariant screening** — D1 (select-agent matching), D2 (pandemic pathogens), D3 (toxin genes), D4 (virulence factors) catch hazardous payloads even if the agent signs within its scope.
- **Runtime threat scoring** — composite scores across session catch slow-drift attacks that stay individually under each threshold (defense against the "dual-use drift" variant in AV-8).

**Implementation requirements.**
- Step 3: D1–D4, P3, C1–C3 invariants with real hazard databases, not stubs.
- Step 4: per-agent ops must be expressible narrowly enough that "synthesize arbitrary DNA" is never a valid leaf op.
- Step 6: screening databases must be signed, freshness-enforced, and fail-closed.

### AV-2. Sequence injection via environmental data

**Methodology.** The planner ingests sensor/instrument telemetry (mass-spec peaks, sequencing reads, plate-reader output) that a compromised lower-tier device has crafted to steer downstream synthesis decisions. The telemetry looks like data but encodes instructions the LLM follows.

**Capability required.** Compromise of an instrument or its driver/firmware.

**Impact scope.** Laboratory.

**Firewall mitigation.**
- **Attested inputs** (`attestation.rs`) — telemetry is signed by the instrument's device key and carries a nonce + freshness window. Unattested or stale readings are not eligible for inclusion in a bundle.
- Even attested readings feed into a *planner*, whose output bundle still goes through PCA + invariant screening.

**Implementation requirements.**
- Step 5: instrument-integration spec must mandate device-key provisioning.
- Step 7: HSM program must cover instrument keys, not just synthesizer keys.

### AV-3. Authority escalation in synthesis workflows

**Methodology.** Attacker tries to widen the scope of a leaf-agent signing key — by forging a parent certificate, replaying an expired delegation, or exploiting an off-by-one in the scope-intersection algebra.

**Capability required.** Medium — requires access to a signing key or a logic flaw in the verifier.

**Impact scope.** Institutional — scope expansion is the highest-leverage single attack.

**Firewall mitigation.**
- **Monotonic narrowing, cryptographically enforced.** Each PCA hop is Ed25519-signed by the parent and declares ops that are proven to be a subset of the parent's ops via the `operations.rs` algebra (already copied verbatim from robotics and test-green).
- **Time-bounded delegations.** Every hop carries `valid_from` / `valid_until` — expired chains fail closed.
- **Reissuance-required revocation.** Emergency recall: parent re-signs a new delegation with the bad child removed; firewall refreshes trust root.

**Implementation requirements.**
- Step 4: high-risk synthesis operations require multi-signature (M-of-N institutional approvers, not just a single PI).
- Step 7: short TTLs on agent keys (hours, not months).
- Ongoing: `authority::operations` test coverage must remain at 100% — any regression here is a catastrophic class of bugs.

### AV-4. Supply chain attacks on synthesis platforms

**Methodology.** Attacker compromises the synthesis platform (vendor firmware, cloud-lab orchestrator, reagent inventory system) so that a valid firewall-signed execution token causes dispensing of *different* reagents or a *different* sequence than approved.

**Capability required.** High — requires vendor or cloud-lab compromise.

**Impact scope.** Institutional to population-level, depending on platform reach.

**Firewall mitigation.**
- **Attested execution.** The platform signs a post-synthesis attestation (sequence actually synthesized, reagents actually dispensed, timestamp) and this attestation is hash-chained into the audit log. Divergence from the approved bundle is detectable in the audit trail.
- **Differential validation.** Two independent firewall instances must issue matching verdicts for high-risk bundles — compromises one at a time do not produce executable tokens.
- **Air-gapped deployments** — for highest-risk synthesis (BSL-3+, Schedule I, select agents), the firewall runs on dedicated hardware on an isolated network with operator-witnessed signing ceremonies per batch.

**Implementation requirements.**
- Step 5: platform integration contract must mandate post-execution attestation.
- Step 7: device-key provisioning ceremony for each deployed platform.
- Step 9: vendor-certification program (FIPS-140 modules, attested boot) before platforms join the trust network.

### AV-5. Database poisoning of screening systems

**Methodology.** Attacker corrupts the hazard database (Select Agent list, CWC schedules, SecureDNA signatures) so that a target sequence/structure passes screening even though it is dangerous.

**Capability required.** Access to database distribution channel, or to the publisher's signing key.

**Impact scope.** Population-level — a poisoned DB lets hazardous synthesis through every firewall using that DB.

**Firewall mitigation.**
- **Signed, versioned, hash-chained DB updates.** Each update is Ed25519-signed by the publisher, carries a monotonically-increasing version, and hash-commits the previous version. Rollback attacks (re-serving an older DB) are detectable.
- **Multi-source consensus.** For highest-risk screening (select agents, CWC), require agreement from N≥2 independent publishers (e.g., HHS + international partner). Single-source compromise is insufficient.
- **Fail-closed on stale DB.** If the local DB copy is older than a configured window (e.g., 30 days), invariants that depend on it fail closed — the firewall rejects bundles it cannot screen freshly.
- **Zero-trust DB queries.** Integrate SecureDNA-style cryptographic screening where possible so that individual queries do not leak to the publisher and the publisher cannot selectively respond.

**Implementation requirements.**
- Step 6: database schema must carry signature + version + previous-hash fields.
- Step 6: client-side verifier for database updates with fail-closed staleness check.
- Step 9: participation in IGSC / SecureDNA so updates flow through an auditable federation.

### AV-6. Replay attacks on synthesis commands

**Methodology.** Attacker captures a legitimately-signed bundle or execution token and re-submits it later to cause duplicate synthesis, or reorders bundles to change the composition of a multi-step synthesis.

**Capability required.** Low — network access to the firewall-to-platform link.

**Impact scope.** Laboratory to institutional — replaying a dual-use synthesis multiplies its effect; replaying in a different ordering can produce an outcome the invariants would have caught in the original order.

**Firewall mitigation.**
- **Per-bundle nonces** (128-bit random, tracked in an O(1) bloom filter + full persistence in audit log). Duplicate nonces fail closed.
- **Strict timestamp windows.** Execution tokens carry `valid_until` — typically seconds to minutes, not hours.
- **Sequence numbers per PCA-chain leaf.** A gap or a backward step triggers `audit-gaps` detection and a threat-score increment.
- **Sequence-aware invariant checks.** Certain invariants (e.g., cumulative synthesis volume per project) are stateful and rely on the strict-monotonicity of the audit log.

**Implementation requirements.**
- Step 3: stateful invariants that track per-operator cumulative exposure.
- Step 5: platform-side nonce cache with durability across reboots.

### AV-7. Model extraction and inversion attacks

**Methodology.** Attacker probes the planning LLM or the firewall-exposed screening endpoint to reverse-engineer the model, extract its training data, or infer proprietary research directions from the set of submitted bundles.

**Capability required.** Low to medium — depends on API exposure.

**Impact scope.** Institutional (IP leak) to population-level (if the leaked data includes pathogen work).

**Firewall mitigation.**
- **Rate-limiting at firewall ingress.** Bundle submission rates per PCA leaf are capped in line with legitimate experimental throughput; anomalous probing triggers threat score and cooldown.
- **Zero-trust screening** (SecureDNA-style) so that screening queries do not themselves leak sequences to a publisher operator.
- **Audit-log minimization.** Sensitive fields (full sequences) are stored as hashes where operationally feasible, with full content only recoverable with an institution-held decryption key.

**Implementation requirements.**
- Step 6: privacy-preserving screening integration.
- Step 9: data-protection compliance (depending on jurisdiction: HIPAA if patient-derived, EU dual-use reg, etc.).

### AV-8. Covert channel exploitation in synthesis data

**Methodology.** Attacker smuggles extra instructions or exfiltrated data through permitted fields in a bundle: unused metadata, order of list elements, encoding-level ambiguity, or sequence-level steganography (synonymous codons encoding a secondary message).

**Capability required.** Low — only requires the ability to submit one bundle.

**Impact scope.** Laboratory (data exfiltration) to institutional (instruction smuggling to a downstream LLM).

**Firewall mitigation.**
- **Canonical serialization before signing.** Bundles are normalized (sorted keys, stripped whitespace, exact-form nonces) before signing; deviating serializations fail verification.
- **Reject-on-unknown-field.** The bundle schema is closed; unknown fields are rejected rather than ignored. This closes the most common exfil side-channel.
- **Sequence-level entropy bounds.** Codon-usage invariants (D7) catch high-entropy steganography in otherwise valid DNA sequences.
- **Audit-log content review.** Periodic random audits compare submitted bundles against a canonical form; divergence indicates attempted smuggling.

**Implementation requirements.**
- Step 3: D7 (codon optimization bounds) must include statistical tests sensitive to deliberate entropy manipulation, not just engineering-level codon preference.
- Core: bundle deserialization must use `deny_unknown_fields` throughout. This is a codebase invariant enforced by code review and by a clippy-style lint. Schema closure (`deny_unknown_fields`) on bundle types — V10-1, 2026-05.
- Core: bundle source, metadata, and payload string lengths are bounded at deserialization / pre-check time, preventing unbounded-payload DoS and audit-log bloat — V10-2, V10-3, V10-4, 2026-05.

---

## 3. Domain-Specific Concerns

### 3.1 Select-agent screening bypass techniques

Known bypass classes, each of which drives specific invariant design:

- **Fragmentation** — splitting a regulated sequence across multiple orders. Mitigation: stateful threat-scoring monitor that aggregates across bundles per PCA subtree; D1 invariant uses sliding-window k-mer matching, not whole-sequence hashing.
- **Codon-substituted homologs** — same protein, different DNA sequence, to evade exact-match hash screening. Mitigation: D1 operates at the translated-protein level with HMM-based homology, not just DNA-level matching.
- **Obfuscation via synonymous mutations + reassembly** — relies on the attacker having synthesis access to multiple fragments and an assembler. Mitigation: assembly-compatibility invariant (D10) flags fragments whose primary use is assembly into a prohibited target.
- **Ordering from multiple identities** — solved at the PCA layer (per-operator scope binding) and at the screening-federation layer (publisher sees patterns across institutions via SecureDNA-style protocols).

### 3.2 Novel pathogen generation risk

An AI-designed sequence that does not appear in any hazard list but is functionally pathogenic is the highest-impact open problem.

**Partial mitigations available in this firewall:**
- Functional-domain invariants (D4) that screen for virulence motifs rather than exact sequences.
- Stability/translation-feasibility invariants (D8–D10) that catch obvious synthesizability but are not the real bottleneck.
- Scope-narrowing that prevents an agent with "therapeutic mAb design" authority from emitting a bundle that translates to a pathogenic polypeptide regardless of sequence novelty.

**Honest limit:** the firewall cannot prove a sequence is non-pathogenic. This is why shadow-mode operation (Step 8) with human expert review is Phase 3 of the roadmap before any autonomous Guardian deployment.

### 3.3 Dual-use research of concern (DURC) boundaries

DURC is a policy category, not a crisp technical one. The firewall's contribution is:
- Making DURC-relevant requests *surfaceable* — every bundle touching a flagged gene/organism family is logged with high-fidelity audit trail, independently of whether it is approved.
- Providing machine-readable policy tags on the PCA chain so that "this PI is authorized for DURC work on scope X" is enforced at delegation time.
- Supplying audit artifacts to the institutional DURC committee for periodic review.

### 3.4 Chemical Weapons Convention compliance

Schedule 1 / 2 / 3 substances (and their precursors) are enumerable. C1 invariant uses exact-structure + substructure matching against the current CWC annex. Unlike bioweapon screening, CWC screening is tractable and should run deterministic-green.

**Special requirement.** Schedule 1 work *always* requires multi-signature + Member State declaration. The PCA chain enforces the multi-sig; a separate compliance log generates OPCW-compatible declarations.

### 3.5 Export-control evasion

Deemed-export rules (EAR, ITAR biodefense articles) require tracking the *citizenship* of personnel touching the research, which the PCA chain can carry as metadata. Cross-institutional delegations between jurisdictions are flagged at the PCA verifier for compliance review.

### 3.6 Academic research vs weaponization

The firewall does not attempt to distinguish these by content. Scope is set at delegation time by human approvers (IBC/IRB/institutional biosafety committee). The firewall enforces the scope; the humans set the scope. If an approver sets a scope that includes weaponization, the firewall will not stop it — that is a scope-setting failure, not a firewall failure, and belongs to the institutional governance layer.

---

## 4. Reference Frameworks

The firewall is designed to plug into, not replace, existing biosecurity structures:

- **HHS Select Agent Program** — D1 invariant ingests SAP lists; audit logs are SAP-audit-ready.
- **Australia Group** — C and D invariants track AG control-list additions; PCA chain carries export-control jurisdiction tags.
- **SecureDNA** — Step 6 targets SecureDNA protocol compatibility for privacy-preserving screening.
- **IGSC voluntary guidelines** — IGSC-compliant screening is a conformance goal for any synthesis platform integration.
- **NSABB oversight** — DURC audit artifacts (§3.3) are generated in a format NSABB review is expected to use.
- **Chemical Weapons Convention** — C1 invariant tracks Annex 1/2/3 schedules; OPCW declaration stub in §3.4.
- **NIH Guidelines for Recombinant/Synthetic Nucleic Acid Research** — scope types on the PCA chain map 1:1 to NIH risk groups.

---

## 5. Defensive Summary Table

| # | Vector | Class | Mitigation in this repo | Spec step that delivers it |
|---|---|---|---|---|
| 1 | Prompt injection | Cognitive | PCA narrowing + D/P/C invariants + threat scoring | 3, 4 |
| 2 | Sequence injection via instruments | Input | Signed attestations on telemetry | 5, 7 |
| 3 | Authority escalation | Crypto | Monotonic PCA narrowing, Ed25519-enforced | Done (copied from robotics) |
| 4 | Platform supply chain | Execution | Post-execution attestation, differential validation, air-gap option | 5, 7 |
| 5 | DB poisoning | Input | Signed + versioned + hash-chained DB updates, multi-source, fail-closed staleness | 6 |
| 6 | Replay / reordering | Protocol | Nonces + timestamps + sequence numbers + stateful invariants | Done (nonces/audit); 3 for stateful |
| 7 | Model extraction | Privacy | Rate limit + zero-trust screening + audit minimization | 6, 9 |
| 8 | Covert channels | Protocol | Canonical serialization, deny-unknown-fields, codon-entropy invariants | Core (enforced); 3 for D7 |

---

## 6. Open Problems

Genuine limits of this design, documented here so implementers and auditors know what the firewall does **not** solve:

1. **Novel-pathogen detection with no homology to known hazards.** No deterministic screen catches this. Shadow-mode + expert review is the compensating control.
2. **Insider with legitimate authority.** The firewall enforces scope; it does not prevent scope-appropriate misuse. Governance-layer problem.
3. **Side-channel leakage through synthesis timing.** A queue-order-sensitive attacker might infer research directions from when requests are processed. Partial mitigation via rate shaping; full mitigation requires confidential computing, out of current scope.
4. **Cryptographic-agility gap.** Ed25519-only today. Post-quantum migration is a lifecycle concern for Step 7.
5. **Cross-jurisdiction enforcement asymmetry.** The firewall is jurisdiction-aware but cannot unilaterally enforce one jurisdiction's rules on another's operators. The federation must do that.

---

## Versioning and revision

This document is v0.1. Changes are tracked in `CHANGELOG.md` under `docs/`. Material changes (new attack vector, revised mitigation) require review by at least one person in addition to the change author. Threat models rot; expect a revision alongside each minor release.
