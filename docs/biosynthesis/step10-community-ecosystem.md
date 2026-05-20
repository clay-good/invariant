# Step 10 — Open Source Community and Ecosystem Development

**Status:** v0.1 plan. Implements `spec.md` Step 10.

The firewall is safety-critical, but safety-critical ≠ closed. This doc specifies how the project cultivates a legitimate contributor base, maintains code quality under community input, and plugs into existing synbio / biosecurity ecosystems — without compromising on the cryptographic and deterministic invariants that make it trustworthy.

---

## 1. Target Stakeholder Groups

Realistic contributors and users in priority order:

1. **Academic synbio researchers** — iGEM teams, university synbio labs. Likely to run the firewall in shadow mode; valuable for corpus and FP-rate feedback.
2. **Biosafety / biosecurity professionals** — IBC members, university biosafety officers, government biosecurity staff. Likely to review threat model and operational procedures; valuable for policy-layer contributions.
3. **Safety-critical open-source developers** — Rust community with embedded/aerospace/medical backgrounds. Likely to contribute to core code (already proven on the robotics sibling).
4. **Regulatory/policy researchers** — think tanks, academic policy programs. Likely to contribute to compliance documentation + threat-model revisions.
5. **Synbio standardization orgs** — IGSC, BioStandards, iGEM Registry. Partnership-level, not individual contribution.
6. **International biosafety communities** — WHO, EU ERA, Asian consortiums. Long-term adoption relationships.

Explicitly not targeted: consumer/hobbyist synbio community. Not a hostility — they are not the audience for cryptographic oversight infrastructure.

---

## 2. Engagement and Outreach

### 2.1 Venues

- **Conferences**: SynBioBeta, ASM Biothreats, International Biosafety Symposium, USENIX Security (for crypto/systems work), SFN-style AI-safety events. Present from day one; the firewall is far more interesting to these communities than random-thing-on-GitHub.
- **Workshops**: 1–2 hands-on workshops per year co-located with partner institutions. Format: 4 hours, deploy the firewall on a lab machine, run a shadow campaign, review the audit log.
- **Curricula**: contribute case-study material to biosafety courses and synbio curricula. 1–2 pages each, plus runnable demo.
- **Publications**:
  - Engineering paper targeting a venue like Nature Biotechnology / Nature Methods — infrastructure description.
  - Security paper targeting USENIX Security / IEEE S&P — formal threat model and adversarial-testing results.
  - Policy paper targeting Science or a journal like Biosecurity and Bioterrorism — governance framework.

### 2.2 Digital presence

- **Repository** as canonical home. README is the front door; it leads with BLUF problems/solutions.
- **Project website** (minimal, static) summarizing scope + linking to docs + linking to paper preprints.
- **Mailing list** for announcements (low-traffic, opt-in).
- **Security-advisories channel** for coordinated disclosure (see §5.1).
- No social media primary presence; use sparingly to amplify publications. The community is small, professional, and reachable without it.

### 2.3 First-year outreach plan

- Month 1–2: threat model + architecture paper preprint on arXiv.
- Month 3: present at nearest synbio/biosecurity conference.
- Month 4–6: three partner-institution shadow deployments; collect data.
- Month 7: publish shadow-mode results.
- Month 9–12: workshop series (3 workshops); contribute to one curriculum.

---

## 3. Repository Structure and Governance

### 3.1 Code organization

Modular by design (already shipped):
- `crates/invariant-biosynthesis-core/` — safety-critical. High review bar. Security team must approve.
- `crates/invariant-biosynthesis-{sim,eval,fuzz}/` — testing infrastructure. Medium review bar.
- `crates/invariant-biosynthesis-cli/` — user interface. Standard review bar.
- `crates/invariant-biosynthesis-platforms/{twist,emerald,...}/` (future) — platform adapters. Each has an adapter maintainer; core team reviews only the crypto-boundary slices.
- `docs/` — documentation. Pull requests welcome. Accuracy + clarity reviewed.
- `corpora/` — test data. Contributions via signed commits referencing provenance.

### 3.2 Contribution tiers

- **Documentation / typos**: one reviewer, merge quickly.
- **Testing / benchmarks / new adversarial cases**: two reviewers, one from core.
- **Adapter / platform integration**: adapter maintainer + core reviewer for crypto boundary.
- **Core safety-critical code** (`authority/`, `audit.rs`, `validator.rs`, `invariants/*`): minimum two core reviewers with explicit security team sign-off. No single-reviewer merges. Cryptographic primitive changes require additional external-auditor review before release.

### 3.3 Code style and quality

- Rust edition 2021, `clippy -D warnings`, rustfmt enforced in CI.
- `#![forbid(unsafe_code)]` throughout.
- `#[serde(deny_unknown_fields)]` codebase-wide (threat model AV-8).
- No panics in non-test code paths — `Result` or fail-closed explicit handling.
- Documentation comment on every pub item; broken-link check in CI.
- License header on every source file.

### 3.4 Issue management

- Issue templates: bug report, feature request, security advisory (link to private channel), documentation request.
- Labels: `good-first-issue`, `help-wanted`, `security`, `blocked-external` (e.g., waiting on SecureDNA protocol publication).
- Triage cadence: weekly by a rotating core maintainer.
- SLAs: acknowledgment within 7 days; substantive response within 30 days.

### 3.5 Release management

- Semantic versioning.
- `0.x.y` until Guardian-mode deployment at ≥3 institutions.
- Pre-1.0 breaking changes allowed with migration notes; post-1.0 breaks gated by major-version bump.
- Each release passes Stage 1 exit criteria (§Step 8).
- Security releases fast-tracked: out-of-band publish, pinned advisory, upgrade path documented.

### 3.6 Governance

- **Initial**: benevolent dictator (original maintainer).
- **By year 2**: technical steering committee (TSC) of 5–7 including at least one biosafety professional, one external security researcher, and representation from at least 2 partner institutions.
- **TSC responsibilities**: release approvals, scope disputes, code-of-conduct decisions, conflict of interest.
- **Code of conduct**: Contributor Covenant, with a biosafety-specific addendum about dual-use research ethics.

---

## 4. Security and Safety Considerations

### 4.1 Responsible disclosure

- Private `security@` email (signed); GPG key published.
- 90-day default disclosure window, negotiable.
- Advisory-registry entry per fix (RustSec, GitHub advisory).
- Bug bounty: none in v1; possibly through partner institution or HackerOne later.

### 4.2 Code audit

- External audit by a recognized firm before v1.0.
- Re-audit on major releases.
- Informal continuous review via bug-bounty / researcher engagement.

### 4.3 Dual-use research oversight

Tension: the firewall itself is dual-use. A well-documented attack surface informs defenders AND attackers.

Policy decisions:
- Threat model and firewall architecture: PUBLIC. Security through obscurity is not security; adversaries reverse-engineer regardless.
- Adversarial test corpus: benign cases PUBLIC; hazardous cases RESTRICTED (access control per §Step 8 §7.2).
- Full hazardous-sequence datasets: never committed to the repo; distributed via partner-institution channels.
- New attack vector research: coordinated with defender community before publication; shadow-fix period before public CVE.

### 4.4 Export control compliance

- Firewall cryptographic content: Ed25519 + SHA-256 are mass-market. EAR 5D002 open-source exception applies. Safe for global distribution.
- BUT: Australia Group may evolve controls specific to AI biosafety tooling. Monitor; file re-review annually.
- Foreign contributor handling: standard open-source contribution model; no deemed-export concern for public-facing work.

### 4.5 Legal and liability

- MIT license.
- CLA: not required (standard for open-source biosecurity projects to avoid CLA friction).
- DCO (Developer Certificate of Origin): required on every commit.
- Warranty disclaim per license.
- Partner institutions sign deployment agreements separately, covering operational liability.

### 4.6 Coordination with authorities

- One designated liaison contact (rotating among TSC).
- Proactive engagement with NIST, NIH, CDC-biosafety, FBI-WMD when material work warrants.
- Reactive engagement on incidents: institution-first, authorities via institutional channels.

---

## 5. Ecosystem Integration

### 5.1 Interoperability

- **GenBank / NCBI** data format support in sequence invariants.
- **SBOL** (Synthetic Biology Open Language) — import/export for protocol descriptions.
- **Autoprotocol** — Strateos/Transcriptic format; bundle translation per Step 5.
- **Symbolic Lab Language (SLL)** — Emerald Cloud Lab.
- **Open Chem APIs**: ChEMBL, PubChem via their REST.
- **CWC declaration formats** for OPCW compliance output.

### 5.2 Standards participation

- ISO/TC 276 (biotechnology) — observer → participant as contributor bandwidth allows.
- IGSC — formal membership when institutional pathway opens.
- IEEE synbio standards — monitor.

### 5.3 API stability

Stable external API surface:
- `SynthesisBundle` serde format (versioned).
- `ExecutionToken` serde format.
- HTTP endpoints for `validate`, `attest`, `audit-export`, `health`.
- Unix socket for local integrations.

Breaking changes follow SemVer.

### 5.4 Compatibility testing

- Reference-conformance test suite runnable by third-party integrators.
- Conformance badge issued on successful suite run (similar to W3C CSS compliance).

### 5.5 Federation protocols

- Cross-institution audit-log replication format (Merkle-root witness).
- Shared corpus format for adversarial cases (versioned signed bundles).
- Trust-root-advertisement federation (WebFinger-style discovery from a domain).

Federation happens among willing institutions; not a centralized service.

---

## 6. Partnerships

### 6.1 Academic

- Technology-transfer offices: the project's MIT license is permissive; derivative research is encouraged.
- Joint grant applications: NSF SaTC, NIH R01 biosafety, DARPA biosecurity calls.
- Student engagement: iGEM teams, Rust-for-Science initiatives.

### 6.2 Industry

- **Pharma R&D**: private engagements; institution integrations; certified vendor integrations.
- **Synthesis platform vendors**: co-develop platform adapters; vendor certification program (§Step 5 §5.1).
- **Cloud labs**: multi-tenant integration patterns; tenant-scope security model.

### 6.3 Government

- NIH / CDC: primary biosafety + NIAID.
- DHS CISA: critical-infrastructure AI security.
- FBI WMD directorate: biosecurity.
- DoD (DARPA, DTRA): biodefense research.
- DoE (national labs): high-assurance deployments.
- International: EU Horizon funding; UK Research and Innovation; Japan AMED.

### 6.4 International

- WHO pandemic-preparedness programs.
- OECD working groups on biosafety/biosecurity.
- Biological Weapons Convention (BWC) tech-review processes.

### 6.5 Intellectual property

- Patent landscape review before v1.0.
- Where novel methods are patentable: file defensive patents; license royalty-free under the MIT license.
- Priority: prevent patent trolling, not extract rents.

---

## 7. Sustainability

### 7.1 Funding

Realistic multi-source mix:
- **Grants**: NSF SaTC, NIH R01/U01, DARPA, NNSA, private foundations (Gates, OpenPhil, LTFF). Multi-year cycles; apply early.
- **Corporate sponsorship**: preserving open-source principles via open-collective or similar. Pharma and synthesis-vendor sponsors likely.
- **Institutional support**: partner institutions contribute maintainer time.
- **Services**: optional paid services (custom integration, institutional training, audit support) — revenue supports free-tier infra.
- **Infrastructure**: GitHub (free for open-source), sponsored CI time, hosting grants from Linux Foundation / CNCF / similar if project graduates to foundation hosting.

Revenue target for Phase-3/4 sustainability: ~ $800k/year covers a lead engineer + security contractor + ops + travel + audits.

### 7.2 Contributors and recognition

- **Maintainer path**: documented. Active contributors get commit bits after demonstrated reliability on non-core areas; core-area bits require additional TSC review.
- **Credit**: AUTHORS file, paper authorship for substantive contributions, institutional affiliations acknowledged.
- **Community events**: semi-annual contributor call; annual in-person meetup at a conference.

### 7.3 Bus factor

- Minimum two maintainers with full commit + release + security rights.
- Runbooks documented for every operational role.
- Audit log + infrastructure recoverable from documentation by any qualified engineer.

### 7.4 Legal entity

- Early: hosted under an existing nonprofit (Linux Foundation, OpenSSF, or similar).
- Later: potentially own 501(c)(3) if scale justifies.
- Helps with funding receipt + liability isolation.

---

## 8. Impact Measurement

### 8.1 Adoption

- Institutions running the firewall (anonymized count).
- Partner institutions in shadow vs Guardian mode.
- Synthesis platforms with certified adapters.
- Bundles validated per quarter (aggregate, privacy-preserving).

### 8.2 Safety impact

- Hazardous bundles rejected (counts; specifics not released).
- Near-miss events reported.
- False-negative events (zero-tolerance metric, published).
- Incident-response time.

### 8.3 Research output

- Publications citing or using the firewall.
- External security advisories disclosed.
- Academic + industry talks referencing the project.

### 8.4 Policy influence

- Regulatory citations.
- Standards contributions adopted.
- Legislative references.

### 8.5 Educational impact

- Courses using firewall material.
- Workshops delivered.
- Early-career researchers trained on the codebase.

### 8.6 International

- Cross-border collaborations via the federation protocol.
- Adoption in non-US jurisdictions.
- Technology-transfer outcomes.

Dashboards published annually, respecting partner-institution confidentiality.

---

## 9. Phasing

### Year 0 (Phase 1)
Foundation: repo public, architecture + threat-model papers posted, first workshop, first adapter (Twist).

### Year 1 (Phase 2)
Integrations: 3 platforms certified, 3 partner-institution shadow deployments, first third-party security audit, SOC 2-ready documentation.

### Year 2 (Phase 3)
Validation: Guardian-mode pilots, regulatory engagement formalized, first TSC convened, contributed to ISO/IGSC work.

### Year 3 (Phase 4)
Production: multi-institution production deployments, FIPS 140 via HSM, EU AI Act conformity, international partnerships.

### Year 4+ (Ongoing)
Ecosystem: federation at scale, curriculum integration, sustainable funding model, v1.0 stable.

Milestones are ambitious; slips are acceptable if the integrity of the firewall's core invariants is preserved. Better late and safe than early and wrong.
