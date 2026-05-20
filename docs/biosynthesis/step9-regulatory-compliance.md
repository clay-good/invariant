# Step 9 — Regulatory Compliance and Certification Strategy

**Status:** v0.1 design. Implements `spec.md` Step 9.

The firewall operates at the intersection of biosafety, export control, research ethics, and AI governance. This document does not replace institutional counsel — it specifies how the firewall's features map onto existing regulatory regimes and what certification pathways exist.

---

## 1. Regulatory Landscape

### 1.1 Biosafety and public health

| Regime | Applies to | Firewall contribution |
|---|---|---|
| HHS Select Agent Program (42 CFR 73) | Possession/transfer of ~70 listed agents | D1 invariant screens against SAP list; audit log is SAP-audit-ready |
| NIH Guidelines for rDNA/synthetic nucleic acids | All NIH-funded recombinant work | NIH Risk Groups encoded in `scope_tags.bsl_max`; per-protocol audit artifacts |
| FDA oversight of synbio products | Therapeutic synbio products (INDs/BLAs) | Audit log supports GxP-compatible record-keeping (21 CFR Part 11 signatures) |
| USDA APHIS biotechnology framework | GMO plants, animals, organisms | Out-of-scope for synthesis firewall; interoperable via scope tags |
| EPA TSCA biotech risk assessment | New microbes for commercial use | TSCA pre-manufacture notice generation from audit log |
| WHO IHR + pandemic preparedness | Cross-border pathogen-research disclosure | Cross-institutional audit replication per §Step 4 §6 |

### 1.2 Export control and dual-use

| Regime | Applies to | Firewall contribution |
|---|---|---|
| EAR Commerce Control List (biological) | Listed agents and equipment export | `export_jurisdiction` in scope_tags; cross-jurisdiction delegations logged |
| ITAR (defense biological articles) | Defense-classified biological work | Hard gate at PCA layer; classified-work scope_tag |
| Australia Group | 40+ country dual-use controls | D1/D4 flag AG-listed items; participation in AG updates (Step 6) |
| Wassenaar Arrangement | Dual-use + military tech | Cryptographic exports of firewall itself (mass-market, EAR only) |
| Chemical Weapons Convention | Schedule 1/2/3 substances | C1 invariant + OPCW declaration generator |
| Nuclear Suppliers Group (dual-use bio parts) | Specific edge cases | Flagged at scope-tag level |

### 1.3 Research ethics and institutional oversight

- **IRB**: human-subjects protection. Firewall's `scope_tags.ethics_approval_ref` carries the IRB protocol ID; any bundle lacking a valid reference for human-subjects-relevant work is rejected.
- **IBC**: institutional biosafety committee. Same mechanism via `scope_tags.ibc_approval_ref`.
- **NSABB**: National Science Advisory Board for Biosecurity — DURC oversight. Firewall audit artifacts generated in the format NSABB review expects.
- **Research Security Program (NSPM-33)**: foreign-collaboration disclosure. Cross-institutional cross-certificates (Step 4 §6) cover the disclosure trail.
- **Deemed-export (EAR Part 734.13)**: release of controlled tech to foreign persons on US soil. Operator-citizenship metadata in PCA carries this; jurisdiction monitor flags potential deemed exports.

### 1.4 AI governance

- **NIST AI Risk Management Framework (AI RMF)**: voluntary but increasingly referenced. Firewall implements "GOVERN-MAP-MEASURE-MANAGE" structurally: scope_tags = govern, invariant set = map, shadow/Guardian testing = measure, incident response = manage.
- **ISO/IEC 23894 (AI risk management)**: parallel to AI RMF; compatible.
- **ISO/IEC 42001 (AI management systems)**: organizational-level certification; firewall is one component of an institution's AI MS.
- **IEEE P7000 series**: autonomous systems ethics; mostly concept-level.
- **EU AI Act**: high-risk AI systems in health and critical infrastructure. Biosynthesis-planning AI probably qualifies as high-risk. Firewall documentation provides the "risk management system" and "record-keeping" and "accuracy/robustness" requirements.
- **Algorithmic accountability/explainability**: deterministic invariants are trivially explainable ("bundle rejected because D1 matched entry #147 with 94% similarity"); cognitive-layer model decisions are the LLM vendor's responsibility.
- **GDPR/HIPAA**: data-protection for sequence data linkable to individuals. Audit-log minimization (Step 6 §6.2, §6.3) addresses this.

---

## 2. Certification Pathways

### 2.1 Functional safety

- **IEC 61508** — generic functional-safety standard. Adaptable to biosynthesis: treat the firewall as a safety-related system with Safety Integrity Level (SIL) classification. SIL 2 or SIL 3 targets depending on deployment risk class.
- **ISO 13849** — safety of laboratory automation machinery. Performance Level d or e for the firewall → platform control path.
- Pursuit: on-demand when a regulated customer (pharma GMP, government lab) requires.

### 2.2 Cybersecurity

- **Common Criteria EAL4+**: multi-year, expensive, usually only on government/defense demand.
- **ISO/IEC 27001** (information security management): more common; institutional-level.
- **SOC 2 Type II**: relevant if firewall is offered as SaaS.
- **FedRAMP** (US government cloud): same only for federal cloud deployments.
- **FIPS 140-2/3 cryptographic validation**: covered in Step 7 §7.1.

### 2.3 Lab-equipment safety

- **ANSI/UL 61010**: laboratory equipment. Relevant for the firewall appliance + synthesizer co-deployment.
- **UL 2900 series**: cybersecurity for network-connectable products.

### 2.4 Quality management

- **ISO 9001**: generic QMS.
- **21 CFR Part 11**: electronic records/signatures. Audit log format is compliant by design (signed entries, immutable).
- **GAMP 5**: GxP computerized systems. Relevant if firewall used in drug-manufacturing context.

### 2.5 Prioritization

v1 pragmatic certification stack:
- Internal: SOC 2 Type II-ready documentation.
- External: third-party security audit of authority/ and screening/ modules; annual pentest.
- FIPS 140: deployment-layer via HSM vendor.

Higher-assurance certifications pursued as customer demand justifies.

---

## 3. Compliance Documentation

Each shipped version produces:

### 3.1 System documentation
- Architecture spec (this repo's `docs/` tree + `spec.md`).
- Threat model (this repo's `docs/threat-model.md`).
- Safety analysis (FMEA — see §4).
- Risk assessment + mitigation matrix (Step 2 §5 defensive summary).
- Statement of applicability to each regulatory regime.

### 3.2 Operational documentation
- Deployment guide per deployment model (Step 7 §6).
- Ceremony scripts under `docs/ceremonies/`.
- Training materials for operators, administrators, and reviewers.
- Emergency-response playbook.
- Backup/DR procedures.

### 3.3 Audit artifacts
- Audit-log format spec.
- Audit-log retention policy (default: indefinite; regulators may require specific minimums).
- Incident-reporting procedure.

### 3.4 Quality management
- Release process documented; CHANGELOG + migration notes per release.
- Bug-triage and fix-verification procedures.
- Continuous-improvement metrics: FP/FN rates, override rates, time-to-mitigation for new threats.

---

## 4. FMEA — Failure Modes and Effects

High-level summary (full FMEA lives in a separate spreadsheet under `docs/fmea/`). Each row: failure mode, effect, severity (S), occurrence (O), detection (D), RPN (S×O×D).

Top failure modes:

| Failure | Effect | S | O | D | RPN | Mitigation |
|---|---|---|---|---|---|---|
| L0 key compromise | All trust broken | 10 | 1 | 3 | 30 | HSM + multi-party custody + audit |
| Invariant FN on select agent | Dangerous synth executed | 10 | 1 | 2 | 20 | Multi-source DB + shadow mode + FN testing |
| Invariant FP on legit research | Research blocked | 3 | 4 | 2 | 24 | Shadow mode concordance; override path |
| Audit log tampered | Forensic trail lost | 9 | 1 | 2 | 18 | Hash chain + Merkle witness + replication |
| HSM unavailable | Firewall stops signing | 6 | 3 | 1 | 18 | Redundant HSMs; fail-closed semantics |
| DB staleness | Invariant fails closed | 4 | 4 | 1 | 16 | Monitoring + publisher SLA |
| Platform signature check bypassed | Vendor-side compromise | 10 | 2 | 4 | 80 | Platform certification; attestation reconciliation |

`docs/fmea/` in Step 9 implementation carries full ~50-row FMEA.

---

## 5. International Harmonization

### 5.1 Mutual recognition

Safety certification issued in one jurisdiction is not auto-recognized in another. Strategy:
- Pursue local certifications per-market on customer demand.
- Where IECEE-CB scheme covers it (electrical safety), leverage.
- For AI/biosafety, no mutual-recognition regime exists yet; contribute to ISO/IEC harmonization workstreams.

### 5.2 Standards participation

- ISO/TC 276 (Biotechnology) — relevant subcommittees.
- IEEE synbio standards working groups.
- IGSC technical working group.
- Attend + contribute, do not lead unless a contributor has the bandwidth and mandate.

### 5.3 Regulatory sandboxes

- FDA's regulatory sandbox programs for digital-health AI: potentially applicable to diagnostic/therapeutic-synth platforms using the firewall.
- UK MHRA, EU EMA have parallel programs.

### 5.4 Stakeholder engagement

Proactive outreach to:
- HHS ASPR (preparedness and response).
- DHS CISA (critical infrastructure cybersecurity).
- FBI WMD directorate (biosecurity).
- State-level biosafety offices.

Messaging: firewall is *complementary* to existing oversight, not a replacement.

---

## 6. Liability and Legal

Out-of-scope for this doc in depth; flag areas needing counsel:
- MIT license disclaims warranty; institutional deployments still carry local liability.
- Indemnification for firewall vendors packaging this — their contracts.
- Insurance: cyber-liability + E&O relevant.
- Patents: priority search on invariant methods; file where appropriate (subject to open-source license commitments).

---

## 7. Certification Roadmap

| Year | Target |
|---|---|
| Y0 (Phase 1) | Internal SOC 2-ready docs; third-party security audit of crypto modules |
| Y1 (Phase 2) | FIPS 140-3 via HSM; ISO 27001 readiness if org pursues |
| Y2 (Phase 3) | IEC 61508 SIL 2 if any deployment requires; ISO 42001 participation |
| Y3 (Phase 4) | Common Criteria EAL4+ on customer demand; EU AI Act conformity assessment |
| Ongoing | Annual pentest; FMEA review; threat-model revision; standards participation |

Priorities shift with customer pipeline; this is a planning baseline, not a commitment.
