# Regulatory Mapping (C2) — Design

| Field | Value |
|---|---|
| Status | Draft, approved in brainstorming 2026-11-03 |
| Date | 2026-11-03 |
| Target version | 1.1.0 (after 1.0.0; additive, schema 1.1) |
| Depends on | F deterministic inventory core (PR #91), C1 CycloneDX AI-BOM (PR #93) |
| Followed by | A1 per-agent capability profile; a per-regulation evidence report (option B below) is a possible later follow-up |

---

## 1. Problem

Quin reports risk signals tied to its own threat and control catalogue (T001–T014, C001–C014 in `rules/risk_taxonomy.yaml`). Teams that answer to the EU AI Act, ISO/IEC 42001 or the NIST AI RMF have to work out by hand which of their obligations a finding relates to. The taxonomy cites OWASP and Databricks DASF, but mentions regulations only in passing (C013).

C2 adds a crosswalk from Quin's controls to those three frameworks and shows it wherever controls already appear.

## 2. Goals

1. A single, validated mapping from each control C001–C014 to clauses of the EU AI Act, ISO/IEC 42001 and NIST AI RMF 1.0.
2. The mapping appears in four places: the generated risk-framework docs, the JSON/YAML report, the HTML report and SARIF.
3. The mapping is presented as informative ("relevant to"), never as a compliance verdict.
4. A bad edit (unknown clause ID, unmapped or unknown control) fails the tests.
5. Additive only: report schema 1.1 gains one optional field; nothing existing changes shape.

## 3. Non-goals

- Compliance verdicts, scoring or a per-regulation evidence report (option B in the brainstorm; possible later follow-up).
- Deciding whether a regulation applies (EU AI Act risk class, Annex III use cases): a code scan cannot see the use case.
- Mapping threats (T001–T014) directly; risk signals inherit references through their controls.
- Regulatory data in the CycloneDX BOM (C1 keeps risk information out of it).
- `skills scan` output (its findings carry no controls).
- General-purpose AI model obligations (EU AI Act Art. 53/55) and conformity assessment: nothing a code scanner finds is evidence for them.
- Reproducing ISO text: only clause IDs and short titles in Quin's own words.

## 4. Decisions

| # | Decision | Chosen | Rejected |
|---|---|---|---|
| D1 | What C2 produces | Crosswalk shown where controls appear | Per-regulation evidence report (later, optional); both at once |
| D2 | What is mapped | Controls only; signals inherit via their controls | Threats only; both |
| D3 | Where it appears | Docs, JSON/YAML, HTML, SARIF | A subset |
| D4 | Where the data lives | New `rules/regulatory_mapping.yaml` with a framework/clause catalogue | `regulatory_refs` inside `risk_taxonomy.yaml`; Python |
| D5 | Report shape | Top-level `controls` catalogue for controls referenced in the report | References repeated on every risk signal |

## 5. Data: `src/quin_scanner/rules/regulatory_mapping.yaml`

### 5.1 Shape

```yaml
disclaimer: >
  Informative mapping of Quin's controls to clauses that the evidence is relevant to.
  It is not a compliance assessment or legal advice; whether a framework applies, and how,
  depends on the use case and the organisation.
frameworks:
  - id: eu-ai-act
    name: EU AI Act
    version: Regulation (EU) 2024/1689
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    clauses:
      - {id: "Art. 14", title: Human oversight}
      ...
  - id: iso-42001
    ...
  - id: nist-ai-rmf
    ...
controls:
  C001:
    eu-ai-act: ["Art. 15"]
    iso-42001: ["A.6.2.2"]
    nist-ai-rmf: ["MEASURE 2.7"]
  ...
```

- Every framework has `id`, `name`, `version`, `url`, `clauses` (each `id`, `title`, optional `url`; a clause without `url` uses the framework's).
- Every control in `risk_taxonomy.yaml` has an entry under `controls`, with a key for every framework; a list may be empty when nothing fits.
- Clause titles are short labels in Quin's own words (ISO text is copyrighted; EU and NIST titles may follow the official ones).

### 5.2 Clause catalogue

**EU AI Act** (Regulation (EU) 2024/1689; link: EUR-Lex ELI)

| ID | Title |
|---|---|
| Art. 9 | Risk management system |
| Art. 10 | Data and data governance |
| Art. 11 | Technical documentation |
| Art. 12 | Record-keeping |
| Art. 13 | Transparency and information to deployers |
| Art. 14 | Human oversight |
| Art. 15 | Accuracy, robustness and cybersecurity |
| Art. 19 | Automatically generated logs |
| Art. 25 | Responsibilities along the AI value chain |
| Art. 26 | Obligations of deployers |
| Art. 50 | Transparency for certain AI systems |
| Art. 72 | Post-market monitoring |
| Art. 73 | Reporting of serious incidents |

**ISO/IEC 42001:2023 Annex A** (link: https://www.iso.org/standard/42001)

| ID | Title (Quin's wording) |
|---|---|
| A.2.2 | AI policy |
| A.3.2 | AI roles and responsibilities |
| A.3.3 | Reporting concerns |
| A.4.5 | System and computing resources |
| A.6.2.2 | System requirements and specification |
| A.6.2.4 | Verification and validation |
| A.6.2.6 | Operation and monitoring |
| A.6.2.7 | Technical documentation |
| A.6.2.8 | Event logging |
| A.7.2 | Data for development and enhancement |
| A.7.3 | Data acquisition |
| A.7.4 | Data quality |
| A.7.5 | Data provenance |
| A.8.2 | Documentation and information for users |
| A.8.4 | Communicating incidents |
| A.9.2 | Responsible use processes |
| A.9.4 | Intended use |
| A.10.3 | Suppliers |

**NIST AI RMF 1.0** (link: https://www.nist.gov/itl/ai-risk-management-framework)

| ID | Title |
|---|---|
| GOVERN 1.1 | Legal and regulatory requirements understood and managed |
| GOVERN 1.6 | Inventory of AI systems |
| GOVERN 2.1 | Roles and responsibilities documented |
| GOVERN 6.1 | Third-party risk policies |
| GOVERN 6.2 | Contingency for third-party failures |
| MAP 3.3 | Targeted application scope specified |
| MAP 3.5 | Human oversight processes defined |
| MEASURE 2.4 | Behaviour monitored in production |
| MEASURE 2.5 | Validity and reliability demonstrated |
| MEASURE 2.6 | Safety risks evaluated |
| MEASURE 2.7 | Security and resilience evaluated |
| MEASURE 2.8 | Transparency and accountability examined |
| MEASURE 2.10 | Privacy risk examined |
| MANAGE 2.3 | Response to previously unknown risks |
| MANAGE 2.4 | Mechanisms to supersede, disengage or deactivate |
| MANAGE 3.1 | Third-party risks monitored |
| MANAGE 3.2 | Pre-trained models monitored |
| MANAGE 4.1 | Post-deployment monitoring |
| MANAGE 4.3 | Incidents and errors communicated |

### 5.3 Mapping (approved 2026-11-03)

| Control | EU AI Act | ISO/IEC 42001 | NIST AI RMF |
|---|---|---|---|
| C001 Input Validation & Filtering | Art. 15 | A.6.2.2 | MEASURE 2.7 |
| C002 Output Validation & Handling | Art. 15 | A.6.2.4 | MEASURE 2.5, MEASURE 2.7 |
| C003 Access Control & Least Privilege | Art. 15 | A.9.4 | MEASURE 2.7 |
| C004 Supply Chain Security | Art. 15, Art. 25 | A.10.3 | GOVERN 6.1, GOVERN 6.2, MANAGE 3.1, MANAGE 3.2 |
| C005 Data Protection & Classification | Art. 10 | A.7.2, A.7.3 | MEASURE 2.10 |
| C006 Human Oversight & Approval Gates | Art. 14, Art. 26 | A.9.2 | MAP 3.5, MANAGE 2.4 |
| C007 Monitoring, Logging & Observability | Art. 12, Art. 19, Art. 26, Art. 72 | A.6.2.6, A.6.2.8 | MEASURE 2.4, MANAGE 4.1 |
| C008 Agent Governance & Boundaries | Art. 9 | A.6.2.2, A.9.4 | MAP 3.3 |
| C009 Testing & Adversarial Evaluation | Art. 9, Art. 15 | A.6.2.4 | MEASURE 2.6, MEASURE 2.7 |
| C010 Infrastructure Security | Art. 15 | A.4.5 | MEASURE 2.7 |
| C011 Model & Data Integrity | Art. 10, Art. 15 | A.7.4, A.7.5 | MEASURE 2.7 |
| C012 Rate Limiting & Resource Management | Art. 15 | A.4.5 | MEASURE 2.7 |
| C013 Transparency & AI Governance | Art. 11, Art. 13, Art. 50 | A.2.2, A.3.2, A.6.2.7, A.8.2 | GOVERN 1.1, GOVERN 1.6, GOVERN 2.1, MEASURE 2.8 |
| C014 Incident Response & Recovery | Art. 73 | A.3.3, A.8.4 | MANAGE 2.3, MANAGE 4.1, MANAGE 4.3 |

Every clause in 5.2 is used by at least one control; the loader rejects unused catalogue entries too, so the catalogue cannot drift.

## 6. Loader: `src/quin_scanner/regulatory.py`

- Loads the YAML once (`yaml.safe_load`, cached).
- `frameworks() -> list[Framework]` and `refs_for_control(control_id) -> list[RegulatoryRef]`, where `RegulatoryRef` has `framework` (id), `framework_name`, `id`, `title`, `url`. Order: frameworks in file order, clauses in the control's list order.
- `refs_for_label("C006: Human Oversight & Approval Gates")` parses the control ID before the first `:`; unknown or unparsable labels return `[]`.
- `validate()` raises `ValueError` listing every problem: control in the taxonomy without an entry, entry for a control not in the taxonomy, missing framework key, unknown clause ID, unused catalogue clause, duplicate IDs, missing required fields. A test calls it on the shipped file.

## 7. Where it appears

### 7.1 Docs

`scripts/generate_risk_framework_docs.py` (output `docs/risk-framework.md`, existing drift check):
- each control section gets a **Regulatory references** list grouped by framework, with links;
- a new **Regulatory crosswalk** section after the controls: the disclaimer, the framework versions with links, and the table from 5.3;
- the intro's list of sources gains the three frameworks.

### 7.2 JSON/YAML report

New optional top-level field `controls` (schema 1.1):

```json
"controls": {
  "C006": {
    "name": "Human Oversight & Approval Gates",
    "regulatory_refs": [
      {"framework": "eu-ai-act", "id": "Art. 14", "title": "Human oversight", "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"}
    ]
  }
}
```

- Contains every control referenced by any risk signal in the report (repo-level and per-agent `recommended_controls`), keyed and sorted by control ID. Empty object when none.
- Built deterministically from the static mapping; nothing from the LLM.
- `docs/schema/report-1.json` documents it as optional; `tests/schema_baseline/` is not touched.

### 7.3 HTML

Next to each control label on a risk signal (repo and agent level): compact chips, one per framework that has references, e.g. `EU Art. 14` · `ISO A.9.2` · `NIST MANAGE 2.4`. Hover (`title`) shows the clause title; each chip links to the crosswalk anchor in `docs/risk-framework.md` (same link base the report already uses for `#c003`). The page reads the data from `controls` in the embedded JSON; all values are rendered as text.

### 7.4 SARIF

- Each rule built from a risk signal gets `properties.tags`: one tag per clause of its controls, `<framework>/<slug>` with the clause ID lowercased, `.` kept, spaces and other characters replaced by `-` — e.g. `eu-ai-act/art-14`, `iso-42001/a.9.2`, `nist-ai-rmf/manage-2.4`. Sorted, deduplicated.
- Controls come from the threat's `recommended_controls` when the rule is a taxonomy threat, else from the signal's own `recommended_controls`.
- Vulnerability rules (CVE/GHSA) get the tags of C004 Supply Chain Security.
- Each such rule also gets `help.text`: `Relevant to (informative): EU AI Act Art. 14; ISO/IEC 42001 A.9.2; NIST AI RMF MANAGE 2.4.`
- Rules with no mapped controls get neither.

## 8. Errors

- The shipped YAML is validated by a test; at runtime the loader trusts it (no per-scan validation cost).
- A control ID that is in the taxonomy but has no references in a framework simply has fewer `regulatory_refs` (possibly `[]`). A label whose ID is not in the taxonomy at all (e.g. free text) gets no `controls` entry and no tags; nothing fails.

## 9. Testing

- Loader: shipped file validates; fixture files with each kind of error are rejected with a message naming the problem; `refs_for_label` parsing.
- Docs: drift check passes after regeneration; crosswalk table matches the YAML.
- JSON: `controls` holds exactly the referenced controls, sorted; validates against schema 1.1; 1.0 reports still validate.
- SARIF: tags and help text for a threat rule, a non-threat signal and a vulnerability rule; no tags when nothing maps; SARIF still validates against the SARIF schema test if one exists.
- HTML: chips render for repo and agent signals; hostile-looking text stays text; mobile width does not overflow.
- Determinism: `controls` and SARIF tags identical across `PYTHONHASHSEED` values.
- Corpus: snapshots unchanged (they do not include `controls`), `--check` exits 0.

## 10. Docs and release

- `docs/risk-framework.md` regenerated; README mentions the crosswalk in one line; CHANGELOG [Unreleased] `### Added` entry.
- Ships in 1.1.0 with F and C1. Branch `feat/regulatory-mapping`, based on `feat/cyclonedx-aibom`, PR stacked on #93.
