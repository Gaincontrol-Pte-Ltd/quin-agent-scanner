# RFC 0001: Risk Framework Documentation & Report Linking

| Field | Value |
|---|---|
| Status | Proposed |
| Author | @flypotato-ten |
| Created | 2026-04-22 |
| Target Version | 0.1.x |

---

## 1. Understanding Summary

- **What**: Extend `src/quin_scanner/rules/risk_taxonomy.yaml` with rich prose fields per threat and control; generate `docs/risk-framework.md` from it; make the HTML scanner report's control labels and risk-signal `↗` icons clickable links into that document.
- **Why**: The HTML report currently shows terse IDs (e.g., `C003: Access Control & Least Privilege`) with no path to authoritative context. The YAML header even references `docs/threats/threat-taxonomy.md` — a file that does not exist. This RFC closes that gap with a durable, generated reference doc.
- **Who for**: Developers, security reviewers, and auditors reading the HTML scanner report.
- **Non-goals**:
  - No change to scanner JSON output schema beyond one additive nullable field (`RiskIndicator.threat_id`).
  - No offline-bundled help content; links are external.
  - No UI modal / tooltip / in-report rendering of framework content.
- **Success criteria**:
  1. Every control and threat shown in the report resolves to a stable anchor in `docs/risk-framework.md`.
  2. The MD file is a generated artifact; drift from YAML fails CI.
  3. No regression in existing report UX (expand/collapse behavior preserved).

---

## 2. Assumptions

1. **GitHub URL base**: `https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/blob/main/docs/risk-framework.md`. Hardcoded. Reports generated from feature branches link to `main`'s version — acceptable drift.
2. **Anchors**: Generator emits explicit `<a id="cNNN"></a>` / `<a id="tNNN"></a>` so `#c003` / `#t001` stay stable regardless of heading edits.
3. **Generator invocation**: Standalone script at `scripts/generate_risk_framework_docs.py`. CI test (`--check` equivalent) compares committed MD to generated output and fails on mismatch. No pre-commit framework required.
4. **Scope**: HTML report only. JSON/stdout outputs unchanged.
5. **YAML schema extension is additive** — existing `recommended_controls`, `key_risk_indicators`, `applies_to`, etc. stay as-is. New fields are optional at the dataclass layer so the loader remains backward-compatible.
6. **Content source**: Drafted from existing local reference docs (`docs/OWASP-*`, `docs/Databricks-DASF-Reference.md`, `docs/OWASP-MAESTRO-Reference.md`). No web-sourced content. User reviews before merge.
7. **Links**: Open in a new tab (`target="_blank" rel="noopener"`), preserving the report view.
8. **Generator performance**: Generator runs in <1s for 28 entries; no external dependencies at generation time.

---

## 3. Decision Log

| # | Decision | Alternatives Considered | Why Chosen |
|---|---|---|---|
| 1 | Single MD file at `docs/risk-framework.md` | Split by type (threats.md + controls.md); per-entry files; hybrid | Simplest to maintain and link; 28 entries is small enough for one scroll |
| 2 | Hardcoded GitHub URL in HTML template | Relative path; configurable base URL; embed inline | Report is shared standalone (email/downloaded); relative paths break; configurability not needed yet |
| 3 | Deep content per entry (description, why-it-matters, how-to-implement, pitfalls, refs) | Minimal; standard; auto-only | Scanner is a security product — users benefit from actionable depth |
| 4 | Risk signals get `↗` icon (link to threat); controls become `<a>` (link to control) | Controls-only; everything linkified | Preserves click-to-expand UX; gives users a path to threat-level detail |
| 5 | YAML-first; MD is generated artifact | Manual sync; validation-only; partial generation | Zero drift guarantee; YAML already the runtime source |
| 6 | All 28 entries authored in one PR (PR 2) | Schema + stubs first, content in follow-ups | User explicitly chose this scope |
| 7 | Single-file YAML extension (Approach 1) | Split structural/content YAML; per-entry MD fragments | Co-location with existing taxonomy; no consumer code changes; small scale doesn't justify split |
| 8 | Three-layer pytest drift prevention | Pre-commit hook; separate CI job | Runs in existing suite; actionable failure messages; no new infrastructure |
| 9 | Add `threat_id: str \| None` to `RiskIndicator` | Skip threat `↗`; reverse-match KRI text to YAML | Makes threat provenance first-class; benefits JSON consumers too |
| 10 | Split into 2 PRs (prereq + main) | One atomic PR | Model-schema change deserves independent review; main PR becomes purely additive |
| 11 | Skip multi-agent-brainstorming review | Invoke it | Medium-impact, reversible, well-scoped change |

---

## 4. Final Design

### 4.1 YAML Schema Extension

File: `src/quin_scanner/rules/risk_taxonomy.yaml` (extended; additive).

**Threat entry** (new fields marked `# NEW`):
```yaml
- id: T001
  name: Input Manipulation & Prompt Injection
  category: Input Manipulation
  applies_to: [standard_ai, agentic_ai, mcp_enabled, multi_agent]
  key_risk_indicators: [...]
  recommended_controls: [C001, C002, C003, C006, C008]
  # NEW
  description: |
    Plain-language 1–2 paragraph explanation of the threat.
  why_it_matters: |
    Business/technical impact framing.
  attack_patterns:
    - Direct injection via user prompt
    - Indirect injection via retrieved content
  external_refs:
    - title: "OWASP LLM01:2025 — Prompt Injection"
      url: "https://genai.owasp.org/llmrisk/llm01-2025-prompt-injection/"
      local: "docs/OWASP-LLM-Top10.md"
```

**Control entry** (new fields marked `# NEW`):
```yaml
- id: C003
  name: Access Control & Least Privilege
  # NEW
  description: |
    Paragraph definition of the control.
  why_it_matters: |
    Consequences when this control is missing/weak.
  how_to_implement:
    - 4–7 verifiable, actionable bullets
  common_pitfalls:
    - Real-world failure modes
  external_refs:
    - title: "Source title"
      url: "https://..."
      local: "docs/OWASP-*.md"
```

`external_refs` is list-of-objects (not strings) so both canonical URL and local backup are addressable.

### 4.2 Generator Script

File: `scripts/generate_risk_framework_docs.py` (new).

```
load risk_taxonomy.yaml (via risk_taxonomy.load_taxonomy)
 → validate prose fields present + control refs resolvable
 → render Jinja2 template → MD string
 → write docs/risk-framework.md (or compare when --check)
```

Deps: `pyyaml` (existing), `jinja2` (new, dev dep).

Template file: `scripts/templates/risk-framework.md.j2`.

**Generated `docs/risk-framework.md` shape:**
```markdown
<!-- GENERATED FILE — do not edit directly. Source: src/quin_scanner/rules/risk_taxonomy.yaml -->
<!-- Regenerate with: uv run python scripts/generate_risk_framework_docs.py -->

# Quin Risk Framework
(intro — sources, how the report links here)

## Table of Contents
- Threats: [T001](#t001) ... [T014](#t014)
- Controls: [C001](#c001) ... [C014](#c014)

## Threats
<a id="t001"></a>
### T001: Input Manipulation & Prompt Injection
**Category** · **Applies to** · **Description** · **Why it matters**
**Attack patterns** · **Key risk indicators** · **Recommended controls** (linked)
**References** (link + local)
---
(repeat for T002–T014)

## Controls
<a id="c001"></a>
### C001: ...
**Description** · **Why it matters** · **How to implement** · **Common pitfalls**
**Threats mitigated** (back-links) · **References**
---
(repeat for C002–C014)
```

Cross-links (threats → recommended controls; controls → threats that reference them) are derived by the generator; not hand-maintained.

### 4.3 Drift-Prevention Tests

File: `tests/test_risk_framework_docs.py` (new). Three layers:

1. **Exact-match drift**: regenerate MD in memory; assert equal to committed `docs/risk-framework.md`. Failure message includes regen command.
2. **Schema completeness**: every threat has description, why_it_matters, attack_patterns, external_refs; every control has description, why_it_matters, how_to_implement, common_pitfalls, external_refs.
3. **Referential integrity**: all `recommended_controls` IDs resolve; all `external_refs.local` paths exist.

No network calls. Runs in existing pytest suite.

### 4.4 HTML Report Template Change

File: `src/quin_scanner/html_template.py` (modified).

Add at top of JS block:
```js
var DOCS_BASE = "https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/blob/main/docs/risk-framework.md";
```

Helper to linkify control labels:
```js
function controlLink(c){
  var m = /^(C\d{3}):/.exec(c);
  if(!m) return esc(c);
  var anchor = m[1].toLowerCase();
  return '<a href="'+DOCS_BASE+'#'+anchor+'" target="_blank" rel="noopener">'+esc(c)+'</a>';
}
```

Risk-signal `↗` icon rendered only when `threat_id` is present on the signal payload:
```js
var externalLink = threatId
  ? '<a class="risk-ext" href="'+DOCS_BASE+'#'+threatId.toLowerCase()+'" target="_blank" rel="noopener" title="View threat details">&#8599;</a>'
  : '';
```

Click handler: skip expand/collapse when the click target is a `.risk-ext` link (let navigation proceed).

**Security**: `href` built from hardcoded constant + regex-matched `[CT]\d{3}` — no untrusted interpolation. `esc()` still wraps label text. `rel="noopener"` paired with `target="_blank"` prevents reverse-tab-nabbing.

### 4.5 Model Change (PR 1 — Prereq)

File: `src/quin_scanner/models.py`.

```python
@dataclass
class RiskIndicator:
    signal: str
    recommended_controls: list[str] = field(default_factory=list)
    threat_id: str | None = None  # NEW — e.g., "T001"

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "recommended_controls": self.recommended_controls,
            "threat_id": self.threat_id,
        }
```

Call-site audit and update:
- LLM synthesis path: prompt contract extended to return `threat_id` per KRI; parser sets the field.
- Hardcoded fallback at `orchestrator.py:1069` (patch/dependency risk): pass `threat_id="T003"` (AI Supply Chain).

Validation test: all emitted `RiskIndicator` values have a valid `threat_id` matching `^T\d{3}$` and resolving to a real threat in the taxonomy.

---

## 5. Implementation Plan

### PR 1 — `threat_id` plumbing (prereq)
- `models.py`: add field + `to_dict()` update.
- Audit all `RiskIndicator(...)` constructors.
- Update LLM synthesis prompt/parser to surface threat_id.
- Update hardcoded orchestrator construction site.
- Test: format + taxonomy-resolution validation.
- CHANGELOG entry.

### PR 2 — Framework doc + linking (main)
Files:
- ✏️ `src/quin_scanner/rules/risk_taxonomy.yaml` — prose fields for all 14 threats + 14 controls.
- ✏️ `src/quin_scanner/risk_taxonomy.py` — extend `Threat`/`Control` dataclasses with optional prose fields.
- ➕ `scripts/generate_risk_framework_docs.py`
- ➕ `scripts/templates/risk-framework.md.j2`
- ➕ `docs/risk-framework.md` (generated, committed)
- ➕ `tests/test_risk_framework_docs.py`
- ✏️ `src/quin_scanner/html_template.py` — `DOCS_BASE`, `controlLink()`, `↗` render, handler update.
- ✏️ `pyproject.toml` — `jinja2` in dev deps.
- ✏️ `CHANGELOG.md` — entry.

### Content sourcing (PR 2)

| quin ID | Primary source(s) in `docs/` |
|---|---|
| T001 Prompt Injection | `OWASP-LLM-Top10.md` (LLM01), `OWASP-Agentic-Top10-Reference.md` (ASI01) |
| T002 Sensitive Data Exposure | `OWASP-LLM-Top10.md` (LLM02, LLM07), `OWASP-MCP-Top10-Reference.md` |
| T003 AI Supply Chain | `OWASP-LLM-Top10.md` (LLM03), `OWASP-Agentic-Top10-Reference.md` (ASI04) |
| T004 Data & Model Poisoning | `OWASP-LLM-Top10.md` (LLM04), `OWASP-Agentic-Top10-Reference.md` (ASI06) |
| T005 Unsafe Output & RCE | `OWASP-LLM-Top10.md` (LLM05), `OWASP-Agentic-Top10-Reference.md` (ASI05) |
| T006 Excessive Permissions | `OWASP-LLM-Top10.md` (LLM06), `OWASP-Agentic-Top10-Reference.md` (ASI02, ASI03) |
| T007 Misinformation & Hallucination | `OWASP-LLM-Top10.md` (LLM09) |
| T008 Resource Abuse | `OWASP-LLM-Top10.md` (LLM10) |
| T009 Inter-Agent Communication | `OWASP-Agentic-Top10-Reference.md` (ASI07), `OWASP-MCP-Top10-Reference.md` |
| T010 Cascading Failures | `OWASP-Agentic-Top10-Reference.md` (ASI08), `OWASP-MAESTRO-Reference.md` |
| T011 Rogue Agents | `OWASP-Agentic-Top10-Reference.md` (ASI10), `OWASP-MAESTRO-Reference.md` |
| T012 Insufficient Observability | `Databricks-DASF-Reference.md`, `OWASP-LLM-Top10.md` (LLM08) |
| T013 Unmanaged AI Infrastructure | `OWASP-MCP-Top10-Reference.md`, `Databricks-DASF-Reference.md` |
| T014 Human-AI Trust Manipulation | `OWASP-Agentic-Top10-Reference.md` (ASI09) |
| C001–C014 | synthesized from OWASP mitigations + DASF controls + MAESTRO countermeasures |

---

## 6. Edge Cases & Risks

| # | Concern | Mitigation |
|---|---|---|
| 1 | Generator run with missing prose field | Generator fails fast with per-field message; no partial output |
| 2 | Old scanner JSON lacks `threat_id` | `↗` icon simply not rendered; control links still work |
| 3 | Ref to nonexistent local doc | Test fails in PR 2; broken local ref never ships |
| 4 | YAML loader back-compat | Dataclass fields default to `None`/`[]`; consumers unaffected |
| 5 | Report XSS via crafted signal | Label wrapped in `esc()`; URL built from constants + regex-matched IDs; `rel="noopener"` |
| 6 | Doc size growth (YAML ~225 → ~800 lines) | Single-file remains navigable; block literals keep prose readable in diffs |
| 7 | Branch-link drift (report from feature branch links to main doc) | Accepted tradeoff per Assumption #1; can revisit if needed |
| 8 | Very long descriptions bloat the MD | No hard cap; can enforce soft cap in tests if patterns emerge |

---

## 7. Exit Criteria (from Brainstorming Skill)

- [x] Understanding Lock confirmed
- [x] Design approach explicitly accepted (Approach 1)
- [x] Major assumptions documented
- [x] Key risks acknowledged
- [x] Decision log complete

Ready for implementation.
