"""
Vulnerability checker for detected agentic-AI frameworks.

Queries two sources and merges results (deduped by CVE ID):

1. OSV.dev — authoritative structured CVE database (free, no auth).
2. LLM web search — configurable provider (Perplexity, Gemini, OpenAI, Anthropic)
   uses the model's native web-search tool to find recent advisories and exploits.

Failures degrade gracefully: a warning is written to stderr and the scan
continues. If both sources fail the scan report simply has no vulnerabilities.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml

from quin_scanner.config import ScannerConfig
from quin_scanner.models import Vulnerability

_OSV_URL = "https://api.osv.dev/v1/query"
_LOOKUP_PATH = Path(__file__).parent / "rules" / "frameworks_lookup.yaml"


def _load_ecosystems() -> dict[str, dict[str, str]]:
    if not _LOOKUP_PATH.exists():
        return {}
    data = yaml.safe_load(_LOOKUP_PATH.read_text(encoding="utf-8")) or {}
    return data.get("ecosystems", {}) or {}


def _warn(msg: str) -> None:
    print(f"[vuln-check] {msg}", file=sys.stderr, flush=True)


@dataclass(frozen=True)
class FrameworkRef:
    name: str           # canonical framework name e.g. "CrewAI"
    version: str        # base version e.g. "0.80.0"
    ecosystem: str      # OSV ecosystem e.g. "PyPI"
    package: str        # canonical package name e.g. "crewai"


# ── Framework string parsing ────────────────────────────────────────────────

_VERSION_IN_STRING = re.compile(r"\s+(\d+(?:\.\d+)+)\s*$")


def parse_framework_ref(framework: str) -> FrameworkRef | None:
    """Parse a framework string like 'CrewAI 0.80.0' into a FrameworkRef.

    Returns None if the string has no version or the framework has no known
    ecosystem mapping.
    """
    if not framework or framework == "unknown":
        return None
    m = _VERSION_IN_STRING.search(framework)
    if not m:
        return None
    version = m.group(1)
    name = framework[: m.start()].strip()
    if not name:
        return None
    eco_map = _load_ecosystems()
    entry = eco_map.get(name)
    if not entry:
        return None
    return FrameworkRef(
        name=name,
        version=version,
        ecosystem=entry["ecosystem"],
        package=entry["package"],
    )


# ── Severity helpers ────────────────────────────────────────────────────────

_SEVERITY_FROM_CVSS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]


def cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    for threshold, label in _SEVERITY_FROM_CVSS:
        if score >= threshold:
            return label
    return "unknown"


def _parse_cvss_vector_score(vector: str) -> float | None:
    """Extract a numeric score from a CVSS vector string if possible."""
    # OSV often stores CVSS vectors rather than raw scores. We can't derive
    # the score from a vector without a full CVSS library, so return None
    # and let the caller fall back to the severity tag.
    return None


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _normalise_severity(raw: str | None) -> str:
    if not raw:
        return "unknown"
    low = raw.strip().lower()
    if low in _SEVERITY_ORDER:
        return low
    return "unknown"


# ── OSV client ──────────────────────────────────────────────────────────────

def query_osv(ref: FrameworkRef, *, timeout: float = 10.0) -> list[Vulnerability]:
    """Call OSV.dev and return parsed Vulnerability records.

    Raises any httpx exception to the caller — the orchestrator layer is
    responsible for converting network errors into warnings.
    """
    payload = {
        "package": {"name": ref.package, "ecosystem": ref.ecosystem},
        "version": ref.version,
    }
    resp = httpx.post(_OSV_URL, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return _parse_osv_response(data, ref)


def _parse_osv_response(data: dict, ref: FrameworkRef) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for v in data.get("vulns", []) or []:
        vuln_id = v.get("id")                      # e.g. GHSA-xxxx or OSV id
        aliases = v.get("aliases", []) or []
        # Prefer CVE id from aliases if present
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None) or vuln_id

        # severity: prefer explicit severity list, then derive from CVSS score
        severity_tag = "unknown"
        cvss_score: float | None = None
        db_spec = v.get("database_specific") or {}
        sev_tag = db_spec.get("severity")
        if isinstance(sev_tag, str):
            severity_tag = _normalise_severity(sev_tag)
        for sev in v.get("severity", []) or []:
            score_val = sev.get("score")
            if isinstance(score_val, (int, float)):
                cvss_score = float(score_val)
                break
            if isinstance(score_val, str):
                # Try parsing "9.8" or a CVSS vector
                try:
                    cvss_score = float(score_val)
                    break
                except ValueError:
                    _parse_cvss_vector_score(score_val)

        if severity_tag == "unknown" and cvss_score is not None:
            severity_tag = cvss_to_severity(cvss_score)

        # Affected range text
        affected_text: str | None = None
        for aff in v.get("affected", []) or []:
            pkg = aff.get("package", {}) or {}
            if pkg.get("name", "").lower() != ref.package.lower():
                continue
            ranges = aff.get("ranges", []) or []
            parts: list[str] = []
            for rg in ranges:
                for ev in rg.get("events", []) or []:
                    if "introduced" in ev:
                        parts.append(f">={ev['introduced']}")
                    elif "fixed" in ev:
                        parts.append(f"<{ev['fixed']}")
            if parts:
                affected_text = ", ".join(parts)
                break

        out.append(
            Vulnerability(
                cve_id=cve_id,
                severity=severity_tag,
                cvss_score=cvss_score,
                published=v.get("published"),
                summary=(v.get("summary") or v.get("details") or "")[:500],
                source="osv",
                source_url=_osv_source_url(v),
                affected_versions=affected_text,
            )
        )
    return out


def _osv_source_url(vuln: dict) -> str | None:
    for ref in vuln.get("references", []) or []:
        if ref.get("type") == "ADVISORY":
            return ref.get("url")
    refs = vuln.get("references", []) or []
    if refs:
        return refs[0].get("url")
    vid = vuln.get("id")
    if vid:
        return f"https://osv.dev/vulnerability/{vid}"
    return None


# ── Web search providers ────────────────────────────────────────────────────

_WEB_PROMPT = """You are a security researcher. Search the web for known
vulnerabilities, CVEs, or publicly disclosed security advisories affecting:

  Framework: {name}
  Version: {version}

Return ONLY a JSON array (no prose, no markdown fences). Each item must have:
  "cve_id": string or null       (e.g. "CVE-2024-12345" or "GHSA-xxxx-xxxx-xxxx")
  "severity": "critical" | "high" | "medium" | "low" | "unknown"
  "cvss_score": number or null   (0.0 to 10.0)
  "published": string or null    (ISO date, e.g. "2024-08-15")
  "summary": string              (1–2 sentences)
  "source_url": string or null   (URL to the advisory or discussion)

Only include items where the affected version range clearly includes {version}.
If none are found, return an empty array []."""


def _extract_json_array(text: str) -> list[dict]:
    """Best-effort extraction of the first JSON array in *text*."""
    # Strip markdown fences
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE)
    # Find first '[' ... matching ']'
    start = cleaned.find("[")
    if start < 0:
        return []
    depth = 0
    for i in range(start, len(cleaned)):
        c = cleaned[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(cleaned[start : i + 1])
                    return parsed if isinstance(parsed, list) else []
                except json.JSONDecodeError:
                    return []
    return []


def _vulns_from_web_items(items: list[dict], provider_tag: str, ref: FrameworkRef) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        severity = _normalise_severity(it.get("severity"))
        cvss_raw = it.get("cvss_score")
        cvss_score: float | None = None
        if isinstance(cvss_raw, (int, float)):
            cvss_score = float(cvss_raw)
        if severity == "unknown" and cvss_score is not None:
            severity = cvss_to_severity(cvss_score)
        out.append(
            Vulnerability(
                cve_id=it.get("cve_id"),
                severity=severity,
                cvss_score=cvss_score,
                published=it.get("published"),
                summary=(it.get("summary") or "")[:500],
                source=f"web:{provider_tag}",
                source_url=it.get("source_url"),
                affected_versions=None,
            )
        )
    return out


def query_web_search(
    ref: FrameworkRef,
    provider: str,
    *,
    timeout: float = 5.0,
    model_override: str | None = None,
) -> list[Vulnerability]:
    """Ask an LLM with web-search enabled for vulnerabilities.

    Supports: perplexity | gemini | openai | anthropic
    """
    prompt = _WEB_PROMPT.format(name=ref.name, version=ref.version)

    if provider == "perplexity":
        return _query_perplexity(prompt, ref, timeout=timeout, model=model_override or "sonar-pro")
    if provider in ("gemini", "google"):
        return _query_gemini(prompt, ref, timeout=timeout, model=model_override or "gemini-2.0-flash")
    if provider == "openai":
        return _query_openai_web(prompt, ref, timeout=timeout, model=model_override or "gpt-4o-mini")
    if provider == "anthropic":
        return _query_anthropic_web(prompt, ref, timeout=timeout, model=model_override or "claude-haiku-4-5-20251001")
    _warn(f"unknown vuln_search_provider {provider!r}")
    return []


def _query_perplexity(prompt: str, ref: FrameworkRef, *, timeout: float, model: str) -> list[Vulnerability]:
    api_key = os.environ.get("PERPLEXITY_API_KEY")
    if not api_key:
        _warn("PERPLEXITY_API_KEY not set; skipping web search")
        return []
    resp = httpx.post(
        "https://api.perplexity.ai/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    items = _extract_json_array(text)
    return _vulns_from_web_items(items, "perplexity", ref)


def _query_gemini(prompt: str, ref: FrameworkRef, *, timeout: float, model: str) -> list[Vulnerability]:
    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        _warn("GOOGLE_API_KEY not set; skipping web search")
        return []
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    resp = httpx.post(
        url,
        json={
            "contents": [{"parts": [{"text": prompt}]}],
            "tools": [{"google_search": {}}],
            "generationConfig": {"temperature": 0},
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    parts = (data.get("candidates", [{}])[0].get("content", {}).get("parts", []) or [])
    text = "".join(p.get("text", "") for p in parts)
    items = _extract_json_array(text)
    return _vulns_from_web_items(items, "gemini", ref)


def _query_openai_web(prompt: str, ref: FrameworkRef, *, timeout: float, model: str) -> list[Vulnerability]:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        _warn("OPENAI_API_KEY not set; skipping web search")
        return []
    # Responses API with web_search_preview tool
    resp = httpx.post(
        "https://api.openai.com/v1/responses",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "tools": [{"type": "web_search_preview"}],
            "input": prompt,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    # Responses API returns output array with message.content parts
    text_chunks: list[str] = []
    for item in data.get("output", []) or []:
        if item.get("type") == "message":
            for c in item.get("content", []) or []:
                t = c.get("text")
                if isinstance(t, str):
                    text_chunks.append(t)
                elif isinstance(t, dict) and "value" in t:
                    text_chunks.append(t["value"])
    text = "\n".join(text_chunks) or data.get("output_text", "")
    items = _extract_json_array(text)
    return _vulns_from_web_items(items, "openai", ref)


def _query_anthropic_web(prompt: str, ref: FrameworkRef, *, timeout: float, model: str) -> list[Vulnerability]:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        _warn("ANTHROPIC_API_KEY not set; skipping web search")
        return []
    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 2048,
            "tools": [{"type": "web_search_20250305", "name": "web_search", "max_uses": 3}],
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    text_chunks: list[str] = []
    for c in data.get("content", []) or []:
        if c.get("type") == "text":
            text_chunks.append(c.get("text", ""))
    text = "\n".join(text_chunks)
    items = _extract_json_array(text)
    return _vulns_from_web_items(items, "anthropic", ref)


# ── Merge / dedupe ──────────────────────────────────────────────────────────

def _dedupe_vulns(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Dedupe by CVE id. Prefer OSV record over web sources.

    Rows without a CVE id are always kept (can't dedupe meaningfully).
    """
    best: dict[str, Vulnerability] = {}
    orphans: list[Vulnerability] = []
    for v in vulns:
        if not v.cve_id:
            orphans.append(v)
            continue
        existing = best.get(v.cve_id)
        if existing is None:
            best[v.cve_id] = v
            continue
        # Prefer OSV over web
        if v.source == "osv" and existing.source != "osv":
            best[v.cve_id] = v
    merged = list(best.values()) + orphans
    # Sort: highest severity first, then by CVSS score desc
    merged.sort(key=lambda v: (_SEVERITY_ORDER.get(v.severity, 0), v.cvss_score or 0.0), reverse=True)
    return merged


# ── Public entry point ──────────────────────────────────────────────────────

class VulnChecker:
    """Orchestrates OSV + web-search lookups for a single framework+version."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def check(self, framework: str) -> list[Vulnerability]:
        if not self.config.vuln_check_enabled:
            return []
        ref = parse_framework_ref(framework)
        if ref is None:
            return []

        all_vulns: list[Vulnerability] = []

        # OSV (always on if enabled)
        try:
            all_vulns.extend(query_osv(ref, timeout=self.config.vuln_osv_timeout))
        except Exception as exc:  # noqa: BLE001
            _warn(f"OSV query failed for {ref.package}@{ref.version}: {exc}")

        # Optional LLM web search
        provider = self.config.vuln_search_provider
        if provider:
            try:
                all_vulns.extend(
                    query_web_search(
                        ref,
                        provider,
                        timeout=self.config.vuln_web_timeout,
                        model_override=self.config.vuln_search_model,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                _warn(f"{provider} web search failed for {ref.name} {ref.version}: {exc}")

        return _dedupe_vulns(all_vulns)
