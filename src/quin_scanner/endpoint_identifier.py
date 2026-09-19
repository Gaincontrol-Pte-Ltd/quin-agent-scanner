"""Identifies the address of LLM inference endpoints used by a repository.

Credentials are never recorded: userinfo (``user:pass@``) and secret-looking query
parameters are redacted from every URL and expression before it is stored.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from quin_scanner.models import EndpointUsage

if TYPE_CHECKING:
    from quin_scanner.file_index import FileIndex
    from quin_scanner.repo_accessor import RepoAccessor

_CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java"}
_CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg"}

# ── Credential redaction ────────────────────────────────────────────────────
_USERINFO_RE = re.compile(r'(://)[^/\s@"\'`]+@')
_SECRET_QUERY_RE = re.compile(
    r'([?&;](?:api[-_]?key|key|token|access[-_]?token|secret|client[-_]?secret|password|passwd|pwd|'
    r'auth|authorization|sig|signature|code)=)[^&\s"\'`]+',
    re.IGNORECASE,
)


def redact(text: str) -> str:
    """Remove credentials embedded in a URL or URL-bearing expression."""
    text = _USERINFO_RE.sub(r"\1REDACTED@", text)
    return _SECRET_QUERY_RE.sub(r"\1REDACTED", text)


# ── Classification ──────────────────────────────────────────────────────────
_PROVIDER_HOSTS = (
    "api.openai.com", "openai.azure.com", "api.anthropic.com",
    "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "api.cohere.ai", "api.cohere.com", "api.together.xyz", "api.mistral.ai",
    "api.groq.com", "api.perplexity.ai", "api.deepseek.com", "api.x.ai",
    "openrouter.ai", "api-inference.huggingface.co", "api.fireworks.ai",
)
_BEDROCK_RE = re.compile(r"(^|\.)bedrock(-runtime)?\.[a-z0-9-]+\.amazonaws\.com$")
_PRIVATE_SUFFIXES = (".local", ".internal", ".lan", ".svc", ".cluster.local", ".corp", ".intranet")


def classify_host(host: str | None) -> str:
    """hosted_provider | local | private | remote | unknown"""
    if not host or any(c in host for c in "{}$<>"):
        return "unknown"
    host = host.lower().strip("[]")
    if any(host == h or host.endswith("." + h) for h in _PROVIDER_HOSTS) or _BEDROCK_RE.search(host):
        return "hosted_provider"
    if host in ("localhost", "0.0.0.0", "host.docker.internal") or host.endswith(".localhost"):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return "local"
        if ip.is_private or ip.is_link_local:
            return "private"
        return "remote"
    except ValueError:
        pass
    if "." not in host or host.endswith(_PRIVATE_SUFFIXES):
        return "private"
    return "remote"


# ── Patterns ────────────────────────────────────────────────────────────────
_URL_RE = re.compile(r'https?://[^\s"\'`<>)\]},]+')
_LLM_PATH_RE = re.compile(
    r"/(v1/)?(chat/completions|completions|embeddings|messages|responses)\b|/api/(generate|chat|embed)\b"
    r"|/openai/deployments/|/v1beta/models|:generateContent"
)
_CODE_KWARG_RE = re.compile(
    r"\b(base_url|api_base|openai_api_base|azure_endpoint|endpoint_url|api_url|inference_url|"
    r"llm_url|llm_base_url|baseURL|baseUrl)\b\s*[=:]\s*(.+)"
)
_REF_KEY_RE = re.compile(r"""\[\s*['"]([\w.-]+)['"]\s*\]|\.get\(\s*['"]([\w.-]+)['"]""")

_LLM_WORDS = re.compile(
    r"llm|model|inference|openai|anthropic|azure|ollama|vllm|litellm|gemini|mistral|groq|cohere|"
    r"bedrock|completion|embedding|llama|together|huggingface|deepseek",
    re.IGNORECASE,
)
_URL_KEY_WORDS = re.compile(r"url|uri|endpoint|base|host|address", re.IGNORECASE)
_KNOWN_KEYS = {"api_base", "openai_api_base", "azure_endpoint", "openai_base_url", "anthropic_base_url"}

_YAML_LINE_RE = re.compile(r"""^(\s*)(?:-\s+)?["']?([A-Za-z0-9_.\-]+)["']?\s*:\s*(.*)$""")
_KV_LINE_RE = re.compile(r"""^\s*["']?([A-Za-z0-9_.\-]+)["']?\s*[:=]\s*["']?([^"'\s,#]+)""")
_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=\s*(.*)$")


def _is_llm_url_key(key: str) -> bool:
    k = key.lower()
    return k in _KNOWN_KEYS or bool(_LLM_WORDS.search(k) and _URL_KEY_WORDS.search(k))


def _clean_value(v: str) -> str:
    v = v.strip()
    v = re.split(r"\s+#", v, maxsplit=1)[0].strip()
    return v.strip("\"'").strip()


def _make(url: str, kind_hint: str | None, source: str, path: str, lineno: int, key: str,
          resolved_from: str = "") -> EndpointUsage:
    url = redact(url)
    host = urlsplit(url).hostname if url.startswith(("http://", "https://")) else None
    kind = kind_hint or classify_host(host)
    return EndpointUsage(
        url=url, host=host or "", kind=kind, source=source,
        file_path=path, line_number=lineno, key=key, resolved_from=resolved_from,
    )


class EndpointIdentifier:
    """Scans code, config and env files for LLM inference endpoint addresses."""

    def identify(self, accessor: "RepoAccessor", file_index: "FileIndex") -> list[EndpointUsage]:
        found: list[EndpointUsage] = []
        for path in file_index.all_files():
            p = Path(path)
            suffix, name = p.suffix.lower(), p.name.lower()
            try:
                if suffix in _CODE_EXTENSIONS:
                    content = accessor.read_file(path)
                    found.extend(self._scan_code(content, path))
                elif name.startswith(".env") or suffix == ".env":
                    found.extend(self._scan_env(accessor.read_file(path), path))
                elif suffix in (".yaml", ".yml"):
                    found.extend(self._scan_yaml(accessor.read_file(path), path))
                elif suffix in _CONFIG_EXTENSIONS:
                    found.extend(self._scan_kv(accessor.read_file(path), path))
            except Exception:
                continue
        found = self._resolve(found)
        seen: set[tuple] = set()
        out: list[EndpointUsage] = []
        for e in found:
            k = (e.url, e.file_path, e.line_number)
            if k not in seen:
                seen.add(k)
                out.append(e)
        return out

    # --- code ---

    def _scan_code(self, content: str, path: str) -> list[EndpointUsage]:
        out: list[EndpointUsage] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            if line.lstrip().startswith(("#", "//", "*", "/*")):
                continue
            m = _CODE_KWARG_RE.search(line)
            if m:
                key, value = m.group(1), m.group(2).strip()
                um = _URL_RE.search(value)
                if um and not value.startswith(("f\"", "f'")) and "{" not in um.group(0):
                    out.append(_make(um.group(0), None, "code", path, lineno, key))
                    continue
                if value and not re.match(r"(None|null|undefined|\"\"|'')\b", value):
                    expr = value.rstrip(",) ")[:200]
                    ref = _REF_KEY_RE.search(expr)
                    suffix = expr.split("}", 1)[1].strip("\"'") if "}" in expr else ""
                    out.append(EndpointUsage(
                        url=redact(expr), host="", kind="unresolved", source="code",
                        file_path=path, line_number=lineno, key=key,
                        ref_key=(ref.group(1) or ref.group(2)) if ref else "",
                        ref_suffix=suffix if suffix.startswith("/") else "",
                    ))
                    continue
            for um in _URL_RE.finditer(line):
                url = um.group(0)
                if "{" in url:
                    continue
                host = urlsplit(url).hostname
                if classify_host(host) == "hosted_provider" or _LLM_PATH_RE.search(url):
                    out.append(_make(url, None, "code", path, lineno, "url"))
        return out

    # --- config ---

    def _scan_env(self, content: str, path: str) -> list[EndpointUsage]:
        out: list[EndpointUsage] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            m = _ENV_LINE_RE.match(line)
            if not m or line.lstrip().startswith("#"):
                continue
            key, value = m.group(1), _clean_value(m.group(2))
            if value.startswith(("http://", "https://")) and _is_llm_url_key(key):
                out.append(_make(value, None, "env_var", path, lineno, key))
        return out

    def _scan_yaml(self, content: str, path: str) -> list[EndpointUsage]:
        out: list[EndpointUsage] = []
        stack: list[tuple[int, str]] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            m = _YAML_LINE_RE.match(line)
            if not m:
                continue
            indent, key, rest = len(m.group(1)), m.group(2), m.group(3)
            while stack and stack[-1][0] >= indent:
                stack.pop()
            value = _clean_value(rest)
            if not value:
                stack.append((indent, key))
                continue
            if value.startswith(("http://", "https://")):
                parents = [k for _, k in stack]
                if _LLM_WORDS.search(" ".join(parents)) or _is_llm_url_key(key):
                    out.append(_make(value, None, "config", path, lineno, ".".join(parents + [key])))
        return out

    def _scan_kv(self, content: str, path: str) -> list[EndpointUsage]:
        out: list[EndpointUsage] = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            m = _KV_LINE_RE.match(line)
            if m and m.group(2).startswith(("http://", "https://")) and _is_llm_url_key(m.group(1)):
                out.append(_make(m.group(2), None, "config", path, lineno, m.group(1)))
        return out

    # --- linking code expressions to config values ---

    @staticmethod
    def _resolve(found: list[EndpointUsage]) -> list[EndpointUsage]:
        configured = [e for e in found if e.source in ("config", "env_var") and e.kind != "unresolved"]
        out: list[EndpointUsage] = []
        for e in found:
            if e.kind == "unresolved" and e.ref_key:
                cands = [c for c in configured if c.key.split(".")[-1] == e.ref_key]
                if cands:
                    c = cands[0]
                    out.append(_make(
                        c.url.rstrip("/") + e.ref_suffix, None, "code", e.file_path, e.line_number,
                        e.key, resolved_from=f"{c.file_path}:{c.line_number}",
                    ))
                    continue
            out.append(e)
        return out
