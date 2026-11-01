"""Remove credentials from text before Quin stores it (reports, inventory) or sends it anywhere (LLM context).

Two kinds of credential are handled:

- values with a recognisable shape (provider API keys, access tokens, private-key headers, bearer tokens), wherever they appear;
- the value of a quoted ``key = "value"`` / ``"key": "value"`` assignment whose name says it is a secret.

Credentials inside URLs (``user:password@host``, ``?api_key=...``) are removed too. Redaction keeps the shape of the text,
so a finding still reads as the line it came from.
"""
from __future__ import annotations

import re

REDACTED = "[REDACTED]"

# ── URLs ────────────────────────────────────────────────────────────────────
_USERINFO_RE = re.compile(r'(://)[^/\s@"\'`]+@')
_SECRET_QUERY_RE = re.compile(
    r'([?&;](?:api[-_]?key|key|token|access[-_]?token|secret|client[-_]?secret|password|passwd|pwd|'
    r'auth|authorization|sig|signature|code)=)[^&\s"\'`]+',
    re.IGNORECASE,
)


def redact_url_credentials(text: str) -> str:
    """Remove credentials embedded in a URL or URL-bearing expression."""
    text = _USERINFO_RE.sub(r"\1REDACTED@", text)
    return _SECRET_QUERY_RE.sub(r"\1REDACTED", text)


# ── Values with a recognisable shape ────────────────────────────────────────
# The look-behind keeps a key-shaped tail inside an ordinary word ("task-...", "risk-...") from matching.
_SHAPED = [
    re.compile(r"(?<![A-Za-z0-9_])sk-[A-Za-z0-9_\-]{20,}"),           # OpenAI, Anthropic (sk-ant-...), and similar
    re.compile(r"(?<![A-Za-z0-9_])AIza[0-9A-Za-z_\-]{35}"),            # Google API keys
    re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,}"),        # GitHub tokens
    re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,}"),
    re.compile(r"(?<![A-Za-z0-9_])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),  # AWS access key ids
    re.compile(r"(?<![A-Za-z0-9_])xox[abprs]-[A-Za-z0-9\-]{10,}"),     # Slack tokens
    re.compile(r"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{30,}"),               # Hugging Face tokens
]
_BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=\-]{20,}")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

# name = "value" / "name": "value" where the name says it is a secret. Only quoted literals: `api_key=os.environ[...]` is code.
_ASSIGNED = re.compile(
    r"""((?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|(?:access|auth|bearer|refresh)[_-]?token|token|"""
    r"""password|passwd|pwd|private[_-]?key|credentials?)["']?\s*[:=]\s*["'])([^"'\s]{8,})(["'])""",
    re.IGNORECASE,
)


# Values that are obviously not credentials: leaving them readable keeps useful signals (`api_key="not-needed"` marks a client
# for a local endpoint) and avoids redacting documentation placeholders.
_PLACEHOLDER = re.compile(
    r"""^(?:not[-_ ]?needed|none|null|nil|dummy[-_a-z0-9]*|test[-_a-z0-9]*|example[-_a-z0-9]*|change[-_ ]?me|placeholder|"""
    r"""your[-_a-z0-9 ]*|my[-_]?(?:api[-_]?)?key|x{4,}|\*{4,}|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%s|%\([a-z_]+\)s)$""",
    re.IGNORECASE,
)


def _redact_assignment(match: re.Match[str]) -> str:
    value = match.group(2)
    if REDACTED in value or _PLACEHOLDER.match(value):
        return match.group(0)
    return f"{match.group(1)}{REDACTED}{match.group(3)}"


def redact_secrets(text: str) -> str:
    """Return *text* with credentials replaced by ``[REDACTED]`` (or ``REDACTED`` inside a URL)."""
    if not text:
        return text
    for pattern in _SHAPED:
        text = pattern.sub(REDACTED, text)
    text = _BEARER.sub(rf"\1{REDACTED}", text)
    text = _PRIVATE_KEY.sub("-----BEGIN PRIVATE KEY----- [REDACTED]", text)
    text = _ASSIGNED.sub(_redact_assignment, text)
    return redact_url_credentials(text)
