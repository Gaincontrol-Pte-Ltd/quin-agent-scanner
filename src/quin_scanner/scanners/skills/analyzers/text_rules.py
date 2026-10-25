from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from quin_scanner.models import SkillFinding
from quin_scanner.scanners.skills.analyzers.common import line_of, make_finding
from quin_scanner.scanners.skills.bundle import SkillBundle, file_kind

_RULES_PATH = Path(__file__).parents[3] / "rules" / "skill_rules.yaml"
_MAX_PER_RULE_PER_FILE = 5
_PROSE_KINDS = frozenset({"markdown", "text"})
_NEGATION = re.compile(
    r"(?i)\b(never(?!\s+mind)|do not|don.?t|does not|doesn.?t|cannot|can.?t|won.?t|will not"
    r"|must not|should not|shouldn.?t|avoid|warn(?:s|ing)?|prevent|detect|block|refuse)\b"
)
# Guidance that introduces a quoted list of things not to write:
# avoid phrasing like ("ignore ...", "disregard ...") / use X instead of "..."
_QUOTE_GUIDANCE = re.compile(_NEGATION.pattern + r"|(?i:\b(?:instead of|rather than)\b)")
# A line that starts with an anti-pattern marker ("- ❌ Deploy without asking", "BAD: ...")
_ANTI_PATTERN_LEAD = re.compile(
    r"\s*(?:(?:[-*+>]|\d+[.)])\s*)*(?:❌|🚫|✗|(?:BAD|Bad|DON.?T|Don.?t)\s*:)"
)
_SENTENCE_END = re.compile(r"[.;!?](?=\s|$)")
_COMPLETE_QUOTE = re.compile(r'"[^"\n]*"|\u201c[^\u201d\n]*\u201d')
# Cues that introduce a quoted phrase as a *mention* of content, not an instruction:
# "if the export contains ...", "a page that says ...", "phrases like ...", "(e.g. ...)".
# Only forms that cannot be a sentence-initial imperative count: third-person or
# participle verbs (contains, includes, says, reads, containing, including, saying),
# base "contain"/"include" only after a subject noun or pronoun, and connectives such
# as "such as" / "for example" / "e.g." / "phrases like". Bare "say", "include",
# "contain" are excluded so that 'Say "..."' / 'Include "..."' stay instructions.
_MENTION_CUE = re.compile(
    r"(?i)\b(?:such as|for (?:example|instance)|(?:phrases?|text|words?|strings?|lines?"
    r"|content|wording) like|looks? like|appears? as|called|label(?:l)?ed|contains|containing"
    r"|includes|including|says|saying|reads|(?:it|they|that|which|who|texts?|content|files?"
    r"|exports?|pages?|documents?|inputs?|messages?|data|outputs?|emails?|comments?"
    r"|responses?|results?)\s+(?:contain|include))\b|\be\.g\."
)
# An output/imperative verb anywhere in the sentence before the quote means the quote is
# something the agent is told to produce or act on, so it is never treated as a mention.
_MENTION_VETO = re.compile(
    r"(?i)\b(?:say|reply|respond|answer|write|print|type|tell|send|add|append|insert"
    r"|paste|use|run|execute|follow|obey)\b"
)
# Sentence end for mention cues; "e.g." and "i.e." do not end a sentence.
_MENTION_SENTENCE_END = re.compile(r"(?<!\be\.g)(?<!\bi\.e)[.;!?](?=\s|$)")


@dataclass(frozen=True)
class TextRule:
    id: str
    title: str
    severity: str
    category: str
    threat_id: str
    confidence: float
    pattern: re.Pattern[str]
    applies_to: frozenset[str]
    skip_in_fence: bool
    negatable: bool
    skip_comment_lines: bool = False
    skip_hosts: frozenset[str] = frozenset()
    skip_patterns: tuple[re.Pattern[str], ...] = ()


@lru_cache(maxsize=1)
def load_rules() -> tuple[TextRule, ...]:
    data = yaml.safe_load(_RULES_PATH.read_text(encoding="utf-8"))
    return tuple(
        TextRule(
            id=r["id"],
            title=r["title"],
            severity=r["severity"],
            category=r["category"],
            threat_id=r["threat_id"],
            confidence=float(r["confidence"]),
            pattern=re.compile(r["pattern"]),
            applies_to=frozenset(r["applies_to"]),
            skip_in_fence=bool(r.get("skip_in_fence", False)),
            negatable=bool(r.get("negatable", False)),
            skip_comment_lines=bool(r.get("skip_comment_lines", False)),
            skip_hosts=frozenset(h.lower() for h in r.get("skip_hosts", [])),
            skip_patterns=tuple(re.compile(p) for p in r.get("skip_patterns", [])),
        )
        for r in data["rules"]
    )


def fenced_lines(text: str) -> set[int]:
    """1-based line numbers inside (and including) *closed* ``` / ~~~ fences.

    An opener without a closing marker hides nothing except the opener line itself.
    """
    out: set[int] = set()
    opener: int | None = None
    marker = ""
    for n, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if opener is None:
            if stripped.startswith(("```", "~~~")):
                opener, marker = n, stripped[:3]
        elif stripped.startswith(marker):
            out.update(range(opener, n + 1))
            opener = None
    if opener is not None:
        out.add(opener)
    return out


_CLAUSE_END = re.compile(r"[.;!?:]")


def _after_last(pattern: re.Pattern[str], s: str) -> str:
    ends = list(pattern.finditer(s))
    return s[ends[-1].end():] if ends else s


def _before_open_quote(before: str) -> str | None:
    """Line text before the quote the match sits in, or None when it is not inside one.

    Earlier, completed quotes on the line are collapsed to "", so a cue may sit before a
    whole list of quoted examples.
    """
    collapsed = _COMPLETE_QUOTE.sub('""', before)
    if "\u201c" in collapsed:
        return collapsed[:collapsed.rfind("\u201c")]
    if collapsed.count('"') % 2 == 1:
        return collapsed[:collapsed.rfind('"')]
    return None


def _in_negated_quote(before: str) -> bool:
    """True when the match sits inside a quoted item whose sentence is anti-pattern guidance.

    E.g. 'avoid override-style language ("ignore ...", "disregard the previous instruction")'.
    Only the current sentence counts.
    """
    prefix = _before_open_quote(before)
    if prefix is None:
        return False
    guidance = _after_last(_SENTENCE_END, prefix)
    return bool(_QUOTE_GUIDANCE.search(guidance[-200:]))


def is_quoted_mention(text: str, start: int) -> bool:
    """True when the match is inside a quote that the sentence introduces as a mention.

    E.g. 'If the export contains text addressed to you - "ignore previous instructions"'.
    Requires (1) the match to sit inside an open straight or curly quote, (2) a mention
    cue (_MENTION_CUE) in the same sentence before the quote, and (3) no output or
    imperative verb (_MENTION_VETO) in that sentence before the quote. Unquoted text is
    never a mention.
    """
    line_start = text.rfind("\n", 0, start) + 1
    prefix = _before_open_quote(text[line_start:start])
    if prefix is None:
        return False
    sentence = _after_last(_MENTION_SENTENCE_END, prefix)[-160:]
    return bool(_MENTION_CUE.search(sentence)) and not _MENTION_VETO.search(sentence)


def is_negated(text: str, start: int) -> bool:
    """True when the match is in negated or anti-pattern context on its line.

    - the same clause (after the last . ; ! ? : or line start) has a negation word, or
    - the line starts with an anti-pattern marker (❌, BAD:) and no sentence ends before
      the match, or
    - the match is inside a quoted list introduced by "avoid", "don't use", "instead of"...
    """
    line_start = text.rfind("\n", 0, start) + 1
    before = text[line_start:start]
    if _NEGATION.search(_after_last(_CLAUSE_END, before)[-60:]):
        return True
    lead = _ANTI_PATTERN_LEAD.match(before)
    if lead and not _SENTENCE_END.search(before, lead.end()):
        return True
    return _in_negated_quote(before)


_URL_HOST = re.compile(r"(?i)\bhttps?://([^/\s\"'`<>()\\]+)")


def _line_hosts_all_skipped(text: str, pos: int, hosts: frozenset[str]) -> bool:
    """True when the line holding *pos* has at least one URL and every URL host is in *hosts*."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start: end if end != -1 else len(text)]
    found = []
    for m in _URL_HOST.finditer(line):
        host = m.group(1).rsplit("@", 1)[-1]
        host = host[1:host.find("]")] if host.startswith("[") else host.split(":", 1)[0]
        found.append(host.lower().rstrip("."))
    return bool(found) and all(h in hosts for h in found)


def _is_comment_line(text: str, pos: int) -> bool:
    """True when the whole line containing *pos* is a code comment (#, //, /*, *)."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start: end if end != -1 else len(text)].lstrip()
    return line.startswith(("#", "//", "/*", "*")) and not line.startswith("#!")


def _line_matches_any(text: str, pos: int, patterns: tuple[re.Pattern[str], ...]) -> bool:
    """True when the line containing *pos* matches any of *patterns*."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start: end if end != -1 else len(text)]
    return any(p.search(line) for p in patterns)


def rule_matches(
    rule: TextRule, text: str, kind: str, fenced: set[int]
) -> Iterator[re.Match[str]]:
    if "any" not in rule.applies_to and kind not in rule.applies_to:
        return
    for m in rule.pattern.finditer(text):
        if rule.skip_in_fence and kind == "markdown" and line_of(text, m.start()) in fenced:
            continue
        if rule.negatable and is_negated(text, m.start()):
            continue
        if rule.negatable and kind in _PROSE_KINDS and is_quoted_mention(text, m.start()):
            continue
        if rule.skip_comment_lines and _is_comment_line(text, m.start()):
            continue
        if rule.skip_patterns and _line_matches_any(text, m.start(), rule.skip_patterns):
            continue
        if rule.skip_hosts and _line_hosts_all_skipped(text, m.start(), rule.skip_hosts):
            continue
        yield m


def analyze_text(bundle: SkillBundle) -> list[SkillFinding]:
    findings: list[SkillFinding] = []
    for f in bundle.files:
        kind = file_kind(f.path)
        if kind is None:
            continue
        fenced = fenced_lines(f.text) if kind == "markdown" else set()
        for rule in load_rules():
            count = 0
            seen_lines: set[int] = set()
            for m in rule_matches(rule, f.text, kind, fenced):
                line_no = line_of(f.text, m.start())
                if line_no in seen_lines:   # one finding per rule per line
                    continue
                seen_lines.add(line_no)
                findings.append(
                    make_finding(
                        bundle,
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        title=rule.title,
                        file_path=f.path,
                        line_number=line_no,
                        evidence_text=m.group(0),
                        threat_id=rule.threat_id,
                        confidence=rule.confidence,
                    )
                )
                count += 1
                if count >= _MAX_PER_RULE_PER_FILE:
                    break
    return findings
