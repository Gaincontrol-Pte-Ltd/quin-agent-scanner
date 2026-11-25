"""The code-pattern pre-filter (#88) must never skip a rule that would have matched."""
from __future__ import annotations

import itertools
import re
from pathlib import Path
from re import _constants as _c  # type: ignore[attr-defined]
from re import _parser as _p  # type: ignore[attr-defined]

import pytest

from quin_scanner.file_index import FileIndex
from quin_scanner.models import ScanFinding
from quin_scanner.regex_prefilter import Literal, TextProbe, required_literals
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.rules import load_rules
from quin_scanner.scanners.code_pattern import _ANY_EXT, CodePatternScanner, _lang_for_ext


def _texts(pattern: str, flags: int = 0) -> list[set[str]] | None:
    """Clauses as plain sets of strings, for readable assertions."""
    clauses = required_literals(pattern, flags)
    return None if clauses is None else [{lit.text for lit in clause} for clause in clauses]


# --- the extractor on tricky patterns ---------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"OpenAIChatCompletionClient", [{"OpenAIChatCompletionClient"}]),
        # \s* / \s+ split runs; each side is required.
        (r"from\s+langchain", [{"langchain"}, {"from"}]),
        (r"ChatOpenAI\s*\(", [{"ChatOpenAI"}, {"("}]),
        # Escaped metacharacters are literals.
        (r"client\.chat\.completions\.create", [{"client.chat.completions.create"}]),
        (r"\"github\.com/tmc/langchaingo", [{'"github.com/tmc/langchaingo'}]),
        # Alternation: one literal per alternative, as one clause.
        (r"(?:openai|anthropic|groq)\s*\(", [{"anthropic", "openai", "groq"}, {"("}]),
        (r"x(?:ab|cd)y", [{"ab", "cd"}, {"x"}, {"y"}]),
        # An alternative with nothing required voids the alternation, not the pattern.
        (r"from\s+(?:openai|)", [{"from"}]),
        (r"from\s+(?:openai|[a-z]+)", [{"from"}]),
        (r"(?:openai|\w+)", None),
        # Optional group / zero-minimum repeats contribute nothing.
        (r"Agent(?:Executor)?\(", [{"Agent"}, {"("}]),
        (r"(?:Executor)*Agent", [{"Agent"}]),
        # A mandatory repeat contributes its body.
        (r"(?:ab)+c", [{"ab"}, {"c"}]),
        (r"(?:ab){2,}c", [{"ab"}, {"c"}]),
        # Character classes contribute nothing and break the run.
        (r"from\s+['\"]openai['\"]", [{"openai"}, {"from"}]),
        (r"[abc]+", None),
        (r"Ag[e]nt", [{"Agent"}]),  # a one-character class parses as the literal itself
        (r"Ag.nt", [{"Ag"}, {"nt"}]),
        # Zero-width assertions and lookarounds contribute nothing.
        (r"\bLlmAgent\s*\(", [{"LlmAgent"}, {"("}]),
        (r"(?<![\w.])Task\s*\(", [{"Task"}, {"("}]),
        (r"(?=openai)\w+", None),
        (r"^import\s+x$", [{"import"}, {"x"}]),
        # Back-references and conditionals contribute nothing.
        (r"(['\"])x\1", [{"x"}]),
        (r"(a)?(?(1)b|c)", None),
        # Nothing to require at all.
        (r".*", None),
        (r"", None),
        (r"\s+", None),
    ],
)
def test_extractor(pattern, expected):
    got = _texts(pattern)
    if expected is None:
        assert got is None
    else:
        assert got is not None and sorted(map(sorted, got)) == sorted(map(sorted, expected))


def test_most_selective_clause_first():
    assert _texts(r"import\s+faiss") == [{"import"}, {"faiss"}]


def test_case_insensitive_literals_are_lowercased_and_flagged():
    assert required_literals(r"(?i)From\s+OpenAI") == (
        frozenset({Literal("openai", True)}), frozenset({Literal("from", True)}))
    assert required_literals(r"OpenAI", re.IGNORECASE) == (frozenset({Literal("openai", True)}),)
    # Scoped flags: only the group is case-insensitive, or only the group is not.
    assert required_literals(r"import\s+(?i:OpenAI)") == (
        frozenset({Literal("import")}), frozenset({Literal("openai", True)}))
    assert set(required_literals(r"(?i)import\s+(?-i:OpenAI)")) == {
        frozenset({Literal("import", True)}), frozenset({Literal("OpenAI")})}


def test_unparseable_pattern_always_runs():
    assert required_literals(r"(unclosed") is None


# --- the probe ---------------------------------------------------------------------------------


def test_probe_requires_every_clause():
    clauses = required_literals(r"from\s+(?:openai|anthropic)")
    assert TextProbe("from anthropic import x").may_match(clauses)
    assert not TextProbe("from x import openai_thing").may_match(required_literals(r"import\s+anthropic"))
    assert not TextProbe("import openai").may_match(clauses)  # no "from"
    assert TextProbe("anything").may_match(None)


def test_probe_case_insensitive():
    clauses = required_literals(r"(?i)openai")
    assert TextProbe("import OPENAI").may_match(clauses)
    assert not TextProbe("import nothing").may_match(clauses)


@pytest.mark.parametrize(
    ("pattern", "text"),
    [
        ("(?i)k", "K"),  # KELVIN SIGN folds to k
        ("(?i)s", "ſ"),  # LATIN SMALL LETTER LONG S folds to s
        ("(?i)K", "k"),
        ("(?i)i", "İ"),  # does not match, but non-ASCII text must not be pre-filtered away
    ],
)
def test_probe_never_rejects_unicode_case_folds(pattern, text):
    assert TextProbe(text).may_match(required_literals(pattern))


# --- equivalence on the real rules -----------------------------------------------------------

_RULES: list[dict] = load_rules("code_patterns.yaml")["patterns"]
_CLASS_POOL = " \tazAZ09_.'\"(=:-/@"


_CATEGORIES = {
    _c.CATEGORY_SPACE: str.isspace, _c.CATEGORY_NOT_SPACE: lambda ch: not ch.isspace(),
    _c.CATEGORY_DIGIT: str.isdigit, _c.CATEGORY_NOT_DIGIT: lambda ch: not ch.isdigit(),
    _c.CATEGORY_WORD: lambda ch: ch.isalnum() or ch == "_",
    _c.CATEGORY_NOT_WORD: lambda ch: not (ch.isalnum() or ch == "_"),
}


def _in_class(ch: str, items) -> bool:
    negate, hit = False, False
    for op, av in items:
        if op is _c.NEGATE:
            negate = True
        elif op is _c.LITERAL:
            hit |= ord(ch) == av
        elif op is _c.RANGE:
            hit |= av[0] <= ord(ch) <= av[1]
        elif op is _c.CATEGORY:
            hit |= _CATEGORIES[av](ch)
    return hit != negate


def _gen(items, limit: int = 24) -> list[str]:
    """Candidate strings built from the parse tree; callers keep only those that really match."""
    out = [""]
    for op, av in items:
        if op is _c.LITERAL:
            opts = [chr(av)]
        elif op is _c.NOT_LITERAL:
            opts = [ch for ch in "ax " if ord(ch) != av][:1]
        elif op is _c.ANY:
            opts = ["a"]
        elif op is _c.IN:
            members = [ch for ch in _CLASS_POOL if _in_class(ch, av)]
            opts = sorted({members[0], members[-1]}) if members else []
        elif op is _c.SUBPATTERN:
            opts = _gen(av[3], limit)
        elif op is _c.ATOMIC_GROUP:
            opts = _gen(av, limit)
        elif op is _c.BRANCH:
            opts = [s for b in av[1] for s in _gen(b, limit)]
        elif op in (_c.MAX_REPEAT, _c.MIN_REPEAT, _c.POSSESSIVE_REPEAT):
            low, high, sub = av
            body = _gen(sub, limit)
            counts = sorted({low, min(low + 1, high), min(low + 2, high)})
            opts = [b * n for n in counts for b in body]
        else:  # AT, ASSERT, ASSERT_NOT, GROUPREF...: zero-width or skipped; filtered later
            opts = [""]
        out = _spread([a + b for a, b in itertools.product(out, opts)], limit * 8)
    return out


def _spread(items: list[str], n: int) -> list[str]:
    """At most n items, evenly spaced, so every alternative of an early branch survives."""
    if len(items) <= n:
        return items
    return [items[i * len(items) // n] for i in range(n)]


def _positive_samples(rule: dict) -> list[str]:
    rx = re.compile(rule["pattern"])
    found = [s for s in _gen(_p.parse(rule["pattern"])) if rx.search(s)]
    return _spread(list(dict.fromkeys(found)), 30)


def _sample_texts() -> list[str]:
    """Matching strings for every rule, the same with every rule's literals damaged, and some
    real-world lines, each alone and embedded in code."""
    texts: list[str] = []
    for rule in _RULES:
        for s in _positive_samples(rule):
            texts += [s, f"    x = {s}  # call", s.upper(), s.lower(), s[1:], s[:-1], s.replace(" ", "")]
    texts += [
        "from crewai import Agent, Task, Crew",
        "import { Agent } from '@mastra/core/agent'",
        "const client = new OpenAI({ apiKey });",
        'model = openai("gpt-4o")',
        "subtask = SubTask(1)",
        "from anthropic import AsyncAnthropic, NOT_GIVEN, BetaTool",
        "use async_openai::Client;",
        'import "github.com/sashabaranov/go-openai"',
        "agent = Agent(model=model, tools=[search])",
        "",
    ]
    return texts


_SAMPLES = _sample_texts()


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r["pattern"])
def test_every_rule_has_a_matching_sample(rule):
    assert _positive_samples(rule), f"generator found no match for {rule['pattern']!r}"


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r["pattern"])
def test_prefilter_never_skips_a_match(rule):
    rx, clauses = re.compile(rule["pattern"]), required_literals(rule["pattern"])
    for text in _SAMPLES:
        if rx.search(text):
            assert TextProbe(text).may_match(clauses), (rule["pattern"], text)


def test_rules_all_get_a_prefilter():
    """Every shipped rule yields required text; a new rule that does not still works (it just
    always runs), but this flags it so the loss of speed is a decision."""
    assert [r["pattern"] for r in _RULES if required_literals(r["pattern"]) is None] == []


class _Unfiltered(CodePatternScanner):
    """The scan loop before #88: every rule of the file's language on every line."""

    def scan(self, accessor, file_index):
        findings = []
        for path in file_index.all_files():
            ext = Path(path).suffix
            if ext not in _ANY_EXT:
                continue
            file_lang = _lang_for_ext(ext)
            content = accessor.read_file(path)
            for lineno, line in enumerate(content.splitlines(), start=1):
                for rule in self._patterns:
                    if rule.get("language", "any") not in ("any", file_lang):
                        continue
                    if rule["_re"].search(line):
                        findings.append(ScanFinding(self.name(), "code_pattern", path, lineno, line.strip(),
                                                    rule["capability_tag"], 0.85))
                        break
        return findings


def _scan(scanner, root: Path) -> list[tuple]:
    accessor = LocalRepoAccessor(root)
    index = FileIndex(accessor)
    index.build()
    return [(f.file_path, f.line_number, f.match_text, f.capability_tag) for f in scanner.scan(accessor, index)]


def test_scanner_findings_equal_unfiltered(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    exts = [".py", ".ts", ".js", ".go", ".rs", ".java"]
    for ext in exts:
        # All samples in one file, and each sample alone in its own file (so most rules are
        # pre-filtered away and only the sample's own rules remain).
        (root / f"all{ext}").write_text("\n".join(_SAMPLES), encoding="utf-8")
        for i, text in enumerate(_SAMPLES[::7]):
            (root / f"one_{i}{ext}").write_text(f"# header\n{text}\n", encoding="utf-8")
    (root / "notes.md").write_text("from openai import OpenAI\n", encoding="utf-8")
    got = _scan(CodePatternScanner(), root)
    assert got == _scan(_Unfiltered(), root)
    assert len(got) > 1000


def test_without_the_private_regex_parser_every_rule_runs(monkeypatch):
    import quin_scanner.regex_prefilter as rp

    monkeypatch.setattr(rp, "_p", None)
    assert rp.required_literals(r"from\s+openai") is None
    assert rp.TextProbe("nothing here").may_match(None) is True
