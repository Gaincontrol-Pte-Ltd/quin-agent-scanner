"""Cheap substring pre-checks that let a scanner skip regexes that cannot match (#88).

``required_literals(pattern)`` reads the parsed regex and returns clauses of literal strings:
every match of the pattern contains, for each clause, at least one of that clause's literals.
``from\\s+(?:openai|anthropic)`` gives ``({"anthropic", "openai"}, {"from"})``. When nothing
can be derived safely it returns ``None``. A caller may skip ``regex.search(text)`` whenever
some clause has no literal in ``text``: the search could not have matched, so the result is the
same.

The extraction is deliberately conservative. Anything it does not fully understand (a character
class, an optional or empty alternative, a lookaround, a back-reference, a conditional group, an
unknown opcode) contributes no clause, and a pattern with no clause left always runs.
"""

from __future__ import annotations

from dataclasses import dataclass
try:  # the regex parser is private: if a future Python moves it, every rule simply always runs
    from re import _constants as _c  # type: ignore[attr-defined]
    from re import _parser as _p  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - only on a Python that renames these modules
    _c = _p = None


@dataclass(frozen=True, order=True)
class Literal:
    """A substring a match must contain. ``ignorecase`` literals are stored lower-cased."""

    text: str
    ignorecase: bool = False


Clause = frozenset[Literal]
"""At least one of these literals occurs in every match."""


def _selectivity(clause: Clause) -> tuple[int, int]:
    """Longer shortest literal first, then fewer literals: the clause least likely to hold."""
    return (-min(len(lit.text) for lit in clause), len(clause))


def _sequence(items, ignorecase: bool) -> list[Clause]:
    """Clauses for a concatenation: every literal run and every mandatory child is required."""
    clauses: list[Clause] = []
    run: list[str] = []

    def flush() -> None:
        if run:
            text = "".join(run)
            clauses.append(frozenset({Literal(text.lower() if ignorecase else text, ignorecase)}))
            run.clear()

    for op, av in items:
        if op is _c.LITERAL:
            run.append(chr(av))
            continue
        # Anything else ends the run of adjacent literals. Breaking a run is always safe: each
        # piece of a required string is itself required.
        flush()
        if op is _c.SUBPATTERN:
            _group, add_flags, del_flags, sub = av
            if add_flags & _c.SRE_FLAG_LOCALE:
                raise ValueError("locale-dependent matching")
            child_icase = (ignorecase or bool(add_flags & _c.SRE_FLAG_IGNORECASE)) and not (
                del_flags & _c.SRE_FLAG_IGNORECASE
            )
            clauses.extend(_sequence(sub, child_icase))
        elif op is _c.ATOMIC_GROUP:
            clauses.extend(_sequence(av, ignorecase))
        elif op in (_c.MAX_REPEAT, _c.MIN_REPEAT, _c.POSSESSIVE_REPEAT):
            low, _high, sub = av
            if low >= 1:
                clauses.extend(_sequence(sub, ignorecase))
        elif op is _c.BRANCH:
            # A match goes through one alternative, so each alternative must give a clause; the
            # union of one clause per alternative is then a clause. An alternative without any
            # (empty, only a class) voids the whole branch.
            _unused, branches = av
            parts = [_sequence(b, ignorecase) for b in branches]
            if parts and all(parts):
                clauses.append(frozenset().union(*(min(part, key=_selectivity) for part in parts)))
        # IN, ANY, NOT_LITERAL, AT (\b, ^, $), ASSERT/ASSERT_NOT (lookarounds), GROUPREF,
        # GROUPREF_EXISTS and any opcode not listed: no clause from this item.
    flush()
    return clauses


def required_literals(pattern: str, flags: int = 0) -> tuple[Clause, ...] | None:
    """Clauses every match of ``pattern`` satisfies, most selective first, or ``None``."""
    if _p is None:
        return None
    try:
        parsed = _p.parse(pattern, flags)
        all_flags = parsed.state.flags | flags
        if all_flags & _c.SRE_FLAG_LOCALE:
            return None
        clauses = _sequence(parsed, bool(all_flags & _c.SRE_FLAG_IGNORECASE))
    except Exception:  # noqa: BLE001 - an unparseable or unexpected pattern just always runs
        return None
    unique = sorted(set(clauses), key=lambda c: (_selectivity(c), sorted(c)))
    return tuple(unique) or None


class TextProbe:
    """Answers "may a pattern with these required literals match this text?" for one text."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._lower: str | None = None
        self._ascii = text.isascii()

    def may_match(self, clauses: tuple[Clause, ...] | None) -> bool:
        """False only when some clause has none of its literals in the text."""
        if clauses is None:
            return True
        return all(any(self._contains(lit) for lit in clause) for clause in clauses)

    def _contains(self, lit: Literal) -> bool:
        if not lit.ignorecase:
            return lit.text in self._text
        # Case-insensitive regex matching uses Unicode case-folding equivalences that str.lower()
        # does not reproduce (the Kelvin sign matches "k", the long s matches "s"). They involve
        # non-ASCII characters only, so lower-casing is exact when text and literal are ASCII.
        if not (self._ascii and lit.text.isascii()):
            return True
        if self._lower is None:
            self._lower = self._text.lower()
        return lit.text in self._lower
