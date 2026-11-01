"""Agent sites in Python source: one ``ast`` pass gives AgentInstanceScanner its typed evidence."""
from __future__ import annotations

import ast
import dataclasses
import warnings

from quin_scanner.inventory.evidence import NO_INSTRUCTIONS, AgentSite, InstructionsRef
from quin_scanner.redaction import redact_secrets

_NAME_KEYWORDS = frozenset({"name", "agent_name"})
_INSTRUCTION_KEYWORDS = ("instructions", "system_prompt", "system_message", "backstory")
_MODEL_KEYWORDS = ("model", "llm", "model_client")
# Base classes that make a subclass an agent (as AgentInstanceScanner's class patterns).
_AGENT_BASES = frozenset({"Role", "BaseAgent", "AssistantAgent", "ConversableAgent", "UserProxyAgent"})
# Constructors that create an agent even without a literal name; other ``...agent(...)`` calls need one.
_ANONYMOUS_CONSTRUCTORS = frozenset({"Agent", "AssistantAgent", "UserProxyAgent", "ConversableAgent", "GroupChatManager"})
# Calls whose first string argument is a file the instructions are read from.
_FILE_READERS = frozenset({"open", "Path", "read_text", "load_prompt"})


def parse_python(content: str) -> ast.Module | None:
    """The module's syntax tree, or None if the source does not parse."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return None


def callee_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def string_constant(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def agent_name(call: ast.Call, callee: str) -> str | None:
    """The literal ``name=``/``agent_name=``, or for ``XAgent("...")`` classes (not bare ``Agent``) the first positional string."""
    name = next((string_constant(kw.value) for kw in call.keywords if kw.arg in _NAME_KEYWORDS), None)
    if name is None and callee.endswith("Agent") and callee != "Agent" and call.args:
        positional = string_constant(call.args[0])
        if positional is not None and 2 <= len(positional) <= 50:
            name = positional
    return name.strip() if name and name.strip() else None


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _first_string_arg(call: ast.Call) -> str | None:
    return next((s for s in (string_constant(a) for a in call.args) if s is not None), None)


def _config_key(node: ast.expr) -> str | None:
    """``self.agents_config['researcher']`` → ``researcher`` (CrewAI)."""
    if isinstance(node, ast.Subscript) and (_dotted(node.value) or "").endswith("agents_config"):
        return string_constant(node.slice)
    return None


def _instructions_ref(node: ast.expr) -> InstructionsRef:
    text = string_constant(node)
    if text is not None:
        return InstructionsRef.literal(text)
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and callee_name(sub.func) in _FILE_READERS:
            path = _first_string_arg(sub)
            if path:
                return InstructionsRef("file", path)
    dotted = _dotted(node)
    return InstructionsRef("var", dotted) if dotted else NO_INSTRUCTIONS


def instructions_of(call: ast.Call) -> InstructionsRef:
    for kw in call.keywords:
        if kw.arg == "config":
            key = _config_key(kw.value)
            if key:
                return InstructionsRef("config", key)
    for kw in call.keywords:
        if kw.arg in _INSTRUCTION_KEYWORDS:
            return _instructions_ref(kw.value)
    return NO_INSTRUCTIONS


def _env_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Call):
        if callee_name(node.func) == "getenv" or (_dotted(node.func) or "").endswith("environ.get"):
            return _first_string_arg(node)
    if isinstance(node, ast.Subscript) and (_dotted(node.value) or "").endswith("environ"):
        return string_constant(node.slice)
    return None


def _expression(node: ast.expr) -> str | None:
    text = string_constant(node)
    if text is not None:
        return redact_secrets(text)
    env = _env_name(node)
    if env:
        return f"env:{env}"
    dotted = _dotted(node)
    if dotted:
        return f"var:{dotted}"
    if isinstance(node, ast.Call):
        callee = callee_name(node.func) or "call"
        arg = _first_string_arg(node)
        return redact_secrets(f"{callee}({arg!r})" if arg else f"{callee}()")
    return None


def model_of(call: ast.Call) -> str | None:
    return next((_expression(kw.value) for kw in call.keywords if kw.arg in _MODEL_KEYWORDS), None)


def _name_chain(node: ast.expr) -> str | None:
    """``search.run`` → ``"search.run"``; None unless the whole expression is names and attributes."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_chain(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _tool_reference(node: ast.expr) -> str | None:
    chain = _name_chain(node)
    if chain:
        return chain
    text = string_constant(node)
    if text is not None:
        return text
    if isinstance(node, ast.Call):
        return next((string_constant(kw.value) for kw in node.keywords if kw.arg == "name"), None)
    return None


def tool_refs_of(call: ast.Call, missing: tuple[str, ...] | None) -> tuple[str, ...] | None:
    """Names in an explicit ``tools=[...]`` (``tools=None`` gives ``()``); ``missing`` when there is no ``tools=`` or ``**``.

    None (not statically known) when the value is not a literal list, or any element is a ``*spread`` or cannot be named:
    a partial list would claim tools are absent that may be passed.
    """
    kw = next((k for k in call.keywords if k.arg == "tools"), None)
    if kw is None:
        # ``**kwargs`` may pass tools implicitly.
        return None if any(k.arg is None for k in call.keywords) else missing
    if isinstance(kw.value, ast.Constant) and kw.value.value is None:
        return ()
    if not isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
        return None
    refs = []
    for element in kw.value.elts:
        ref = None if isinstance(element, ast.Starred) else _tool_reference(element)
        if ref is None or not ref.strip():
            return None
        refs.append(ref.strip())
    return tuple(refs)


def _agent_functions(tree: ast.Module) -> dict[str, int]:
    """Functions decorated with ``@agent`` (CrewAI and similar), with the decorator's line."""
    found: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if callee_name(target) == "agent":
                    found.setdefault(node.name, decorator.lineno)
    return found


def _base_name(base: ast.expr) -> str | None:
    """``BaseAgent`` and ``BaseAgent[Ctx]`` (a subscripted generic) both name ``BaseAgent``."""
    return callee_name(base.value if isinstance(base, ast.Subscript) else base)


def _agent_classes(tree: ast.Module) -> dict[str, int]:
    return {
        node.name: node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and any(_base_name(base) in _AGENT_BASES for base in node.bases)
    }


class _Collector(ast.NodeVisitor):
    def __init__(self, path: str, classes: dict[str, int], functions: dict[str, int]) -> None:
        self.path = path
        self.classes = classes
        self.functions = functions
        self.sites: list[AgentSite] = []
        self.functions_with_constructors: set[str] = set()
        self._loops = 0
        self._enclosing: list[str | None] = []   # innermost last; None for functions that are not @agent

    def _visit_all(self, nodes: list) -> None:
        for node in nodes:
            self.visit(node)

    def _in_loop(self, nodes: list) -> None:
        self._loops += 1
        self._visit_all(nodes)
        self._loops -= 1

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        # The iterable is evaluated once and ``else:`` runs once: only the body repeats.
        self._visit_all([node.target, node.iter])
        self._in_loop(node.body)
        self._visit_all(node.orelse)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self._in_loop([node.test, *node.body])
        self._visit_all(node.orelse)

    def _comprehension(self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp) -> None:
        # Only the first generator's iterable is evaluated once, outside the comprehension's loop.
        first, *rest = node.generators
        self.visit(first.iter)
        elements = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
        self._in_loop([first.target, *first.ifs, *rest, *elements])

    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _comprehension

    def _new_scope(self, node: ast.AST) -> None:
        # A function or class defined inside a loop body is not itself in a loop.
        saved, self._loops = self._loops, 0
        self.generic_visit(node)
        self._loops = saved

    visit_Lambda = visit_ClassDef = _new_scope

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._enclosing.append(node.name if node.name in self.functions else None)
        self._new_scope(node)
        self._enclosing.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        site = self._site(node)
        if site is not None:
            self.sites.append(site)
        self.generic_visit(node)

    def _site(self, node: ast.Call) -> AgentSite | None:
        callee = callee_name(node.func)
        if not callee:
            return None
        common = {"file_path": self.path, "line": node.lineno, "in_loop": self._loops > 0}
        if callee in self.classes:
            return AgentSite(
                role="instance", kind="constructor", name=agent_name(node, callee) or callee,
                instructions=instructions_of(node), model_expr=model_of(node),
                tool_refs=tool_refs_of(node, missing=None), **common,
            )
        if isinstance(node.func, ast.Name) and callee in self.functions:
            return AgentSite(role="instance", kind="decorator", name=callee, **common)
        lowered = callee.lower()
        if lowered != "groupchatmanager" and not lowered.endswith("agent"):
            return None
        name = agent_name(node, callee)
        instructions = instructions_of(node)
        enclosing = next((f for f in reversed(self._enclosing) if f), None)
        if enclosing:
            self.functions_with_constructors.add(enclosing)
            name = name or enclosing
        if name is None and callee not in _ANONYMOUS_CONSTRUCTORS and instructions.kind != "config":
            return None
        return AgentSite(
            role="both", kind="constructor", name=name, instructions=instructions,
            model_expr=model_of(node), tool_refs=tool_refs_of(node, missing=()), **common,
        )


def _redacted(site: AgentSite) -> AgentSite:
    """Credentials removed from every user-content string a site carries (a literal's hash is not user content)."""
    instructions = site.instructions
    if instructions.kind in ("file", "var", "config"):
        instructions = InstructionsRef(instructions.kind, redact_secrets(instructions.value))
    return dataclasses.replace(
        site,
        name=redact_secrets(site.name) if site.name else site.name,
        instructions=instructions,
        model_expr=redact_secrets(site.model_expr) if site.model_expr else site.model_expr,
        tool_refs=None if site.tool_refs is None else tuple(redact_secrets(ref) for ref in site.tool_refs),
    )


def agent_sites(tree: ast.Module, path: str) -> list[AgentSite]:
    """Every agent definition and instance in one parsed Python file, sorted by line, with credentials redacted.

    A tree too deep to walk recursively (it parsed, but visiting it raises RecursionError) gives no sites.
    """
    try:
        return [_redacted(site) for site in _all_sites(tree, path)]
    except RecursionError:
        return []


def _all_sites(tree: ast.Module, path: str) -> list[AgentSite]:
    classes = _agent_classes(tree)
    functions = _agent_functions(tree)
    collector = _Collector(path, classes, functions)
    collector.visit(tree)
    sites = list(collector.sites)
    sites += [
        AgentSite(role="definition", kind="subclass", name=name, file_path=path, line=line)
        for name, line in classes.items()
    ]
    sites += [
        AgentSite(role="definition", kind="decorator", name=name, file_path=path, line=line)
        for name, line in functions.items()
        if name not in collector.functions_with_constructors
    ]
    return sorted(sites, key=lambda s: (s.line or 0, s.name or "", s.kind))
