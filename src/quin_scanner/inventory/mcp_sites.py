"""MCP servers implemented in code, and the tools registered on them (MCPScanner's code evidence, #71).

Python is parsed with ``ast``: ``FastMCP(...)`` / ``MCPServer(...)`` imported from ``mcp.server...`` or ``fastmcp``, and
the low-level ``Server(...)`` only when imported from ``mcp.server`` or ``mcp.server.lowlevel`` (``Server`` is a common
name). Tools are functions decorated ``@<server>.tool(...)``, and for low-level servers ``Tool(name=...)`` calls inside
the ``@<server>.list_tools()`` function.

JavaScript/TypeScript is read like ``js_sites``, skipping comments and strings: ``new McpServer({...})`` and
``new Server({...})`` when the class is imported from ``@modelcontextprotocol/sdk`` or ``@modelcontextprotocol/server``.
Tools are ``<server>.tool("name", ...)`` and ``<server>.registerTool("name", ...)`` calls, and for low-level servers the
``name:`` of the object literals in the ``tools`` array of the ``ListToolsRequestSchema`` handler.

A tool registered on a server that is not created in the same file (``server`` passed in as a parameter, or imported
from the module that creates it) is a :class:`LooseTool`; the caller links it to a server elsewhere in the repository.
Names are literals, or module constants (``NAME = "x"``, ``Tools.STATUS.value``, ``const name = "x"``) that resolve to one.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from quin_scanner.inventory.evidence import clean_name
from quin_scanner.inventory.js_sites import _string_at, _top_level_items, _top_level_view, _value, code_view
from quin_scanner.inventory.python_sites import parse_python, string_constant

PYTHON_SUFFIXES = frozenset({".py"})
TYPESCRIPT_SUFFIXES = frozenset({".ts", ".tsx", ".mts", ".cts"})
JAVASCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs"})
CODE_SUFFIXES = PYTHON_SUFFIXES | TYPESCRIPT_SUFFIXES | JAVASCRIPT_SUFFIXES


@dataclass(frozen=True)
class McpTool:
    name: str
    line: int | None


@dataclass
class McpServerSite:
    """One constructor call that creates an MCP server."""
    name: str | None          # literal (or resolved constant) name; None when not statically known
    var: str | None           # the variable it is assigned to (``server``, ``self.mcp``), if any
    file_path: str
    line: int | None
    language: str             # "python" | "typescript" | "javascript"
    sdk: str                  # "mcp", "fastmcp", "@modelcontextprotocol/sdk", "@modelcontextprotocol/server"
    tools: list[McpTool] = field(default_factory=list)


@dataclass(frozen=True)
class LooseTool:
    """A tool registered on ``receiver``, a server that this file does not create."""
    receiver: str
    name: str
    file_path: str
    line: int | None
    language: str


def language_of(path: str) -> str | None:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in PYTHON_SUFFIXES:
        return "python"
    if suffix in TYPESCRIPT_SUFFIXES:
        return "typescript"
    if suffix in JAVASCRIPT_SUFFIXES:
        return "javascript"
    return None


def mcp_sites(content: str, path: str) -> tuple[list[McpServerSite], list[LooseTool]]:
    """The MCP servers created in one file and the tools registered on servers created elsewhere."""
    language = language_of(path)
    if language == "python":
        tree = parse_python(content)
        if tree is None:
            return [], []
        try:
            return _python_sites(tree, path)
        except RecursionError:
            return [], []
    if language is not None:
        return _js_sites(content, path, language)
    return [], []


def _clean(name: str | None) -> str | None:
    return clean_name(name) if name else None


# ── Python ──────────────────────────────────────────────────────────────────────────────────────────────────────────

_PY_HIGH_LEVEL = frozenset({"FastMCP", "MCPServer"})
_PY_LOW_LEVEL_MODULES = frozenset({"mcp.server", "mcp.server.lowlevel", "mcp.server.lowlevel.server"})


def _under(module: str, package: str) -> bool:
    return module == package or module.startswith(package + ".")


def _py_server_class(module: str, cls: str) -> tuple[str, bool] | None:
    """(sdk, low_level) when ``cls`` imported from ``module`` is an MCP server class, else None."""
    if cls in _PY_HIGH_LEVEL:
        if _under(module, "fastmcp"):
            return "fastmcp", False
        if _under(module, "mcp.server"):
            return "mcp", False
    if cls == "Server" and module in _PY_LOW_LEVEL_MODULES:
        return "mcp", True
    return None


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


class _PythonModule:
    """Imports and string constants of one module."""

    def __init__(self, tree: ast.Module) -> None:
        self.names: dict[str, tuple[str, str]] = {}   # local name → (module, imported name), absolute imports only
        self.imported: set[str] = set()               # every name bound by an import, relative imports included
        self.modules: dict[str, str] = {}             # local name → module, for ``import a.b [as c]``
        self.constants: dict[str, str] = {}           # ``NAME`` / ``Class.ATTR`` → string literal
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    local = alias.asname or alias.name
                    self.imported.add(local)
                    if node.level == 0 and node.module:
                        self.names[local] = (node.module, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    self.imported.add(local)
                    self.modules[local] = alias.name if alias.asname else alias.name.split(".")[0]
        for node in tree.body:
            self._constant(node, "")
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    self._constant(item, node.name + ".")

    def _constant(self, node: ast.stmt, prefix: str) -> None:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            target, value = node.target.id, node.value
        else:
            return
        text = string_constant(value)
        if text is not None:
            self.constants[prefix + target] = text

    def resolve(self, node: ast.expr | None) -> str | None:
        """A string literal, or a module constant / class attribute (``.value`` of an enum member too) holding one."""
        if node is None:
            return None
        text = string_constant(node)
        if text is not None:
            return text
        dotted = _dotted(node)
        if dotted is None:
            return None
        if dotted.endswith(".value"):
            dotted = dotted[: -len(".value")]
        return self.constants.get(dotted)

    def server_class(self, func: ast.expr) -> tuple[str, bool] | None:
        if isinstance(func, ast.Name):
            imported = self.names.get(func.id)
            return _py_server_class(*imported) if imported else None
        dotted = _dotted(func)
        if dotted is None or "." not in dotted:
            return None
        prefix, _, cls = dotted.rpartition(".")
        first, _, rest = prefix.partition(".")
        if first in self.modules:
            module = self.modules[first]
        elif first in self.names:
            module = ".".join(self.names[first])
        else:
            return None
        return _py_server_class(f"{module}.{rest}" if rest else module, cls)


@dataclass
class _PyServer:
    site: McpServerSite
    scope: tuple[int, ...]
    low_level: bool
    handlers: list[ast.expr] = field(default_factory=list)   # list-tools handlers: on_list_tools=, add_request_handler


def _call_name(call: ast.Call, module: _PythonModule) -> str | None:
    """The ``name=`` keyword, else the first positional argument, resolved to a string."""
    for kw in call.keywords:
        if kw.arg == "name":
            return module.resolve(kw.value)
    return module.resolve(call.args[0]) if call.args else None


class _PythonCollector(ast.NodeVisitor):
    """Server constructors (with the variable and scope they are bound in), tool decorators, list-tools handler
    registrations and every function by name.

    Scopes are the enclosing functions and classes; ``self.x = Server(...)`` belongs to the enclosing class, so methods
    of that class find it.
    """

    def __init__(self, module: _PythonModule, path: str) -> None:
        self.module = module
        self.path = path
        self.scope: list[tuple[int, bool]] = []   # (id(node), is_class)
        self.servers: list[_PyServer] = []
        self.functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        self._assigned: dict[int, str] = {}   # id(constructor call) → variable
        # (receiver, decorator attribute, decorator, function, scope)
        self.decorated: list[tuple[str, str, ast.expr, ast.FunctionDef | ast.AsyncFunctionDef, tuple[int, ...]]] = []
        # (receiver, handler expression, scope, line) for ``<server>.add_request_handler("tools/list", ..., handler)``
        self.registered: list[tuple[str, ast.expr, tuple[int, ...], int]] = []

    def _scope_ids(self) -> tuple[int, ...]:
        return tuple(node_id for node_id, _ in self.scope)

    def _class_scope(self) -> tuple[int, ...]:
        """The scope up to the innermost enclosing class (the whole scope when there is none)."""
        for i in range(len(self.scope) - 1, -1, -1):
            if self.scope[i][1]:
                return tuple(node_id for node_id, _ in self.scope[: i + 1])
        return self._scope_ids()

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.functions.setdefault(node.name, []).append(node)
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and target.attr in ("tool", "list_tools"):
                receiver = _dotted(target.value)
                if receiver:
                    self.decorated.append((receiver, target.attr, decorator, node, self._scope_ids()))
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.scope.append((id(node), False))
        for child in (node.args, *node.body):
            self.visit(child)
        self.scope.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for child in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(child)
        self.scope.append((id(node), True))
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def _assign(self, targets: list[ast.expr], value: ast.expr | None) -> None:
        if isinstance(value, ast.Call):
            for target in targets:
                var = _dotted(target)
                if var:
                    self._assigned[id(value)] = var

    def visit_Assign(self, node: ast.Assign) -> None:
        self._assign(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._assign([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        found = self.module.server_class(node.func)
        if found is not None:
            sdk, low_level = found
            var = self._assigned.get(id(node))
            scope = self._class_scope() if var and var.startswith("self.") else self._scope_ids()
            self.servers.append(_PyServer(
                McpServerSite(
                    name=_clean(_call_name(node, self.module)), var=var, file_path=self.path,
                    line=node.lineno, language="python", sdk=sdk,
                ),
                scope, low_level, [kw.value for kw in node.keywords if kw.arg == "on_list_tools"],
            ))
        elif (
            isinstance(node.func, ast.Attribute) and node.func.attr == "add_request_handler"
            and len(node.args) >= 3 and string_constant(node.args[0]) == "tools/list"
        ):
            receiver = _dotted(node.func.value)
            if receiver:
                self.registered.append((receiver, node.args[2], self._scope_ids(), node.lineno))
        self.generic_visit(node)

    def server_for(self, receiver: str, scope: tuple[int, ...], line: int) -> _PyServer | None:
        """The server assigned to ``receiver`` in the innermost enclosing scope; the last one before ``line`` there."""
        candidates = [s for s in self.servers if s.site.var == receiver and scope[: len(s.scope)] == s.scope]
        if not candidates:
            return None
        depth = max(len(s.scope) for s in candidates)
        innermost = [s for s in candidates if len(s.scope) == depth]
        before = [s for s in innermost if (s.site.line or 0) <= line]
        return before[-1] if before else innermost[0]

    def handler_functions(self, handler: ast.expr) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        """The functions a handler expression names (``list_tools``, ``self._list_tools``)."""
        if isinstance(handler, ast.Name):
            return list(self.functions.get(handler.id, []))
        if isinstance(handler, ast.Attribute):
            return list(self.functions.get(handler.attr, []))
        return []


def _declared_tools(
    collector: _PythonCollector, functions: list[ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[McpTool]:
    """``Tool(name=...)`` calls in list-tools handlers, and in the functions of this file that they call (one level:
    ``return ListToolsResult(tools=self._tool_definitions())``)."""
    bodies = list(functions)
    for function in functions:
        for node in ast.walk(function):
            if isinstance(node, ast.Call):
                bodies += [f for f in collector.handler_functions(node.func) if f not in bodies]
    tools: list[McpTool] = []
    for body in bodies:
        for node in ast.walk(body):
            if isinstance(node, ast.Call) and _callee(node.func) == "Tool":
                name_node = next((kw.value for kw in node.keywords if kw.arg == "name"), None)
                name = _clean(collector.module.resolve(name_node))
                if name:
                    tools.append(McpTool(name, node.lineno))
    return tools


def _python_sites(tree: ast.Module, path: str) -> tuple[list[McpServerSite], list[LooseTool]]:
    module = _PythonModule(tree)
    collector = _PythonCollector(module, path)
    collector.visit(tree)
    loose: list[LooseTool] = []
    handlers: dict[int, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for receiver, attr, decorator, function, scope in collector.decorated:
        server = collector.server_for(receiver, scope, function.lineno)
        if attr == "tool":
            name = _call_name(decorator, module) if isinstance(decorator, ast.Call) else None
            # Without a resolvable name the SDK names the tool after the function.
            name = _clean(name) or function.name
            if server is not None:
                server.site.tools.append(McpTool(name, function.lineno))
            elif receiver in module.imported:
                loose.append(LooseTool(receiver, name, path, function.lineno, "python"))
        elif server is not None:
            handlers.setdefault(id(server), []).append(function)
    for receiver, handler, scope, line in collector.registered:
        server = collector.server_for(receiver, scope, line)
        if server is not None:
            handlers.setdefault(id(server), []).extend(collector.handler_functions(handler))
    for server in collector.servers:
        functions = handlers.get(id(server), [])
        for handler in server.handlers:
            functions += collector.handler_functions(handler)
        if server.low_level and functions:
            server.site.tools.extend(_declared_tools(collector, functions))
    return [s.site for s in collector.servers], loose


def _callee(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# ── JavaScript / TypeScript ─────────────────────────────────────────────────────────────────────────────────────────

_JS_PACKAGES = ("@modelcontextprotocol/sdk", "@modelcontextprotocol/server")
_JS_SERVER_CLASSES = frozenset({"McpServer", "Server"})
_IDENT = r"[A-Za-z_$][\w$]*"
_IMPORT = re.compile(rf"\bimport\s+(type\s+)?(?:{_IDENT}\s*,\s*)?\{{([^}}]*)\}}\s*from\s*(['\"])([^'\"]+)\3")
_IMPORT_ANY = re.compile(r"\b(?:import|from|require\s*\()\s*(['\"])(@modelcontextprotocol/[^'\"]+)\1")
_REQUIRE = re.compile(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*(['\"])([^'\"]+)\2\s*\)")
_NEW = re.compile(rf"\bnew\s+({_IDENT})\s*\(")
_ASSIGNED = re.compile(
    rf"(?:\b(?:const|let|var)\s+({_IDENT})(?:\s*:\s*[^=;]+?)?|((?:this\.)?{_IDENT}))\s*=\s*$"
)
_REGISTRATION = re.compile(rf"(?<![\w$.])((?:this\s*\.\s*)?{_IDENT})\s*\.\s*(tool|registerTool)\s*\(")
_LIST_TOOLS_HANDLER = re.compile(rf"(?<![\w$.])((?:this\s*\.\s*)?{_IDENT})\s*\.\s*setRequestHandler\s*\(\s*ListToolsRequestSchema\b")
_TOOLS_ARRAY = re.compile(r"(?:^|[,{\s])tools\s*:\s*\[")
_OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}


def _js_package(source: str) -> str | None:
    for package in _JS_PACKAGES:
        if source == package or source.startswith(package + "/"):
            return package
    return None


def _js_imports(content: str, view: str) -> tuple[dict[str, tuple[str, str]], bool]:
    """Local name → (class, package) for the server classes imported from the MCP SDK (value imports only), and
    whether the file imports anything from it at all (types included)."""
    classes: dict[str, tuple[str, str]] = {}

    def add(specifiers: str, package: str, separator: str) -> None:
        for spec in specifiers.split(","):
            spec = spec.strip()
            if not spec or spec.startswith("type "):
                continue
            imported, *rest = re.split(separator, spec, maxsplit=1)
            imported = imported.strip()
            local = rest[0].strip() if rest else imported
            if imported in _JS_SERVER_CLASSES and re.fullmatch(_IDENT, local):
                classes[local] = (imported, package)

    for match in _IMPORT.finditer(content):
        package = _js_package(match.group(4))
        if package and view[match.start()] == content[match.start()] and not match.group(1):
            add(match.group(2), package, r"\s+as\s+")
    for match in _REQUIRE.finditer(content):
        package = _js_package(match.group(3))
        if package and view[match.start()] == content[match.start()]:
            add(match.group(1), package, r"\s*:\s*")
    imports_sdk = any(view[m.start()] == content[m.start()] for m in _IMPORT_ANY.finditer(content))
    return classes, imports_sdk


def _closing(view: str, opening: int) -> int | None:
    """The bracket closing the one at ``opening``, counted in the code view (strings and comments are blank)."""
    depth = 0
    for i in range(opening, len(view)):
        char = view[i]
        if char in _OPEN_TO_CLOSE:
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _line(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _skip_space(content: str, i: int) -> int:
    while i < len(content) and content[i].isspace():
        i += 1
    return i


def _js_constant(content: str, view: str, name: str) -> str | None:
    """The string a ``const|let|var <name> = "..."`` in this file holds, when every such declaration holds the same one.

    Module-level declarations (at the start of a line, ``export`` allowed) win over nested ones when there are any, so a
    local variable of the same name in a handler does not hide the module constant.
    """
    found = [
        m for m in re.finditer(rf"\b(?:const|let|var)\s+{re.escape(name)}\s*(?::\s*[^=;]+?)?=\s*", content)
        if view[m.start()] == content[m.start()]
    ]
    top = [m for m in found if re.fullmatch(r"(?:export\s+)?", content[content.rfind("\n", 0, m.start()) + 1:m.start()])]
    values: set[str] = set()
    for match in top or found:
        start = match.end()
        if start < len(content) and content[start] in "'\"`":
            text = _string_at(content, start)
            if text is None or (content[start] == "`" and "${" in text):
                return None
            values.add(text)
        else:
            return None
    return values.pop() if len(values) == 1 else None


def _js_string_arg(content: str, view: str, start: int) -> str | None:
    """The first argument at ``start`` when it is a string literal, or an identifier naming a string constant."""
    i = _skip_space(content, start)
    if i >= len(content):
        return None
    if content[i] in "'\"`":
        text = _string_at(content, i)
        if text is None or (content[i] == "`" and "${" in text):
            return None
        return text
    ident = re.match(_IDENT, content[i:])
    if ident and content[_skip_space(content, i + ident.end()):][:1] in (",", ")"):
        return _js_constant(content, view, ident.group(0))
    return None


def _receiver(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _js_sites(content: str, path: str, language: str) -> tuple[list[McpServerSite], list[LooseTool]]:
    view = code_view(content)
    classes, imports_sdk = _js_imports(content, view)
    if not imports_sdk:
        return [], []
    servers: list[tuple[int, McpServerSite, bool]] = []   # (offset, site, low_level)
    for match in _NEW.finditer(content):
        if view[match.start():match.end()] != match.group(0) or match.group(1) not in classes:
            continue
        cls, package = classes[match.group(1)]
        name = None
        first = _skip_space(content, match.end())
        if first < len(content) and content[first] == "{":
            closing = _closing(view, first)
            if closing is not None:
                body = content[first + 1:closing]
                found = _value(body, _top_level_view(body), "name")
                if found and (found[0] == "literal" or (found[0] == "template" and "${" not in found[1])):
                    name = found[1]
        assigned = _ASSIGNED.search(view[max(0, match.start() - 200):match.start()])
        var = (assigned.group(1) or assigned.group(2)) if assigned else None
        servers.append((match.start(), McpServerSite(
            name=_clean(name), var=_receiver(var) if var else None, file_path=path, line=_line(content, match.start()),
            language=language, sdk=package,
        ), cls == "Server"))

    def server_for(receiver: str, offset: int) -> McpServerSite | None:
        named = [(o, s) for o, s, _ in servers if s.var == receiver]
        if not named:
            return None
        before = [s for o, s in named if o <= offset]
        return before[-1] if before else named[0][1]

    loose: list[LooseTool] = []
    for match in _REGISTRATION.finditer(content):
        if view[match.start():match.end()] != match.group(0):
            continue
        name = _clean(_js_string_arg(content, view, match.end()))
        if not name:
            continue
        receiver = _receiver(match.group(1))
        line = _line(content, match.start())
        server = server_for(receiver, match.start())
        if server is not None:
            server.tools.append(McpTool(name, line))
        else:
            loose.append(LooseTool(receiver, name, path, line, language))

    low_level = {id(site) for _, site, is_low in servers if is_low}
    for match in _LIST_TOOLS_HANDLER.finditer(content):
        if view[match.start():match.end()] != match.group(0):
            continue
        server = server_for(_receiver(match.group(1)), match.start())
        opening = content.find("(", match.start() + len(match.group(1)))
        closing = _closing(view, opening) if opening != -1 else None
        if server is None or id(server) not in low_level or closing is None:
            continue
        for array in _TOOLS_ARRAY.finditer(view, opening, closing):
            start = array.end() - 1
            end = _closing(view, start)
            if end is None:
                continue
            offset = start + 1
            for item in _top_level_items(content[start + 1:end]):
                stripped = item.strip()
                item_offset = offset + (len(item) - len(item.lstrip()))
                offset += len(item) + 1
                if not stripped.startswith("{"):
                    continue
                body = stripped[1:stripped.rfind("}")] if "}" in stripped else ""
                found = _value(body, _top_level_view(body), "name")
                if found and found[0] == "literal" and _clean(found[1]):
                    server.tools.append(McpTool(_clean(found[1]), _line(content, item_offset)))
    return [site for _, site, _ in servers], loose
