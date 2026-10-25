from __future__ import annotations

import hashlib
from pathlib import PurePosixPath

import yaml

from quin_scanner.file_index import FileIndex
from quin_scanner.models import SkillRecord
from quin_scanner.repo_accessor import RepoAccessor

_ECOSYSTEM_DIRS = {".claude": "claude", ".codex": "codex", ".opencode": "opencode"}

_MCP_MARKERS = (
    "@mcp.tool", "FastMCP(", "McpServer(", "server.tool(", ".registerTool(",
    '"inputSchema"', "mcp.server",
)
_MCP_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".json"}
_MCP_MAX_FILES_READ = 2000
_MCP_MAX_FILE_CHARS = 200_000


def _skill_id(path: str) -> str:
    return hashlib.sha256(path.encode()).hexdigest()[:16]


def parse_frontmatter(text: str) -> tuple[dict, bool]:
    """Parse YAML frontmatter. Returns (data, valid)."""
    text = text.lstrip("﻿")
    if not text.startswith("---"):
        return {}, False
    lines = text.splitlines()
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return {}, False
    try:
        data = yaml.safe_load("\n".join(lines[1:end]))
    except yaml.YAMLError:
        return {}, False
    if not isinstance(data, dict):
        return {}, False
    return data, True


def _split_tools(value: object) -> list[str]:
    """Split an `allowed-tools` value on commas/whitespace outside parentheses."""
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if not isinstance(value, str):
        return []
    tools: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0 and (ch == "," or ch.isspace()):
            if cur:
                tools.append("".join(cur))
                cur = []
            continue
        cur.append(ch)
    if cur:
        tools.append("".join(cur))
    return tools


def _ecosystem(path: str) -> str:
    for part in PurePosixPath(path).parts:
        if part in _ECOSYSTEM_DIRS:
            return _ECOSYSTEM_DIRS[part]
    return "generic"


def discover_skills(accessor: RepoAccessor, file_index: FileIndex) -> list[SkillRecord]:
    """Find every directory containing SKILL.md (case-insensitive) and describe it."""
    all_files = file_index.all_files()
    skill_mds = sorted(p for p in all_files if PurePosixPath(p).name.lower() == "skill.md")
    roots: dict[str, str] = {}
    for md in skill_mds:
        parent = str(PurePosixPath(md).parent)
        roots[parent] = md

    records: list[SkillRecord] = []
    for root, md_path in roots.items():
        if root == ".":
            under = list(all_files)
        else:
            prefix = root + "/"
            under = [f for f in all_files if f.startswith(prefix)]
        inner_roots = [
            r for r in roots
            if r != root and (root == "." or r.startswith(root + "/"))
        ]
        files = [
            f for f in under
            if not any(f.startswith(r + "/") for r in inner_roots)
        ]
        try:
            data, valid = parse_frontmatter(accessor.read_file(md_path))
        except Exception:
            data, valid = {}, False
        dir_name = PurePosixPath(root).name if root != "." else PurePosixPath(accessor.repo_identifier()).name
        records.append(
            SkillRecord(
                id=_skill_id(md_path),
                name=str(data.get("name") or dir_name or "skill"),
                description=str(data.get("description") or ""),
                root_path=root,
                skill_md_path=md_path,
                ecosystem=_ecosystem(md_path),
                allowed_tools=_split_tools(data.get("allowed-tools", data.get("allowed_tools"))),
                files=sorted(files),
                frontmatter_valid=valid,
            )
        )
    return records


def discover_mcp_sources(
    accessor: RepoAccessor, file_index: FileIndex, stats: dict | None = None
) -> SkillRecord | None:
    """Return one synthetic record whose files are repo files defining MCP tools.

    When *stats* is given, ``stats["read_cap_hit"]`` reports whether the read cap stopped the search.
    """
    if stats is not None:
        stats["read_cap_hit"] = False
    candidates: list[str] = []
    read = 0
    for path in sorted(file_index.all_files()):
        if PurePosixPath(path).suffix.lower() not in _MCP_SUFFIXES:
            continue
        if read >= _MCP_MAX_FILES_READ:
            if stats is not None:
                stats["read_cap_hit"] = True
            break
        read += 1
        try:
            text = accessor.read_file(path)
        except Exception:
            continue
        if len(text) > _MCP_MAX_FILE_CHARS:
            continue
        if any(marker in text for marker in _MCP_MARKERS):
            candidates.append(path)
    if not candidates:
        return None
    return SkillRecord(
        id=_skill_id("mcp:tool-definitions"),
        name="MCP tool definitions",
        description="MCP tool definitions found in repository source",
        root_path=".",
        skill_md_path="",
        ecosystem="mcp",
        files=candidates,
    )
