from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.skills.discovery import (
    discover_mcp_sources,
    discover_skills,
    parse_frontmatter,
)


def _index(tmp_path):
    accessor = LocalRepoAccessor(tmp_path)
    fi = FileIndex(accessor)
    fi.build()
    return accessor, fi


def _write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_parse_frontmatter_valid_and_invalid():
    data, ok = parse_frontmatter("---\nname: x\ndescription: y\n---\n# body")
    assert ok and data == {"name": "x", "description": "y"}
    assert parse_frontmatter("# no frontmatter") == ({}, False)
    assert parse_frontmatter("---\nname: [unclosed\n---\n")[1] is False
    assert parse_frontmatter("---\n- a\n- b\n---\n")[1] is False
    assert parse_frontmatter("---\nname: x\n")[1] is False  # never closed


def test_discovers_claude_skill_with_metadata(tmp_path):
    _write(
        tmp_path,
        ".claude/skills/commit/SKILL.md",
        "---\nname: commit\ndescription: Make commits\n"
        "allowed-tools: Bash(git add:*), Bash(git status:*)\n---\nBody",
    )
    _write(tmp_path, ".claude/skills/commit/scripts/run.sh", "echo hi")
    accessor, fi = _index(tmp_path)
    [rec] = discover_skills(accessor, fi)
    assert rec.name == "commit"
    assert rec.ecosystem == "claude"
    assert rec.allowed_tools == ["Bash(git add:*)", "Bash(git status:*)"]
    assert rec.skill_md_path == ".claude/skills/commit/SKILL.md"
    assert ".claude/skills/commit/scripts/run.sh" in rec.files
    assert rec.frontmatter_valid


def test_allowed_tools_list_form_and_codex_opencode(tmp_path):
    _write(tmp_path, ".codex/skills/a/SKILL.md", "---\nname: a\nallowed-tools: [Read, Grep]\n---\n")
    _write(tmp_path, ".opencode/skill/b/SKILL.md", "---\nname: b\n---\n")
    accessor, fi = _index(tmp_path)
    recs = {r.name: r for r in discover_skills(accessor, fi)}
    assert recs["a"].ecosystem == "codex" and recs["a"].allowed_tools == ["Read", "Grep"]
    assert recs["b"].ecosystem == "opencode"


def test_generic_skill_name_defaults_to_directory_and_invalid_frontmatter(tmp_path):
    _write(tmp_path, "skills/my-skill/SKILL.md", "# just markdown")
    accessor, fi = _index(tmp_path)
    [rec] = discover_skills(accessor, fi)
    assert rec.name == "my-skill"
    assert rec.ecosystem == "generic"
    assert rec.frontmatter_valid is False


def test_lowercase_skill_md_and_repo_root_skill(tmp_path):
    _write(tmp_path, "skill.md", "---\nname: root\n---\n")
    _write(tmp_path, "helper.py", "x = 1")
    accessor, fi = _index(tmp_path)
    [rec] = discover_skills(accessor, fi)
    assert rec.root_path == "."
    assert "helper.py" in rec.files


def test_nested_skill_files_belong_to_inner_skill_only(tmp_path):
    _write(tmp_path, "skills/outer/SKILL.md", "---\nname: outer\n---\n")
    _write(tmp_path, "skills/outer/a.py", "a = 1")
    _write(tmp_path, "skills/outer/inner/SKILL.md", "---\nname: inner\n---\n")
    _write(tmp_path, "skills/outer/inner/b.py", "b = 1")
    accessor, fi = _index(tmp_path)
    recs = {r.name: r for r in discover_skills(accessor, fi)}
    assert "skills/outer/a.py" in recs["outer"].files
    assert "skills/outer/inner/b.py" not in recs["outer"].files
    assert "skills/outer/inner/b.py" in recs["inner"].files


def test_no_skills_returns_empty(tmp_path):
    _write(tmp_path, "app.py", "print(1)")
    accessor, fi = _index(tmp_path)
    assert discover_skills(accessor, fi) == []
    assert discover_mcp_sources(accessor, fi) is None


def test_discover_mcp_sources_finds_tool_definitions(tmp_path):
    _write(tmp_path, "server.py", "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n")
    _write(tmp_path, "other.py", "print(1)")
    _write(tmp_path, "tools.json", '{"tools": [{"name": "t", "inputSchema": {}}]}')
    accessor, fi = _index(tmp_path)
    rec = discover_mcp_sources(accessor, fi)
    assert rec is not None
    assert rec.ecosystem == "mcp"
    assert sorted(rec.files) == ["server.py", "tools.json"]
