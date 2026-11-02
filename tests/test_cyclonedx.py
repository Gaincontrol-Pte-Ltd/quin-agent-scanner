"""CycloneDX AI-BOM mapping (spec: docs/superpowers/specs/2026-11-02-cyclonedx-ai-bom-design.md)."""
from __future__ import annotations

import json
import re

from quin_scanner import __version__
from quin_scanner.cyclonedx import (
    _iso_utc,
    _purl,
    _Refs,
    _repo_name,
    build_bom,
    omitted_vulnerability_count,
    to_cyclonedx,
)
from quin_scanner.models import (
    AgentInstance,
    AgentProfile,
    EndpointUsage,
    InstanceTool,
    LLMInferredItem,
    MCPServer,
    ModelUsage,
    RiskIndicator,
    ScanReport,
    ToolUsage,
    Vulnerability,
)
from quin_scanner.vuln_checker import FrameworkRef
from tests.cyclonedx_support import bom_errors


def _report(**fields) -> ScanReport:
    base = dict(
        repo_path="/home/dev/demo-repo",
        scan_timestamp="2026-11-02T10:15:30.123456+00:00",
        is_ai_application=True,
        confidence=0.9,
    )
    base.update(fields)
    return ScanReport(**base)


def _valid(bom: dict) -> dict:
    assert bom_errors(bom) == []
    return bom


class TestHeader:
    def test_header_fields(self):
        bom = _valid(build_bom(_report()))
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"
        assert bom["version"] == 1
        assert re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}", bom["serialNumber"])

    def test_serial_number_is_new_every_time(self):
        assert build_bom(_report())["serialNumber"] != build_bom(_report())["serialNumber"]

    def test_metadata(self):
        meta = build_bom(_report())["metadata"]
        assert meta["timestamp"] == "2026-11-02T10:15:30Z"
        assert meta["tools"] == {"components": [{"type": "application", "name": "quin-scanner", "version": __version__}]}
        assert meta["component"] == {"type": "application", "bom-ref": "repo", "name": "demo-repo"}

    def test_empty_inventory_is_valid_and_has_only_the_root(self):
        bom = _valid(build_bom(_report()))
        assert "components" not in bom
        assert "services" not in bom
        assert "vulnerabilities" not in bom
        assert bom["dependencies"] == [{"ref": "repo"}]

    def test_to_cyclonedx_is_indented_json(self):
        text = to_cyclonedx(_report())
        assert text.startswith("{\n  \"bomFormat\": \"CycloneDX\"")
        assert json.loads(text)["specVersion"] == "1.6"

    def test_non_ascii_is_kept(self):
        text = to_cyclonedx(_report(repo_path="/home/dev/démo"))
        assert "démo" in text


class TestRepoName:
    def test_github_owner_and_repo(self):
        assert _repo_name("acme/agents") == "acme/agents"

    def test_local_path_uses_the_directory_name(self):
        assert _repo_name("/home/dev/demo-repo/") == "demo-repo"

    def test_windows_path(self):
        assert _repo_name("C:\\work\\demo") == "demo"

    def test_git_suffix_is_removed(self):
        assert _repo_name("/srv/demo.git") == "demo"

    def test_empty_falls_back(self):
        assert _repo_name("") == "repository"


class TestIsoUtc:
    def test_offset_datetime(self):
        assert _iso_utc("2026-11-02T12:15:30+02:00") == "2026-11-02T10:15:30Z"

    def test_z_suffix(self):
        assert _iso_utc("2024-08-15T09:00:00Z") == "2024-08-15T09:00:00Z"

    def test_bare_date(self):
        assert _iso_utc("2024-08-15") == "2024-08-15T00:00:00Z"

    def test_naive_datetime_is_utc(self):
        assert _iso_utc("2024-08-15T09:00:00") == "2024-08-15T09:00:00Z"

    def test_unparsable_and_empty(self):
        assert _iso_utc("last week") is None
        assert _iso_utc("0001-01-01T00:00:00+01:00") is None
        assert _iso_utc("9999-12-31T23:00:00-05:00") is None
        assert _iso_utc("") is None
        assert _iso_utc(None) is None


class TestRefs:
    def test_first_use_is_unchanged_and_repeats_get_a_counter(self):
        refs = _Refs()
        assert refs.take("service:mcp:fs") == "service:mcp:fs"
        assert refs.take("service:mcp:fs") == "service:mcp:fs#2"
        assert refs.take("service:mcp:fs") == "service:mcp:fs#3"

    def test_root_is_reserved(self):
        assert _Refs().take("repo") == "repo#2"


def _vuln(cve_id="CVE-2024-0001", severity="high", source="osv", **kw) -> Vulnerability:
    fields = dict(cve_id=cve_id, severity=severity, cvss_score=7.5, published="2024-08-15",
                  summary="Prompt injection in tool router", source=source,
                  source_url=f"https://osv.dev/vulnerability/{cve_id}")
    fields.update(kw)
    return Vulnerability(**fields)


class TestFramework:
    def test_framework_component(self):
        bom = _valid(build_bom(_report(framework="CrewAI 0.80.0")))
        assert bom["components"] == [{
            "type": "framework", "bom-ref": "pkg:pypi/crewai@0.80.0", "name": "crewai",
            "version": "0.80.0", "purl": "pkg:pypi/crewai@0.80.0",
        }]
        assert {"ref": "repo", "dependsOn": ["pkg:pypi/crewai@0.80.0"]} in bom["dependencies"]
        assert {"ref": "pkg:pypi/crewai@0.80.0"} in bom["dependencies"]

    def test_unresolvable_framework_gives_no_component(self):
        bom = _valid(build_bom(_report(framework="unknown")))
        assert "components" not in bom

    def test_pypi_names_are_normalised(self):
        assert _purl(FrameworkRef("X", "1.0", "PyPI", "Llama_Index.Core")) == "pkg:pypi/llama-index-core@1.0"

    def test_npm_scope_is_percent_encoded(self):
        assert _purl(FrameworkRef("Mastra", "0.10.1", "npm", "@mastra/core")) == "pkg:npm/%40mastra/core@0.10.1"

    def test_npm_without_scope(self):
        assert _purl(FrameworkRef("Vercel AI SDK", "4.0.0", "npm", "ai")) == "pkg:npm/ai@4.0.0"

    def test_unknown_ecosystem(self):
        assert _purl(FrameworkRef("X", "1.0", "Maven", "x")) is None


class TestVulnerabilities:
    def test_osv_vulnerability(self):
        bom = _valid(build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=[_vuln()])))
        assert bom["vulnerabilities"] == [{
            "bom-ref": "vuln:CVE-2024-0001",
            "id": "CVE-2024-0001",
            "source": {"name": "OSV", "url": "https://osv.dev/vulnerability/CVE-2024-0001"},
            "ratings": [{"score": 7.5, "severity": "high"}],
            "description": "Prompt injection in tool router",
            "published": "2024-08-15T00:00:00Z",
            "affects": [{"ref": "pkg:pypi/crewai@0.80.0"}],
        }]

    def test_web_search_and_unidentified_entries_are_left_out(self):
        vulns = [_vuln("CVE-2024-0002", source="web:perplexity"), _vuln(None), _vuln("")]
        bom = _valid(build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=vulns)))
        assert "vulnerabilities" not in bom

    def test_no_framework_component_means_no_vulnerabilities(self):
        bom = _valid(build_bom(_report(framework="unknown", vulnerabilities=[_vuln()])))
        assert "vulnerabilities" not in bom

    def test_optional_fields_are_omitted(self):
        v = _vuln(cvss_score=None, published="soon", summary="", source_url=None, severity="weird")
        out = build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=[v]))["vulnerabilities"][0]
        assert out["ratings"] == [{"severity": "unknown"}]
        assert out["source"] == {"name": "OSV"}
        assert "published" not in out and "description" not in out
        _valid(build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=[v])))

    def test_sorted_by_severity_then_id_and_deduplicated(self):
        vulns = [_vuln("CVE-B", "medium"), _vuln("CVE-C", "critical"), _vuln("CVE-A", "medium"), _vuln("CVE-C", "critical")]
        bom = build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=vulns))
        assert [v["id"] for v in bom["vulnerabilities"]] == ["CVE-C", "CVE-A", "CVE-B"]

    def test_omitted_count_counts_web_search_entries(self):
        vulns = [_vuln(), _vuln("CVE-2", source="web:gemini"), _vuln("CVE-3", source="web:openai")]
        assert omitted_vulnerability_count(_report(vulnerabilities=vulns)) == 2

    def test_duplicate_id_picks_the_same_winner_in_either_order(self):
        a = _vuln("CVE-D", "high", cvss_score=7.0, summary="alpha")
        b = _vuln("CVE-D", "high", cvss_score=9.0, summary="beta")
        one = build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=[a, b]))["vulnerabilities"]
        two = build_bom(_report(framework="CrewAI 0.80.0", vulnerabilities=[b, a]))["vulnerabilities"]
        assert one == two
        assert one[0]["description"] == "beta"


def _model(provider="openai", name="gpt-4o", file="app.py", line=3) -> ModelUsage:
    return ModelUsage(provider=provider, model_name=name, source="code", file_path=file, line_number=line)


class TestModels:
    def test_model_component_with_occurrences(self):
        usages = [_model(line=9), _model(file="a.py", line=2), _model(line=3), _model(line=3)]
        bom = _valid(build_bom(_report(model_usages=usages)))
        assert bom["components"] == [{
            "type": "machine-learning-model", "bom-ref": "model:openai/gpt-4o", "name": "gpt-4o",
            "publisher": "openai",
            "evidence": {"occurrences": [
                {"location": "a.py", "line": 2}, {"location": "app.py", "line": 3}, {"location": "app.py", "line": 9},
            ]},
        }]

    def test_one_component_per_provider_and_name(self):
        usages = [_model("openai", "gpt-4o"), _model("azure", "gpt-4o"), _model("anthropic", "claude-x")]
        refs = [c["bom-ref"] for c in build_bom(_report(model_usages=usages))["components"]]
        assert refs == ["model:anthropic/claude-x", "model:azure/gpt-4o", "model:openai/gpt-4o"]

    def test_empty_name_and_missing_location(self):
        bom = _valid(build_bom(_report(model_usages=[_model(name=" "), _model(file="")])))
        assert len(bom["components"]) == 1
        assert "evidence" not in bom["components"][0]

    def test_empty_provider_becomes_unknown(self):
        bom = build_bom(_report(model_usages=[_model(provider="")]))
        assert bom["components"][0]["bom-ref"] == "model:unknown/gpt-4o"
        assert bom["components"][0]["publisher"] == "unknown"

    def test_models_are_not_root_dependencies(self):
        bom = build_bom(_report(model_usages=[_model()]))
        assert {"ref": "repo"} in bom["dependencies"]
        assert {"ref": "model:openai/gpt-4o"} in bom["dependencies"]


def _instance(iid, file="crew.py", line=10, scope="production", model=None, tools=(), known=True, many=False):
    return AgentInstance(
        id=iid, file=file, line=line, scope=scope, model=model,
        tools=[InstanceTool(name=n, tool_id=t, resolved=t is not None) for n, t in tools],
        tools_known=known, multiplicity="many" if many else "one",
    )


def _agent(aid="agent:researcher", name="researcher", scope="production", instances=(), identity="strong"):
    return AgentProfile(name=name, agent_type="worker", goal="Find things", capabilities=["search"],
                        id=aid, identity=identity, scope=scope, instances=list(instances),
                        risk_signals=[RiskIndicator(signal="Tool divergence", severity="medium")],
                        flags=["tool_divergence"], provenance={"goal": "llm"})


def _tool(tid="tool:search", name="search", file="tools.py", line=4, tool_type="tool_definition"):
    return ToolUsage(tool_name=name, tool_type=tool_type, service_category="web_search",
                     source_file=file, line_number=line, id=tid)


def _component(bom, ref):
    return next(c for c in bom["components"] if c["bom-ref"] == ref)


class TestAgents:
    def test_agent_component(self):
        agent = _agent(instances=[_instance("agent:researcher/crew.py#1", model="gpt-4o", tools=[("search", "tool:search")])])
        bom = _valid(build_bom(_report(agents=[agent], tool_usages=[_tool()])))
        assert _component(bom, "agent:researcher") == {
            "type": "application", "bom-ref": "agent:researcher", "name": "researcher", "scope": "required",
            "properties": [{"name": "quin:identity", "value": "strong"}, {"name": "quin:kind", "value": "agent"}],
            "evidence": {"occurrences": [{
                "bom-ref": "agent:researcher/crew.py#1", "location": "crew.py", "line": 10,
                "additionalContext": "scope=production; model=gpt-4o; tools=search",
            }]},
        }

    def test_test_and_example_agents_are_excluded(self):
        bom = build_bom(_report(agents=[_agent("agent:a", "a", scope="test"), _agent("agent:b", "b", scope="example")]))
        assert [c["scope"] for c in bom["components"]] == ["excluded", "excluded"]

    def test_instance_context_variants(self):
        instances = [
            _instance("i#1", line=1, scope="test", known=False),
            _instance("i#2", line=2, tools=()),
            _instance("i#3", line=3, model="env:MODEL", tools=[("a", None), ("b", "tool:b")], many=True),
        ]
        occ = build_bom(_report(agents=[_agent(instances=instances)]))["components"][0]["evidence"]["occurrences"]
        assert [o["additionalContext"] for o in occ] == [
            "scope=test; tools=unknown",
            "scope=production; tools=",
            "scope=production; model=env:MODEL; tools=a,b; multiplicity=many",
        ]

    def test_occurrences_sorted_and_line_optional(self):
        instances = [_instance("x#2", file="b.py", line=None), _instance("x#1", file="a.py", line=7)]
        occ = _valid(build_bom(_report(agents=[_agent(instances=instances)])))["components"][0]["evidence"]["occurrences"]
        assert occ[0]["location"] == "a.py"
        assert occ[1] == {"bom-ref": "x#2", "location": "b.py", "additionalContext": "scope=production; tools="}

    def test_weak_agent_without_name_uses_its_id(self):
        bom = _valid(build_bom(_report(agents=[_agent("agent:@x.py#1", "", identity="weak")])))
        assert bom["components"][0]["name"] == "agent:@x.py#1"

    def test_llm_fields_are_not_exported(self):
        text = to_cyclonedx(_report(
            agents=[_agent()],
            llm_inferred_agents=[LLMInferredItem(name="ghost", evidence="maybe")],
            llm_inferred_tools=[LLMInferredItem(name="phantom_tool")],
        ))
        for absent in ("Find things", "Tool divergence", "tool_divergence", "ghost", "phantom_tool", "worker", "provenance"):
            assert absent not in text

    def test_agents_are_root_dependencies(self):
        bom = build_bom(_report(agents=[_agent()]))
        assert {"ref": "repo", "dependsOn": ["agent:researcher"]} in bom["dependencies"]


class TestTools:
    def test_tool_component(self):
        bom = _valid(build_bom(_report(tool_usages=[_tool()])))
        assert bom["components"] == [{
            "type": "application", "bom-ref": "tool:search", "name": "search",
            "properties": [{"name": "quin:kind", "value": "tool"}, {"name": "quin:tool-type", "value": "tool_definition"}],
            "evidence": {"occurrences": [{"location": "tools.py", "line": 4}]},
        }]

    def test_service_category_is_not_exported(self):
        assert "web_search" not in to_cyclonedx(_report(tool_usages=[_tool()]))

    def test_tool_without_location(self):
        bom = _valid(build_bom(_report(tool_usages=[_tool(file="", line=None)])))
        assert "evidence" not in bom["components"][0]

    def test_tool_without_id_gets_one_from_its_name(self):
        assert build_bom(_report(tool_usages=[_tool(tid="")]))["components"][0]["bom-ref"] == "tool:search"


class TestComponentOrder:
    def test_framework_models_agents_tools(self):
        report = _report(framework="CrewAI 0.80.0", model_usages=[_model()], agents=[_agent()], tool_usages=[_tool()])
        kinds = [c["bom-ref"].split(":")[0] for c in build_bom(report)["components"]]
        assert kinds == ["pkg", "model", "agent", "tool"]

    def test_agents_sorted_by_ref(self):
        bom = build_bom(_report(agents=[_agent("agent:b", "b"), _agent("agent:a", "a")]))
        assert [c["bom-ref"] for c in bom["components"]] == ["agent:a", "agent:b"]


class TestAgentDependencies:
    def test_agent_depends_on_linked_tools_and_literal_models(self):
        instances = [
            _instance("r#1", model="gpt-4o", tools=[("search", "tool:search"), ("ghost", None)]),
            _instance("r#2", model="env:MODEL", tools=[("search", "tool:search"), ("missing", "tool:missing")]),
        ]
        bom = _valid(build_bom(_report(agents=[_agent(instances=instances)], tool_usages=[_tool()],
                                       model_usages=[_model(name="GPT-4o")])))
        assert {"ref": "agent:researcher", "dependsOn": ["model:openai/GPT-4o", "tool:search"]} in bom["dependencies"]

    def test_every_component_has_a_dependency_entry(self):
        report = _report(framework="CrewAI 0.80.0", model_usages=[_model()], agents=[_agent()], tool_usages=[_tool()])
        bom = build_bom(report)
        refs = {c["bom-ref"] for c in bom["components"]} | {"repo"}
        assert {d["ref"] for d in bom["dependencies"]} == refs


def _endpoint(url="https://llm.internal.example/v1", host="llm.internal.example", kind="private"):
    return EndpointUsage(url=url, host=host, kind=kind, source="code", file_path="app.py", line_number=5)


class TestServices:
    def test_mcp_server(self):
        bom = _valid(build_bom(_report(mcp_servers=[MCPServer(name="filesystem", transport="stdio", source_file=".mcp.json")])))
        assert bom["services"] == [{
            "bom-ref": "service:mcp:filesystem", "name": "filesystem",
            "properties": [{"name": "quin:source-file", "value": ".mcp.json"}, {"name": "quin:transport", "value": "stdio"}],
        }]
        assert {"ref": "repo", "dependsOn": ["service:mcp:filesystem"]} in bom["dependencies"]

    def test_mcp_without_source_file(self):
        bom = _valid(build_bom(_report(mcp_servers=[MCPServer(name="fs")])))
        assert bom["services"][0]["properties"] == [{"name": "quin:transport", "value": "unknown"}]

    def test_duplicate_mcp_names_get_counters_in_sorted_order(self):
        servers = [MCPServer(name="fs", transport="stdio", source_file="b/.mcp.json"),
                   MCPServer(name="fs", transport="stdio", source_file="a/.mcp.json")]
        services = _valid(build_bom(_report(mcp_servers=servers)))["services"]
        assert [(s["bom-ref"], s["properties"][0]["value"]) for s in services] == [
            ("service:mcp:fs", "a/.mcp.json"), ("service:mcp:fs#2", "b/.mcp.json"),
        ]

    def test_endpoints_grouped_by_host(self):
        endpoints = [_endpoint(), _endpoint(url="https://llm.internal.example/v2"), _endpoint(),
                     _endpoint(url="http://localhost:11434", host="localhost", kind="local")]
        services = _valid(build_bom(_report(llm_endpoints=endpoints)))["services"]
        assert services == [
            {"bom-ref": "service:endpoint:llm.internal.example", "name": "llm.internal.example",
             "endpoints": ["https://llm.internal.example/v1", "https://llm.internal.example/v2"],
             "properties": [{"name": "quin:endpoint-kind", "value": "private"}]},
            {"bom-ref": "service:endpoint:localhost", "name": "localhost",
             "endpoints": ["http://localhost:11434"],
             "properties": [{"name": "quin:endpoint-kind", "value": "local"}]},
        ]

    def test_unresolved_endpoints_are_left_out(self):
        bom = build_bom(_report(llm_endpoints=[_endpoint(url="settings.base_url", host="", kind="unresolved")]))
        assert "services" not in bom

    def test_services_sorted_by_ref(self):
        bom = build_bom(_report(mcp_servers=[MCPServer(name="a")], llm_endpoints=[_endpoint()]))
        assert [s["bom-ref"] for s in bom["services"]] == ["service:endpoint:llm.internal.example", "service:mcp:a"]


def _full_report() -> ScanReport:
    agent = _agent(instances=[
        _instance("agent:researcher/crew.py#1", model="gpt-4o", tools=[("search", "tool:search")]),
        _instance("agent:researcher/tests/t.py#1", file="tests/t.py", scope="test", known=False),
    ])
    return _report(
        framework="CrewAI 0.80.0",
        agents=[agent, _agent("agent:writer", "writer", scope="example")],
        tool_usages=[_tool(), _tool("tool:scrape", "scrape", tool_type="external_service")],
        model_usages=[_model()],
        mcp_servers=[MCPServer(name="fs", transport="stdio", source_file=".mcp.json")],
        llm_endpoints=[_endpoint()],
        vulnerabilities=[_vuln(), _vuln("CVE-2024-9", source="web:gemini")],
    )


class TestWholeBom:
    def test_full_report_is_valid(self):
        _valid(build_bom(_full_report()))

    def test_bom_refs_are_unique(self):
        text = to_cyclonedx(_full_report())
        refs = re.findall(r'"bom-ref": "([^"]+)"', text)
        assert len(refs) == len(set(refs))

    def test_dependencies_point_at_known_refs(self):
        bom = build_bom(_full_report())
        known = {c["bom-ref"] for c in bom["components"]} | {s["bom-ref"] for s in bom["services"]} | {"repo"}
        for dep in bom["dependencies"]:
            assert dep["ref"] in known
            assert set(dep.get("dependsOn", [])) <= known

    def test_same_report_gives_same_bom_apart_from_serial(self):
        def stable(report):
            bom = build_bom(report)
            bom.pop("serialNumber")
            return json.dumps(bom)
        assert stable(_full_report()) == stable(_full_report())

    def test_top_level_key_order(self):
        assert list(build_bom(_full_report())) == [
            "bomFormat", "specVersion", "serialNumber", "version", "metadata",
            "components", "services", "dependencies", "vulnerabilities",
        ]
