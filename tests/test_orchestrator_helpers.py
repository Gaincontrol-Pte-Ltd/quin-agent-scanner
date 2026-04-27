"""Tests for orchestrator helper functions."""
from __future__ import annotations


from quin_scanner.models import (
    MCPServer,
    ModelUsage,
    ScanFinding,
    ToolUsage,
)
from quin_scanner.orchestrator import (
    ScanOrchestrator,
    _extract_mcp_servers,
    _extract_infra,
    _filter_hallucinated_tools,
    _classify_tool_usages,
    _looks_like_model_name,
    _pre_summarise,
)


def _finding(scanner_name, match_text, file_path="src/main.py",
             capability_tag="llm-api", confidence=0.8, line_number=1):
    return ScanFinding(
        scanner_name=scanner_name,
        category="test",
        file_path=file_path,
        line_number=line_number,
        match_text=match_text,
        capability_tag=capability_tag,
        confidence=confidence,
    )


class TestExtractMCPServers:
    def test_stdio_server(self):
        findings = [_finding("MCPScanner", "stdio:my-server")]
        servers = _extract_mcp_servers(findings)
        assert len(servers) == 1
        assert servers[0].name == "my-server"
        assert servers[0].transport == "stdio"

    def test_http_server(self):
        findings = [_finding("MCPScanner", "http://localhost:3000")]
        servers = _extract_mcp_servers(findings)
        assert len(servers) == 1
        assert servers[0].transport == "http"

    def test_sse_server(self):
        findings = [_finding("MCPScanner", "sse connection")]
        servers = _extract_mcp_servers(findings)
        assert len(servers) == 1
        assert servers[0].transport == "sse"

    def test_unknown_transport(self):
        findings = [_finding("MCPScanner", "custom-protocol")]
        servers = _extract_mcp_servers(findings)
        assert servers[0].transport == "unknown"

    def test_ignores_non_mcp_findings(self):
        findings = [_finding("DependencyScanner", "some-package")]
        assert _extract_mcp_servers(findings) == []


class TestExtractInfra:
    def test_terraform(self):
        findings = [_finding("IaCScanner", "AWS provider config", file_path="infra/main.tf")]
        infra = _extract_infra(findings)
        assert infra is not None
        assert infra.platform == "terraform"

    def test_kubernetes(self):
        findings = [_finding("IaCScanner", "Deployment spec", file_path="k8s/deployment.yaml")]
        infra = _extract_infra(findings)
        assert infra is not None
        assert infra.platform == "kubernetes"

    def test_docker_compose(self):
        findings = [_finding("IaCScanner", "services", file_path="docker-compose.yaml")]
        infra = _extract_infra(findings)
        assert infra is not None
        assert infra.platform == "docker-compose"

    def test_no_iac_returns_none(self):
        findings = [_finding("DependencyScanner", "requests")]
        assert _extract_infra(findings) is None


class TestFilterHallucinatedTools:
    def test_removes_model_names(self):
        tools = [ToolUsage(tool_name="gpt-4o"), ToolUsage(tool_name="real_tool")]
        models = [ModelUsage(provider="openai", model_name="gpt-4o", source="code", file_path="x.py", line_number=1)]
        deps = []
        filtered = _filter_hallucinated_tools(tools, models, deps)
        assert len(filtered) == 1
        assert filtered[0].tool_name == "real_tool"

    def test_removes_model_name_prefixes(self):
        tools = [ToolUsage(tool_name="gpt-4o-mini"), ToolUsage(tool_name="real_tool")]
        models = []
        deps = []
        filtered = _filter_hallucinated_tools(tools, models, deps)
        assert len(filtered) == 1
        assert filtered[0].tool_name == "real_tool"

    def test_removes_raw_dep_names(self):
        tools = [
            ToolUsage(tool_name="chromadb"),
            ToolUsage(tool_name="chromadb", tool_type="external_service"),
        ]
        models = []
        deps = [_finding("DependencyScanner", "chromadb>=0.4")]
        filtered = _filter_hallucinated_tools(tools, models, deps)
        # Keeps external_service, removes the raw dep
        assert len(filtered) == 1
        assert filtered[0].tool_type == "external_service"

    def test_empty_inputs(self):
        assert _filter_hallucinated_tools([], [], []) == []


class TestClassifyToolUsages:
    def test_skill_in_skills_dir(self):
        tools = [ToolUsage(tool_name="research", source_file="skills/research.md")]
        _classify_tool_usages(tools, [])
        assert tools[0].tool_type == "skill"

    def test_mcp_tool_matching(self):
        tools = [ToolUsage(tool_name="my-server")]
        servers = [MCPServer(name="my-server", transport="stdio")]
        _classify_tool_usages(tools, servers)
        assert tools[0].tool_type == "mcp_tool"

    def test_external_service_not_reclassified(self):
        tools = [ToolUsage(tool_name="chromadb", tool_type="external_service", source_file="skills/x.md")]
        _classify_tool_usages(tools, [])
        assert tools[0].tool_type == "external_service"


class TestLooksLikeModelName:
    def test_model_prefixes(self):
        assert _looks_like_model_name("gpt-4o") is True
        assert _looks_like_model_name("claude-haiku") is True
        assert _looks_like_model_name("dall-e-3") is True
        assert _looks_like_model_name("llama-3") is True
        assert _looks_like_model_name("gemini-2.0-flash") is True
        assert _looks_like_model_name("mistral-large") is True
        assert _looks_like_model_name("text-embedding-3-small") is True

    def test_non_model_names(self):
        assert _looks_like_model_name("google_search") is False
        assert _looks_like_model_name("web_scraper") is False
        assert _looks_like_model_name("my_tool") is False


class TestDeduplication:
    def test_keeps_highest_confidence(self):
        findings = [
            _finding("ScannerA", "match", confidence=0.7, capability_tag="tag1"),
            _finding("ScannerB", "match", confidence=0.9, capability_tag="tag1"),
        ]
        deduped = ScanOrchestrator._deduplicate(findings)
        assert len(deduped) == 1
        assert deduped[0].confidence == 0.9

    def test_different_tags_kept(self):
        findings = [
            _finding("ScannerA", "match", capability_tag="tag1"),
            _finding("ScannerA", "match", capability_tag="tag2"),
        ]
        deduped = ScanOrchestrator._deduplicate(findings)
        assert len(deduped) == 2


class TestAggregateConfidence:
    def test_single_finding(self):
        findings = [_finding("ScannerA", "x", confidence=0.95)]
        assert ScanOrchestrator._aggregate_confidence(findings) == 0.95

    def test_corroboration_boost(self):
        findings = [
            _finding("ScannerA", "x", confidence=0.95),
            _finding("ScannerB", "y", confidence=0.90),
        ]
        conf = ScanOrchestrator._aggregate_confidence(findings)
        assert conf == 0.98  # 0.95 + 0.03

    def test_capped_at_099(self):
        findings = [
            _finding(f"Scanner{i}", "x", confidence=0.95)
            for i in range(10)
        ]
        conf = ScanOrchestrator._aggregate_confidence(findings)
        assert conf <= 0.99

    def test_empty_findings(self):
        assert ScanOrchestrator._aggregate_confidence([]) == 0.0


class TestPreSummarise:
    def test_groups_by_scanner(self):
        findings = [
            _finding("ScannerA", "match1"),
            _finding("ScannerA", "match2"),
            _finding("ScannerB", "match3"),
        ]
        summaries = _pre_summarise(findings)
        assert len(summaries) == 2
        scanner_names = {s["scanner"] for s in summaries}
        assert scanner_names == {"ScannerA", "ScannerB"}

    def test_caps_at_top_n(self):
        findings = [
            _finding("ScannerA", f"match{i}", confidence=i * 0.1)
            for i in range(20)
        ]
        summaries = _pre_summarise(findings)
        assert len(summaries) == 1
        # Default cap is 5
        assert len(summaries[0]["top_artifacts"]) == 5

    def test_prompt_discovery_higher_cap(self):
        findings = [
            _finding("PromptDiscoveryScanner", f"match{i}", confidence=i * 0.05)
            for i in range(20)
        ]
        summaries = _pre_summarise(findings)
        assert len(summaries[0]["top_artifacts"]) == 10

    def test_truncates_snippets(self):
        long_text = "x" * 1000
        findings = [_finding("ScannerA", long_text)]
        summaries = _pre_summarise(findings)
        assert len(summaries[0]["top_artifacts"][0]["text"]) == 500


class TestDedupRepoSignals:
    """_dedup_repo_signals drops repo-level KRIs already attributed per-agent."""

    def _ri(self, signal, threat_id):
        from quin_scanner.models import RiskIndicator
        return RiskIndicator(signal=signal, recommended_controls=[], threat_id=threat_id)

    def _agent(self, name, risk_signals):
        from quin_scanner.models import AgentProfile
        return AgentProfile(
            name=name, agent_type="worker", goal="", capabilities=[],
            risk_signals=risk_signals, skills=[], tools=[], source_file="",
        )

    def test_drops_signal_already_on_an_agent(self):
        from quin_scanner.orchestrator import _dedup_repo_signals
        repo = [
            self._ri("Agent retrieves external content (RAG, web, email, documents)", "T001"),
            self._ri("No centralized logging of MCP tool invocations", "T012"),
        ]
        agents = [self._agent("Researcher", [
            self._ri("Agent retrieves external content (RAG, web, email, documents)", "T001"),
        ])]
        result = _dedup_repo_signals(repo, agents)
        assert len(result) == 1
        assert result[0].threat_id == "T012"

    def test_keeps_signal_when_only_threat_id_matches(self):
        """Different signal text under same threat should NOT be dropped."""
        from quin_scanner.orchestrator import _dedup_repo_signals
        repo = [self._ri("Hard-coded credentials in MCP server configurations", "T002")]
        agents = [self._agent("A", [
            self._ri("System prompts containing credentials, connection strings, or internal URLs", "T002"),
        ])]
        assert _dedup_repo_signals(repo, agents) == repo

    def test_dedup_is_case_and_whitespace_insensitive(self):
        from quin_scanner.orchestrator import _dedup_repo_signals
        repo = [self._ri("  AGENT retrieves external content  ", "t001")]
        agents = [self._agent("A", [
            self._ri("Agent retrieves external content", "T001"),
        ])]
        assert _dedup_repo_signals(repo, agents) == []

    def test_no_agents_returns_input_unchanged(self):
        from quin_scanner.orchestrator import _dedup_repo_signals
        repo = [self._ri("any signal", "T003")]
        assert _dedup_repo_signals(repo, []) == repo

    def test_empty_threat_id_dedups_on_signal_text_only(self):
        """Two signals with empty threat_id and identical text dedup."""
        from quin_scanner.orchestrator import _dedup_repo_signals
        repo = [self._ri("foo", "")]
        agents = [self._agent("A", [self._ri("foo", "")])]
        assert _dedup_repo_signals(repo, agents) == []


class TestSortedRepoSignals:
    """Severity-aware stable sort puts critical/high first."""

    def _ri(self, signal, severity):
        from quin_scanner.models import RiskIndicator
        return RiskIndicator(signal=signal, recommended_controls=[], threat_id="T003", severity=severity)

    def test_severity_order(self):
        from quin_scanner.orchestrator import _sorted_repo_signals
        signals = [
            self._ri("low item", "low"),
            self._ri("medium item", "medium"),
            self._ri("critical item", "critical"),
            self._ri("high item", "high"),
            self._ri("info item", "info"),
        ]
        result = _sorted_repo_signals(signals)
        assert [s.severity for s in result] == ["critical", "high", "medium", "low", "info"]

    def test_stable_within_severity(self):
        """Items with same severity preserve insertion order."""
        from quin_scanner.orchestrator import _sorted_repo_signals
        signals = [
            self._ri("first medium", "medium"),
            self._ri("critical", "critical"),
            self._ri("second medium", "medium"),
        ]
        result = _sorted_repo_signals(signals)
        assert [s.signal for s in result] == ["critical", "first medium", "second medium"]

    def test_unknown_severity_treated_as_medium(self):
        from quin_scanner.orchestrator import _sorted_repo_signals
        signals = [
            self._ri("bogus", "weird-tier"),
            self._ri("crit", "critical"),
        ]
        result = _sorted_repo_signals(signals)
        assert result[0].severity == "critical"
