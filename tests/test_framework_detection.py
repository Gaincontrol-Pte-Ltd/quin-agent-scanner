"""Tests for framework detection and version extraction."""
from __future__ import annotations


from quin_scanner.models import ScanFinding
from quin_scanner.orchestrator import (
    _detect_framework,
    _extract_framework_version,
    _parse_version_tuple,
)


def _finding(scanner_name, match_text, file_path="src/main.py", confidence=0.8):
    return ScanFinding(
        scanner_name=scanner_name,
        category="test",
        file_path=file_path,
        line_number=1,
        match_text=match_text,
        capability_tag="llm-api",
        confidence=confidence,
    )


class TestDetectFramework:
    def test_dependency_crewai(self):
        findings = [_finding("DependencyScanner", "crewai>=0.80.0")]
        assert _detect_framework(findings) == "CrewAI"

    def test_dependency_langchain(self):
        findings = [_finding("DependencyScanner", "langchain>=0.1.0")]
        assert _detect_framework(findings) == "LangChain"

    def test_dependency_openai_agents(self):
        findings = [_finding("DependencyScanner", "openai-agents>=0.1")]
        assert _detect_framework(findings) == "OpenAI Agents SDK"

    def test_code_pattern_metagpt(self):
        findings = [_finding("CodePatternScanner", "from metagpt.roles import Role")]
        assert _detect_framework(findings) == "MetaGPT"

    def test_code_pattern_autogen(self):
        findings = [_finding("CodePatternScanner", "from autogen_agentchat import Agent")]
        assert _detect_framework(findings) == "AutoGen"

    def test_code_pattern_vercel_ai(self):
        findings = [_finding("CodePatternScanner", "from '@ai-sdk/openai'")]
        assert _detect_framework(findings) == "Vercel AI SDK"

    def test_no_findings_returns_unknown(self):
        assert _detect_framework([]) == "unknown"

    def test_unrelated_findings_returns_unknown(self):
        findings = [_finding("DependencyScanner", "requests>=2.0")]
        assert _detect_framework(findings) == "unknown"

    def test_file_marker_skips_example_dirs(self):
        """File markers in example/demo directories should not count."""
        findings = [_finding("FrameworkMarkerScanner", "crew.py", file_path="examples/crew.py")]
        # Should not detect as CrewAI since it's in an examples directory
        result = _detect_framework(findings)
        # The marker is in a secondary dir so it should be skipped
        assert result == "unknown"

    def test_code_pattern_beats_dependency_for_metagpt(self):
        """Code pattern imports should take priority over package name for self-imports."""
        findings = [
            _finding("DependencyScanner", "langchain>=0.1.0"),
            _finding("CodePatternScanner", "from metagpt.roles import Role"),
        ]
        assert _detect_framework(findings) == "MetaGPT"


class TestExtractFrameworkVersion:
    def test_exact_pin(self):
        findings = [_finding("DependencyScanner", "crewai==0.80.0")]
        assert _extract_framework_version("CrewAI", findings) == "0.80.0"

    def test_gte_specifier(self):
        findings = [_finding("DependencyScanner", "crewai>=0.80.0")]
        assert _extract_framework_version("CrewAI", findings) == "0.80.0"

    def test_tilde_specifier(self):
        findings = [_finding("DependencyScanner", "crewai~=0.80.0")]
        assert _extract_framework_version("CrewAI", findings) == "0.80.0"

    def test_multiple_versions_picks_highest(self):
        findings = [
            _finding("DependencyScanner", "crewai>=0.70.0"),
            _finding("DependencyScanner", "crewai>=0.80.0"),
        ]
        assert _extract_framework_version("CrewAI", findings) == "0.80.0"

    def test_no_version_returns_none(self):
        findings = [_finding("DependencyScanner", "crewai")]
        assert _extract_framework_version("CrewAI", findings) is None

    def test_unknown_framework_returns_none(self):
        findings = [_finding("DependencyScanner", "crewai>=0.80.0")]
        assert _extract_framework_version("unknown", findings) is None

    def test_no_matching_package(self):
        findings = [_finding("DependencyScanner", "requests>=2.0")]
        assert _extract_framework_version("CrewAI", findings) is None


class TestParseVersionTuple:
    def test_simple(self):
        assert _parse_version_tuple("1.2.3") == (1, 2, 3)

    def test_two_parts(self):
        assert _parse_version_tuple("1.2") == (1, 2)

    def test_comparison(self):
        assert _parse_version_tuple("0.80.0") > _parse_version_tuple("0.70.0")
        assert _parse_version_tuple("1.0.0") > _parse_version_tuple("0.99.99")
