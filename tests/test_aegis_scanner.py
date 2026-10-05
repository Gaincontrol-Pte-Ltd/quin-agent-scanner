"""Tests for opt-in Aegis SDK detection and governed-agent classification."""
from __future__ import annotations

from click.testing import CliRunner

from quin_scanner.cli import cli
from quin_scanner.config import ScannerConfig
from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.aegis import AegisScanner, classify_governance


def _scan(tmp_path, files: dict[str, str]):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    accessor = LocalRepoAccessor(tmp_path)
    index = FileIndex(accessor)
    index.build()
    return AegisScanner().scan(accessor, index)


def _kinds(findings):
    return {f.capability_tag.split(":")[1] for f in findings}


def test_requirements_dependency_with_file_url(tmp_path):
    f = _scan(tmp_path, {"requirements.txt": "aegis-core @ file:///x/aegis_core-0.2.4.whl\nlangchain\n"})
    assert _kinds(f) == {"dependency"}
    assert len(f) == 1


def test_secret_manager_prefix_and_underscore(tmp_path):
    f = _scan(tmp_path, {"requirements.txt": "aegis_secret_manager_aws>=1\n"})
    assert _kinds(f) == {"dependency"}


def test_pyproject_dependency(tmp_path):
    f = _scan(tmp_path, {"pyproject.toml": 'dependencies = [\n  "aegis-crewai>=0.2",\n  "crewai",\n]\n'})
    assert len(f) == 1 and f[0].match_text.startswith("aegis-crewai")


def test_package_json_plugin(tmp_path):
    f = _scan(tmp_path, {"package.json": '{"dependencies": {"aegis-openclaw-plugin": "^0.1.0", "x": "1"}}'})
    assert _kinds(f) == {"dependency"}


def test_python_import_and_initialize(tmp_path):
    src = "from aegis_core import initialize as aegis_initialize\nengine = aegis_initialize(cfg['aegis'])\n"
    f = _scan(tmp_path, {"main.py": src})
    assert _kinds(f) == {"import", "integration"}


def test_wrapper_classes(tmp_path):
    f = _scan(tmp_path, {"t.py": "class T(AegisBaseTool):\n    pass\nmw=[AegisFunctionMiddleware()]\n"})
    assert _kinds(f) == {"integration"}


def test_unrelated_aegis_word_not_flagged(tmp_path):
    f = _scan(tmp_path, {"a.py": "# aegis was a shield\nimport os\n", "requirements.txt": "requests\n"})
    assert f == []


def test_comment_mentions_not_flagged(tmp_path):
    f = _scan(tmp_path, {"a.py": "# uses AegisBaseTool and aegis_initialize()\n// AegisEngine\n"})
    assert f == []


def test_openclaw_plugin_manifest(tmp_path):
    f = _scan(tmp_path, {"openclaw.plugin.json": '{"id": "aegis-openclaw"}'})
    assert _kinds(f) == {"plugin"}


def test_aegis_yaml_config(tmp_path):
    f = _scan(tmp_path, {"config.yaml": "aegis:\n  enabled: true\n  config_file: /opt/aegis/config.bin\n"})
    assert _kinds(f) == {"config"}


class TestClassify:
    def test_governed_on_code_evidence(self, tmp_path):
        f = _scan(tmp_path, {"m.py": "from aegis_core import initialize\n"})
        g = classify_governance(True, f)
        assert g.status == "governed" and g.aegis_detected

    def test_declared_only(self, tmp_path):
        f = _scan(tmp_path, {"requirements.txt": "aegis-core\n"})
        g = classify_governance(True, f)
        assert g.status == "declared_only"
        assert g.packages == ["aegis-core"]

    def test_ungoverned_ai_app(self):
        assert classify_governance(True, []).status == "ungoverned"

    def test_not_applicable(self):
        g = classify_governance(False, [])
        assert g.status == "not_applicable" and not g.aegis_detected


class TestOptIn:
    def test_off_by_default(self):
        assert ScannerConfig().detect_aegis is False

    def test_load_from_args_flag(self):
        assert ScannerConfig.load_from_args(detect_aegis=True).detect_aegis is True

    def test_report_omits_governance_when_disabled(self, tmp_path):
        from quin_scanner.orchestrator import ScanOrchestrator
        (tmp_path / "m.py").write_text("import openai\nfrom aegis_core import initialize\n")
        cfg = ScannerConfig.load_from_args(no_llm=True)
        cfg.vuln_check_enabled = False
        off = ScanOrchestrator().run(LocalRepoAccessor(tmp_path), cfg, verbose=False)
        assert "governance" not in off.to_dict()
        cfg.detect_aegis = True
        on = ScanOrchestrator().run(LocalRepoAccessor(tmp_path), cfg, verbose=False)
        assert on.to_dict()["governance"]["status"] == "governed"
        # Aegis evidence must not alter the regular detection output.
        assert on.confidence == off.confidence
        assert len(on.artifacts) == len(off.artifacts)

    def test_cli_flag_exists(self):
        res = CliRunner().invoke(cli, ["scan", "--help"])
        assert "--detect-aegis" in res.output


class TestAboutAegisInHtml:
    def _html(self, status: str) -> str:
        from quin_scanner.models import GovernanceInfo, ScanReport
        from quin_scanner.report import ReportGenerator
        g = GovernanceInfo(aegis_detected=status == "governed", status=status)
        r = ScanReport(repo_path="r", scan_timestamp="t", is_ai_application=True, confidence=0.9, governance=g)
        return ReportGenerator.to_html(r)

    def test_info_button_and_link_present_when_flag_used(self):
        html = self._html("ungoverned")
        assert 'id="aegis-more"' in html and "https://gaincontrol.ai/" in html

    def test_absent_without_governance(self):
        from quin_scanner.models import ScanReport
        from quin_scanner.report import ReportGenerator
        r = ScanReport(repo_path="r", scan_timestamp="t", is_ai_application=True, confidence=0.9)
        assert '"governance"' not in ReportGenerator.to_html(r)


class TestPromoWhenFlagOff:
    def _html(self, **kw):
        from quin_scanner.models import ScanReport
        from quin_scanner.report import ReportGenerator
        return ReportGenerator.to_html(ScanReport(repo_path="r", scan_timestamp="t", **kw))

    def test_promo_markup_and_hint_in_template(self):
        html = self._html(is_ai_application=True, confidence=0.9)
        assert "aegis-promo" in html and "--detect-aegis" in html and "https://gaincontrol.ai/" in html


def test_aegis_examples_in_test_files_are_not_evidence(tmp_path):
    src = "from aegis_core import initialize as aegis_initialize\nengine = aegis_initialize(cfg['aegis'])\n"
    for rel in ("tests/test_x.py", "pkg/test_y.py", "src/__tests__/a.ts", "fixtures/app.py", "a.spec.ts", "conftest.py", "b_test.py"):
        assert _scan(tmp_path, {rel: src}) == [], rel


def test_test_path_evidence_is_dropped_but_real_source_still_counts(tmp_path):
    src = "from aegis_core import initialize as aegis_initialize\n"
    f = _scan(tmp_path, {"tests/test_x.py": src, "app/main.py": src})
    assert {x.file_path for x in f} == {"app/main.py"}


def test_framework_without_aegis_is_ungoverned():
    # a repo using langchain whose only Aegis mentions were in tests: no evidence left
    assert classify_governance(True, []).status == "ungoverned"
    assert classify_governance(True, []).aegis_detected is False


def test_repo_with_only_test_fixtures_is_ungoverned_end_to_end(tmp_path):
    src = "from aegis_core import initialize as aegis_initialize\n"
    f = _scan(tmp_path, {"tests/test_x.py": src, "requirements.txt": "langchain\n"})
    assert classify_governance(True, f).status == "ungoverned"
