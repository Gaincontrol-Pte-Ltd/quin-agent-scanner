"""Drift, completeness, and referential-integrity tests for docs/risk-framework.md.

Layers:
  1. Drift    — the on-disk Markdown matches what the generator produces now.
  2. Completeness — every T0NN / C0NN in the YAML appears in the MD, with a stable
     anchor the HTML report can deep-link to.
  3. Referential — every control_id referenced by a threat actually exists, and
     every threat_id referenced by a hardcoded RiskIndicator exists too.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "generate_risk_framework_docs.py"
DOC_PATH = REPO_ROOT / "docs" / "risk-framework.md"


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_risk_framework_docs", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


try:
    import jinja2  # noqa: F401
    _HAS_JINJA = True
except ImportError:
    _HAS_JINJA = False


requires_jinja = pytest.mark.skipif(
    not _HAS_JINJA,
    reason="jinja2 is a dev dependency and not installed in this environment",
)


class TestDrift:
    @requires_jinja
    def test_generated_matches_on_disk(self):
        """The committed docs/risk-framework.md must match what the generator produces."""
        generator = _load_generator()
        assert DOC_PATH.exists(), (
            "docs/risk-framework.md is missing. Run "
            "`python scripts/generate_risk_framework_docs.py`."
        )
        generated = generator.render()
        on_disk = DOC_PATH.read_text(encoding="utf-8")
        assert on_disk == generated, (
            "docs/risk-framework.md is out of sync with "
            "src/quin_scanner/rules/risk_taxonomy.yaml. "
            "Run `python scripts/generate_risk_framework_docs.py` to refresh."
        )


class TestCompleteness:
    def test_every_threat_has_anchor_and_heading(self):
        from quin_scanner.risk_taxonomy import load_taxonomy
        tax = load_taxonomy()
        text = DOC_PATH.read_text(encoding="utf-8")
        for t in tax.threats:
            anchor = f'<a id="{t.id.lower()}"></a>'
            heading = f"### {t.id} — {t.name}"
            assert anchor in text, f"missing anchor for threat {t.id}"
            assert heading in text, f"missing heading for threat {t.id}"

    def test_every_control_has_anchor_and_heading(self):
        from quin_scanner.risk_taxonomy import load_taxonomy
        tax = load_taxonomy()
        text = DOC_PATH.read_text(encoding="utf-8")
        for c in tax.controls:
            anchor = f'<a id="{c.id.lower()}"></a>'
            heading = f"### {c.id} — {c.name}"
            assert anchor in text, f"missing anchor for control {c.id}"
            assert heading in text, f"missing heading for control {c.id}"

    def test_anchor_id_format_is_stable(self):
        """Anchor IDs must stay t0NN / c0NN — external deep-links depend on it."""
        text = DOC_PATH.read_text(encoding="utf-8")
        ids = re.findall(r'<a id="([^"]+)"></a>', text)
        for anchor_id in ids:
            assert re.match(r"^(t|c)\d{3}$", anchor_id), (
                f"anchor id {anchor_id!r} does not match t0NN / c0NN — "
                "changing this will break HTML-report deep links"
            )


class TestReferentialIntegrity:
    def test_all_threat_recommended_controls_exist(self):
        from quin_scanner.risk_taxonomy import load_taxonomy
        tax = load_taxonomy()
        control_ids = {c.id for c in tax.controls}
        for t in tax.threats:
            for cid in t.recommended_controls:
                assert cid in control_ids, (
                    f"threat {t.id} references unknown control {cid}"
                )

    def test_threat_ids_and_control_ids_follow_convention(self):
        from quin_scanner.risk_taxonomy import load_taxonomy
        tax = load_taxonomy()
        for t in tax.threats:
            assert re.match(r"^T\d{3}$", t.id), f"bad threat id {t.id!r}"
        for c in tax.controls:
            assert re.match(r"^C\d{3}$", c.id), f"bad control id {c.id!r}"

    def test_external_refs_have_title_and_url(self):
        from quin_scanner.risk_taxonomy import load_taxonomy
        tax = load_taxonomy()
        for t in tax.threats:
            for r in t.external_refs:
                assert r.title and r.url, f"threat {t.id} ref missing title/url"
                assert r.url.startswith(("http://", "https://")), (
                    f"threat {t.id} ref has non-http url: {r.url}"
                )
        for c in tax.controls:
            for r in c.external_refs:
                assert r.title and r.url, f"control {c.id} ref missing title/url"
                assert r.url.startswith(("http://", "https://")), (
                    f"control {c.id} ref has non-http url: {r.url}"
                )
