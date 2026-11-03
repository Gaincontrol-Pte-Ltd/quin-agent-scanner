"""The regulatory crosswalk data and its loader (spec: docs/superpowers/specs/2026-11-03-regulatory-mapping-design.md)."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from quin_scanner import regulatory
from quin_scanner.regulatory import (
    controls_catalog,
    control_id_of,
    frameworks,
    load_mapping,
    problems,
    refs_for_control,
    refs_for_label,
    sarif_tag,
)
from quin_scanner.risk_taxonomy import load_taxonomy

MAPPING = Path(regulatory.__file__).parent / "rules" / "regulatory_mapping.yaml"
CONTROL_IDS = [c.id for c in load_taxonomy().controls]


def _data():
    return yaml.safe_load(MAPPING.read_text(encoding="utf-8"))


class TestShippedMapping:
    def test_shipped_file_is_valid(self):
        assert problems(_data(), CONTROL_IDS) == []

    def test_every_taxonomy_control_is_mapped(self):
        assert sorted(load_mapping().controls) == sorted(CONTROL_IDS)

    def test_all_ids_are_strings(self):
        for fw in _data()["frameworks"]:
            for clause in fw["clauses"]:
                assert isinstance(clause["id"], str), clause

    def test_frameworks_in_file_order(self):
        assert [f.id for f in frameworks()] == ["eu-ai-act", "iso-42001", "nist-ai-rmf"]

    def test_disclaimer_says_informative(self):
        assert "not a compliance assessment" in regulatory.disclaimer()


class TestProblems:
    def _mutated(self, change):
        data = copy.deepcopy(_data())
        change(data)
        return problems(data, CONTROL_IDS)

    def test_unknown_clause(self):
        found = self._mutated(lambda d: d["controls"]["C001"]["iso-42001"].append("A.6.2.88"))
        assert "control C001: unknown iso-42001 clause A.6.2.88" in found

    def test_unmapped_control(self):
        found = self._mutated(lambda d: d["controls"].pop("C014"))
        assert "control C014 has no mapping entry" in found

    def test_entry_for_unknown_control(self):
        found = self._mutated(lambda d: d["controls"].__setitem__("C099", {"eu-ai-act": [], "iso-42001": [], "nist-ai-rmf": []}))
        assert "mapping entry C099 is not a control in the taxonomy" in found

    def test_missing_framework_key(self):
        found = self._mutated(lambda d: d["controls"]["C003"].pop("nist-ai-rmf"))
        assert "control C003: missing key nist-ai-rmf" in found

    def test_unused_clause(self):
        found = self._mutated(lambda d: d["frameworks"][0]["clauses"].append({"id": "Art. 99", "title": "Unused"}))
        assert "eu-ai-act clause Art. 99 is not used by any control" in found

    def test_duplicate_clause(self):
        found = self._mutated(lambda d: d["frameworks"][1]["clauses"].append({"id": "A.2.2", "title": "Again"}))
        assert "framework iso-42001: duplicate clause A.2.2" in found

    def test_missing_framework_field(self):
        found = self._mutated(lambda d: d["frameworks"][2].pop("version"))
        assert "framework nist-ai-rmf: missing version" in found

    def test_missing_disclaimer(self):
        assert "missing disclaimer" in self._mutated(lambda d: d.pop("disclaimer"))

    def test_load_mapping_raises_on_problems(self, tmp_path):
        data = _data()
        data["controls"]["C001"]["iso-42001"] = ["A.6.2.88"]
        bad = tmp_path / "bad.yaml"
        bad.write_text(yaml.safe_dump(data), encoding="utf-8")
        load_mapping.cache_clear()
        try:
            with pytest.raises(ValueError, match="unknown iso-42001 clause A.6.2.88"):
                load_mapping(bad)
        finally:
            load_mapping.cache_clear()


class TestLookups:
    def test_refs_for_control(self):
        refs = refs_for_control("C006")
        assert [(r.framework, r.id) for r in refs] == [
            ("eu-ai-act", "Art. 14"), ("eu-ai-act", "Art. 26"),
            ("iso-42001", "A.9.2"),
            ("nist-ai-rmf", "MAP 3.5"), ("nist-ai-rmf", "MANAGE 2.4"),
        ]
        assert refs[0].title == "Human oversight"
        assert refs[0].framework_name == "EU AI Act"
        assert refs[0].url == "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"

    def test_refs_for_unknown_control(self):
        assert refs_for_control("C999") == []

    def test_control_id_of(self):
        assert control_id_of("C003: Access Control & Least Privilege") == "C003"
        assert control_id_of("c003") == "C003"
        assert control_id_of("Rotate the key") is None
        assert control_id_of("") is None

    def test_refs_for_label(self):
        assert refs_for_label("C010: Infrastructure Security")[0].id == "Art. 15"
        assert refs_for_label("free text") == []

    def test_to_dict(self):
        assert refs_for_control("C001")[0].to_dict() == {
            "framework": "eu-ai-act", "id": "Art. 15", "title": "Accuracy, robustness and cybersecurity",
            "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
        }

    def test_sarif_tags(self):
        tags = {sarif_tag(r) for r in refs_for_control("C006")}
        assert tags == {"eu-ai-act/art-14", "eu-ai-act/art-26", "iso-42001/a.9.2",
                        "nist-ai-rmf/map-3.5", "nist-ai-rmf/manage-2.4"}


class TestControlsCatalog:
    def test_catalog_of_labels(self):
        catalog = controls_catalog(["C006: Human Oversight & Approval Gates", "C001", "C006", "free text", "C999"])
        assert list(catalog) == ["C001", "C006"]
        assert catalog["C006"]["name"] == "Human Oversight & Approval Gates"
        assert catalog["C006"]["regulatory_refs"][0] == {
            "framework": "eu-ai-act", "id": "Art. 14", "title": "Human oversight",
            "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
        }

    def test_empty(self):
        assert controls_catalog([]) == {}
