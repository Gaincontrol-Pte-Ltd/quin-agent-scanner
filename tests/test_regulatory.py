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
            with pytest.raises(ValueError, match=r"invalid regulatory mapping in .*bad\.yaml: .*unknown iso-42001 clause A.6.2.88"):
                load_mapping(bad)
        finally:
            load_mapping.cache_clear()


class TestStricterValidation:
    def _mutated(self, change):
        data = copy.deepcopy(_data())
        change(data)
        return problems(data, CONTROL_IDS)

    def test_clauses_must_be_a_list(self):
        found = self._mutated(lambda d: d["frameworks"][0].__setitem__("clauses", "Art. 9"))
        assert "framework eu-ai-act: clauses must be a list" in found

    def test_control_framework_value_must_be_a_list(self):
        found = self._mutated(lambda d: d["controls"]["C001"].__setitem__("iso-42001", "A.6.2.2"))
        assert "control C001: iso-42001 must be a list of clause IDs" in found

    def test_none_counts_as_empty(self):
        found = self._mutated(lambda d: d["controls"]["C001"].__setitem__("iso-42001", None))
        assert not any("must be a list" in f for f in found)

    def test_non_string_clause_id_in_control(self):
        found = self._mutated(lambda d: d["controls"]["C001"]["iso-42001"].append(7))
        assert "control C001: iso-42001 clause 7 must be a string (quote it)" in found

    def test_non_string_catalogue_clause_id(self):
        found = self._mutated(lambda d: d["frameworks"][1]["clauses"].append({"id": 7, "title": "Seven"}))
        assert "framework iso-42001: clause id 7 must be a string (quote it)" in found

    def test_non_string_framework_id(self):
        def change(d):
            d["frameworks"][0]["id"] = 5
        assert "framework id 5 must be a string (quote it)" in self._mutated(change)

    def test_non_string_control_key_does_not_raise(self):
        found = self._mutated(lambda d: d["controls"].__setitem__(15, {}))
        assert "control key 15 must be a string" in found

    def test_duplicate_clause_in_control(self):
        found = self._mutated(lambda d: d["controls"]["C001"]["eu-ai-act"].append("Art. 15"))
        assert "control C001: duplicate eu-ai-act clause Art. 15" in found

    def test_blank_disclaimer(self):
        assert "missing disclaimer" in self._mutated(lambda d: d.__setitem__("disclaimer", "   "))

    def test_blank_framework_name(self):
        found = self._mutated(lambda d: d["frameworks"][0].__setitem__("name", "  "))
        assert "framework eu-ai-act: name must be a non-empty string" in found

    def test_non_string_framework_version(self):
        found = self._mutated(lambda d: d["frameworks"][2].__setitem__("version", 1.0))
        assert "framework nist-ai-rmf: version must be a non-empty string" in found

    def test_framework_url_must_be_https(self):
        found = self._mutated(lambda d: d["frameworks"][0].__setitem__("url", "http://example.com"))
        assert "framework eu-ai-act: url must start with https://" in found

    def test_clause_url_must_be_https(self):
        found = self._mutated(lambda d: d["frameworks"][0]["clauses"][0].__setitem__("url", "javascript:alert(1)"))
        assert "framework eu-ai-act: clause Art. 9: url must start with https://" in found

    def test_urls_must_not_contain_markup_characters(self):
        for bad in ("https://x.org/a b", "https://x.org/a(1)", "https://x.org/<a>", 'https://x.org/"q"'):
            found = self._mutated(lambda d: d["frameworks"][0].__setitem__("url", bad))
            assert 'framework eu-ai-act: url must not contain spaces or ()<>"' in found
            found = self._mutated(lambda d: d["frameworks"][0]["clauses"][0].__setitem__("url", bad))
            assert 'framework eu-ai-act: clause Art. 9: url must not contain spaces or ()<>"' in found

    def test_blank_clause_title(self):
        found = self._mutated(lambda d: d["frameworks"][0]["clauses"][0].__setitem__("title", "  "))
        assert "framework eu-ai-act: clause Art. 9: title must be a non-empty string without | or newlines" in found

    def test_pipe_in_title(self):
        found = self._mutated(lambda d: d["frameworks"][0]["clauses"][0].__setitem__("title", "A | B"))
        assert "framework eu-ai-act: clause Art. 9: title must be a non-empty string without | or newlines" in found

    def test_pipe_in_framework_name(self):
        found = self._mutated(lambda d: d["frameworks"][0].__setitem__("name", "EU | AI"))
        assert "framework eu-ai-act: name must not contain | or newlines" in found

    def test_bracket_in_clause_id(self):
        def change(d):
            d["frameworks"][0]["clauses"][0]["id"] = "Art. [9]"
        found = self._mutated(change)
        assert any("clause 'Art. [9]': id must be non-empty and not contain" in f for f in found)

    def test_newline_in_framework_id(self):
        found = self._mutated(lambda d: d["frameworks"][0].__setitem__("id", "eu\nai"))
        assert "framework eu\nai: id must not contain | [ ] or newlines" in found


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
