"""The vendored CycloneDX schema validates offline and rejects invalid BOMs."""
from __future__ import annotations

from tests.cyclonedx_support import bom_errors

_MINIMAL = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version": 1,
}


def test_minimal_bom_is_valid():
    assert bom_errors(_MINIMAL) == []


def test_wrong_component_type_is_reported():
    bom = {**_MINIMAL, "components": [{"type": "agent", "name": "x"}]}
    assert bom_errors(bom)


def test_bad_serial_number_is_reported():
    assert bom_errors({**_MINIMAL, "serialNumber": "not-a-uuid"})


def test_bad_timestamp_is_reported_and_good_one_accepted():
    comp = {"type": "application", "bom-ref": "repo", "name": "x"}
    bad = {**_MINIMAL, "metadata": {"timestamp": "last week", "component": comp}}
    good = {**_MINIMAL, "metadata": {"timestamp": "2026-11-02T10:15:30Z", "component": comp}}
    assert any("last week" in e for e in bom_errors(bad))
    assert bom_errors(good) == []


def test_duplicate_bom_ref_is_reported():
    bom = {**_MINIMAL, "components": [
        {"type": "library", "name": "a", "bom-ref": "x"},
        {"type": "library", "name": "b", "bom-ref": "y", "components": [{"type": "library", "name": "c", "bom-ref": "x"}]},
    ]}
    assert "duplicate bom-ref: x" in bom_errors(bom)


def test_dangling_refs_are_reported():
    bom = {**_MINIMAL,
           "metadata": {"component": {"type": "application", "bom-ref": "repo", "name": "r"}},
           "components": [{"type": "library", "name": "a", "bom-ref": "a"}],
           "dependencies": [{"ref": "repo", "dependsOn": ["a", "ghost"]}, {"ref": "nope"}],
           "vulnerabilities": [{"id": "V1", "affects": [{"ref": "missing"}]}]}
    errors = bom_errors(bom)
    assert "unknown ref in dependencies: ghost" in errors
    assert "unknown ref in dependencies: nope" in errors
    assert "unknown ref in vulnerabilities: missing" in errors
    assert "unknown ref in dependencies: a" not in errors
