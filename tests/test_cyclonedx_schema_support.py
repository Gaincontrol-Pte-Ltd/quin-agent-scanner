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
