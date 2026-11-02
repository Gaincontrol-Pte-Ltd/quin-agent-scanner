"""Validates CycloneDX 1.6 BOMs against the vendored official schema, offline."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

SCHEMA_DIR = Path(__file__).resolve().parent / "cyclonedx_schema"
_FILES = ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    schemas = {name: json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8")) for name in _FILES}
    # bom-1.6 refers to the other two by relative URI; register them under their $id so nothing is fetched.
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT7)) for schema in schemas.values()
    )
    return Draft7Validator(schemas["bom-1.6.schema.json"], registry=registry, format_checker=FormatChecker())


def bom_errors(bom: dict) -> list[str]:
    """Schema errors as "path: message" strings; empty when the BOM is valid."""
    return sorted(f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in _validator().iter_errors(bom))
