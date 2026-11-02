"""Validates CycloneDX 1.6 BOMs against the vendored official schema, offline."""
from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

SCHEMA_DIR = Path(__file__).resolve().parent / "cyclonedx_schema"
_FILES = ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")


_checker = FormatChecker()


@_checker.checks("date-time", raises=ValueError)
def _is_rfc3339(value: object) -> bool:
    """jsonschema skips date-time without rfc3339-validator; this strict check needs no dependency."""
    if not isinstance(value, str):
        return True
    if not re.fullmatch(r".+T.+(Z|[+-]\d{2}:\d{2})", value):
        raise ValueError(f"not an RFC 3339 date-time: {value!r}")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return True


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    schemas = {name: json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8")) for name in _FILES}
    # bom-1.6 refers to the other two by relative URI; register them under their $id so nothing is fetched.
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT7)) for schema in schemas.values()
    )
    return Draft7Validator(schemas["bom-1.6.schema.json"], registry=registry, format_checker=_checker)


def _walk(items: list[dict]):
    """Yields every component or service, nested ones included."""
    for item in items:
        yield item
        yield from _walk(item.get("components", []))
        yield from _walk(item.get("services", []))


def _referential_errors(bom: dict) -> list[str]:
    """Checks the schema cannot express: bom-ref uniqueness and that every reference resolves."""
    root = bom.get("metadata", {}).get("component")
    nodes_list = list(_walk(([root] if root else []) + bom.get("components", []) + bom.get("services", [])))
    nodes = {n["bom-ref"] for n in nodes_list if "bom-ref" in n}
    refs = [n["bom-ref"] for n in nodes_list if "bom-ref" in n]
    for n in nodes_list:
        refs += [o["bom-ref"] for o in n.get("evidence", {}).get("occurrences", []) if "bom-ref" in o]
    refs += [v["bom-ref"] for v in bom.get("vulnerabilities", []) if "bom-ref" in v]
    errors: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        if ref in seen:
            errors.append(f"duplicate bom-ref: {ref}")
        seen.add(ref)
    for dep in bom.get("dependencies", []):
        for ref in [dep["ref"], *dep.get("dependsOn", [])]:
            if ref not in nodes:
                errors.append(f"unknown ref in dependencies: {ref}")
    root_ref = root.get("bom-ref") if root else None
    for vuln in bom.get("vulnerabilities", []):
        for affected in vuln.get("affects", []):
            if affected["ref"] not in nodes or affected["ref"] == root_ref:
                errors.append(f"unknown ref in vulnerabilities: {affected['ref']}")
    return errors


def bom_errors(bom: dict) -> list[str]:
    """Schema and referential errors as strings; empty when the BOM is valid."""
    schema = sorted(f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in _validator().iter_errors(bom))
    return schema + _referential_errors(bom)
