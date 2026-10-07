#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Spot two copies of one NetBox tenant written differently in a single entity.

Diode trims names and finds a tenant by the slug of its name, whatever its
group. Two copies whose names slugify alike therefore resolve to one tenant,
and written differently the entity is refused or the tenant rewritten on every
run.
"""

import re
import unicodedata
from typing import Any


def slug(value: str) -> str:
    """Return Django's slugify of value, which Diode matches tenants by."""
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^\w\s-]", "", value.lower())
    return re.sub(r"[-\s]+", "-", value).strip("-_")


def _same(a: str, b: str) -> bool:
    """Report whether two trimmed names resolve alike: equal, or the same non-empty slug."""
    return a == b or (slug(a) != "" and slug(a) == slug(b))


def _differ(a: str | None, b: str | None) -> bool:
    """
    Report whether two optional values are both set and disagree once trimmed.

    An empty string is set: it is sent, and Diode refuses it against a value.
    """
    return a is not None and b is not None and a.strip() != b.strip()


def _tags_differ(a: list[str] | None, b: list[str] | None) -> bool:
    return bool(a) and bool(b) and [t.strip() for t in a] != [t.strip() for t in b]


def _parts(tenant: Any) -> tuple[str, str, Any]:
    """Return a tenant's trimmed name and group, and the tenant itself for its other fields."""
    if isinstance(tenant, str):
        return tenant.strip(), "", None
    return tenant.name.strip(), (tenant.group or "").strip(), tenant


def written_differently(first: Any, second: Any, *, compare_fields: bool) -> str | None:
    """
    Return what makes two copies of one tenant disagree, or None.

    "group" when their groups are one NetBox group written two ways, "tenant"
    when their names resolve to one tenant but the name, group or (with
    compare_fields) description, comments or tags differ. Either value may be a
    tenant name or a TenantParameters.
    """
    name_a, group_a, a = _parts(first)
    name_b, group_b, b = _parts(second)
    if group_a != group_b and _same(group_a, group_b):
        return "group"
    if not _same(name_a, name_b):
        return None
    if name_a != name_b or group_a != group_b:
        return "tenant"
    if compare_fields and a is not None and b is not None and (
        _differ(a.description, b.description)
        or _differ(a.comments, b.comments)
        or _tags_differ(a.tags, b.tags)
    ):
        return "tenant"
    return None
