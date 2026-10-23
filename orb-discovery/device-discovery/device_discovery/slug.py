#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""Slugs built the way NetBox and Diode build them."""

import re
import unicodedata


def slug(value: str) -> str:
    """
    Return Django's slugify of value.

    NetBox only accepts ASCII in a slug, and Diode derives the slugs it matches
    tenants by the same way, so accents are folded rather than kept.
    """
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^\w\s-]", "", value.lower())
    return re.sub(r"[-\s]+", "-", value).strip("-_")
