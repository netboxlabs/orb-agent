#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Platform name templating.

A bounded token renderer and validator shared by the policy model
(config-load validation) and the translator (rendering). Uses str.replace
over the single ``{os_version}`` placeholder — never str.format — so an
operator template cannot trigger attribute access or format-spec injection
and cannot raise at render time.
"""

import re

from device_discovery.slug import slug

# NetBox's maximum length of a platform name (and slug).
PLATFORM_NAME_MAX = 100

_PLACEHOLDER = "{os_version}"
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")


def render_platform_name(template: str, os_version: str) -> str:
    """
    Render a platform name from ``template`` using bounded token replacement.

    A long ``os_version`` is shortened so that the name fits ``PLATFORM_NAME_MAX``
    with the template's own text intact: cutting the rendered name instead would
    drop text after ``{os_version}`` (``{os_version} Fabric Engine``), and two OS
    families could end up with the same name.
    """
    pieces = template.split(_PLACEHOLDER)
    count = len(pieces) - 1
    if not count:
        return template
    room = max(PLATFORM_NAME_MAX - len("".join(pieces)), 0) // count
    return os_version[:room].join(pieces)


def platform_template_problem(template: str) -> str | None:
    """
    Return a human-readable reason the template is unusable, or None if valid.

    Rejects: empty/whitespace; placeholders other than ``{os_version}``
    (including attribute access / format specs); a missing ``{os_version}``
    (without it the template is a fixed name, which ``defaults.device.platform``
    covers); stray or unbalanced braces; and a template that is nothing but
    ``{os_version}`` or whose other text vanishes from the slug (``--- {os_version}``,
    an OS name without ASCII letters or digits) or leaves no room for the version
    within ``PLATFORM_NAME_MAX``. NetBox identifies a platform by its name and by its slug
    within its manufacturer, not by its parent, so a bare release such as
    ``9.4.0.0`` discovered from two OS families of one manufacturer would be a
    single platform whose parent follows whichever policy ran last.
    """
    if not template or not template.strip():
        return "template is empty"
    tokens = _PLACEHOLDER_RE.findall(template)
    for tok in tokens:
        if any(c in tok for c in ".[:!"):
            return f"disallowed placeholder {{{tok}}}"
        if tok != "os_version":
            return f"unknown placeholder {{{tok}}}"
    if "os_version" not in tokens:
        return "template must include the {os_version} placeholder"
    residual = template.replace(_PLACEHOLDER, "")
    if "{" in residual or "}" in residual:
        return "template has stray or unbalanced braces"
    if not slug(residual):
        return "template must include text besides {os_version} that is kept in a slug (ASCII letters or digits), e.g. the OS name"
    if len(residual) >= PLATFORM_NAME_MAX:
        return f"template text besides {{os_version}} must be shorter than {PLATFORM_NAME_MAX} characters"
    return None


def platform_parent_problem(parent: str) -> str | None:
    """Return a reason the (trimmed) parent platform name is unusable, or None if valid."""
    if not slug(parent):
        return "parent must include ASCII letters or digits (its slug would be empty)"
    if len(parent) > PLATFORM_NAME_MAX:
        return f"parent must not be longer than {PLATFORM_NAME_MAX} characters"
    return None
