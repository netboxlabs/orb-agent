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

_PLACEHOLDER = "{os_version}"
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")


def render_platform_name(template: str, os_version: str) -> str:
    """Render a platform name from ``template`` using bounded token replacement."""
    return template.replace(_PLACEHOLDER, os_version)


def platform_template_problem(template: str) -> str | None:
    """
    Return a human-readable reason the template is unusable, or None if valid.

    Rejects: empty/whitespace; placeholders other than ``{os_version}``
    (including attribute access / format specs); a missing ``{os_version}``
    (without it the template is a fixed name, which ``defaults.device.platform``
    covers); stray or unbalanced braces; and a template that is nothing but
    ``{os_version}`` or whose other text vanishes from the slug (``--- {os_version}``,
    an OS name without ASCII letters or digits). NetBox identifies a platform by its name and by its slug
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
    return None
