#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Stack (virtual-chassis) member name templating.

A bounded token renderer and validator shared by the policy model
(config-load validation) and the chassis translator (rendering). Uses
str.replace over a fixed placeholder set — never str.format — so an operator
template cannot trigger attribute access or format-spec injection and cannot
raise at render time.
"""

import re

DEFAULT_STACK_MEMBER_TEMPLATE = "{name}-{id}"

# Placeholders the renderer substitutes. {name} = stack/VC name, {id} =
# device-reported member id.
_ALLOWED_PLACEHOLDERS = ("name", "id")
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")


def render_stack_member_name(template: str, name: str, member_id: object) -> str:
    """Render a member name from ``template`` using bounded token replacement."""
    return template.replace("{name}", str(name)).replace("{id}", str(member_id))


def stack_template_problem(template: str) -> str | None:
    """
    Return a human-readable reason the template is unusable, or None if valid.

    Rejects: empty/whitespace; placeholders that are unknown or contain
    ``.``/``[``/``:`` (attribute access / format specs); a missing ``{name}``
    (without it, names collide across stacks in the same site); and templates
    that do not render distinct names for distinct member ids.
    """
    if not template or not template.strip():
        return "template is empty"
    tokens = _PLACEHOLDER_RE.findall(template)
    for tok in tokens:
        if any(c in tok for c in ".[:"):
            return f"disallowed placeholder {{{tok}}}"
        if tok not in _ALLOWED_PLACEHOLDERS:
            return f"unknown placeholder {{{tok}}}"
    if "name" not in tokens:
        return "template must include the {name} placeholder"
    if render_stack_member_name(template, "vc", "1") == render_stack_member_name(
        template, "vc", "2"
    ):
        return "template does not vary by member {id}"
    return None
