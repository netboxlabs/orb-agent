#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Report policy keys a model does not define, instead of dropping them.

Pydantic ignores unrecognized input keys by default, so a key written at the
wrong nesting level parses without complaint and the setting never takes
effect. Nothing downstream can tell that apart from the option being absent.
The mixin here keeps that permissive behaviour and adds a warning that names
the key, and where it would have been recognized when that is nearby.
"""

import logging
import typing
from collections import deque
from typing import Any

from pydantic import BaseModel, model_validator

logger = logging.getLogger(__name__)

# A misplaced key is almost always one or two levels from where it belongs
# (``discover_modules`` written on config rather than config.options). Past
# that the guess stops being useful and starts pointing at coincidences.
_MAX_SUGGESTION_DEPTH = 2


def _accepted_names(model: type[BaseModel]) -> set[str]:
    """Return every key name ``model`` accepts from input, aliases included."""
    names: set[str] = set()
    for name, field in model.model_fields.items():
        names.add(name)
        for alias in (field.alias, field.validation_alias):
            if isinstance(alias, str):
                names.add(alias)
    return names


def _annotation_models(annotation: Any) -> list[type[BaseModel]]:
    """Pull every model out of an annotation, unwrapping unions and containers."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    found: list[type[BaseModel]] = []
    for arg in typing.get_args(annotation):
        found.extend(_annotation_models(arg))
    return found


def _nested_models(model: type[BaseModel]) -> list[tuple[str, type[BaseModel]]]:
    """Return (field name, nested model) for each field that holds a model."""
    return [(name, nested) for name, field in model.model_fields.items() for nested in _annotation_models(field.annotation)]


def suggest_path(model: type[BaseModel], key: str) -> str | None:
    """
    Return the dotted path where ``key`` would be recognized, or None.

    Breadth-first so the shallowest match wins: a key valid on both
    ``options`` and ``defaults.device`` reports the shorter path.
    """
    queue: deque[tuple[type[BaseModel], tuple[str, ...]]] = deque([(model, ())])
    seen: set[type[BaseModel]] = {model}
    while queue:
        current, path = queue.popleft()
        if len(path) >= _MAX_SUGGESTION_DEPTH:
            continue
        for name, nested in _nested_models(current):
            if key in _accepted_names(nested):
                return ".".join((*path, name, key))
            if nested not in seen:
                seen.add(nested)
                queue.append((nested, (*path, name)))
    return None


class WarnUnknownKeys(BaseModel):
    """
    Mixin that warns about input keys the model does not define.

    Applied to the two blocks whose contents are a fixed, documented set of
    keys — ``config`` and its ``options`` — so the class name is also the
    YAML key an operator writes. Blocks that legitimately carry
    operator-chosen keys, such as the policy map and the ``scope`` entries,
    are deliberately left out: there is no closed key set to check against.
    """

    @model_validator(mode="before")
    @classmethod
    def _warn_unknown_keys(cls, data: Any) -> Any:
        """Log one warning per unrecognized key, then hand the input on unchanged."""
        if not isinstance(data, dict):
            return data
        label = cls.__name__.lower()
        accepted = _accepted_names(cls)
        for key in data:
            if not isinstance(key, str) or key in accepted:
                continue
            suggestion = suggest_path(cls, key)
            if suggestion:
                logger.warning(
                    "ignoring unrecognized %s key %r; did you mean %r?",
                    label,
                    key,
                    suggestion,
                )
            else:
                logger.warning("ignoring unrecognized %s key %r", label, key)
        return data
