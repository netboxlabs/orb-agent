#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""
Parity of the local FortiOS parsers against real captures.

The captures under corpus/ come from networktocode/ntc-templates
(tests/fortinet/, Apache-2.0), with public addresses replaced. baseline.json
records what the ntc-templates parsers produced for the six fields the driver
consumes, so the local parsers can be held to the behaviour they replace.
"""

import json
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"
PHYS_FIELDS = ("name", "status", "speed")
FLAT_FIELDS = ("name", "ip_address", "netmask")


def load_baseline() -> list[dict]:
    """Return the committed baseline entries."""
    return json.loads((CORPUS_DIR / "baseline.json").read_text(encoding="utf-8"))


def test_corpus_is_present_and_shaped_as_documented():
    """11 captures, 73 physical blocks, 102 flat rows, each name preceded by a header."""
    phys = sorted(CORPUS_DIR.glob("phys_*.raw"))
    flat = sorted(CORPUS_DIR.glob("flat_*.raw"))
    assert len(phys) == 4, "expected 4 physical captures"
    assert len(flat) == 7, "expected 7 flat captures"

    blocks = sum(
        1
        for f in phys
        for line in f.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("==[")
    )
    assert blocks == 73, f"expected 73 physical blocks, found {blocks}"

    names = 0
    for f in flat:
        lines = [line for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
        for index, line in enumerate(lines):
            if not line.startswith("name:"):
                continue
            names += 1
            assert index and lines[index - 1].startswith("=="), (
                f"{f.name}: every name: line must directly follow a == header"
            )
    assert names == 102, f"expected 102 flat rows, found {names}"


def test_baseline_matches_the_templates_it_was_generated_from():
    """
    The committed baseline still reproduces from ntc-templates.

    Guards against vendoring the wrong bytes, and tells us if an ntc-templates
    upgrade changes the values we pinned.
    """
    from ntc_templates.parse import parse_output

    for entry in load_baseline():
        raw = (CORPUS_DIR / entry["capture"]).read_text(encoding="utf-8")
        command = (
            "get system interface physical"
            if entry["command"] == "physical"
            else "get system interface"
        )
        fields = PHYS_FIELDS if entry["command"] == "physical" else FLAT_FIELDS
        parsed = parse_output(platform="fortinet", command=command, data=raw)
        got = [{k: row.get(k, "") for k in fields} for row in parsed]
        assert got == entry["rows"], f"{entry['capture']} drifted from baseline"
