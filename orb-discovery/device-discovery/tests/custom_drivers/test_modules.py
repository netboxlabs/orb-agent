# Copyright 2026 NetBox Labs Inc
"""Tests for the vendor-neutral _modules helper."""

import pytest

from custom_napalm._modules import is_optic_pid


@pytest.mark.parametrize("pid,expected", [
    ("SFP-10G-LR", True),
    ("SFP+10G-SR", True),
    ("QSFP-100G-SR4", True),
    ("QSFP+40G-LR4", True),
    ("QSFP28-100G-LR", True),
    ("QSFP-DD-400G-DR4", True),
    ("GLC-T", True),
    ("X2-10GB-LR", True),
    ("CFP-40G-LR4", True),
    ("CFP2-100G-LR4", True),
    ("XENPAK-10GB-LR", True),
    ("XFP-10G-LR", True),
    ("CVR-X2-SFP", True),
    ("SFP28-25G-SR", True),
    ("SFP56-50G-LR", True),
    ("QSFP56-200G-FR4", True),
    ("OSFP-400G-DR4", True),
    ("QDD-400G-DR4-S", True),  # Cisco 400G QSFP-DD PIDs start with QDD-, not QSFP-DD
    ("QDD-400G-FR4-S", True),
    ("QDD-2X100-CWDM4-S", True),
    ("QDDX-NOTANOPTIC", False),  # prefix needs the dash — QDDX- != QDD-
    ("OSPF-PROCESS", False),  # OSPF, not OSFP — typo-guard must not false-match
    ("C9400-LC-48U", False),
    ("C9400-SUP-1", False),
    ("DCS-7500R-36CQ", False),
    ("N9K-X9716D-GX", False),
    ("PWR-C5-715WAC", False),
    ("FAN-T1", False),
    ("", False),
    ("   ", False),
])
def test_is_optic_pid(pid, expected):
    """Standardized optic prefixes match; vendor linecard/psu/fan PIDs do not."""
    assert is_optic_pid(pid) is expected
