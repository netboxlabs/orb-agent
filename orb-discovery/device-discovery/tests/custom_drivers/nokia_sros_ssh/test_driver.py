"""Unit tests for custom_napalm.nokia_sros_ssh.SROSSSHDriver."""

from pathlib import Path

from custom_napalm.nokia_sros_ssh import (
    SROSSSHDriver,
    _nokia_sros_ssh_parse_port_list,
    _parse_port_hw_mac_addresses,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeCLIDevice


class TestSROSSSHDriver(BaseDriverTest):
    """Unit tests for SROSSSHDriver using file-based CLI mocks."""

    driver_cls = SROSSSHDriver
    fake_device_cls = FakeCLIDevice
    mock_data_root = Path(__file__).parent / "mock_data"


# ---------------------------------------------------------------------------
# _parse_port_hw_mac_addresses — parser unit tests
# ---------------------------------------------------------------------------


_SHOW_PORT_DETAIL_TWO_PORTS = """\
===============================================================================
Ethernet Interface
===============================================================================
Interface          : 1/1/1                      Oper Speed       : 1 Gbps
Admin State        : up                         Oper Duplex      : full
Configured Mac     : 90:ec:00:00:00:01
Hardware Mac       : 90:ec:00:00:00:01
===============================================================================
===============================================================================
Ethernet Interface
===============================================================================
Interface          : 1/1/2                      Oper Speed       : 1 Gbps
Admin State        : up                         Oper Duplex      : full
Configured Mac     : 90:ec:00:00:00:02
Hardware Mac       : 90:ec:00:00:00:02
===============================================================================
"""


def test_parse_port_hw_mac_addresses_typical_multi_block():
    """Two consecutive port blocks → port_id → normalised MAC dict."""
    result = _parse_port_hw_mac_addresses(_SHOW_PORT_DETAIL_TWO_PORTS)
    assert result == {
        "1/1/1": "90:EC:00:00:00:01",
        "1/1/2": "90:EC:00:00:00:02",
    }


def test_parse_port_hw_mac_addresses_empty_input_returns_empty():
    """Empty / None input never raises — empty dict result."""
    assert _parse_port_hw_mac_addresses("") == {}
    assert _parse_port_hw_mac_addresses(None) == {}  # type: ignore[arg-type]


def test_parse_port_hw_mac_addresses_skips_block_without_hw_mac():
    """A block with Interface but no Hardware Mac row is silently skipped."""
    text = """\
===============================================================================
Ethernet Interface
===============================================================================
Interface          : 1/1/9                      Oper Speed       : N/A
Admin State        : down
Configured Mac     : N/A
===============================================================================
===============================================================================
Ethernet Interface
===============================================================================
Interface          : 1/1/10                     Oper Speed       : 10 Gbps
Hardware Mac       : 90:ec:00:00:00:0a
===============================================================================
"""
    # 1/1/9 lacks a Hardware Mac row → skipped. 1/1/10 still resolves.
    assert _parse_port_hw_mac_addresses(text) == {"1/1/10": "90:EC:00:00:00:0A"}


def test_parse_port_hw_mac_addresses_prefers_hardware_over_configured():
    """When both ``Configured Mac`` and ``Hardware Mac`` are present, only Hardware is taken."""
    text = """\
===============================================================================
Ethernet Interface
===============================================================================
Interface          : 1/1/1
Configured Mac     : aa:bb:cc:dd:ee:ff
Hardware Mac       : 90:ec:00:00:00:01
===============================================================================
"""
    assert _parse_port_hw_mac_addresses(text) == {"1/1/1": "90:EC:00:00:00:01"}


def test_parse_port_hw_mac_addresses_md_cli_hardware_address_label():
    """MD-CLI (SR-OS 19+) uses ``Hardware Address`` instead of ``Hardware Mac``."""
    text = """\
===============================================================================
Ethernet Interface
===============================================================================
Interface         : 1/1/c2/1                   Oper Speed         : 10 Gbps
Configured Address: aa:bb:cc:dd:ee:42
Hardware Address  : 90:ec:00:00:00:42
===============================================================================
"""
    assert _parse_port_hw_mac_addresses(text) == {"1/1/c2/1": "90:EC:00:00:00:42"}


def test_parse_port_hw_mac_addresses_accepts_non_padded_mac():
    """napalm.mac() accepts ``aa:bb:cc:dd:ee:1`` and pads to ``AA:BB:CC:DD:EE:01`` — regex must allow shorter form too."""
    text = """\
===============================================================================
Interface          : 1/1/1
Hardware Mac       : aa:bb:cc:dd:ee:1
===============================================================================
"""
    assert _parse_port_hw_mac_addresses(text) == {"1/1/1": "AA:BB:CC:DD:EE:01"}


def test_driver_exposes_get_modules():
    """SSH driver MUST expose a callable get_modules method."""
    assert hasattr(SROSSSHDriver, "get_modules")
    assert callable(SROSSSHDriver.get_modules)


def _run_both_drivers(scenario: str):
    """Construct one NETCONF and one SSH driver against the named scenario."""
    from custom_napalm.nokia_sros import SROSDriver
    from tests.custom_drivers.mock_device import FakeNetconfConn

    netconf_mock = Path(__file__).parents[1] / "nokia_sros" / "mock_data" / "test_get_modules" / scenario
    netconf_drv = object.__new__(SROSDriver)
    netconf_drv.hostname = netconf_drv.username = netconf_drv.password = "test"
    netconf_drv.timeout = 60
    netconf_drv.conn = FakeNetconfConn(netconf_mock)

    ssh_mock = Path(__file__).parent / "mock_data" / "test_get_modules" / scenario
    ssh_drv = object.__new__(SROSSSHDriver)
    ssh_drv.hostname = ssh_drv.username = ssh_drv.password = "test"
    ssh_drv.timeout = 60
    ssh_drv.device = FakeCLIDevice(ssh_mock)

    return netconf_drv.get_modules(), ssh_drv.get_modules()


def test_get_modules_parity_with_netconf_sr12():
    """SR-12 envelope MUST match between NETCONF and SSH drivers."""
    netconf, ssh = _run_both_drivers("sr12_full")
    assert netconf == ssh


def test_get_modules_parity_with_netconf_sr7s():
    """SR-7s IMM envelope (depth-3 via integrated MDA) MUST match across transports."""
    netconf, ssh = _run_both_drivers("sr7s_imm")
    assert netconf == ssh


def test_get_modules_parity_with_netconf_sr1():
    """SR-1 fixed-config envelope is None on both transports."""
    netconf, ssh = _run_both_drivers("sr1_fixed")
    assert netconf is None
    assert ssh is None


# ---------------------------------------------------------------------------
# _nokia_sros_ssh_parse_port_list — port-id regex unit tests
# ---------------------------------------------------------------------------


def test_parse_port_list_classic_three_segment():
    """Standard slot/mda/port form is matched."""
    text = """\
===============================================================================
Ports on Slot 1
===============================================================================
1/1/1         Up    Yes  Up      9212
1/2/1         Up    Yes  Up      9212
===============================================================================
"""
    assert _nokia_sros_ssh_parse_port_list(text) == ["1/1/1", "1/2/1"]


def test_parse_port_list_connector_cage_four_segment():
    """FP4 IMM connector-cage form slot/mda/c<N>/port is matched."""
    text = """\
1/1/c2/1      Up    Yes  Up      9212
1/1/c3/1      Up    Yes  Up      9212
"""
    assert _nokia_sros_ssh_parse_port_list(text) == ["1/1/c2/1", "1/1/c3/1"]


def test_parse_port_list_last_line_no_trailing_whitespace():
    """A port-id terminating at EOL (no trailing whitespace) is still matched."""
    text = "1/1/1\n2/1/1"
    assert _nokia_sros_ssh_parse_port_list(text) == ["1/1/1", "2/1/1"]


def test_parse_port_list_empty_input_returns_empty():
    """Empty / None input never raises — empty list result."""
    assert _nokia_sros_ssh_parse_port_list("") == []
    assert _nokia_sros_ssh_parse_port_list(None) == []  # type: ignore[arg-type]


def test_parse_port_list_breakout_subports():
    """QSFP/QSFP28 breakout sub-port form `slot/mda/port[N]` is matched."""
    text = """\
1/1/1[1]      Up    Yes  Up      9212
1/1/1[2]      Up    Yes  Up      9212
1/1/c2/1[1]   Up    Yes  Up      9212
"""
    assert _nokia_sros_ssh_parse_port_list(text) == ["1/1/1[1]", "1/1/1[2]", "1/1/c2/1[1]"]


def test_parse_port_list_ignores_line_internal_port_ids():
    """A port-id inside a description column (not at line start) is NOT matched."""
    text = "Description    : To 1/1/1 from peer\n1/1/2         Up"
    assert _nokia_sros_ssh_parse_port_list(text) == ["1/1/2"]


def test_parse_cards_case_insensitive_detail_header():
    """`Card N detail` (MD-CLI lower-case) matches the same as `Card N Detail`."""
    from custom_napalm.nokia_sros_ssh import _nokia_sros_ssh_parse_cards
    text = """\
===============================================================================
Card 1 detail
===============================================================================
Slot                           : 1
Card Type                      : iom4-e
Serial Number                  : NS-IOM1-001
Part Number                    : 3HE09576AA
===============================================================================
"""
    rows = _nokia_sros_ssh_parse_cards(text)
    assert rows == [{
        "slot": "1",
        "equipped_type": "iom4-e",
        "pid": "3HE09576AA",
        "sn": "NS-IOM1-001",
    }]


def test_parse_mdas_case_insensitive_detail_header():
    """`MDA 4/1 detail` (MD-CLI lower-case) matches the same as `MDA 4/1 Detail`."""
    from custom_napalm.nokia_sros_ssh import _nokia_sros_ssh_parse_mdas
    text = """\
===============================================================================
MDA 4/1 detail
===============================================================================
Slot                           : 4
MDA                            : 1
MDA Type                       : me10-10gb-sfp+
Serial Number                  : NS-MDA-004
Part Number                    : 3HE09579AA
===============================================================================
"""
    rows = _nokia_sros_ssh_parse_mdas(text)
    assert rows == [{
        "parent_slot": "4",
        "mda_slot": "1",
        "equipped_type": "me10-10gb-sfp+",
        "pid": "3HE09579AA",
        "sn": "NS-MDA-004",
    }]


def test_classify_xcm_ssh_as_linecard():
    """SSH classifier handles XCM (7950 XRS forwarding card) too."""
    from custom_napalm.nokia_sros_ssh import classify_module_type_nokia_sros_ssh
    assert classify_module_type_nokia_sros_ssh("xcm-x20") == "linecard"
    assert classify_module_type_nokia_sros_ssh("XCM-X20") == "linecard"


def test_parse_port_transceiver_accepts_model_number_label():
    """Real SR-OS prints `Model Number :` in Transceiver Data — must be matched."""
    from custom_napalm.nokia_sros_ssh import _nokia_sros_ssh_parse_port_transceiver
    text = """\
===============================================================================
Port 1/1/1
===============================================================================
Description                    : To-Spine-A
Transceiver Data
   Model Number                : SFP-10G-LR
   Serial Number               : OPTIC10G0001
   Part Number                 : 3HE04823AA
===============================================================================
"""
    assert _nokia_sros_ssh_parse_port_transceiver(text) == {
        "port_id": "1/1/1",
        "model": "SFP-10G-LR",
        "sn": "OPTIC10G0001",
        "pid": "3HE04823AA",
    }


def test_parse_cards_real_sros_format_uses_summary_for_equipped_type():
    """Equipped type comes from summary; part/serial from Hardware Data subsection."""
    from custom_napalm.nokia_sros_ssh import _nokia_sros_ssh_parse_cards
    text = """\
===============================================================================
Card Summary
===============================================================================
Slot   Provisioned Type           Equipped Type              Admin  Oper
                                                             State  State
-------------------------------------------------------------------------------
1      iom4-e                     iom4-e                     up     up
A      cpm5                       cpm5                       up     up
===============================================================================
Card 1
===============================================================================
Hardware Data
-------------------------------------------------------------------------------
   Part number                   : 3HE09576AA
   Serial number                 : NS-IOM1-001
===============================================================================
Card A
===============================================================================
Hardware Data
-------------------------------------------------------------------------------
   Part number                   : 3HE07016AA
   Serial number                 : NS-CPMA-001
===============================================================================
"""
    rows = _nokia_sros_ssh_parse_cards(text)
    assert rows == [
        {"slot": "1", "equipped_type": "iom4-e", "pid": "3HE09576AA", "sn": "NS-IOM1-001"},
        {"slot": "A", "equipped_type": "cpm5", "pid": "3HE07016AA", "sn": "NS-CPMA-001"},
    ]


def test_parse_card_summary_single_type_row():
    """When Equipped Type == Provisioned Type, SR-OS leaves the equipped column blank."""
    from custom_napalm.nokia_sros_ssh import _nokia_sros_ssh_parse_card_summary
    text = """\
===============================================================================
Card Summary
===============================================================================
Slot   Provisioned Type           Equipped Type              Admin  Oper
-------------------------------------------------------------------------------
1      iom5-e:he1200g+                                       up     up
2      iom4-e                     iom4-e                     up     up
A      cpm5                                                  up     up/active
B      cpm5                                                  up     up/standby
===============================================================================
"""
    summary = _nokia_sros_ssh_parse_card_summary(text)
    assert summary == {
        # single-type form: equipped column blank → falls back to provisioned
        "1": "iom5-e:he1200g+",
        # two-type form: equipped column populated → used directly
        "2": "iom4-e",
        # operational state suffix `/active` / `/standby` does not break parsing
        "A": "cpm5",
        "B": "cpm5",
    }


def test_fetch_mdas_skips_sfm_and_cpm_slots():
    """SFM and CPM rows must not trigger `show mda <slot> detail` commands."""
    from custom_napalm.nokia_sros_ssh import _nokia_sros_ssh_fetch_and_parse_mdas

    class _FakeDevice:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def send_command(self, cmd: str) -> str:
            self.commands.append(cmd)
            return ""

    class _FakeDriver:
        def __init__(self) -> None:
            self.device = _FakeDevice()

    driver = _FakeDriver()
    card_rows = [
        {"slot": "1", "equipped_type": "iom4-e", "pid": "X", "sn": "Y"},
        {"slot": "A", "equipped_type": "cpm5", "pid": "X", "sn": "Y"},
        {"slot": "SFM 1", "equipped_type": "sfm5-12", "pid": "X", "sn": "Y"},
        {"slot": "SFM 2", "equipped_type": "sfm5-12", "pid": "X", "sn": "Y"},
        {"slot": "2", "equipped_type": "imm36-100g-qsfp28", "pid": "X", "sn": "Y"},
    ]
    _nokia_sros_ssh_fetch_and_parse_mdas(driver, card_rows)
    # Only IOM (slot 1) and IMM (slot 2) should generate MDA commands.
    assert driver.device.commands == [
        "show mda 1 detail",
        "show mda 2 detail",
    ]


def test_parse_sfms_real_sros_format():
    """`show sfm detail` accepts both `Fabric <N>` (real SR-OS) and `SFM <N>` headers."""
    from custom_napalm.nokia_sros_ssh import _nokia_sros_ssh_parse_sfms
    text = """\
===============================================================================
SFM Summary
===============================================================================
Slot  Provisioned Type     Equipped Type        Admin  Operational
                                                State  State
-------------------------------------------------------------------------------
1     sfm5-12              sfm5-12              up     up
2     sfm5-12              sfm5-12              up     up
===============================================================================
Fabric 1
===============================================================================
Hardware Data
-------------------------------------------------------------------------------
   Part number                  : 3HE08648AA
   Serial number                : NS-SFM1-001
===============================================================================
SFM 2
===============================================================================
Hardware Data
-------------------------------------------------------------------------------
   Part number                  : 3HE08648AA
   Serial number                : NS-SFM2-001
===============================================================================
"""
    rows = _nokia_sros_ssh_parse_sfms(text)
    assert rows == [
        # First block uses real SR-OS `Fabric 1` header
        {"slot": "SFM 1", "equipped_type": "sfm5-12", "pid": "3HE08648AA", "sn": "NS-SFM1-001"},
        # Second block uses legacy `SFM 2` header — still accepted
        {"slot": "SFM 2", "equipped_type": "sfm5-12", "pid": "3HE08648AA", "sn": "NS-SFM2-001"},
    ]


def test_parse_cards_summary_header_not_mismatched_as_slot():
    """`Card Summary` header must NOT be matched as slot='Summary'."""
    from custom_napalm.nokia_sros_ssh import _nokia_sros_ssh_parse_cards
    text = """\
===============================================================================
Card Summary
===============================================================================
1      iom4-e                     iom4-e                     up     up
===============================================================================
"""
    # No `Card N` per-card detail block → no rows emitted (summary alone is
    # not enough; we need Part/Serial from Hardware Data).
    rows = _nokia_sros_ssh_parse_cards(text)
    assert rows == []


def test_parse_port_transceiver_accepts_bare_model_label():
    """Legacy / abbreviated SR-OS outputs print `Model :` — still accepted."""
    from custom_napalm.nokia_sros_ssh import _nokia_sros_ssh_parse_port_transceiver
    text = """\
===============================================================================
Port 2/1/1
===============================================================================
Transceiver Data
   Model                       : QSFP-100G-SR4
   Serial Number               : OPTIC100G0001
   Part Number                 : 3HE04824AA
===============================================================================
"""
    assert _nokia_sros_ssh_parse_port_transceiver(text) == {
        "port_id": "2/1/1",
        "model": "QSFP-100G-SR4",
        "sn": "OPTIC100G0001",
        "pid": "3HE04824AA",
    }
