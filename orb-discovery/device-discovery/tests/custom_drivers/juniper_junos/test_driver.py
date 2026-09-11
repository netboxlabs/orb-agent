"""
Tests for the JunOSDriver subclass.

Covers two extension surfaces beyond the inherited NAPALM behaviour:

- ``get_interfaces_vlans``: VLAN-interface associations parsed from the
  ELS / non-ELS ``<get-ethernet-switching-interface-information>`` reply.
  Driven by file-based scenario fixtures via ``BaseDriverTest``.
- ``get_chassis_members``: Junos Virtual Chassis discovery via
  ``<get-virtual-chassis-information>``. Scenario fixtures cover the
  parsing paths; the unit-level tests below pin the log-level discipline
  (``RpcError`` → DEBUG; other exceptions → WARNING) so standalone
  EX/QFX devices do not produce per-cycle warning noise.
"""

import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from jnpr.junos.exception import RpcError

from custom_napalm.junos import (
    JunOSDriver,
    _junos_get_chassis_members_impl,
    classify_module_type_junos,
)
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakePyEZDevice


@pytest.mark.parametrize("part_number,description,name,expected", [
    # Junos reports transceivers as "Xcvr N" leaf elements — the element NAME
    # is the optic signal, NOT the description (which can advertise port caps).
    ("740-021308", "SFP+-10G-SR", "Xcvr 0", "transceiver"),
    ("740-061405", "SFP28-25G-SR", "Xcvr 0", "transceiver"),
    ("740-058734", "QSFP28-100G-LR4", "Xcvr 1", "transceiver"),
    # MSA-prefixed part still wins via is_optic_pid regardless of name.
    ("QSFP-100G-LR4", "", "Xcvr 0", "transceiver"),
    # codex-3 regression (the bug): FPC/PIC descriptions advertise PORT
    # CAPABILITIES ("48x SFP/SFP+ ports", "4x 40GE QSFP+") that the old
    # description regex false-matched as transceiver, dropping the linecard
    # bay + its interfaces in linecards mode. Name-gating keeps them linecard.
    ("750-054576", "48x SFP/SFP+ ports", "PIC 0", "linecard"),
    ("750-054576", "4x 40GE QSFP+", "PIC 1", "linecard"),
    ("750-068369", "MPC7E 3D MRATE-12xQSFPP-XGE-XLGE-CGE", "FPC 0", "linecard"),
    # Routing Engine maps to supervisor (Junos uses RE terminology).
    ("740-031116", "RE-S-1800x4 Routing Engine", "Routing Engine 0", "supervisor"),
    # RE classification is name-based for robustness: even an empty/terse
    # description maps to supervisor when the element is named "Routing Engine N".
    ("740-x", "RE-S-2X00x6", "Routing Engine 0", "supervisor"),
    # A non-MSA element NOT named Xcvr falls through to linecard (name-gating).
    ("750-xxxx", "some linecard", "FPC 2", "linecard"),
    # A Midplane-like FRU classifies as linecard (the default) — but the parse
    # gate skips it at the top level, so this never reaches Diode emission.
    # The gate is the real protection; the classifier is secondary.
    ("711-x", "Midplane", "Midplane", "linecard"),
])
def test_classify_module_type_junos(part_number, description, name, expected):
    """Optics classify by the Xcvr element name (or MSA part); descriptions never gate."""
    assert classify_module_type_junos(part_number, description, name) == expected


class TestJunOSDriver(BaseDriverTest):
    """Tests for the Juniper Junos custom NAPALM driver."""

    driver_cls = JunOSDriver
    fake_device_cls = FakePyEZDevice
    mock_data_root = Path(__file__).parent / "mock_data"

    def test_get_facts(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_interfaces(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_interfaces_ip(self, scenario):
        """
        The override drops a virtual address and keeps everything else.

        No longer inherited: this driver overrides get_interfaces_ip to leave
        out the addresses the device reports as VRRP virtual addresses. Upstream
        still does the parsing, including turning the maskless virtual address
        into a host length, so this exercises the real chain rather than a stub.
        """
        mock_dir = self.mock_data_root / "test_get_interfaces_ip" / scenario
        driver = self._build_driver(mock_dir)
        result = driver.get_interfaces_ip()
        assert result["ae0.100"]["ipv4"] == {"192.0.2.3": {"prefix_length": 24}}, (
            "the virtual address must be gone and the real one untouched"
        )
        assert result["lo0.0"]["ipv4"] == {"192.0.2.4": {"prefix_length": 32}}, (
            "a loopback is reported maskless too, and must survive"
        )

    def test_get_config(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_config_sanitized(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_get_vlans(self, scenario):
        """Skip: inherited from napalm.junos.junos.JunOSDriver."""
        pytest.skip("inherited from napalm.junos.junos.JunOSDriver")

    def test_junos_driver_exposes_get_modules(self) -> None:
        """get_modules() must exist on JunOSDriver after this batch lands."""
        assert hasattr(JunOSDriver, "get_modules")
        assert callable(getattr(JunOSDriver, "get_modules"))


def test_chassis_members_rpc_error_logs_debug_not_warning(caplog):
    """
    Standalone EX/QFX (no VC) raises RpcError — must log at DEBUG, not WARNING.

    Without this discipline every non-VC Junos device would emit a per-cycle
    WARNING during discovery, drowning out signals operators actually care about.
    """
    driver = MagicMock()
    driver.device.rpc.get_virtual_chassis_information.side_effect = RpcError(
        rsp="virtual-chassis information not available"
    )

    with caplog.at_level(logging.DEBUG, logger="custom_napalm.junos"):
        result = _junos_get_chassis_members_impl(driver)

    assert result is None
    assert not any(
        r.levelno >= logging.WARNING for r in caplog.records
    ), "RpcError on standalone Junos must NOT log at WARNING level"
    assert any(
        r.levelno == logging.DEBUG and "RPC not supported" in r.message
        for r in caplog.records
    ), "expected DEBUG log explaining the standalone-Junos fallback"


def test_chassis_members_unexpected_exception_logs_warning(caplog):
    """
    Any non-RpcError exception (transport / driver bug) must still surface as WARNING.

    The WARNING must include exception info (traceback) — without it, operators
    only see the exception string, which is rarely enough to root-cause transport
    or PyEZ failures.
    """
    driver = MagicMock()
    driver.device.rpc.get_virtual_chassis_information.side_effect = RuntimeError("boom")

    with caplog.at_level(logging.DEBUG, logger="custom_napalm.junos"):
        result = _junos_get_chassis_members_impl(driver)

    assert result is None
    warning_records = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "unexpected RPC failure" in r.message
    ]
    assert warning_records, "non-RpcError exceptions must log at WARNING so operators see real problems"
    # Traceback must be attached. Python sets r.exc_info to a 3-tuple when
    # exc_info=True is passed (or via logger.exception); falsy otherwise.
    assert warning_records[0].exc_info is not None and warning_records[0].exc_info[0] is RuntimeError, (
        "WARNING record must carry the traceback (exc_info) so operators can diagnose"
    )


def test_interfaces_vlans_falls_back_to_the_details_rpc_when_the_first_is_a_syntax_error(caplog):
    """
    The details RPC answers where the first is a syntax error, and its rows are parsed.

    An ELS Junos refuses get-ethernet-switching-interface-information outright
    and answers get-ethernet-switching-interface-details with the nested entry
    rows. The refusal is logged at DEBUG only, since it is the normal state of
    such a switch.
    """
    from lxml import etree

    fixture = (
        Path(__file__).parent
        / "mock_data"
        / "test_get_interfaces_vlans"
        / "els_details"
        / "get-ethernet-switching-interface-details.xml"
    )
    driver = JunOSDriver.__new__(JunOSDriver)
    driver.device = MagicMock()
    driver.device.rpc.get_ethernet_switching_interface_information.side_effect = RpcError(
        rsp="syntax error"
    )
    driver.device.rpc.get_ethernet_switching_interface_details.return_value = etree.fromstring(
        fixture.read_bytes()
    )

    with caplog.at_level(logging.DEBUG, logger="custom_napalm.junos"):
        result = driver.get_interfaces_vlans()

    assert result["xe-0/0/19"] == {"mode": "trunk", "tagged": [665], "untagged": None}
    assert result["xe-0/0/6"]["tagged"] == [156, 162, 166]
    assert "em0" not in result and "em0.0" not in result, "an interface with no VLAN rows is skipped"
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)


def test_details_walk_survives_an_xml_comment_in_the_reply():
    """
    A comment node in the details reply is skipped, not a reason to drop the result.

    Real ncclient replies can carry comments and processing instructions,
    whose tags are not strings; reading a name off one raised, the fallback
    caught it, and every association of an otherwise valid reply was lost.
    """
    from lxml import etree

    from custom_napalm.junos import _els_details_to_switchports

    fixture = (
        Path(__file__).parent
        / "mock_data"
        / "test_get_interfaces_vlans"
        / "els_details"
        / "get-ethernet-switching-interface-details.xml"
    )
    text = fixture.read_text(encoding="utf-8").replace(
        "<l2iff-interface-name>xe-0/0/19.0</l2iff-interface-name>",
        "<!-- a comment the switch left --><l2iff-interface-name>xe-0/0/19.0</l2iff-interface-name>",
        1,
    )
    assert "<!--" in text
    result = _els_details_to_switchports(etree.fromstring(text.encode("utf-8")))
    assert result["xe-0/0/19"] == {"mode": "trunk", "tagged": [665], "untagged": None}


class TestJunosSwitchportModeFallback:
    """
    Classify a switchport when the reply carries no mode element.

    The plain form of ``<get-ethernet-switching-interface-information>`` can
    answer with VLAN memberships and no ``<interface-port-mode>`` anywhere. A
    measured EX4550 on 15.1 does exactly that, and every one of its ports read
    as routed, so the switch reached NetBox with no VLAN associations at all.
    """

    @staticmethod
    def _wrapper(xml: str):
        from lxml import etree

        return etree.fromstring(
            b'<switching-interface-information xmlns:junos="http://xml.juniper.net/junos/x/junos">'
            + xml.encode()
            + b"</switching-interface-information>"
        )

    @staticmethod
    def _driver(brief: str, detail: str | None = None, vlans: dict | None = None):
        from custom_napalm.junos import JunOSDriver

        wrapper = TestJunosSwitchportModeFallback._wrapper

        class Dev:
            def __init__(self):
                self.rpc = self
                self.asked = []

            def get_ethernet_switching_interface_information(self, **kw):
                self.asked.append(kw)
                if kw.get("detail"):
                    if detail is None:
                        raise RuntimeError("this platform rejects the argument")
                    return wrapper(detail)
                return wrapper(brief)

            def get_ethernet_switching_interface_details(self, **kw):
                raise RuntimeError("not an ELS switch")

        d = object.__new__(JunOSDriver)
        d.device = Dev()
        d.get_vlans = lambda: (vlans if vlans is not None else {})
        return d

    ACCESS_MEMBER = """
        <interface>
          <interface-name>ge-0/0/23.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>VL888</interface-vlan-name>
              <interface-vlan-member-tagid>888</interface-vlan-member-tagid>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""

    TRUNK_MEMBER = """
        <interface>
          <interface-name>xe-0/0/17.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>VL156</interface-vlan-name>
              <interface-vlan-member-tagid>156</interface-vlan-member-tagid>
              <interface-vlan-member-tagness>tagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""

    def test_mode_is_read_from_membership_when_the_element_is_absent(self):
        """A tagged member makes a trunk; an untagged-only member makes access."""
        d = self._driver(self.ACCESS_MEMBER + self.TRUNK_MEMBER)
        result = d.get_interfaces_vlans()

        assert result["ge-0/0/23.0"] == {"mode": "access", "tagged": [], "untagged": 888}
        assert result["xe-0/0/17.0"] == {"mode": "trunk", "tagged": [156], "untagged": None}

    def test_the_detail_form_is_asked_for_first(self):
        """
        Ask for the reply that carries the mode element.

        It is the authoritative statement of access versus trunk, and only the
        detailed reply has it.
        """
        detail = """
        <interface>
          <interface-name>ge-0/0/23.0</interface-name>
          <interface-port-mode>Trunk</interface-port-mode>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>VL888</interface-vlan-name>
              <interface-vlan-member-tagid>888</interface-vlan-member-tagid>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""
        d = self._driver(self.ACCESS_MEMBER, detail=detail)
        result = d.get_interfaces_vlans()

        assert d.device.asked[0] == {"detail": True}, "the detailed form must be asked for first"
        # The device says trunk. Membership alone would have inferred access,
        # which is the case inference cannot get right and the element can.
        assert result["ge-0/0/23.0"]["mode"] == "trunk"

    def test_the_plain_form_still_answers_when_detail_is_refused(self):
        """A platform that rejects the argument keeps the behaviour it has."""
        d = self._driver(self.ACCESS_MEMBER, detail=None)
        result = d.get_interfaces_vlans()

        assert [kw.get("detail", False) for kw in d.device.asked] == [True, False]
        assert result["ge-0/0/23.0"]["mode"] == "access"

    def test_a_member_named_but_not_tagged_is_resolved_from_the_vlan_table(self):
        """Junos reports some members by name alone; the device's own table names them."""
        xml = """
        <interface>
          <interface-name>ge-0/0/9.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>VOICE</interface-vlan-name>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""
        d = self._driver(xml, vlans={30: {"name": "VOICE"}, 40: {"name": "DATA"}})

        assert d.get_interfaces_vlans()["ge-0/0/9.0"] == {
            "mode": "access",
            "tagged": [],
            "untagged": 30,
        }

    def test_a_name_differing_only_in_case_is_a_different_name(self):
        """
        A name differing only in case names a different VLAN.

        Junos puts the out-of-band management port in a pseudo-VLAN named
        ``mgmt`` that is not in the switching space, while a real VLAN on the
        same measured switch is named ``MGMT`` at tag 20. Case-folding would
        bind the management port to that VLAN, wrongly and silently.
        """
        xml = """
        <interface>
          <interface-name>me0.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>mgmt</interface-vlan-name>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""
        d = self._driver(xml, vlans={20: {"name": "MGMT"}})

        assert d.get_interfaces_vlans()["me0.0"]["untagged"] is None

    def test_a_name_the_table_gives_two_ids_is_refused(self):
        """Nothing but the device could say which was meant, and it has not."""
        xml = """
        <interface>
          <interface-name>ge-0/0/9.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>SHARED</interface-vlan-name>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""
        d = self._driver(xml, vlans={10: {"name": "SHARED"}, 11: {"name": "SHARED"}})

        assert d.get_interfaces_vlans()["ge-0/0/9.0"]["untagged"] is None

    def test_the_vlan_table_is_fetched_once_at_most(self):
        """
        Fetch the VLAN table once at most, and only when a name needs it.

        The table costs an RPC. It is not fetched at all when every member
        carries a tagid, and fetched once however many members are reported by
        name, rather than once per member.
        """
        xml = """
        <interface>
          <interface-name>ge-0/0/9.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>VOICE</interface-vlan-name>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>
        <interface>
          <interface-name>ge-0/0/10.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>DATA</interface-vlan-name>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
            <interface-vlan-member>
              <interface-vlan-name>VOICE</interface-vlan-name>
              <interface-vlan-member-tagness>tagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""

        calls = []
        d = self._driver(xml)
        d.get_vlans = lambda: (calls.append(1), {30: {"name": "VOICE"}, 40: {"name": "DATA"}})[1]
        result = d.get_interfaces_vlans()
        assert len(calls) == 1, f"three named members must cost one get_vlans, got {len(calls)}"
        assert result["ge-0/0/10.0"] == {"mode": "trunk", "tagged": [30], "untagged": 40}

        calls.clear()
        d = self._driver(self.ACCESS_MEMBER + self.TRUNK_MEMBER)
        d.get_vlans = lambda: (calls.append(1), {})[1]
        d.get_interfaces_vlans()
        assert calls == [], "a walk with no named member must not fetch the table at all"

    def test_an_all_member_is_a_trunk_even_with_no_mode_element(self):
        """
        A member named ``all`` makes a trunk.

        ``vlan members all`` is only configurable under ``port-mode trunk``, so
        the member named ``all`` is a trunk-only construct. Reading the mode off
        membership has to count it, or the one shape that says trunk loudest is
        the one that still reports routed.
        """
        xml = """
        <interface>
          <interface-name>xe-0/0/40.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>all</interface-vlan-name>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""
        d = self._driver(xml)

        assert d.get_interfaces_vlans()["xe-0/0/40.0"]["mode"] == "trunk-all"

    def test_a_native_vlan_id_makes_a_single_untagged_member_a_trunk(self):
        """
        A native VLAN id makes a single untagged member a trunk.

        A native VLAN is only meaningful on a trunk, so it decides the one case
        inference otherwise gets wrong: a trunk whose only member is untagged.
        Without this the port is reported as access, which is not a missing
        association but an affirmatively wrong one.
        """
        xml = """
        <interface>
          <interface-name>xe-0/0/41.0</interface-name>
          <interface-native-vlan-id>99</interface-native-vlan-id>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>VL99</interface-vlan-name>
              <interface-vlan-member-tagid>99</interface-vlan-member-tagid>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""
        d = self._driver(xml)

        assert d.get_interfaces_vlans()["xe-0/0/41.0"] == {
            "mode": "trunk",
            "tagged": [],
            "untagged": 99,
        }

    def test_a_vid_outside_the_dot1q_range_is_not_membership(self):
        """
        A VID outside 1-4094 is not membership.

        A member carrying tagid 0 must not make the port look like it has an
        untagged VLAN. Counting it would infer access and then drop the VID,
        writing mode=access to NetBox with no VLAN to go with it, where the
        honest answer is that the port has no usable membership at all.
        """
        xml = """
        <interface>
          <interface-name>ge-0/0/44.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>bogus</interface-vlan-name>
              <interface-vlan-member-tagid>0</interface-vlan-member-tagid>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""
        d = self._driver(xml)

        assert d.get_interfaces_vlans()["ge-0/0/44.0"]["mode"] == "routed"

    def test_the_vlan_table_may_key_on_strings(self):
        """
        The VLAN table may key on strings.

        PyEZ tables key on the reply's ``vlan-tag`` text, so ``get_vlans()``
        hands back string keys on the switch_style tables this driver meets.
        """
        xml = """
        <interface>
          <interface-name>ge-0/0/9.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>VOICE</interface-vlan-name>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""
        d = self._driver(xml, vlans={"30": {"name": "VOICE"}, "40": {"name": "DATA"}})

        assert d.get_interfaces_vlans()["ge-0/0/9.0"]["untagged"] == 30

    def test_a_name_resolving_outside_the_dot1q_range_is_refused(self):
        """A table entry out of range names no VLAN that NetBox could hold."""
        xml = """
        <interface>
          <interface-name>ge-0/0/9.0</interface-name>
          <interface-vlan-member-list>
            <interface-vlan-member>
              <interface-vlan-name>ODD</interface-vlan-name>
              <interface-vlan-member-tagness>untagged</interface-vlan-member-tagness>
            </interface-vlan-member>
          </interface-vlan-member-list>
        </interface>"""
        d = self._driver(xml, vlans={9999: {"name": "ODD"}})

        assert d.get_interfaces_vlans()["ge-0/0/9.0"]["mode"] == "routed"
