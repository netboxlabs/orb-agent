"""Unit tests for custom_napalm.nokia_sros.SROSDriver."""

from pathlib import Path

from custom_napalm.nokia_sros import SROSDriver
from tests.custom_drivers.base_test import BaseDriverTest
from tests.custom_drivers.mock_device import FakeNetconfConn


class TestSROSDriver(BaseDriverTest):
    """Unit tests for SROSDriver using file-based NETCONF XML mocks."""

    driver_cls = SROSDriver
    fake_device_cls = FakeNetconfConn
    mock_data_root = Path(__file__).parent / "mock_data"

    def _build_driver(self, mock_dir: Path) -> SROSDriver:
        """Instantiate SROSDriver with a fake NETCONF connection (no real device needed)."""
        driver = object.__new__(SROSDriver)
        driver.hostname = "test-host"
        driver.username = "test-user"
        driver.password = "test-pass"
        driver.timeout = 60
        driver.R19 = False
        driver.conn = FakeNetconfConn(mock_dir)
        return driver


def test_driver_exposes_get_modules():
    """Driver MUST expose a callable get_modules method."""
    from custom_napalm.nokia_sros import SROSDriver
    assert hasattr(SROSDriver, "get_modules")
    assert callable(SROSDriver.get_modules)


# ---------------------------------------------------------------------------
# Transceiver attachment — port-id form coverage
# ---------------------------------------------------------------------------


def _build_mda_bay_map():
    """Construct a single MDA bay map for transceiver-attachment unit tests."""
    from custom_napalm._modules import ModuleBay, ModuleEntry
    parent = ModuleBay(
        name="1", position="1",
        module=ModuleEntry(model="IOM", serial="SN-IOM-1", type="linecard"),
    )
    mda = ModuleBay(
        name="1/1", position="1/1",
        module=ModuleEntry(model="MDA", serial="SN-MDA-1", type="linecard"),
    )
    parent.module.sub_bays.append(mda)
    return {"1/1": mda}, parent


def test_attach_transceiver_classic_3_segment_port_id():
    """Classic slot/mda/port (1/1/1) emits card-slot, MDA-path, and per-port keys."""
    from custom_napalm.nokia_sros import _nokia_sros_attach_transceiver_sub_bays
    mda_map, _ = _build_mda_bay_map()
    rows = [{"port_id": "1/1/1", "model": "SFP-10G-LR", "sn": "OPT1"}]
    ifaces = _nokia_sros_attach_transceiver_sub_bays(rows, mda_map, [], False)
    assert ifaces == {"1": ["1/1/1"], "1/1": ["1/1/1"], "1/1/1": ["1/1/1"]}
    assert mda_map["1/1"].module.sub_bays[0].name == "1/1/1"


def test_attach_transceiver_fp4_c_cage_port_id():
    """FP4 connector-cage (1/1/c2/1) emits the same three keys as classic form."""
    from custom_napalm.nokia_sros import _nokia_sros_attach_transceiver_sub_bays
    mda_map, _ = _build_mda_bay_map()
    rows = [{"port_id": "1/1/c2/1", "model": "QSFP28-SR4", "sn": "OPT2"}]
    ifaces = _nokia_sros_attach_transceiver_sub_bays(rows, mda_map, [], False)
    assert ifaces == {"1": ["1/1/c2/1"], "1/1": ["1/1/c2/1"], "1/1/c2/1": ["1/1/c2/1"]}
    assert mda_map["1/1"].module.sub_bays[0].name == "1/1/c2/1"


def test_attach_transceiver_card_slot_key_aggregates_across_mdas():
    """Multiple transceivers under the same card aggregate into one card-slot key."""
    from custom_napalm._modules import ModuleBay, ModuleEntry
    from custom_napalm.nokia_sros import _nokia_sros_attach_transceiver_sub_bays
    parent = ModuleBay(name="1", position="1",
                       module=ModuleEntry(model="IOM", serial="SN-1", type="linecard"))
    mda1 = ModuleBay(name="1/1", position="1/1",
                     module=ModuleEntry(model="MDA", serial="SN-MDA1", type="linecard"))
    mda2 = ModuleBay(name="1/2", position="1/2",
                     module=ModuleEntry(model="MDA", serial="SN-MDA2", type="linecard"))
    parent.module.sub_bays.extend([mda1, mda2])
    mda_map = {"1/1": mda1, "1/2": mda2}
    rows = [
        {"port_id": "1/1/1", "model": "SFP-10G-LR", "sn": "OPT-A"},
        {"port_id": "1/2/1", "model": "QSFP-100G-SR4", "sn": "OPT-B"},
    ]
    ifaces = _nokia_sros_attach_transceiver_sub_bays(rows, mda_map, [], False)
    # Card-slot key "1" aggregates ports from both MDAs — critical for
    # linecards-mode routing which never descends into sub-bays.
    assert ifaces["1"] == ["1/1/1", "1/2/1"]
    assert ifaces["1/1"] == ["1/1/1"]
    assert ifaces["1/2"] == ["1/2/1"]


def test_attach_transceiver_unknown_mda_path_promotes_orphan_bay():
    """A port-id whose slot/mda doesn't match any known MDA is promoted to a device-rooted bay."""
    from custom_napalm.nokia_sros import _nokia_sros_attach_transceiver_sub_bays
    mda_map, _ = _build_mda_bay_map()
    bays = []
    rows = [{"port_id": "9/9/1", "model": "SFP-X", "sn": "OPT3"}]
    ifaces = _nokia_sros_attach_transceiver_sub_bays(rows, mda_map, bays, False)
    assert ifaces == {"9/9/1": ["9/9/1"]}
    assert mda_map["1/1"].module.sub_bays == []
    assert len(bays) == 1
    assert bays[0].name == "9/9/1"
    assert bays[0].position == "9/9/1"
    assert bays[0].module.model == "SFP-X"
    assert bays[0].module.serial == "OPT3"
    assert bays[0].module.type == "transceiver"


def test_attach_transceiver_unknown_mda_path_without_optic_is_noop():
    """An unmatched MDA path with no model/serial promotes nothing — no data to promote."""
    from custom_napalm.nokia_sros import _nokia_sros_attach_transceiver_sub_bays
    mda_map, _ = _build_mda_bay_map()
    bays = []
    rows = [{"port_id": "9/9/1", "model": "", "sn": ""}]
    ifaces = _nokia_sros_attach_transceiver_sub_bays(rows, mda_map, bays, False)
    assert ifaces == {}
    assert bays == []
    assert mda_map["1/1"].module.sub_bays == []


def test_attach_transceiver_declines_promotion_on_modular_chassis_with_incomplete_mda():
    """
    Card bays exist but the MDA never reached the bay map — decline promotion.

    A modular chassis whose MDA row was incomplete must not invent a
    device-rooted bay for the optic beneath it.
    """
    from custom_napalm._modules import ModuleBay, ModuleEntry
    from custom_napalm.nokia_sros import _nokia_sros_attach_transceiver_sub_bays
    card_bay = ModuleBay(
        name="1", position="1",
        module=ModuleEntry(model="IOM", serial="SN-IOM-1", type="linecard"),
    )
    bays = [card_bay]
    rows = [{"port_id": "1/1/1", "model": "SFP-10G-LR", "sn": "OPT1"}]
    # mda_bays_by_path is empty: the "1/1" MDA row was incomplete (missing
    # PID/serial, or its parent card never emitted) and never made it in.
    ifaces = _nokia_sros_attach_transceiver_sub_bays(rows, {}, bays, True)
    assert ifaces == {}
    assert bays == [card_bay]
    assert card_bay.module.sub_bays == []


def test_attach_transceiver_snapshot_survives_self_mutation_across_multiple_orphans():
    """
    Promoting the FIRST orphan optic must not cause the SECOND to be declined.

    On a genuinely fixed platform (no card bays at all), ``bays`` starts
    empty and is the same list promotion appends to. A
    guard that reads ``bays`` live inside the loop (instead of a snapshot
    taken once before it starts) would see a non-empty list after the
    first append and refuse every optic that follows — this test pins the
    snapshot behavior that avoids that self-mutation trap.
    """
    from custom_napalm.nokia_sros import _nokia_sros_attach_transceiver_sub_bays
    bays = []
    rows = [
        {"port_id": "1/1/c1", "model": "SFP-10G-LR", "sn": "OPT-A"},
        {"port_id": "1/1/c2", "model": "SFP-10G-LR", "sn": "OPT-B"},
    ]
    ifaces = _nokia_sros_attach_transceiver_sub_bays(rows, {}, bays, False)
    assert len(bays) == 2
    assert {b.name for b in bays} == {"1/1/c1", "1/1/c2"}
    assert ifaces == {"1/1/c1": ["1/1/c1"], "1/1/c2": ["1/1/c2"]}


def test_attach_transceiver_routes_optic_less_port_to_parent_bays():
    """Copper/empty-cage ports still get parent routing; no transceiver sub-bay."""
    from custom_napalm.nokia_sros import _nokia_sros_attach_transceiver_sub_bays
    mda_map, _ = _build_mda_bay_map()
    rows = [
        {"port_id": "1/1/1", "model": "SFP-10G-LR", "sn": "OPT-A"},  # has optic
        {"port_id": "1/1/2", "model": "", "sn": ""},                  # copper / empty cage
    ]
    ifaces = _nokia_sros_attach_transceiver_sub_bays(rows, mda_map, [], False)
    # Both ports route to card-slot + mda-path; only the optic'd port has
    # a per-port key AND a transceiver sub-bay.
    assert ifaces == {
        "1": ["1/1/1", "1/1/2"],
        "1/1": ["1/1/1", "1/1/2"],
        "1/1/1": ["1/1/1"],
    }
    sub_bays = mda_map["1/1"].module.sub_bays
    assert len(sub_bays) == 1
    assert sub_bays[0].name == "1/1/1"
    assert sub_bays[0].module.type == "transceiver"


def test_rows_from_state_xml_includes_sfm_subtree():
    """SFMs live in state/sfm — must be emitted as top-level bays with SFM-prefixed names."""
    from lxml import etree

    from custom_napalm.nokia_sros import _nokia_sros_rows_from_state_xml
    xml = """\
<state xmlns="urn:nokia.com:sros:ns:yang:sr:state">
  <sfm>
    <sfm-slot>1</sfm-slot>
    <equipped-type>sfm5-12</equipped-type>
    <hardware-data>
      <part-number>3HE08648AA</part-number>
      <serial-number>NS-SFM1-001</serial-number>
    </hardware-data>
  </sfm>
  <sfm>
    <sfm-slot>2</sfm-slot>
    <equipped-type>sfm5-12</equipped-type>
    <hardware-data>
      <part-number>3HE08648AA</part-number>
      <serial-number>NS-SFM2-001</serial-number>
    </hardware-data>
  </sfm>
</state>
"""
    root = etree.fromstring(xml.encode("utf-8"))
    rows = _nokia_sros_rows_from_state_xml(root)
    sfm_rows = [r for r in rows if r["slot"].startswith("SFM ")]
    assert sfm_rows == [
        {"kind": "card", "slot": "SFM 1", "parent_slot": None, "mda_slot": None,
         "equipped_type": "sfm5-12", "pid": "3HE08648AA", "sn": "NS-SFM1-001"},
        {"kind": "card", "slot": "SFM 2", "parent_slot": None, "mda_slot": None,
         "equipped_type": "sfm5-12", "pid": "3HE08648AA", "sn": "NS-SFM2-001"},
    ]


def test_chassis_fingerprint_extracts_part_number_when_present():
    """
    A present chassis/hardware-data/part-number must be returned, not read as absent.

    Regression pin for the failure mode called out in the promotion gate:
    getting this backwards makes every SR-1 (which reports zero cards by
    design) decline every optic instead of promoting them.
    """
    from lxml import etree

    from custom_napalm.nokia_sros import _nokia_sros_chassis_fingerprint
    xml = """\
<state xmlns="urn:nokia.com:sros:ns:yang:sr:state">
  <chassis>
    <hardware-data>
      <part-number>3HE-SR1-AA</part-number>
      <serial-number>NS-FP-001</serial-number>
    </hardware-data>
  </chassis>
</state>
"""
    root = etree.fromstring(xml.encode("utf-8"))
    assert _nokia_sros_chassis_fingerprint(root) == "3HE-SR1-AA"


def test_chassis_fingerprint_absent_returns_empty():
    """No chassis/hardware-data/part-number element at all returns ""."""
    from lxml import etree

    from custom_napalm.nokia_sros import _nokia_sros_chassis_fingerprint
    xml = """\
<state xmlns="urn:nokia.com:sros:ns:yang:sr:state">
  <chassis>
    <hardware-data>
      <serial-number>NS-FP-002</serial-number>
    </hardware-data>
  </chassis>
</state>
"""
    root = etree.fromstring(xml.encode("utf-8"))
    assert _nokia_sros_chassis_fingerprint(root) == ""


def test_chassis_fingerprint_no_chassis_element_returns_empty():
    """No <chassis> element at all (truncated state tree) returns ""."""
    from lxml import etree

    from custom_napalm.nokia_sros import _nokia_sros_chassis_fingerprint
    xml = '<state xmlns="urn:nokia.com:sros:ns:yang:sr:state"><port><port-id>1/1/1</port-id></port></state>'
    root = etree.fromstring(xml.encode("utf-8"))
    assert _nokia_sros_chassis_fingerprint(root) == ""


def test_classify_xcm_as_linecard():
    """7950 XRS forwarding cards (XCM) classify as linecard, not 'other'."""
    from custom_napalm.nokia_sros import classify_module_type_nokia_sros
    assert classify_module_type_nokia_sros("xcm-x20") == "linecard"
    assert classify_module_type_nokia_sros("XCM-X20") == "linecard"
    assert classify_module_type_nokia_sros("xcm-4q-xma") == "linecard"


def test_classify_known_prefixes():
    """Regression coverage for the full classifier prefix table."""
    from custom_napalm.nokia_sros import classify_module_type_nokia_sros
    assert classify_module_type_nokia_sros("iom4-e") == "linecard"
    assert classify_module_type_nokia_sros("imm36-100g-qsfp28") == "linecard"
    assert classify_module_type_nokia_sros("cpm5") == "supervisor"
    assert classify_module_type_nokia_sros("sfm-7") == "linecard"
    assert classify_module_type_nokia_sros("psu-ac") == "other"
