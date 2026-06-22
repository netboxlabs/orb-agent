"""Sanity tests for FakeJsonRpcDevice and FakePyEZDevice mock helpers."""

import json
from pathlib import Path

from tests.custom_drivers.mock_device import FakeJsonRpcDevice, FakePyEZDevice

# ----- FakeJsonRpcDevice ----------------------------------------------


def test_fake_jsonrpc_run_commands_loads_json(tmp_path: Path):
    """JSON file is loaded and returned as a dict in the result list."""
    (tmp_path / "show_interfaces_switchport.json").write_text(
        json.dumps({"switchports": {"Et1": {"switchportInfo": {"mode": "access"}}}})
    )
    fake = FakeJsonRpcDevice(tmp_path)
    out = fake.run_commands(["show interfaces switchport"], encoding="json")
    assert out == [{"switchports": {"Et1": {"switchportInfo": {"mode": "access"}}}}]


def test_fake_jsonrpc_run_commands_missing_returns_empty_dict(tmp_path: Path):
    """Missing fixture silently returns an empty dict in the result list."""
    fake = FakeJsonRpcDevice(tmp_path)
    out = fake.run_commands(["show foo"], encoding="json")
    assert out == [{}]


def test_fake_jsonrpc_show_loads_json(tmp_path: Path):
    """show() loads the matching JSON fixture and returns a dict."""
    (tmp_path / "show_interface_switchport.json").write_text(
        json.dumps({"TABLE_interface": {"ROW_interface": []}})
    )
    fake = FakeJsonRpcDevice(tmp_path)
    out = fake.show("show interface switchport", raw_text=False)
    assert out == {"TABLE_interface": {"ROW_interface": []}}


def test_fake_jsonrpc_show_missing_returns_empty(tmp_path: Path):
    """show() returns an empty dict when the fixture file is absent."""
    fake = FakeJsonRpcDevice(tmp_path)
    out = fake.show("show foo bar", raw_text=False)
    assert out == {}


# ----- FakePyEZDevice -------------------------------------------------


def test_fake_pyez_rpc_call_loads_xml(tmp_path: Path):
    """rpc.<name>() returns an lxml Element parsed from the matching XML fixture."""
    (tmp_path / "get-ethernet-switching-interface-information.xml").write_text(
        "<ethernet-switching-interface-information><interface/></ethernet-switching-interface-information>"
    )
    fake = FakePyEZDevice(tmp_path)
    out = fake.rpc.get_ethernet_switching_interface_information()
    # PyEZ returns lxml.etree._Element; we expose .tag / .findall like real lxml
    assert out.tag == "ethernet-switching-interface-information"


def test_fake_pyez_rpc_call_missing_returns_empty(tmp_path: Path):
    """rpc.<name>() returns an empty <data/> element when the fixture is absent."""
    fake = FakePyEZDevice(tmp_path)
    out = fake.rpc.get_something_unmocked()
    # Empty <data/> element when fixture absent
    assert out is not None
    assert len(out) == 0
