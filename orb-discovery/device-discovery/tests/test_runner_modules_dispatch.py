"""
Test the runner's _collect_modules dispatch.

Calls ``PolicyRunner._collect_modules`` directly (rather than duplicating the
snippet) so the production logic is what's pinned. Covers:

- ``options.discover_modules == "off"`` → no driver call, no data mutation.
- Driver lacks ``get_modules`` → no-op.
- Happy path: callable, payload stored on data["modules"].
- The runner always invokes get_modules() regardless of chassis_members —
  the driver itself decides whether to emit a standalone or VC envelope,
  so the runner is agnostic.
- Driver raises → WARNING + data["modules"] = None, no propagation.
"""

import logging
from unittest.mock import MagicMock

import pytest

from custom_napalm.aruba_aoscx import AOSCXDriver
from custom_napalm.aruba_aoscx_ssh import AOSCXSSHDriver
from custom_napalm.cisco_fxos import FXOSDriver
from custom_napalm.eos import EOSDriver
from custom_napalm.huawei_vrp import VRPDriver
from custom_napalm.ios import IOSDriver
from custom_napalm.iosxr import IOSXRDriver
from custom_napalm.iosxr_netconf import IOSXRNETCONFDriver
from custom_napalm.junos import JunOSDriver
from custom_napalm.nokia_sros import SROSDriver
from custom_napalm.nokia_sros_ssh import SROSSSHDriver
from custom_napalm.nxos import NXOSDriver
from custom_napalm.nxos_ssh import NXOSSSHDriver
from custom_napalm.paloalto_panos import PANOSDriver
from custom_napalm.paloalto_panos_ssh import PANOSSHDriver
from device_discovery.policy.models import Config, Defaults, Options
from device_discovery.policy.runner import PolicyRunner


def _runner(discover_modules: str = "off") -> PolicyRunner:
    """Build a minimal PolicyRunner with discover_modules pre-configured."""
    runner = PolicyRunner()
    runner.name = "test-policy"
    runner.config = Config(
        defaults=Defaults(),
        options=Options(discover_modules=discover_modules),  # type: ignore[arg-type]
    )
    return runner


def _mock_device(with_modules: bool):
    """Build a mock NAPALM device, optionally exposing get_modules()."""
    base_attrs = ["get_facts", "get_interfaces", "get_interfaces_ip", "get_vlans"]
    if with_modules:
        dev = MagicMock(spec=[*base_attrs, "get_modules"])
        dev.get_modules = MagicMock(return_value={
            "members": {
                None: {
                    "bays": [
                        {
                            "name": "1",
                            "position": "1",
                            "module": {
                                "model": "C9400-LC-48U",
                                "serial": "FOC1",
                                "description": "",
                                "type": "linecard",
                                "sub_bays": [],
                            },
                        },
                    ],
                    "interfaces_by_bay": {"1": ["Te1/0/1"]},
                },
            },
        })
    else:
        dev = MagicMock(spec=base_attrs)
    return dev


def test_collect_modules_skips_when_off() -> None:
    """discover_modules='off' → no driver call, no data mutation."""
    runner = _runner("off")
    dev = _mock_device(with_modules=True)
    data: dict = {}
    runner._collect_modules(runner.config, dev, data, "host")
    assert "modules" not in data
    assert not dev.get_modules.called


def test_collect_modules_skips_when_driver_lacks_method() -> None:
    """When the driver does not expose get_modules, dispatch is a no-op."""
    runner = _runner("linecards")
    dev = _mock_device(with_modules=False)
    data: dict = {}
    runner._collect_modules(runner.config, dev, data, "host")
    assert "modules" not in data


def test_collect_modules_calls_when_linecards() -> None:
    """discover_modules='linecards' → driver call, payload stored."""
    runner = _runner("linecards")
    dev = _mock_device(with_modules=True)
    data: dict = {}
    runner._collect_modules(runner.config, dev, data, "host")
    assert "modules" in data
    member = data["modules"]["members"][None]
    assert member["bays"][0]["module"]["serial"] == "FOC1"


def test_collect_modules_runs_regardless_of_chassis_members():
    """
    With discover_modules != off, the runner calls get_modules() on every cycle.

    The driver decides whether to emit a standalone or per-member envelope
    based on its own chassis introspection; the runner is agnostic and no
    longer short-circuits on chassis_members. This pins the
    VC-of-modular-aware behavior where module discovery proceeds even on
    a validated multi-member chassis.
    """
    runner = _runner("linecards")
    dev = _mock_device(with_modules=True)
    data: dict = {
        "chassis_members": {
            "members": [
                {"id": 1, "serial": "FOC1"},
                {"id": 2, "serial": "FOC2"},
            ],
            "domain": None,
        },
    }
    runner._collect_modules(runner.config, dev, data, "host")
    assert "modules" in data
    assert dev.get_modules.called


def test_collect_modules_swallows_driver_exception(caplog) -> None:
    """Driver raising → WARNING logged, data['modules']=None, no propagation."""
    runner = _runner("linecards")
    dev = MagicMock()
    dev.get_modules = MagicMock(side_effect=RuntimeError("boom"))
    data: dict = {}
    with caplog.at_level(logging.WARNING, logger="device_discovery.policy.runner"):
        runner._collect_modules(runner.config, dev, data, "host")
    assert data["modules"] is None
    assert any(
        "Error getting modules" in r.message and "boom" in r.message
        for r in caplog.records
    )


# Confirms every driver class shipping a public get_modules() entry point is
# callable. Catches accidental rename / decorator drift without exercising the
# per-driver internals (those live in the per-driver test modules).
@pytest.mark.parametrize(
    "driver_cls",
    [
        pytest.param(IOSDriver, id="ios"),
        pytest.param(EOSDriver, id="eos"),
        pytest.param(IOSXRDriver, id="iosxr"),
        pytest.param(IOSXRNETCONFDriver, id="iosxr_netconf"),
        pytest.param(JunOSDriver, id="junos"),
        pytest.param(NXOSDriver, id="nxos"),
        pytest.param(NXOSSSHDriver, id="nxos_ssh"),
        pytest.param(FXOSDriver, id="fxos"),
        pytest.param(VRPDriver, id="vrp"),
        pytest.param(AOSCXDriver, id="aoscx"),
        pytest.param(AOSCXSSHDriver, id="aoscx_ssh"),
        pytest.param(SROSDriver, id="nokia_sros"),
        pytest.param(SROSSSHDriver, id="nokia_sros_ssh"),
        pytest.param(PANOSDriver, id="paloalto_panos"),
        pytest.param(PANOSSHDriver, id="paloalto_panos_ssh"),
    ],
)
def test_driver_exposes_get_modules(driver_cls) -> None:
    """Every driver MUST expose a callable get_modules method."""
    assert hasattr(driver_cls, "get_modules")
    assert callable(getattr(driver_cls, "get_modules"))
