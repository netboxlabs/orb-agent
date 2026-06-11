"""
Test the runner's _collect_network_instances dispatch.

Calls ``PolicyRunner._collect_network_instances`` directly (rather than
duplicating the snippet) so the production logic is what's pinned. Covers:

- ``options.discover_vrfs == False`` → no driver call, no data mutation.
- Driver lacks ``get_network_instances`` → no-op.
- Happy path: callable, payload stored on data["network_instances"].
- Driver raises (incl. NotImplementedError from the NAPALM base class) →
  WARNING, no key set, no propagation.
"""

import logging
from unittest.mock import MagicMock

import pytest
from napalm.base.base import NetworkDriver

from custom_napalm.cumulus_linux import CumulusDriver
from custom_napalm.dell_sonic import SONiCDriver
from custom_napalm.eos import EOSDriver
from custom_napalm.hp_comware import ComwareDriver
from custom_napalm.huawei_vrp import VRPDriver
from custom_napalm.ios import IOSDriver
from custom_napalm.iosxr import IOSXRDriver
from custom_napalm.iosxr_netconf import IOSXRNETCONFDriver
from custom_napalm.junos import JunOSDriver
from custom_napalm.nokia_srl import SRLDriver
from custom_napalm.nokia_sros import SROSDriver
from custom_napalm.nxos import NXOSDriver
from custom_napalm.nxos_ssh import NXOSSSHDriver
from device_discovery.policy.models import Config, Defaults, Options
from device_discovery.policy.runner import PolicyRunner

_INSTANCES = {
    "MGMT": {
        "name": "MGMT",
        "type": "L3VRF",
        "state": {"route_distinguisher": "123:456"},
        "interfaces": {"interface": {"Management1": {}}},
    },
}


def _runner(discover_vrfs: bool = False) -> PolicyRunner:
    """Build a minimal PolicyRunner with discover_vrfs pre-configured."""
    runner = PolicyRunner()
    runner.name = "test-policy"
    runner.config = Config(
        defaults=Defaults(),
        options=Options(discover_vrfs=discover_vrfs),
    )
    return runner


def _mock_device(with_network_instances: bool):
    """Build a mock NAPALM device, optionally exposing get_network_instances()."""
    base_attrs = ["get_facts", "get_interfaces", "get_interfaces_ip", "get_vlans"]
    if with_network_instances:
        dev = MagicMock(spec=[*base_attrs, "get_network_instances"])
        dev.get_network_instances = MagicMock(return_value=_INSTANCES)
    else:
        dev = MagicMock(spec=base_attrs)
    return dev


def test_collect_network_instances_skips_when_off() -> None:
    """discover_vrfs=False → no driver call, no data mutation."""
    runner = _runner(discover_vrfs=False)
    dev = _mock_device(with_network_instances=True)
    data: dict = {}
    runner._collect_network_instances(runner.config, dev, data, "host")
    assert "network_instances" not in data
    assert not dev.get_network_instances.called


def test_collect_network_instances_skips_when_driver_lacks_method() -> None:
    """When the driver does not expose get_network_instances, dispatch is a no-op."""
    runner = _runner(discover_vrfs=True)
    dev = _mock_device(with_network_instances=False)
    data: dict = {}
    runner._collect_network_instances(runner.config, dev, data, "host")
    assert "network_instances" not in data


def test_collect_network_instances_calls_when_enabled() -> None:
    """discover_vrfs=True → driver call, payload stored."""
    runner = _runner(discover_vrfs=True)
    dev = _mock_device(with_network_instances=True)
    data: dict = {}
    runner._collect_network_instances(runner.config, dev, data, "host")
    assert data["network_instances"] == _INSTANCES


def test_collect_network_instances_swallows_driver_exception(caplog) -> None:
    """Driver raising → WARNING logged, no key set, no propagation."""
    runner = _runner(discover_vrfs=True)
    dev = MagicMock()
    dev.get_network_instances = MagicMock(side_effect=RuntimeError("boom"))
    data: dict = {}
    with caplog.at_level(logging.WARNING, logger="device_discovery.policy.runner"):
        runner._collect_network_instances(runner.config, dev, data, "host")
    assert "network_instances" not in data
    assert any(
        "Error getting network instances" in r.message and "boom" in r.message
        for r in caplog.records
    )


def test_collect_network_instances_swallows_not_implemented(caplog) -> None:
    """NAPALM base-class NotImplementedError → WARNING, discovery continues."""
    runner = _runner(discover_vrfs=True)
    dev = MagicMock()
    dev.get_network_instances = MagicMock(side_effect=NotImplementedError())
    data: dict = {}
    with caplog.at_level(logging.WARNING, logger="device_discovery.policy.runner"):
        runner._collect_network_instances(runner.config, dev, data, "host")
    assert "network_instances" not in data
    assert any("Error getting network instances" in r.message for r in caplog.records)


# Pins the support matrix VRF discovery relies on: these drivers carry a real
# get_network_instances() and it lives in the expected package — inherited
# from upstream NAPALM (ios/eos/junos/nxos/nxos_ssh) or implemented in
# custom_napalm (iosxr/iosxr_netconf/nokia_sros/nokia_srl). Asserting the
# owning module (not just "is not the base-class stub") also catches the
# case where a wrapper driver accidentally shadows the upstream getter,
# which a bare identity check against NetworkDriver would miss.
@pytest.mark.parametrize(
    ("driver_cls", "expected_module_prefix"),
    [
        pytest.param(IOSDriver, "napalm.", id="ios"),
        pytest.param(EOSDriver, "napalm.", id="eos"),
        pytest.param(JunOSDriver, "napalm.", id="junos"),
        pytest.param(NXOSDriver, "napalm.", id="nxos"),
        pytest.param(NXOSSSHDriver, "napalm.", id="nxos_ssh"),
        pytest.param(IOSXRDriver, "custom_napalm.", id="iosxr"),
        pytest.param(IOSXRNETCONFDriver, "custom_napalm.", id="iosxr_netconf"),
        pytest.param(SROSDriver, "custom_napalm.", id="nokia_sros"),
        pytest.param(SRLDriver, "custom_napalm.", id="nokia_srl"),
        pytest.param(VRPDriver, "custom_napalm.", id="huawei_vrp"),
        pytest.param(ComwareDriver, "custom_napalm.", id="hp_comware"),
        pytest.param(CumulusDriver, "custom_napalm.", id="cumulus_linux"),
        pytest.param(SONiCDriver, "custom_napalm.", id="dell_sonic"),
    ],
)
def test_driver_implements_get_network_instances(
    driver_cls, expected_module_prefix
) -> None:
    """get_network_instances is owned by the expected package, not a stub."""
    owner = next(
        klass
        for klass in driver_cls.__mro__
        if "get_network_instances" in klass.__dict__
    )
    assert (
        owner is not NetworkDriver
    ), f"{driver_cls.__name__} resolves to the NAPALM base-class stub"
    assert owner.__module__.startswith(expected_module_prefix), (
        f"{driver_cls.__name__}.get_network_instances is owned by "
        f"{owner.__module__}, expected {expected_module_prefix}*"
    )
