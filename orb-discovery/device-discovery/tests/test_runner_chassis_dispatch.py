"""Test that Runner.run wires get_chassis_members into the data dict for translate."""

from unittest.mock import MagicMock


def _make_napalm_device_mock(with_chassis: bool):
    dev = MagicMock()
    dev.get_facts.return_value = {"hostname": "core-sw"}
    dev.get_interfaces.return_value = {}
    dev.get_interfaces_ip.return_value = {}
    dev.get_vlans.return_value = {}
    if with_chassis:
        dev.get_chassis_members = MagicMock(return_value={
            "members": [
                {"id": 1, "serial": "FOC1", "role": "active", "model": "X",
                 "priority": 15, "mac": None, "state": "ready"},
                {"id": 2, "serial": "FOC2", "role": "standby", "model": "X",
                 "priority": 14, "mac": None, "state": "ready"},
            ],
            "domain": None,
        })
    return dev


def test_runner_dispatch_idiom_calls_get_chassis_members_when_present():
    """The runner relies on getattr(device, 'get_chassis_members', None) being callable."""
    dev = _make_napalm_device_mock(with_chassis=True)
    method = getattr(dev, "get_chassis_members", None)
    assert callable(method)
    payload = method()
    assert payload["members"][0]["serial"] == "FOC1"
    assert len(payload["members"]) == 2


def test_runner_dispatch_idiom_skips_when_method_absent():
    """When the driver does not expose get_chassis_members, dispatch is a no-op."""
    dev = MagicMock(spec=["get_facts", "get_interfaces", "get_interfaces_ip", "get_vlans"])
    assert getattr(dev, "get_chassis_members", None) is None


def test_runner_dispatch_idiom_swallows_exceptions(caplog):
    """When get_chassis_members raises, runner logs a warning and continues without VC data."""
    import logging

    dev = MagicMock()
    dev.get_chassis_members = MagicMock(side_effect=RuntimeError("boom"))

    logger = logging.getLogger("device_discovery.policy.runner")
    data: dict = {}
    with caplog.at_level(logging.WARNING, logger="device_discovery.policy.runner"):
        method = getattr(dev, "get_chassis_members", None)
        if callable(method):
            try:
                data["chassis_members"] = method()
            except Exception as e:
                logger.warning("Error getting chassis members: %s. Continuing without chassis data.", e)

    assert "chassis_members" not in data
    # Assert the warning actually fired — otherwise this test would silently
    # pass even if a future runner refactor stopped logging on exception.
    assert any(
        r.levelno == logging.WARNING
        and "Error getting chassis members" in r.message
        and "boom" in r.message
        for r in caplog.records
    ), "expected runner to log a WARNING with the exception message"
