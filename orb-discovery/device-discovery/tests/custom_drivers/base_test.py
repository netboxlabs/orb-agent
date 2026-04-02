"""
Base test class for custom NAPALM drivers.

Usage
-----
For each new driver, create a subclass and set three class attributes::

    class TestMyDriver(BaseDriverTest):
        driver_cls = MyDriver
        fake_device_cls = FakeCLIDevice   # or FakeXmlDevice
        mock_data_root = Path(__file__).parent / "mock_data"

Then add a conftest.py in the same directory that calls
``parametrize_scenarios`` so pytest discovers scenario folders from disk::

    # conftest.py
    from tests.custom_drivers.base_test import parametrize_scenarios

    def pytest_generate_tests(metafunc):
        parametrize_scenarios(metafunc, Path(__file__).parent / "mock_data")

Adding a new scenario for an existing test is then a matter of creating a
folder under ``mock_data/test_get_facts/<new_scenario>/`` with the
appropriate mock files.  No Python changes required.
"""

import json
from pathlib import Path
from typing import Any


def parametrize_scenarios(metafunc, mock_data_root: Path) -> None:
    """
    Parametrize ``scenario`` fixture from sub-folders of each test method's mock directory.

    For ``test_get_facts``, looks for folders under ``mock_data_root/test_get_facts/``.
    Falls back to ``["normal"]`` if the directory doesn't exist.
    """
    if "scenario" not in metafunc.fixturenames:
        return
    method = metafunc.function.__name__
    scenario_dir = mock_data_root / method
    if scenario_dir.is_dir():
        scenarios = [p.name for p in sorted(scenario_dir.iterdir()) if p.is_dir()]
    else:
        scenarios = ["normal"]
    metafunc.parametrize("scenario", scenarios)


def _load_expected(mock_dir: Path) -> dict | None:
    path = mock_dir / "expected_result.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return None


class BaseDriverTest:
    """
    Tests for the NAPALM getter methods used by device-discovery.

    Validates:
    1. Return type is a dict.
    2. All required keys are present (NAPALM contract).
    3. Result matches ``expected_result.json`` when the file exists.
    """

    driver_cls: type
    fake_device_cls: type
    mock_data_root: Path

    # ------------------------------------------------------------------
    # Fixture helpers
    # ------------------------------------------------------------------

    def _build_driver(self, mock_dir: Path) -> Any:
        """Instantiate the driver, bypassing open() and injecting a fake device."""
        driver = object.__new__(self.driver_cls)
        # Minimal attribute set common to all NAPALM drivers
        driver.hostname = "test-host"
        driver.username = "test-user"
        driver.password = "test-pass"
        driver.timeout = 60
        driver.device = self.fake_device_cls(mock_dir)
        return driver

    def _mock_dir(self, method: str, scenario: str) -> Path:
        return self.mock_data_root / method / scenario

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_get_facts(self, scenario: str) -> None:
        """Verify get_facts returns a valid dict with required keys."""
        mock_dir = self._mock_dir("test_get_facts", scenario)
        driver = self._build_driver(mock_dir)
        result = driver.get_facts()

        assert isinstance(result, dict), "get_facts must return a dict"
        required = {"hostname", "vendor", "model", "os_version", "serial_number", "uptime", "interface_list", "fqdn"}
        assert required <= result.keys(), f"Missing keys: {required - result.keys()}"
        assert isinstance(result["interface_list"], list)
        assert isinstance(result["uptime"], (int, float))

        expected = _load_expected(mock_dir)
        if expected is not None:
            assert result == expected

    def test_get_interfaces(self, scenario: str) -> None:
        """Verify get_interfaces returns a valid dict with required per-interface keys."""
        mock_dir = self._mock_dir("test_get_interfaces", scenario)
        driver = self._build_driver(mock_dir)
        result = driver.get_interfaces()

        assert isinstance(result, dict), "get_interfaces must return a dict"
        required_keys = {"is_up", "is_enabled", "description", "last_flapped", "mtu", "speed", "mac_address"}
        for intf, data in result.items():
            assert required_keys <= data.keys(), f"{intf}: missing {required_keys - data.keys()}"
            assert isinstance(data["is_up"], bool)
            assert isinstance(data["is_enabled"], bool)

        expected = _load_expected(mock_dir)
        if expected is not None:
            assert result == expected

    def test_get_interfaces_ip(self, scenario: str) -> None:
        """Verify get_interfaces_ip returns valid address families with prefix lengths."""
        mock_dir = self._mock_dir("test_get_interfaces_ip", scenario)
        driver = self._build_driver(mock_dir)
        result = driver.get_interfaces_ip()

        assert isinstance(result, dict), "get_interfaces_ip must return a dict"
        for intf, families in result.items():
            for family, addrs in families.items():
                assert family in ("ipv4", "ipv6"), f"Unknown address family: {family}"
                for addr, info in addrs.items():
                    assert "prefix_length" in info, f"{intf}/{addr}: missing prefix_length"
                    assert isinstance(info["prefix_length"], int)

        expected = _load_expected(mock_dir)
        if expected is not None:
            assert result == expected

    def test_get_config(self, scenario: str) -> None:
        """Verify get_config returns a dict with running/candidate/startup keys."""
        mock_dir = self._mock_dir("test_get_config", scenario)
        driver = self._build_driver(mock_dir)
        result = driver.get_config()

        assert isinstance(result, dict), "get_config must return a dict"
        assert {"running", "candidate", "startup"} <= result.keys()

        expected = _load_expected(mock_dir)
        if expected is not None:
            assert result == expected

    def test_get_vlans(self, scenario: str) -> None:
        """Verify get_vlans returns a valid dict with name and interfaces per VLAN."""
        mock_dir = self._mock_dir("test_get_vlans", scenario)
        driver = self._build_driver(mock_dir)
        result = driver.get_vlans()

        assert isinstance(result, dict), "get_vlans must return a dict"
        for vlan_id, data in result.items():
            assert "name" in data, f"VLAN {vlan_id}: missing 'name'"
            assert "interfaces" in data, f"VLAN {vlan_id}: missing 'interfaces'"
            assert isinstance(data["interfaces"], list)

        expected = _load_expected(mock_dir)
        if expected is not None:
            assert result == expected
