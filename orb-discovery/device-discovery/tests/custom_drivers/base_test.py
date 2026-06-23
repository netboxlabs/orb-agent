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

import pytest


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


def _load_expected(mock_dir: Path) -> Any:
    """
    Load expected_result.json and normalize string-keyed "null" back to None.

    JSON cannot encode Python's None as a dict key. Module-discovery fixtures
    use the literal string "null" for the standalone member bucket; this
    loader rewrites that key back to None so deep equality against the
    production result holds.
    """
    path = mock_dir / "expected_result.json"
    if not path.exists():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    return _normalize_null_member_keys(raw)


def _normalize_null_member_keys(value: Any, *, inside_members: bool = False) -> Any:
    """
    Recursively rewrite a JSON-loaded dict tree so member-id keys match Python types.

    JSON cannot encode Python's ``None`` or ``int`` as dict keys. Inside the
    ``members`` sub-tree of a module-discovery payload, key ``"null"`` is
    rewritten to ``None`` and any digit-string key is rewritten to ``int``.
    Outside ``members`` the keys are left as-is (the rest of the payload
    naturally uses string keys).
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if inside_members:
                if k == "null":
                    new_key: Any = None
                elif isinstance(k, str) and k.isdigit():
                    new_key = int(k)
                else:
                    new_key = k
            else:
                new_key = k
            # Recurse — children of a 'members' dict are themselves NOT in
            # the members-key space, so reset the flag. Conversely, when
            # we encounter a key named 'members' at any level, the next
            # level IS the per-member buckets.
            child_inside = (k == "members")
            out[new_key] = _normalize_null_member_keys(v, inside_members=child_inside)
        return out
    if isinstance(value, list):
        return [_normalize_null_member_keys(item) for item in value]
    return value


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

    def test_get_config_sanitized(self, scenario: str) -> None:
        """Verify get_config(sanitized=True) redacts sensitive fields."""
        mock_dir = self._mock_dir("test_get_config_sanitized", scenario)
        driver = self._build_driver(mock_dir)
        result = driver.get_config(sanitized=True)

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

    def test_get_chassis_members(self, scenario: str) -> None:
        """Verify get_chassis_members payload shape (driver-optional)."""
        mock_dir = self._mock_dir("test_get_chassis_members", scenario)
        driver = self._build_driver(mock_dir)
        if not hasattr(driver, "get_chassis_members"):
            pytest.skip(f"{self.driver_cls.__name__} does not expose get_chassis_members")

        result = driver.get_chassis_members()
        assert result is None or isinstance(result, dict), (
            "get_chassis_members must return a dict or None"
        )
        if isinstance(result, dict):
            assert "members" in result and isinstance(result["members"], list)
            for m in result["members"]:
                assert isinstance(m, dict)
                # bool is a subclass of int in Python — exclude explicitly so True/False
                # are not accepted as member ids (matches translate-side validation).
                mid = m.get("id")
                assert isinstance(mid, int) and not isinstance(mid, bool), (
                    f"member id must be a real int, got {mid!r}"
                )
                assert isinstance(m.get("serial"), str) and m["serial"], (
                    f"member without serial leaked through: {m}"
                )
                assert m.get("role") in ("active", "standby", "member")

        # Use the file's existence (not its parsed value) as the signal —
        # ``null`` is a valid expected return for standalone scenarios.
        expected_path = mock_dir / "expected_result.json"
        if expected_path.exists():
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
            assert result == expected

    def test_get_network_instances(self, scenario: str) -> None:
        """Verify get_network_instances payload shape (driver-optional)."""
        from napalm.base.base import NetworkDriver

        if self.driver_cls.get_network_instances is NetworkDriver.get_network_instances:
            pytest.skip(
                f"{self.driver_cls.__name__} does not implement get_network_instances"
            )
        mock_dir = self._mock_dir("test_get_network_instances", scenario)
        if not mock_dir.is_dir():
            # Covers drivers that inherit the getter from upstream NAPALM
            # (ios/eos/junos/nxos) — those are exercised by upstream, not here.
            pytest.skip("no get_network_instances fixtures for this driver")
        driver = self._build_driver(mock_dir)
        result = driver.get_network_instances()

        assert isinstance(result, dict), "get_network_instances must return a dict"
        for ni_name, ni in result.items():
            assert isinstance(ni, dict), f"{ni_name}: instance must be a dict"
            assert ni.get("name") == ni_name, f"{ni_name}: name/key mismatch"
            assert isinstance(ni.get("type"), str), f"{ni_name}: missing type"
            state = ni.get("state")
            assert isinstance(state, dict) and "route_distinguisher" in state, (
                f"{ni_name}: missing state.route_distinguisher"
            )
            interfaces = ni.get("interfaces")
            assert isinstance(interfaces, dict) and isinstance(
                interfaces.get("interface"), dict
            ), f"{ni_name}: malformed interfaces envelope"

        expected = _load_expected(mock_dir)
        if (mock_dir / "expected_result.json").exists():
            assert result == expected

    def test_get_modules(self, scenario: str) -> None:
        """Verify get_modules payload shape (driver-optional)."""
        mock_dir = self._mock_dir("test_get_modules", scenario)
        driver = self._build_driver(mock_dir)
        if not hasattr(driver, "get_modules"):
            pytest.skip(f"{self.driver_cls.__name__} does not expose get_modules")

        result = driver.get_modules()
        assert result is None or isinstance(result, dict), (
            "get_modules must return a dict or None"
        )
        if isinstance(result, dict):
            # Nested envelope: {"members": {member_id_or_None: {bays, ifs}}}.
            assert "members" in result and isinstance(result["members"], dict)
            for member_id, member in result["members"].items():
                assert member_id is None or isinstance(member_id, int), (
                    f"member id must be int or None, got {member_id!r}"
                )
                assert "bays" in member and isinstance(member["bays"], list)
                assert "interfaces_by_bay" in member and isinstance(
                    member["interfaces_by_bay"], dict
                )
                for bay in member["bays"]:
                    assert isinstance(bay, dict)
                    assert isinstance(bay.get("name"), str) and bay["name"]
                    mod = bay.get("module") or {}
                    assert mod.get("serial"), (
                        f"bay {bay['name']} on member {member_id} has empty serial"
                    )
                    assert mod.get("type") in {
                        "linecard", "supervisor", "fan", "psu", "transceiver",
                    }

        expected = _load_expected(mock_dir)
        if (mock_dir / "expected_result.json").exists():
            assert result == expected

    def test_get_interfaces_vlans(self, scenario: str) -> None:
        """Verify get_interfaces_vlans returns valid per-iface VLAN config (driver-optional)."""
        mock_dir = self._mock_dir("test_get_interfaces_vlans", scenario)
        driver = self._build_driver(mock_dir)
        if not hasattr(driver, "get_interfaces_vlans"):
            pytest.skip(f"{self.driver_cls.__name__} does not expose get_interfaces_vlans")

        result = driver.get_interfaces_vlans()
        assert isinstance(result, dict), "get_interfaces_vlans must return a dict"
        for ifname, info in result.items():
            assert info.get("mode") in ("access", "trunk", "trunk-all", "routed"), (
                f"{ifname}: invalid mode {info.get('mode')!r}"
            )
            assert "tagged" in info, f"{ifname}: missing 'tagged' key"
            assert "untagged" in info, f"{ifname}: missing 'untagged' key"
            tagged = info["tagged"]
            assert isinstance(tagged, list)
            for v in tagged:
                assert isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 4094, (
                    f"{ifname}: bad tagged VID {v}"
                )
            untagged = info["untagged"]
            assert untagged is None or (
                isinstance(untagged, int)
                and not isinstance(untagged, bool)
                and 1 <= untagged <= 4094
            )

        expected = _load_expected(mock_dir)
        if expected is not None:
            assert result == expected
