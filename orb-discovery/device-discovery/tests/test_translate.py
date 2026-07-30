#!/usr/bin/env python
# Copyright 2024 NetBox Labs Inc
"""NetBox Labs - Translate Unit Tests."""

import pytest
from netboxlabs.diode.sdk.ingester import Device, Entity, Interface

from device_discovery.interface import (
    translate_interface,
    translate_interface_ips,
)
from device_discovery.policy.models import (
    Defaults,
    DeviceParameters,
    IpamParameters,
    Napalm,
    ObjectParameters,
    Options,
    PrefixParameters,
    TenantParameters,
    VlanParameters,
    VrfParameters,
)
from device_discovery.translate import (
    _build_vlan_cache,
    _ensure_vlan,
    _strip_prefix,
    _target_ipv4_candidate,
    apply_interface_vlans,
    assign_primary_ip,
    translate_data,
    translate_device,
    translate_device_config,
    translate_vlan,
    translate_vrf,
)


def test_napalm_netbox_id_parsed():
    """netbox_id field is parsed correctly."""
    n = Napalm(hostname="192.168.1.1", username="admin", password="secret", netbox_id=42)
    assert n.netbox_id == 42


def test_napalm_netbox_id_optional():
    """netbox_id defaults to None."""
    n = Napalm(hostname="192.168.1.1", username="admin", password="secret")
    assert n.netbox_id is None


@pytest.fixture
def sample_device_info():
    """Sample device information for testing."""
    return {
        "hostname": "router1",
        "model": "ISR4451",
        "vendor": "Cisco",
        "serial_number": "123456789",
        "os_version": "v15.2",
        "platform": "ios",
        "interface_list": ["GigabitEthernet0/0", "GigabitEthernet0/0/1"],
    }


@pytest.fixture
def sample_interface_info():
    """Sample interface information for testing."""
    return {
        "GigabitEthernet0/0": {
            "is_enabled": True,
            "mtu": 1500,
            "mac_address": "00:1C:58:29:4A:71",
            "speed": 1000,
            "description": "Uplink Interface",
        },
        "GigabitEthernet0/0/1": {
            "is_enabled": True,
            "mtu": 1500,
            "mac_address": "00:1C:58:29:4A:72",
            "speed": 10000,
            "description": "Uplink Interface",
        },
    }


@pytest.fixture
def sample_interface_overflows_info():
    """Sample interface information for testing."""
    return {
        "GigabitEthernet0/0": {
            "is_enabled": True,
            "mtu": 150000000000,
            "mac_address": "00:1C:58:29:4A:71",
            "speed": 10000000000,
            "description": "Uplink Interface",
        }
    }


@pytest.fixture
def sample_interfaces_ip():
    """Sample interface IPs for testing."""
    return {"GigabitEthernet0/0/1": {"ipv4": {"192.0.2.1": {"prefix_length": 24}}}}


@pytest.fixture
def sample_defaults():
    """Sample defaults for testing."""
    return Defaults(
        site="New York",
        tags=["tag1", "tag2"],
        if_type="other",
        location="local",
        tenant="test",
        device=DeviceParameters(comments="testing", tags=["devtag"]),
        interface=ObjectParameters(description="testing", tags=["inttag"]),
        ipaddress=IpamParameters(description="ip test", tags=["iptag"]),
        prefix=PrefixParameters(description="prefix test", tags=["prefixtag"]),
        vlan=VlanParameters(comments="test"),
    )


@pytest.fixture
def sample_tenant_parameters():
    """Sample tenant parameters for testing."""
    return TenantParameters(
        name="Tenant With Group",
        group="Tenant Group",
        description="Tenant description",
        comments="Tenant comments",
        tags=["tenant-tag"],
    )


@pytest.fixture
def sample_vrf_parameters():
    """Sample VRF parameters for testing."""
    return VrfParameters(
        name="VRF-A",
        rd="65000:100",
        description="VRF description",
        comments="VRF comments",
        tags=["vrf-tag"],
    )


@pytest.fixture
def sample_override_defaults(sample_defaults):
    """Sample defaults with device overrides."""
    sample_defaults.device.model = "Catalyst"
    return sample_defaults


def test_translate_vrf_none_returns_none():
    """Ensure translate_vrf returns None for None input."""
    assert translate_vrf(None) is None


def test_translate_vrf_string_returns_vrf():
    """Ensure translate_vrf wraps a string into a VRF with just the name."""
    from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
    vrf = translate_vrf("my-vrf")
    assert isinstance(vrf, pb.VRF)
    assert vrf.name == "my-vrf"
    assert vrf.rd == ""


def test_translate_device_with_asset_tag(sample_device_info, sample_defaults):
    """Ensure device asset_tag is translated correctly."""
    sample_defaults.device = DeviceParameters(asset_tag="ASSET-001")
    device = translate_device(sample_device_info, sample_defaults)
    assert device.asset_tag == "ASSET-001"


def test_translate_device_asset_tag_none_by_default(sample_device_info, sample_defaults):
    """Ensure device asset_tag is None when not set."""
    device = translate_device(sample_device_info, sample_defaults)
    assert device.asset_tag == ""


def test_translate_device_with_rack(sample_device_info, sample_defaults):
    """Ensure device is associated with rack, reusing defaults.site and location."""
    sample_defaults.rack = "Rack-01"
    device = translate_device(sample_device_info, sample_defaults)
    assert device.rack.name == "Rack-01"
    assert device.rack.site.name == "New York"
    # The location default must be attached to the rack too, with its site
    # embedded so NetBox can match on site+location+name.
    assert device.rack.location.name == "local"
    assert device.rack.location.site.name == "New York"


def test_translate_device_rack_without_location(sample_device_info, sample_defaults):
    """Rack carries no location when no location default is set (site+name only)."""
    sample_defaults.rack = "Rack-01"
    sample_defaults.location = None
    device = translate_device(sample_device_info, sample_defaults)
    assert device.rack.name == "Rack-01"
    assert device.rack.site.name == "New York"
    assert not device.rack.HasField("location")


def test_translate_device_rack_none_by_default(sample_device_info, sample_defaults):
    """Ensure device rack is not set when not configured."""
    device = translate_device(sample_device_info, sample_defaults)
    assert not device.HasField("rack")


def test_translate_interface_ips_with_vrf_parameters(
    sample_device_info,
    sample_interface_info,
    sample_interfaces_ip,
    sample_defaults,
    sample_vrf_parameters,
):
    """Ensure VRF parameters translate into VRF entities with route distinguisher."""
    sample_defaults.ipaddress = IpamParameters(vrf=sample_vrf_parameters)
    sample_defaults.prefix = PrefixParameters(vrf=VrfParameters(name="Prefix-VRF", rd="65000:200"))
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0/1",
        sample_interface_info["GigabitEthernet0/0/1"],
        sample_defaults,
    )
    ip_entities = list(
        translate_interface_ips(interface, sample_interfaces_ip, sample_defaults)
    )

    assert len(ip_entities) == 2
    assert ip_entities[0].prefix.vrf.name == "Prefix-VRF"
    assert ip_entities[0].prefix.vrf.rd == "65000:200"
    assert ip_entities[1].ip_address.vrf.name == "VRF-A"
    assert ip_entities[1].ip_address.vrf.rd == "65000:100"


def test_translate_interface_ips_with_vrf_string(
    sample_device_info,
    sample_interface_info,
    sample_interfaces_ip,
    sample_defaults,
):
    """Ensure plain string VRF still works (backwards compatibility)."""
    sample_defaults.ipaddress = IpamParameters(vrf="plain-vrf")
    sample_defaults.prefix = PrefixParameters(vrf="plain-prefix-vrf")
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0/1",
        sample_interface_info["GigabitEthernet0/0/1"],
        sample_defaults,
    )
    ip_entities = list(
        translate_interface_ips(interface, sample_interfaces_ip, sample_defaults)
    )

    assert len(ip_entities) == 2
    assert ip_entities[0].prefix.vrf.name == "plain-prefix-vrf"
    assert ip_entities[1].ip_address.vrf.name == "plain-vrf"


# --- per-address-family VRF (orb-agent#392) ---------------------------------


@pytest.fixture
def sample_interfaces_ip_dual_stack():
    """Dual-stack IPs on the same interface — IPv4 + IPv6."""
    return {
        "GigabitEthernet0/0/1": {
            "ipv4": {"192.0.2.1": {"prefix_length": 24}},
            "ipv6": {"2001:db8::1": {"prefix_length": 64}},
        }
    }


def _emit_dual_stack(
    sample_device_info,
    sample_interface_info,
    sample_interfaces_ip_dual_stack,
    sample_defaults,
):
    """Translate a dual-stack interface and bucket the emitted entities by IP version."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0/1",
        sample_interface_info["GigabitEthernet0/0/1"],
        sample_defaults,
    )
    entities = list(
        translate_interface_ips(
            interface, sample_interfaces_ip_dual_stack, sample_defaults
        )
    )
    ip4 = {"prefix": None, "ip": None}
    ip6 = {"prefix": None, "ip": None}
    for e in entities:
        if e.HasField("prefix"):
            bucket = ip4 if "." in e.prefix.prefix else ip6
            bucket["prefix"] = e.prefix
        elif e.HasField("ip_address"):
            bucket = ip4 if "." in e.ip_address.address else ip6
            bucket["ip"] = e.ip_address
    return ip4, ip6


def test_per_af_vrf_picks_ipv4_and_ipv6_overrides(
    sample_device_info,
    sample_interface_info,
    sample_interfaces_ip_dual_stack,
    sample_defaults,
):
    """vrf_ipv4 / vrf_ipv6 land on the right AF independently."""
    sample_defaults.ipaddress = IpamParameters(
        vrf="fallback-vrf",
        vrf_ipv4=VrfParameters(name="customer-v4", rd="65000:10"),
        vrf_ipv6=VrfParameters(name="global-v6", rd="65000:20"),
    )
    sample_defaults.prefix = PrefixParameters(
        vrf="fallback-prefix-vrf",
        vrf_ipv4=VrfParameters(name="customer-v4-prefix", rd="65000:10"),
        vrf_ipv6=VrfParameters(name="global-v6-prefix", rd="65000:20"),
    )
    ip4, ip6 = _emit_dual_stack(
        sample_device_info,
        sample_interface_info,
        sample_interfaces_ip_dual_stack,
        sample_defaults,
    )
    assert ip4["ip"].vrf.name == "customer-v4"
    assert ip4["ip"].vrf.rd == "65000:10"
    assert ip6["ip"].vrf.name == "global-v6"
    assert ip6["ip"].vrf.rd == "65000:20"
    assert ip4["prefix"].vrf.name == "customer-v4-prefix"
    assert ip6["prefix"].vrf.name == "global-v6-prefix"


def test_per_af_vrf_falls_back_to_top_level_when_unset(
    sample_device_info,
    sample_interface_info,
    sample_interfaces_ip_dual_stack,
    sample_defaults,
):
    """If vrf_ipv4 / vrf_ipv6 are unset, both AFs use the top-level `vrf`."""
    sample_defaults.ipaddress = IpamParameters(vrf="shared-vrf")
    sample_defaults.prefix = PrefixParameters(vrf="shared-prefix-vrf")
    ip4, ip6 = _emit_dual_stack(
        sample_device_info,
        sample_interface_info,
        sample_interfaces_ip_dual_stack,
        sample_defaults,
    )
    assert ip4["ip"].vrf.name == "shared-vrf"
    assert ip6["ip"].vrf.name == "shared-vrf"
    assert ip4["prefix"].vrf.name == "shared-prefix-vrf"
    assert ip6["prefix"].vrf.name == "shared-prefix-vrf"


def test_per_af_vrf_only_one_family_overridden(
    sample_device_info,
    sample_interface_info,
    sample_interfaces_ip_dual_stack,
    sample_defaults,
):
    """vrf_ipv4 set but not vrf_ipv6 → IPv4 picks the override, IPv6 uses the fallback."""
    sample_defaults.ipaddress = IpamParameters(
        vrf="fallback-vrf",
        vrf_ipv4=VrfParameters(name="customer-v4", rd="65000:10"),
    )
    sample_defaults.prefix = PrefixParameters(
        vrf="fallback-prefix-vrf",
        vrf_ipv6=VrfParameters(name="global-v6-prefix", rd="65000:20"),
    )
    ip4, ip6 = _emit_dual_stack(
        sample_device_info,
        sample_interface_info,
        sample_interfaces_ip_dual_stack,
        sample_defaults,
    )
    assert ip4["ip"].vrf.name == "customer-v4"
    assert ip6["ip"].vrf.name == "fallback-vrf"
    assert ip4["prefix"].vrf.name == "fallback-prefix-vrf"
    assert ip6["prefix"].vrf.name == "global-v6-prefix"


def test_per_af_vrf_only_ipv4_no_top_level_leaves_ipv6_without_vrf(
    sample_device_info,
    sample_interface_info,
    sample_interfaces_ip_dual_stack,
    sample_defaults,
):
    """No top-level vrf, only vrf_ipv4 → IPv6 emits no VRF (no override AND no fallback)."""
    sample_defaults.ipaddress = IpamParameters(
        vrf_ipv4=VrfParameters(name="customer-v4", rd="65000:10"),
    )
    sample_defaults.prefix = PrefixParameters(
        vrf_ipv4=VrfParameters(name="customer-v4-prefix", rd="65000:10"),
    )
    ip4, ip6 = _emit_dual_stack(
        sample_device_info,
        sample_interface_info,
        sample_interfaces_ip_dual_stack,
        sample_defaults,
    )
    assert ip4["ip"].vrf.name == "customer-v4"
    assert not ip6["ip"].HasField("vrf"), "IPv6 must NOT carry a VRF when neither vrf_ipv6 nor vrf is set"
    assert ip4["prefix"].vrf.name == "customer-v4-prefix"
    assert not ip6["prefix"].HasField("vrf")


def test_per_af_vrf_accepts_scalar_string(
    sample_device_info,
    sample_interface_info,
    sample_interfaces_ip_dual_stack,
    sample_defaults,
):
    """vrf_ipv4 / vrf_ipv6 accept the same str | VrfParameters polymorphic shape as vrf."""
    sample_defaults.ipaddress = IpamParameters(
        vrf_ipv4="customer-v4",
        vrf_ipv6="global-v6",
    )
    ip4, ip6 = _emit_dual_stack(
        sample_device_info,
        sample_interface_info,
        sample_interfaces_ip_dual_stack,
        sample_defaults,
    )
    assert ip4["ip"].vrf.name == "customer-v4"
    assert ip4["ip"].vrf.rd == ""
    assert ip6["ip"].vrf.name == "global-v6"
    assert ip6["ip"].vrf.rd == ""


def test_translate_device(sample_device_info, sample_defaults):
    """Ensure device translation is correct."""
    device = translate_device(sample_device_info, sample_defaults)
    assert device.name == "router1"
    assert device.device_type.model == "ISR4451"
    assert device.platform.name == "ios"
    assert device.serial == "123456789"
    assert device.site.name == "New York"
    assert device.comments == "testing"
    assert device.role.name == "undefined"
    assert device.location.name == "local"
    assert device.location.site.name == "New York"
    assert device.tenant.name == "test"
    assert len(device.tags) == 3


def test_translate_device_with_overrides(sample_device_info, sample_override_defaults):
    """Ensure device translation respects model overrides."""
    device = translate_device(sample_device_info, sample_override_defaults)
    assert device.device_type.model == "Catalyst"
    assert device.device_type.manufacturer.name == "Cisco"


def test_translate_device_with_tenant_parameters(
    sample_device_info, sample_defaults, sample_tenant_parameters
):
    """Ensure tenant parameters translate into Tenant entities."""
    sample_defaults.tenant = sample_tenant_parameters
    device = translate_device(sample_device_info, sample_defaults)

    assert device.tenant.name == "Tenant With Group"
    assert device.tenant.group.name == "Tenant Group"
    assert device.tenant.description == "Tenant description"
    assert device.tenant.comments == "Tenant comments"
    assert len(device.tenant.tags) == 1


def test_translate_device_serial_list(sample_device_info, sample_defaults):
    """Ensure device translation handles list serial numbers."""
    sample_device_info["serial_number"] = ["123456789", "987654321"]
    device = translate_device(sample_device_info, sample_defaults)
    assert device.serial == "123456789"
    sample_device_info["serial_number"] = []
    device = translate_device(sample_device_info, sample_defaults)
    assert device.serial == ""


def test_translate_interface(
    sample_device_info, sample_interface_info, sample_defaults
):
    """Ensure interface translation is correct."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_info["GigabitEthernet0/0"],
        sample_defaults,
    )
    assert interface.device.name == "router1"
    assert interface.name == "GigabitEthernet0/0"
    assert interface.enabled is True
    assert interface.mtu == 1500
    assert interface.primary_mac_address.mac_address == "00:1C:58:29:4A:71"
    assert interface.speed == 1000000
    assert interface.description == "Uplink Interface"
    assert len(interface.tags) == 3


def test_translate_interface_with_overflow_data(
    sample_device_info, sample_interface_overflows_info, sample_defaults
):
    """Ensure interface translation is correct."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_overflows_info["GigabitEthernet0/0"],
        sample_defaults,
    )
    assert interface.device.name == "router1"
    assert interface.name == "GigabitEthernet0/0"
    assert interface.enabled is True
    assert interface.mtu == 0
    assert interface.primary_mac_address.mac_address == "00:1C:58:29:4A:71"
    assert interface.speed == 0
    assert interface.description == "Uplink Interface"
    assert len(interface.tags) == 3


def test_translate_interface_ips(
    sample_device_info, sample_interface_info, sample_interfaces_ip, sample_defaults
):
    """Ensure interface IPs translation is correct."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0",
        sample_interface_info["GigabitEthernet0/0"],
        sample_defaults,
    )
    ip_entities = list(
        translate_interface_ips(interface, sample_interfaces_ip, sample_defaults)
    )

    assert len(ip_entities) == 0

    interface = translate_interface(
        device,
        "GigabitEthernet0/0/1",
        sample_interface_info["GigabitEthernet0/0/1"],
        sample_defaults,
    )
    ip_entities = list(
        translate_interface_ips(interface, sample_interfaces_ip, sample_defaults)
    )

    assert len(ip_entities) == 2
    assert ip_entities[0].prefix.prefix == "192.0.2.0/24"
    assert ip_entities[1].ip_address.address == "192.0.2.1/24"
    assert ip_entities[0].prefix.description == "prefix test"
    assert ip_entities[1].ip_address.description == "ip test"
    assert len(ip_entities[0].prefix.tags) == 3
    assert len(ip_entities[1].ip_address.tags) == 3


def test_translate_interface_ips_with_tenant_parameters(
    sample_device_info,
    sample_interface_info,
    sample_interfaces_ip,
    sample_defaults,
    sample_tenant_parameters,
):
    """Ensure interface IP translation supports tenant parameters."""
    sample_defaults.ipaddress.tenant = sample_tenant_parameters
    sample_defaults.prefix.tenant = TenantParameters(
        name="Prefix Tenant", group="Prefix Group"
    )
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0/1",
        sample_interface_info["GigabitEthernet0/0/1"],
        sample_defaults,
    )
    ip_entities = list(
        translate_interface_ips(interface, sample_interfaces_ip, sample_defaults)
    )

    assert len(ip_entities) == 2
    assert ip_entities[0].prefix.tenant.name == "Prefix Tenant"
    assert ip_entities[0].prefix.tenant.group.name == "Prefix Group"
    assert ip_entities[1].ip_address.tenant.name == "Tenant With Group"
    assert ip_entities[1].ip_address.tenant.group.name == "Tenant Group"


def test_translate_data(
    sample_device_info, sample_interface_info, sample_interfaces_ip, sample_defaults
):
    """Ensure data translation is correct."""
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
    }
    entities = list(translate_data(data))
    assert len(entities) == 5
    assert entities[0].device.name == "router1"
    assert entities[0].device.site.name == "undefined"
    assert entities[0].device.platform.name == "IOS v15.2"
    assert entities[1].interface.name == "GigabitEthernet0/0"
    assert entities[2].interface.name == "GigabitEthernet0/0/1"
    assert entities[3].prefix.prefix == "192.0.2.0/24"
    assert entities[4].ip_address.address == "192.0.2.1/24"

    data["defaults"] = sample_defaults
    data["options"] = Options(platform_omit_version=True)

    entities = list(translate_data(data))
    assert entities[0].device.site.name == "New York"
    assert entities[0].device.platform.name == "ios"

    data["defaults"].role = "switch"
    data["defaults"].device.platform = "custom"
    data["options"].platform_omit_version = False

    entities = list(translate_data(data))
    assert entities[0].device.platform.name == "custom"
    assert entities[0].device.role.name == "switch"


def test_translate_data_truncates_platform(sample_device_info, sample_defaults):
    """Ensure overly long platform strings are truncated to 100 characters while preserving the ``<DRIVER> <os_version>`` format."""
    long_os_version = "v" * 150
    device_info = sample_device_info.copy()
    device_info["os_version"] = long_os_version
    data = {
        "device": device_info,
        "interface": {},
        "interface_ip": {},
        "driver": "ios",
        "defaults": sample_defaults,
    }

    entities = list(translate_data(data))

    assert len(entities) == 1
    # Truncation preserves the "IOS " driver prefix instead of dropping it.
    expected = ("IOS " + long_os_version)[:100]
    assert entities[0].device.platform.name == expected
    assert entities[0].device.platform.name.startswith("IOS ")
    assert len(entities[0].device.platform.name) == 100


def test_translate_data_handles_missing_os_version(sample_device_info, sample_defaults):
    """A None/missing os_version must not crash _resolve_platform."""
    device_info = sample_device_info.copy()
    device_info["os_version"] = None
    data = {
        "device": device_info,
        "interface": {},
        "interface_ip": {},
        "driver": "ios",
        "defaults": sample_defaults,
    }

    entities = list(translate_data(data))

    assert len(entities) == 1
    # Driver-only when os_version is empty/None.
    assert entities[0].device.platform.name == "IOS"


def test_translate_data_creates_missing_interface(sample_device_info, sample_defaults):
    """Ensure translate_data creates interfaces referenced only by IP data."""
    interfaces = {
        "GigabitEthernet0/0": {
            "is_enabled": True,
            "mtu": 1500,
            "mac_address": "00:1C:58:29:4A:71",
            "speed": 1000,
            "description": "Uplink Interface",
        }
    }
    interfaces_ip = {
        "Loopback0": {"ipv4": {"198.51.100.1": {"prefix_length": 32}}},
    }
    data = {
        "device": sample_device_info,
        "interface": interfaces,
        "interface_ip": interfaces_ip,
        "driver": "ios",
    }

    entities = list(translate_data(data))

    loopback_interface = next(
        entity.interface
        for entity in entities
        if entity.WhichOneof("entity") == "interface"
        and entity.interface.name == "Loopback0"
    )
    loopback_ip = next(
        entity.ip_address
        for entity in entities
        if entity.WhichOneof("entity") == "ip_address"
    )

    # device + 2 interfaces + the loopback IP. No prefix: a /32 loopback is a
    # host prefix and is deliberately not derived.
    assert len(entities) == 4
    assert (
        sum(1 for entity in entities if entity.WhichOneof("entity") == "interface") == 2
    )
    assert not [e for e in entities if e.WhichOneof("entity") == "prefix"], (
        "a /32 loopback must not produce a Prefix entity"
    )
    assert loopback_interface.name == "Loopback0"
    assert loopback_ip.address == "198.51.100.1/32"
    assert loopback_ip.assigned_object_interface.name == "Loopback0"


def test_translate_data_creates_missing_subinterface_with_parent(
    sample_device_info, sample_defaults
):
    """Ensure translate_data creates subinterfaces and assigns parent relationships."""
    interfaces = {
        "ethernet-1/1": {
            "is_enabled": True,
            "mtu": 1500,
            "mac_address": "00:1C:58:29:4A:71",
            "speed": 1000,
            "description": "Parent Interface",
        },
        "ethernet-1/10": {
            "is_enabled": True,
            "mtu": 1500,
            "mac_address": "00:1C:58:29:4A:72",
            "speed": 1000,
            "description": "Interface",
        },
    }
    interfaces_ip = {
        "ethernet-1/1.0": {"ipv4": {"10.0.0.1": {"prefix_length": 30}}},
    }
    data = {
        "device": sample_device_info,
        "interface": interfaces,
        "interface_ip": interfaces_ip,
        "driver": "ios",
    }

    entities = list(translate_data(data))

    subinterface = next(
        entity.interface
        for entity in entities
        if entity.WhichOneof("entity") == "interface"
        and entity.interface.name == "ethernet-1/1.0"
    )
    parent_interface = next(
        entity.interface
        for entity in entities
        if entity.WhichOneof("entity") == "interface"
        and entity.interface.name == "ethernet-1/1"
    )
    ip_entity = next(
        entity.ip_address
        for entity in entities
        if entity.WhichOneof("entity") == "ip_address"
    )

    assert subinterface.parent.name == "ethernet-1/1"
    assert subinterface.parent.name == parent_interface.name
    assert subinterface.type == "virtual"
    # Parent interface now matches built-in Nokia pattern (ethernet-\d+/\d+)
    assert parent_interface.type == "1000base-t"
    assert ip_entity.address == "10.0.0.1/30"
    assert ip_entity.assigned_object_interface.name == "ethernet-1/1.0"


def test_translate_data_handles_none_defaults_and_options(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """Ensure translation works when defaults and options are None."""
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
        "defaults": None,
        "options": None,
    }

    entities = list(translate_data(data))

    assert len(entities) == 5
    assert entities[0].device.site.name == "undefined"
    assert entities[0].device.platform.name == "IOS v15.2"


def test_translate_vlan(sample_defaults):
    """Ensure VLAN translation is correct."""
    vid = "1"
    vlan_name = "Test  VLAN   "
    vlan = translate_vlan(vid, vlan_name, sample_defaults)

    assert vlan.vid == 1
    assert vlan.name == "Test VLAN"
    assert len(vlan.tags) == 2
    assert vlan.comments == "test"

    vid = "2"
    vlan_name = "Test - VLAN   "
    vlan = translate_vlan(vid, vlan_name, sample_defaults)
    assert vlan.vid == 2
    assert vlan.name == "Test - VLAN"

    vlan_name = "info-vlan "
    vlan = translate_vlan(vid, vlan_name, sample_defaults)
    assert vlan.vid == 2
    assert vlan.name == "info-vlan"

    vid = "NA"
    vlan = translate_vlan(vid, vlan_name, sample_defaults)
    assert vlan is None


def test_translate_vlan_with_none_id(sample_defaults):
    """Ensure translate_vlan returns None for invalid None VLAN IDs."""
    vlan = translate_vlan(None, "Invalid VLAN", sample_defaults)
    assert vlan is None


def test_translate_vlan_with_defaults(sample_defaults):
    """Ensure VLAN translation includes default values."""
    sample_defaults.vlan = VlanParameters(
        tags=["vlantag"],
        comments="Default VLAN comment",
        description="Default VLAN description",
        group="Default Group",
        tenant="Default Tenant",
        role="Default Role",
    )
    vid = "200"
    vlan_name = "Default VLAN"
    vlan = translate_vlan(vid, vlan_name, sample_defaults)

    assert vlan.vid == 200
    assert vlan.name == "Default VLAN"
    assert vlan.comments == "Default VLAN comment"
    assert vlan.description == "Default VLAN description"
    assert vlan.group.name == "Default Group"
    assert vlan.tenant.name == "Default Tenant"
    assert vlan.role.name == "Default Role"
    assert len(vlan.tags) == 3


def test_translate_vlan_group_scope_site_set_when_site_defined(sample_defaults):
    """VLAN group is wrapped with slug + scope_site when defaults.site is a real value."""
    sample_defaults.site = "New York"
    sample_defaults.vlan = VlanParameters(group="Default Group")

    vlan = translate_vlan("10", "V10", sample_defaults)

    assert vlan.group.name == "Default Group"
    assert vlan.group.slug == "default-group"
    assert vlan.group.scope_site.name == "New York"


def test_translate_vlan_group_scope_site_set_when_site_undefined(sample_defaults):
    """scope_site is still populated when defaults.site is the sentinel 'undefined'."""
    sample_defaults.site = "undefined"
    sample_defaults.vlan = VlanParameters(group="Default Group")

    vlan = translate_vlan("11", "V11", sample_defaults)

    assert vlan.group.name == "Default Group"
    assert vlan.group.slug == "default-group"
    assert vlan.group.scope_site.name == "undefined"


def test_translate_vlan_group_no_scope_site_when_site_none(sample_defaults):
    """VLAN group has slug but no scope_site when defaults.site is None."""
    sample_defaults.site = None
    sample_defaults.vlan = VlanParameters(group="Default Group")

    vlan = translate_vlan("12", "V12", sample_defaults)

    assert vlan.group.name == "Default Group"
    assert vlan.group.slug == "default-group"
    assert vlan.group.scope_site.name == ""


def test_translate_vlan_no_group_unaffected_by_site(sample_defaults):
    """When no group is set, scope_site is not applied (group stays unset)."""
    sample_defaults.site = "New York"
    sample_defaults.vlan = VlanParameters(comments="no group")

    vlan = translate_vlan("13", "V13", sample_defaults)

    assert vlan.group.name == ""
    assert vlan.group.slug == ""
    assert vlan.group.scope_site.name == ""


def test_translate_vlan_with_tenant_parameters(
    sample_defaults, sample_tenant_parameters
):
    """Ensure VLAN translation supports tenant parameter objects."""
    sample_defaults.vlan = VlanParameters(
        tenant=sample_tenant_parameters, description="Tenant VLAN"
    )
    vlan = translate_vlan("201", "Tenant VLAN", sample_defaults)

    assert vlan.vid == 201
    assert vlan.tenant.name == "Tenant With Group"
    assert vlan.tenant.group.name == "Tenant Group"
    assert vlan.description == "Tenant VLAN"


def test_translate_data_with_interface_patterns(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """Test full data translation with interface patterns."""
    from device_discovery.policy.models import InterfacePattern

    defaults = Defaults(
        site="New York",
        if_type="other",
        interface_patterns=[
            InterfacePattern(match="GigabitEthernet.*", type="1000base-t"),
        ],
    )

    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
        "defaults": defaults,
    }

    entities = list(translate_data(data))

    # Find interface entities
    interface_entities = [e for e in entities if e.WhichOneof("entity") == "interface"]

    # Both GigabitEthernet interfaces should match the pattern
    for interface_entity in interface_entities:
        if interface_entity.interface.name.startswith("GigabitEthernet"):
            assert interface_entity.interface.type == "1000base-t"


def test_translate_data_with_builtin_patterns(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """Test full data translation with built-in patterns (zero configuration)."""
    defaults = Defaults(
        site="New York",
        if_type="other",
        # No interface_patterns specified - should use built-ins
    )

    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
        "defaults": defaults,
    }

    entities = list(translate_data(data))

    # Find interface entities
    interface_entities = [e for e in entities if e.WhichOneof("entity") == "interface"]

    # Both GigabitEthernet interfaces should match built-in pattern
    for interface_entity in interface_entities:
        if interface_entity.interface.name.startswith("GigabitEthernet"):
            assert interface_entity.interface.type == "1000base-t"


def test_translate_device_config_with_valid_config():
    """Test that translate_device_config returns DeviceConfig with valid data."""
    config_info = {
        "startup": "startup config content",
        "running": "running config content",
    }
    options = Options(capture_running_config=True, capture_startup_config=True)

    result = translate_device_config(config_info, options)

    # Should return a valid DeviceConfig
    assert result is not None
    assert result.startup == b"startup config content"
    assert result.running == b"running config content"
    # Protobuf uses empty bytes for unset byte fields
    assert result.candidate == b""


def test_translate_device_config_with_empty_config():
    """Test that translate_device_config returns None with empty config."""
    config_info = {}
    options = Options(capture_running_config=True, capture_startup_config=True)

    result = translate_device_config(config_info, options)

    assert result is None


def test_translate_device_handles_none_config():
    """Test that translate_device handles None config_info gracefully in the integration."""
    device_info = {
        "hostname": "test-router",
        "model": "ISR4451",
        "vendor": "Cisco",
        "serial_number": "123456",
        "platform": "ios",
    }
    defaults = Defaults(site="Test Site", role="router")
    options = Options(capture_running_config=True, capture_startup_config=True)

    # translate_device should handle None config_info without error
    # The 'if config_info and options' check will skip config translation
    device = translate_device(device_info, defaults, None, options)

    assert device is not None
    assert device.name == "test-router"


def test_translate_device_config_respects_capture_flags():
    """Test that config capture respects the configuration flags."""
    config_info = {
        "startup": "startup config content",
        "running": "running config content",
    }

    # Test with both flags disabled
    options_disabled = Options(
        capture_running_config=False, capture_startup_config=False
    )
    result = translate_device_config(config_info, options_disabled)
    assert result is None

    # Test with only running config enabled
    options_running = Options(capture_running_config=True, capture_startup_config=False)
    result = translate_device_config(config_info, options_running)
    assert result is not None
    assert result.running == b"running config content"
    # Protobuf uses empty bytes for unset byte fields
    assert result.startup == b""

    # Test with only startup config enabled
    options_startup = Options(capture_running_config=False, capture_startup_config=True)
    result = translate_device_config(config_info, options_startup)
    assert result is not None
    assert result.startup == b"startup config content"
    # Protobuf uses empty bytes for unset byte fields
    assert result.running == b""


def test_translate_device_config_string_to_bytes_conversion():
    """Test that string configs are converted to bytes."""
    config_info = {
        "startup": "startup config as string",
        "running": "running config as string",
    }
    options = Options(capture_running_config=True, capture_startup_config=True)

    result = translate_device_config(config_info, options)

    # Verify strings were converted to bytes
    assert result is not None
    assert isinstance(result.running, bytes)
    assert isinstance(result.startup, bytes)
    assert result.running == b"running config as string"
    assert result.startup == b"startup config as string"


def test_translate_device_config_with_bytes_input():
    """Test that bytes configs are handled correctly."""
    config_info = {
        "startup": b"startup config as bytes",
        "running": b"running config as bytes",
    }
    options = Options(capture_running_config=True, capture_startup_config=True)

    result = translate_device_config(config_info, options)

    # Bytes should pass through without conversion
    assert result is not None
    assert isinstance(result.running, bytes)
    assert isinstance(result.startup, bytes)
    assert result.running == b"running config as bytes"
    assert result.startup == b"startup config as bytes"


def test_translate_device_config_with_empty_string():
    """Test that empty string configs are properly encoded to bytes."""
    config_info = {
        "startup": "",  # Empty string should be encoded to b""
        "running": "running config content",
    }
    options = Options(capture_running_config=True, capture_startup_config=True)

    result = translate_device_config(config_info, options)

    # Empty strings should be encoded to empty bytes
    assert result is not None
    assert isinstance(result.startup, bytes)
    assert result.startup == b""
    assert isinstance(result.running, bytes)
    assert result.running == b"running config content"


def test_translate_device_config_candidate_not_captured():
    """Test that candidate config is never captured (always None)."""
    config_info = {
        "startup": "startup config",
        "running": "running config",
        "candidate": "candidate config",  # Should be ignored
    }
    options = Options(capture_running_config=True, capture_startup_config=True)

    result = translate_device_config(config_info, options)

    # Candidate should always be empty (not captured)
    assert result is not None
    assert result.candidate == b""


def test_translate_device_with_config_integration(sample_device_info):
    """Test that translate_device integrates with config translation."""
    config_info = {
        "startup": "startup config content",
        "running": "running config content",
    }
    defaults = Defaults(site="New York", role="router")
    options = Options(capture_running_config=True, capture_startup_config=True)

    device = translate_device(sample_device_info, defaults, config_info, options)

    # Device should be created successfully
    assert device.name == "router1"
    # Config integration documented for when SDK is available


def test_translate_data_with_config(sample_device_info):
    """Test full data translation with config data."""
    config_info = {
        "startup": "startup configuration content here",
        "running": "running configuration content here",
    }
    defaults = Defaults(site="New York", role="router")
    options = Options(capture_running_config=True, capture_startup_config=True)

    data = {
        "device": sample_device_info,
        "config": config_info,
        "driver": "ios",
        "defaults": defaults,
        "options": options,
    }

    entities = list(translate_data(data))

    # Should have exactly one device entity (no interfaces/IPs in data)
    assert len(entities) == 1
    device_entities = [e for e in entities if e.WhichOneof("entity") == "device"]
    assert len(device_entities) == 1

    # When SDK supports it, device will have config attached


def test_translate_device_with_netbox_id(sample_device_info, sample_defaults):
    """Device metadata contains source_match when netbox_id is provided."""
    device = translate_device(sample_device_info, sample_defaults, netbox_id=42)
    assert "source_match" in device.metadata
    assert device.metadata["source_match"]["netbox_id"] == 42


def test_translate_device_without_netbox_id(sample_device_info, sample_defaults):
    """Device metadata has no source_match key when netbox_id is not provided."""
    device = translate_device(sample_device_info, sample_defaults)
    assert "source_match" not in device.metadata


def test_translate_data_with_config_disabled(sample_device_info):
    """Test that config is not captured when flags are disabled."""
    config_info = {
        "startup": "startup configuration",
        "running": "running configuration",
    }
    defaults = Defaults(site="New York", role="router")
    options = Options(capture_running_config=False, capture_startup_config=False)

    data = {
        "device": sample_device_info,
        "config": config_info,
        "driver": "ios",
        "defaults": defaults,
        "options": options,
    }

    entities = list(translate_data(data))

    # Device should be created but without config
    device_entities = [e for e in entities if e.WhichOneof("entity") == "device"]
    assert len(device_entities) == 1


def test_strip_prefix_returns_address_without_cidr():
    """StripPrefix drops the /prefix suffix (helper sanity)."""
    assert _strip_prefix("192.0.2.10/24") == "192.0.2.10"
    assert _strip_prefix("10.0.0.1") == "10.0.0.1"


def test_target_ipv4_candidate_ipv4_literal():
    """IPv4 literal is returned canonicalized."""
    assert _target_ipv4_candidate("10.0.0.1") == "10.0.0.1"


def test_target_ipv4_candidate_ipv6_literal_ignored():
    """IPv6 literals are not eligible for primary-IPv4 matching."""
    assert _target_ipv4_candidate("2001:db8::1") is None


def test_target_ipv4_candidate_hostname_ignored():
    """Hostnames are deliberately not re-resolved for primary-IP matching."""
    assert _target_ipv4_candidate("router.example.com") is None


def test_target_ipv4_candidate_blank_host():
    """Empty / whitespace-only hosts yield no candidate."""
    assert _target_ipv4_candidate(None) is None
    assert _target_ipv4_candidate("") is None
    assert _target_ipv4_candidate("   ") is None


def test_translate_data_sets_primary_ip_when_target_matches(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """End-to-end: hostname equal to a discovered interface IP populates primary_ip4."""
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
        "target_hostname": "192.0.2.1",
    }
    entities = list(translate_data(data))
    device_entity = next(e for e in entities if e.WhichOneof("entity") == "device")
    assert device_entity.device.HasField("primary_ip4")
    assert device_entity.device.primary_ip4.address == "192.0.2.1/24"
    # The primary IP must be attached to the interface that holds it.
    assert device_entity.device.primary_ip4.HasField("assigned_object_interface")
    assert (
        device_entity.device.primary_ip4.assigned_object_interface.name
        == "GigabitEthernet0/0/1"
    )


def test_translate_data_no_primary_ip_when_target_does_not_match(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """No match leaves primary_ip4 unset."""
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
        "target_hostname": "198.51.100.99",
    }
    entities = list(translate_data(data))
    device_entity = next(e for e in entities if e.WhichOneof("entity") == "device")
    assert not device_entity.device.HasField("primary_ip4")


def test_translate_data_no_primary_ip_without_hostname(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """Missing hostname is a no-op (backwards compatible)."""
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
    }
    entities = list(translate_data(data))
    device_entity = next(e for e in entities if e.WhichOneof("entity") == "device")
    assert not device_entity.device.HasField("primary_ip4")


def test_translate_data_hostname_target_is_noop(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """
    Hostname targets do not trigger DNS re-resolution.

    Device-discovery deliberately matches only IPv4 literals because
    re-resolving a hostname can pick a different address than the one
    NAPALM actually connected to, which would silently mis-associate the
    primary IP.
    """
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
        "target_hostname": "router.example",
    }
    entities = list(translate_data(data))
    device_entity = next(e for e in entities if e.WhichOneof("entity") == "device")
    assert not device_entity.device.HasField("primary_ip4")


def test_translate_data_ipv6_literal_target_is_noop(
    sample_device_info, sample_interface_info, sample_interfaces_ip
):
    """IPv6 targets do not set primary_ip4 (IPv4-only)."""
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "driver": "ios",
        "target_hostname": "2001:db8::1",
    }
    entities = list(translate_data(data))
    device_entity = next(e for e in entities if e.WhichOneof("entity") == "device")
    assert not device_entity.device.HasField("primary_ip4")


def test_translate_data_device_config_only_on_top_level_device(
    sample_device_info, sample_interface_info, sample_interfaces_ip, sample_defaults
):
    """
    Config lives only on the top-level Device entity.

    ``translate_data`` deep-copies the Device for the interface entities and
    clears ``config`` on the copy (``device_for_interfaces.ClearField("config")``),
    so the Device reference embedded in each Interface must carry no config
    even when the top-level Device does. Guards against regressions in the
    ordering of deep-copy / ClearField / assign_primary_ip / Entity wrap.
    """
    config_info = {
        "running": "hostname router1\n",
        "startup": "hostname router1\n",
    }
    options = Options(capture_running_config=True, capture_startup_config=True)
    data = {
        "device": sample_device_info,
        "interface": sample_interface_info,
        "interface_ip": sample_interfaces_ip,
        "config": config_info,
        "driver": "ios",
        "defaults": sample_defaults,
        "options": options,
        "target_hostname": "192.0.2.1",
    }
    entities = list(translate_data(data))

    device_entity = next(e for e in entities if e.WhichOneof("entity") == "device")
    assert device_entity.device.HasField("config"), (
        "top-level Device must carry the captured config"
    )

    interface_entities = [e for e in entities if e.WhichOneof("entity") == "interface"]
    assert interface_entities, "expected at least one Interface in the output"
    for e in interface_entities:
        assert not e.interface.device.HasField("config"), (
            f"Interface {e.interface.name!r} must not carry device.config; "
            "ClearField('config') on device_for_interfaces was skipped"
        )

    # primary_ip4 also references a Device (via assigned_object_interface ->
    # device). That Device is the interface-scoped copy, so it must also be
    # config-free.
    assert device_entity.device.HasField("primary_ip4")
    primary_ip4 = device_entity.device.primary_ip4
    assert primary_ip4.HasField("assigned_object_interface")
    assert not primary_ip4.assigned_object_interface.device.HasField("config"), (
        "primary_ip4's assigned interface must not carry device.config"
    )


def test_assign_primary_ip_ignores_ip_without_interface_assignment():
    """Enforce the "verified interface IP" guarantee directly on the helper."""
    from netboxlabs.diode.sdk.ingester import Device, Entity, IPAddress

    device = Device(name="router")
    unassigned = Entity(ip_address=IPAddress(address="10.0.0.1/32"))
    assign_primary_ip(device, [unassigned], "10.0.0.1")
    assert not device.HasField("primary_ip4")


def test_assign_primary_ip_multiple_matches_deterministic_warn(caplog):
    """Two matching entries resolve to the lexicographically smaller key + Warn log."""
    from netboxlabs.diode.sdk.ingester import (
        Device,
        Entity,
        Interface,
        IPAddress,
    )

    device = Device(name="router")
    ip_high = Entity(
        ip_address=IPAddress(
            address="10.0.0.1/32",
            assigned_object_interface=Interface(name="Loopback1"),
        )
    )
    ip_low = Entity(
        ip_address=IPAddress(
            address="10.0.0.1/32",
            assigned_object_interface=Interface(name="Loopback0"),
        )
    )
    with caplog.at_level("WARNING"):
        assign_primary_ip(device, [ip_high, ip_low], "10.0.0.1")
    assert device.HasField("primary_ip4")
    # Lexicographic tie-break picks "Loopback0" over "Loopback1".
    assert device.primary_ip4.assigned_object_interface.name == "Loopback0"
    assert any(
        "multiple candidates match target" in rec.message for rec in caplog.records
    )


def test_build_vlan_cache_from_get_vlans():
    """_build_vlan_cache produces vid->VLAN map from get_vlans() shape."""
    raw = {"10": {"name": "DATA"}, "20": {"name": "VOICE"}}
    cache = _build_vlan_cache(raw, Defaults())
    assert set(cache.keys()) == {10, 20}
    assert cache[10].vid == 10
    assert cache[10].name == "DATA"
    assert cache[20].name == "VOICE"


def test_build_vlan_cache_empty():
    """_build_vlan_cache returns empty dict for None or empty input."""
    assert _build_vlan_cache({}, Defaults()) == {}
    assert _build_vlan_cache(None, Defaults()) == {}


def test_ensure_vlan_returns_cached():
    """_ensure_vlan returns the cached VLAN without creating a stub."""
    defaults = Defaults()
    cache = _build_vlan_cache({"10": {"name": "DATA"}}, defaults)
    new_stubs: list = []
    vlan = _ensure_vlan(10, cache, defaults, Options(), new_stubs)
    assert vlan.vid == 10
    assert vlan.name == "DATA"
    assert new_stubs == []


def test_ensure_vlan_creates_stub_when_unknown_and_flag_true():
    """_ensure_vlan synthesizes a stub VLAN when the VID is unknown and the flag is True."""
    cache: dict = {}
    new_stubs: list = []
    vlan = _ensure_vlan(99, cache, Defaults(), Options(create_unknown_vlans=True), new_stubs)
    assert vlan.vid == 99
    assert vlan.name == "VLAN99"
    assert len(new_stubs) == 1
    assert new_stubs[0].vid == 99
    assert new_stubs[0].name == "VLAN99"
    assert cache[99].vid == 99


def test_ensure_vlan_returns_none_when_unknown_and_flag_false():
    """_ensure_vlan returns None when the VID is unknown and create_unknown_vlans is False."""
    cache: dict = {}
    new_stubs: list = []
    vlan = _ensure_vlan(99, cache, Defaults(), Options(create_unknown_vlans=False), new_stubs)
    assert vlan is None
    assert new_stubs == []
    assert 99 not in cache


def _make_iface_entity(name: str) -> Entity:
    """Build a minimal Interface Entity for tests."""
    return Entity(
        interface=Interface(
            device=Device(name="sw1"),
            name=name,
            type="1000base-t",
        )
    )


def test_apply_interface_vlans_access():
    """Access mode sets Interface.mode='access' with untagged_vlan, no tagged."""
    entities = [_make_iface_entity("Gi1/0/1")]
    defaults = Defaults()
    options = Options()
    cache = _build_vlan_cache({"10": {"name": "DATA"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/1": {"mode": "access", "tagged": [], "untagged": 10}},
        cache, defaults, options, new_stubs,
    )
    iface = entities[0].interface
    assert iface.mode == "access"
    assert iface.untagged_vlan.vid == 10
    assert list(iface.tagged_vlans) == []
    assert new_stubs == []


def test_apply_interface_vlans_trunk_with_native():
    """Trunk mode maps to Interface.mode='tagged' with native + tagged list."""
    entities = [_make_iface_entity("Gi1/0/24")]
    defaults = Defaults()
    options = Options()
    cache = _build_vlan_cache(
        {"1": {"name": "default"}, "10": {"name": "DATA"}, "20": {"name": "VOICE"}},
        defaults,
    )
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/24": {"mode": "trunk", "tagged": [10, 20], "untagged": 1}},
        cache, defaults, options, new_stubs,
    )
    iface = entities[0].interface
    assert iface.mode == "tagged"
    assert iface.untagged_vlan.vid == 1
    assert sorted(v.vid for v in iface.tagged_vlans) == [10, 20]


def test_apply_interface_vlans_drops_native_from_tagged_defensively():
    """If a driver leaks the native VID into 'tagged', it must be filtered out."""
    entities = [_make_iface_entity("Gi1/0/24")]
    defaults = Defaults()
    cache = _build_vlan_cache({"1": {"name": "default"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/24": {"mode": "trunk", "tagged": [1, 10], "untagged": 1}},
        cache, defaults, Options(), new_stubs,
    )
    iface = entities[0].interface
    assert sorted(v.vid for v in iface.tagged_vlans) == [10]


def test_apply_interface_vlans_routed_no_op():
    """Routed mode leaves Interface.mode/untagged_vlan/tagged_vlans untouched."""
    entities = [_make_iface_entity("Gi1/0/2")]
    defaults = Defaults()
    cache = {}
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/2": {"mode": "routed", "tagged": [], "untagged": None}},
        cache, defaults, Options(), new_stubs,
    )
    iface = entities[0].interface
    assert iface.mode == ""
    assert not iface.HasField("untagged_vlan")
    assert list(iface.tagged_vlans) == []


def test_apply_interface_vlans_unknown_vid_creates_stub():
    """Unknown tagged VIDs are stubbed when create_unknown_vlans is True."""
    entities = [_make_iface_entity("Gi1/0/24")]
    defaults = Defaults()
    cache = _build_vlan_cache({"1": {"name": "default"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/24": {"mode": "trunk", "tagged": [99], "untagged": 1}},
        cache, defaults, Options(create_unknown_vlans=True), new_stubs,
    )
    iface = entities[0].interface
    assert sorted(v.vid for v in iface.tagged_vlans) == [99]
    assert [s.vid for s in new_stubs] == [99]


def test_apply_interface_vlans_unknown_vid_dropped_when_flag_false():
    """Unknown tagged VIDs are dropped (no association, no stub) when flag is False."""
    entities = [_make_iface_entity("Gi1/0/24")]
    defaults = Defaults()
    cache = _build_vlan_cache({"1": {"name": "default"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/24": {"mode": "trunk", "tagged": [99], "untagged": 1}},
        cache, defaults, Options(create_unknown_vlans=False), new_stubs,
    )
    iface = entities[0].interface
    assert list(iface.tagged_vlans) == []
    assert new_stubs == []


def test_apply_interface_vlans_iface_not_in_entities_is_skipped():
    """Driver-returned interface names not present in emitted entities are skipped."""
    entities = [_make_iface_entity("Gi1/0/1")]
    defaults = Defaults()
    cache = _build_vlan_cache({"10": {"name": "DATA"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi9/9/9": {"mode": "access", "tagged": [], "untagged": 10}},
        cache, defaults, Options(), new_stubs,
    )
    iface = entities[0].interface
    assert iface.mode == ""
    assert not iface.HasField("untagged_vlan")


def test_apply_interface_vlans_handles_empty_input():
    """Empty interfaces_vlans dict is a no-op."""
    entities = [_make_iface_entity("Gi1/0/1")]
    new_stubs: list = []
    apply_interface_vlans(entities, {}, {}, Defaults(), Options(), new_stubs)
    assert new_stubs == []


def test_translate_data_emits_interface_vlan_associations():
    """translate_data() applies interface↔VLAN associations and emits stub VLANs."""
    data = {
        "driver": "ios",
        "device": {
            "hostname": "sw1",
            "vendor": "Cisco",
            "model": "C9300",
            "os_version": "17.6",
            "serial_number": "ABC123",
            "uptime": 1000,
            "interface_list": ["Gi1/0/1", "Gi1/0/24"],
            "fqdn": "sw1.example.com",
        },
        "interface": {
            "Gi1/0/1": {"is_up": True, "is_enabled": True, "description": "",
                         "last_flapped": 0.0, "mtu": 1500, "speed": 1000, "mac_address": ""},
            "Gi1/0/24": {"is_up": True, "is_enabled": True, "description": "",
                          "last_flapped": 0.0, "mtu": 1500, "speed": 1000, "mac_address": ""},
        },
        "interface_ip": {},
        "vlan": {"1": {"name": "default"}, "10": {"name": "DATA"}},
        "interfaces_vlans": {
            "Gi1/0/1":  {"mode": "access", "tagged": [], "untagged": 10},
            "Gi1/0/24": {"mode": "trunk",  "tagged": [10, 99], "untagged": 1},
        },
        "defaults": Defaults(),
        "options": Options(),
    }

    entities = list(translate_data(data))

    iface_by_name = {
        e.interface.name: e.interface
        for e in entities if e.HasField("interface")
    }
    assert iface_by_name["Gi1/0/1"].mode == "access"
    assert iface_by_name["Gi1/0/1"].untagged_vlan.vid == 10
    assert iface_by_name["Gi1/0/24"].mode == "tagged"
    assert iface_by_name["Gi1/0/24"].untagged_vlan.vid == 1
    assert sorted(v.vid for v in iface_by_name["Gi1/0/24"].tagged_vlans) == [10, 99]

    vlan_vids = sorted(e.vlan.vid for e in entities if e.HasField("vlan"))
    assert 99 in vlan_vids, "stub VLAN(vid=99) must be emitted alongside known VLANs"


def test_apply_interface_vlans_skips_non_int_untagged():
    """Non-int untagged value (driver bug) is silently dropped, not raised."""
    entities = [_make_iface_entity("Gi1/0/1")]
    defaults = Defaults()
    cache = _build_vlan_cache({"10": {"name": "DATA"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/1": {"mode": "access", "tagged": [], "untagged": "not-a-vid"}},
        cache, defaults, Options(), new_stubs,
    )
    iface = entities[0].interface
    assert iface.mode == "access"
    assert not iface.HasField("untagged_vlan")
    assert new_stubs == []


def test_apply_interface_vlans_filters_out_of_range_tagged_vids():
    """Tagged VIDs outside 1..4094 are dropped (defensive)."""
    entities = [_make_iface_entity("Gi1/0/24")]
    defaults = Defaults()
    cache = _build_vlan_cache({"1": {"name": "default"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/24": {"mode": "trunk", "tagged": [10, 0, 5000, "bad", 99], "untagged": 1}},
        cache, defaults, Options(create_unknown_vlans=True), new_stubs,
    )
    iface = entities[0].interface
    # Only 10 and 99 survive (0 out-of-range, 5000 out-of-range, "bad" non-int)
    assert sorted(v.vid for v in iface.tagged_vlans) == [10, 99]


def test_apply_interface_vlans_handles_non_list_tagged():
    """Non-list 'tagged' value (driver bug) is treated as empty, not raised."""
    entities = [_make_iface_entity("Gi1/0/1")]
    defaults = Defaults()
    cache = _build_vlan_cache({"10": {"name": "DATA"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/1": {"mode": "access", "tagged": None, "untagged": 10}},
        cache, defaults, Options(), new_stubs,
    )
    iface = entities[0].interface
    assert iface.mode == "access"
    assert iface.untagged_vlan.vid == 10
    assert list(iface.tagged_vlans) == []


def test_apply_interface_vlans_trunk_all_maps_to_tagged_all():
    """mode=trunk-all from the driver maps to NetBox 'tagged-all'."""
    entities = [_make_iface_entity("Gi1/0/48")]
    defaults = Defaults()
    cache = _build_vlan_cache({"99": {"name": "MGMT"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/48": {"mode": "trunk-all", "tagged": [], "untagged": 99}},
        cache, defaults, Options(), new_stubs,
    )
    iface = entities[0].interface
    assert iface.mode == "tagged-all"
    assert iface.untagged_vlan.vid == 99
    assert list(iface.tagged_vlans) == []


def test_apply_interface_vlans_is_idempotent_on_tagged_vlans():
    """Calling apply_interface_vlans twice doesn't duplicate tagged VLANs."""
    entities = [_make_iface_entity("Gi1/0/24")]
    defaults = Defaults()
    cache = _build_vlan_cache(
        {"1": {"name": "default"}, "10": {"name": "DATA"}, "20": {"name": "VOICE"}},
        defaults,
    )
    new_stubs: list = []
    payload = {"Gi1/0/24": {"mode": "trunk", "tagged": [10, 20], "untagged": 1}}
    apply_interface_vlans(entities, payload, cache, defaults, Options(), new_stubs)
    apply_interface_vlans(entities, payload, cache, defaults, Options(), new_stubs)
    iface = entities[0].interface
    # Without the clear-before-append, this would be [10, 10, 20, 20].
    assert sorted(v.vid for v in iface.tagged_vlans) == [10, 20]


def test_apply_interface_vlans_clears_stale_untagged_when_new_has_none():
    """Switching an interface from access (untagged=10) to a trunk with no native clears the stale link."""
    entities = [_make_iface_entity("Gi1/0/1")]
    defaults = Defaults()
    cache = _build_vlan_cache({"10": {"name": "DATA"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {"Gi1/0/1": {"mode": "access", "tagged": [], "untagged": 10}},
        cache, defaults, Options(), new_stubs,
    )
    iface = entities[0].interface
    assert iface.HasField("untagged_vlan")
    apply_interface_vlans(
        entities,
        {"Gi1/0/1": {"mode": "trunk", "tagged": [10], "untagged": None}},
        cache, defaults, Options(), new_stubs,
    )
    assert not iface.HasField("untagged_vlan")
    assert sorted(v.vid for v in iface.tagged_vlans) == [10]


def test_apply_interface_vlans_skips_non_dict_payload(caplog):
    """A non-dict interfaces_vlans payload (e.g. list) is logged and skipped, not raised."""
    import logging
    entities = [_make_iface_entity("Gi1/0/1")]
    new_stubs: list = []
    with caplog.at_level(logging.WARNING):
        apply_interface_vlans(
            entities,
            ["malformed", "list"],
            {}, Defaults(), Options(), new_stubs,
        )
    iface = entities[0].interface
    assert iface.mode == ""
    assert not iface.HasField("untagged_vlan")
    assert list(iface.tagged_vlans) == []
    assert any("not a dict" in r.message for r in caplog.records)


def test_apply_interface_vlans_skips_non_dict_per_entry(caplog):
    """A non-dict value for a single interface key is logged and skipped."""
    import logging
    entities = [_make_iface_entity("Gi1/0/1"), _make_iface_entity("Gi1/0/2")]
    defaults = Defaults()
    cache = _build_vlan_cache({"10": {"name": "DATA"}}, defaults)
    new_stubs: list = []
    with caplog.at_level(logging.WARNING):
        apply_interface_vlans(
            entities,
            {
                "Gi1/0/1": {"mode": "access", "tagged": [], "untagged": 10},
                "Gi1/0/2": "broken-string-value",
            },
            cache, defaults, Options(), new_stubs,
        )
    iface1 = entities[0].interface
    iface2 = entities[1].interface
    # The good entry processed normally
    assert iface1.mode == "access"
    assert iface1.untagged_vlan.vid == 10
    # The bad entry left untouched
    assert iface2.mode == ""
    assert not iface2.HasField("untagged_vlan")
    # Warning logged
    assert any(
        "is not a dict" in r.message and "Gi1/0/2" in r.message
        for r in caplog.records
    )


def test_apply_interface_vlans_skips_none_per_entry(caplog):
    """A None value for a single interface key is logged and skipped (treated as malformed)."""
    import logging
    entities = [_make_iface_entity("Gi1/0/1")]
    defaults = Defaults()
    cache = {}
    new_stubs: list = []
    with caplog.at_level(logging.WARNING):
        apply_interface_vlans(
            entities,
            {"Gi1/0/1": None},
            cache, defaults, Options(), new_stubs,
        )
    iface = entities[0].interface
    assert iface.mode == ""
    assert not iface.HasField("untagged_vlan")
    assert any("is not a dict" in r.message for r in caplog.records)


def test_apply_interface_vlans_routed_leaves_stale_state_untouched():
    """
    Documented limitation: routed mode is a no-op.

    Diode plugin's PATCH semantics don't propagate field clears, so prior
    VLAN associations remain in NetBox. Operators must clear manually
    until Diode supports explicit field clearing.
    """
    from netboxlabs.diode.sdk.ingester import VLAN
    entities = [_make_iface_entity("Gi1/0/1")]
    iface = entities[0].interface
    iface.mode = "access"
    iface.untagged_vlan.CopyFrom(VLAN(vid=10, name="DATA"))
    iface.tagged_vlans.append(VLAN(vid=20, name="OTHER"))

    apply_interface_vlans(
        entities,
        {"Gi1/0/1": {"mode": "routed", "tagged": [], "untagged": None}},
        {}, Defaults(), Options(), [],
    )

    # Stale state intentionally preserved (see comment in apply_interface_vlans).
    assert iface.mode == "access"
    assert iface.untagged_vlan.vid == 10
    assert [v.vid for v in iface.tagged_vlans] == [20]


def test_apply_interface_vlans_unknown_mode_leaves_stale_state_untouched():
    """Same documented limitation for unknown driver modes."""
    from netboxlabs.diode.sdk.ingester import VLAN
    entities = [_make_iface_entity("Gi1/0/1")]
    iface = entities[0].interface
    iface.mode = "tagged"
    iface.untagged_vlan.CopyFrom(VLAN(vid=1))
    iface.tagged_vlans.append(VLAN(vid=10))

    apply_interface_vlans(
        entities,
        {"Gi1/0/1": {"mode": "private-vlan-host", "tagged": [], "untagged": None}},
        {}, Defaults(), Options(), [],
    )
    assert iface.mode == "tagged"
    assert iface.untagged_vlan.vid == 1
    assert [v.vid for v in iface.tagged_vlans] == [10]


def test_apply_interface_vlans_clears_stale_untagged_when_create_unknown_vlans_false():
    """
    Verify stale untagged_vlan is cleared when stub creation is refused.

    When create_unknown_vlans=False AND the new untagged VID is unknown,
    a previously-set untagged_vlan on the entity is cleared at the proto layer.
    """
    from netboxlabs.diode.sdk.ingester import VLAN
    entities = [_make_iface_entity("Gi1/0/1")]
    iface = entities[0].interface
    # Pre-populate as if a prior translation left an untagged_vlan link.
    iface.untagged_vlan.CopyFrom(VLAN(vid=10, name="DATA"))
    assert iface.untagged_vlan.vid == 10

    apply_interface_vlans(
        entities,
        # New payload references vid=99, which isn't in the cache.
        # With create_unknown_vlans=False, _ensure_vlan returns None and the
        # untagged_vlan should be cleared at the proto level.
        {"Gi1/0/1": {"mode": "access", "tagged": [], "untagged": 99}},
        {},
        Defaults(),
        Options(create_unknown_vlans=False),
        [],
    )

    iface = entities[0].interface
    assert iface.mode == "access"
    assert not iface.HasField("untagged_vlan"), (
        "untagged_vlan must be cleared when the new VID is unknown and "
        "create_unknown_vlans=False — otherwise the Interface keeps a stale link."
    )


def test_apply_interface_vlans_rejects_bool_vids():
    """
    Booleans pretending to be VIDs (Python: bool is a subclass of int) are rejected.

    Without an explicit isinstance(bool) guard in _safe_vid, True would coerce
    to int(1) and silently associate VLAN 1.
    """
    entities = [_make_iface_entity("Gi1/0/1")]
    defaults = Defaults()
    cache = _build_vlan_cache({"1": {"name": "default"}}, defaults)
    new_stubs: list = []
    apply_interface_vlans(
        entities,
        {
            "Gi1/0/1": {
                "mode": "trunk",
                "tagged": [True, False, 10],  # bool entries should be dropped
                "untagged": True,             # bool untagged should also be rejected
            },
        },
        cache, defaults, Options(), new_stubs,
    )
    iface = entities[0].interface
    assert iface.mode == "tagged"
    # untagged was True (rejected) → no untagged_vlan should be set
    assert not iface.HasField("untagged_vlan")
    # tagged was [True, False, 10] → only 10 survives the bool rejection
    assert sorted(v.vid for v in iface.tagged_vlans) == [10]


def test_translate_data_subinterface_becomes_virtual_with_parent(
    sample_device_info, sample_defaults
):
    """
    Sub-interface names translate to NetBox 'virtual' interfaces with parent set.

    Any IPs in interface_ip attach to the sub-interface, not the parent — this
    pins the driver↔translator contract for the Nokia SR Linux model
    (parent carries no IPs; subs carry IPs). Same contract applies to
    Junos-style sub-interfaces.
    """
    interfaces = {
        "mgmt0": {
            "is_up": True,
            "is_enabled": True,
            "description": "",
            "last_flapped": -1.0,
            "mtu": -1,
            "speed": 1000.0,
            "mac_address": "",
        },
        "mgmt0.0": {
            "is_up": True,
            "is_enabled": True,
            "description": "",
            "last_flapped": -1.0,
            "mtu": -1,
            "speed": -1.0,
            "mac_address": "",
        },
    }
    interfaces_ip = {
        "mgmt0.0": {
            "ipv4": {"172.24.0.101": {"prefix_length": 24}},
            "ipv6": {"fe80::42:acff:fe12:6": {"prefix_length": 64}},
        },
    }
    data = {
        "device": sample_device_info,
        "interface": interfaces,
        "interface_ip": interfaces_ip,
        "driver": "nokia_srl",
        "defaults": sample_defaults,
    }

    entities = list(translate_data(data))

    iface_entities = [e for e in entities if e.HasField("interface")]
    ip_entities = [e for e in entities if e.HasField("ip_address")]

    by_name = {e.interface.name: e.interface for e in iface_entities}
    assert "mgmt0" in by_name, "physical parent interface must be emitted"
    assert "mgmt0.0" in by_name, "sub-interface must be emitted as its own entity"

    parent_iface = by_name["mgmt0"]
    sub_iface = by_name["mgmt0.0"]

    assert sub_iface.type == "virtual", (
        "sub-interfaces must be typed 'virtual' so NetBox renders them under the parent"
    )
    assert sub_iface.parent.name == "mgmt0", (
        "sub-interface must carry a parent reference to its physical interface"
    )
    assert parent_iface.parent.name == "", (
        "physical parent must not carry a parent reference (no self-loops)"
    )

    ip_targets = {
        ip.ip_address.assigned_object_interface.name for ip in ip_entities
    }
    assert ip_targets, "expected at least one IP address entity"
    assert ip_targets == {"mgmt0.0"}, (
        "all IPs must be assigned to the sub-interface, not the physical parent"
    )


def _emit_ips_for(
    sample_device_info,
    sample_interface_info,
    sample_defaults,
    interfaces_ip,
    options=None,
):
    """Translate one interface's IPs and split the result into prefixes and addresses."""
    device = translate_device(sample_device_info, sample_defaults)
    interface = translate_interface(
        device,
        "GigabitEthernet0/0/1",
        sample_interface_info["GigabitEthernet0/0/1"],
        sample_defaults,
    )
    entities = list(
        translate_interface_ips(
            interface, interfaces_ip, sample_defaults, options=options
        )
    )
    prefixes = [e.prefix.prefix for e in entities if e.HasField("prefix")]
    addresses = [e.ip_address.address for e in entities if e.HasField("ip_address")]
    return prefixes, addresses


@pytest.mark.parametrize(
    ("family", "ip", "prefix_length", "address", "reason"),
    [
        ("ipv4", "10.0.0.1", 32, "10.0.0.1/32", "IPv4 host prefix"),
        ("ipv6", "2001:db8::5", 128, "2001:db8::5/128", "IPv6 host prefix"),
        (
            "ipv6",
            "fe80::5a86:70f0:a8:e47f",
            128,
            "fe80::5a86:70f0:a8:e47f/128",
            "link-local, host length",
        ),
        ("ipv6", "fe80::42:acff:fe12:6", 64, "fe80::42:acff:fe12:6/64", "link-local, /64"),
        ("ipv6", "fe80::1", 10, "fe80::1/10", "link-local at its own /10"),
        # A mask wider than /10 widens the network out of fe80::/10, so the
        # network is no longer link-local by containment even though the
        # address plainly is: fe80::1/9 -> fe80::/9, fe80::1/8 -> fe00::/8.
        # Judging the network instead of the address emitted an enormous
        # container prefix for a link-local address.
        ("ipv6", "fe80::1", 9, "fe80::1/9", "link-local, mask wider than /10"),
        ("ipv6", "fe80::1", 8, "fe80::1/8", "link-local normalizing to fe00::/8"),
        ("ipv6", "fe80::1", 1, "fe80::1/1", "link-local with an absurd /1 mask"),
    ],
)
def test_no_prefix_derived_for_host_and_ipv6_link_local(
    sample_device_info,
    sample_interface_info,
    sample_defaults,
    family,
    ip,
    prefix_length,
    address,
    reason,
):
    """
    Host prefixes and IPv6 link-locals must not become Prefix entities.

    A /32 or /128 "prefix" only restates the address, and an fe80:: prefix is
    per-link noise. Both produced thousands of spurious Assurance deviations.
    The IPAddress entity is still emitted so the interface stays documented.
    """
    interfaces_ip = {
        "GigabitEthernet0/0/1": {family: {ip: {"prefix_length": prefix_length}}}
    }
    prefixes, addresses = _emit_ips_for(
        sample_device_info, sample_interface_info, sample_defaults, interfaces_ip
    )

    assert prefixes == [], f"no prefix may be derived from a {reason}, got {prefixes}"
    assert addresses == [address], (
        f"the IPAddress for a {reason} must still be emitted, got {addresses}"
    )


def test_prefix_still_derived_when_no_prefix_length_reported(
    sample_device_info, sample_interface_info, sample_defaults
):
    """
    A driver that omits prefix_length defaults to /32 or /128 — still suppressed.

    This is the path that made the behavior so noisy: any driver not reporting a
    mask silently produced a host prefix for every address it found.
    """
    interfaces_ip = {
        "GigabitEthernet0/0/1": {
            "ipv4": {"10.0.0.1": {}},
            "ipv6": {"2001:db8::5": {}},
        }
    }
    prefixes, addresses = _emit_ips_for(
        sample_device_info, sample_interface_info, sample_defaults, interfaces_ip
    )

    assert prefixes == [], f"missing prefix_length must not yield a host prefix, got {prefixes}"
    assert sorted(addresses) == ["10.0.0.1/32", "2001:db8::5/128"]


@pytest.mark.parametrize(
    ("family", "ip", "prefix_length", "expected_prefix"),
    [
        ("ipv4", "192.0.2.1", 24, "192.0.2.0/24"),
        # /31 is a real point-to-point subnet, not a host route.
        ("ipv4", "10.1.1.0", 31, "10.1.1.0/31"),
        # IPv4 link-local and the loopback net are ordinary networks by mask
        # and stay in scope for emission — only IPv6 link-local is suppressed.
        ("ipv4", "169.254.10.5", 16, "169.254.0.0/16"),
        ("ipv4", "127.0.0.1", 8, "127.0.0.0/8"),
        ("ipv6", "2001:db8::1", 64, "2001:db8::/64"),
        # A global-unicast /127 p2p link is not a host prefix.
        ("ipv6", "2001:db8::2", 127, "2001:db8::2/127"),
    ],
)
def test_ordinary_prefixes_are_still_derived(
    sample_device_info,
    sample_interface_info,
    sample_defaults,
    family,
    ip,
    prefix_length,
    expected_prefix,
):
    """Real subnets keep producing Prefix entities — the fix is narrowly scoped."""
    interfaces_ip = {
        "GigabitEthernet0/0/1": {family: {ip: {"prefix_length": prefix_length}}}
    }
    prefixes, _ = _emit_ips_for(
        sample_device_info, sample_interface_info, sample_defaults, interfaces_ip
    )

    assert prefixes == [expected_prefix]


def test_suppressed_prefix_does_not_drop_sibling_prefixes(
    sample_device_info, sample_interface_info, sample_defaults
):
    """A dual-stack interface keeps its real prefix while the link-local is skipped."""
    interfaces_ip = {
        "GigabitEthernet0/0/1": {
            "ipv4": {"172.24.0.101": {"prefix_length": 24}},
            "ipv6": {
                "2001:db8::1": {"prefix_length": 64},
                "fe80::42:acff:fe12:6": {"prefix_length": 64},
            },
        }
    }
    prefixes, addresses = _emit_ips_for(
        sample_device_info, sample_interface_info, sample_defaults, interfaces_ip
    )

    assert sorted(prefixes) == ["172.24.0.0/24", "2001:db8::/64"]
    assert len(addresses) == 3, "every address is still emitted, including the fe80::"


@pytest.mark.parametrize(
    ("family", "ip", "prefix_length", "expected_prefix"),
    [
        ("ipv4", "10.0.0.1", 32, "10.0.0.1/32"),
        ("ipv6", "2001:db8::5", 128, "2001:db8::5/128"),
    ],
)
def test_emit_host_prefixes_restores_host_prefixes(
    sample_device_info,
    sample_interface_info,
    sample_defaults,
    family,
    ip,
    prefix_length,
    expected_prefix,
):
    """
    emit_host_prefixes: true opts back in to /32 and /128 prefixes.

    Some operators do track loopback /32s as NetBox prefixes; without this
    option they had no way to keep them.
    """
    interfaces_ip = {
        "GigabitEthernet0/0/1": {family: {ip: {"prefix_length": prefix_length}}}
    }
    prefixes, _ = _emit_ips_for(
        sample_device_info,
        sample_interface_info,
        sample_defaults,
        interfaces_ip,
        options=Options(emit_host_prefixes=True),
    )

    assert prefixes == [expected_prefix]


@pytest.mark.parametrize(
    ("ip", "prefix_length"),
    [
        ("fe80::5a86:70f0:a8:e47f", 128),
        ("fe80::42:acff:fe12:6", 64),
        # The wide-mask cases must stay suppressed with the opt-in on too.
        ("fe80::1", 9),
        ("fe80::1", 8),
    ],
)
def test_emit_host_prefixes_does_not_resurrect_ipv6_link_local(
    sample_device_info,
    sample_interface_info,
    sample_defaults,
    ip,
    prefix_length,
):
    """
    emit_host_prefixes must not bring back fe80:: prefixes.

    An fe80::x/128 address is a link-local that happens to carry host length,
    not a loopback an operator wants tracked. The link-local rule is therefore
    ungated by the option; if it were gated, opting in to host prefixes would
    silently restore the exact noise this suppresses.
    """
    interfaces_ip = {
        "GigabitEthernet0/0/1": {"ipv6": {ip: {"prefix_length": prefix_length}}}
    }
    prefixes, addresses = _emit_ips_for(
        sample_device_info,
        sample_interface_info,
        sample_defaults,
        interfaces_ip,
        options=Options(emit_host_prefixes=True),
    )

    assert prefixes == [], (
        f"emit_host_prefixes must not resurrect the link-local {ip}/{prefix_length}"
    )
    assert addresses == [f"{ip}/{prefix_length}"]


def test_emit_host_prefixes_defaults_to_off(
    sample_device_info, sample_interface_info, sample_defaults
):
    """An explicit Options() with no override still suppresses host prefixes."""
    interfaces_ip = {
        "GigabitEthernet0/0/1": {"ipv4": {"10.0.0.1": {"prefix_length": 32}}}
    }
    prefixes, addresses = _emit_ips_for(
        sample_device_info,
        sample_interface_info,
        sample_defaults,
        interfaces_ip,
        options=Options(),
    )

    assert Options().emit_host_prefixes is False
    assert prefixes == []
    assert addresses == ["10.0.0.1/32"]


def test_emit_host_prefixes_keeps_real_subnets_untouched(
    sample_device_info, sample_interface_info, sample_defaults
):
    """The opt-in only adds host prefixes; ordinary subnets are unaffected."""
    interfaces_ip = {
        "GigabitEthernet0/0/1": {
            "ipv4": {"172.24.0.101": {"prefix_length": 24}, "10.0.0.1": {"prefix_length": 32}},
            "ipv6": {"fe80::42:acff:fe12:6": {"prefix_length": 64}},
        }
    }
    prefixes, _ = _emit_ips_for(
        sample_device_info,
        sample_interface_info,
        sample_defaults,
        interfaces_ip,
        options=Options(emit_host_prefixes=True),
    )

    assert sorted(prefixes) == ["10.0.0.1/32", "172.24.0.0/24"]
