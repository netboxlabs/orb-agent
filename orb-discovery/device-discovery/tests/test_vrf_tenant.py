#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""A configured VRF carries its own tenant, and the matcher stubs keep it."""

import re

import pytest
from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from pydantic import ValidationError

from device_discovery.policy.models import (
    Config,
    Defaults,
    IpamParameters,
    Napalm,
    Policy,
    PrefixParameters,
    TenantParameters,
    VlanParameters,
    VrfParameters,
    check_vrf_tenants,
)
from device_discovery.policy.runner import merge_override_defaults
from device_discovery.policy.tenants import slug
from device_discovery.stubs import (
    _ip_match_stub,
    _same_primary_ip,
    _vrf_match_stub,
    vrf_match_key,
)
from device_discovery.translate import translate_vrf


def _tenant(name="acme", group=None, **fields):
    tenant = pb.Tenant(name=name, **fields)
    if group:
        tenant.group.CopyFrom(pb.TenantGroup(name=group))
    return tenant


def test_vrf_parameters_accept_tenant_string_or_mapping():
    """vrf.tenant takes the same string or {name, group} form as defaults tenants."""
    assert VrfParameters(name="example-vrf", tenant="acme").tenant == "acme"
    vrf = VrfParameters.model_validate(
        {"name": "example-vrf", "tenant": {"name": "acme", "group": "customers"}}
    )
    assert vrf.tenant == TenantParameters(name="acme", group="customers")


def test_vrf_parameters_refuse_unknown_key():
    """A misspelt key would leave the VRF without the setting and match the wrong VRF."""
    with pytest.raises(ValidationError, match="tennant"):
        VrfParameters.model_validate({"name": "example-vrf", "tennant": "acme"})


def test_vrf_tenant_refuses_unknown_key():
    """A misspelt group would leave the VRF matching an ungrouped tenant; defaults.tenant stays lenient."""
    with pytest.raises(ValidationError, match="grup"):
        VrfParameters.model_validate({"name": "example-vrf", "tenant": {"name": "acme", "grup": "customers"}})
    assert Defaults.model_validate({"tenant": {"name": "acme", "grup": "customers"}}).tenant.name == "acme"


def test_translate_vrf_carries_tenant_mapping():
    """The tenant map, group included, reaches the VRF."""
    vrf = translate_vrf(
        VrfParameters(
            name="example-vrf",
            tenant=TenantParameters(name="acme", group="customers", description="d"),
        )
    )
    assert vrf.tenant.name == "acme"
    assert vrf.tenant.group.name == "customers"
    assert vrf.tenant.description == "d"


def test_translate_vrf_carries_tenant_string():
    """A tenant name alone reaches the VRF without a group."""
    vrf = translate_vrf(VrfParameters(name="example-vrf", tenant="acme"))
    assert vrf.tenant.name == "acme"
    assert not vrf.tenant.HasField("group")


def test_translate_vrf_without_tenant():
    """A VRF without its own tenant is sent without one."""
    assert not translate_vrf(VrfParameters(name="example-vrf")).HasField("tenant")


def test_vrf_match_stub_keeps_tenant_identity_only():
    """The stub resolves to the same VRF as the rich one, without its extra fields."""
    rich = pb.VRF(name="example-vrf", description="d")
    rich.tenant.CopyFrom(_tenant(group="customers", description="td", tags=[pb.Tag(name="t")]))
    assert _vrf_match_stub(rich) == pb.VRF(name="example-vrf", tenant=_tenant(group="customers"))


def test_vrf_match_stub_keeps_ungrouped_tenant():
    """An ungrouped tenant and the rd both survive into the stub."""
    rich = pb.VRF(name="example-vrf", rd="65000:1", tenant=_tenant())
    assert _vrf_match_stub(rich) == pb.VRF(name="example-vrf", rd="65000:1", tenant=_tenant())


def test_vrf_match_stub_without_tenant():
    """A tenant-less VRF gets a tenant-less stub."""
    assert not _vrf_match_stub(pb.VRF(name="example-vrf")).HasField("tenant")


def test_ip_match_stub_keeps_vrf_tenant():
    """The IP stub embeds a VRF stub that keeps the tenant."""
    rich = pb.IPAddress(address="192.0.2.1/24")
    rich.vrf.CopyFrom(pb.VRF(name="example-vrf", tenant=_tenant(group="customers")))
    assert _ip_match_stub(rich).vrf.tenant == _tenant(group="customers")


def test_vrf_match_key_without_rd_includes_tenant():
    """Without an rd, the tenant and its group are part of the VRF identity."""
    plain = vrf_match_key(pb.VRF(name="example-vrf"))
    owned = vrf_match_key(pb.VRF(name="example-vrf", tenant=_tenant()))
    grouped = vrf_match_key(pb.VRF(name="example-vrf", tenant=_tenant(group="customers")))
    assert len({plain, owned, grouped}) == 3
    assert owned == vrf_match_key(pb.VRF(name="example-vrf", description="d", tenant=_tenant(description="td")))


def test_vrf_match_key_with_rd_ignores_tenant():
    """With an rd the plugin matches by rd alone, so the tenant is not identity."""
    assert vrf_match_key(pb.VRF(name="example-vrf", rd="65000:1", tenant=_tenant())) == vrf_match_key(
        pb.VRF(name="other-vrf", rd="65000:1")
    )


def test_same_primary_ip_distinguishes_vrf_tenant():
    """One address in same-named VRFs of different tenants is two IP objects."""
    def ip(vrf):
        address = pb.IPAddress(address="192.0.2.1/24")
        address.vrf.CopyFrom(vrf)
        return address

    owned = ip(pb.VRF(name="example-vrf", tenant=_tenant()))
    assert _same_primary_ip(owned, ip(pb.VRF(name="example-vrf", tenant=_tenant())))
    assert not _same_primary_ip(owned, ip(pb.VRF(name="example-vrf")))
    assert not _same_primary_ip(owned, ip(pb.VRF(name="example-vrf", tenant=_tenant(group="customers"))))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Acme Corp", "acme-corp"),
        ("Acme-Corp", "acme-corp"),
        ("Acme.Corp", "acmecorp"),
        ("Acme_Corp", "acme_corp"),
        (" _Acme_ ", "acme"),
        ("a  -- b", "a-b"),
        ("Café", "cafe"),
        ("日本", ""),
    ],
)
def test_slug_matches_django_slugify(value, expected):
    """Diode finds a tenant by Django's slugify of its name; the port must agree."""
    assert slug(value) == expected


def _defaults(ip_tenant=None, vrf_tenant=None, tenant=None):
    return Defaults(
        tenant=tenant,
        ipaddress=IpamParameters(
            tenant=ip_tenant, vrf=VrfParameters(name="example-vrf", tenant=vrf_tenant)
        ),
    )


ACME = TenantParameters(name="acme", group="customers", description="d", comments="c", tags=["a"])
DIFFERS = "write it differently"


@pytest.mark.parametrize(
    ("ip_tenant", "vrf_tenant"),
    [
        pytest.param(ACME, ACME, id="identical"),
        pytest.param(ACME, TenantParameters(name="acme", group="customers"), id="fields on one side"),
        pytest.param(TenantParameters(name="acme", group="customers"), ACME, id="fields on the vrf side"),
        pytest.param(ACME, ACME.model_copy(update={"description": "d "}), id="description padded"),
        pytest.param(ACME, ACME.model_copy(update={"tags": ["a "]}), id="tag padded"),
        pytest.param(ACME, ACME.model_copy(update={"name": "acme "}), id="name padded"),
        pytest.param(ACME, ACME.model_copy(update={"group": "customers "}), id="group padded"),
        pytest.param("acme ", "acme", id="string padded"),
        pytest.param(ACME, TenantParameters(name="globex", group="partners", description="x"), id="other tenant"),
        pytest.param(
            TenantParameters(name="日本", description="x"),
            TenantParameters(name="中国", description="y"),
            id="names without a slug",
        ),
        pytest.param(TenantParameters(name=" ", group="customers"), TenantParameters(name=" "), id="blank names"),
        pytest.param(None, ACME, id="no ip tenant"),
    ],
)
def test_vrf_tenant_written_consistently_is_accepted(ip_tenant, vrf_tenant):
    """Copies Diode merges cleanly, or never merges, are accepted."""
    check_vrf_tenants(_defaults(ip_tenant, vrf_tenant))


@pytest.mark.parametrize(
    ("ip_tenant", "vrf_tenant", "message"),
    [
        pytest.param(ACME, ACME.model_copy(update={"description": "x"}), DIFFERS, id="description"),
        pytest.param(ACME, ACME.model_copy(update={"comments": "x"}), DIFFERS, id="comments"),
        pytest.param(ACME, ACME.model_copy(update={"tags": ["b"]}), DIFFERS, id="tags"),
        pytest.param(
            ACME.model_copy(update={"tags": ["a", "b"]}),
            ACME.model_copy(update={"tags": ["b", "a"]}),
            DIFFERS,
            id="tags reordered",
        ),
        pytest.param(ACME, ACME.model_copy(update={"description": "  "}), DIFFERS, id="blank description"),
        pytest.param(ACME, ACME.model_copy(update={"description": ""}), DIFFERS, id="empty description"),
        pytest.param(ACME, ACME.model_copy(update={"name": "Acme"}), DIFFERS, id="case"),
        pytest.param("Acme Corp", "Acme-Corp", DIFFERS, id="slug alike"),
        pytest.param("Café", "Cafe", DIFFERS, id="accent"),
        pytest.param(ACME, ACME.model_copy(update={"group": "partners"}), DIFFERS, id="other group"),
        pytest.param(ACME, ACME.model_copy(update={"group": None}), DIFFERS, id="ungrouped"),
        pytest.param(ACME, TenantParameters(name="globex", group="Customers"), "tenant group in two ways", id="group case"),
    ],
)
def test_vrf_tenant_written_two_ways_is_refused(ip_tenant, vrf_tenant, message):
    """Copies Diode would merge and then refuse, or rewrite every run, are refused."""
    with pytest.raises(ValueError, match=message):
        check_vrf_tenants(_defaults(ip_tenant, vrf_tenant))


def test_vrf_tenant_is_compared_with_every_tenant_default():
    """The device, prefix, VLAN and other VRF copies all reach Diode in full in one run."""
    clash = ACME.model_copy(update={"description": "x"})
    cases = {
        "defaults.tenant and defaults.ipaddress.vrf.tenant": Defaults(
            tenant=ACME, ipaddress=IpamParameters(vrf=VrfParameters(name="v", tenant=clash))
        ),
        "defaults.prefix.tenant and defaults.prefix.vrf_ipv6.tenant": Defaults(
            prefix=PrefixParameters(tenant=ACME, vrf_ipv6=VrfParameters(name="v", tenant=clash))
        ),
        "defaults.ipaddress.vrf_ipv4.tenant and defaults.vlan.tenant": Defaults(
            vlan=VlanParameters(tenant=ACME), ipaddress=IpamParameters(vrf_ipv4=VrfParameters(name="v", tenant=clash))
        ),
        "defaults.ipaddress.vrf.tenant and defaults.prefix.vrf.tenant": Defaults(
            ipaddress=IpamParameters(vrf=VrfParameters(name="v", tenant=ACME)),
            prefix=PrefixParameters(vrf=VrfParameters(name="v", tenant=clash)),
        ),
    }
    for paths, defaults in cases.items():
        with pytest.raises(ValueError, match=rf"{re.escape(paths)} name the same NetBox tenant"):
            check_vrf_tenants(defaults)


def test_pairs_without_a_vrf_tenant_are_left_alone():
    """Tenant defaults that clashed before VRF tenants existed still load."""
    check_vrf_tenants(
        Defaults(
            tenant=ACME,
            ipaddress=IpamParameters(tenant=ACME.model_copy(update={"description": "x"}), vrf="example-vrf"),
        )
    )


def _scope(hostname="192.0.2.10", **override):
    return Napalm(
        hostname=hostname,
        username="admin",
        password="secret",
        override_defaults=Defaults(**override) if override else None,
    )


def test_policy_refuses_a_clash_in_its_defaults():
    """A clash in the policy defaults is refused when the policy is parsed."""
    with pytest.raises(ValidationError, match=DIFFERS):
        Policy(config=Config(defaults=_defaults(ACME, ACME.model_copy(update={"description": "x"}))), scope=[_scope()])


def test_policy_refuses_an_override_that_clashes_once_merged():
    """The error names the target whose override_defaults clashes."""
    with pytest.raises(ValidationError, match=rf"192\.0\.2\.11, with its override_defaults: .*{DIFFERS}"):
        Policy(
            config=Config(defaults=Defaults(ipaddress=IpamParameters(tenant=ACME))),
            scope=[
                _scope("192.0.2.10"),
                _scope(
                    "192.0.2.11",
                    ipaddress=IpamParameters(
                        vrf=VrfParameters(name="example-vrf", tenant=ACME.model_copy(update={"description": "x"}))
                    ),
                ),
            ],
        )


def test_policy_accepts_an_override_consistent_once_merged():
    """An override is judged merged, not alone: a partial tenant there is fine."""
    Policy(
        config=Config(defaults=Defaults(ipaddress=IpamParameters(tenant=TenantParameters(name="acme", group="customers")))),
        scope=[
            _scope(
                ipaddress=IpamParameters(
                    tenant=TenantParameters(name="acme"),
                    vrf=VrfParameters(name="example-vrf", tenant=TenantParameters(name="acme", group="customers")),
                )
            )
        ],
    )


POLICY_VRF = VrfParameters(name="vrf-a", rd="65000:1", description="d", tenant=ACME)


def _merged_vrf(override_vrf):
    merged = merge_override_defaults(
        Defaults(ipaddress=IpamParameters(vrf=POLICY_VRF)),
        Defaults(ipaddress=IpamParameters(vrf=override_vrf)),
    )
    return merged.ipaddress.vrf


def test_override_naming_another_vrf_inherits_nothing():
    """A different VRF must not take the policy VRF's rd or tenant."""
    assert _merged_vrf(VrfParameters(name="vrf-b")) == VrfParameters(name="vrf-b")


def test_override_refining_the_policy_vrf_keeps_the_rest():
    """An override naming the same VRF refines it field by field."""
    assert _merged_vrf(VrfParameters.model_validate({"name": "vrf-a", "rd": "65000:2"})) == POLICY_VRF.model_copy(
        update={"rd": "65000:2"}
    )
    refined = merge_override_defaults(
        Defaults(ipaddress=IpamParameters(vrf=POLICY_VRF)),
        Defaults.model_validate({"ipaddress": {"vrf": {"name": "vrf-a", "tenant": {"name": "acme", "description": "x"}}}}),
    )
    assert refined.ipaddress.vrf.tenant == ACME.model_copy(update={"description": "x"})


def test_override_naming_another_vrf_tenant_inherits_nothing_from_it():
    """A different tenant must not take the policy VRF tenant's group or description."""
    merged = _merged_vrf(VrfParameters(name="vrf-a", tenant=TenantParameters(name="globex")))
    assert merged.tenant == TenantParameters(name="globex")
    assert merged.rd == "65000:1"


def test_vrf_tenant_with_mixed_key_types_is_refused_cleanly():
    """A non-string key is reported as a validation error, not a crash."""
    with pytest.raises(ValidationError, match="tenant has no"):
        VrfParameters.model_validate({"name": "example-vrf", "tenant": {"name": "acme", 1: "x", "grup": "y"}})


def test_override_string_naming_the_policy_vrf_keeps_it():
    """vrf: "vrf-a" adds nothing to the policy's vrf-a, so it must not drop its rd or tenant."""
    assert _merged_vrf("vrf-a") == POLICY_VRF
    assert _merged_vrf("vrf-a ") == POLICY_VRF, "names compare trimmed, as Diode does"
    assert _merged_vrf("vrf-b") == "vrf-b"
    assert _merged_vrf(VrfParameters(name="vrf-a ", description="x")) == POLICY_VRF.model_copy(
        update={"name": "vrf-a ", "description": "x"}
    ), "a padded map name refines too"


def test_override_with_an_empty_tenant_keeps_the_policy_tenant():
    """An empty name names nothing, so it neither replaces nor clears the policy's tenant."""
    assert merge_override_defaults(Defaults(tenant=ACME), Defaults(tenant="")).tenant == ACME


def test_override_naming_another_tenant_replaces_every_tenant_default():
    """An override naming an ungrouped tenant everywhere is consistent once merged."""
    globex = TenantParameters(name="globex")
    base = Defaults(
        tenant=ACME,
        ipaddress=IpamParameters(tenant=ACME, vrf=VrfParameters(name="vrf-a", tenant=ACME)),
        prefix=PrefixParameters(tenant=ACME),
        vlan=VlanParameters(tenant=ACME),
    )
    override = Defaults(
        tenant=globex,
        ipaddress=IpamParameters(tenant=globex, vrf=VrfParameters(name="vrf-b", tenant=globex)),
        prefix=PrefixParameters(tenant=globex),
        vlan=VlanParameters(tenant=globex),
    )
    merged = merge_override_defaults(base, override)
    for tenant in (
        merged.tenant,
        merged.ipaddress.tenant,
        merged.ipaddress.vrf.tenant,
        merged.prefix.tenant,
        merged.vlan.tenant,
    ):
        assert tenant == globex
    check_vrf_tenants(merged)


def test_override_naming_the_same_tenant_refines_it():
    """The same tenant, by map or by bare name, keeps what the policy gave it."""
    base = Defaults(tenant=ACME, ipaddress=IpamParameters(tenant=ACME))
    refined = merge_override_defaults(
        base, Defaults.model_validate({"tenant": {"name": "acme", "description": "x"}, "ipaddress": {"tenant": "acme"}})
    )
    assert refined.tenant == ACME.model_copy(update={"description": "x"})
    assert refined.ipaddress.tenant == ACME


def test_override_merges_per_family_and_prefix_vrfs_alike():
    """vrf_ipv4, vrf_ipv6 and the prefix block follow the same rule as ipaddress.vrf."""
    base = Defaults(
        ipaddress=IpamParameters(vrf_ipv4=POLICY_VRF),
        prefix=PrefixParameters(vrf_ipv6=POLICY_VRF),
    )
    merged = merge_override_defaults(
        base,
        Defaults(
            ipaddress=IpamParameters(vrf_ipv4=VrfParameters(name="vrf-b")),
            prefix=PrefixParameters(vrf_ipv6=VrfParameters(name="vrf-a", tenant=TenantParameters(name="globex"))),
        ),
    )
    assert merged.ipaddress.vrf_ipv4 == VrfParameters(name="vrf-b")
    assert merged.prefix.vrf_ipv6 == POLICY_VRF.model_copy(update={"tenant": TenantParameters(name="globex")})
