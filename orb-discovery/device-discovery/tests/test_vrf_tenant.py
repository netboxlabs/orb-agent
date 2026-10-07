#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""A configured VRF carries its own tenant, and the matcher stubs keep it."""

import pytest
from netboxlabs.diode.sdk.diode.v1 import ingester_pb2 as pb
from pydantic import ValidationError

from device_discovery.policy.models import (
    Defaults,
    IpamParameters,
    PrefixParameters,
    TenantParameters,
    VrfParameters,
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


@pytest.mark.parametrize(
    ("ip_tenant", "vrf_tenant"),
    [
        pytest.param(ACME, ACME, id="identical"),
        pytest.param(ACME, TenantParameters(name="acme", group="customers"), id="fields on one side"),
        pytest.param(TenantParameters(name="acme", group="customers"), ACME, id="fields on the vrf side"),
        pytest.param("acme ", "acme", id="string padded"),
        pytest.param(ACME, ACME.model_copy(update={"description": "d "}), id="description padded"),
        pytest.param(ACME, ACME.model_copy(update={"tags": ["a "]}), id="tag padded"),
        pytest.param(ACME, ACME.model_copy(update={"name": "acme "}), id="name padded"),
        pytest.param(ACME, TenantParameters(name="globex", group="partners", description="x"), id="other tenant"),
        pytest.param(
            TenantParameters(name="日本", description="x"),
            TenantParameters(name="中国", description="y"),
            id="names without a slug",
        ),
        pytest.param("acme", "acme", id="same string"),
        pytest.param(None, ACME, id="no ip tenant"),
    ],
)
def test_vrf_tenant_written_consistently_is_accepted(ip_tenant, vrf_tenant):
    """Copies Diode merges cleanly, or never merges, are accepted."""
    _defaults(ip_tenant, vrf_tenant)


@pytest.mark.parametrize(
    ("ip_tenant", "vrf_tenant", "message"),
    [
        pytest.param(ACME, ACME.model_copy(update={"description": "x"}), "write it differently", id="description"),
        pytest.param(ACME, ACME.model_copy(update={"comments": "x"}), "write it differently", id="comments"),
        pytest.param(ACME, ACME.model_copy(update={"tags": ["b"]}), "write it differently", id="tags"),
        pytest.param(
            ACME.model_copy(update={"tags": ["a", "b"]}),
            ACME.model_copy(update={"tags": ["b", "a"]}),
            "write it differently",
            id="tags reordered",
        ),
        pytest.param(ACME, ACME.model_copy(update={"description": "  "}), "write it differently", id="blank description"),
        pytest.param(ACME, ACME.model_copy(update={"description": ""}), "write it differently", id="empty description"),
        pytest.param(ACME, ACME.model_copy(update={"name": "Acme"}), "write it differently", id="case"),
        pytest.param("Acme Corp", "Acme-Corp", "write it differently", id="slug alike"),
        pytest.param("Café", "Cafe", "write it differently", id="accent"),
        pytest.param(ACME, ACME.model_copy(update={"group": "partners"}), "write it differently", id="other group"),
        pytest.param(ACME, ACME.model_copy(update={"group": None}), "write it differently", id="ungrouped"),
        pytest.param(ACME, TenantParameters(name="globex", group="Customers"), "tenant group in two ways", id="group case"),
    ],
)
def test_vrf_tenant_written_two_ways_is_refused(ip_tenant, vrf_tenant, message):
    """Copies Diode would merge and then refuse, or rewrite every run, are refused."""
    with pytest.raises(ValidationError, match=message):
        _defaults(ip_tenant, vrf_tenant)


def test_vrf_tenant_against_device_tenant_compares_name_and_group_only():
    """The address's nested device keeps only its tenant's name and group."""
    _defaults(tenant=ACME, vrf_tenant=ACME.model_copy(update={"description": "x", "tags": ["b"]}))
    with pytest.raises(ValidationError, match="write it differently"):
        _defaults(tenant=ACME, vrf_tenant=ACME.model_copy(update={"name": "Acme"}))
    with pytest.raises(ValidationError, match="write it differently"):
        _defaults(tenant="acme", vrf_tenant=ACME)


def test_prefix_vrf_tenant_is_checked_against_the_prefix_tenant_only():
    """A prefix carries its own tenant and its VRF's, but no device."""
    conflicting = ACME.model_copy(update={"description": "x"})
    with pytest.raises(ValidationError, match=r"prefix\.tenant and prefix\.vrf_ipv6\.tenant"):
        Defaults(
            prefix=PrefixParameters(
                tenant=ACME, vrf_ipv6=VrfParameters(name="example-vrf", tenant=conflicting)
            )
        )
    Defaults(
        tenant="Acme",
        prefix=PrefixParameters(vrf=VrfParameters(name="example-vrf", tenant="acme")),
    )


def test_vrf_tenant_conflict_after_override_merge_is_refused():
    """A target override that clashes with the policy defaults is refused when merged."""
    base = Defaults(ipaddress=IpamParameters(tenant=ACME))
    override = Defaults(
        ipaddress=IpamParameters(
            vrf=VrfParameters(name="example-vrf", tenant=ACME.model_copy(update={"description": "x"}))
        )
    )
    with pytest.raises(ValidationError, match="write it differently"):
        merge_override_defaults(base, override)
