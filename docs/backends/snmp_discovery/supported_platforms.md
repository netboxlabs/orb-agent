# SNMP Discovery — Supported Platforms

This page lists the vendors with bundled device model coverage for the [SNMP discovery](./README.md) backend.

The backend works with **any SNMPv1, SNMPv2c, or SNMPv3 capable device**. Entity discovery (interfaces, IP addresses, VLANs, LAG membership) is derived from standard MIBs (IF-MIB, IP-MIB, LLDP-MIB, BRIDGE-MIB, etc.) and is therefore vendor-agnostic.

What differs by vendor is the **device model name** populated in NetBox. snmp-discovery resolves a device's `sysObjectID` OID against a library of bundled YAML lookup extensions, turning the raw OID into a recognizable model name (for example `catalyst2955C12` instead of `.1.3.6.1.4.1.9.1.489`). When no match is found, the raw OID is kept.

> Compatibility note: coverage of a vendor file does not guarantee that every product line or firmware variant has a model entry. Report gaps via a GitHub issue against [orb-discovery](https://github.com/netboxlabs/orb-discovery/issues).

## Bundled device model lookup extensions

The following vendor files ship with orb-agent and orb-discovery, providing device model resolution for their equipment:

| Vendor / Family | Lookup file |
|-----------------|-------------|
| 3Com | `a3com.yaml` |
| Alvarion | `alvarion.yaml` |
| APC (Schneider Electric) | `apc.yaml` |
| Arista | `arista.yaml` |
| HPE Aruba Networking | `aruba.yaml` |
| ATEN | `aten.yaml` |
| ATTO Technology | `atto.yaml` |
| Bachmann BlueNet 2 | `bachmann-bluenet2.yaml` |
| Broadcom cable modem | `brcm-cm.yaml` |
| Brocade (Ruckus / Extreme) | `brocade.yaml` |
| Cadant | `cadant.yaml` |
| Check Point | `checkpoint.yaml` |
| Ciena | `ciena.yaml` |
| Cisco | `cisco.yaml` |
| Citrix | `citrix.yaml` |
| Colubris (HPE) | `colubris.yaml` |
| CyberPower | `cyberpower.yaml` |
| DASAN Networks | `dasan.yaml` |
| Dell Networking | `dell-networking.yaml` |
| Dell EMC OS10 / SmartFabric | `dellemc-os10.yaml` |
| D-Link DES-7200 | `des7200.yaml` |
| Eaton | `eaton.yaml` |
| Extreme Networks | `extreme.yaml` |
| Dell Force10 | `f10.yaml` |
| F5 Networks | `f5.yaml` |
| Fortinet | `fortinet.yaml` |
| FS.com | `fs.yaml` |
| Hirschmann HM2 | `hm2.yaml` |
| HPE | `hpe.yaml` |
| Infoblox | `infoblox.yaml` |
| Juniper | `juniper.yaml` |
| Lenovo | `lenovo.yaml` |
| NVIDIA Mellanox | `mellanox.yaml` |
| Cisco Meraki | `meraki.yaml` |
| MikroTik | `mikrotik.yaml` |
| MX Digital | `mx-digital.yaml` |
| MX | `mx.yaml` |
| MY | `my.yaml` |
| NetApp | `netapp.yaml` |
| NETGEAR | `netgear.yaml` |
| Juniper NetScreen (legacy) | `netscreen.yaml` |
| NOS | `nos.yaml` |
| Nutanix | `nutanix.yaml` |
| OG | `og.yaml` |
| Palo Alto Networks | `pan.yaml` |
| Cisco PCube / SCE | `pcube.yaml` |
| QTECH | `qtech.yaml` |
| Raritan | `raritan.yaml` |
| RDN | `rdn.yaml` |
| Redline Communications | `redline.yaml` |
| Rittal CMC III | `rittal-cmc-iii.yaml` |
| Riverbed | `riverbed.yaml` |
| Ruckus / CommScope | `ruckus.yaml` |
| Schleifenbauer | `schleifenbauer.yaml` |
| Silver Peak (Aruba EdgeConnect) | `silverpeak.yaml` |
| TP-Link | `tplink.yaml` |
| Tripp Lite (Eaton) | `tripp-lite.yaml` |
| Ubiquiti | `ubiquiti.yaml` |
| Vertiv | `vertiv.yaml` |
| VMware | `vmware.yaml` |
| WatchGuard | `watchguard.yaml` |
| Waystream | `waystream.yaml` |
| World Wide Packets (Ciena) | `wwp.yaml` |

The authoritative list and the contents of each file live at [orb-discovery/snmp-discovery/data/lookup_extensions](https://github.com/netboxlabs/orb-discovery/tree/develop/snmp-discovery/data/lookup_extensions).

Manufacturer-level resolution (SNMP enterprise number → vendor name) is handled by [`manufacturers.yaml`](https://github.com/netboxlabs/orb-discovery/blob/develop/snmp-discovery/data/manufacturers.yaml), which covers the full IANA Private Enterprise Number registry.

## Extending device coverage

You can add or override lookup data without rebuilding the agent. See the [Device Model Lookup](./README.md#device-model-lookup) section of the SNMP Discovery docs for the `lookup_extensions_dir` option and the YAML format for custom files.

## Interface ↔ VLAN associations

Switchport-to-VLAN association discovery is built on standard MIBs with one vendor overlay:

| Layer | MIB / OID root | What it provides |
|-------|----------------|------------------|
| **Generic** | Q-BRIDGE-MIB (RFC 4363, `1.3.6.1.2.1.17.7.1.4`) + BRIDGE-MIB `dot1dBasePortIfIndex` | VLAN catalog (`dot1qVlanStaticTable` — names + admin status), per-port PVID (`dot1qPvid`), per-VLAN egress + untagged port masks (`dot1qVlanStatic{Egress,Untagged}Ports`). Required for trunk classification. |
| **Cisco overlay** | CISCO-VLAN-MEMBERSHIP-MIB `vmMembershipTable`, CISCO-VOICE-VLAN-MIB `vmVoiceVlanId` | Access VLAN refinement on non-trunk ports + voice-VLAN promotion. Walked only when `sysObjectID` falls under enterprise prefix `1.3.6.1.4.1.9.` (Cisco Systems) or `1.3.6.1.4.1.29671.` (Meraki). |

When a switchport has both Q-BRIDGE membership and the Cisco overlay rows, the overlay layers on top of the generic classification (vmMembership refines the access VLAN for non-trunk ports; vmVoiceVlanId is promoted into the tagged VLAN list per Cisco's voice-on-access semantics). When a device exposes only the Cisco overlay (classic Cisco IOS without Q-BRIDGE), the overlay alone is sufficient to classify access ports — but trunk allowed/native VLANs cannot be reconstructed from `vmMembershipTable` (which is non-trunk by spec).

### Device coverage

| Device class | Generic Q-BRIDGE | Cisco overlay | Result |
|--------------|------------------|---------------|--------|
| Arista EOS, Aruba CX, Juniper Junos ELS, MikroTik RouterOS, HPE Comware, Extreme EXOS (recent), Cumulus Linux / SONiC, Dell OS10 | ✅ Full | n/a | Access + trunk classification, real VLAN names |
| Classic Cisco IOS (e.g. Catalyst 2960, 2950) | ⚠️ None or partial | ✅ Available | Access classification via `vmMembershipTable`; trunk ports remain unclassified |
| Cisco IOS-XE (e.g. Catalyst 3850, 9400) | ⚠️ Sometimes empty pre-16.x | ✅ Available | As above; access ports classify, trunks unclassified unless Q-BRIDGE is also present |
| Cisco NX-OS | ⚠️ Q-BRIDGE present, trunk membership often vendor-only | ✅ Available | Access via overlay; trunks may rely on Q-BRIDGE membership masks |
| Pre-ELS Junos | ⚠️ Incomplete | n/a | Limited — defer to a future Junos overlay |
| Cisco WLC (e.g. 9800), routers, anything without `dot1dBasePortIfIndex` | n/a | n/a | No interface mutations emitted (refused by design — see Bridge-port translation below); VLAN catalog still emitted if `dot1qVlanStaticTable` is present |

**Voice VLAN (Cisco):** when `vmVoiceVlanId` returns a valid VID (in 1..4094), an access port is promoted to `mode=tagged` with the access VLAN as untagged and the voice VLAN as tagged — same NetBox-mapping convention as device-discovery. Sentinel values are filtered: `0` (no voice), `4095` (dot1p-only / priority-tagged), `4096` (untagged voice rides the access VLAN). Voice-on-trunk is not promoted (would create double-tagging).

**Bridge-port translation:** Q-BRIDGE port masks are encoded by `dot1dBasePort`, not `ifIndex`. snmp-discovery walks `BRIDGE-MIB::dot1dBasePortIfIndex` (`1.3.6.1.2.1.17.1.4.1.2`) and translates bridge-port → ifIndex before emitting Interface mutations. **If this table is missing**, snmp-discovery refuses to mutate Interface entities (VLAN entities are still emitted from the static catalog) — there is no "bridge-port == ifIndex" fallback because that assumption silently produces wrong cross-references on switches that allocate bridge ports separately from ifIndex.

**Trunk-allowed-all detection:** trunks are marked `tagged-all` only when the membership-derived allowed set covers the full active 1..4094 range. Q-BRIDGE exposes membership, not the operator's configured intent — so a trunk explicitly configured with `1-4094` and one currently a member of all VLANs look identical at the SNMP layer.

**Adding a new vendor overlay:** mirrors the Cisco overlay shape — one `mapping/qbridge/extract_<vendor>.go` file in [orb-discovery](https://github.com/netboxlabs/orb-discovery/tree/develop/snmp-discovery/mapping/qbridge), one `vendor:` block in [`mapping.yaml`](https://github.com/netboxlabs/orb-discovery/blob/develop/snmp-discovery/policy/mapping.yaml), and one `sysObjectID` prefix in the vendor-matcher table in [`policy/vendor.go`](https://github.com/netboxlabs/orb-discovery/blob/develop/snmp-discovery/policy/vendor.go). Open an issue against [orb-discovery](https://github.com/netboxlabs/orb-discovery/issues) to request additions.
