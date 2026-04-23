# SNMP Discovery — Supported Platforms

This page lists the vendors with bundled device model coverage for the [SNMP discovery](./snmp_discovery.md) backend.

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

You can add or override lookup data without rebuilding the agent. See the [Device Model Lookup](./snmp_discovery.md) section of the SNMP Discovery docs for the `lookup_extensions_dir` option and the YAML format for custom files.
