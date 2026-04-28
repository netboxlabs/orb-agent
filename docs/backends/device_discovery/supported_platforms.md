# Device Discovery — Supported Platforms

This page lists the vendors, operating systems, and NAPALM drivers supported by the [device discovery](./README.md) backend.

The backend connects to network devices over SSH / NETCONF / vendor APIs via [NAPALM](https://napalm.readthedocs.io/). Support is driver-bound: a device is supported only if a corresponding NAPALM driver exists.

> Compatibility note: driver presence does not guarantee that every feature on every OS version works. Vendors regularly change CLI/API behavior across releases. Report gaps via a GitHub issue against [orb-discovery](https://github.com/netboxlabs/orb-discovery/issues).

## Auto-discovery behavior

When a scope entry does not specify a `driver`, device-discovery attempts driver detection automatically. Only the **standard NAPALM drivers** below are tried during auto-discovery. Custom drivers must be used explicitly by either setting `driver:` on the scope entry, or by listing them in the `discovery_drivers` option (see [Custom Driver Discovery Example](./README.md#custom-driver-discovery-example)).

## Interface ↔ VLAN associations

Drivers that implement `get_interfaces_vlans()` populate per-interface switching configuration on the emitted `Interface` entities (mode, untagged/access VLAN, tagged VLAN list). Drivers without the method continue to emit interfaces without VLAN associations — this is opt-in per driver.

| Driver | Status |
|--------|--------|
| `ios` | Supported (Cisco IOS, IOS-XE) |
| `cisco_s300` | Supported (Cisco Small Business 300/350/550) |

Additional vendors will land in follow-up changes. See the [device discovery README](./README.md#diode-entities) for the contract and the `create_unknown_vlans` option.

## Standard NAPALM drivers

These drivers ship with the [NAPALM](https://napalm.readthedocs.io/en/latest/support/) library and are eligible for auto-discovery.

| Driver | Vendor | Platform / OS |
|--------|--------|---------------|
| `eos` | Arista | EOS |
| `ios` | Cisco | IOS / IOS-XE |
| `iosxr` | Cisco | IOS-XR (XML agent) |
| `iosxr_netconf` | Cisco | IOS-XR (NETCONF) |
| `junos` | Juniper | Junos |
| `nxos` | Cisco | NX-OS (NX-API) |
| `nxos_ssh` | Cisco | NX-OS (SSH) |

## Custom NAPALM drivers (orb-discovery)

These drivers are bundled with device-discovery. They are **not** tried during auto-discovery unless explicitly listed in `discovery_drivers`; otherwise set `driver:` on the scope entry.

| Driver | Vendor | Platform / OS |
|--------|--------|---------------|
| `alcatel_aos` | Nokia / Alcatel-Lucent Enterprise | AOS |
| `aruba_aoscx` | HPE Aruba Networking | AOS-CX (REST) |
| `aruba_aoscx_ssh` | HPE Aruba Networking | AOS-CX (SSH) |
| `aruba_os` | HPE Aruba Networking | ArubaOS (controllers) |
| `aruba_osswitch` | HPE Aruba Networking | ArubaOS-Switch (ex-ProCurve) |
| `avaya_ers` | Extreme Networks (ex-Avaya) | Ethernet Routing Switch (ERS) |
| `brocade_fastiron` | Ruckus / CommScope (ex-Brocade) | FastIron (ICX) |
| `brocade_netiron` | Extreme Networks (ex-Brocade) | NetIron (MLX / CES / CER) |
| `checkpoint_gaia` | Check Point | Gaia |
| `ciena_saos` | Ciena | SAOS |
| `cisco_apic` | Cisco | ACI APIC |
| `cisco_asa` | Cisco | ASA |
| `cisco_asa_ssh` | Cisco | ASA (SSH) |
| `cisco_ftd_ssh` | Cisco | Firepower Threat Defense (FTD) |
| `cisco_fxos` | Cisco | FXOS |
| `cisco_s300` | Cisco | Small Business 300/350/550 series |
| `cisco_viptela_ssh` | Cisco | Viptela / SD-WAN |
| `cisco_wlc` | Cisco | Wireless LAN Controller (AireOS) |
| `cumulus_linux` | NVIDIA (ex-Cumulus) | Cumulus Linux |
| `dell_ftos` | Dell | Force10 / FTOS |
| `dell_powerconnect` | Dell | PowerConnect |
| `dell_sonic` | Dell | Enterprise SONiC |
| `ericsson_ipos` | Ericsson | IPOS (ex-Redback SmartEdge) |
| `extreme_exos` | Extreme Networks | EXOS |
| `extreme_slx` | Extreme Networks | SLX-OS |
| `extreme_vsp` | Extreme Networks | VSP / VOSS |
| `fortinet_fortios_ssh` | Fortinet | FortiOS |
| `hp_comware` | HPE / H3C | Comware |
| `hp_procurve` | HPE | ProCurve (legacy) |
| `huawei_smartax` | Huawei | SmartAX (OLT) |
| `huawei_vrp` | Huawei | VRP |
| `mikrotik_routeros` | MikroTik | RouterOS |
| `nokia_srl` | Nokia | SR Linux |
| `nokia_sros` | Nokia | SR OS (gNMI/NETCONF) |
| `nokia_sros_ssh` | Nokia | SR OS (SSH) |
| `paloalto_panos` | Palo Alto Networks | PAN-OS (XML API) |
| `paloalto_panos_ssh` | Palo Alto Networks | PAN-OS (SSH) |
| `ubiquiti_edgerouter` | Ubiquiti | EdgeRouter (EdgeOS) |
| `ubiquiti_edgeswitch` | Ubiquiti | EdgeSwitch |
| `ubiquiti_unifiswitch` | Ubiquiti | UniFi Switch |

The source for the custom drivers is maintained at [orb-discovery/device-discovery/custom_napalm](https://github.com/netboxlabs/orb-discovery/tree/develop/device-discovery/custom_napalm).

## Querying supported drivers at runtime

device-discovery exposes its effective driver list via its capabilities endpoint:

```sh
curl http://<agent-host>:8072/api/v1/capabilities
# => {"supported_drivers": ["eos", "ios", "junos", ...]}
```
