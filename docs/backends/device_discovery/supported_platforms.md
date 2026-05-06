# Device Discovery — Supported Platforms

This page lists the vendors, operating systems, and NAPALM drivers supported by the [device discovery](./README.md) backend.

The backend connects to network devices over SSH / NETCONF / vendor APIs via [NAPALM](https://napalm.readthedocs.io/). Support is driver-bound: a device is supported only if a corresponding NAPALM driver exists.

> Compatibility note: driver presence does not guarantee that every feature on every OS version works. Vendors regularly change CLI/API behavior across releases. Report gaps via a GitHub issue against [orb-agent](https://github.com/netboxlabs/orb-agent/issues).

## Auto-discovery behavior

When a scope entry does not specify a `driver`, device-discovery attempts driver detection automatically. Only the **standard NAPALM drivers** below are tried during auto-discovery. Custom drivers must be used explicitly by either setting `driver:` on the scope entry, or by listing them in the `discovery_drivers` option (see [Custom Driver Discovery Example](./README.md#custom-driver-discovery-example)).

## Interface ↔ VLAN associations

Drivers that implement `get_interfaces_vlans()` populate per-interface switching configuration on the emitted `Interface` entities (mode, untagged/access VLAN, tagged VLAN list). Drivers without the method continue to emit interfaces without VLAN associations — this is opt-in per driver.

| Driver | Status |
|--------|--------|
| `eos` | Supported (Arista EOS) — via eAPI JSON; works over `transport=ssh` or `transport=https` |
| `ios` | Supported (Cisco IOS, IOS-XE) |
| `nxos` | Supported (Cisco NX-OS) — via NX-API JSON |
| `nxos_ssh` | Supported (Cisco NX-OS) — via SSH + ntc-templates |
| `junos` | Supported (Juniper Junos) — EX/QFX switching, handles ELS and non-ELS configurations |
| `cisco_s300` | Supported (Cisco Small Business 300/350/550) |
| `mellanox_mlnxos` | Supported (Mellanox MLNX-OS) — via SSH; hybrid mode collapses to trunk (native + tagged) |
| `dell_sonic` | Supported (Dell Enterprise SONiC) — via SSH; parses `show interface switchport` |
| `cumulus_linux` | Supported (Cumulus Linux / NVIDIA) — via SSH using `bridge -j vlan show` JSON |
| `aruba_aoscx` | Supported (HPE Aruba AOS-CX) — via pyaoscx REST API |
| `aruba_osswitch` | Supported (HPE ArubaOS-Switch / ex-ProCurve) — via REST; per-VLAN→per-port inversion |
| `huawei_vrp` | Supported (Huawei VRP) — via SSH + ntc-templates `display port vlan`; hybrid collapses to trunk |
| `dell_ftos` | Supported (Dell Force10 / FTOS) — via SSH; handles OS9 and OS10/IOS-style `show interfaces switchport` |
| `aruba_aoscx_ssh` | Supported (HPE Aruba AOS-CX) — via SSH; same `vlan_mode` semantics as the REST counterpart |
| `hp_comware` | Supported (HPE / H3C Comware) — via SSH; merges `display interface brief` + `display vlan all` |
| `extreme_exos` | Supported (Extreme EXOS) — via SSH; per-port `show ports information detail` parsing |
| `alcatel_aos` | Supported (Alcatel-Lucent OmniSwitch / AOS) — via SSH + ntc-templates `show vlan port` |
| `hp_procurve` | Supported (HPE ProCurve / ArubaOS-Switch CLI) — via SSH; `show vlans` enumeration + per-VLAN membership |
| `brocade_fastiron` | Supported (Ruckus / Brocade FastIron / ICX) — via SSH; per-VLAN inversion (handles `ethe`, `lag`, `ve`) |
| `dell_powerconnect` | Supported (Dell PowerConnect) — via SSH; `show interfaces switchport` section parser |
| `extreme_vsp` | Supported (Extreme VSP / VOSS, ex-Avaya) — via SSH; aggregates `show interfaces gigabitethernet vlan` + tengigabit variant |
| `brocade_netiron` | Supported (Brocade / Extreme NetIron MLX/CES/CER) — via SSH; per-VLAN regex inversion of `show running-config vlan` (handles `ethe`, `lag`, `ve`); canonical-name remap to `GigabitEthernet`/`10GigabitEthernet`/etc via `show interfaces` cross-reference |
| `avaya_ers` | Supported (Avaya / Extreme ERS) — via SSH + ntc-templates; `show vlan interface info` (driver-local parser) + `show vlan` inversion; UntagAll → access; UntagPvidOnly → trunk-with-native; TagAll → trunk-no-native |
| `extreme_slx` | Supported (Extreme SLX-OS) — via SSH; driver-local parser of `show vlan brief` `(u)`/`(t)` flags; reuses existing `_expand_vlan_port` for `Eth`/`Po` name canonicalisation |
| `ubiquiti_edgeswitch` | Supported (Ubiquiti EdgeSwitch / Broadcom-fastpath) — via SSH; `show interfaces switchport` summary + `show running-config` `vlan participation`/`vlan tagging` directives |
| `ubiquiti_unifiswitch` | Supported (Ubiquiti UniFi Switch) — via SSH; `show vlan` enumeration + per-VID `show vlan id <N>` membership parsing |

See the [device discovery README](./README.md#diode-entities) for the contract and the `create_unknown_vlans` option. Additional vendors land as follow-up PRs as the underlying drivers gain support.

**Cisco IOS / NX-OS voice-VLAN quirk:** an access port carrying a voice VLAN is reported as `mode=tagged` (NetBox's `tagged-with-untagged-native` semantics) with the data VLAN as untagged and the voice VLAN as tagged — because NetBox's strict `access` mode disallows tagged VLANs. This only fires when the voice VLAN differs from the access VLAN; same-VLAN configurations stay as plain `mode=access`.

**Junos VLAN-name members:** v1 reads `<interface-vlan-member-tagid>` directly from the PyEZ RPC response. Members emitted with only a name (no tagid) are skipped with a warning; resolution against `get_vlans()` is deferred to a follow-up. Voice-VLAN promotion is also deferred for Junos — VOIP semantics differ from the Cisco family.

**Structured-API vs CLI:** `eos`, `nxos`, `junos`, and `aruba_aoscx` fetch via structured APIs (eAPI / NX-API / NETCONF / pyaoscx REST) and have no ntc-templates dependency. The CLI-scrape paths (`ios`, `cisco_s300`, `nxos_ssh`, `mellanox_mlnxos`, `dell_sonic`, `cumulus_linux`, `huawei_vrp`, `dell_ftos`, `aruba_aoscx_ssh`, `hp_comware`, `extreme_exos`, `alcatel_aos`, `hp_procurve`, `brocade_fastiron`, `dell_powerconnect`, `extreme_vsp`, `brocade_netiron`, `avaya_ers`, `extreme_slx`, `ubiquiti_edgeswitch`, `ubiquiti_unifiswitch`) parse vendor-specific output with regex or ntc-templates.

**ArubaOS-Switch (`aruba_osswitch`)** has no first-class "all VLANs" wildcard in its REST model, so the driver never emits `mode=tagged-all`; restricted trunks always carry an explicit tagged VLAN list.

**Cumulus Linux (`cumulus_linux`)** uses the Linux bridge VLAN model: a port with PVID-only is reported as `mode=access`; PVID + additional VIDs becomes `mode=tagged` with the PVID as untagged; VIDs without PVID becomes `mode=tagged` with no untagged. The driver does not emit `mode=tagged-all` because the kernel requires explicit VID lists.

**AOS-CX (`aruba_aoscx`)** distinguishes `vlan_mode=native-untagged` (native VID untagged on the wire — emits `untagged_vlan`) from `vlan_mode=native-tagged` (native VID is also tagged on egress — the native VID is folded into `tagged_vlans` and no `untagged_vlan` is emitted). The REST convention "empty `vlan_trunks` under `vlan_mode=trunk` means all VLANs allowed" is honoured and produces `mode=tagged-all`.

**Huawei VRP (`huawei_vrp`)** collapses `hybrid` link-type to trunk (PVID native + Trunk VLAN List tagged). LNP-negotiated link-types (`auto`, `desirable`) infer mode from membership shape: empty trunk-VLAN list → access on PVID; non-empty → trunk with PVID as native. `dot1q-tunnel` ports keep their PVID as access. The full `1-4094` range is emitted as `tagged-all`.

**Dell FTOS (`dell_ftos`)** supports both OS10/IOS-style (`Administrative mode`, `Trunking VLANs Enabled`) and OS9-style (`802.1QTagged`, `Vlan membership` block — both `U/T <vids>` and `Vlan <vid>` token forms) outputs. FTOS `general` mode collapses to trunk.

**HP Comware (`hp_comware`)** merges per-port mode + PVID from `display interface brief` with per-VLAN tagged/untagged port lists from `display vlan all`. Hybrid collapses to trunk. Abbreviated interface names (`GE`, `XGE`, `25GE/40GE/100GE/...`, `BAGG`, `RAGG`, `Vlan-int`) are expanded to full names so they match `get_interfaces()` keys. Comware does not render an "all VLANs" wildcard, so trunk-all is never emitted.

**Extreme EXOS (`extreme_exos`)** parses per-port `show ports information detail` (using `Internal Tag` for untagged + `802.1Q Tag` for tagged). EXOS does not emit a first-class wildcard; tagged lists are always explicit and the driver never emits `mode=tagged-all`.

**Alcatel-Lucent AOS (`alcatel_aos`)** uses ntc-templates `show vlan port` which emits one row per (VLAN, port) with TYPE in `untagged`/`qtagged`. STATUS=`forbidden` rows are filtered. Port keys preserve the AOS `slot/port` form verbatim.

**HP ProCurve (`hp_procurve`)** has no admin-mode keyword on the port — mode is inferred from membership shape across `show vlans <vid>` outputs (1× Untagged + 0 Tagged → access; 1× Untagged + ≥1 Tagged → trunk-with-native; Tagged-only → trunk-no-native). `GVRP` and `Forbid` rows are skipped. There is no first-class wildcard; trunks always carry an explicit list.

**Brocade FastIron (`brocade_fastiron`)** uses regex-based parsing of `show running-config vlan` (rather than ntc-templates, which only emit `ethe` ports) so that LAG (`lag <N>`) and VE (`ve <N>`) memberships are captured alongside physical ports. `dual-mode` is implicit — a port that appears as `untagged` in one VLAN and `tagged` in others classifies as trunk with that as native. No first-class wildcard.

**Dell PowerConnect (`dell_powerconnect`)** parses `show interfaces switchport` per-port sections. `General` mode collapses to trunk (matches the FTOS / Mellanox / AOS-CX general→trunk pattern). On Trunk ports, `Default VLAN: disabled` strips the native VLAN regardless of any Untagged row in the membership table. Membership rows with a blank VLAN-name column are still captured. `Layer3` and other non-A/T/G modes map to routed.

**Extreme VSP / VOSS (`extreme_vsp`)** issues two speed-specific commands (`show interfaces gigabitethernet vlan` + `show interfaces tengigabitethernet vlan`) — the same speeds `get_interfaces()` and `get_facts()` enumerate, so VLAN entries always line up with discovered Interface entities. Missing/empty modules are tolerated. `UNTAGGED_VID=0` signals "no native"; the full `1-4094` range is promoted to `mode=tagged-all`.

**Brocade/Extreme NetIron (`brocade_netiron`)** uses regex parsing of `show running-config vlan` (the same path as `get_vlans()`) so LAG (`lag <N>`) and VE (`ve <N>`) memberships are captured alongside physical `ethe` ports. Bare port IDs (`1/1`, `3/4`) are remapped to the canonical speed-prefixed form `get_interfaces()` emits (`GigabitEthernet1/1`, `10GigabitEthernet3/4`) via a `show interfaces` cross-reference — without this `apply_interface_vlans()` would silently drop every entry due to exact-name mismatch. `dual-mode` is implicit (port untagged in one VLAN + tagged in others → trunk-with-native). Multi-untagged on a single port → routed (anomalous; 802.1Q forbids).

**Avaya/Extreme ERS (`avaya_ers`)** uses `show vlan interface info` (driver-local parser) for the per-port `Tagging` column plus `show vlan` (ntc-template) inverted for membership lists. Tagging modes: `UntagAll` → access on PVID (membership churn ignored — operator intent is encoded in the tagging mode); `UntagPvidOnly` → trunk with PVID native + tagged from members; `TagAll` → trunk no native, PVID stays in tagged list when a member; `Disable` / unknown → routed. Trunk modes with empty membership data → routed (defensive; avoids clobbering NetBox `tagged_vlans` via PATCH).

**Extreme SLX-OS (`extreme_slx`)** uses driver-local parsing of `show vlan brief` with `(u)`/`(t)` flags driving membership-shape mode inference (no admin-mode column on SLX-OS). Reuses the existing `_expand_vlan_port` helper for `Eth`/`Po` token canonicalisation so port keys match `get_interfaces()`. Multi-untagged → routed; out-of-range VIDs dropped via `coerce_vid()`.

**Ubiquiti EdgeSwitch (`ubiquiti_edgeswitch`)** combines `show interfaces switchport` summary (Mode + PVID column) with running-config `vlan participation`/`vlan tagging` directives — the bundled `ubiquiti_edgeswitch_show_vlan` ntc-template does not capture per-port tagging. `Access` requires exactly one untagged member (no PVID-only fallback — mirrors the dell_powerconnect tightening); `General` collapses to trunk; `Trunk` with no membership data → routed.

**Ubiquiti UniFi Switch (`ubiquiti_unifiswitch`)** shares the Broadcom-fastpath CLI base with EdgeSwitch but its `show vlan` output is a simple list with no port column. The driver enumerates VIDs via `show vlan` and queries each with `show vlan id <N>` (mirrors the ProCurve approach), then aggregates per-port and infers mode from membership shape (no admin-mode keyword exists in this CLI).

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

## Custom NAPALM drivers

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
| `mellanox_mlnxos` | NVIDIA / Mellanox | MLNX-OS |
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
