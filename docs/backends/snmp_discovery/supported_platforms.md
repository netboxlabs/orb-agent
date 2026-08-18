# SNMP Discovery — Supported Platforms

This page lists the vendors with bundled device model coverage for the [SNMP discovery](./README.md) backend.

The backend works with **any SNMPv1, SNMPv2c, or SNMPv3 capable device**. Entity discovery (interfaces, IP addresses, VLANs, LAG membership) is derived from standard MIBs (IF-MIB, IP-MIB, LLDP-MIB, BRIDGE-MIB, etc.) and is therefore vendor-agnostic.

What differs by vendor is the **device model name** populated in NetBox. snmp-discovery resolves a device's `sysObjectID` OID against a library of bundled YAML lookup extensions, turning the raw OID into a recognizable model name (for example `catalyst2955C12` instead of `.1.3.6.1.4.1.9.1.489`). When no match is found, the raw OID is kept.

> Compatibility note: coverage of a vendor file does not guarantee that every product line or firmware variant has a model entry. Report gaps via a GitHub issue against [orb-agent](https://github.com/netboxlabs/orb-agent/issues).

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

The authoritative list and the contents of each file live at [orb-discovery/snmp-discovery/data/lookup_extensions](https://github.com/netboxlabs/orb-agent/tree/develop/orb-discovery/snmp-discovery/data/lookup_extensions).

Manufacturer-level resolution (SNMP enterprise number → vendor name) is handled by [`manufacturers.yaml`](https://github.com/netboxlabs/orb-agent/blob/develop/orb-discovery/snmp-discovery/data/manufacturers.yaml), which covers the full IANA Private Enterprise Number registry.

## Extending device coverage

You can add or override lookup data without rebuilding the agent. See the [Device Model Lookup](./README.md#device-model-lookup) section of the SNMP Discovery docs for the `lookup_extensions_dir` option and the YAML format for custom files.

## Interface ↔ VLAN associations

Switchport-to-VLAN association discovery is built on standard MIBs with one vendor overlay:

| Layer | MIB / OID root | What it provides |
|-------|----------------|------------------|
| **Generic** | Q-BRIDGE-MIB (RFC 4363, `1.3.6.1.2.1.17.7.1.4`) + BRIDGE-MIB `dot1dBasePortIfIndex` | VLAN catalog (`dot1qVlanStaticTable` — names + admin status), per-port PVID (`dot1qPvid`), per-VLAN egress + untagged port masks (`dot1qVlanStatic{Egress,Untagged}Ports`). Required for trunk classification. |
| **Cisco overlay** | CISCO-VLAN-MEMBERSHIP-MIB `vmMembershipTable`, CISCO-VOICE-VLAN-MIB `vmVoiceVlanId` | Access VLAN refinement on non-trunk ports + voice-VLAN promotion. Walked only when `sysObjectID` falls under enterprise prefix `1.3.6.1.4.1.9.` (Cisco Systems) or `1.3.6.1.4.1.29671.` (Meraki). |
| **CISCOSB overlay** | CISCOSB private `vlan` group (`1.3.6.1.4.1.9.6.1.101.48`): `vlanAccessPortModeVlanId`, `vlanTrunkPortModeNativeVlanId` | Corrects the untagged VLAN on Cisco small-business switches, where the standard sources are wrong rather than absent. Indexed by `ifIndex` rather than bridge port. Shares the Cisco vendor gate above. |

When a switchport has both Q-BRIDGE membership and the Cisco overlay rows, the overlay layers on top of the generic classification (vmMembership refines the access VLAN for non-trunk ports; vmVoiceVlanId is promoted into the tagged VLAN list per Cisco's voice-on-access semantics). When a device exposes only the Cisco overlay (classic Cisco IOS without Q-BRIDGE), the overlay alone is sufficient to classify access ports — but trunk allowed/native VLANs cannot be reconstructed from `vmMembershipTable` (which is non-trunk by spec).

The CISCOSB overlay is different in kind from the Cisco one: on those switches the generic sources are not merely absent but actively wrong. `dot1qPvid` answers 1 for every port whatever the port is configured for, and the per-VLAN egress/untagged masks come back empty, so Q-BRIDGE alone reports the whole switch as access VLAN 1. Where these private columns are present they therefore take precedence for the untagged VLAN.

The overlay corrects the untagged VLAN only. It does not determine tagged membership or access-vs-trunk mode, so a trunk port on one of these switches is reported as an access port carrying its native VLAN. The private MIB does define per-port egress bitmaps that would supply both, but they are returned empty in practice, leaving no reliable source to derive membership or mode from.

### Device coverage

| Device class | Generic Q-BRIDGE | Cisco overlay | Result |
|--------------|------------------|---------------|--------|
| Arista EOS, Aruba CX, Juniper Junos ELS, MikroTik RouterOS, HPE Comware, Extreme EXOS (recent), Cumulus Linux / SONiC, Dell OS10 | ✅ Full | n/a | Access + trunk classification, real VLAN names |
| Classic Cisco IOS (e.g. Catalyst 2960, 2950) | ⚠️ None or partial | ✅ Available | Access classification via `vmMembershipTable`; trunk ports remain unclassified |
| Cisco IOS-XE (e.g. Catalyst 3850, 9400) | ⚠️ Sometimes empty pre-16.x | ✅ Available | As above; access ports classify, trunks unclassified unless Q-BRIDGE is also present |
| Cisco NX-OS | ⚠️ Q-BRIDGE present, trunk membership often vendor-only | ✅ Available | Access via overlay; trunks may rely on Q-BRIDGE membership masks |
| Cisco small business (Catalyst 1200/1300, CBS/SG series) | ❌ Present but wrong: `dot1qPvid` answers 1 on every port, egress/untagged masks empty | ✅ CISCOSB overlay | Correct untagged VLAN per port; mode is not derived, so trunks appear as access on their native VLAN |
| Pre-ELS Junos | ⚠️ Incomplete | n/a | Limited — defer to a future Junos overlay |
| Cisco WLC (e.g. 9800), routers, anything without `dot1dBasePortIfIndex` | n/a | n/a | No interface mutations emitted (refused by design — see Bridge-port translation below); VLAN catalog still emitted if `dot1qVlanStaticTable` is present |

**Voice VLAN (Cisco):** when `vmVoiceVlanId` returns a valid VID (in 1..4094), an access port is promoted to `mode=tagged` with the access VLAN as untagged and the voice VLAN as tagged — same NetBox-mapping convention as device-discovery. Sentinel values are filtered: `0` (no voice), `4095` (dot1p-only / priority-tagged), `4096` (untagged voice rides the access VLAN). Voice-on-trunk is not promoted (would create double-tagging).

**Bridge-port translation:** Q-BRIDGE port masks are encoded by `dot1dBasePort`, not `ifIndex`. snmp-discovery walks `BRIDGE-MIB::dot1dBasePortIfIndex` (`1.3.6.1.2.1.17.1.4.1.2`) and translates bridge-port → ifIndex before emitting Interface mutations. **If this table is missing**, snmp-discovery refuses to mutate Interface entities (VLAN entities are still emitted from the static catalog) — there is no "bridge-port == ifIndex" fallback because that assumption silently produces wrong cross-references on switches that allocate bridge ports separately from ifIndex.

**Trunk-allowed-all detection:** trunks are marked `tagged-all` only when the membership-derived allowed set covers the full active 1..4094 range. Q-BRIDGE exposes membership, not the operator's configured intent — so a trunk explicitly configured with `1-4094` and one currently a member of all VLANs look identical at the SNMP layer.

## Modules / ModuleBays

Module / module-bay discovery is **vendor-neutral**: it works on any device that populates `ENTITY-MIB::entPhysicalTable` (RFC 6933) with the standard class hierarchy (`chassis(3)` → `container(5)` → `module(9)`), plus optionally `entAliasMappingTable` for per-port transceiver-to-`ifIndex` linkage. There are no per-vendor branches in the implementation — the same code path covers every vendor below. Emission is gated by the `discover_modules` policy option (`off` / `linecards` / `full`); see the [SNMP discovery README](./README.md#modules--modulebays) for the contract, the three modes, and the current sub-bay rendering trade-off.

| Platform | Status |
|---|---|
| Cisco IOS-XE (Catalyst 9404R / 9407R / 9410R) | Vendor-neutral via ENTITY-MIB — tested |
| Cisco NX-OS (Nexus 9500 modular chassis) | Vendor-neutral via ENTITY-MIB — tested |
| Juniper JunOS (MX / EX modular chassis) | Vendor-neutral via ENTITY-MIB — tested |
| Arista EOS (7280R / 7500R chassis) | Vendor-neutral via ENTITY-MIB — tested |
| Aruba CX (8400 chassis, including empty-bay surfacing) | Vendor-neutral via ENTITY-MIB — tested |
| Nokia SROS (7750 SR / 7250 IXR) | Vendor-neutral via ENTITY-MIB — tested |

Any other vendor that populates `entPhysicalTable` per RFC 6933 will be discovered with no code change; report gaps as a GitHub issue against [orb-agent](https://github.com/netboxlabs/orb-agent/issues).

**PID classifier.** Module rows (`entPhysicalClass = module(9)`) are split into `supervisor` / `linecard` / `transceiver` / `psu` / `fan` types by matching `entPhysicalModelName` (the vendor product ID) against a small set of prefix rules: `SUP*` / `SUPV*` / `SUP\d` → `supervisor`; optic designators → `transceiver`, matched as prefixes on the effective PID: `SFP-` / `SFP+` / `SFP28-` / `SFP56-` / `QSFP-` / `QSFP+` / `QSFP28` / `QSFP56-` / `QDD-` / `OSFP-` / `GLC-` / `X2-` / `CFP-` / `CFP2-` / `XENPAK-` / `XFP-` / `CVR-`, kept in step with the device-discovery backend's list so the two agree on what an optic is; `PSU-` / `PWR-` or `-PWR-` infixes → `psu`; `FAN` / `-FAN-` → `fan`; everything else inside a chassis slot defaults to `linecard`. The classifier is shared across all vendors — no Cisco-only / Arista-only branch. PSU and fan modules are recognised so they label correctly in OTLP metrics, but **never** emitted as `Module` entities (counted in `modules_dropped` instead) — the inventory surface in NetBox stays scoped to line cards, supervisors, and transceivers.

### Fixed-port optics

Not every transceiver arrives as a `module(9)` row under a linecard. On fixed-port hardware — and in some per-port cages on modular platforms — the optic itself is published as a `container(5)` row or a `port(10)` row, with no `module(9)` level in between. The module scan widens to those two classes, but only for rows that carry a recognised optic PID (the same prefix list the PID classifier above uses); a bare cage or a port row without one is left alone, so ordinary container and port rows are never mistaken for modules. `entPhysicalClass = module(9)` remains the only class scanned unconditionally.

**Bay naming.** An optic whose bay does not already identify a port is named for the interface it serves rather than for a bare position number. That covers three shapes: an optic with no `module(9)` parent at all; an optic published directly under a linecard, where the nearest container is the linecard's own slot rather than a cage; and an optic under a chassis-rooted module, where no container exists above it and the bay is synthesized from the optic's own row. In each case a position number would name several bays the same — some platforms report a non-positional `entPhysicalParentRelPos` of `-1` for every child — and the duplicate-bay guard would then discard all but one optic. Only a modular optic whose cage sits **below** its own `module(9)` parent keeps the cage's name outright: that cage identifies the port and is never renamed. A fixed-port optic's cage does not take precedence — the interface name is preferred over it, and the cage name is the fallback when no interface can be derived. When nothing nameable is available at all and the bay would otherwise be inherited from an enclosing module's slot, the optic's own `entPhysicalIndex` names the bay instead: it is unattractive but stable across polls and unique on the device, where the inherited name would collide with the module already installed in that slot. The name is taken from an anchored `Xcvr for <iface>` `entPhysicalDescr` — anchored because some platforms publish a "Lane N for Xcvr for `<iface>`" row beneath the same optic, and an unanchored match would emit one bay per lane — or, failing that, from an interface-shaped `entPhysicalName`. Either candidate must contain a digit: one platform names every optic row with the literal token `port`, which would otherwise give every bay on the chassis the same name.

**Optics without a serial.** An optic reporting no serial is still discovered and emitted, in every class. NetBox leaves a module's serial optional and matches `dcim.module` on the module bay it is installed in, never on the serial, so a serial-less module reconciles exactly as a serialled one does: the field is omitted from the payload rather than sent empty, and a later poll updates the same object instead of creating another. Vendors that omit optic serials are common rather than exceptional, and on lower-end switching a blank `entPhysicalSerialNum` is the norm across modules generally, so gating on one would discard a large amount of inventory that reconciles perfectly well. The bay name is what has to be distinct, and that comes from the interface the row names, not from the serial.

**Interface-association limitation.** A fixed-port transceiver — one with no `module(9)` parent — is still emitted as its own `ModuleBay` and `Module`, with model, serial, and the interface-named bay all present. Its owning interface does not carry a `module=` reference, though: the `entAliasMappingTable`-based routing that attaches `Interface.module` only walks transceivers nested under another module, and a fixed-port optic never is one, so it never participates — this holds even on a device that populates `entAliasMappingTable`. The visible shape is the same as the documented `iosxr` limitation on the device-discovery side (a transceiver Module emitted without its interface backref), though the cause there is a location-string/interface-name mismatch rather than this routing gap.

**Known false negatives.** The PID prefix list is not exhaustive. It carries the MSA/SFF designators, kept in step with the device-discovery backend's list so an optic is not recognised by one backend and missed by the other. Real transceivers observed in captures whose PID still does not match, and are therefore not recognised as transceivers: `CAB-SFP-SFP-1M`, `SFPP-PC005`, `ABCU-5710RZ-CS5`, `FN-TRAN-SFP+GC`, `10GE SR 300m SFP+`, `10GE LR 10km SFP+`. Each begins with a vendor cable or part designator rather than a standardized transceiver one, so catching them would mean matching on something other than a designator prefix — which would risk claiming a non-optic row and manufacturing a bay that does not exist on the device. That is deferred deliberately; widening the designator list itself is not, and `QDD-` and `CVR-` were added once captures showed them.

**Empty-bay harvest and nested containers.** A `container(5)` row with no `module(9)` or `port(10)` child underneath is harvested as an empty bay in `full` mode (see [Empty bays](./README.md#modules--modulebays) in the SNMP discovery README). That harvest used to mark only a bay's *nearest* `container(5)` ancestor as populated, so a container whose own children are themselves containers — never a module or port leaf directly — was reported as an empty bay even when everything beneath it was fully populated. On two Arista EOS captures this misreported three containers per device — the transceiver, fan-tray, and power-supply slot containers — as empty even though every cage beneath them held a populated module. The rule is now: a container is an empty bay only if nothing beneath it was emitted, implemented by walking up from every populated bay and marking each `container(5)` ancestor in turn. A genuinely empty slot is unaffected: it has no module beneath it at any depth, so it is still correctly reported as an empty bay.

**Test fixtures.** Half the unit fixtures behind these rules are transcribed from real SNMP simulator recordings rather than hand-authored: row class, parentage, `entPhysicalParentRelPos`, and which fields are populated all mirror the capture, because those are exactly the values the logic above reads. Two mirror separate Arista EOS fixed-port captures — one where every optic has a lane child, one where almost none do, which is the shape that would otherwise reach the empty-bay harvest. One mirrors a Cisco Catalyst 9404R capture with a `port(10)` optic nested inside a linecard's own cage. One mirrors a two-member stack whose optics are named with the literal token `port`. One mirrors a fixed-port device reporting no serial on any optic. The rest are synthetic, and each is labelled as such at its definition, because no capture in the corpus shows the shape it pins: a serial-less optic in a `container(5)` cage of its own; the several bay-name collisions the duplicate-bay guard exists to refuse; an optic whose `entPhysicalName` is its own PID; an optic directly under a slotted linecard with no cage between them; and an optic under a chassis-rooted module whose `entPhysicalParentRelPos` is non-positional. Those are invariants the logic must hold rather than behaviour a device has been observed to need, and keeping the distinction explicit means a future reader can tell which fixtures carry evidence and which carry intent.

