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
| `avaya_ers` | Supported (Avaya / Extreme ERS) — via SSH + ntc-templates; `show vlan interface info` + `show vlan` inversion; UntagAll → access; UntagPvidOnly + Hybrid → trunk-with-native; TagAll + TagPvidOnly → trunk-no-native; v1 (STG) and v2 (no-STG) firmware layouts auto-detected |
| `extreme_slx` | Supported (Extreme SLX-OS) — via SSH; driver-local parser of `show vlan brief` `(u)`/`(t)` flags; reuses existing `_expand_vlan_port` for `Eth`/`Po` name canonicalisation |
| `ubiquiti_edgeswitch` | Supported (Ubiquiti EdgeSwitch / Broadcom-fastpath) — via SSH; `show interfaces switchport` summary + `show running-config` parsing both native (`vlan participation`/`vlan tagging`) and Cisco-style (`switchport access vlan` / `switchport trunk allowed vlan ...`) directives |
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

**Avaya/Extreme ERS (`avaya_ers`)** uses `show vlan interface info` (driver-local parser) for the per-port `Tagging` column plus `show vlan` (ntc-template) inverted for membership lists. Tagging modes: `UntagAll` → access on PVID (membership churn ignored — operator intent is encoded in the tagging mode); `UntagPvidOnly` and `Hybrid` → trunk with PVID native + tagged from members (Hybrid is NetBox-equivalent to UntagPvidOnly); `TagAll` and `TagPvidOnly` → trunk no native, full membership tagged (PVID stays in the tagged list — `TagPvidOnly`'s "other VLANs untagged" behaviour can't be represented faithfully on a NetBox trunk, trunk-no-native is the safest mapping); `Disable` / unknown / out-of-range PVID → routed. Trunk modes with empty membership data → routed (defensive; avoids clobbering NetBox `tagged_vlans` via PATCH). The parser auto-detects v1 (STG before PVID) and v2 (no STG; PRI before Tagging) firmware layouts and resolves chassis-wide `ALL` and unit-wide `<unit>/ALL` membership wildcards against the discovered port catalog.

**Extreme SLX-OS (`extreme_slx`)** uses driver-local parsing of `show vlan brief` with `(u)`/`(t)` flags driving membership-shape mode inference (no admin-mode column on SLX-OS). Reuses the existing `_expand_vlan_port` helper for `Eth`/`Po` token canonicalisation so port keys match `get_interfaces()`. Multi-untagged → routed; out-of-range VIDs dropped via `coerce_vid()`.

**Ubiquiti EdgeSwitch (`ubiquiti_edgeswitch`)** combines `show interfaces switchport` summary (Mode + PVID column) with running-config parsing — the bundled `ubiquiti_edgeswitch_show_vlan` ntc-template does not capture per-port tagging. The driver accepts both the native syntax (`vlan participation include/exclude`, `vlan tagging`, `vlan pvid`) and the Cisco-flavoured syntax (`switchport access vlan`, `switchport trunk native vlan`, `switchport trunk allowed vlan add|remove|except|all`, `switchport general pvid`/`allowed vlan add ... tagged|untagged`); operators using either form get correct VLAN data. `switchport trunk allowed vlan all` promotes to `mode=tagged-all` (the only first-class wildcard path on EdgeSwitch); `except <vlist>` and `all` followed by a later `add`/`remove` both fall back to routed (NetBox can't represent "all VLANs except these" without enumerating the chassis). `Access` mode requires exactly one untagged member when membership is captured, and trusts the summary PVID for default-config ports that EdgeSwitch's running-config omits. `General` collapses to trunk; multiple untagged members on Trunk/General → routed (anomalous; 802.1Q forbids).

**Ubiquiti UniFi Switch (`ubiquiti_unifiswitch`)** shares the Broadcom-fastpath CLI base with EdgeSwitch but its `show vlan` output is a simple list with no port column. The driver enumerates VIDs via `show vlan` and queries each with `show vlan id <N>` (mirrors the ProCurve approach), then aggregates per-port and infers mode from membership shape (no admin-mode keyword exists in this CLI).

## Switch stacks / Virtual Chassis (VC)

Drivers that implement `get_chassis_members()` discover switch-stack / Virtual Chassis topology and emit a NetBox `VirtualChassis` plus one `Device` per stack member. Interfaces and IP addresses are routed to the member that physically owns them via the `parse_member_id` helper. Drivers without the method continue to emit a single `Device` regardless of whether the target is in stack mode — this is opt-in per driver, analogous to interface ↔ VLAN associations.

See [Switch stacks / Virtual Chassis](./README.md#switch-stacks--virtual-chassis) in the README for the emission shape and master-pinning rationale.

| Driver | Status |
|--------|--------|
| `ios` | Supported (Cisco IOS / IOS-XE) — Catalyst StackWise (3850, 9300, 2960X, etc.); parses `show switch detail` + `show inventory` via ntc-templates |
| `junos` | Supported (Juniper EX / QFX) — Virtual Chassis via the `<get-virtual-chassis-information>` PyEZ RPC; tolerates both `<member-list>/<member>` (modern) and bare `<member>` (older releases) shapes |
| `aruba_aoscx` | Supported (HPE Aruba AOS-CX) — Virtual Switching Framework (VSF) via pyaoscx REST (`/system/vsf_members` + optional `/system/vsf`); tolerates list-of-members and dict-keyed-by-id payload shapes |
| `aruba_aoscx_ssh` | Supported (HPE Aruba AOS-CX) — VSF via SSH `show vsf detail` (ntc-template `aruba_aoscx_show_vsf_detail`); member role comes from the `Status` field |
| `hp_comware` | Supported (HPE / H3C Comware) — Intelligent Resilient Framework (IRF) via SSH; parses `display irf` driver-locally (no ntc-template) for member id / role / priority / CPU-Mac, joins per-member serial + model from `display device manuinfo` by MAC. Handles both fixed-switch IRF and modular-chassis IRF (12500-series) through the same MAC-keyed path |
| `brocade_fastiron` | Supported (Brocade / Ruckus FastIron ICX) — ICX 7150 / 7250 / 7450 / 7650 / 7750 stacking via SSH; parses `show stack` driver-locally for member id / role / priority / MAC and joins per-unit serial + model from `show version` Hardware-section UNIT blocks |
| `huawei_vrp` | Supported (Huawei VRP iStack) — S5700 / S5720 / S6700 / S6720 stacking via SSH; parses `display stack` driver-locally for slot / role / MAC / priority / Device Type and joins per-member serial from `display esn`. CSS (Cluster Switch System — modular-chassis VRP variant) is deferred to a follow-up |

**Cisco IOS (`ios`)** detects 2+ populated stack members in `show switch detail`; per-member serials and models come from `show inventory` rows whose NAME matches `Switch <N>` (or, on some IOS / IOS-XE versions, a bare number). Members without a serial — or scenarios where the inventory output uses the `Chassis` keyword instead of per-switch entries (e.g. CSR1000v identifying as a single chassis) — fall back to the single-Device path. Stack-member port names are parsed across the full Catalyst interface family: Gi/Te/Fo/Hu plus the mGig prefixes (`TwoGigabitEthernet`, `FiveGigabitEthernet`, `TwentyFiveGigE`) on 9300/9400 hardware. FEX 3-tuple / 4-tuple names (`Eth101/1/1`, `GigabitEthernet101/1/0/1`) are rejected so a FEX id can never leak through as a stack-member id.

**Juniper Junos (`junos`)** discovers VC members through a structured NETCONF RPC, so there is no CLI scraping. Member roles map: `Master*` (the trailing asterisk on the active master is stripped) → active, `Backup` → standby, `Linecard` → member. `NotPrsnt` slots are filtered before payload construction so empty member ids don't pollute the VC. Standalone EX/QFX devices (no VC configured) commonly raise `RpcError` for this RPC — the driver catches it at DEBUG level (not WARNING) so non-VC devices do not emit per-cycle warning noise during discovery; unexpected exceptions still surface at WARNING with full traceback.

**Aruba AOS-CX (`aruba_aoscx`, `aruba_aoscx_ssh`)** discovers VSF members across both transports. The REST path fetches `GET /system/vsf_members?depth=2` (and optionally `/system/vsf?attributes=domain_id` for the domain id) via pyaoscx and tolerates both payload shapes pyaoscx surfaces — a list of member dicts or a dict keyed by member id. Field-alias tolerance accepts `mac`/`mac_address`, `serial`/`serial_number`, and `product`/`product_name`/`model`. Role normalization maps AOS-CX 10.10+ aliases `conductor` / `commander` → active. The SSH path parses `show vsf detail` via the bundled ntc-template `aruba_aoscx_show_vsf_detail`; the `Status` field (`Active` / `Standby` / not-present) drives the role mapping, so member role is available without scraping the `show vsf` summary. Absent slots (status ∈ {`missing`, `not_present`, `absent`}) are filtered before payload construction. Non-VSF firmware returns HTTP 404 on the REST endpoint — the driver logs at DEBUG (no per-cycle warning noise on standalone AOS-CX devices) and falls back to the single-Device path; unexpected exceptions still surface at WARNING with full traceback.

**HP / H3C Comware IRF (`hp_comware`)** discovers IRF members via SSH. `display irf` is parsed driver-locally (no ntc-template exists) for member id / role / priority / CPU-Mac; per-member serial + model are joined from `display device manuinfo` (ntc-template) keyed by **MAC address** so both fixed-switch IRF (`Slot N` == member N) and modular-chassis IRF (`Chassis N` groups `Subslot` blades under a single member) work through the same code path. The regex tolerates both the standard `MemberID Role Priority …` layout and the `MemberID Slot Role …` variant emitted by modular HPE/H3C 12500-series platforms. Comware-5 `Slave` is mapped to `standby`, the `>` disabled-stack-capability row marker is accepted, and the trailing settings block is matched for both `Domain ID` (Comware 7) and `Topo-domain ID` (Comware 5) labels. Standalone Comware emits a 1-member `display irf` row, which `validate_chassis_payload` then falls through to the single-Device path. `display irf` exceptions surface at WARNING + traceback; empty output is DEBUG.

**Brocade / Ruckus FastIron ICX (`brocade_fastiron`)** discovers ICX stacks (ICX 7150 / 7250 / 7450 / 7650 / 7750) via SSH. `show stack` is parsed driver-locally (no ntc-template exists) for member id / cfg flag / model / role / Cisco-dotted MAC / priority / state; the cfg-flag class is widened to any single letter so legend-listed variants (`D`/`S`/`M`/`R`) all parse. Per-unit serial + model are joined from `show version` Hardware-section `UNIT N: SL n: <MODEL>` headers and the following `Serial #:` line. The driver **bypasses** the brocade_fastiron `show version` ntc-template because that template's `POE` capture is the case-sensitive literal `(POE)`, which silently breaks parsing on ICX7250 / ICX7400 `PoE` / `PoE+` units (raising `TextFSMError` mid-parse) — the driver-local parser handles both PoE and non-PoE units cleanly. Join key is the stack-member id (both commands share the same id space). Standalone ICX emits a `No stack` banner → DEBUG, returns None; multi-member stacks emit the payload. `show version` failures keep `show stack` data and surface at WARNING + traceback.

**Huawei VRP iStack (`huawei_vrp`)** discovers iStack-mode stacks (S5700 / S5720 / S6700 / S6720) via SSH. `display stack` is parsed driver-locally for slot / role / dashed-MAC / priority / Device Type; the model capture is greedy-to-EOL so VRP's power-suffix / hardware-variant tokens (`S5720-32X-EI-AC PWR-AC HW`) survive. Per-member serial is joined from `display esn` (the same command `get_facts` already uses) keyed by slot id, supporting both `ESN of slot N:` and `ESN of slot N is:` separator variants. **Vendor-specific role handling**: Huawei iStack `Slave` denotes the third+ member (NOT the secondary master) — the OPPOSITE of H3C Comware 5, where `Slave` means standby. The driver pre-translates `Master`/`Standby`/`Slave` to NetBox `active`/`standby`/`member` BEFORE calling the global `normalize_role`, preserving Comware compatibility unchanged. Standalone VRP and CSS-mode chassis both return an error banner for `display stack` → DEBUG, return None (no false positives for CSS). **CSS (Cluster Switch System — modular-chassis VRP)** is deferred to a follow-up batch: CSS uses `display css status` and requires a 4-tuple branch (`<chassis>/<slot>/<subslot>/<port>`) in `parse_member_id` for interface routing.

**Master pinning across vendors.** Regardless of driver, the master Device emitted to Diode is always the **lowest stack-member id present**. This is independent of live role (StackWise's `Active`, Junos VC's `Master*`) so a role failover does not change the master record sent to NetBox — the Diode plugin's `unique_master` matcher resolves the existing VC on re-run instead of creating a new one. The matcher fields used for VC re-identification (asset_tag, primary_ip4/6, name+site+tenant, `metadata.source_match`) are carried consistently across master Device, VC `master` ref, and each member's `virtual_chassis.master` ref so the matcher cascade resolves through the same record every cycle.

## Modules / ModuleBays

Drivers that implement `get_modules()` discover the per-slot module inventory on modular chassis and emit NetBox `Module` and `ModuleBay` entities under the chassis device (or, on VC-of-modular topologies, under each member that physically owns the slot). Drivers without the method continue to emit no module entries regardless of whether the target is a modular chassis — this is opt-in per driver, analogous to interface ↔ VLAN associations and stack discovery. Emission is also gated by the `discover_modules` policy option (`off` / `linecards` / `full`); see the [device discovery README](./README.md#modules--modulebays) for the contract, the three modes, and the current sub-bay rendering trade-off.

| Driver | Status |
|--------|--------|
| `ios` | Supported (Cisco IOS / IOS-XE) — Catalyst 9404R / 9407R / 9410R modular chassis plus Catalyst 9300 with FRU uplink modules and Catalyst 9400 / 9500 in StackWise Virtual mode; parses `show inventory` driver-locally for `Slot N` / `Switch N Slot M` (also `Slot N - <role>` with hyphenated role) and `Switch N FRU Uplink Module M` rows, joins per-slot model + serial + description, and PID-classifies each row into `supervisor` / `linecard` / `transceiver` (extensible to `fan` / `psu`). Transceiver sub-bays are derived from `show ip interface brief` rows whose name canonicalises to a port form (long-form `GigabitEthernet`/`TenGigabitEthernet`/...) and whose installed PID classifies as a transceiver — `StackPort` and other non-port `show inventory` NAME rows are filtered out by a narrow ifname-prefix regex plus the PID gate. |
| `eos` | Supported (Arista EOS) — 7500R / 7800R3 modular chassis (fixed-configuration platforms like the 7280R have no card slots, so `get_modules` returns no module entries — `discover_modules` is a safe no-op there). Reads the structured `show inventory` JSON envelope (`cardSlots` + `xcvrSlots`) via the upstream `EOSDriver._run_commands` wrapper, which works against either the eAPI transport or the SSH-CLI transport (`\| json` pipe) depending on `optional_args["transport"]`. Bays are keyed by full slot name (`Supervisor1`, `Linecard1`, …) so supervisor-vs-linecard slot-1 entries don't collide. PSU / fan recognized but never emitted as Module entities. Standalone modular only — Arista MLAG is peer-to-peer, not a virtual chassis. |
| `junos` | Supported (Juniper Junos) — MX480 / MX960 / MX10003 / EX9214 / QFX10000 modular chassis, plus Junos Virtual Chassis of EX9200s for the VC-of-modular case. Walks the pyEZ NETCONF `<get-chassis-inventory/>` RPC tree — `chassis-module` (FPC) → `chassis-sub-module` (PIC) → `chassis-sub-sub-module` (transceiver) — at depth 3, the maximum the canonical envelope supports. Routing Engine modules classify as `supervisor`. Standalone non-modular EX/QFX returns no module entries. |
| `nxos` | Supported (Cisco NX-OS via NX-API) — Nexus 9500-series (9504 / 9508 / 9516) and Nexus 7000 legacy modular chassis. Joins `show module` (chassis-aware slot occupancy) with `show inventory` (PID + serial) on the slot number. Fabric modules — reported in the `show module` Xbar table (NX-API `TABLE_xbarinfo`) — are emitted as `linecard`-type Module entities. Transceiver sub-bays come from `show inventory` rows keyed by `EthernetN/M` ifnames. Active and standby supervisors both emit as `supervisor`-type Module entities. Standalone modular only — vPC / VDC do not model as virtual chassis in NetBox. |
| `nxos_ssh` | Supported (Cisco NX-OS via SSH) — same hardware coverage as `nxos`, including fabric modules. Uses ntc-templates for `show module` and `show inventory` (the `cisco_nxos_show_inventory.textfsm` template covers the same NAME/DESCR/PID/VID/SN block format used by `cisco_ios_show_inventory.textfsm`); the Xbar (fabric) table that ntc-templates drops is recovered by a narrow raw-text scrape so fabric modules emit identically to the NX-API path. Produces an envelope byte-identical to the NX-API path for the same physical chassis. |
| `cisco_fxos` | Supported (Cisco FXOS) — Firepower 9300 / 4100 security appliances. Reuses the driver's existing `show inventory` parse (ntc-templates `cisco_nxos` block: NAME / DESCR / PID / VID / SN) and emits security modules (`Module N`) and network modules (`Network Module N`) as `linecard`-type Module entities. The MIO / supervisor is the integrated `Chassis` row, not a separate slot bay, so no supervisor Module is emitted. PSU / fan recognized but not emitted. Standalone only — no virtual chassis. |
| `huawei_vrp` | Supported (Huawei VRP) — CloudEngine CE12800 modular chassis. Joins `display device` (slot + board-type token) with `display esn` (per-slot serial); MPU boards classify as `supervisor`, LPU / SFU boards as `linecard`, other Huawei board types (e.g. CMU monitoring units) are filtered out. Standalone slot bays only — no transceiver sub-bays (no DOM / optic template), no CSS-of-modular dispatch, and NE40E `display device` (which uses a 6-column layout the `huawei_vrp` ntc-template does not match) are documented v1 limitations. Returns no module entries when `display device` does not parse. |
| `aruba_aoscx` | Supported (Aruba AOS-CX via REST) — 8400 / 6400 modular chassis. Parses the pyaoscx `system/subsystems` resource (member-addressed `<type>,<member/slot>` keys); `management_module` classifies as `supervisor`, `line_card` / `fabric_module` as `linecard`, other subsystem types are filtered out. DOM optics from each interface's `hw_intf_info` become transceiver sub-bays under the owning line-card slot. Supports standalone chassis plus VSF-of-modular (one nested member envelope per VSF member). |
| `aruba_aoscx_ssh` | Unsupported — AOS-CX has no `show modules`-equivalent ntc-template, so `get_modules()` is a no-op (returns no module entries). Use the REST `aruba_aoscx` driver for module / module bay discovery on AOS-CX. |
| `iosxr` | Supported (Cisco IOS-XR via pyIOSXR / XML-Agent over SSH) — ASR9000 / NCS5500 / NCS5700 / NCS540 / NCS6000 modular chassis. Fetches `show inventory` through the XR XML-Agent and reuses the `cisco_nxos_show_inventory` ntc-template (XR shares the NAME / DESCR / PID / VID / SN block layout). RP / RSP slots classify as `supervisor`; numeric line-card slots as `linecard`; fabric / switch cards (`FC*` / `SC*`) emit as `linecard` (no distinct fabric type today). DOM optics become transceiver sub-bays under the owning linecard. Supports standalone and **nV-cluster (per-rack member) dispatch** — rack-prefixed slot names are the authoritative cluster signal, no separate cluster RPC needed. |
| `iosxr_netconf` | Supported (Cisco IOS-XR via NETCONF) — same hardware coverage as `iosxr`. Fetches a focused `Cisco-IOS-XR-invmgr-oper:inventory` subtree via ncclient and walks the flat `entities/entity` view (matching the path the upstream `napalm.iosxr_netconf` driver already uses for `get_facts`) to the same row shape the SSH path consumes, so the emitted envelope is byte-identical to the SSH path for the same physical chassis. |

**Cisco IOS (`ios`)** classifies modules from `show inventory` PIDs: a `SUP`/supervisor PID becomes `type=supervisor`, optic PIDs (SFP-*, QSFP-*, X2-*, GLC-*, CFP-*, etc.) become `type=transceiver`, and everything else inside a chassis slot defaults to `type=linecard`. Role-hint extraction from `Slot N <role>` / `Slot N - <role>` NAME rows takes precedence over PID-only inference (so e.g. `Slot 1 Supervisor` always classifies as `supervisor`, even if the PID is ambiguous). On a VC-of-modular topology (Catalyst 9300 stack with FRU uplinks, Catalyst 9400 / 9500 StackWise Virtual), the driver groups inventory rows by stack-member id using the `Switch N Slot M` / `Switch N FRU Uplink Module M` row prefixes and emits one nested member envelope per switch. Standalone non-modular chassis (no `Slot N` / `Switch N Slot M` rows; e.g. a Cat 3850 or 2960X) emit no module entries — the standalone single-`Device` path is unchanged. Standalone IOS-XE platforms that report rows like `module 0` (ISR / ASR route processors) are rejected by the slot regex so they cannot leak through as bogus chassis slots. The 4-tuple SVL interface parser accepts both `Gi`/`GigabitEthernet` (Cat 9500 SVL with 1G FRU uplinks) and the higher-speed prefixes (`Te`/`Fo`/`Hu`/multigig), with bare-`Ethernet`/`Eth` 4-tuple names still rejected as NX-OS FEX.

**Arista EOS (`eos`).** Module discovery uses `self._run_commands(["show inventory"], encoding="json")` — the upstream `EOSDriver` wrapper that bridges BOTH the eAPI transport (pyeapi `Node.run_commands`) AND the SSH-CLI transport (Netmiko `send_command` + ` | json` pipe). The active transport is whichever was selected by the driver's `optional_args["transport"]` setting at `open()` time (defaults to eAPI). Either transport returns the same JSON envelope, so module discovery works on both. The driver still returns `None` if the active transport rejects the command (e.g. unprivileged operator on SSH-only, or eAPI disabled and SSH timing out). Fabric modules (`Fabric N` slot names) are emitted as `linecard`-type Module entities for v1 because NetBox's Module schema does not carry a distinct fabric concept today. PSU / fan slots are classified but not emitted.

**Juniper Junos (`junos`).** Supports the FPC → PIC → transceiver depth-3 hierarchy on standalone modular chassis (MX / EX9200 / QFX10000) and on Junos Virtual Chassis composed of modular members. VC detection inspects the root tag of the chassis-inventory RPC reply — `multi-routing-engine-results` → VC, `chassis-inventory` → standalone. Standalone non-modular switches (e.g. EX3400) return `None` so the existing single-Device discovery path is unchanged. Routing Engine `<chassis-module>` entries map to `supervisor`. Transceivers are recognized by MSA-prefixed part numbers (`SFP-`, `QSFP-`, …) OR — for Juniper optics whose `<part-number>` is an internal `740-xxxxxx` code rather than an MSA PID — by an optic keyword (`sfp`/`qsfp`/`xfp`/`transceiver`/`optic`) in the `<description>`, matched on word boundaries so a line-card description that merely lists `SFPP` ports is not misclassified. Four-level FPC → MIC → PIC → optic chassis (some MX MIC platforms) are a known v1 limitation — the optic below the depth-3 cap is not emitted.

**Cisco NX-OS (`nxos`, NX-API JSON).** Calls NX-API via the existing `device.show(cmd, raw_text=False)` transport (same API as `get_interfaces_vlans`). Joins `show module` and `show inventory` on the slot number; fixed switches (`show module` returns one row) yield `None`. vPC and VDC are not virtual chassis in NetBox terms and are intentionally NOT emitted as VC payloads.

**Cisco NX-OS (`nxos_ssh`, SSH CLI).** Functional equivalent of `nxos` for deployments where the eAPI / NX-API transport is unavailable. Parses `show module` and `show inventory` via `ntc_templates.parse_output(platform="cisco_nxos", ...)` direct calls. The envelope is byte-identical to the NX-API path for the same physical chassis, so customers can switch transports without re-discovering modules.

**Cisco FXOS (`cisco_fxos`).** Reuses the driver's existing `show inventory` parse (ntc-templates `cisco_nxos` block) rather than issuing a new command. Security modules (`Module N`) and network modules (`Network Module N`) are emitted as `linecard`-type Module entities, keyed so the bare-integer security-module slots and the full-name network-module bays do not collide. The Firepower MIO / supervisor is integrated into the `Chassis` row, which is not iterated as a slot bay, so no supervisor Module is emitted. Firepower transceivers are not reliably present in `show inventory`, so no optic sub-bays are produced in v1. Returns no module entries when the inventory has no module rows (e.g. a fixed FTD / ASA on Firepower 1000). Standalone only — Firepower has no virtual-chassis concept.

**Huawei VRP (`huawei_vrp`).** Joins two CLI commands on the slot number: `display device` supplies the per-slot board-type token (parsed via the `huawei_vrp` ntc-template, where the board type lands in the `pid` field on the CloudEngine `Device status:` layout) and `display esn` supplies the per-slot serial. MPU (Main Processing Unit) boards classify as `supervisor`; LPU (line) and SFU (fabric) boards as `linecard`; unknown board tokens (e.g. CMU monitoring units) classify as `other` and are dropped before emission, so non-forwarding auxiliary FRUs are not mis-discovered as linecards. Standalone slot bays only — three documented v1 limitations: (1) transceiver sub-bays are not emitted (no DOM / optic ntc-template), (2) CSS-of-modular (Cluster Switch System) is not dispatched, and (3) NE40E `display device` uses a 6-column layout (`Slot Type Online Register Status Primary`) that the `huawei_vrp` ntc-template does not match, so NE40E chassis return no module entries in v1 pending a verified driver-local fallback parser. The driver returns no module entries (rather than guessing) whenever `display device` fails to parse or reports no slot rows.

**Aruba AOS-CX REST (`aruba_aoscx`).** Reads the pyaoscx `system/subsystems` resource — a map keyed `<subsystem_type>,<member/slot>` (e.g. `line_card,1/3`). Classification is an emit-whitelist: `management_module` → `supervisor`, `line_card` / `fabric_module` → `linecard`; any other subsystem type is filtered out rather than guessed. Empty line-card slots (no part number / serial) are skipped. DOM optics are read from each interface's `hw_intf_info` (the same attribute the driver already consumes for MAC / speed) and emitted as transceiver sub-bays under the line-card slot that physically owns the member-addressed port. Beyond standalone chassis, the driver dispatches VSF-of-modular topologies into one nested member envelope per VSF member, using the member id embedded in the subsystem key.

**Aruba AOS-CX SSH (`aruba_aoscx_ssh`).** AOS-CX exposes no `show modules`-equivalent command with an ntc-template, so the SSH driver's `get_modules()` is an intentional no-op that returns no module entries. Operators who need module / module bay discovery on AOS-CX should use the REST `aruba_aoscx` driver.

**Cisco IOS-XR (`iosxr`).** Uses pyIOSXR's `_execute_show("show inventory")` to fetch the inventory text over the XR XML-Agent and parses it via the `cisco_nxos_show_inventory` ntc-template — XR's block layout matches NX-OS / IOS / FXOS, so no new template is needed. Classification keys off the slot NAME pattern (e.g. `0/RP0/CPU0` → supervisor, `0/0/CPU0` → linecard, `0/FC0` → linecard); fabric / switch cards emit as `linecard` because NetBox has no distinct fabric Module type today. Transceiver-PID rows whose NAME matches the port pattern (`<r>/<s>/<port>` or `<r>/<s>/<port>:<sub>`) attach as transceiver sub-bays under the linecard whose `<rack>/<slot>` prefix matches. Multi-rack nV cluster dispatch is auto-detected from the leading rack id in slot NAMEs — each rack becomes its own NetBox member envelope, no separate cluster-membership command is consulted. PSU / fan rows are recognized but never emitted as Module entities. Standalone fixed-config XR (e.g. IOS-XRv) returns no module entries.

**Cisco IOS-XR (`iosxr_netconf`).** Functional equivalent of `iosxr` for deployments using pure NETCONF transport. ncclient `<get>` with a focused subtree filter on the `Cisco-IOS-XR-invmgr-oper:inventory` model returns a flat `entities/entity` list (same view the upstream `napalm.iosxr_netconf` driver uses for `get_facts`); each `<entity>` carries a `<name>` (the slot identifier — `Rack 0`, `0/RP0/CPU0`, `0/0/CPU0`, …) plus an `<attributes><inv-basic-bag>` container with `<description>`, `<model-name>`, and `<serial-number>`. An lxml walk produces row dicts matching the SSH driver's `name` / `descr` / `pid` / `sn` shape, so classification, nV dispatch, and sub-bay attachment all share the same logic. The emitted envelope is byte-identical to the SSH path on the same physical chassis.

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
