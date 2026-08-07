# SNMP Discovery
The SNMP discovery backend leverages SNMP (Simple Network Management Protocol) to connect to network devices and collect network information.

This backend works with any SNMPv1/v2c/v3 capable device. For the list of vendors with bundled device model lookup coverage, see [SNMP Discovery — Supported Platforms](./supported_platforms.md).

## Diode Entities
The SNMP discovery backend uses [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) to ingest the following entities:

* [Device](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/device/main.go)
* [Interface](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/interface_entity/main.go)
* [IP Address](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/ip_address/main.go)
* [Mac Address](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/mac_address/main.go)
* [Platform](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/platform/main.go)
* [Manufacturer](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/manufacturer/main.go)
* [Site](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/site/main.go)
* [VLAN](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/vlan/main.go)
* [VirtualChassis](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/virtual_chassis/main.go)
* [Module](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/module/main.go)
* [ModuleBay](https://github.com/netboxlabs/diode-sdk-go/blob/develop/docs/examples/module_bay/main.go)

When a target is a switch stack / Virtual Chassis (NetBox `VirtualChassis`), snmp-discovery emits one `VirtualChassis` entity plus one `Device` per stack member, and routes each interface/IP to the member that physically owns it — see [Switch stacks / Virtual Chassis](#switch-stacks--virtual-chassis) below. Standalone switches and devices not in stack mode fall through to the existing single-`Device` path with no change in behaviour.

When a target is a modular chassis and the `discover_modules` policy option is enabled, snmp-discovery additionally emits `Module` and `ModuleBay` entities for each chassis slot (and, in `full` mode, each transceiver sub-bay) — see [Modules / ModuleBays](#modules--modulebays) below. Defaults to `off`, so existing operators see zero behaviour change unless they explicitly opt in.

When the `discover_vrfs` policy option is enabled, snmp-discovery emits a `VRF` entity for each VRF reported by the device's VRF MIB tables and attaches it to the IP addresses of the VRF's member interfaces — see [VRFs](#vrfs) below. Defaults to `false`, so existing operators see zero behaviour change.

When the `discover_asset_tags` policy option is enabled, snmp-discovery reads `ENTITY-MIB::entPhysicalAssetID` and populates `asset_tag` on each emitted device — including per-member tags on virtual-chassis stacks. Defaults to `false`, so existing operators see zero behaviour change. Note that NetBox `asset_tag` values are unique and act as the highest-precedence device matcher during ingestion: enable this only if the tags provisioned on your devices are trustworthy and unique.

When the `emit_device_name` policy option is set to `false`, snmp-discovery still walks `sysName` but does **not** emit `Device.name` on the matched device. Use this with a target `netbox_id` / `metadata.source_match` so Diode matches the existing NetBox record without proposing a hostname rename when the device's `sysName` differs from the NetBox name. The name is suppressed only when the device carries a matcher that also travels on its nested references — `source_match` (netbox_id) or `asset_tag`; if neither is present the name is kept and a warning is logged. (Matching by `serial` or `primary_ip` alone does not enable omission: `serial` is not a unique NetBox matcher, and `primary_ip` is stripped from the nested device stubs.) The name is suppressed across every representation of the device that reaches the payload: the device itself, the shared virtual-chassis master reference, the nested device stubs on interfaces, and the device reference embedded in its own `primary_ip4`/`primary_ip6`. On a virtual-chassis stack, member names and the virtual-chassis name are unaffected. Defaults to `true`.

When a device exposes the relevant MIBs, interfaces also carry their switching configuration: `mode` (`access` / `tagged` / `tagged-all` / unset for routed), the untagged (access/native) VLAN, and the list of tagged VLANs. VLANs referenced on an interface but not present in the device's VLAN database are auto-emitted as VLAN entities so the association is complete in NetBox; this behavior can be disabled via the `create_unknown_vlans` option (see below). Auto-emitted stubs use the placeholder name `VLAN<vid>` (e.g. `VLAN42`) because NetBox's `ipam.vlan.name` is required — operators or sibling switches can later overwrite the placeholder via the same vid+group matcher. VLAN discovery uses Q-BRIDGE-MIB (RFC 4363) as the generic source and a Cisco-specific overlay (CISCO-VLAN-MEMBERSHIP-MIB, CISCO-VOICE-VLAN-MIB) on Cisco devices that don't fully implement Q-BRIDGE — see [SNMP Discovery — Supported Platforms](./supported_platforms.md#interface--vlan-associations) for which device classes are covered.

Note: when a switchport is converted to a routed (L3) interface between discovery cycles, prior `mode`/untagged-VLAN/tagged-VLAN associations are NOT automatically cleared in NetBox; operators must clear them manually. This is a current limitation of the Diode plugin's PATCH semantics and is tracked separately. The same caveat applies on device-discovery.

## Configuration
The `snmp_discovery` backend uses the `diode` settings specified in the `common` subsection to forward discovery results. Optional backend-level settings tune ingest throughput and memory use (see [Backend](#backend) below). Per-policy behavior is configured separately under [Policy](#policy).

```yaml
orb:
  backends:
    snmp_discovery:
      ingest_buffer_size: 512
    common:
      diode:
        target: grpc://127.0.0.1:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
```

### Backend
Backend-level settings apply to the `snmp_discovery` process as a whole (distinct from per-policy `config`).

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| ingest_buffer_size | integer | no | Capacity of the buffered queue that serializes Diode ingest calls. Defaults to `512`. |

Diode ingest runs through a single-consumer queue so concurrent crawl jobs finishing at once do not trigger concurrent OAuth token refresh storms. Increase `ingest_buffer_size` when large subnet bursts may enqueue many payloads before the consumer drains them; decrease it if memory is a concern — each queued request retains its entity payload until processed.

## Policy
SNMP discovery policies are broken down into two subsections: `config` and `scope`.


### Config Section
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| schedule | cron format | no | Cron expression for scheduling (e.g., "*/5 * * * *") |
| timeout | integer | no | Timeout for whole policy in seconds (defaults to 120) |
| snmp_timeout | integer | no | Timeout for SNMP operations in seconds for SNMP operations (defaults to 5) |
| snmp_probe_timeout | integer | no | Timeout for SNMP probe operations in seconds (defaults to 1) |
| retries | integer | no | Number of retries for SNMP operations (defaults to 0) |
| lookup_extensions_dir | string | no | Directory containing device model lookup files |
| defaults | map | no | Default values for entities (description, comments, tags, etc.) |
| options | map | no | Per-policy behavior toggles (see [Options Parameters](#options-parameters)) |

#### Options Parameters
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| create_unknown_vlans | bool | no | Auto-emit a VLAN entity for any VID referenced on an interface but absent from the device's `dot1qVlanStaticTable`. Stubs inherit attributes from `defaults.vlan` for stable matching. Defaults to `true`. Set `false` to drop unknown VIDs from interface associations entirely (requires every referenced VLAN to already exist in NetBox). |
| discover_asset_tags | bool | no | When `true`, walks `ENTITY-MIB::entPhysicalAssetID` and populates each device's `asset_tag` from its chassis row — standalone devices get the chassis tag; each virtual-chassis member gets its own per-member tag. An operator-supplied `defaults.asset_tag` (literal or OID reference) always takes precedence on the target device. Values that are empty, non-printable, well-known placeholders (`UNKNOWN`, `N/A`, `None`, `0`, …), longer than NetBox's 50-character limit, or duplicated across chassis rows of the same target are skipped with a warning — `asset_tag` is unique in NetBox and is the highest-precedence device matcher, so a duplicated tag would merge two devices into one record. The same protection applies across targets of one policy: the first target to report a tag owns it for the lifetime of the policy, and other targets reporting the same value (vendor-cloned EEPROM data) are skipped with a warning. Defaults to `false` — the column is not even walked when off. |
| discover_modules | string | no | Controls emission of `Module` / `ModuleBay` entities on modular chassis. One of `off` (default — no modules emitted, zero behaviour change), `linecards` (one Module per chassis slot — line cards and supervisors; PSU / fan recognised by the PID classifier but never emitted), or `full` (linecards plus one Module per transceiver sub-bay; interfaces carry a `module=` ref to the transceiver they're connected to). Detection is vendor-neutral via `ENTITY-MIB::entPhysicalTable` — see the [supported platforms page](./supported_platforms.md#modules--modulebays). See [Modules / ModuleBays](#modules--modulebays) for the emission shape and current sub-bay rendering trade-off. |
| discover_vrfs | bool | no | When `true`, discovers VRFs from the device's VRF MIB tables and attaches them to the IP addresses of each VRF's member interfaces (matched by `ifIndex`). A discovered VRF takes precedence over the `vrf` / `vrf_ipv4` / `vrf_ipv6` defaults for those interfaces; other addresses keep the configured defaults. Defaults to `false` — the VRF tables are not even walked when off. See [VRFs](#vrfs) for the MIB tiers, route-distinguisher handling, and limitations. |
| emit_prefixes | bool | no | Derive one `Prefix` entity per unique (network, VRF) from the discovered IP addresses, matching device-discovery's behavior. **Defaults to `true`** — set `false` to opt out. See [Prefixes](#prefixes). |
| emit_host_prefixes | bool | no | Derive a `Prefix` from IPv4 `/32` and IPv6 `/128` addresses. **Defaults to `false`** (the opposite of `emit_prefixes`): a host prefix only restates the address, which is already emitted as an `IPAddress` entity. Set `true` to derive them anyway, e.g. when loopback `/32`s are deliberately tracked as prefixes in NetBox. IPv6 link-local prefixes (`fe80::/10`) are never derived and are unaffected by this option. See [Prefixes](#prefixes). |
| emit_device_name | bool | no | **Defaults to `true`.** Set `false` to stop emitting `Device.name` (from `sysName`) on the matched device, so continual discovery under Assurance does not propose a hostname rename when `sysName` differs from the NetBox name. `sysName` is still walked; only the emitted field is suppressed. Intended for use with a target `netbox_id` / `metadata.source_match`. Takes effect only when the device is matchable by a field that also travels on its nested references — `source_match` (netbox_id) or `asset_tag`; if neither is present the name is kept and a warning is logged, to avoid emitting an unmatchable device. Matching by `serial` (not unique in NetBox) or `primary_ip` alone does **not** enable omission. Does not affect virtual-chassis member names. |
| interface_name_source | string | no | Source for the NetBox interface **name**. One of `auto` (default — ifDescr preferred, ifName used when ifDescr is empty or looks like a hardware description; zero behaviour change), `ifname` (force SNMP `ifName`), or `ifdescr` (force `ifDescr`). Each forced mode falls back to the other field when its primary is empty for an interface. An unrecognized value is warned once and treated as `auto`. ⚠️ Changing this on an existing deployment renames interfaces — see [Interface Name Selection](./interface.md#interface-name-selection). |
| propagate_defaults_to_prefix_scope | bool | no | When `true` AND no explicit `defaults.prefix.scope_*` is set, `defaults.site` cascades to the Prefix scope site and `defaults.location` to the scope location (location wins, carrying the site). Defaults to `false`. Any explicit `defaults.prefix.scope_*` skips the cascade wholesale. |

#### Defaults Parameters
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| tags | list | no | List of tags to apply to all discovered entities |
| site | string | no | Default site name for discovered devices |
| location | string | no | Default location for discovered devices. Accepts a literal name or an SNMP OID reference (see [Default values from SNMP OIDs](#default-values-from-snmp-oids)) |
| asset_tag | string | no | Default asset tag for discovered devices. Accepts a literal value or an SNMP OID reference (see [Default values from SNMP OIDs](#default-values-from-snmp-oids)). NetBox enforces a 50-character limit; resolved values longer than 50 characters are warn-logged and skipped |
| role | string | no | Default role for discovered devices |
| tenant | string \| map | no | Default tenant for discovered devices. Accepts a bare tenant name or a map with `name` + optional `group` / `description` / `comments` / `tags` (see the [tenant map](#tenant-map) below). Applies to Device entities only — IP address, prefix, and VLAN tenants keep their own per-entity defaults (`ip_address.tenant`, `prefix.tenant`, `vlan.tenant`). Virtual-chassis members inherit the master's tenant. In a per-target `override_defaults`, tenant merges field-wise: overriding `name` keeps an inherited `group` |
| interface_patterns | list  | no | User-defined interface type patterns (see [Interface Type Matching](./interface.md)) |
| interface_exclude_patterns | list | no | Regex patterns to exclude interfaces (and their IPs) from ingestion (see [Interface Exclusion](./interface.md#interface-exclusion-patterns)) |

##### Nested Defaults
| Parameter | Type | Description |
|---------|----|-----------|
| device      | map  | Device-specific defaults        |
| ├─ description | string  | Device description           |
| ├─ comments   | string  | Device comments               |
| ├─ model   | string  | Override the auto-discovered device model (see [Device Model Lookup](#device-model-lookup)) |
| ├─ manufacturer | string  | Override the auto-discovered manufacturer name |
| ├─ platform   | string  | Override the auto-discovered platform name   |
| interface    | map  | Interface-specific defaults    |
| ├─ description | string  | Interface description        |
| ├─ if_type       | string | Interface type (e.g. "ethernet", "virtual")  |
| ip_address   | map  | IP address-specific defaults  |
| ├─ role   | string  | IP address role                  |
| ├─ vrf   | string \| map  | IP address VRF name, or a VRF map (see the [vrf map](#vrf-map) below). Used for both address families unless an AF-specific override is set. |
| ├─ vrf_ipv4   | string \| map  | IPv4-specific VRF override (same shape as `vrf`). When set, IPv4 addresses use this VRF; IPv6 still uses `vrf`. The override replaces `vrf` wholesale for its family — it does not inherit `vrf.name`. |
| ├─ vrf_ipv6   | string \| map  | IPv6-specific VRF override (same shape as `vrf`). When set, IPv6 addresses use this VRF; IPv4 still uses `vrf`. |
| prefix   | map  | Prefix-specific defaults applied to derived Prefix entities (see [Prefixes](#prefixes)) |
| ├─ description | string  | Prefix description |
| ├─ comments | string  | Prefix comments |
| ├─ tags | list  | Prefix tags |
| ├─ role | string  | Prefix role |
| ├─ tenant | string  | Prefix tenant |
| ├─ vrf   | string \| map  | Prefix VRF (same `vrf` map shape; independent of `ip_address.vrf`) |
| ├─ vrf_ipv4   | string \| map  | IPv4-specific prefix VRF override |
| ├─ vrf_ipv6   | string \| map  | IPv6-specific prefix VRF override |
| ├─ scope_site | string  | Prefix scope site. Setting any explicit scope skips the `propagate_defaults_to_prefix_scope` cascade wholesale. |
| ├─ scope_location | string  | Prefix scope location (wins over `scope_site` on the wire, carrying the site for NetBox's per-site location uniqueness) |
| vrf | map | VRF-specific defaults (used within `ip_address` and `prefix`, incl. the `vrf_ipv4` / `vrf_ipv6` overrides) |
| ├─ name | string  | VRF name |
| ├─ rd | string  | Route distinguisher (e.g. `65000:100`) |
| ├─ description | string  | VRF description |
| ├─ comments | string  | VRF comments |
| ├─ tags | list  | VRF tags |
| ├─ tenant   | string  | IP address tenant              |
| ├─ description | string  | IP address description      |
| vlan    | map  | VLAN-specific defaults  |
| ├─ description | string  | VLAN description |
| ├─ tags | list | Per-VLAN tags. Merged with the top-level `tags` list on each emitted VLAN entity, mirroring the `device`/`interface`/`ip_address` defaults pattern. |
| ├─ group | string | VLAN group name. When set, every emitted VLAN is attached to an `ipam.vlangroup` scoped to `defaults.site`: the group's `scope_site` is populated from `defaults.site` |
| ├─ tenant | string | VLAN tenant |
| ├─ status | string | VLAN status override (`active`, `reserved`, `deprecated`). When unset, status is derived from `dot1qVlanStaticRowStatus`: `active(1)` → `active`, `notInService(2)` → `reserved`. |

##### Tenant Map
The top-level `tenant` default accepts either a bare string (tenant name) or a map:

| Parameter | Type | Description |
|---------|----|-----------|
| name | string  | Tenant name |
| group | string  | Tenant group name |
| description | string  | Tenant description |
| comments | string  | Tenant comments |
| tags | list  | Tenant tags |

### Scope Section
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| targets | list | yes | List of SNMP targets to discover. Supports subnets (e.g. 192.168.1.0/28), IP ranges (192.168.0.1-192.168.0.10 or 192.168.0.1-10), and per-target authentication. |
| authentication | map | conditional | Policy-level SNMP authentication settings (required unless all targets have their own authentication) |

#### Target Parameters
Each target in the `targets` list can include:

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| host | string | yes | Target hostname,  IP address, subnets or IP ranges |
| port | integer | no | SNMP port (defaults to 161) |
| authentication | map | no | Target-specific authentication (overrides policy-level authentication) |
| override_defaults | map | no | Allows overriding of any defaults for a specific target in the scope |
| netbox_id | integer | no | NetBox device primary key. When set, the diode plugin matches the device by PK instead of by name. Ignored when host is a subnet or IP range. |

#### Authentication Parameters
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| protocol_version | string | yes | SNMP protocol version ("SNMPv1", "SNMPv2c", or "SNMPv3") |
| community | string | yes* | SNMP community string for v1/v2c authentication |
| username | string | no | SNMPv3 username |
| security_level | string | no | SNMPv3 security level ("noAuthNoPriv", "authNoPriv", "authPriv") |
| auth_protocol | string | no | SNMPv3 authentication protocol (see [SNMPv3 auth/priv protocols](#snmpv3-authpriv-protocols)) |
| auth_passphrase | string | no | SNMPv3 authentication passphrase |
| priv_protocol | string | no | SNMPv3 privacy protocol (see [SNMPv3 auth/priv protocols](#snmpv3-authpriv-protocols)) |
| priv_passphrase | string | no | SNMPv3 privacy passphrase |
| context_name | string | no | SNMPv3 context name (equivalent to `snmpwalk -n`). Required by devices that expose MIB data in a named context; such devices return an empty walk when it is omitted. Rejected for SNMPv1/v2c. |

*Required for SNMPv1/v2c, optional for SNMPv3

**Note:** Authentication can be specified at the policy level (under `scope.authentication`) as a fallback, or per-target (under each target's `authentication` field). Targets without authentication use the policy-level authentication — this is a wholesale replacement, not a field-level merge: a target with its own `authentication` block does not inherit any individual field, such as `context_name`, from the policy-level block. Environment variables are supported using `${VAR}` syntax for `community`, `username`, `auth_passphrase`, `priv_passphrase`, and `context_name` fields.

#### SNMPv3 auth/priv protocols
Values are case-sensitive and must be passed as one of the strings in the tables below.

`auth_protocol`:

| Value | Algorithm |
|:-----:|:---------:|
| `NoAuth` | No authentication |
| `MD5` | HMAC-MD5-96 |
| `SHA` | HMAC-SHA-1-96 (SHA-1) |
| `SHA224` | HMAC-SHA-224 |
| `SHA256` | HMAC-SHA-256 |
| `SHA384` | HMAC-SHA-384 |
| `SHA512` | HMAC-SHA-512 |

`priv_protocol`:

| Value | Algorithm |
|:-----:|:---------:|
| `NoPriv` | No privacy |
| `DES` | CBC-DES |
| `AES` | CFB128-AES-128 |
| `AES192` | CFB128-AES-192 (Blumenthal-draft key localization) |
| `AES256` | CFB128-AES-256 (Blumenthal-draft key localization) |
| `AES192C` | CFB128-AES-192 (Reeder-draft key localization, Cisco) |
| `AES256C` | CFB128-AES-256 (Reeder-draft key localization, Cisco) |

**Note:** `SHA` is SHA-1 and `AES` is AES-128 — both kept for backward compatibility. For modern deployments, prefer `SHA256` (or stronger) and `AES256`. Use the `*C` privacy variants when interoperating with Cisco devices that follow the Reeder AES key-localization draft instead of the Blumenthal draft.

### Sample
A sample policy including all parameters supported by the SNMP discovery backend.

```yaml
config:
  schedule: "0 */6 * * *" # Cron expression - every 6 hours
  timeout: 300 # Timeout for policy in seconds (default 2 minutes)
  snmp_timeout: 10 # Timeout for SNMP operations in seconds (default 5 seconds)
  retries: 3 # Number of retries
  defaults:
    tags: ["snmp-discovery", "orb"]
    site: "datacenter-01"
    location: ".1.3.6.1.2.1.1.6.0"     # Resolve from sysLocation (or use a literal like "rack-42")
    asset_tag: ".1.3.6.1.2.1.1.4.0"    # Resolve from sysContact (or use a literal)
    role: "network"
    tenant: "network-ops"              # Bare name, or a map: { name: network-ops, group: infrastructure }
    ip_address:
      description: "SNMP discovered IP"
      role: "management"
      tenant: "network-ops"
      # vrf accepts either a bare name (rd left empty) ...
      # vrf: "management"
      # ... or a map with name + optional rd / description / comments / tags:
      vrf:
        name: "management"
        rd: "65000:100"
      # Per-address-family overrides (optional): the family-specific VRF
      # wins for that family's addresses, replacing vrf wholesale.
      # vrf_ipv4: "ipv4-vrf"
      # vrf_ipv6: { name: "ipv6-vrf", rd: "65000:6" }
    interface:
      description: "Auto-discovered interface"
      if_type: "ethernet"
    interface_patterns:
      - match: "^(GigabitEthernet|Gi).*"
        type: "1000base-t"
      - match: "^(TenGigE|Te).*"
        type: "10gbase-x-sfpp"
    interface_exclude_patterns:
      - "^tap.*"
      - "^veth.*"
    device:
      description: "SNMP discovered device"
      comments: "Automatically discovered via SNMP"
    vlan:
      tags: ["snmp-discovery"]
      group: "datacenter-01"
      tenant: "network-ops"
  options:
    create_unknown_vlans: true # Default; set false to drop unknown VIDs from interface associations
  lookup_extensions_dir: "/opt/orb/snmp-extensions" # Specifies a directory containing device data yaml files (see below)
scope:
  targets:
    - host: "192.168.1.1/24" # subnet support
    - host: "192.168.2.2-10" # range support
    - host: "10.0.0.1"
      port: 162  # Non-standard SNMP port
      netbox_id: 42
      override_defaults:
        role: "switch"
        tags: ["custom"]
        device:
          model: "CCR2004-16G-2S+"     # Hard-override auto-discovered model
          manufacturer: "MikroTik"      # Hard-override auto-discovered manufacturer
          platform: "RouterOS"          # Hard-override auto-discovered platform
    - host: "10.0.0.10"
      port: 161
      authentication:  # Per-target authentication (optional)
        protocol_version: "SNMPv3"
        security_level: "authPriv"
        username: "admin"
        auth_protocol: "SHA"
        auth_passphrase: "${SNMP_AUTH_PASS}"
        priv_protocol: "AES"
        priv_passphrase: "${SNMP_PRIV_PASS}"
  authentication:  # Policy-level authentication (fallback)
    protocol_version: "SNMPv2c"
    community: "public"
```

## Switch stacks / Virtual Chassis

When the target reports 2+ chassis rows in `ENTITY-MIB` (`entPhysicalTable`) with non-empty serials, snmp-discovery emits a NetBox `VirtualChassis` plus one `Device` per stack member, and routes each interface and IP address to the correct member. Detection is vendor-neutral and driven entirely by `entPhysicalClass`, `entPhysicalContainedIn`, and `entPhysicalSerialNum`; no vendor-specific MIB is required. Standalone switches, devices not in stack mode, and members without a serial fall back to the existing single-`Device` path with no change in behaviour.

**Topology patterns detected.** Two valid `ENTITY-MIB` shapes are supported:

| Pattern | Chassis row's `entPhysicalContainedIn` | Used by |
|---|---|---|
| Flat | `0` (chassis rows at the ENTITY-MIB root) | Catalyst 9300/3850 stacks, Aruba CX VSF, Juniper EX/QFX Virtual Chassis, HP/H3C IRF, Huawei iStack, Brocade ICX |
| Wrapped | non-zero, pointing at a `entPhysicalClass = 11` (stack) container | Cisco StackWise Virtual on 9400/9500/9600/etc. |

**Emission shape** (in order):

1. **Master `Device`** — plain (no `vc_position`, no `virtual_chassis` ref). Named `<sysName>` from the SNMP walk; serial taken from the lowest-id chassis row.
2. **`VirtualChassis`** — named `<sysName>`, with `master` set to the inline matcher block of the master Device.
3. **N − 1 member `Device` entities** — each named `<sysName>-<memberID>` (matching the format `device_discovery` emits, so the same physical stack discovered by both services lands on the same NetBox rows), carrying `vc_position = <memberID>` and an inline `virtual_chassis` ref pointing to the same matcher block. Per-member serial comes from `entPhysicalSerialNum` on the member's chassis row; per-member model comes from `entPhysicalModelName` when populated.
4. **Interface / IPAddress entities** — routed to the member that physically owns them. Routing uses `entAliasMappingTable` (RFC 6933) when present, then falls back to ifName parsing: Cisco IOS/IOS-XE/NX-OS 3-tuple (`Gi1/0/1`, `Te2/1/0/3`, etc., including short forms `Te`/`Fo`/`Hu`/`Tw`/`Fi`/`Twe`), Junos FPC, Aruba CX numeric, H3C dashed. Subinterface unit suffixes (`Gi2/0/1.100`) strip to the parent before parsing.

**Member ID derivation.** One scheme is chosen for the whole member set, first usable wins. When `entPhysicalParentRelPos` is populated (`> 0`) and distinct across members it provides the member id directly; otherwise the trailing integer of `entPhysicalName` (`Switch 2`) is used. When neither column can number the members — some stacks report the same position on every chassis row and name them all `Chassis` — the leading number on each chassis's **port descendants** is used, reached by walking `entPhysicalContainedIn` downward (ports are named in the same namespace as `ifName`, e.g. `2/1/24`). That tier is accepted only when every member yields exactly one distinct number, and those numbers are distinct across members and greater than zero; anything else falls through. The final fallback is the ordinal position of the chassis row in the inventory.

Master identity is pinned to the **lowest member id present**, regardless of live role — this is required because the Diode plugin resolves an existing `VirtualChassis` via its `unique_master` matcher, and pinning to the lowest id keeps the master Device stable across live stack-role failovers so re-runs upsert the existing VC instead of creating a new one. The other matcher fields used for VC re-identification (asset_tag, primary_ip4/6, name+site+tenant, and `metadata.source_match`) are carried consistently on both the rich master Device and the inline VC `master` ref.

**When the device contradicts itself.** A signal that is merely absent falls through to the next tier, and the ordinal fallback always yields ids. But a device that reports the *same* position on two chassis rows, or the same trailing number in two names, has asserted something impossible. If no other tier can resolve such a set, the stack is refused rather than guessed: no `VirtualChassis` and no member Devices are emitted, since inventing a numbering would put wrong `vc_position` values and wrong member Device names into NetBox.

The master does still receive a serial in that case, taken from the lowest `entPhysicalIndex` chassis row. Note this is a different ordering from the lowest-member-id rule above, and necessarily so: a refused set has no member ids to pin to, and the row index is the only ordering that does not depend on the disputed numbering. Only the numbering was ambiguous — each chassis row's serial was unambiguous — so refusing the structure while dropping the serial would discard a fact the device reported plainly.

**Member AssetTag is cleared.** Diode's highest-precedence matcher for `dcim.device` is `asset_tag` (unique). The master Device carries the policy `defaults.asset_tag` value if configured; member Devices have it explicitly cleared so multiple members do not collapse onto one NetBox row through a shared asset tag. Master / standalone AssetTag behaviour from `defaults.asset_tag` is unchanged. When the `discover_asset_tags` option is enabled, members instead receive their own per-row `entPhysicalAssetID` values — only the operator-supplied defaults tag is never replicated to members.

**Orphaned member ports.** If a chassis row is dropped from the validated payload (empty serial, duplicate serial collapsed against a lower-id row, etc.) but the device still reports ports owned by that member, those interfaces are **skipped with a WARNING** rather than routed to master. Routing them to master would silently misattribute member-N ports to a different device — operators see the warning in logs and the missing port in NetBox, not a corrupted port→device mapping.

## VRFs

When the `discover_vrfs` policy option is enabled (defaults to `false`), snmp-discovery walks the device's VRF MIB tables and emits a NetBox `VRF` entity per VRF, attached to the `IPAddress` entities of the VRF's member interfaces (membership is matched by `ifIndex`, so no name canonicalization is involved). With the option off, the VRF table columns are not walked at all — zero additional SNMP load.

**MIB tiers.** Three sources are tried in order until one yields VRFs:

1. **MPLS-L3VPN-STD-MIB** (RFC 4382) — the standards path (`mplsL3VpnVrfTable` for names + route distinguishers, `mplsL3VpnIfConfTable` for membership). Implemented by Cisco IOS/IOS-XE/IOS-XR, Juniper, Nokia, Huawei, and others.
2. **MPLS-VPN-MIB** (the pre-standard experimental arc) — same table shapes; common on older Cisco IOS.
3. **CISCO-VRF-MIB** — VRF-lite platforms without the MPLS feature MIBs. No route distinguisher is available on this tier.

A tier that exposes VRF names but no membership (split-arc agents) merges membership from the lower tiers; lower tiers never introduce additional VRF names on their own.

**Precedence.** A discovered VRF wins over the `defaults.ip_address.vrf` / `vrf_ipv4` / `vrf_ipv6` settings for member interfaces' addresses; every other address keeps the configured defaults. The device's primary IP reference is kept consistent with its underlying IP address entity, so NetBox (where IP identity is address + VRF) never sees the same address in two VRF contexts.

**Route distinguishers.** Both the RFC 4382 8-byte binary encoding (type 0/1/2) and the display-string form some agents return are decoded to the canonical `ASN:nn` / `IP:nn` text. Unset or undecodable RDs stay off the wire entirely, so the VRF matches NetBox records whose RD is empty — the same caveat as device-discovery applies: if a VRF with the same name already exists in NetBox **with** an RD while the device reports none, the first cycle creates a separate RD-less VRF record.

**Limitation — VRF-scoped addresses.** Some platforms only expose VRF-scoped IP addresses through SNMPv3 contexts or `community@vrf` conventions; snmp-discovery walks the standard IP-MIB tables in the default context and attaches VRFs to whatever addresses are visible there. Addresses hidden behind per-VRF contexts are not discovered (same as before this feature); per-context walking is a possible follow-up.


## Prefixes

Prefix entities are derived from the discovered IP addresses — the network of each address/prefix-length — exactly as device-discovery does. One `Prefix` is emitted per unique (network, VRF) pair per target. **This is on by default** (`emit_prefixes: true`); set `emit_prefixes: false` in the policy options to opt out.

- **VRF**: a prefix whose addresses were attached to a discovered VRF (see [VRFs](#vrfs)) carries that VRF; everything else resolves from `defaults.prefix.vrf` / `vrf_ipv4` / `vrf_ipv6` (independent of the `ip_address` knobs).
- **Scope**: explicit `defaults.prefix.scope_site` / `scope_location` always win; with `propagate_defaults_to_prefix_scope: true` and no explicit scope, `defaults.site` / `defaults.location` cascade in.
- **Safety guards**: zero-length networks (agent-quirk `0.0.0.0` masks) and IPv4-mapped IPv6 addresses never derive prefixes.
- **Host prefixes and IPv6 link-locals are not derived by default**: an IPv4 `/32` or IPv6 `/128` "prefix" only restates the address, which is already emitted as an `IPAddress` entity, and an `fe80::` prefix is per-link rather than globally meaningful. Both are skipped. The `IPAddress` entities are untouched, so the addresses stay documented — only the derived `Prefix` is dropped. IPv4 link-local (`169.254.0.0/16`) and the loopback net (`127.0.0.0/8`) are ordinary networks by mask and are still derived.
- **Opting back in to host prefixes**: set `emit_host_prefixes: true` to derive `/32` and `/128` prefixes again, for example when loopback `/32`s are deliberately tracked as prefixes in NetBox. Note its default (`false`) is the opposite of `emit_prefixes` (`true`). The opt-in covers host prefixes only: IPv6 link-local prefixes stay suppressed even with it enabled, including an `fe80::…/128` address, which is a link-local that happens to carry host length rather than a loopback worth tracking.
- **Data-quality note**: when an agent doesn't implement `ipAddressPrefixTable`, addresses fall back to host length. With the default settings those addresses derive no prefix, per the rule above, so a missing prefix table costs prefix coverage rather than filling IPAM with host routes. Enabling `emit_host_prefixes` on such a target will produce a host prefix for every address it reports, which is usually not what you want.


## Modules / ModuleBays

When the `discover_modules` policy option is enabled, snmp-discovery emits NetBox `Module` and `ModuleBay` entities for each chassis slot reported in `ENTITY-MIB` `entPhysicalTable` (and, in `full` mode, for each transceiver sub-bay). Discovery is **vendor-neutral**: rows are selected by `entPhysicalClass` alone — `chassis(3)` anchors the device, `container(5)` rows become module bays, `module(9)` rows become modules — with PID-prefix classification used only to split modules into `supervisor` / `linecard` / `transceiver` / `psu` / `fan` types. Any vendor that populates `entPhysicalTable` per ENTITY-MIB (RFC 6933) is supported; see the [supported platforms page](./supported_platforms.md#modules--modulebays) for the list known-tested. The option defaults to `off` so existing operators see zero behaviour change unless they explicitly opt in.

**Three modes:**

| `discover_modules` | What gets emitted |
|---|---|
| `off` *(default)* | No module / module-bay entities. Existing behaviour. |
| `linecards` | One `ModuleBay` + `Module` per chassis slot (line cards, supervisors). PSU and fan modules are recognised by the PID classifier so they label correctly in metrics, but are **never** emitted as `Module` entities — useful when operators care about the slot inventory but not power/cooling FRUs. Transceiver sub-bays are skipped. |
| `full` | `linecards` plus one extra `ModuleBay` + `Module` for every transceiver sub-bay reported by the device. Interfaces backed by a transceiver carry a `module=` reference to the transceiver module so NetBox shows which port is populated by which optic. Per-port linkage uses `entAliasMappingTable` (RFC 6933) when present to map transceiver rows to their owning `ifIndex`. |

**Emission order** (standalone modular chassis): `Device` → all `ModuleBay` + `Module` entries → `Interface` / `IPAddress` entries. The order matters because each interface entity may reference the module installed in its bay; emitting modules first lets the Diode reconciler resolve `Interface.module` against the just-created module.

**Virtual-chassis-of-modular** (e.g. Cisco StackWise Virtual on Catalyst 9500 / 9600, Catalyst 9300 stack with FRU uplink modules). When a VC member is itself a modular chassis, modules and bays are dispatched per member via the `ChassisInventory.Members` map: each `Module` / `ModuleBay` carries `device=` set to the member that physically owns the slot, and the `Module.module_bay` reference points at that member's bay. Master identity follows the same lowest-member-id pinning as the VC envelope itself. The emission order becomes: `Device(master)` → `VirtualChassis` → `Device(non-master members)` → all `ModuleBay` + `Module` per member → `Interface` / `IPAddress` per member.

**Empty bays.** A `container(5)` row with no `module(9)` child (an Aruba CX 8400 pattern, where empty line-card slots still surface as containers) is emitted as a bare `ModuleBay` with no installed Module. This faithfully captures the physical chassis surface so operators see populated *and* empty slots in NetBox.

**Chassis-rooted modules.** On fixed-FRU switches where a `module(9)` row's `entPhysicalContainedIn` chain leads directly to the `chassis(3)` row without an intermediate `container(5)` bay, snmp-discovery synthesises a `ModuleBay` named `Slot <ParentRelPos>` derived from the module's own `entPhysicalParentRelPos`. The module is then installed in the synthesised bay, keeping the `Device → ModuleBay → Module` shape uniform regardless of how the vendor models its inventory tree.

**Interface.Module routing.** The reference from an interface to the transceiver installed on it is populated through a bay matcher (Device + Serial + `ModuleBay{Name, Position, Device}`) so the Diode reconciler resolves to the standalone Module already emitted in the same payload, rather than creating a duplicate inline. When `entAliasMappingTable` is populated, transceiver rows are mapped to their owning `ifIndex` via that table; otherwise transceiver attachment falls back to the row's parent-bay name.

**Current sub-bay rendering trade-off (transient).** In `full` mode the transceiver sub-bay is emitted device-rooted — i.e. without a `module=parent_linecard` link. As a result, NetBox renders the transceiver sub-bay at chassis level (alongside the line-card slot bays) instead of visually nested under its parent line card. The transceiver `Module` itself is still installed in the sub-bay correctly via `Module.module_bay`, so per-port optic visibility works as expected; only the bay-under-linecard hierarchy is lost. The link is dropped because, in the current per-entity reconciler, attaching `module=parent_linecard` on a sub-bay causes the parent Module to be re-created from inside the sub-bay's changeset and conflicts at apply with the line card already created by the prior top-level Module entity. The link will be restored once the reconciler resolves nested parent-module refs against committed sibling entities in a single ingest call.

**Metrics.** Three OTLP counters cover module discovery operationally: `modules_emitted{vendor,type}`, `module_bays_emitted{vendor}`, and `modules_dropped{reason}` (e.g. PSU/fan filtered from `linecards`, malformed row, missing parent). PSU and fan rows count in `modules_dropped` rather than `modules_emitted` even though their PIDs are recognised by the classifier.

**Supported vendors.** Module discovery works on any vendor that populates `entPhysicalTable` per RFC 6933 — see the [supported platforms page](./supported_platforms.md#modules--modulebays) for the platforms known-tested in v1.

## Device Model Lookup

The `lookup_extensions_dir` config option points to a directory of YAML files that map SNMP `sysObjectID` OIDs to human-readable device model names. Without these files, snmp-discovery would ingest raw OIDs (for example `.1.3.6.1.4.1.9.1.489`) instead of recognizable model names (for example `catalyst2955C12`).

A curated set of vendor lookup files ships with the orb-agent and orb-discovery images (see [SNMP Discovery — Supported Platforms](./supported_platforms.md)), and `lookup_extensions_dir` only needs to be set when you want to add extra files or override the bundled ones.

### File format

Lookup files must have a `.yaml` or `.yml` extension and contain a `devices` section keyed by OID (note the leading `.`):

```yaml
devices:
  .1.3.6.1.4.1.9.1.1215: ciscoMwr2941DCA
  .1.3.6.1.4.1.9.1.489: catalyst2955C12
  .1.3.6.1.4.1.9.1.2101: ciscoASR92024TZM
```

### Overriding or extending coverage

To add your own OIDs or override a bundled file:

1. Identify the `sysObjectID` for your equipment (typically in vendor MIB files).
2. Create a YAML file in the format above with OIDs prefixed by `.`.
3. Drop the file into the directory referenced by `lookup_extensions_dir`.

```sh
# Seed a local override directory from the bundled files
git clone https://github.com/netboxlabs/orb-agent.git
cp orb-agent/orb-discovery/snmp-discovery/data/lookup_extensions/*.yaml /opt/orb/snmp-extensions/
```

When snmp-discovery encounters a device, it reads the device's `sysObjectID`, searches the YAML files in `lookup_extensions_dir` for a match, and falls back to the raw OID when no match is found.

### Dynamic model resolution (shared sysObjectID)

Some vendors return the same `sysObjectID` for every model in their catalog (for example MikroTik uses `.1.3.6.1.4.1.14988.1` across RouterOS devices), so a single static mapping cannot distinguish the actual model. The `devices:` map accepts OID references as values: instead of a literal model name, use an OID string (format `.1.3.6.1...`) that points to another OID already in the SNMP walk. At discovery time, snmp-discovery dereferences the walked value for that OID and uses it as the model name.

```yaml
devices:
  .1.3.6.1.4.1.14988.1: .1.3.6.1.2.1.1.1.0   # MikroTik: resolve model from sysDescr
  .1.3.6.1.4.1.14988.2: mikrotikSwOSSwitch   # Static literal (unchanged behavior)
```

No extra SNMP traffic is generated — the referenced OID must already be collected by the policy's walk set. `sysDescr` (`.1.3.6.1.2.1.1.1.0`) is always walked. If the referenced OID is missing or empty for a given device, snmp-discovery falls back to using the raw `sysObjectID`. The bundled `mikrotik.yaml` keeps the historical static `mikrotikRouter` model string by default for backward compatibility; operators who want per-device MikroTik model names can opt in by adding the override above to their `lookup_extensions_dir`.

## Default values from SNMP OIDs

Selected `defaults` fields accept either a literal value or an SNMP OID reference of the form `.1.3.6.1.…`. When the configured value matches the SNMP OID syntax (rooted at `.1.3.6.1.`), snmp-discovery dereferences the walked value at discovery time and uses that as the field value. Anything else is treated as a literal — including dotted-decimal literals such as `"3.14.159"` (a room number) or `"10.0.0.1"`, which do not start with the standard SNMP Internet prefix.

| Defaults field | OID-reference supported? |
|---|---|
| `defaults.location` | yes |
| `defaults.asset_tag` | yes |
| other `defaults.*` fields | not yet — literal only |

Any OID in the **device-system-group walked snapshot** is a valid reference target. The full list available today:

| OID | Name | Type | Typical use |
|---|---|---|---|
| `.1.3.6.1.2.1.1.1.0` | `sysDescr` | free text (often long) | Rarely useful as `location`/`asset_tag` because values commonly exceed NetBox's 100-char `Location.name` / 50-char `asset_tag` limits. |
| `.1.3.6.1.2.1.1.2.0` | `sysObjectID` | OID string (e.g. `.1.3.6.1.4.1.9.1.1234`) | Not a useful default source on its own. |
| `.1.3.6.1.2.1.1.4.0` | `sysContact` | free text | Some operators repurpose this as an inventory identifier — point `defaults.asset_tag` at it. |
| `.1.3.6.1.2.1.1.5.0` | `sysName` | free text | Device hostname — point `defaults.asset_tag` at it when hostname doubles as the inventory tag. |
| `.1.3.6.1.2.1.1.6.0` | `sysLocation` | free text | Physical location free-text per RFC 3418 — point `defaults.location` at it. |

OIDs walked under **other** mapping groups — most notably ENTITY-MIB rows such as `entPhysicalSerialNum` (`.1.3.6.1.2.1.47.1.1.1.1.11.<row>`) — are **not** reachable: the mapping framework groups walked PDUs per-`Map()` call, and `defaults.location`/`defaults.asset_tag` resolution runs against the device-system-group snapshot only.

```yaml
defaults:
  site: "datacenter-01"
  location: ".1.3.6.1.2.1.1.6.0"     # Use sysLocation
  asset_tag: ".1.3.6.1.2.1.1.4.0"    # Use sysContact (note: sysContact is RFC 3418 contact info,
                                       # not an asset tag by default — only opt in if your
                                       # operators have repurposed it for inventory tracking)
```

Resolution rules:

- The OID-reference syntax matches `^\.1\.3\.6\.1\.(\d+\.)+\d+$`; everything else stays a literal.
- The leading dot is mandatory: `.1.3.6.1.…`. A value without it (e.g. `1.3.6.1.2.1.1.6.0`) is treated as a literal and used verbatim — it will not be dereferenced.
- A configured OID reference whose walked value is missing or empty leaves the field unset for that device — no fallback to a literal.
- `defaults.asset_tag` is capped at NetBox's 50-character limit; longer resolved values are warn-logged and skipped (rather than truncated) to avoid silent asset-tag uniqueness collisions.
- `defaults.location` resolved via an OID reference will create (or match) a NetBox `Location` object named after the resolved string, scoped to `defaults.site`. Free-text `sysLocation` values can therefore produce messy Location objects (`"Front Door"`, vendor defaults, etc.) — curate your fleet before enabling this in production. Resolved values longer than NetBox's 100-char `Location.name` limit will be rejected at upsert time.

`entPhysicalAssetID` (ENTITY-MIB `.1.3.6.1.2.1.47.1.1.1.1.15`) is the standards-aligned asset-tag source, but it is a table column requiring chassis-row selection (`entPhysicalClass = chassis(3)`). It is not yet reachable from this `defaults.asset_tag` mechanism and is tracked as a follow-up.

### Manufacturer overrides

Manufacturers are derived from the Private Enterprise Number (PEN) segment of `sysObjectID` against a mechanically generated IANA catalog, which produces strings such as `ciscoSystems` or `Aruba a Hewlett Packard Enterprise company`. For NetBox deployments that already hold `Cisco Systems` / `Aruba` `Manufacturer` objects, any lookup-extension YAML file may also include a `manufacturers:` block keyed by IANA PEN:

```yaml
manufacturers:
  9: Cisco Systems       # PEN 9 (Cisco)
  14823: Aruba           # PEN 14823 (Aruba/HPE)
devices:
  .1.3.6.1.4.1.9.1.2495: c9300-48p
```

Overrides are layered — a value from `lookup_extensions_dir` wins over a value from the bundled files, which wins over the raw IANA name. The built-in `manufacturers.yaml` remains IANA-sourced; renames are strictly opt-in via lookup-extension files.

### Override precedence

When multiple sources can supply a device's `manufacturer`, `model`, or `platform`, the highest-priority non-empty value wins:

1. Per-target `override_defaults.device.{model,manufacturer,platform}` (hard override)
2. User `lookup_extensions_dir/*.yaml` (`manufacturers:` and `devices:` including dynamic refs)
3. Bundled `lookup_extensions/*.yaml` (`manufacturers:` and `devices:`)
4. Raw IANA manufacturer name / raw `sysObjectID` model
