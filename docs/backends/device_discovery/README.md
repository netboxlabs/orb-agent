# Device Discovery
The device discovery backend leverages [NAPALM](https://napalm.readthedocs.io/en/latest/index.html) to connect to network devices and collect network information.

For the full list of vendors and NAPALM drivers supported by this backend (standard and custom), see [Device Discovery — Supported Platforms](./supported_platforms.md).

## Diode Entities
The device discovery backend uses [Diode Python SDK](https://github.com/netboxlabs/diode-sdk-python) to ingest the following entities:

* [Device](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/device.py)
* [Interface](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/interface_example.py)
* [Device Type](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/device_type.py)
* [Platform](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/platform.py)
* [Manufacturer](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/manufacturer.py)
* [Site](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/site.py)
* [Role](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/role.py)
* [IP Address](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/ip_address.py)
* [Prefix](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/prefix.py)
* [VLAN](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/vlan.py)
* [VirtualChassis](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/virtual_chassis_example.py)
* [Module](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/module.py)
* [ModuleBay](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/examples/module_bay.py)

Interfaces are attached to the device and ip addresses will be attached to the interfaces. Prefixes are added to the same interface site that it belongs to.

When a target is a switch stack / Virtual Chassis (NetBox `VirtualChassis`), device-discovery emits one `VirtualChassis` entity plus one `Device` per member, and routes each interface/IP to the member that physically owns it — see [Switch stacks / Virtual Chassis](#switch-stacks--virtual-chassis) below. Drivers that do not implement stack discovery (or devices not in stack mode) fall through to the existing single-`Device` path with no change in behaviour.

When a target is a modular chassis and the `discover_modules` policy option is enabled, device-discovery additionally emits `Module` and `ModuleBay` entities for each chassis slot (and, in `full` mode, each transceiver sub-bay) — see [Modules / ModuleBays](#modules--modulebays) below. Defaults to `off`, so existing operators see zero behaviour change.

## Switch stacks / Virtual Chassis

When a driver implements stack-member discovery and the target reports 2+ members with serials, device-discovery emits a NetBox `VirtualChassis` plus one `Device` per member, and routes each interface and IP address to the correct member based on the interface name prefix (e.g. `GigabitEthernet1/0/1` → member 1, `GigabitEthernet2/0/12` → member 2). Standalone switches, devices not in stack mode, and members without a serial (which Diode cannot resolve) fall back to the existing single-`Device` path with no change in behaviour.

**Emission shape** (in order):
1. **Master `Device`** — plain (no `vc_position`, no `virtual_chassis` ref). Named `<hostname>-<id>` where `<hostname>` is the management hostname and `<id>` is the master's stack-member id.
2. **`VirtualChassis`** — named `<hostname>`, with `master` set to the inline matcher block of the master Device.
3. **N − 1 member `Device` entities** — each carries `vc_position = <member id>` and an inline `virtual_chassis` ref pointing to the same matcher block.
4. **Interface / IPAddress entities** — routed to the member device whose id matches the interface name prefix. Logical interfaces with no parseable member id (`Vlan*`, `Loopback*`, `Port-channel*`, etc.) land on the master.

**Master pinning.** The logical master sent to Diode is always the **lowest stack-member id present**, regardless of live role. This is required because the NetBox Diode plugin resolves an existing `VirtualChassis` via its `unique_master` matcher — pinning to the lowest id keeps the master Device stable across StackWise role failovers so re-runs upsert the existing VC instead of creating a new one. The other matcher fields used for VC re-identification (asset_tag, primary_ip4/6, name+site+tenant, and `metadata.source_match`) are carried consistently on both the rich master Device and the inline VC `master` ref so the plugin's matcher cascade resolves through the same record on every cycle.

**Orphaned member ports.** If a member is dropped from the validated payload (missing serial, duplicate id, etc.) but the device still reports its ports via `show interfaces`, those interfaces are **skipped with a WARNING** rather than routed to master. Routing them to master would silently misattribute member-N ports to a different device — operators see the warning in logs and the missing port in NetBox, not a corrupted port→device mapping.

**Supported drivers.** Stack discovery is opt-in per driver (analogous to interface↔VLAN associations). See the [supported platforms page](./supported_platforms.md#switch-stacks--virtual-chassis-vc) for the current list; vendors land as follow-up PRs as the underlying drivers gain stack-discovery support.

When a driver supports it, interfaces also carry their switching configuration: `mode` (`access` / `tagged` / `tagged-all` / unset for routed), the untagged (access/native) VLAN, and the list of tagged VLANs. Trunks that allow every VLAN (e.g. Cisco IOS `Trunking VLANs Enabled: ALL` or `1-4094`) are emitted as `tagged-all` so NetBox sees the proper 802.1Q semantics rather than a `tagged` interface with an empty allowed-VLAN list. VLANs referenced on an interface but not present in the device's VLAN database are auto-emitted as VLAN entities so the association is complete in NetBox; this behavior can be disabled via the `create_unknown_vlans` option (see below). Auto-emitted stubs use the placeholder name `VLAN<vid>` (e.g. `VLAN42`) because NetBox's `ipam.vlan.name` is required — operators or sibling switches can later overwrite the placeholder via the same vid+group matcher. Malformed CLI rows that the driver cannot parse fail closed (plain `tagged` mode with no tagged VLANs and a logged warning) — they never silently widen an interface to all VLANs. Note: when a switchport is converted to a routed (L3) interface between discovery cycles, prior `mode`/untagged-VLAN/tagged-VLAN associations are NOT automatically cleared in NetBox; operators must clear them manually. This is a current limitation of the Diode plugin's PATCH semantics and is tracked separately.

## Modules / ModuleBays

When a driver implements module discovery and the `discover_modules` policy option is enabled, device-discovery emits NetBox `Module` and `ModuleBay` entities for each chassis slot (e.g. a Catalyst 9404R supervisor + line cards in slots 1–4) and, in `full` mode, for each transceiver sub-bay reported by the device. Standalone non-modular switches (e.g. a Cat 3850 / 9300 with no removable line cards) and devices whose driver does not implement module discovery fall back to the existing emission with no change in behaviour. The option defaults to `off` so existing operators see zero behaviour change unless they explicitly opt in.

**Three modes:**

| `discover_modules` | What gets emitted |
|---|---|
| `off` *(default)* | No module / module-bay entities. Existing behaviour. |
| `linecards` | One `ModuleBay` + `Module` per chassis slot (line cards, supervisors, PSU / fan modules a driver classifies explicitly). Transceiver sub-bays are skipped — useful when operators care about the slot inventory but not per-port optics. |
| `full` | `linecards` plus one extra `ModuleBay` + `Module` for every transceiver sub-bay reported by the device. Interfaces backed by a transceiver carry a `module=` reference to the transceiver module so NetBox shows which port is populated by which optic. |

**Emission order** (standalone modular chassis): `Device` → all `ModuleBay` + `Module` entries → `Interface` / `IPAddress` entries. The order matters because each interface entity may reference the module installed in its bay; emitting modules first lets the Diode reconciler resolve `Interface.module` against the just-created module.

**Virtual-chassis-of-modular** (e.g. Catalyst 9300 stack with FRU uplinks, Catalyst 9400 / 9500 in StackWise Virtual mode). When a VC member is itself a modular chassis, modules and bays are dispatched per member: each `Module` / `ModuleBay` carries `device=` set to the member that physically owns the slot, and the `Module.module_bay` reference points at that member's bay. The emission order becomes: `Device(master)` → `VirtualChassis` → `Device(non-master members)` → all `ModuleBay` + `Module` per member → `Interface` / `IPAddress` per member. Stack members that are non-modular emit no module entries; the VC stack envelope is unchanged.

**Current sub-bay rendering trade-off (transient).** In `full` mode the transceiver sub-bay is emitted device-rooted — i.e. without a `module=parent_linecard` link. As a result, NetBox renders the transceiver sub-bay at chassis level (alongside the line-card slot bays) instead of visually nested under its parent line card. The transceiver `Module` itself is still installed in the sub-bay correctly via `Module.module_bay`, so per-port optic visibility works as expected; only the bay-under-linecard hierarchy is lost. The link is dropped because, in the current per-entity reconciler, attaching `module=parent_linecard` on a sub-bay causes the parent Module to be re-created from inside the sub-bay's changeset and conflicts at apply with the line card already created by the prior top-level Module entity. The link will be restored once the reconciler resolves nested parent-module refs against committed sibling entities in a single ingest call.

**Supported drivers.** Module discovery is opt-in per driver (analogous to interface↔VLAN associations and stack discovery). See the [supported platforms page](./supported_platforms.md#modules--modulebays) for the current list; vendors land as follow-up PRs as the underlying drivers gain module-discovery support.

## Configuration
The `device_discovery` backend does not require any special configuration, though overriding `host` and `port` values can be specified. The backend will use the `diode` settings specified in the `common` subsection to forward discovery results.


```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    device_discovery:
      host: 192.168.5.11 # default 0.0.0.0
      port: 8857 # default 8072

```

## Policy
Device discovery policies are broken down into two subsections: `config` and `scope`. 

### Config
Config defines data for the whole scope and is optional overall.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| schedule | cron format | no  |  If defined, it will execute scope following cron schedule time. If not defined, it will execute scope only once  |
| defaults | map | no  |  key value pair that defines default values  |
| options | map | no | key value pair that defines config options |

#### Options
Current supported options:
|  Key  | Type |  Description  |
|:-----:|:----:|:-------------:|
| platform_omit_version  | bool | If True, only the driver name will be used as the NetBox platform name (defaults to 'False' if not specified) |
| port_scan_ports | list | TCP ports to probe before discovery if hostname is a IP Range or a Subnet (defaults to [22,23,80,443,830,57400]) |
| port_scan_timeout | float | TCP port probe timeout in seconds (defaults to 0.5) |
| capture_running_config | bool | If True, collects the running configuration from the device and ingests it as a DeviceConfig entity (defaults to 'False' if not specified) |
| capture_startup_config | bool | If True, collects the startup/saved configuration from the device and ingests it as a DeviceConfig entity (defaults to 'False' if not specified) |
| sanitize_config | bool | If False, captured configuration is stored as-is without redacting sensitive values such as passwords and pre-shared keys (defaults to 'True' if not specified) |
| discovery_drivers | list | Restrict auto-discovery to this ordered list of driver names (e.g. `[paloalto_panos, huawei_vrp]`). Only used when a scope entry has no `driver` set. If not specified, only standard NAPALM drivers are tried. Custom drivers (`paloalto_panos`, `paloalto_panos_ssh`, `huawei_vrp`) must be listed explicitly to be used in auto-discovery. See the [supported platforms page](./supported_platforms.md) for the full list. |
| create_unknown_vlans | bool | When discovering interface↔VLAN associations, auto-emit a VLAN entity for any VID referenced on an interface but absent from the device's VLAN database. Stubs inherit attributes from `defaults.vlan` for stable matching. Defaults to `True`. Set `False` to drop unknown VIDs from interface associations entirely (requires every referenced VLAN to already exist in NetBox). Only drivers that implement `get_interfaces_vlans()` populate these associations — see the [supported platforms page](./supported_platforms.md). |
| discover_modules | str | Controls emission of `Module` / `ModuleBay` entities on modular chassis. One of `off` (default — no modules emitted, zero behaviour change), `linecards` (one Module per chassis slot — line cards, supervisors, etc. — transceiver sub-bays skipped), or `full` (linecards plus one Module per transceiver sub-bay; interfaces carry a `module=` ref to the transceiver they're connected to). Only drivers that implement `get_modules()` populate module data — see the [supported platforms page](./supported_platforms.md#modules--modulebays). See [Modules / ModuleBays](#modules--modulebays) for the emission shape and current sub-bay rendering trade-off. |

#### Defaults
Current supported defaults:

|  Key  | Type |  Description  |
|:-----:|:----:|:-------------:|
| site  | str | NetBox Site Name (defaults to 'undefined' if not specified) |
| role  | str  | Device role (e.g., switch) (defaults to 'undefined' if not specified) |
| if_type | str | Default interface type when no pattern matches (defaults to 'other' if not specified) |
| interface_patterns | list | User-defined interface type patterns (see [Interface Type Matching](./interface.md)) |
| interface_exclude_patterns | list | Regex patterns to exclude interfaces (and their IPs) from ingestion (see [Interface Exclusion](./interface.md#interface-exclusion-patterns)) |
| location | str | Device location |
| rack  | str | Rack name to associate the device with |
| tenant | str/map | Device tenant |
| description | str  | General description   |
| comments   | str  | General comments       |
| tags       | list | List of tags           |

##### Nested Defaults

| Key          | Type  | Description                   |
|-------------|------|---------------------------------|
| device      | map  | Device-specific defaults        |
| ├─ model | str  | Device type model (overrides the model automatically retrieved from NAPALM)   |
| ├─ manufacturer | str  | Device manufacturer (overrides the vendor automatically retrieved from NAPALM) |
| ├─ platform | str  | Device platform (overrides the defined/discovered NAPALM driver name and OS version) |
| ├─ description | str  | Device description           |
| ├─ comments   | str  | Device comments               |
| ├─ tags       | list | Device tags                   |
| ├─ asset_tag | str  | Device asset tag                      |
| tenant | map | Tenant-specific defaults              |
| ├─ name | str | Tenant name                          |
| ├─ group | str | Tenant group                        |
| ├─ description | str  | Tenant description           |
| ├─ tags       | list | Tenant tags                   |
| interface    | map  | Interface-specific defaults    |
| ├─ description | str  | Interface description        |
| ├─ tags       | list | Interface tags               |
| ipaddress    | map  | IP address-specific defaults  |
| ├─ role   | str  | IP address role                  |
| ├─ tenant   | str  | IP address tenant              |
| ├─ vrf   | str/map  | IP address VRF name, or VRF object with route distinguisher |
| ├─ description | str  | IP address description      |
| ├─ comments   | str  | IP address comments          |
| ├─ tags       | list | IP address tags              |
| prefix       | map  | Prefix-specific defaults      |
| ├─ role   | str  | Prefix role                    |
| ├─ tenant   | str  | Prefix tenant                |
| ├─ vrf   | str/map  | Prefix VRF name, or VRF object with route distinguisher |
| ├─ description | str  | Prefix description        |
| ├─ comments   | str  | Prefix comments            |
| ├─ tags       | list | Prefix tags                |
| vrf | map | VRF-specific defaults (used within ipaddress and prefix) |
| ├─ name | str | VRF name |
| ├─ rd | str | Route distinguisher (e.g. `65000:100`) |
| ├─ description | str | VRF description |
| ├─ comments | str | VRF comments |
| ├─ tags | list | VRF tags |
| vlan       | map  | VLAN-specific defaults        |
| ├─ group   | str  | VLAN group name. When set, every emitted VLAN is attached to an `ipam.vlangroup` scoped to `defaults.site`: the group's `scope_site` is populated from `defaults.site` |
| ├─ tenant   | str  | VLAN tenant                  |
| ├─ role   | str  | VLAN role                      |
| ├─ description | str  | VLAN description          |
| ├─ comments   | str  | VLAN comments              |
| ├─ tags       | list | VLAN tags                  |


### Scope
The scope defines a list of devices that can be accessed and pulled data. 

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| hostname | string | yes  | Device hostname. It also supports subnets (e.g. 192.168.1.0/28) and IP ranges in the format 192.168.0.1-192.168.0.10 or 192.168.0.1-10.  |
| username | string | yes  | Device username  |
| password | string | yes  | Device username's password |
| driver | string | no  | If defined, connect using the specified NAPALM driver. If not set, all installed drivers are tried (or the `discovery_drivers` list if configured). |
| optional_args | map | no  | NAPALM optional arguments defined [here](https://napalm.readthedocs.io/en/latest/support/#list-of-supported-optional-arguments). Commonly used: `ssh_config_file` for jumphost support (see [SSH Configuration guide](./ssh.md)), `canonical_int` for interface naming, `timeout` for slow connections. |
| override_defaults | map | no | Allows overriding of any defaults for a specific device in the scope |
| netbox_id | integer | no | NetBox device primary key. When set, the diode plugin matches the device by PK instead of by name. Ignored when hostname is a subnet or IP range. |

### SSH Configuration and Jumphost Support

For advanced SSH scenarios including bastion/jumphost connectivity, VRF-aware connections, and multi-hop SSH configurations, see the dedicated guide: [SSH Configuration and Jumphost Support](./ssh.md).

The `ssh_config_file` optional argument allows you to specify a standard OpenSSH configuration file for connecting to devices through intermediate jump servers:

```yaml
scope:
  - driver: ios
    hostname: 192.168.10.5
    username: admin
    password: ${DEVICE_PASS}
    optional_args:
      ssh_config_file: /opt/orb/ssh-napalm.conf
```

See the [SSH Configuration guide](./ssh.md) for complete examples, security best practices, and troubleshooting.

### Sample
A sample policy including all parameters supported by the device discovery backend.
```yaml
orb:
  ...
  policies:
    device_discovery:
      discovery_1:
        config:
          schedule: "* * * * *"
          defaults:
            site: New York NY
            role: switch
            if_type: other
            interface_patterns:
              - match: "^(GigabitEthernet|Gi).*"
                type: "1000base-t"
              - match: "^(TenGig|Te).*"
                type: "10gbase-x-sfpp"
              - match: "^Loopback.*"
                type: "virtual"
            interface_exclude_patterns:
              - "^tap.*"
              - "^veth.*"
            location: Row A
            rack: Rack-01
            tenant: NetBox Labs
            description: for all
            comments: comment all
            tags: [tag1, tag2]
            device:
              model: C9200-48P
              manufacturer: Cisco
              asset_tag: ASSET-001
              description: device description
              comments: this device
              tags: [tag3, tag4]
            interface:
              description: interface description
              tags: [tag5]
            ipaddress:
              description: my ip
              comments: my comment
              tags: [tag6]
              vrf:
                name: VRF-A
                rd: "65000:100"
            prefix:
              description:
              comments:
              tags: [tag7]
              vrf:
                name: VRF-A
                rd: "65000:100"
            vlan:
              role: role
        scope:
          - driver: ios
            hostname: 192.168.0.5
            username: admin
            password: ${PASS}
            optional_args:
               canonical_int: True
               ssh_config_file: /opt/orb/ssh-napalm.conf
          - hostname: myhost.com
            username: remote
            password: 12345
            netbox_id: 42
            override_defaults:
              role: router
              location: Row B
```

### Custom Driver Discovery Example

Use `discovery_drivers` to limit auto-discovery to a specific set of drivers. This is useful when you know the device type in advance or when using custom NAPALM drivers shipped with device-discovery (`paloalto_panos`, `paloalto_panos_ssh`, `huawei_vrp`).

```yaml
orb:
  ...
  policies:
    device_discovery:
      panos_discovery:
        config:
          schedule: "0 * * * *"
          options:
            discovery_drivers:
              - paloalto_panos
              - paloalto_panos_ssh
          defaults:
            site: DC1
        scope:
          - hostname: 192.168.10.20
            username: admin
            password: ${PANOS_PASS}
```

In this example, only the `paloalto_panos` and `paloalto_panos_ssh` drivers are tried during auto-discovery for devices in this policy. If you set `driver` explicitly on a scope entry, `discovery_drivers` is ignored for that entry.

### Advanced Sample

You can reuse credentials across multiple devices in the `scope` section by using YAML anchors (`&`) and aliases (`<<`). This reduces redundancy and simplifies configuration management.

```yaml
orb:
  ...
  policies:
    device_discovery:
      discovery_1:
        credentials: &ios_credentials
          username: admin
          password: ${PASS}
          driver: ios
        config:
          defaults:
            site: my site
            tenant: my tenant
        scope:
          - hostname: 192.168.10.3
            <<: *ios_credentials
          - hostname: 192.168.10.5
            <<: *ios_credentials
```

In this example:
- The `credentials` section defines reusable credentials using the anchor `&ios_credentials`.
- The `<<: *ios_credentials` alias is used to include the credentials in multiple devices within the `scope` section.

## What NAPALM Collects Automatically

The tables below show which fields are populated automatically from the device versus which must be provided via `defaults` in the policy configuration.

### Device

| Field | Source | Notes |
|-------|--------|-------|
| Name | `get_facts()` → `hostname` | Auto-collected |
| Model | `get_facts()` → `model` | Auto-collected; overridable via `defaults.device.model` |
| Manufacturer | `get_facts()` → `vendor` | Auto-collected; overridable via `defaults.device.manufacturer` |
| Platform | `get_facts()` → `os_version` + driver name | Format: `"<DRIVER> <os_version>"`. Overridable via `defaults.device.platform`. Use `platform_omit_version: true` to use only the driver name |
| Serial number | `get_facts()` → `serial_number` | Auto-collected |
| Status | — | Always set to `"active"` |
| Site | **Not collected** | Must be set via `defaults.site` |
| Role | **Not collected** | Must be set via `defaults.role` |
| Location | **Not collected** | Must be set via `defaults.location` |
| Tenant | **Not collected** | Must be set via `defaults.tenant` |
| Description | **Not collected** | Must be set via `defaults.device.description` |
| Comments | **Not collected** | Must be set via `defaults.device.comments` |
| Tags | **Not collected** | Must be set via `defaults.tags` or `defaults.device.tags` |

### Interface

| Field | Source | Notes |
|-------|--------|-------|
| Name | `get_interfaces()` → interface key | Auto-collected |
| Enabled | `get_interfaces()` → `is_enabled` | Auto-collected |
| MAC address | `get_interfaces()` → `mac_address` | Auto-collected |
| Description | `get_interfaces()` → `description` | Auto-collected; falls back to `defaults.interface.description` if empty |
| Speed | `get_interfaces()` → `speed` (Mbps) | Auto-collected; stored in NetBox as Kbps |
| MTU | `get_interfaces()` → `mtu` | Auto-collected |
| Type | Interface name pattern matching + speed | Determined by: (1) user `interface_patterns`, (2) built-in patterns, (3) speed-based detection, (4) `defaults.if_type`. Subinterfaces (`.` or `:` separator) are always `"virtual"` |
| Tags | **Not collected** | Must be set via `defaults.tags` or `defaults.interface.tags` |

### IP Address

| Field | Source | Notes |
|-------|--------|-------|
| Address (with prefix length) | `get_interfaces_ip()` | Auto-collected; IPv4 and IPv6 |
| Assigned interface | — | Automatically linked to the interface |
| Role | **Not collected** | Must be set via `defaults.ipaddress.role` |
| VRF | **Not collected** | Must be set via `defaults.ipaddress.vrf` |
| Tenant | **Not collected** | Must be set via `defaults.ipaddress.tenant` |

### Prefix

Prefixes are derived from IP addresses discovered on interfaces. The network address is computed automatically from each discovered IP/prefix-length.

| Field | Source | Notes |
|-------|--------|-------|
| Prefix (network address) | Derived from IP address | Auto-computed |
| Site | — | Inherited from the interface's site |
| VRF / Role / Tenant | **Not collected** | Must be set via `defaults.prefix.*` |

### VLAN

| Field | Source | Notes |
|-------|--------|-------|
| VID | `get_vlans()` → VLAN ID | Auto-collected |
| Name | `get_vlans()` → VLAN name | Auto-collected |
| Group / Role / Tenant | **Not collected** | Must be set via `defaults.vlan.*` |

### Virtual Chassis (switch stacks)

Only emitted when the driver implements `get_chassis_members()` and the target reports 2+ stack members with serials. See [Switch stacks / Virtual Chassis](#switch-stacks--virtual-chassis) above for the emission shape and the [supported platforms page](./supported_platforms.md#switch-stacks--virtual-chassis-vc) for the driver list.

| Field | Source | Notes |
|-------|--------|-------|
| `VirtualChassis.name` | `device.hostname` | The management hostname becomes the VC name |
| `VirtualChassis.master` | Lowest member id present | Pinned to lowest id (not live role) so the master Device is stable across StackWise role failovers |
| `VirtualChassis.domain` | Driver-supplied (when available) | Optional; only some platforms surface a VC domain id |
| Member `Device.name` | `<hostname>-<member_id>` | E.g. `core-sw-1`, `core-sw-2` |
| Member `Device.serial` | Per-member from driver | Required — members without a serial are dropped |
| Member `Device.model` | Per-member from driver | Falls back to chassis model if the driver doesn't surface per-member models |
| Member `Device.vc_position` | Stack-member id | Preserved exactly (e.g. id=1,2,4 if slot 3 is empty) |
| Member-interface routing | Interface name prefix | Parsed via `parse_member_id` — Cisco IOS canonical (`Gi1/0/1` → member 1), mGig families (`TwoGigabitEthernet`, `FiveGigabitEthernet`, `TenGigabitEthernet`, `TwentyFiveGigE`), Junos FPC (`ge-1/0/0` → FPC 1), Aruba CX bare 3-tuple (`1/1/1`), HP/H3C Comware hyphenated speed prefixes (`Ten-GigabitEthernet`, `Twenty-FiveGigE`, `FortyGigE`, `FiftyGigE`, `TwoHundredGigE`, `FourHundredGigE`), Huawei VRP (`XGigabitEthernet`, `10GE`/`25GE`/`40GE`/`50GE`/`100GE`/`200GE`/`400GE`); FastIron ICX uses the same bare 3-tuple form as Aruba CX |