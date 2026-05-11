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

When a device exposes the relevant MIBs, interfaces also carry their switching configuration: `mode` (`access` / `tagged` / `tagged-all` / unset for routed), the untagged (access/native) VLAN, and the list of tagged VLANs. VLANs referenced on an interface but not present in the device's VLAN database are auto-emitted as VLAN entities so the association is complete in NetBox; this behavior can be disabled via the `create_unknown_vlans` option (see below). Auto-emitted stubs use the placeholder name `VLAN<vid>` (e.g. `VLAN42`) because NetBox's `ipam.vlan.name` is required — operators or sibling switches can later overwrite the placeholder via the same vid+group matcher. VLAN discovery uses Q-BRIDGE-MIB (RFC 4363) as the generic source and a Cisco-specific overlay (CISCO-VLAN-MEMBERSHIP-MIB, CISCO-VOICE-VLAN-MIB) on Cisco devices that don't fully implement Q-BRIDGE — see [SNMP Discovery — Supported Platforms](./supported_platforms.md#interface--vlan-associations) for which device classes are covered.

Note: when a switchport is converted to a routed (L3) interface between discovery cycles, prior `mode`/untagged-VLAN/tagged-VLAN associations are NOT automatically cleared in NetBox; operators must clear them manually. This is a current limitation of the Diode plugin's PATCH semantics and is tracked separately. The same caveat applies on device-discovery.

## Configuration
The `snmp_discovery` backend does not require any special configuration in the backends section. The backend will use the `diode` settings specified in the `common` subsection to forward discovery results.

```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://127.0.0.1:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    snmp_discovery:
```

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

#### Defaults Parameters
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| tags | list | no | List of tags to apply to all discovered entities |
| site | string | no | Default site name for discovered devices |
| location | string | no | Default location for discovered devices |
| role | string | no | Default role for discovered devices |
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
| ipaddress    | map  | IP address-specific defaults  |
| ├─ role   | string  | IP address role                  |
| ├─ vrf   | string  | IP address vrf                    |
| ├─ tenant   | string  | IP address tenant              |
| ├─ description | string  | IP address description      |
| vlan    | map  | VLAN-specific defaults  |
| ├─ description | string  | VLAN description |
| ├─ tags | list | Per-VLAN tags. Merged with the top-level `tags` list on each emitted VLAN entity, mirroring the `device`/`interface`/`ipaddress` defaults pattern. |
| ├─ group | string | VLAN group name. When set, every emitted VLAN is attached to a `ipam.vlangroup` scoped to `defaults.site`: the group's `scope_site` is populated from `defaults.site` (even when that resolves to the `undefined` sentinel), and the slug is auto-generated from the name so the reconciler dedupes the group across runs. |
| ├─ tenant | string | VLAN tenant |
| ├─ status | string | VLAN status override (`active`, `reserved`, `deprecated`). When unset, status is derived from `dot1qVlanStaticRowStatus`: `active(1)` → `active`, `notInService(2)` → `reserved`. |

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

*Required for SNMPv1/v2c, optional for SNMPv3

**Note:** Authentication can be specified at the policy level (under `scope.authentication`) as a fallback, or per-target (under each target's `authentication` field). Targets without authentication use the policy-level authentication. Environment variables are supported using `${VAR}` syntax for `community`, `username`, `auth_passphrase`, and `priv_passphrase` fields.

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
    location: "rack-42"
    role: "network"
    ip_address:
      description: "SNMP discovered IP"
      role: "management"
      tenant: "network-ops"
      vrf: "management"
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
git clone https://github.com/netboxlabs/orb-discovery.git
cp orb-discovery/snmp-discovery/data/lookup_extensions/*.yaml /opt/orb/snmp-extensions/
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
