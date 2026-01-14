# SNMP Discovery
The SNMP discovery backend leverages SNMP (Simple Network Management Protocol) to connect to network devices and collect network information.

## Diode Entities
The SNMP discovery backend uses [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) to ingest the following entities:

* [Device](https://github.com/netboxlabs/diode-sdk-go?tab=readme-ov-file#supported-entities-object-types)
* [Interface](https://github.com/netboxlabs/diode-sdk-go?tab=readme-ov-file#supported-entities-object-types)
* [IP Address](https://github.com/netboxlabs/diode-sdk-go?tab=readme-ov-file#supported-entities-object-types)
* [Mac Address](https://github.com/netboxlabs/diode-sdk-go?tab=readme-ov-file#supported-entities-object-types)
* [Platform](https://github.com/netboxlabs/diode-sdk-go?tab=readme-ov-file#supported-entities-object-types)
* [Manufacturer](https://github.com/netboxlabs/diode-sdk-go?tab=readme-ov-file#supported-entities-object-types)
* [Site](https://github.com/netboxlabs/diode-sdk-go?tab=readme-ov-file#supported-entities-object-types)

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

#### Defaults Parameters
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| tags | list | no | List of tags to apply to all discovered entities |
| site | string | no | Default site name for discovered devices |
| location | string | no | Default location for discovered devices |
| role | string | no | Default role for discovered devices |
| interface_patterns | list | User-defined interface type patterns (see [Interface Type Matching](./snmp_discovery_interface.md)) |

##### Nested Defaults
| Parameter | Type | Description |
|:---------:|:----:|:-----------:|
| device      | map  | Device-specific defaults        |
| ├─ description | string  | Device description           |
| ├─ comments   | string  | Device comments               |
| interface    | map  | Interface-specific defaults    |
| ├─ description | string  | Interface description        |
| ├─ if_type       | string | Interface type (e.g. "ethernet", "virtual")  |
| ipaddress    | map  | IP address-specific defaults  |
| ├─ role   | string  | IP address role                  |
| ├─ vrf   | string  | IP address vrf                    |
| ├─ tenant   | string  | IP address tenant              |
| ├─ description | string  | IP address description      |

### Scope Section
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| targets | list | yes | List of SNMP targets to discover. It also supports subnets (e.g. 192.168.1.0/28) and IP ranges in the format 192.168.0.1-192.168.0.10 or 192.168.0.1-10. |
| authentication | map | yes | SNMP authentication settings |

#### Authentication Parameters
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| protocol_version | string | yes | SNMP protocol version ("SNMPv1", "SNMPv2c", or "SNMPv3") |
| community | string | yes* | SNMP community string for v1/v2c authentication |
| username | string | no | SNMPv3 username |
| security_level | string | no | SNMPv3 security level ("noAuthNoPriv", "authNoPriv", "authPriv") |
| auth_protocol | string | no | SNMPv3 authentication protocol ("SHA", "MD5") |
| auth_passphrase | string | no | SNMPv3 authentication passphrase |
| priv_protocol | string | no | SNMPv3 privacy protocol ("AES", "DES") |
| priv_passphrase | string | no | SNMPv3 privacy passphrase |

*Required for SNMPv1/v2c, optional for SNMPv3

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
    device:
      description: "SNMP discovered device"
      comments: "Automatically discovered via SNMP"
  lookup_extensions_dir: "/opt/orb/snmp-extensions" # Specifies a directory containing device data yaml files (see below)
scope:
  targets:
    - host: "192.168.1.1/24" # subnet support
    - host: "192.168.2.2-10" #range support
    - host: "10.0.0.1"
      port: 162  # Non-standard SNMP port
  authentication:
    protocol_version: "SNMPv2c"
    community: "public"
```
