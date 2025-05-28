# SNMP Discovery
The SNMP discovery backend leverages SNMP (Simple Network Management Protocol) to connect to network devices and collect network information.

## Diode Entities
The SNMP discovery backend uses [Diode Python SDK](https://github.com/netboxlabs/diode-sdk-python) to ingest the following entities:

* [Device](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#device)
* [Interface](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#interface)
* [IP Address](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#ip-address)
* [Mac Address](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#mac-address)
* [Platform](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#platform)
* [Manufacturer](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#manufacturer)
* [Site](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#site)

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

### Config
Config defines data for the whole scope and is optional overall.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| timeout | integer | no | Timeout in minutes for SNMP operations (defaults to 2) |
| retries | integer | no | Number of retries for SNMP operations |
| devices_file | string | yes | Path to the YAML file containing device data |

### Scope
The scope defines SNMP authentication and target devices to collect data from.

#### Authentication
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| protocol_version | string | yes | SNMP protocol version (SNMPv2c or SNMPv3) |
| community | string | yes | SNMP community string for authentication |

#### Targets
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| host | string | yes | Target host IP address or range (e.g., "0.0.0.0" or "0.0.0.0-1") |
| port | integer | yes | SNMP port number |

#### Additional Parameters
| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| mapping_config | string | yes | Path to the YAML file containing SNMP OID mappings |

### Sample
A sample policy including all parameters supported by the SNMP discovery backend.

```yaml
config:
  schedule: "*/5 * * * *"  # Optional: Cron expression for scheduling
  retries: 3  # Optional: Number of SNMP retries (default: 0)
  timeout: 2
  device_file: /opt/orb/devices.yaml # data about device types
  defaults:  # Optional: Default values for entities
    description: "Global description"  # Optional: Global description for all entities
    comments: "Global comments"  # Optional: Global comments for all entities
    tags:  # Optional: Global tags for all entities
      - "global"
      - "snmp"
    ip_address:  # Optional: Defaults specific to IP addresses
      description: "IP Address description"
      comments: "IP Address comments"
      tags:
        - "ip"
        - "default"
    interface:  # Optional: Defaults specific to interfaces
      description: "Interface description"
      tags:
        - "interface"
        - "default"
    device:  # Optional: Defaults specific to devices
      description: "Device description"
      tags:
        - "device"
        - "default"
scope:
  targets:  # List of SNMP targets to discover
    - host: "192.168.1.1"  # Required: Hostname or IP address
      port: 161  # Optional: SNMP port (default: 161)
    - host: "10.10.10.0/24"  # CIDR range: expands to all IPs in the subnet
    - host: "10.10.10.10-20" # Dash range: expands to 10.10.10.10, 10.10.10.11, ..., 10.10.10.20
    - host: "mydevice.local" # Hostname
  mapping_config: /opt/orb/mapping.yaml # mappings between SNMP object IDs and netbox diode entities 
  authentication:  # SNMP authentication settings
    protocol_version: "SNMPv2c"  # Required: SNMP protocol version ("SNMPv1", "SNMPv2c", or "SNMPv3")
    community: "public"  # Required for v1/v2c: SNMP community string
    # Optional for v3:
    # username: "user"
    # security_level: authPriv # Allowed values: ("NoAuthNoPriv", "AuthNoPriv", "AuthPriv")
    # auth_protocol: "SHA"
    # auth_passphrase: "authkey"
    # priv_protocol: "AES"
    # priv_passphrase: "privkey"
```

Example mapping file
```yaml
entries:
  # Interface mappings
  - oid: ".1.3.6.1.2.1.2.2.1"
    entity: "interface"
    field: "_id"
    identifier_size: 1
    mapping_entries:
      - oid: ".1.3.6.1.2.1.2.2.1.2"
        entity: "interface"
        field: "name"
      - oid: ".1.3.6.1.2.1.2.2.1.5"
        entity: "interface"
        field: "speed"
      - oid: ".1.3.6.1.2.1.2.2.1.6"
        entity: "interface"
        field: "macAddress"
      - oid: ".1.3.6.1.2.1.2.2.1.7"
        entity: "interface"
        field: "adminStatus"

  # IP Address mappings
  - oid: ".1.3.6.1.2.1.4.20.1"
    entity: "ipAddress"
    field: "_id"
    identifier_size: 4
    mapping_entries:
      - oid: ".1.3.6.1.2.1.4.20.1.1"
        entity: "ipAddress"
        field: "address"
      - oid: ".1.3.6.1.2.1.4.20.1.2"
        entity: "ipAddress"
        field: "assigned_object"
        relationship:
          type: "interface"
          field: "_id"

  # Device mappings
  - oid: ".1.3.6.1.2.1.1"
    entity: "device"
    field: "_id"
    mapping_entries:
      - oid: ".1.3.6.1.2.1.1.5.0"
        entity: "device"
        field: "name"
      - oid: ".1.3.6.1.2.1.1.2.0"
        entity: "device"
        field: "platform"
```

Example device data file. This can be generated or extended using the scripts available [here](https://github.com/netboxlabs/orb-discovery/tree/develop/snmp-discovery/scripts).
```yaml
manufacturers:
  - name: Reserved
    pen: 0
  - name: NxNetworks
    pen: 1
  - name: IBM httpsw3ibmcomstandards 
    pen: 2
  - name: Carnegie Mellon
    pen: 3
  - name: Unix
    pen: 4
  - name: ACC
    pen: 5
  - name: TWG
    pen: 6
  - name: CAYMAN
    pen: 7
  - name: PSI
    pen: 8
  - name: ciscoSystems
    pen: 9
  - name: NSC
    pen: 10
  - name: HewlettPackard
    pen: 11
  - name: Epilogue
    pen: 12
  - name: U of Tennessee
    pen: 13
  - name: BBN Technologies
    pen: 14
  - name: Xylogics Inc
    pen: 15
  - name: Timeplex
    pen: 16
  - name: Canstar
    pen: 17
  - name: Wellfleet
    pen: 18
  - name: TRW
    pen: 19
  - name: MIT
    pen: 20
  - name: EON
    pen: 21
  - name: Fibronics
    pen: 22
  - name: Novell
    pen: 23
  - name: Spider Systems
    pen: 24
  - name: NSFNET
    pen: 25
  #  ... (other manufacturers can be added here)
devices:
  - id: 1
    oid: 136141911
    name: ciscoGatewayServer
  - id: 2
    oid: 136141912
    name: ciscoTerminalServer
  - id: 3
    oid: 136141913
    name: ciscoTrouter
  - id: 4
    oid: 136141914
    name: ciscoProtocolTranslator
  - id: 5
    oid: 136141915
    name: ciscoIGS
  - id: 6
    oid: 136141916
    name: cisco3000
  - id: 7
    oid: 136141917
    name: cisco4000
  - id: 8
    oid: 136141918
    name: cisco7000
  - id: 9
    oid: 136141919
    name: ciscoCS500
  - id: 10
    oid: 1361419110
    name: cisco2000
  - id: 11
    oid: 1361419111
    name: ciscoAGSplus
  - id: 12
    oid: 1361419112
    name: cisco7010
  - id: 13
    oid: 1361419113
    name: cisco2500
  - id: 14
    oid: 1361419114
    name: cisco4500
  - id: 15
    oid: 1361419115
    name: cisco2102
  - id: 16
    oid: 1361419116
    name: cisco2202
  # ... (other devices can be added here)
```