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
orb:
  policies:
    snmp_discovery:
      snmp_cisco:
        config:
          timeout: 2 #default 2 minutes
          devices_file: /opt/orb/device-data.yaml
        scope:
          authentication:
              protocol_version: SNMPv2c # SNMPv2c|SNMPv3
              community: cisco-c3750
          targets:
            - host: 0.0.0.0
              port: 161
          mapping_config: /opt/orb/snmp-mapping.yaml
      snmp_junos:
        config:
          timeout: 5 #default 2 minutes
          retries: 1
          devices_file: /opt/orb/device-data.yaml
        scope:
          authentication:
              protocol_version: SNMPv2c # SNMPv2c|SNMPv3
              community: juniper-mx960-16-1r6-7-b
          targets:
            - host: 0.0.0.0-1
              port: 162
          mapping_config: /opt/orb/snmp-mapping.yaml
``` 