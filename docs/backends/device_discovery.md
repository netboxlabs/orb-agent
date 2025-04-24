# Device Discovery
The device discovery backend leverages [NAPALM](https://napalm.readthedocs.io/en/latest/index.html) to connect to network devices and collect network information.

## Diode Entities
The device discovery backend uses [Diode Python SDK](https://github.com/netboxlabs/diode-sdk-python) to ingest the following entities:

* [Device](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#device)
* [Interface](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#interface)
* [Device Type](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#device-type)
* [Platform](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#platform)
* [Manufacturer](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#manufacturer)
* [Site](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#site)
* [Role](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#role)
* [IP Address](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#ip-address)
* [Prefix](https://github.com/netboxlabs/diode-sdk-python/blob/develop/docs/entities.md#prefix)

Interfaces are attached to the device and ip addresses will be attached to the interfaces. Prefixes are added to the same interface site that it belongs to.

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

#### Defaults
Current supported defaults:

|  Key  | Type |  Description  |
|:-----:|:----:|:-------------:|
| site  | str | NetBox Site Name |
| role       | str  | Device role (e.g., switch) |
| description | str  | General description   |
| comments   | str  | General comments       |
| tags       | list | List of tags           |

##### Nested Defaults

| Key          | Type  | Description                   |
|-------------|------|---------------------------------|
| device      | map  | Device-specific defaults        |
| ├─ description | str  | Device description           |
| ├─ comments   | str  | Device comments               |
| ├─ tags       | list | Device tags                   |
| interface    | map  | Interface-specific defaults    |
| ├─ description | str  | Interface description        |
| ├─ tags       | list | Interface tags               |
| ipaddress    | map  | IP address-specific defaults  |
| ├─ description | str  | IP address description      |
| ├─ comments   | str  | IP address comments          |
| ├─ tags       | list | IP address tags              |
| prefix       | map  | Prefix-specific defaults      |
| ├─ description | str  | Prefix description          |
| ├─ comments   | str  | Prefix comments              |
| ├─ tags       | list | Prefix tags                  |

### Scope
The scope defines a list of devices that can be accessed and pulled data. 

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| hostname | string | yes  | Device hostname |
| username | string | yes  | Device username  |
| password | string | yes  | Device username's password |
| optional_args | map | no  | NAPALM optional arguments defined [here](https://napalm.readthedocs.io/en/latest/support/#list-of-supported-optional-arguments) |
| driver | string | no  |  If defined, try to connect to device using the specified NAPALM driver. If not, it will try all the current installed drivers |



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
            description: for all
            comments: comment all
            tags: [tag1, tag2]
            device:
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
            prefix:
              description:
              comments:
              tags: [tag7]
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
```