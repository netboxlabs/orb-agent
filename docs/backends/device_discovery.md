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
* [VLAN](https://github.com/netboxlabs/diode-sdk-python/blob/develop/README.md#supported-entities-object-types)

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
| options | map | no | key value pair that defines config options |

#### Options
Current supported options:
|  Key  | Type |  Description  |
|:-----:|:----:|:-------------:|
| platform_omit_version  | bool | If True, only the driver name will be used as the NetBox platform name (defaults to 'False' if not specified) |

#### Defaults
Current supported defaults:

|  Key  | Type |  Description  |
|:-----:|:----:|:-------------:|
| site  | str | NetBox Site Name (defaults to 'undefined' if not specified) |
| role  | str  | Device role (e.g., switch) (defaults to 'undefined' if not specified) |
| if_type | str | Interface Type (defaults to 'other' if not specified) |
| location | str | Device location |
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
| ├─ vrf   | str  | IP address vrf                    |
| ├─ description | str  | IP address description      |
| ├─ comments   | str  | IP address comments          |
| ├─ tags       | list | IP address tags              |
| prefix       | map  | Prefix-specific defaults      |
| ├─ role   | str  | Prefix role                    |
| ├─ tenant   | str  | Prefix tenant                |
| ├─ vrf   | str  | Prefix vrf                      |
| ├─ description | str  | Prefix description        |
| ├─ comments   | str  | Prefix comments            |
| ├─ tags       | list | Prefix tags                |
| vlan       | map  | VLAN-specific defaults        |
| ├─ group   | str  | VLAN group                    |
| ├─ tenant   | str  | VLAN tenant                  |
| ├─ role   | str  | VLAN role                      |
| ├─ description | str  | VLAN description          |
| ├─ comments   | str  | VLAN comments              |
| ├─ tags       | list | VLAN tags                  |

### Scope
The scope defines a list of devices that can be accessed and pulled data. 

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| hostname | string | yes  | Device hostname |
| username | string | yes  | Device username  |
| password | string | yes  | Device username's password |
| driver | string | no  |  If defined, try to connect to device using the specified NAPALM driver. If not, it will try all the current installed drivers |
| optional_args | map | no  | NAPALM optional arguments defined [here](https://napalm.readthedocs.io/en/latest/support/#list-of-supported-optional-arguments) |
| override_defaults | map | no | Allows overriding of any defaults for a specific device in the scope |




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
            location: Row A
            tenant: NetBox Labs
            description: for all
            comments: comment all
            tags: [tag1, tag2]
            device:
              model: C9200-48P
              manufacturer: Cisco
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
            override_defaults:
              role: router
              location: Row B
```

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