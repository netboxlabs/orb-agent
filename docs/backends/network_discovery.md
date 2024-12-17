# Network Discovery
The network discovery backend leverages NMAP to scan network and discovers IP information.


## Configuration
The `network_discovery` backend does not require any special configuration, though overriding `host` and `port` values can be specified. The backend will use the `diode` settings specified in the `common` subsection to forward discovery results.


```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        api_key: ${DIODE_API_KEY}
        agent_name: agent01
    network_discovery:
      host: 192.168.5.11 #default 0.0.0.0
      port: 8863 # default 8072
      log_level: ERROR #default INFO
      log_format: JSON #default TEXT

```

## Policy
Network discovery policies are broken down into two subsections: `config` and `scope`.

### Config
Config defines data for the whole scope and is optional overall.

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| schedule | cron format | no  |  If defined, it will execute scope following cron schedule time. If not defined, it will execute scope only once  |
| defaults | map | no  |  key value pair that defines default values  |
| timeout | int | no | Timeout in minutes for the nmap scan operation. The default value is 2 minutes.

#### Defaults
Current supported defaults:

|  Key  |  Description  |
|:-----:|:-------------:|
| comments  |  NetBox Comments information to be added to discovered IP |
| description  |  NetBox Description data to be added to discovered IP |

### Scope
The scope defines a list of devices that can be accessed and pulled data. 

| Parameter | Type | Required | Description |
|:---------:|:----:|:--------:|:-----------:|
| targets | list | yes  | The targets that NMAP will scan. These can be specified as IP addresses (192.168.1.1), IP ranges (192.168.1.10-20), IP subnets with mask (192.168.1.0/24) or resolvable domain names. |




### Sample
A sample policy including all parameters supported by the network discovery backend.
```yaml
orb:
  ...
  policies:
    network_discovery:
      discovery_1:
        config:
          schedule: "* * * * *"
          timeout: 5
          defaults:
            comments: none
            description: IP discovered by network discovery
        scope:
          targets: 
            - 192.168.7.32
            - 192.168.7.30-40 # IP range
            - 192.168.7.0/24 # IP subnet
            - google.com #dns lookup

```