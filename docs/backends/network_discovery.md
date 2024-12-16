# Network Discovery
The network discovery backend leverages NMAP to scan network and discovers IP information.


## Configuration
At startup, configure the backend to specify where it should send data.


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
Network discovery policy can be splited into config and scope. 

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
| targets | list | yes  | The host targets that NMAP will run over. |




### Sample
A policy sample with all parameters supported by network discovery backend.
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
            - google.com #dns lookup

```