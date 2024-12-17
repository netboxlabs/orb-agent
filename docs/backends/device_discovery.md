# Device Discovery
The device discovery backend leverages NAPALM to connect to network devices and collect network information.


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
    device_discovery:
      host: 192.168.5.11 #default 0.0.0.0
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

|  Key  |  Description  |
|:-----:|:-------------:|
| site  |  NetBox Site Name |

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
        scope:
          - driver: ios
            hostname: 192.168.0.5
            username: admin
            password: ${PASS}
            optional_args:
               canonical_int: True
          - hostname: myhost.com
            username: remote
            password: 12345
```