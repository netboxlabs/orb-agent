# Device Discovery
Device discovery backend uses the power of NAPALM to connect to network devices and retrieve network information.


## Configuration
At backend startup time, you should configure the backend to point where it should sent data to.


```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.31.114:8080/diode
        api_key: ${DIODE_API_KEY}
        agent_name: agent01
    device_discovery:
      host: 192.168.5.11 #default 0.0.0.0
      port: 8857 # default 8072

```

## Policy
Device discovery policy can be splited into config and scope. Config defines data for the whole scope and g