# Configuration Samples
Here is a collection of configuration samples supported by orb agent

## Device-discovery backend
This sample configuration file demonstrates the device discovery backend connecting to a Cisco router at 192.168.0.5. It retrieves device, interface, and IP information, then sends the data to a [diode](https://github.com/netboxlabs/diode) server running at 192.168.0.100.

```yaml
orb:
  config_manager: 
    active: local
  backends:
    device_discovery:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        api_key: ${DIODE_API_KEY}
        agent_name: agent01
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
```

Run command:
```sh
 docker run -v /local/orb:/opt/orb/ \
 -e DIODE_API_KEY={YOUR_API_KEY} \
 -e PASS={DEVICE_PASSWORD} \
 netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

### Custom Drivers
To specify community or custom NAPALM drivers, use the environment variable `INSTALL_DRIVERS_PATH`. Ensure that the required files are placed in the mounted volume (`/opt/orb`).

Mounted folder example:
```sh
/local/orb/
├── agent.yaml
├── drivers.txt
├── napalm-mos/
└── napalm-ros-0.3.2.tar.gz
```

Example `drivers.txt`:
```txt
napalm-sros==1.0.2 # try install from pypi
napalm-ros-0.3.2.tar.gz # try install from a tar.gz
./napalm-mos # try to install from a folder that contains project.toml
```

Run command:
```sh
 docker run -v /local/orb:/opt/orb/ \
 -e DIODE_API_KEY={YOUR_API_KEY} \
 -e PASS={DEVICE_PASSWORD} \
 -e INSTALL_DRIVERS_PATH=/opt/orb/drivers.txt \
 netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```
The relative path used by `pip install` should point to the directory containing the `.txt` file.


## Network-discovery backend
```yaml
orb:
  config_manager:
    active: local
  backends:
    network_discovery:
    common:
      diode:
        target: grpc://192.168.31.114:8080/diode
        api_key: ${DIODE_API_KEY}
        agent_name: agent02
  policies:
    network_discovery:
      policy_1:
        config:
          schedule: "0 */2 * * *"
          timeout: 5
        scope:
          targets: [192.168.1.1/22, google.com]
```

Run command:
```sh
 docker run -v /local/orb:/opt/orb/ \
 -e DIODE_API_KEY={YOUR_API_KEY} \
 netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```