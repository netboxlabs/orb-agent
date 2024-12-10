# orb-agent
TBD

## Getting Started
Start by cloning the orb-agent project in your local environment using the following command:

```sh
https://github.com/netboxlabs/orb-agent.git
```

Then, build the orb-agent docker image using Make:
```sh
make agent
```

Finally, run it passing your config file(s)
```sh
 docker run -v /local/orb:/opt/orb/ netboxlabs/orb-agent:develop run -c /opt/orb/agent.yaml
```

### Config file samples
This contains diferent config file examples

#### Device-discovery backend

Config file:
```yaml
orb:
  config_manager: local
  backends:
    device_discovery:
      binary: device_discovery
  policies:
    device_discovery:
      discovery_1:
        config:
          schedule: "0 */2 * * *"
          defaults:
            site: New York NY
        scope:
          - hostname: 10.90.0.50
            username: admin
            password: ${PASS}


discovery:
  config:
    target: grpc://192.168.31.114:8080/diode
    api_key: ${DIODE_API_KEY}
```

Run command:
```sh
 docker run -v /local/orb:/opt/orb/ \
 -e DIODE_API_KEY={YOUR_API_KEY} \
 -e PASS={DEVICE_PASSWORD} \
 netboxlabs/orb-agent:develop run -c /opt/orb/agent.yaml
```

##### Custom Drivers
You can specify community or custom NAPALM drivers using env variable `INSTALL_DRIVERS_PATH`. Ensure that the required files are placed in the mounted volume (`/opt/orb`).

mounted folder example:
```sh
/local/orb/
├── agent.yaml
├── drivers.txt
├── napalm-mos/
└── napalm-ros-0.3.2.tar.gz
```

`drivers.txt` sample:
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
 netboxlabs/orb-agent:develop run -c /opt/orb/agent.yaml
```
The relative path used by `pip install` is the folder that contains `.txt` file.


#### Network-discovery backend
```yaml
orb:
  config_manager: local
  backends:
    network_discovery:
      binary: /opt/usr/network_discovery
  policies:
    network_discovery:
      discovery_1:
        config:
          schedule: "0 */2 * * *"
        scope:
          targets: [192.168.1.1/22, google.com]
          timeout: 5

network:
  config:
    target: grpc://192.168.31.114:8080/diode
    api_key: ${DIODE_API_KEY}
```
