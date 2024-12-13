# orb-agent
TBD

## Getting Started
1. Clone the orb-agent project to your local environment:

```sh
git clone https://github.com/netboxlabs/orb-agent.git
```

2. Enter the orb-agent directory and build the orb-agent docker image:
```sh
make agent
```

3. Start the agent, passing your config file(s):
```sh
 docker run -v /local/orb:/opt/orb/ netboxlabs/orb-agent:develop run -c /opt/orb/agent.yaml
```

## Config file samples

### Device-discovery backend

```yaml
orb:
  config_manager: 
    active: local
  backends:
    device_discovery:
    common:
      diode:
        target: grpc://192.168.31.114:8080/diode
        api_key: ${DIODE_API_KEY}
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
```

Run command:
```sh
 docker run -v /local/orb:/opt/orb/ \
 -e DIODE_API_KEY={YOUR_API_KEY} \
 -e PASS={DEVICE_PASSWORD} \
 netboxlabs/orb-agent:develop run -c /opt/orb/agent.yaml
```

#### Custom Drivers
You can specify community or custom NAPALM drivers using the env variable `INSTALL_DRIVERS_PATH`. Ensure that the required files are placed in the mounted volume (`/opt/orb`).

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
 netboxlabs/orb-agent:develop run -c /opt/orb/agent.yaml
```
The relative path used by `pip install` is the folder that contains `.txt` file.


### Network-discovery backend
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
 netboxlabs/orb-agent:develop run -c /opt/orb/agent.yaml
```
