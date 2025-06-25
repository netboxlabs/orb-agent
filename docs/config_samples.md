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
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
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
            optional_args:
              ssh_config_file: /opt/orb/ssh-napalm.conf
```

Run command:
```sh
 docker run -v /local/orb:/opt/orb/ \
 -e DIODE_CLIENT_ID={YOUR_DIODE_CLIENT_ID} \
 -e DIODE_CLIENT_SECRET={YOUR_DIODE_CLIENT_SECRET} \
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
 -e DIODE_CLIENT_ID={YOUR_DIODE_CLIENT_ID} \
 -e DIODE_CLIENT_SECRET={YOUR_DIODE_CLIENT_SECRET} \
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
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
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
 docker run --net=host -v /local/orb:/opt/orb/ \
 -e DIODE_CLIENT_ID={YOUR_DIODE_CLIENT_ID} \
 -e DIODE_CLIENT_SECRET={YOUR_DIODE_CLIENT_SECRET} \
 netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

## Worker backend
```yaml
orb:
  config_manager:
    active: local
  backends:
    worker:
    common:
      diode:
        target: grpc://192.168.31.114:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent02
  policies:
    worker:
      policy_1:
        config:
          package: my_worker #Required
          schedule: "0 */2 * * *"
          custom_config: config
        scope:
          custom_val: value
```

### Custom Workers
To specify required custom workers packages, use the environment variable `INSTALL_WORKERS_PATH`. Ensure that the required files are placed in the mounted volume (`/opt/orb`).

Mounted folder example:
```sh
/local/orb/
├── agent.yaml
├── workers.txt
├── my-worker/
└── nbl-custom-worker-1.0.2.tar.gz
```

Example `workers.txt`:
```txt
my-custom-wkr==0.1.2 # try install from pypi
nbl-custom-worker-1.0.2.tar.gz # try install from a tar.gz
./my-worker # try to install from a folder that contains project.toml
```

Run command:
```sh
 docker run -v /local/orb:/opt/orb/ \
 -e DIODE_CLIENT_ID={YOUR_DIODE_CLIENT_ID} \
 -e DIODE_CLIENT_SECRET={YOUR_DIODE_CLIENT_SECRET} \
 -e INSTALL_WORKERS_PATH=/opt/orb/workers.txt \
 netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```
The relative path used by `pip install` should point to the directory containing the `.txt` file.

## SNMP Discovery Backend

The SNMP discovery backend leverages SNMP (Simple Network Management Protocol) to connect to network devices and collect network information. It uses [Diode Python SDK](https://github.com/netboxlabs/diode-sdk-python) to ingest Device, Interface, IP Address, Mac Address, Platform, Manufacturer, and Site entities.

### Basic Configuration
```yaml
orb:
  config_manager:
    active: local
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    snmp_discovery:
  policies:
    snmp_network_1:
      config:
        schedule: "0 */6 * * *" # Cron expression - every 6 hours
        timeout: 300 # Timeout in seconds (default 2 minutes)
        retries: 3 # Number of retries
        defaults:
          tags: ["snmp-discovery", "orb"]
          site: "datacenter-01"
          location: "rack-42"
          role: "network"
          ip_address:
            description: "SNMP discovered IP"
            role: "management"
            tenant: "network-ops"
            vrf: "management"
          interface:
            description: "Auto-discovered interface"
            if_type: "ethernet"
          device:
            description: "SNMP discovered device"
            comments: "Automatically discovered via SNMP"
        # lookup_extensions_dir: "/opt/orb/snmp-extensions" # Specifies aa directory containing additional device data yaml files (see below)
      scope:
        targets:
          - host: "192.168.1.1"
          - host: "192.168.1.254"
          - host: "10.0.0.1"
            port: 162  # Non-standard SNMP port
        authentication:
          protocol_version: "v2c"
          community: "public"
          # For SNMPv3, use these fields instead:
          # security_level: "authPriv"
          # username: "snmp-user"
          # auth_protocol: "SHA"
          # auth_passphrase: "auth-password"
          # priv_protocol: "AES"
          # priv_passphrase: "priv-password"
    discover_once: # will run only once
      scope:
        targets:
          - host: "core-switch.example.com"
            port: 161
          - host: "192.168.100.50"
            port: 161
        authentication:
          protocol_version: "v3"
          security_level: "authPriv"
          username: "monitoring"
          auth_protocol: "SHA"
          auth_passphrase: "secure-auth-pass"
          priv_protocol: "AES" 
          priv_passphrase: "secure-priv-pass"
```

### Device Model Lookup
The `lookup_extensions_dir` specifies a directory containing device data YAML files that map SNMP device ObjectIds (from querying `.1.3.6.1.2.1.1.2.0`) to human-readable device names. This allows snmp-discovery to provide meaningful device identification instead of raw ObjectId values. This only needs to be set if additional or modified files are being provided in addition the ones that are included with orb-discovery and orb-agent.

More details about the file format and adding devices that aren't already covered are [available here](https://github.com/netboxlabs/orb-discovery/blob/release/snmp-discovery/README.md#device-model-lookup).

### Running the SNMP Discovery Backend

Run using the following command (assuming you have placed all the files above in the `/local/orb` directory):

```bash
docker run --net=host \
    -v "/local/orb:/opt/orb/" \
    -e DIODE_CLIENT_ID=$DIODE_CLIENT_ID \
    -e DIODE_CLIENT_SECRET=$DIODE_CLIENT_SECRET \
    netboxlabs/orb-agent:latest \
    run -c "/opt/orb/snmp-config.yaml"
```
