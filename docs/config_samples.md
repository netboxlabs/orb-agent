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
 docker run -v /local/orb:/opt/orb/ \
 -e DIODE_API_KEY={YOUR_API_KEY} \
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
 -e DIODE_API_KEY={YOUR_API_KEY} \
 -e INSTALL_WORKERS_PATH=/opt/orb/workers.txt \
 netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```
The relative path used by `pip install` should point to the directory containing the `.txt` file.

## SNMP Discovery Backend

This sample configuration file demonstrates the device discovery backend connecting to a Cisco router at 192.168.0.5. It retrieves device, interface, and IP information, then sends the data to a [diode](https://github.com/netboxlabs/diode) server running at 192.168.0.100.

snmp-policy.yaml
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
    snmp_discovery:
      snmp_cisco:
        config:
          retries: 1
          devices_file: /opt/orb/device-data.yaml
        scope:
          authentication:
              protocol_version: SNMPv2c
              community: cisco-c3750
          targets:
            - host: 192.168.0.5
              port: 161
          mapping_config: /opt/orb/snmp-mapping.yaml
```

device-data.yaml
```yaml
manufacturers:
  - name: Reserved
    pen: 0
  - name: NxNetworks
    pen: 1
  - name: IBM httpsw3ibmcomstandards 
    pen: 2
  - name: Carnegie Mellon
    pen: 3
  - name: Unix
    pen: 4
  - name: ACC
    pen: 5
  - name: TWG
    pen: 6
  - name: CAYMAN
    pen: 7
  - name: PSI
    pen: 8
  - name: ciscoSystems
    pen: 9
  - name: NSC
    pen: 10
  - name: HewlettPackard
    pen: 11
  - name: Epilogue
    pen: 12
  - name: U of Tennessee
    pen: 13
  - name: BBN Technologies
    pen: 14
  - name: Xylogics Inc
    pen: 15
  - name: Timeplex
    pen: 16
  - name: Canstar
    pen: 17
  - name: Wellfleet
    pen: 18
  - name: TRW
    pen: 19
  - name: MIT
    pen: 20
  - name: EON
    pen: 21
  - name: Fibronics
    pen: 22
  - name: Novell
    pen: 23
  - name: Spider Systems
    pen: 24
  - name: NSFNET
    pen: 25
  #  ... (other manufacturers can be added here)
devices:
  - id: 1
    oid: 136141911
    name: ciscoGatewayServer
  - id: 2
    oid: 136141912
    name: ciscoTerminalServer
  - id: 3
    oid: 136141913
    name: ciscoTrouter
  - id: 4
    oid: 136141914
    name: ciscoProtocolTranslator
  - id: 5
    oid: 136141915
    name: ciscoIGS
  - id: 6
    oid: 136141916
    name: cisco3000
  - id: 7
    oid: 136141917
    name: cisco4000
  - id: 8
    oid: 136141918
    name: cisco7000
  - id: 9
    oid: 136141919
    name: ciscoCS500
  - id: 10
    oid: 1361419110
    name: cisco2000
  - id: 11
    oid: 1361419111
    name: ciscoAGSplus
  - id: 12
    oid: 1361419112
    name: cisco7010
  - id: 13
    oid: 1361419113
    name: cisco2500
  - id: 14
    oid: 1361419114
    name: cisco4500
  - id: 15
    oid: 1361419115
    name: cisco2102
  - id: 16
    oid: 1361419116
    name: cisco2202
  # ... (other devices can be added here)
```

snmp-mapping.yaml
```yaml
entries:
  # Interface mappings
  - oid: ".1.3.6.1.2.1.2.2.1"
    entity: "interface"
    field: "_id"
    identifier_size: 1
    mapping_entries:
      - oid: ".1.3.6.1.2.1.2.2.1.2"
        entity: "interface"
        field: "name"
      - oid: ".1.3.6.1.2.1.2.2.1.5"
        entity: "interface"
        field: "speed"
      - oid: ".1.3.6.1.2.1.2.2.1.6"
        entity: "interface"
        field: "macAddress"
      - oid: ".1.3.6.1.2.1.2.2.1.7"
        entity: "interface"
        field: "adminStatus"

  # IP Address mappings
  - oid: ".1.3.6.1.2.1.4.20.1"
    entity: "ipAddress"
    field: "_id"
    identifier_size: 4
    mapping_entries:
      - oid: ".1.3.6.1.2.1.4.20.1.1"
        entity: "ipAddress"
        field: "address"
      - oid: ".1.3.6.1.2.1.4.20.1.2"
        entity: "ipAddress"
        field: "assigned_object"
        relationship:
          type: "interface"
          field: "_id"

  # Device mappings
  - oid: ".1.3.6.1.2.1.1"
    entity: "device"
    field: "_id"
    mapping_entries:
      - oid: ".1.3.6.1.2.1.1.5.0"
        entity: "device"
        field: "name"
      - oid: ".1.3.6.1.2.1.1.2.0"
        entity: "device"
        field: "platform"
```

Run using the following command (assuming you have placed all the files above in the `/local/orb` directory )
```bash
docker run --net=host \
    -v "/local/orb:/opt/orb/" \
    -e DIODE_CLIENT_ID=$DIODE_CLIENT_ID \
    -e DIODE_CLIENT_SECRET=$DIODE_CLIENT_SECRET \
    netboxlabs/orb-agent:latest \
    run -d -c "/opt/orb/snmp-config.yaml"
```