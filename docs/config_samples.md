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

## Device Discovery with Jumphost

This example demonstrates discovering devices through a bastion host using SSH ProxyJump.

**Scenario:**
- Bastion host at 203.0.113.100
- Network devices in 10.0.0.0/8 accessible only through bastion
- Key-based authentication to bastion
- Password authentication to network devices

**Directory Structure:**
```
/local/orb/
├── agent.yaml
├── ssh-jumphost.conf
└── keys/
    └── bastion_key
```

**SSH Config** (`/local/orb/ssh-jumphost.conf`):
```sshconfig
Host bastion
  HostName 203.0.113.100
  User admin
  IdentityFile /opt/orb/keys/bastion_key
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

Host 10.*
  ProxyJump bastion
  StrictHostKeyChecking no
```

**Agent Config** (`/local/orb/agent.yaml`):
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
        agent_name: bastion-agent
    device_discovery:
  policies:
    device_discovery:
      behind_bastion:
        config:
          schedule: "*/10 * * * *"
          defaults:
            site: Remote Site
            role: switch
        scope:
          - driver: ios
            hostname: 10.0.1.10
            username: cisco
            password: ${CISCO_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-jumphost.conf
          - driver: eos
            hostname: 10.0.2.20
            username: arista
            password: ${ARISTA_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-jumphost.conf
```

**Setup Commands:**
```bash
# Create directory structure
mkdir -p /local/orb/keys

# Generate SSH key for bastion
ssh-keygen -t rsa -b 4096 -f /local/orb/keys/bastion_key -N ""
chmod 600 /local/orb/keys/bastion_key

# Copy public key to bastion host
ssh-copy-id -i /local/orb/keys/bastion_key.pub admin@203.0.113.100

# Create the SSH config and agent config files (content above)
```

**Run Command:**
```bash
docker run -v /local/orb:/opt/orb/ \
  -e DIODE_CLIENT_ID="${DIODE_CLIENT_ID}" \
  -e DIODE_CLIENT_SECRET="${DIODE_CLIENT_SECRET}" \
  -e CISCO_PASS="${CISCO_PASS}" \
  -e ARISTA_PASS="${ARISTA_PASS}" \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

For advanced scenarios including VRF-aware connections, multiple jumphosts, and performance optimization with Control Master, see the comprehensive [SSH Configuration and Jumphost Support](backends/device_discovery_ssh.md) guide.

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
    snmp_discovery:
      snmp_network_1:
        config:
          schedule: "0 */6 * * *" # Cron expression - every 6 hours
          timeout: 300 # Timeout for policy in seconds (default 2 minutes)
          snmp_timeout: 10 # Timeout for SNMP operations in seconds (default 5 seconds)
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
          # lookup_extensions_dir: "/opt/orb/snmp-extensions" # Specifies a directory containing additional device data yaml files (see below)
        scope:
          targets:
            - host: "192.168.1.1"
            - host: "192.168.1.254"
            - host: "10.0.0.1"
              port: 162  # Non-standard SNMP port
          authentication:
            protocol_version: "SNMPv2c"
            community: "public" # Also supports resolving values from environment variables eg ${SNMP_COMMUNITY}
            # For SNMPv3, use these fields instead:
            # security_level: "authPriv"
            # username: "snmp-user" # Also supports resolving values from environment variables eg ${SNMP_USERNAME}
            # auth_protocol: "SHA"
            # auth_passphrase: "auth-password" # Also supports resolving values from environment variables eg ${SNMP_AUTH_PASSPHRASE}
            # priv_protocol: "AES"
            # priv_passphrase: "priv-password"# Also supports resolving values from environment variables eg ${SNMP_PRIV_PASSPHRASE}
      discover_once: # will run only once
        scope:
          targets:
            - host: "core-switch.example.com"
              port: 161
            - host: "192.168.100.50"
              port: 161
          authentication:
            protocol_version: "SNMPv3"
            security_level: "authPriv"
            username: "monitoring"
            auth_protocol: "SHA"
            auth_passphrase: "secure-auth-pass"
            priv_protocol: "AES" 
            priv_passphrase: "secure-priv-pass"
```

**Note:** The following authentication fields support environment variable substitution using the `${VARNAME}` syntax:

- `community`
- `username`
- `auth_passphrase`
- `priv_passphrase`

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

## Diode Dry Run Mode

The Orb Agent supports a diode dry run mode that allows you to test your configuration without sending data to the Diode server. This is useful for debugging and validating your configuration.

### Basic Configuration

```yaml
orb:
  config_manager:
    active: local
  backends:
    device_discovery:
    common:
      diode:
        dry_run: true
        dry_run_output_dir: /opt/orb/
        # No need for target, client_id, client_secret when in dry_run mode
        agent_name: agent01
  policies:
    device_discovery:
      discovery_1:
        config:
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
-e PASS={DEVICE_PASSWORD} \
-v /local/output:/opt/orb/output \
netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

When running in dry run mode, the agent will:
1. Process all policies as usual
2. Write the data that would be sent to Diode as JSON files in the specified output directory.
3. For this sample policy, a file named `agent01_device-discovery_<timestamp>.json` will be generated in `/opt/orb` folder.
4. No data will be sent to any remote server

This allows you to inspect the data that would be collected and sent to Diode Server before configuring the actual connection.
This feature is supported by the [Device Discovery](./backends/device_discovery.md), [Network Discovery](./backends/network_discovery.md), [Worker](./backends/worker.md) and [SNMP Discovery](./backends/snmp_discovery.md) backends.

## Exporting OpenTelemetry Metrics

The backends support exporting metrics using OpenTelemetryover GRPC.

### Basic Configuration

```yaml
orb:
  config_manager:
    active: local
  labels:
    agent_id: "network-agent-001"
    location: "datacenter-east"
  backends:
    # Discovery backends that export to OpenTelemetry via gRPC
    device_discovery:
    network_discovery:
    snmp_discovery:
    worker:
          
    common:
      otel:
        # gRPC endpoint for discovery backends
        grpc: "grpc://otel-collector.monitoring.svc.cluster.local:4317"
        
        # Labels attached to all telemetry data
        agent_labels:
          environment: "production"
          datacenter: "us-east-1"
          cluster: "main"
          service: "orb-agent"
          version: "v2.0.0"
          team: "platform"
      
      diode:
        target: "grpc://diode.example.com:8080/diode"
        client_id: "${DIODE_CLIENT_ID}"
        client_secret: "${DIODE_CLIENT_SECRET}"
        agent_name: "network-agent-001"
  
  policies:
    device_discovery:
      policy_1:
        config:
          schedule: "*/10 * * * *"
        scope:
          - driver: ios
            hostname: "192.168.1.1"
            username: "admin"
            password: "${DEVICE_PASSWORD}"
    
    network_discovery:
      policy_1:
        config:
          schedule: "0 */2 * * *"
          timeout: 5
        scope:
          targets: [192.168.1.0, 192.168.1.1]
```
