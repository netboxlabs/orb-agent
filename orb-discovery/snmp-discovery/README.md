# snmp-discovery
Orb snmp discovery backend

### Usage
```bash
Usage of snmp-discovery:
 -diode-app-name-prefix string
    	diode producer_app_name prefix
  -diode-client-id string
    	diode client ID (REQUIRED). Environment variables can be used by wrapping them in ${} (e.g. ${MY_DIODE_CLIENT_ID})
  -diode-client-secret string
    	diode client secret (REQUIRED). Environment variables can be used by wrapping them in ${} (e.g. ${MY_DIODE_CLIENT_SECRET})
  -diode-target string
    	diode target (REQUIRED). Environment variables can be used by wrapping them in ${} (e.g. ${MY_DIODE_TARGET})
  -help
    	show this help
  -host string
    	server host (default "0.0.0.0")
  -port int
      server port (default 8070)
  -log-format string
    	log format (default "TEXT")
  -log-level string
    	log level (default "INFO")
  -otel-endpoint string    # OpenTelemetry exporter endpoint
  -otel-export-period int
    	Period in seconds between OpenTelemetry exports (default 10)
```

## Configuration

The SNMP discovery service is configured using a YAML file. The configuration file has the following structure:

```yaml
config:
  schedule: "*/5 * * * *"  # Optional: Cron expression for scheduling
  defaults:  # Optional: Default values for entities
    description: "Global description"  # Optional: Global description for all entities
    comments: "Global comments"  # Optional: Global comments for all entities
    tags:  # Optional: Global tags for all entities
      - "global"
      - "snmp"
    ip_address:  # Optional: Defaults specific to IP addresses
      description: "IP Address description"
      comments: "IP Address comments"
      tags:
        - "ip"
        - "default"
    interface:  # Optional: Defaults specific to interfaces
      description: "Interface description"
      tags:
        - "interface"
        - "default"
    device:  # Optional: Defaults specific to devices
      description: "Device description"
      tags:
        - "device"
        - "default"
scope:
  targets:  # List of SNMP targets to discover
    - host: "192.168.1.1"  # Required: Hostname or IP address
      port: 161  # Optional: SNMP port (default: 161)
    - host: "10.10.10.0/24"  # CIDR range: expands to all IPs in the subnet
    - host: "10.10.10.10-20" # Dash range: expands to 10.10.10.10, 10.10.10.11, ..., 10.10.10.20
    - host: "mydevice.local" # Hostname
  authentication:  # SNMP authentication settings
    protocol_version: "SNMPv2c"  # Required: SNMP protocol version ("SNMPv1", "SNMPv2c", or "SNMPv3")
    community: "public"  # Required for v1/v2c: SNMP community string
    # Optional for v3:
    # username: "user"
    # security_level: authPriv # Allowed values: ("NoAuthNoPriv", "AuthNoPriv", "AuthPriv")
    # auth_protocol: "SHA"
    # auth_passphrase: "authkey"
    # priv_protocol: "AES"
    # priv_passphrase: "privkey"
  retries: 3  # Optional: Number of SNMP retries (default: 0)

#### Target Range Formats

The `host` field in `targets` supports the following formats:

- **Single IP address:**
  - `192.168.1.1`
- **Hostname:**
  - `mydevice.local`
- **CIDR range:**
  - `10.10.10.0/24` (expands to all IPs in the subnet)
- **Dash range:**
  - `10.10.10.10-20` (expands to 10.10.10.10, 10.10.10.11, ..., 10.10.10.20)

Invalid or out-of-bounds ranges will be skipped and logged.

### Defaults

The `defaults` section allows you to specify default values for entities discovered by SNMP. These defaults can be applied globally to all entities or specifically to certain entity types.

#### Global Defaults

Global defaults are applied to all entities if they don't have entity-specific defaults:

- `description`: A global description for all entities
- `comments`: Global comments for all entities
- `tags`: Global tags for all entities

#### Entity-Specific Defaults

Entity-specific defaults override global defaults for their respective entity types:

- `ipAddress`: Defaults for IP addresses
  - `description`: Description for IP addresses
  - `comments`: Comments for IP addresses
  - `tags`: Tags for IP addresses

- `interface`: Defaults for interfaces
  - `description`: Description for interfaces
  - `tags`: Tags for interfaces

- `device`: Defaults for devices
  - `description`: Description for devices
  - `tags`: Tags for devices

### Mappings

The `mappings` section defines how SNMP OIDs are mapped to entities. Each mapping entry has the following fields:

- `oid`: The SNMP OID to map
- `entity`: The entity type to map to (e.g., "interface", "ipAddress", "device")
- `field`: The field to map to
- `identifierSize`: The size of the identifier in the OID (default: 1)
- `mappingEntries`: Optional nested mappings for additional fields

### Authentication

The `authentication` section configures SNMP authentication settings:

- `protocolVersion`: The SNMP protocol version ("1", "2c", or "3")
- `community`: The SNMP community string (required for v1/v2c)
- `username`: The SNMP username (required for v3)
- `authProtocol`: The authentication protocol (required for v3)
- `authKey`: The authentication key (required for v3)
- `privProtocol`: The privacy protocol (required for v3)
- `privKey`: The privacy key (required for v3)

### Metrics

The SNMP discovery service includes comprehensive metrics collection using OpenTelemetry. Metrics can be configured using command-line flags or environment variables.

#### Available Metrics

The following metrics are collected:

- **discovery_attempts**: Counter of SNMP discovery attempts
- **discovery_success**: Counter of successful SNMP discoveries
- **discovery_failure**: Counter of failed SNMP discoveries
- **policy_executions**: Counter of policy executions
- **api_requests**: Counter of API requests
- **discovery_latency**: Histogram of SNMP discovery latency
- **api_response_latency**: Histogram of API response latency
- **active_policies**: UpDown counter of active policies

#### Configuration Options

Metrics can be configured using the following options:

1. **Command-line flags:**
   ```bash
   -otel-endpoint string    # OpenTelemetry exporter endpoint
   -otel-export-period int  # Export period in seconds
   ```

2. **Environment variables:**
   ```bash
   OTEL_ENDPOINT="http://localhost:4317"  # OpenTelemetry exporter endpoint
   OTEL_EXPORT_PERIOD=10                  # Export period in seconds
   ```

#### Example Configuration

To enable metrics export to an OpenTelemetry collector:

```bash
snmp-discovery \
  -otel-endpoint="http://localhost:4317" \
  -otel-export-period=10
```

Or using environment variables:

```bash
export OTEL_ENDPOINT="http://localhost:4317"
export OTEL_EXPORT_PERIOD=10
snmp-discovery
```

#### Troubleshooting

If metrics are not being exported:

1. Verify the OpenTelemetry collector is running and accessible
2. Check the metrics endpoint URL is correct
3. Ensure the export period is set appropriately
4. Check the application logs for any metrics-related errors
