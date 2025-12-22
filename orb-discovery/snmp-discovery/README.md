# snmp-discovery
Orb snmp discovery backend, which is a wrapper over [NMAP](https://nmap.org/) scanner.

### Usage
```sh
Usage of snmp-discovery:
  -diode-app-name-prefix string
    	diode producer_app_name prefix
  -diode-client-id string
    	diode client ID. Environment variable can be used by wrapping it in ${} (e.g. ${DIODE_CLIENT_ID})
  -diode-client-secret string
    	diode client secret. Environment variable can be used by wrapping it in ${} (e.g. ${DIODE_CLIENT_SECRET})
  -diode-target string
    	diode target. Environment variable can be used by wrapping it in ${} (e.g. ${DIODE_TARGET})
  -dry-run
    	run in dry-run mode, do not ingest data
  -dry-run-output-dir string
    	output dir for dry-run mode.  Environment variable can be used by wrapping it in ${} (e.g. ${DRY_RUN_OUTPUT_DIR})
  -help
    	show this help
  -host string
    	server host (default "0.0.0.0")
  -log-format string
    	log format (default "TEXT")
  -log-level string
    	log level (default "INFO")
  -otel-endpoint string
    	OpenTelemetry exporter endpoint (e.g. localhost:4317). Environment variable can be used by wrapping it in ${} (e.g. ${OTEL_ENDPOINT})
  -otel-export-period int
    	Period in seconds between OpenTelemetry exports (default 10)
  -port int
    	server port (default 8070)
```

### Policy RFC
```yaml
policies:
  snmp_network_1:
    config:
      schedule: "0 */6 * * *" # Cron expression - every 6 hours
      timeout: 300 # Timeout for policy in seconds (default 2 minutes)
      snmp_timeout: 300 # Timeout for SNMP operations in seconds (default 5 seconds)
      snmp_probe_timeout: 1 # Timeout for SNMP probe operations in seconds (default 1 second)
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
      lookup_extensions_dir: "/opt/orb/snmp-extensions" # (Optional) Specifies an override for the directory containing device data yaml files (see below). Defaults to `/etc/snmp-discovery/lookup-extensions
    scope:
      targets:
        - host: "192.168.1.1/24" # subnet support
        - host: "192.168.2.1-20" # range support
        - host: "10.0.0.1"
          port: 162  # Non-standard SNMP port
      authentication:
        protocol_version: "v2c"
        community: "public"
        # For SNMPv3, use these fields instead:
        # security_level: "authPriv"
        # username: "${SNMP_USERNAME}"
        # auth_protocol: "SHA"
        # auth_passphrase: "${SNMP_AUTH_PASS}"
        # priv_protocol: "AES"
        # priv_passphrase: "${SNMP_PRIV_PASS}"

**Note:** The following authentication fields support environment variable substitution using the `${VARNAME}` syntax:

- `community`
- `username`
- `auth_passphrase`
- `priv_passphrase`

For example:

```yaml
authentication:
  protocol_version: "v3"
  security_level: "authPriv"
  username: "${SNMP_USERNAME}"
  auth_protocol: "SHA"
  auth_passphrase: "${SNMP_AUTH_PASS}"
  priv_protocol: "AES"
  priv_passphrase: "${SNMP_PRIV_PASS}"
```

If the referenced environment variable is not set, the service will exit with an error.
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
The `lookup_extensions_dir` specifies a directory containing device data YAML files that map SNMP device OIDs to human-readable device names. This allows snmp-discovery to provide meaningful device identification instead of raw OID values. This only needs to be set if additional or modified files are being provided instead of the ones that are included with orb-discovery and orb-agent.

#### File Format
Device lookup files must be in YAML format with a `.yaml` or `.yml` extension. Each file should contain a `devices` section that maps SNMP device OIDs to device names:

```yaml
devices:
  .1.3.6.1.4.1.9.1.1215: ciscoMwr2941DCA
  .1.3.6.1.4.1.9.1.489: catalyst2955C12
  .1.3.6.1.4.1.9.1.2101: ciscoASR92024TZM
  .1.3.6.1.4.1.9.1.2874: ciscoCat930048H
  .1.3.6.1.4.1.9.1.2276: ciscoC6840xle
```

#### Example Device Lookup Files
The repository includes several pre-built device lookup files for popular vendors. These are included in the orb-discovery and orb-agent images.

- **Cisco devices**: `cisco.yaml` - Contains mappings for Cisco routers, switches, and other networking equipment
- **TP-Link devices**: `tplink.yaml` - Contains mappings for TP-Link switches and routers
- **Dell Networking**: `dell-networking.yaml` - Contains mappings for Dell networking equipment
- **Lenovo devices**: `lenovo.yaml` - Contains mappings for Lenovo networking equipment
- **Ruckus devices**: `ruckus.yaml` - Contains mappings for Ruckus wireless equipment

The full list of vendor device files is available [here](https://github.com/netboxlabs/orb-discovery/tree/release/snmp-discovery/lookup_extension).

#### Creating Custom Device Lookup Files
You can create custom device lookup files for your specific hardware or to override the name of a device model by:

1. Identifying the SNMP device ObjectIDs for your equipment (usually found in vendor MIB files)
2. Creating a YAML file with the format shown above. Ensure that ObjectIDs have a `.` prefix.
3. Placing the file in your `lookup_extensions_dir` directory

```bash
# Clone the repository to get device lookup files
git clone https://github.com/netboxlabs/orb-discovery.git
cd orb-discovery/snmp-discovery/lookup_extensions/

# Copy the files to your lookup extensions directory
cp *.yaml /opt/orb/snmp-extensions/
```

#### How It Works
When snmp-discovery encounters a device during scanning, it:

1. Retrieves the device's SNMP system object ID (sysObjectID)
2. Searches through all YAML files in the `lookup_extensions_dir`
3. If a match is found, uses the human-readable device name instead of the raw OID
4. If no match is found, falls back to the original OID value

This provides much more meaningful device identification in your discovery results, making it easier to understand what equipment has been discovered on your network.

## Run snmp-discovery
snmp-discovery can be run by cloning it's git repo
```sh
git clone https://github.com/netboxlabs/orb-discovery.git
cd snmp-discovery/
make bin
build/snmp-discovery --diode-target grpc://192.168.31.114:8080/diode  --diode-client-id '${DIODE_CLIENT_ID}' --diode-client-secret '${DIODE_CLIENT_SECRET}'
```

### ⚠️ Warning
Be **AWARE** that executing a policy with only targets defined will use default SNMP parameters:

- **Protocol Version**: v2c (if not specified)
- **Community**: "public" (if not specified for v1/v2c)
- **Port**: 161 (standard SNMP port, if not specified)
- **Security Level**: noAuthNoPriv (if not specified for v3)

Always ensure proper authentication is configured for production environments to avoid security risks.

### Docker Image
device-discovery can be build and run using docker:
```sh
cd snmp-discovery/
docker build --no-cache -t snmp-discovery:develop -f docker/Dockerfile .
docker run --net=host -e DIODE_CLIENT_ID={YOUR_CLIENT} \
 -e DIODE_CLIENT_SECRET=${YOUR_SECRET} \
 snmp-discovery:develop snmp-discovery \
 --diode-target grpc://192.168.31.114:8080/diode \
 --diode-client-id '${DIODE_CLIENT_ID}' \
 --diode-client-secret '${DIODE_CLIENT_SECRET}'
```

### Routes (v1)

#### Get runtime and capabilities information

<details>
 <summary><code>GET</code> <code><b>/api/v1/status</b></code> <code>(gets network runtime data)</code></summary>

##### Parameters

> None

##### Responses

> | http code     | content-type                      | response                                                            |
> |---------------|-----------------------------------|---------------------------------------------------------------------|
> | `200`         | `application/json; charset=utf-8` |  `{"start_time": "2024-12-03T17:56:53.682805366-03:00", "up_time_seconds": 3678, "version": "0.1.0" }`                    |

##### Example cURL

> ```sh
>  curl -X GET -H "Content-Type: application/json" http://localhost:8073/api/v1/status
> ```

</details>

<details>
 <summary><code>GET</code> <code><b>/api/v1/capabilities</b></code> <code>(gets snmp-discovery capabilities)</code></summary>

##### Parameters

> None

##### Responses

> | http code     | content-type                      | response                                                            |
> |---------------|-----------------------------------|---------------------------------------------------------------------|
> | `200`         | `application/json; charset=utf-8` | `{"supported_args":["targets, ports"]}`      |

##### Example cURL

> ```sh
>  curl -X GET -H "Content-Type: application/json" http://localhost:8073/api/v1/capabilities
> ```

</details>

#### Policies Management


<details>
 <summary><code>POST</code> <code><b>/api/v1/policies</b></code> <code>(Creates a new policy)</code></summary>

##### Parameters

> | name      |  type     | data type               | description                                                           |
> |-----------|-----------|-------------------------|-----------------------------------------------------------------------|
> | None      |  required | YAML object             | yaml format specified in [Policy RFC](#policy-rfc)                    |
 

##### Responses

> | http code     | content-type                       | response                                                            |
> |---------------|------------------------------------|---------------------------------------------------------------------|
> | `201`         | `application/json; charset=UTF-8`  | `{"detail":"policy 'policy_name' was started"}`                     |
> | `400`         | `application/json; charset=UTF-8`  | `{ "detail": "invalid Content-Type. Only 'application/x-yaml' is supported" }`|
> | `400`         | `application/json; charset=UTF-8`  | Any other policy error                                              |
> | `403`         | `application/json; charset=UTF-8`  | `{ "detail": "config field is required" }`                          |
> | `409`         | `application/json; charset=UTF-8`  | `{ "detail": "policy 'policy_name' already exists" }`               |
 

##### Example cURL

> ```sh
>  curl -X POST -H "Content-Type: application/x-yaml" --data-binary @policy.yaml http://localhost:8073/api/v1/policies
> ```

</details>

<details>
 <summary><code>DELETE</code> <code><b>/api/v1/policies/{policy_name}</b></code> <code>(delete a existing policy)</code></summary>

##### Parameters

> | name              |  type     | data type      | description                         |
> |-------------------|-----------|----------------|-------------------------------------|
> |   `policy_name`   |  required | string         | The unique policy name              |

##### Responses

> | http code     | content-type                      | response                                                            |
> |---------------|-----------------------------------|---------------------------------------------------------------------|
> | `200`         | `application/json; charset=UTF-8` | `{ "detail": "policy 'policy_name' was deleted" }`                  |
> | `400`         | `application/json; charset=UTF-8` | Any other policy deletion error                                     |
> | `404`         | `application/json; charset=UTF-8` | `{ "detail": "policy 'policy_name' not found" }`                    |

##### Example cURL

> ```sh
>  curl -X DELETE http://localhost:8073/api/v1/policies/policy_name
> ```

</details>
