# network-discovery
Orb network discovery backend, which is a wrapper over [NMAP](https://nmap.org/) scanner.

### Requirements
network discovery requires [NMAP](https://nmap.org/) to be installed on the machine. To enable full feature support, `nmap` must have the necessary capabilities to perform raw socket operations. However, for default usage, this is not required.

On UNIX systems, users can enable raw socket operations for nmap by running the following command:
```sh
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)
```

### Usage
```sh
Usage of network-discovery:
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
        OpenTelemetry exporter endpoint
  -otel-export-period int
        Period in seconds between OpenTelemetry exports (default 60)
  -port int
        server port (default 8073)
```

### Policy RFC
```yaml
policies:
  network_1:
    config:
      schedule: "* * * * *" #Cron expression
      timeout: 10 #default 5 minutes
    scope:
      targets: [192.168.1.0/24] # REQUIRED param
      fast_mode: True # -F 
      timing: 2 # -T [0-5]
      ports: [22,161,162,443,500-600,8080] # -p
      exclude_ports: [23, 9000-12000] # --exclude-ports 
      scan_types: [connect, udp, fin ] # -sT -sU -sF
      top_ports: 10 # --top-ports
      ping_scan: True # -sn
      max_retries: 1 # --max-retries
  discover_once: # will run only once
    scope:
       targets: 
        - 192.168.0.34/24
        - google.com
```
## Run network-discovery
network-discovery can be run by cloning it's git repo
```sh
git clone https://github.com/netboxlabs/orb-discovery.git
cd network-discovery/
make build
build/network-discovery --diode-target grpc://192.168.31.114:8080/diode  --diode-client-id '${DIODE_CLIENT_ID}' --diode-client-secret '${DIODE_CLIENT_SECRET}'
```

### ⚠️ Warning
Be **AWARE** that executing a policy with only targets defined is equivalent to running `nmap <targets>`, which in turn is the same as executing `nmap -sS -p1-1000 --open -T4 <target>`:

- `-sS` → SYN scan (stealth scan, requires root privileges)
- `-p1-1000` → Scans the top 1000 most common ports
- `--open` → Only shows open ports
- `-T4` → Uses the agressive timing template

### Docker Image
device-discovery can be build and run using docker:
```sh
cd network-discovery/
docker build --no-cache -t network-discovery:develop -f docker/Dockerfile .
docker run --net=host -e DIODE_CLIENT_ID={YOUR_CLIENT} \
 -e DIODE_CLIENT_SECRET=${YOUR_SECRET} \
 network-discovery:develop network-discovery \
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
 <summary><code>GET</code> <code><b>/api/v1/capabilities</b></code> <code>(gets network-discovery capabilities)</code></summary>

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
