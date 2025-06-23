# worker
Orb worker backend - allow running custom Backend implementations

### Usage
```bash
usage: orb-worker [-h] [-V] [-s HOST] [-p PORT] [-t DIODE_TARGET] [-c DIODE_CLIENT_ID] [-k DIODE_CLIENT_SECRET] [-a DIODE_APP_NAME_PREFIX] [-d]
               [-o DRY_RUN_OUTPUT_DIR] [--otel-endpoint OTEL_ENDPOINT] [--otel-export-period OTEL_EXPORT_PERIOD]

Orb Worker Backend

options:
  -h, --help            show this help message and exit
  -V, --version         Display Orb Worker and Diode SDK versions
  -s HOST, --host HOST  Server host
  -p PORT, --port PORT  Server port
  -t DIODE_TARGET, --diode-target DIODE_TARGET
                        Diode target. Environment variable can be used by wrapping it in ${} (e.g. ${TARGET})
  -c DIODE_CLIENT_ID, --diode-client-id DIODE_CLIENT_ID
                        Diode Client ID. Environment variable can be used by wrapping it in ${} (e.g. ${MY_CLIENT_ID})
  -k DIODE_CLIENT_SECRET, --diode-client-secret DIODE_CLIENT_SECRET
                        Diode Client Secret. Environment variable can be used by wrapping it in ${} (e.g. ${MY_CLIENT_SECRET})
  -a DIODE_APP_NAME_PREFIX, --diode-app-name-prefix DIODE_APP_NAME_PREFIX
                        Diode producer_app_name prefix
  -d, --dry-run         Run in dry-run mode, do not ingest data
  -o DRY_RUN_OUTPUT_DIR, --dry-run-output-dir DRY_RUN_OUTPUT_DIR
                        Output dir for dry-run mode. Environment variable can be used by wrapping it in ${} (e.g. ${OUTPUT_DIR})
  --otel-endpoint OTEL_ENDPOINT
                        OpenTelemetry exporter endpoint
  --otel-export-period OTEL_EXPORT_PERIOD
                        Period in seconds between OpenTelemetry exports (default: 60)
```

### Policy RFC
```yaml
policies:
  worker_policy:
    config:
      package: my_custom_package
      schedule: "* * * * *" #Cron expression
      custom_config: custom value
    scope:
      any_key: any_value
```
## Run worker
worker can be run by installing it with pip
```sh
git clone https://github.com/netboxlabs/orb-discovery.git
cd orb-discovery/
pip install --no-cache-dir ./worker/
orb-worker -t 'grpc://192.168.0.10:8080/diode' -c '${DIODE_CLIENT_ID}' -k '${DIODE_CLIENT_SECRET}'
```

## Docker Image
worker can be build and run using docker:
```sh
cd worker
docker build --no-cache -t worker:develop -f docker/Dockerfile .
docker run  -e DIODE_CLIENT_ID=${YOUR_CLIENT} -e DIODE_CLIENT_SECRET=${YOUR_SECRET} -p 8071:8071 worker:develop \
 orb-worker -t 'grpc://192.168.0.10:8080/diode' -c '${DIODE_CLIENT_ID}' -k '${DIODE_CLIENT_SECRET}'
```

### Routes (v1)

#### Get runtime and capabilities information

<details>
 <summary><code>GET</code> <code><b>/api/v1/status</b></code> <code>(gets worker runtime data)</code></summary>

##### Parameters

> None

##### Responses

> | http code     | content-type                      | response                                                            |
> |---------------|-----------------------------------|---------------------------------------------------------------------|
> | `200`         | `application/json; charset=utf-8` |  `{"version": "0.1.0","up_time_seconds": 3678 }`                    |

##### Example cURL

> ```sh
>  curl -X GET -H "Content-Type: application/json" http://localhost:8071/api/v1/status
> ```

</details>

<details>
 <summary><code>GET</code> <code><b>/api/v1/capabilities</b></code> <code>(gets worker capabilities)</code></summary>

##### Parameters

> None

##### Responses

> | http code     | content-type                      | response                                                            |
> |---------------|-----------------------------------|---------------------------------------------------------------------|
> | `200`         | `application/json; charset=utf-8` | `{"loaded_modules":["custom_nbl","generic_worker"]}`      |

##### Example cURL

> ```sh
>  curl -X GET -H "Content-Type: application/json" http://localhost:8071/api/v1/capabilities
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
>  curl -X POST -H "Content-Type: application/x-yaml" --data-binary @policy.yaml http://localhost:8071/api/v1/policies
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
>  curl -X DELETE http://localhost:8071/api/v1/policies/policy_name
> ```

</details>
