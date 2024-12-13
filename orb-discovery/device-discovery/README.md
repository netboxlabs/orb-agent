# device-discovery
Orb device discovery backend

### Usage
```bash
usage: device-discovery [-h] [-V] [-s HOST] [-p PORT] -t DIODE_TARGET -k DIODE_API_KEY

Orb Discovery Backend

options:
  -h, --help            show this help message and exit
  -V, --version         Display Discovery, NAPALM and Diode SDK versions
  -s HOST, --host HOST  Server host
  -p PORT, --port PORT  Server port
  -t DIODE_TARGET, --diode-target DIODE_TARGET
                        Diode target
  -k DIODE_API_KEY, --diode-api-key DIODE_API_KEY
                        Diode API key. Environment variables can be used by wrapping them in ${} (e.g.
                        ${MY_API_KEY})
  -a DIODE_APP_NAME_PREFIX, --diode-app-name-prefix DIODE_APP_NAME_PREFIX
                        Diode producer_app_name prefix
```

### Policy RFC
```yaml
policies:
  discovery_1:
    config:
      schedule: "* * * * *" #Cron expression
      defaults:
        site: New York NY
    scope:
      - hostname: 192.168.0.32
        username: ${USER}
        password: admin
      - driver: eos
        hostname: 127.0.0.1
        username: admin
        password: ${ARISTA_PASSWORD}
        optional_args:
          enable_password: ${ARISTA_PASSWORD}
  discover_once: # will run only once
    scope:
      - hostname: 192.168.0.34
        username: ${USER}
        password: ${PASSWORD}
```
## Run device-discovery
device-discovery can be run by installing it with pip
```sh
git clone https://github.com/netboxlabs/orb-discovery.git
cd orb-discovery/
pip install --no-cache-dir ./device-discovery/
device-discovery -t 'grpc://192.168.0.10:8080/diode' -k '${DIODE_API_KEY}'
```

## Docker Image
device-discovery can be build and run using docker:
```sh
cd device-discovery
docker build --no-cache -t device-discovery:develop -f docker/Dockerfile .
docker run  -e DIODE_API_KEY={YOUR_API_KEY} -p 8072:8072 device-discovery:develop \
 device-discovery -t 'grpc://192.168.0.10:8080/diode' -k '${DIODE_API_KEY}'
```

### Routes (v1)

#### Get runtime and capabilities information

<details>
 <summary><code>GET</code> <code><b>/api/v1/status</b></code> <code>(gets discovery runtime data)</code></summary>

##### Parameters

> None

##### Responses

> | http code     | content-type                      | response                                                            |
> |---------------|-----------------------------------|---------------------------------------------------------------------|
> | `200`         | `application/json; charset=utf-8` |  `{"version": "0.1.0","up_time_seconds": 3678 }`                    |

##### Example cURL

> ```sh
>  curl -X GET -H "Content-Type: application/json" http://localhost:8072/api/v1/status
> ```

</details>

<details>
 <summary><code>GET</code> <code><b>/api/v1/capabilities</b></code> <code>(gets device-discovery capabilities)</code></summary>

##### Parameters

> None

##### Responses

> | http code     | content-type                      | response                                                            |
> |---------------|-----------------------------------|---------------------------------------------------------------------|
> | `200`         | `application/json; charset=utf-8` | `{"supported_drivers":["ios","eos","junos","nxos","cumulus"]}`      |

##### Example cURL

> ```sh
>  curl -X GET -H "Content-Type: application/json" http://localhost:8072/api/v1/capabilities
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
>  curl -X POST -H "Content-Type: application/x-yaml" --data-binary @policy.yaml http://localhost:8072/api/v1/policies
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
>  curl -X DELETE http://localhost:8072/api/v1/policies/policy_name
> ```

</details>
