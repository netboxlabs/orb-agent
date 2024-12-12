# network-discovery
Orb network discovery backend

### Usage
```sh
Usage of network-discovery:
  -diode-api-key string
    	diode api key (REQUIRED). Environment variables can be used by wrapping them in ${} (e.g. ${MY_API_KEY})
  -diode-target string
    	diode target (REQUIRED)
  -help
    	show this help
  -host string
    	server host (default "0.0.0.0")
  -log-format string
    	log format (default "TEXT")
  -log-level string
    	log level (default "INFO")
  -port int
    	server port (default 8073)
```

### Policy RFC
```yaml
policies:
  network_1:
    config:
      schedule: "* * * * *" #Cron expression
      timeout: 5 #default 2 minutes
    scope:
      targets: [192.168.1.0/24]
  discover_once: # will run only once
    scope:
       targets: 
        - 192.168.0.34/24
        - google.com
```
## Run device-discovery
device-discovery can be run by installing it with pip
```sh
git clone https://github.com/netboxlabs/orb-discovery.git
cd network-discovery/
make bin
build/network-discovery --diode-target grpc://192.168.31.114:8080/diode  --diode-api-key '${DIODE_API_KEY}'
```

## Docker Image
device-discovery can be build and run using docker:
```sh
cd network-discovery/
docker build --no-cache -t network-discovery:develop -f docker/Dockerfile .
docker run --net=host -e DIODE_API_KEY={YOUR_API_KEY} \
 network-discovery:develop network-discovery \
 --diode-target grpc://192.168.31.114:8080/diode \
 --diode-api-key '${DIODE_API_KEY}'
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
