# orb-agent
Orb network observability agent, part of the NetBox ecosystem and developed by NetBox Labs

## Project status

The Orb agent project is currently in the Public Preview stage. For details, please see [NetBox Labs Product and Feature Lifecycle](https://docs.netboxlabs.com/product_feature_lifecycle/). We actively welcome feedback to help us identify and prioritize bugs, features, and improvements.

## Getting Started
To run `orb-agent`, first pull the Docker image from [Docker Hub](https://hub.docker.com/r/netboxlabs/orb-agent) and

TBD

```sh
docker pull netboxlabs/orb-agent:latest
```

## Orb Agent Configuration
The Orb agent's configuration consists of three main sections: `Config Manager`, `Backends`, and `Policies`.


### Config Manager
The configuration manager is responsible for retrieving policies and passing them to each backend.

```yaml
orb:
  config_manager:
    active: local
  ...
```

Currently, only the `local` manager is supported, which retrieves policies from the same configuration file passed to the agent.

### Backends
Each Orb agent backend has its own capabilities and can be used in different ways to monitor the network.

```yaml
orb:
  ...
  backends:
    common:
    network_discovery:
    ...
```

### Commons
The common section defines configuration settings that apply to all backends. Currently, it supports passing [diode](https://github.com/netboxlabs/diode) server configuration across every backend

```yaml
    common:
      diode:
        target: grpc://192.168.0.22:8080/diode
        api_key: ${DIODE_API_KEY}
        agent_name: agent01
```

#### Supported backends
Currently, the Orb agent supports the following backends:
- [Device Discovery](./docs/backends/device_discovery.md) 
- [Network Discovery](./docs/backends/network_discovery.md) 

### Policies
Policies define how backends should collect and process information. Each backend can handle multiple policies simultaneously. These policies must be defined under the orb `policies` section, with specific backend configurations, since each backend handles policies in its own unique way:

 ```yaml
orb:
  ...
  policies:
    device_discovery:
      policy_1:
        # see device_discovery section
    network_discovery:
      discovery_1:
       # see network_discovery section
 ```

 ## Configuration samples
 [Here](./docs/config_samples.md) you can find a sample collections on how you can configure orb agent to collect network information.

## Required Notice

Copyright NetBox Labs, Inc.