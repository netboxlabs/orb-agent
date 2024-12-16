# orb-agent
Orb network observability agent, part of the NetBox ecosystem and developed by NetBox Labs

## Project status

The Orb Agent project is currently in the _Public Preview_ stage. Please
see [NetBox Labs Product and Feature Lifecycle](https://docs.netboxlabs.com/product_feature_lifecycle/) for more
details. We actively welcome feedback to help identify and prioritize bugs, new features and areas of improvement.

## Getting Started
To be able to run `orb-agent` you just need to pull docker from [docker hub](https://hub.docker.com/r/netboxlabs/orb-agent) and

TBD

```sh
docker pull netboxlabs/orb-agent:latest
```

## Orb Agent Configuration
The configuration of orb agent can be divided into three sections: `Config Manager`, `Backends` and `Policies`.


### Config Manager
The configuration manager is responsible for retrieving policies and passing for each backend.

```yaml
orb:
  config_manager:
    active: local
  ...
```

Currently, the only supported manager is the `local`. The policy will be retrieved from the same entry config file passed to the agent.

### Backends
Each orb agent backend has its own capabilities and can be used in diferent ways to observe the network. 

```yaml
orb:
  ...
  backends:
    common:
    network_discovery:
    ...
```

### Commons
The common section is used to define configuration that will be passed to all backends. Currently, supports passing [diode](https://github.com/netboxlabs/diode) server configuration to every backend

```yaml
    common:
      diode:
        target: grpc://192.168.0.22:8080/diode
        api_key: ${DIODE_API_KEY}
        agent_name: agent01
```

#### Supported backends
At the moment, orb agent support the following backends:
- [Device Discovery](./docs/backends/device_discovery.md) 
- [Network Discovery](./docs/backends/network_discovery.md) 

### Policies
 Policies is the way that backends understand how they should act and collect information. Each backend support multiple policies at same time.
 They should be defined under orb `policies` and the backend for each should be specified as each backend has its own internal way to define and handle policies:

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