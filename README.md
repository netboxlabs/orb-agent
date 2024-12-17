# Orb Agent - the NetBox Discovery agent
Orb agent is a component of the NetBox Discovery solution. It provides network discovery and observability capabilities and is developed by NetBox Labs.

## Project status

The Orb agent project is currently in the Public Preview stage. For details, please see [NetBox Labs Product and Feature Lifecycle](https://docs.netboxlabs.com/product_feature_lifecycle/). We actively welcome feedback to help us identify and prioritize bugs, features, and improvements.

## Getting Started
To run `orb-agent`, first pull the Docker image from [Docker Hub](https://hub.docker.com/r/netboxlabs/orb-agent):


```sh
docker pull netboxlabs/orb-agent:latest
```

## Orb Agent Configuration
To run, the Orb agent requires a configuration file. This configuration file consists of three main sections: `Config Manager`, `Backends`, and `Policies`.


### Config Manager
The `Config Manager` section specifies how Orb agent should retrieve it's configuration information. The configuration manager is responsible for processing the configuration to retrieve policies and pass them to the appropriate backend.

```yaml
orb:
  config_manager:
    active: local
  ...
```

Currently, only the `local` manager is supported, which retrieves policies from the local configuration file passed to the agent.

### Backends
The `Backends` section specifies what Orb agent backends should be enabled. Each Orb agent backend offers specific discovery or observability capabilities and may require specific configuration information.  

```yaml
orb:
  ...
  backends:
    network_discovery:
    ...
```
Only the `network_discovery` and `device_discovery` backends are currently supported. They do not require any special configuration.
- [Device Discovery](./docs/backends/device_discovery.md) 
- [Network Discovery](./docs/backends/network_discovery.md)
### Commons
A special `common` subsection under `Backends` defines configuration settings that are shared with all backends. Currently, it supports passing [diode](https://github.com/netboxlabs/diode) server settings to all backends.

```yaml
  backends:
      ...
      common:
        diode:
          target: grpc://192.168.0.22:8080/diode
          api_key: ${DIODE_API_KEY}
          agent_name: agent01
```


### Policies
The `Policies` section specifies what discovery policies should be passed to each backend. Policies define specific settings for discovery (such as scheduling and default properties) and the scope (targets). Backends can run multiple policies simultaneously, but for each backend all policies must have a unique name. These policies are defined in the `policies` section and are grouped under a subsection for each backend:

 ```yaml
orb:
  ...
  policies:
    device_discovery:
      device_policy_1:
        # see docs/backends/device_discovery.md
    network_discovery:
      network_policy_1:
       # see docs/backends/network_discovery.md
 ```

 ## Configuration samples
You can find sample configurations [here](./docs/config_samples.md) of how to configure Orb agent to run network and device discoveries.

## Required Notice

Copyright NetBox Labs, Inc.