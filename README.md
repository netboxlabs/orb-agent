# Orb Agent - the NetBox Discovery agent
Orb agent is a component of the NetBox Discovery solution. It provides network discovery and observability capabilities and is developed by NetBox Labs.

## Project status
The Orb agent project is currently in the Public Preview stage. For details, please see [NetBox Labs Product and Feature Lifecycle](https://docs.netboxlabs.com/product_feature_lifecycle/). We actively welcome feedback to help us identify and prioritize bugs, features, and improvements.

## Getting Started
To get started with `orb-agent`, first pull the Docker image from [Docker Hub](https://hub.docker.com/r/netboxlabs/orb-agent):

```sh
docker pull netboxlabs/orb-agent:latest
```

## Orb Agent Configuration
The Orb agent requires a configuration file (`agent.yaml`). For a full reference of all supported keys see the [Agent Configuration File reference](./docs/configs/agent_yaml.md).

This file consists of three main sections: `config_manager`, `backends`, and `policies`.

### Config Manager
The `config_manager` section specifies how Orb agent should retrieve it's configuration information. The configuration manager is responsible for processing the configuration to retrieve policies and pass them to the appropriate backend.

```yaml
orb:
  config_manager:
    active: local
  ...
```

Currently, only the `local` and `git` sources are supported for config manager.
- [Local](./docs/configs/local.md)
- [Git](./docs/configs/git.md)

### Secrets Manager
The `secrets_manager` section specifies how Orb agent should retrieve and inject secrets into policies. The secrets manager can reference external secret stores like HashiCorp Vault, Doppler, CyberArk, or Delinea Secret Server to retrieve sensitive information such as credentials without hardcoding them in configuration files.

```yaml
orb:
  secrets_manager:
    active: vault
    sources:
      vault:
        address: "https://vault.example.com:8200"
        namespace: "my-namespace"
        timeout: 60
        auth: "token"
        auth_args:
          token: "${VAULT_TOKEN}"
        schedule: "*/5 * * * *"
  ...
```

Supported secrets managers:
- [HashiCorp Vault](./docs/secretsmgr/vault.md)
- [Doppler](./docs/secretsmgr/doppler.md)
- [CyberArk (CCP)](./docs/secretsmgr/cyberark.md) (beta)
- [Delinea Secret Server](./docs/secretsmgr/delinea.md) (beta)

The secrets manager to use, and its connection settings, can also be selected and configured entirely via environment variables — independently of the config manager and without editing the YAML file. See [Environment-Driven Configuration](./docs/advanced_config/env_config.md).

### Environment variable configuration
Any `orb.*` configuration value can be set or overridden with `ORB_*` environment variables layered on top of the `--config` file(s), using `__` as the path delimiter (for example `ORB_SECRETS_MANAGER__ACTIVE=vault`). This is most commonly used to select and configure the secrets manager per deployment without editing or templating the YAML, but it applies to any config key. See [Environment-Driven Configuration](./docs/advanced_config/env_config.md) for the full scheme, precedence rules, and worked examples.

### Backends
The `backends` section specifies what Orb agent backends should be enabled. Each Orb agent backend offers specific discovery or observability capabilities and may require specific configuration information.  

```yaml
orb:
  ...
  backends:
    network_discovery:
    ...
```

#### Discovery Backends
Only the `network_discovery`, `device_discovery`, `worker`, `snmp_discovery` and `gnmi_discovery` (beta) backends are currently supported. They do not require any special configuration.
- [Device Discovery](./docs/backends/device_discovery/README.md) ([supported platforms](./docs/backends/device_discovery/supported_platforms.md))
- [Network Discovery](./docs/backends/network_discovery.md)
- [Worker](./docs/backends/worker.md)
- [SNMP Discovery](./docs/backends/snmp_discovery/README.md) ([supported platforms](./docs/backends/snmp_discovery/supported_platforms.md))
- [gNMI Discovery](./docs/backends/gnmi_discovery.md) (beta)

#### Observability Backends
Observability backends focus on collecting and exporting rich telemetry from network traffic or probes so you can feed metrics into your monitoring stack.

- [pktvisor](./docs/backends/pktvisor.md)
- [OpenTelemetry Infinity](./docs/backends/opentelemetry_infinity.md)

#### Common
A special `common` subsection under `backends` defines configuration settings that are shared with all backends. Currently, it supports passing [diode](https://github.com/netboxlabs/diode) server settings and OpenTelemetry configuration to all backends.

```yaml
  backends:
      ...
      common:
        diode:
          target: grpc://192.168.0.22:8080/diode
          client_id: ${DIODE_CLIENT_ID}
          client_secret: ${DIODE_CLIENT_SECRET}
          agent_name: agent01
          dry_run: false
          dry_run_output_dir: /opt/orb
        otlp:
          grpc: "grpc://otel-collector:4317"
          agent_labels:
            environment: "production"
            datacenter: "us-east-1"
            service: "network-monitoring"
```

### Policies
The `policies` section specifies what discovery policies should be passed to each backend. Policies define specific settings for discovery (such as scheduling and default properties) and the scope (targets). Backends can run multiple policies simultaneously, but for each backend all policies must have a unique name. These policies are defined in the `policies` section and are grouped under a subsection for each backend:

 ```yaml
orb:
  ...
  policies:
    device_discovery:
      device_policy_1:
        # see docs/backends/device_discovery/README.md
    network_discovery:
      network_policy_1:
       # see docs/backends/network_discovery.md
    worker:
      worker_policy_1:
       # see docs/backends/worker.md
    snmp_discovery:
      snmp_policy_1:
       # see docs/backends/snmp.md
 ```

## System Requirements

### Quick Reference

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| **CPU** | 2 cores | 4 cores |
| **Memory** | 1.5 GB | 2 GB |
| **Disk Space** | 1 GB | 2 GB |

### Container Runtime

| Runtime | Minimum Version | Recommended Version |
|---------|-----------------|---------------------|
| Docker Engine | 20.10 | 24.0+ |
| Podman | 4.0 | 5.0+ |

### Operating System

| OS | Support | Notes |
|----|---------|-------|
| Linux (x86_64) | ✅ Full | Required for `--net=host` |
| Linux (arm64) | ✅ Full | Tested on ARM64 |
| macOS | ⚠️ Limited | No host networking support |
| Windows | ⚠️ Limited | No host networking support |

## Running the agent

To run `orb-agent`, use the following command from the directory where your created your `agent.yaml` file:

```sh
 docker run --net=host -v ${PWD}:/opt/orb/ netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```
The container needs sufficient permissions, to send `icmp` and `tcp` packets. This can either be achieved by setting the network-mode to `host` or by changing the container user to `root`: 

```sh
 docker run -u root -v ${PWD}:/opt/orb/ netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

Or if using podman
```sh
podman run -d --privileged --net=host \
  -v ${PWD}:/opt/orb/ \
  -e DIODE_CLIENT_ID \
  -e DIODE_CLIENT_SECRET \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

**Note for rootless podman users:** If running podman without root/sudo privileges, network discovery requires specific configuration to avoid raw socket limitations. The command above requires `sudo` for full NMAP functionality. For rootless operation, see the [Network Discovery backend documentation](./docs/backends/network_discovery.md#rootless-podman-deployment) for TCP connect scan configuration.

### Outbound proxy
If the agent must send outbound traffic to your Diode target through a corporate forward proxy, see the [Outbound Proxy Support](./docs/advanced_config/outbound_proxy.md) guide for the supported proxy environment variables and examples.

### Configuration samples
You can find complete sample configurations [here](./docs/config_samples.md) of how to configure Orb agent to run network and device discoveries, as well as the relevant `docker run` commands.

## Required Notice
Copyright NetBox Labs, Inc.
