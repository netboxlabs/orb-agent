# Discovery Agent

The Orb agent is the part of NetBox Discovery that runs inside your network. It finds devices, interfaces, IP addresses and other network data, and sends what it finds to Diode, which writes it into NetBox. It can also collect telemetry from your network and export it to your monitoring tools.

The agent is developed by NetBox Labs and runs as a Docker or Podman container.

## How it works

1. **You run the agent on a host in your network.**
   The host needs to reach the devices you want to discover, and your Diode endpoint.
2. **`agent.yaml` tells it which backends to run.**
   Each backend does one kind of work, such as scanning subnets or connecting to devices over SNMP.
3. **Policies tell each backend what to discover, and when.**
   A policy names its targets, such as subnets or devices, and a schedule.
4. **Backends send their results on.**
   Discovery backends send data to Diode, which writes it into NetBox. Telemetry backends export metrics over OpenTelemetry (OTLP) to your monitoring stack.

## What the agent can do

### Discovery

| Backend | What it does |
|:--|:--|
| [Network discovery](backends/network_discovery.md) | Scans subnets and IP ranges with nmap to find active IP addresses. |
| [Device discovery](backends/device_discovery/README.md) | Connects to network devices over SSH, NETCONF or vendor APIs, using NAPALM drivers, and collects devices, interfaces, IP addresses, VLANs and more. See the [supported platforms](backends/device_discovery/supported_platforms.md). |
| [SNMP discovery](backends/snmp_discovery/README.md) | Queries devices over SNMP for the same kinds of data. See the [supported platforms](backends/snmp_discovery/supported_platforms.md). |
| [gNMI discovery](backends/gnmi_discovery.md) | Subscribes to devices over gNMI and keeps NetBox up to date as they change. |
| [Worker](backends/worker.md) | Runs your own Python discovery code. |

### Telemetry

| Backend | What it does |
|:--|:--|
| [SNMP telemetry](backends/snmp_telemetry.md) | Polls devices over SNMP and receives their traps, and exports the metrics. |
| [gNMI telemetry](backends/gnmi_telemetry.md) | Streams metrics from devices over gNMI, and exports them. |
| [pktvisor](backends/pktvisor/README.md) | Analyzes network traffic and runs active probes. |
| [OpenTelemetry Infinity](backends/opentelemetry_infinity.md) | Runs OpenTelemetry collectors that forward metrics from the other backends to your monitoring stack. |

## Get started

To set up NetBox Discovery for the first time, follow these steps:

1. **Set up Diode and get credentials.**
   See [Getting started](https://netboxlabs.com/docs/discovery/getting-started/). The steps depend on whether you use NetBox Cloud, NetBox Enterprise or NetBox Community.
2. **Install and run the agent.**
   See [Install and Run the Agent](advanced_config/install.md).
3. **Write policies for what you want to discover.**
   See [Policies](configs/policies.md) and the page for each backend you use.

## In this section

- **[Deploy and Operate](advanced_config/README.md)**
  Install the agent, run it as a service, upgrade it, and adapt it to your environment, including non-root users and outbound proxies.
- **[Configure](configs/README.md)**
  How `agent.yaml` works, how to write policies, where policies come from, and how to use environment variables.
- **[Secrets managers](secretsmgr/README.md)**
  Fetch credentials from HashiCorp Vault, Doppler, CyberArk or Delinea, instead of keeping them in the configuration.
- **[Configuration Samples](config_samples.md)**
  Complete example configurations, with the commands to run them.

## Project status

The Orb agent is in Public Preview. For details, see [NetBox Labs Product and Feature Lifecycle](https://docs.netboxlabs.com/product_feature_lifecycle/). We welcome feedback on bugs, features and improvements in [GitHub Issues](https://github.com/netboxlabs/orb-agent/issues).

## Required notice

Copyright NetBox Labs, Inc.
