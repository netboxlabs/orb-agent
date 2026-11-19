# Deploy and Operate

The Orb agent runs as a Docker or Podman container on a host inside your network. Once started, it stays running and carries out each policy on its schedule. It sends what it discovers to Diode, which writes the data into NetBox.

Choose a host that can reach both sides:

- **The devices and networks you want to discover**
  The agent connects to them directly, for example over SSH, SNMP or a network scan. A Linux host works best, because discovery needs host networking, which Docker and Podman support fully only on Linux.
- **Your Diode endpoint**
  On NetBox Cloud and NetBox Enterprise, Diode is part of your NetBox instance. On NetBox Community, it's a Diode server that you run yourself. If outbound traffic must go through a proxy, see [Outbound Proxy Support](outbound_proxy.md).

One agent can run many policies. For large networks, or sites that can't reach each other, deploy an agent in each location.

To set up NetBox Discovery for the first time, including Diode credentials, start with [Getting started](https://netboxlabs.com/docs/discovery/getting-started/). To change what the agent discovers, see [Configuration](../configs/README.md).

- **[Install and Run the Agent](install.md)**
  Pull the image, create `agent.yaml` and `.env`, test in the foreground, and run the agent as a service that survives reboots. Also covers day-to-day commands and upgrades.
- **[Running as a Non-Root User](non_root_user.md)**
  Run the agent as a user other than root, if your security policy requires it. Lists the features that still need root.
- **[Outbound Proxy Support](outbound_proxy.md)**
  Send the agent's traffic to Diode through a corporate forward proxy, including proxies that intercept TLS.
