# Deploy and Operate

To set up NetBox Discovery for the first time, including Diode credentials, start with [Getting started](https://netboxlabs.com/docs/discovery/getting-started/). To change what the agent discovers, see [Configuration](../configs/README.md).

- **[Install and Run the Agent](install.md)**
  Pull the image, create `agent.yaml` and `.env`, test in the foreground, and run the agent as a service that survives reboots. Also covers day-to-day commands and upgrades.
- **[Running as a Non-Root User](non_root_user.md)**
  Run the agent as a user other than root, if your security policy requires it. Lists the features that still need root.
- **[Outbound Proxy Support](outbound_proxy.md)**
  Send the agent's traffic to Diode through a corporate forward proxy, including proxies that intercept TLS.
