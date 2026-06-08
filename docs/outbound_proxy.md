# Outbound Proxy Support

Some environments require all outbound traffic to leave the network through a corporate forward proxy. Orb Agent's outbound connection to your [Diode](https://github.com/netboxlabs/diode) target (used to send discovered data to NetBox) honors the standard proxy environment variables, so no extra configuration flags are required.

This applies to deployments where the agent runs on-premises and must reach a remote (for example, cloud-hosted) Diode endpoint through a proxy.

## How it works

Orb Agent sends data to Diode through one of two clients, depending on the backend:

- the [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) — used by the **network discovery** and **SNMP discovery** backends
- the [Diode Python SDK](https://github.com/netboxlabs/diode-sdk-python) — used by the **device discovery** and **worker** backends

Both clients respect the conventional proxy environment variables used by Go and Python:

| Variable | Purpose |
|----------|---------|
| `HTTPS_PROXY` | Proxy URL for the outbound Diode connection. Set this for any remote Diode target — see the note below, it applies even when the target is plain `grpc://`. |
| `HTTP_PROXY` | Proxy URL for plain HTTP calls. Generally not needed for Diode egress; prefer `HTTPS_PROXY`. |
| `NO_PROXY` | Comma-separated list of hosts, domains, or IPs that must bypass the proxy and be reached directly. |

Both lowercase (`https_proxy`, `no_proxy`) and uppercase forms are recognized.

> **Use `HTTPS_PROXY` for the Diode connection, even with a `grpc://` target.** The network and SNMP discovery backends use the Go SDK, and `grpc-go` selects its proxy from `HTTPS_PROXY` (and `NO_PROXY`) regardless of whether the Diode target is `grpcs://` or plain `grpc://`. Setting only `HTTP_PROXY` will not route the gRPC data stream for those backends. When in doubt, set `HTTPS_PROXY`.

When a proxy variable is set, the agent routes the Diode connection — both the initial authentication request and the data stream — through the proxy using the standard `CONNECT` tunneling method. The `target` in your `agent.yaml` stays unchanged; the proxy is selected purely from the environment.

> **Keep internal discovery traffic direct.** A forward proxy is typically only appropriate for the outbound Diode/egress connection. Traffic from discovery backends to internal targets (network devices, SNMP hosts, etc.) usually must *not* go through the proxy. Add those internal hosts and ranges to `NO_PROXY` so they are reached directly.

## Configuration

Set the proxy variables in the agent's container environment. The `target` and credentials in `agent.yaml` are unchanged.

### Example `agent.yaml`

```yaml
orb:
  config_manager:
    active: local
  backends:
    network_discovery:
    common:
      diode:
        target: ${DIODE_URL}
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
```

### Example environment file

```sh
# Diode endpoint and credentials.
# docker --env-file does not expand ${...}, so use concrete values here.
DIODE_URL=grpcs://diode.example.com/diode
DIODE_CLIENT_ID=your-diode-client-id
DIODE_CLIENT_SECRET=your-diode-client-secret

# Route outbound Diode traffic through the corporate proxy
HTTPS_PROXY=http://proxy.example.com:8080

# Reach internal discovery targets directly (bypass the proxy)
NO_PROXY=internal-target.example.com,10.0.0.0/8
```

### Running the agent

```sh
docker run --net=host \
  -v ${PWD}:/opt/orb/ \
  --env-file ${PWD}/.env \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

Or pass the variables individually (the Diode credentials must be supplied alongside the proxy variables):

```sh
docker run --net=host \
  -v ${PWD}:/opt/orb/ \
  -e DIODE_URL=grpcs://diode.example.com/diode \
  -e DIODE_CLIENT_ID=your-diode-client-id \
  -e DIODE_CLIENT_SECRET=your-diode-client-secret \
  -e HTTPS_PROXY=http://proxy.example.com:8080 \
  -e NO_PROXY=internal-target.example.com,10.0.0.0/8 \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

## TLS-intercepting proxies

If the proxy terminates and re-signs TLS (TLS interception / "MITM"), the agent must trust the proxy's CA certificate, or the Diode connection will fail certificate verification. Provide the proxy CA certificate to the Diode client:

```sh
# Mount the proxy CA bundle into the container and point the Diode client at it
-e DIODE_CERT_FILE=/opt/orb/proxy-ca.pem
```

Exact variable names can differ between the two clients, so see the SDK references for the full list of TLS-related options — the [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) and the [Diode Python SDK environment variables reference](https://github.com/netboxlabs/diode-sdk-python?tab=readme-ov-file#environment-variables). Disabling certificate verification entirely is possible for quick testing but is not recommended for production.

## Verifying

After setting the proxy variables, start the agent and confirm in the proxy's access logs that the outbound connection to the Diode endpoint is observed, and that discovered data reaches NetBox. Running the agent with debug logging (`-d`) helps confirm the connection is established. Any proxy or TLS errors will surface in the agent logs.

## Notes and limitations

- Proxy selection is currently driven entirely by environment variables. A first-class, `agent.yaml`-based proxy setting is planned as a future enhancement.
- Only the outbound Diode connection is covered here. If you need to proxy other agent egress paths, please open an issue describing the use case.
