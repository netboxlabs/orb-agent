# Outbound Proxy Support

The Orb agent sends the data it discovers to NetBox through [Diode](https://github.com/netboxlabs/diode), the NetBox Labs ingestion service. 

If your network sends outbound traffic through a corporate forward proxy, the agent can reach Diode through it. For example, you might run the agent on-premises and send data to a cloud-hosted Diode.

You configure the proxy with the standard proxy environment variables. There are no proxy settings in `agent.yaml`, and the Diode `target` in the file stays the same.

## Set the proxy variables

Set these variables in the agent's container environment:

| Variable | Value |
|:--|:--|
| `HTTP_PROXY` | Your proxy URL, for example `http://proxy.example.com:8080` |
| `HTTPS_PROXY` | The same proxy URL |
| `NO_PROXY` | Comma-separated hosts, domains and IP ranges the agent should reach directly |

Set **both** `HTTP_PROXY` and `HTTPS_PROXY` to the same URL. Different backends choose between them in different ways, and setting both covers every backend and Diode target. See [How the agent chooses a proxy](#how-the-agent-chooses-a-proxy) for more information.

Lower-case names, such as `https_proxy`, also work.

:::note
Add your network devices and internal ranges to `NO_PROXY`. A forward proxy is usually meant only for traffic leaving your network. Discovery traffic to devices, SNMP hosts and other internal targets should not go through it.
:::

## Example

`agent.yaml` uses `${VAR}` placeholders for the Diode settings, as it would without a proxy:

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

Put the Diode settings and the proxy variables in an environment file, `.env`:

```sh
# Diode endpoint and credentials.
# docker --env-file does not expand ${...}, so use literal values.
DIODE_URL=grpcs://diode.example.com/diode
DIODE_CLIENT_ID=your-diode-client-id
DIODE_CLIENT_SECRET=your-diode-client-secret

# Send outbound Diode traffic through the proxy.
HTTP_PROXY=http://proxy.example.com:8080
HTTPS_PROXY=http://proxy.example.com:8080

# Reach internal discovery targets directly.
NO_PROXY=internal-target.example.com,10.0.0.0/8
```

Start the agent with the environment file:

```sh
docker run --net=host \
  -v ${PWD}:/opt/orb/ \
  --env-file ${PWD}/.env \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

You can also pass each variable with `-e` instead of using `--env-file`.

## TLS-intercepting proxies

Some proxies decrypt and re-sign TLS traffic. If yours does, the agent must trust the proxy's CA certificate, or the connection to Diode fails certificate verification.

1. Save the proxy's CA certificate as `proxy-ca.pem` in the directory you mount at `/opt/orb`.
2. Add this line to your `.env` file:

   ```sh
   DIODE_CERT_FILE=/opt/orb/proxy-ca.pem
   ```

Both Diode SDKs read the certificate from `DIODE_CERT_FILE`. For other TLS options, see the [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) and the [Diode Python SDK environment variables](https://github.com/netboxlabs/diode-sdk-python?tab=readme-ov-file#environment-variables).

:::note

`DIODE_SKIP_TLS_VERIFY` turns off certificate verification entirely. Use it only for quick tests, never in production.

:::

## Check the connection

1. Start the agent with debug logging by adding `-d` after `run`.
2. In the proxy's access logs, check for a connection to your Diode endpoint.
3. Check that discovered data arrives in NetBox.

Proxy and TLS errors appear in the agent's logs.

## How the agent chooses a proxy

Each backend sends data to Diode through one of two SDKs. They choose a proxy variable differently, which is why you should set both.

| Backends | SDK | `grpc://` target | `grpcs://` target |
|:--|:--|:--|:--|
| Network discovery, SNMP discovery, gNMI discovery | [Diode Go SDK](https://github.com/netboxlabs/diode-sdk-go) | Data: `HTTPS_PROXY`<br>Sign-in: `HTTP_PROXY` | `HTTPS_PROXY` |
| Device discovery, worker | [Diode Python SDK](https://github.com/netboxlabs/diode-sdk-python) | `HTTP_PROXY` | `HTTPS_PROXY`, or `HTTP_PROXY` if that is not set |

The Go SDK makes two connections: a sign-in request to get an access token, and the data stream. With a `grpc://` target, they use different variables.

Both the sign-in request and the data stream go through the proxy, using standard `CONNECT` tunneling.

## Limitations

- Only the connection to Diode is covered. Other outbound traffic, such as telemetry exports, does not necessarily follow these variables.
- You can set the proxy only with environment variables, not in `agent.yaml`.

If you need to send other traffic through a proxy, [open an issue](https://github.com/netboxlabs/orb-agent/issues) describing your setup.
