# Local Testing Guide

This guide covers running orb-agent with local code changes in two modes:
1. **Standalone (local config)** — open source mode, no fleet required
2. **Fleet-connected** — against a local orb-pro dev fleet (Kind + Tilt)

---

## Prerequisites

- Docker (or Podman)
- Go 1.25+
- For fleet mode: a running orb-pro local dev environment (`make dev` in the orb-pro repo)

---

## Building the Local Image

From the `orb-agent` repo root:

```bash
# Fast build (uses Docker cache), tags as netboxlabs/orb-agent:develop
make agent_fast

# Full rebuild (no cache)
make agent

# Or build just the binary (no Docker)
make agent_bin
# Binary output: build/orb-agent
```

The `agent_fast` target tags the image as `netboxlabs/orb-agent:develop`, which is what the orb-pro test infrastructure expects.

---

## Mode 1: Standalone (Local Config)

No fleet required. The agent runs with `config_manager.active: local` and policies defined inline.

### Example: Dry Run (no external dependencies)

Create a config file (e.g., `test-config.yaml`):

```yaml
orb:
  config_manager:
    active: local
  backends:
    network_discovery:
    common:
      diode:
        dry_run: true
        dry_run_output_dir: /opt/orb/
        agent_name: local-test
  policies:
    network_discovery:
      test_scan:
        scope:
          targets: [192.168.1.1]
          scan_types: [connect]
          skip_host: true
          ports: [22, 80, 443]
```

Run:

```bash
docker run --net=host \
  -v $(pwd):/opt/orb/ \
  netboxlabs/orb-agent:develop run -c /opt/orb/test-config.yaml
```

### Example: With Diode Target

```yaml
orb:
  config_manager:
    active: local
  backends:
    device_discovery:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
  policies:
    device_discovery:
      discovery_1:
        config:
          schedule: "* * * * *"
        scope:
          - driver: ios
            hostname: 192.168.0.5
            username: admin
            password: ${PASS}
```

Run:

```bash
docker run --net=host \
  -v $(pwd):/opt/orb/ \
  -e DIODE_CLIENT_ID=your-id \
  -e DIODE_CLIENT_SECRET=your-secret \
  -e PASS=device-password \
  netboxlabs/orb-agent:develop run -c /opt/orb/agent.yaml
```

### Running as a Binary (no Docker)

```bash
make agent_bin
./build/orb-agent run -c test-config.yaml
```

See [config_samples.md](config_samples.md) for more standalone configuration examples.

---

## Mode 2: Fleet-Connected (Against Local orb-pro)

The agent connects to the orb-pro fleet via MQTT (RabbitMQ) and receives policies dynamically.

### Prerequisites

1. orb-pro local dev environment running: `cd /path/to/orb-pro && make dev`
2. Tilt UI accessible at http://localhost:10350 (verify services are green)

### Local Fleet Port Map (Tilt port-forwards)

| Service           | Localhost Port | Purpose                          |
|-------------------|---------------|----------------------------------|
| Auth (token)      | 9123          | OAuth2 token endpoint            |
| Auth (admin)      | 9124          | Admin client management          |
| Fleet gRPC        | 8204          | Agent registration & management  |
| Sink gRPC         | 8205          | Data sink                        |
| Discovery gRPC    | 8206          | Discovery service                |
| Secrets gRPC      | 8207          | Secrets management               |
| RabbitMQ MQTT     | 1883          | Agent MQTT broker                |
| RabbitMQ AMQP     | 5672          | AMQP management                  |
| RabbitMQ UI       | 15672         | RabbitMQ management console      |
| OTEL Collector    | 4317          | OpenTelemetry gRPC               |
| PostgreSQL        | 5433          | Database (mapped from 5432)      |
| Grafana           | 3000          | Dashboards                       |
| Prometheus        | 9090          | Metrics                          |

### Step 1: Get Admin Credentials

The orb-pro dev environment provisions OAuth2 clients automatically. Credentials are stored at:

```
orb-pro/docker/oauth2/client/client-credentials.json
```

The admin client (`orb-admin-fleet`) is used to create agents via the Fleet API.

### Step 2: Create an Agent via gRPC

Using the orb-pro test helpers or a gRPC client, create an agent. The response returns the agent's `client_id` and `client_secret` needed for the agent config.

You can use the orb-pro Python test framework:

```python
from helpers.test_api_helper import FleetApi, AuthApi, AUTH_TOKEN_URL

auth = AuthApi(AUTH_TOKEN_URL)
token = auth.get_token()  # Uses admin credentials

fleet = FleetApi()
agent = fleet.create_agent(token, {
    "name": "dev-test-agent",
    "orbLabels": {"environment": "dev"}
})

print(f"client_id: {agent['client_id']}")
print(f"client_secret: {agent['client_secret']}")
```

### Step 3: Write the Fleet Agent Config

Create `fleet-config.yaml`:

```yaml
version: 1.0
orb:
  labels:
    environment: dev
    test: local-build
  config_manager:
    active: fleet
    sources:
      fleet:
        token_url: "http://host.docker.internal:9123/token"  # macOS
        # token_url: "http://localhost:9123/token"            # Linux
        client_id: "<FROM_STEP_2>"
        client_secret: "<FROM_STEP_2>"
        otlp_bridge_grpc_port: 4317
  secrets_manager:
    active: fleet
  backends:
    network_discovery:
      port: 5001
    device_discovery:
      port: 5002
    common:
      diode:
        agent_name: "orb-agent-fleet"
```

### Step 4: Run the Agent

```bash
docker run \
  -v $(pwd):/opt/orb/ \
  netboxlabs/orb-agent:develop run -d -c /opt/orb/fleet-config.yaml
```

> **macOS note**: Do NOT use `--net=host` — it doesn't work with Docker Desktop.
> The agent reaches the host via `host.docker.internal` (configured in token_url above).
>
> **Linux note**: Use `--net=host` and set token_url to `http://localhost:9123/token`.

### Step 5: Verify

- Check agent appears in fleet: use the Fleet gRPC API at `localhost:8204`
- Check MQTT connection: RabbitMQ management UI at http://localhost:15672
- Check agent logs: `docker logs -f <container-id>`
- Check Tilt dashboard: http://localhost:10350

---

## Docker Networking Reference

| Platform | Host Access from Container         | Network Flag |
|----------|------------------------------------|--------------|
| macOS    | `host.docker.internal`             | (none)       |
| Linux    | `localhost` / `127.0.0.1`          | `--net=host` |

---

## Quick Reference: Common Workflows

### Rebuild and restart after code changes

```bash
# Rebuild image with latest code
make agent_fast

# Stop old container and start new one
docker rm -f orb-agent-dev 2>/dev/null
docker run --name orb-agent-dev \
  -v $(pwd):/opt/orb/ \
  netboxlabs/orb-agent:develop run -c /opt/orb/fleet-config.yaml
```

### Run tests against the local image

From the orb-pro repo, after building the local image:

```bash
cd /path/to/orb-pro
# The tests automatically use netboxlabs/orb-agent:develop
pytest tests/agents/ -v
```

### Check version of running image

```bash
docker run --rm netboxlabs/orb-agent:develop version
```
