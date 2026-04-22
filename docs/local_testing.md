# Local Testing Guide

This guide covers running orb-agent with local code changes.

---

## Prerequisites

- Docker (or Podman)
- Go 1.25+

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

