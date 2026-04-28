# Agent Configuration File (`agent.yaml`)

The agent configuration file is the single file passed to the agent at startup via the `-c` flag. It defines the agent's identity, how policies are loaded, which backends are active, and optional secrets management.

```bash
docker run ... netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

## Top-Level Structure

```yaml
version: 1.0          # Optional
orb:
  labels: ...         # Agent identity labels
  config_manager: ... # How policies are loaded (required)
  backends: ...       # Which backends are enabled (required)
  policies: ...       # Inline policies (only with config_manager.active: local)
  secrets_manager: .. # Optional: Vault secret resolution
```

| Key | Required | Description |
|-----|----------|-------------|
| `version` | No | Config schema version (informational) |
| `orb.labels` | No | Key/value pairs that identify this agent instance. Used by the Git config manager to match `selector.yaml` entries |
| `orb.config_manager` | Yes | Defines where policies come from (`local` or `git`) |
| `orb.backends` | Yes | Declares which discovery backends to run and their common settings |
| `orb.policies` | Only with `local` | Inline policy definitions. Ignored when `config_manager.active` is `git` |
| `orb.secrets_manager` | No | Configures Vault to resolve `${vault://...}` references at runtime |

---

## `orb.labels`

Free-form key/value pairs that identify this agent instance. When using the Git config manager, labels are matched against `selector.yaml` to determine which policies apply to this agent.

```yaml
orb:
  labels:
    region: EU
    pop: ams02
    environment: production
```

---

## `orb.config_manager`

Controls how the agent loads policies. Exactly one source is active at a time.

```yaml
orb:
  config_manager:
    active: local   # or: git
    sources:
      local: ...
      git: ...
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `active` | string | Yes | Which source to use: `local` or `git` |

### `local`

Policies are read directly from `orb.policies` in the same config file. No additional parameters required.

```yaml
orb:
  config_manager:
    active: local
```

### `git`

Policies are fetched from a Git repository. See the full [Git configuration manager documentation](git.md).

```yaml
orb:
  config_manager:
    active: git
    sources:
      git:
        url: "https://github.com/myorg/policyrepo"
        branch: main
        schedule: "*/5 * * * *"
        auth: basic
        username: myuser
        password: ${GIT_TOKEN}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | Git repository URL |
| `branch` | string | No | Branch to use (default: repository default branch) |
| `schedule` | cron | No | How often to poll for changes. If omitted, policies are fetched once at startup |
| `auth` | string | No | `basic` (password or token) or `ssh`. Omit for public repositories |
| `username` | string | No | Username for basic auth |
| `password` | string | No | Password or token for basic auth; passphrase for SSH keys |
| `private_key` | string | No | Path to SSH private key file |
| `skip_tls` | bool | No | Skip TLS certificate verification (default: `false`) |

---

## `orb.backends`

Declares which backends are enabled. Each key activates a backend. The `common` sub-key holds settings shared across all backends.

```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    device_discovery:   # enabled, using defaults
    snmp_discovery:     # enabled, using defaults
```

### `common.diode`

Shared Diode connection settings used by all discovery backends.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | Yes* | Diode server gRPC endpoint, e.g. `grpc://host:8080/diode` |
| `client_id` | string | Yes* | Diode client ID |
| `client_secret` | string | Yes* | Diode client secret |
| `agent_name` | string | No | Label attached to all ingested data |
| `dry_run` | bool | No | When `true`, writes output to files instead of sending to Diode (default: `false`) |
| `dry_run_output_dir` | string | No | Directory for dry-run output files (default: current directory) |

\* Not required when `dry_run: true`.

### `common.otlp`

Optional OpenTelemetry export for backend metrics.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grpc` | string | No | gRPC endpoint for OTLP export, e.g. `grpc://collector:4317` |
| `http` | string | No | HTTP endpoint for OTLP export |
| `agent_labels` | map | No | Extra key/value labels attached to all exported telemetry |

### Backend keys

Each backend key enables that backend. An empty value (no sub-keys) uses all defaults. All discovery backends accept optional `host` and `port` overrides.

| Key | Backend | Default port | Notes |
|-----|---------|-------------|-------|
| `device_discovery` | NAPALM-based device discovery | 8072 | Optional `host`/`port` overrides |
| `snmp_discovery` | SNMP-based discovery | 8070 | Optional `host`/`port` overrides |
| `network_discovery` | Network/port scan discovery | 8073 | Optional `host`/`port` overrides |
| `worker` | Custom worker backend | 8071 | Optional `host`/`port` overrides |
| `pktvisor` | pktvisor packet analytics | — | See [pktvisor docs](../backends/pktvisor.md) |
| `opentelemetry_infinity` | OpenTelemetry Infinity | — | See [OTel Infinity docs](../backends/opentelemetry_infinity.md) |

---

## `orb.policies`

Defines policies inline. Only used when `config_manager.active: local`. Each top-level key matches a backend name; beneath it, each named entry is an independent policy.

```yaml
orb:
  policies:
    device_discovery:
      my_policy:
        config:
          schedule: "0 * * * *"
          defaults:
            site: New York NY
        scope:
          - hostname: 192.168.0.5
            username: admin
            password: ${PASS}
            driver: ios
    network_discovery:
      scan_policy:
        config:
          schedule: "0 */2 * * *"
        scope:
          targets: [192.168.1.0/24]
```

For the full list of parameters per backend, see:
- [Device Discovery](../backends/device_discovery/README.md)
- [SNMP Discovery](../backends/snmp_discovery/README.md)
- [Network Discovery](../backends/network_discovery.md)
- [Worker](../backends/worker.md)

---

## `orb.secrets_manager`

Configures HashiCorp Vault as an external secrets source. When active, `${vault://...}` references in policy and config values are resolved at runtime.

The placeholder format is `${vault://mount/path/to/secret/fieldname}`, where:
- `mount` is the KV v2 engine mount name
- `path/to/secret` is the path within that mount
- `fieldname` is the key within the secret (last path segment)

```yaml
# Example: read the "password" key from secret at kv/myapp/db
password: ${vault://kv/myapp/db/password}
```

```yaml
orb:
  secrets_manager:
    active: vault
    sources:
      vault:
        address: "https://vault.example.com:8200"
        auth: token
        auth_args:
          token: ${VAULT_TOKEN}
        schedule: "*/5 * * * *"
```

See the full [Vault secrets manager documentation](../secretsmgr/vault.md) for all parameters and authentication methods.

Plain `${VAR_NAME}` references are **not** resolved by the secrets manager — those are handled by environment variable substitution as described below.

---

## Environment Variable Substitution

Values can reference environment variables using `${VAR_NAME}` syntax. Resolution is handled at different layers depending on the field:

| Scope | Supported fields | Resolved by |
|-------|-----------------|-------------|
| Git config manager | `url`, `password` | Go agent at startup |
| Vault secrets manager `auth_args` | All fields | Go agent at startup |
| `device_discovery` policy (all fields) | Any string value in `scope` and `defaults` | Python backend at policy execution |
| `snmp_discovery` policy authentication | `community`, `username`, `auth_passphrase`, `priv_passphrase` | Go SNMP backend at policy execution |

```yaml
# Git config (resolved by Go agent)
password: ${GIT_TOKEN}

# device_discovery policy scope (resolved by Python backend)
scope:
  - hostname: 192.168.0.5
    username: admin
    password: ${DEVICE_PASS}
```

For fields not listed above (e.g. `network_discovery` scope), use the Vault secrets manager to inject values at runtime.
