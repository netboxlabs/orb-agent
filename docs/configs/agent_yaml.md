# Agent Configuration File (`agent.yaml`)

The Orb agent reads its configuration from a YAML file that you pass with `-c` when you start it:

```sh
docker run ... netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

The file tells the agent which backends to run, where to get its policies, and how to reach Diode, the service that delivers discovered data to NetBox. This page lists every key the file supports.

## Minimal file example

This file runs network discovery on one subnet every two hours and sends the results to Diode:

```yaml
orb:
  config_manager:
    active: local
  backends:
    common:
      diode:
        target: grpc://diode.example.com:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    network_discovery:
  policies:
    network_discovery:
      office_scan:
        config:
          schedule: "0 */2 * * *"
        scope:
          targets: [192.168.1.0/24]
```

`${DIODE_CLIENT_ID}` and `${DIODE_CLIENT_SECRET}` are read from the environment when the agent starts. See [Environment variables in the file](#environment-variables-in-the-file).

## Top-level keys

All keys sit under `orb`, except `version`.

| Key | Required | Description |
|:--|:--|:--|
| `version` | No | Schema version. Informational only; the agent ignores it. |
| `orb.config_manager` | No | Where the agent gets its policies. Defaults to `local`. |
| `orb.backends` | Yes | Which backends to run, and settings they share. |
| `orb.policies` | With `local` | Policies defined in this file. |
| `orb.secrets_manager` | No | An external secrets store for credentials. |
| `orb.labels` | No | Key/value pairs that identify this agent. |
| `orb.debug` | No | Turns on debug logging. |
| `orb.files_manager` | No | Where files delivered by Fleet are stored. |

### `orb.config_manager`

Sets where the agent gets its policies. One source is active at a time.

| `active` | Policies come from |
|:--|:--|
| `local` | `orb.policies` in this file. This is the default if `active` is unset. |
| `git` | A Git repository, re-checked on a schedule. |
| `fleet` | NetBox Labs cloud. |

#### `local`

Needs no other settings:

```yaml
orb:
  config_manager:
    active: local
```

See [Local](local.md).

#### `git`

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
|:--|:--|:--|:--|
| `url` | string | Yes | Repository URL. |
| `branch` | string | No | Branch to read. Defaults to the repository's default branch. |
| `schedule` | cron | No | How often to check for changes. If unset, policies are read once at startup. |
| `auth` | string | No | `basic`, `ssh` or `github_app`. Omit for a public repository. |
| `username` | string | No | Username for `basic`. |
| `password` | string | No | Password or token for `basic`, or the key passphrase for `ssh`. |
| `private_key` | string | No | Path to the SSH private key, for `ssh`. |
| `skip_tls` | bool | No | Skip TLS certificate verification. Defaults to `false`. |
| `github_app.client_id` | string | With `github_app` | The app's Client ID. The numeric App ID also works. |
| `github_app.installation_id` | string | With `github_app` | The numeric ID of the app's installation on the repository owner. |
| `github_app.private_key` | string | With `github_app` | Path to the app's `.pem` key, or the key itself. |

See [Git](git.md) for repository layout and how the agent selects policies.

### `orb.backends`

Each key under `backends` turns on that backend. A key with no settings uses the defaults. The `common` key holds settings that all backends share.

```yaml
orb:
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: agent01
    device_discovery:
    snmp_discovery:
```

#### `common.diode`

How discovery backends connect to Diode.

| Parameter | Type | Required | Description |
|:--|:--|:--|:--|
| `target` | string | Yes, unless `dry_run` | Diode gRPC endpoint, for example `grpc://host:8080/diode`. |
| `client_id` | string | Yes, unless `dry_run` | Diode client ID. |
| `client_secret` | string | Yes, unless `dry_run` | Diode client secret. |
| `agent_name` | string | No | A name attached to all data this agent sends. |
| `dry_run` | bool | No | Write results to files instead of sending them to Diode. Defaults to `false`. |
| `dry_run_output_dir` | string | No | Where dry-run files are written. Defaults to the current directory. |

#### `common.otlp`

Where backends export metrics with OpenTelemetry (OTLP).

| Parameter | Type | Required | Description |
|:--|:--|:--|:--|
| `grpc` | string | No | OTLP gRPC endpoint, for example `grpc://collector:4317`. Required by `snmp_telemetry` and `gnmi_telemetry`. |
| `http` | string | No | OTLP HTTP endpoint, for example `http://collector:4318`. Used by pktvisor. |
| `agent_labels` | map | No | Labels added to all exported metrics. |

#### Backends

| Key | Backend | Default port |
|:--|:--|:--|
| `device_discovery` | [Device discovery](../backends/device_discovery/README.md) | 8072 |
| `network_discovery` | [Network discovery](../backends/network_discovery.md) | 8073 |
| `snmp_discovery` | [SNMP discovery](../backends/snmp_discovery/README.md) | 8070 |
| `gnmi_discovery` | [gNMI discovery](../backends/gnmi_discovery.md) | 8075 |
| `worker` | [Worker](../backends/worker.md) | 8071 |
| `snmp_telemetry` | [SNMP telemetry](../backends/snmp_telemetry.md) | 8078 |
| `gnmi_telemetry` | [gNMI telemetry](../backends/gnmi_telemetry.md) | 8079 |
| `pktvisor` | [pktvisor](../backends/pktvisor/README.md) | 10853 |
| `opentelemetry_infinity` | [OpenTelemetry Infinity](../backends/opentelemetry_infinity.md) | 10222 |

Each backend listens on a local port that the agent uses to control it. To change it, set `host` and `port` under the backend's key.

:::note
A backend won't start if another process is already using its port. This happens when two agents share the host network with the same ports, or when a backend from an earlier run is still running. Give each agent its own ports, or stop the leftover process.
:::

Any backend can also take these keys:

| Key | Values | Default | Description |
|:--|:--|:--|:--|
| `start_mode` | `eager`, `on_demand` | `eager` | `eager` starts the backend with the agent, and a failed start stops the agent. `on_demand` starts it when its first policy arrives, and retries a failed start every five minutes. |
| `start_timeout` | 1–300 | 30 | Seconds an `on_demand` backend has to become ready. Valid only with `on_demand`. |

```yaml
orb:
  backends:
    gnmi_telemetry:
      start_mode: on_demand
      start_timeout: 60
```

### `orb.policies`

Policies tell each backend what to discover and when. Define them here when `config_manager.active` is `local`. With `git` or `fleet`, the agent ignores this section.

Group policies under the backend that runs them. Each key beneath a backend is a policy name.

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

The settings for each policy depend on the backend. See the page for each backend in the [Backends](#backends) table.

#### Policy names

The agent uses the name exactly as written, in backend status and in telemetry.

- **Any characters except `/`.** Spaces, `#`, `?`, `%` and non-ASCII characters all work. A policy whose name contains `/` fails to apply.
- **Unique within a backend.** A duplicate name is a YAML error, and the agent rejects the whole file.
- **Best kept unique across backends.** If two backends have a policy with the same name, their telemetry can be mixed up.

### `orb.secrets_manager`

Connects the agent to a secrets store, so the file can refer to credentials instead of containing them. Each store has its own placeholder, such as `${vault://...}`, that you can use in policies and in other settings.

| `active` | Secrets store | Placeholder |
|:--|:--|:--|
| `vault` | [HashiCorp Vault](../secretsmgr/vault.md) | `${vault://...}` |
| `doppler` | [Doppler](../secretsmgr/doppler.md) | `${doppler://...}` |
| `cyberark` | [CyberArk Central Credential Provider](../secretsmgr/cyberark.md) | `${cyberark://...}` |
| `delinea` | [Delinea Secret Server](../secretsmgr/delinea.md) | `${delinea://...}` |
| `dsv` | [Delinea DevOps Secrets Vault](../secretsmgr/dsv.md) | `${dsv://...}` |
| `fleet` | NetBox Labs cloud | — |

For example, with Vault:

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

Each store's page lists its settings and placeholder formats. If `active` is unset, the agent runs without a secrets manager.

### `orb.labels`

Key/value pairs that identify this agent. With the Git config manager, the agent matches its labels against `selector.yaml` in the repository to choose its policies.

```yaml
orb:
  labels:
    region: EU
    pop: ams02
    environment: production
```

### `orb.debug`

Turns on debug logging, the same as starting the agent with `-d`:

```yaml
orb:
  debug:
    enable: true
```

### `orb.files_manager`

Used only with Fleet. Sets where the agent stores files that Fleet delivers.

| Parameter | Type | Description |
|:--|:--|:--|
| `root` | string | Directory for delivered files. Defaults to `/opt/orb/files`. |

## Environment variables in the file

A value written as `${VAR_NAME}` is replaced with the environment variable `VAR_NAME`. Keep credentials such as Diode client secrets out of the file this way.

Which values are replaced depends on what reads them:

| Section | Values replaced | Replaced by |
|:--|:--|:--|
| `config_manager.sources.git` | `url`, `password`, and the three `github_app` values | The agent, at startup |
| `config_manager.sources.fleet` | `token_url`, `client_id`, `client_secret` | The agent, at startup |
| `secrets_manager.sources.vault` | Everything under `auth_args` | The agent, at startup |
| `secrets_manager.sources.doppler` | `token`, `api_host`, `project`, `config` | The agent, at startup |
| `secrets_manager.sources.cyberark` | `url`, `app_id`, `reason`, `ca_bundle`, `client_cert`, `client_key` | The agent, at startup |
| `secrets_manager.sources.delinea` | `server_url`, `tenant`, `username`, `password` | The agent, at startup |
| `secrets_manager.sources.dsv` | `tenant`, `client_id`, `client_secret`, `tld`, `url_template`, `schedule` | The agent, at startup |
| `device_discovery` policies | Any text value in `scope` and `defaults` | The backend, when the policy runs |
| `snmp_discovery` policies | `community`, `username`, `auth_passphrase`, `priv_passphrase`, `context_name` | The backend, when the policy runs |
| `snmp_telemetry` policies | `community`, `username`, `auth_passphrase`, `priv_passphrase` | The backend, when the policy runs |
| `gnmi_telemetry` policies | `username`, `password`, `tls.ca`, `tls.cert`, `tls.key` | The backend, when the policy runs |

For the values the agent replaces at startup:

- **The placeholder must be the whole value.** `password: ${GIT_TOKEN}` works. `url: https://${GIT_HOST}/repo` is left as written.
- **The variable must be set.** If it isn't, the agent stops with the error `a provided environment variable is not set`.

`snmp_telemetry` and `gnmi_telemetry` replace only variables you allow. List them in `policy_env_vars` under the backend's key; if you don't, every reference is refused. See [SNMP telemetry](../backends/snmp_telemetry.md) and [gNMI telemetry](../backends/gnmi_telemetry.md).

For a value not listed here, such as a `network_discovery` target, use a [secrets manager](#orbsecrets_manager) instead.

:::note
To set or override any key from the environment without writing a placeholder in the file, see [Environment-Driven Configuration](../advanced_config/env_config.md).
:::
