# Environment Variables

The Orb agent reads its settings from `agent.yaml`. You can also supply settings from environment variables, so the file doesn't have to contain credentials, and one file can serve several deployments. For how the file is organized, see [Configure](../configs/README.md).

There are two ways to use environment variables:

| | `${VAR}` placeholders | `ORB_*` overrides |
|:--|:--|:--|
| How it works | You write `${VAR}` as a value in the file, and the agent replaces it with the variable's value | You set an `ORB_*` variable, and the agent applies it on top of the file, whether or not the file mentions that setting |
| Example | `client_secret: ${DIODE_CLIENT_SECRET}` | `ORB_SECRETS_MANAGER__ACTIVE=vault` |
| Use it for | Credentials and other per-deployment values in backends and policies, such as the Diode client secret | Choosing and configuring the secrets manager or config manager per deployment, without editing the file |

Most setups only need placeholders. The two can be used together.

Either way, the variables must be set in the agent container's environment, for example with `--env-file` or `-e` on `docker run`. See [Install and Run the Agent](install.md).

## Placeholders in `agent.yaml`

A value written as `${VAR_NAME}` is replaced with the value of the environment variable `VAR_NAME`:

```yaml
orb:
  backends:
    common:
      diode:
        target: ${DIODE_TARGET}
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
```

### Where placeholders work

Placeholders work only in the settings listed here. Elsewhere, `${VAR}` is kept as literal text.

| Section | Values replaced | Replaced by |
|:--|:--|:--|
| `backends.common.diode` | `target`, `client_id`, `client_secret`, `dry_run_output_dir` | Each discovery backend, when it starts |
| `config_manager.sources.git` | `url`, `password`, and the three `github_app` values | The agent, at startup |
| `config_manager.sources.fleet` | `token_url`, `client_id`, `client_secret` | The agent, at startup |
| `secrets_manager.sources.vault` | Everything under `auth_args` | The agent, at startup |
| `secrets_manager.sources.doppler` | `token`, `api_host`, `project`, `config` | The agent, at startup |
| `secrets_manager.sources.cyberark` | `url`, `app_id`, `reason`, `ca_bundle`, `client_cert`, `client_key` | The agent, at startup |
| `secrets_manager.sources.delinea` | `server_url`, `tenant`, `username`, `password` | The agent, at startup |
| `secrets_manager.sources.dsv` | `tenant`, `client_id`, `client_secret`, `tld`, `url_template`, `schedule` | The agent, at startup |
| `device_discovery` policies | Any text value in the policy | The backend, when the policy is applied |
| `worker` policies | Any text value in the policy | The backend, when the policy is applied |
| `snmp_discovery` policies | `community`, `username`, `auth_passphrase`, `priv_passphrase`, `context_name` | The backend, when the policy is applied |
| `snmp_telemetry` policies | `community`, `username`, `auth_passphrase`, `priv_passphrase` | The backend, when the policy is applied |
| `gnmi_telemetry` policies | `username`, `password`, `tls.ca`, `tls.cert`, `tls.key` | The backend, when the policy is applied |

For a value not listed here, such as a `network_discovery` target, use a [secrets manager](../secretsmgr/README.md) instead.

### Rules

- **The placeholder must be the whole value.**
  `password: ${GIT_TOKEN}` works. `url: https://${GIT_HOST}/repo` is left as written.
- **Telemetry backends replace only variables you allow.**
  For `snmp_telemetry` and `gnmi_telemetry`, list the variables in `policy_env_vars` under the backend's key. Otherwise, every reference is refused. See [SNMP telemetry](../backends/snmp_telemetry.md) and [gNMI telemetry](../backends/gnmi_telemetry.md).

### If a variable isn't set

What happens depends on what reads the value:

| Where the placeholder is | Result |
|:--|:--|
| Settings the agent replaces at startup | The agent stops with `a provided environment variable is not set`. |
| `common.diode`, read by network, SNMP or gNMI discovery | That backend stops with the same error. |
| `common.diode` or a policy, read by device discovery or the worker | The placeholder is used as literal text. The problem shows up later, for example as a Diode authentication failure. |
| An SNMP discovery or telemetry policy | The policy is refused. |

Device discovery and the worker give no warning, so if they fail to authenticate, check that every variable they use is set.

## `ORB_*` overrides

An `ORB_*` variable sets one setting from the environment. Use overrides when the same `agent.yaml` is deployed in several places that differ in only a few settings, such as which secrets manager to use.

### Naming an override

An override name is the setting's path, in upper case, with `ORB_` in front and `__` (two underscores) between levels:

| Setting in `agent.yaml` | Environment variable |
|:--|:--|
| `orb.secrets_manager.active` | `ORB_SECRETS_MANAGER__ACTIVE` |
| `orb.secrets_manager.sources.vault.address` | `ORB_SECRETS_MANAGER__SOURCES__VAULT__ADDRESS` |
| `orb.secrets_manager.sources.vault.auth_args.token` | `ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH_ARGS__TOKEN` |
| `orb.config_manager.active` | `ORB_CONFIG_MANAGER__ACTIVE` |

A single `_` stays part of the name, so `SECRETS_MANAGER` maps to `secrets_manager`. The agent lower-cases the whole name before matching it to a setting.

### Precedence

The agent loads each file passed with `-c`, in order, then applies the overrides on top. An override wins over the file. Settings that no override touches keep their value from the file.

### Where overrides work

Overrides work best in the `config_manager` and `secrets_manager` sections. Setting one value there leaves the other values in that section unchanged.

The `backends` and `policies` sections behave differently. An override that reaches into a backend or policy **replaces that whole entry** with only the values you set in the environment. For example, `ORB_BACKENDS__COMMON__DIODE__TARGET` replaces the entire `common` entry. That drops the Diode credentials and any `otlp` settings the file defined there.

Keep backend and policy settings in the file. For values in those sections that change per deployment, use [placeholders](#placeholders-in-agentyaml).

### Value types

The agent converts each value to the type its setting expects:

- **Booleans**
  Accept `true`/`false`, `1`/`0`, `t`/`f`, and upper-case forms such as `TRUE`. `yes`, `no`, `on` and `off` work only in the file.
- **Integers**
  Are always read as decimal, so `010` is ten.
- **Values under `auth_args`, `backends` or `policies`**
  Are always stored as strings, because those sections accept any key and the agent can't know the intended type. A password of `0` stays the string `"0"`. Vault AppRole's `wrapping_token` is a boolean, so set it in the file.

Overrides can't reach a setting whose name contains upper-case letters, because names are lower-cased. Set those in the file.

An empty value is ignored. For example, `ORB_SECRETS_MANAGER__ACTIVE=` leaves the file's setting in place. For the values each setting accepts, see the [Agent Configuration File](../configs/agent_yaml.md) reference.

## Examples

### Docker: Vault with a static token

In this example, `agent.yaml` holds the backends and policies. The environment selects and configures Vault, and supplies the Diode credentials.

`/local/orb/agent.yaml`:

```yaml
orb:
  backends:
    common:
      diode:
        target: ${DIODE_TARGET}
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
    network_discovery:
  policies:
    network_discovery:
      office_scan:
        config:
          schedule: "0 */2 * * *"
        scope:
          targets: [192.168.0.0/22]
```

`/local/orb/.env`:

```sh
# Placeholders in agent.yaml
DIODE_TARGET=grpc://diode.example.com:8080/diode
DIODE_CLIENT_ID=your-client-id
DIODE_CLIENT_SECRET=your-client-secret

# Overrides: use Vault as the secrets manager
ORB_SECRETS_MANAGER__ACTIVE=vault
ORB_SECRETS_MANAGER__SOURCES__VAULT__ADDRESS=https://vault.example.com:8200
ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH=token
ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH_ARGS__TOKEN=your-vault-token
```

Start the agent with the environment file:

```sh
docker run --net=host \
  -v /local/orb:/opt/orb/ \
  --env-file /local/orb/.env \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

Policies can now refer to Vault secrets with `${vault://...}`. See [HashiCorp Vault](../secretsmgr/vault.md).

### Kubernetes: Vault with the pod's service account

With Vault's Kubernetes auth method, no static token is needed. Vault checks the pod's own service account token, which the agent reads from disk.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: orb-agent
spec:
  serviceAccountName: orb-agent
  containers:
    - name: orb-agent
      image: netboxlabs/orb-agent:latest
      args: ["run", "-c", "/opt/orb/agent.yaml"]
      env:
        - name: ORB_SECRETS_MANAGER__ACTIVE
          value: "vault"
        - name: ORB_SECRETS_MANAGER__SOURCES__VAULT__ADDRESS
          value: "http://vault:8200"
        - name: ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH
          value: "kubernetes"
        - name: ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH_ARGS__ROLE
          value: "orb-agent"
      volumeMounts:
        - name: agent-config
          mountPath: /opt/orb/agent.yaml
          subPath: agent.yaml
  volumes:
    - name: agent-config
      configMap:
        name: orb-agent-config
```

To supply the Diode credentials for the file's placeholders, add them to `env` from a Kubernetes Secret with `secretKeyRef`.

## Troubleshooting

Start the agent with `-d` to see debug-level messages.

| Situation | Result | Logged at |
|:--|:--|:--|
| A placeholder's variable isn't set | Depends on where the placeholder is. See [If a variable isn't set](#if-a-variable-isnt-set) | — |
| An override's value is empty (`ORB_SECRETS_MANAGER__ACTIVE=`) | Ignored, so the file's value stays | debug |
| An override's name has no `__`, ends in `__`, contains `____`, or contains `.` | Ignored | debug |
| An override's name is well formed but matches no setting (a typo such as `ORB_SECRETS_MANAGER__ACTVE`) | Ignored | warning |
| A typo inside `backends`, `policies` or `auth_args` | Applied as a new key. These sections accept any key, so no warning is logged | — |
| A value can't be converted, such as `abc` for a number | The agent doesn't start | error |
| Two names map to the same setting, such as names that differ only in case | The agent doesn't start | error |
| One name sets a setting and another sets a setting beneath it (`…__ACTIVE` and `…__ACTIVE__X`) | The agent doesn't start | error |
