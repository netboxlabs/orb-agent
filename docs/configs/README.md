# Configure

You configure the Orb agent with one YAML file, usually named `agent.yaml`. 

You pass it with `-c` when you start the agent. This file says what the agent runs, what it discovers, and where it gets the information it needs to do that.

## The parts of `agent.yaml`

Every setting sits under the `orb` key:

```yaml
orb:
  backends:          # Which backends run, and how they reach Diode
    common:
      diode:
        target: grpc://diode.example.com:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
    network_discovery:
  policies:          # What each backend discovers, and when
    network_discovery:
      office_scan:
        config:
          schedule: "0 */2 * * *"
        scope:
          targets: [192.168.1.0/24]
  config_manager:    # Where policies come from (optional)
    active: local
  secrets_manager:   # Where credentials come from (optional)
    active: vault
    sources:
      vault:
        address: https://vault.example.com:8200
        auth: token
        auth_args:
          token: ${VAULT_TOKEN}
```

- **Backends**
  A backend does one kind of work, such as network discovery, device discovery or SNMP telemetry. Each key under `backends` turns one on. The `common` key holds settings that all backends share, such as the Diode connection.
- **Policies**
  A policy tells a backend what to do and when: which targets to discover, on what schedule, and with what defaults. Policies are grouped under the backend that runs them. One backend can run many policies.
- **Config manager**
  Sets where the agent reads its policies from. The default is the `policies` section of this file.
- **Secrets manager**
  Connects the agent to an external secrets store, so the file can refer to credentials instead of containing them. Leave it out if you don't use one.

The file can also set labels that identify the agent, and turn on debug logging. See [Top-level keys](agent_yaml.md#top-level-keys).

## Where policies come from

The config manager decides where the agent reads its policies. To choose one, set `orb.config_manager.active`:

| Source | Value of `active` | Use it when |
|:--|:--|:--|
| [Local](local.md) | `local` | One agent runs a fixed set of policies, or you're trying the agent out. Policies are read from `orb.policies` in the file. This is the default. |
| [Git](git.md) | `git` | You manage policies for several agents from one place. Policies are read from a Git repository and re-checked on a schedule, so you can change them without touching the agent host. |

Only policies come from the config manager. The agent always reads `backends`, `config_manager` and `secrets_manager` from the file at startup, even with Git. Those sections must be correct before the agent starts.

## Keeping credentials out of the file

The file usually needs credentials, such as the Diode client secret and device passwords. There are three ways to keep them out of it:

- **`${VAR}` placeholders**
  Write `client_secret: ${DIODE_CLIENT_SECRET}` in the file, and set the variable in the container's environment. See [Environment variables in the file](agent_yaml.md#environment-variables-in-the-file).
- **`ORB_*` overrides**
  Set any setting from the environment without mentioning it in the file, for example `ORB_SECRETS_MANAGER__ACTIVE=vault`. Useful when one file serves several deployments. See [Environment-Driven Configuration](../advanced_config/env_config.md).
- **A secrets manager**
  Fetch credentials from HashiCorp Vault, Doppler, CyberArk or Delinea when a policy runs. See [Secrets managers](../secretsmgr/README.md).

## Additional information

- **[Agent Configuration File](agent_yaml.md)**
  Every key `agent.yaml` supports, with its type, default and description.
- **[Policies](policies.md)**
  What a policy contains, when it runs, and how to name and change it.
- **[Local](local.md)**
  Define policies in `agent.yaml`.
- **[Git](git.md)**
  Read policies from a Git repository, and choose which agents run which policies.
- **[Environment-Driven Configuration](../advanced_config/env_config.md)**
  Set or override any setting with `ORB_*` environment variables.
- **[Configuration Samples](../config_samples.md)**
  Complete example files for each backend.

For the settings each backend's policies support, see the backend's page. The [Backends](agent_yaml.md#backends) table links to each one.
