# Configuration

The agent is configured by an `agent.yaml` file passed at startup with `-c`. It
declares the agent's identity, which backends run, which policies they run, and
where those policies come from.

- [Agent Configuration File (`agent.yaml`)](agent_yaml.md) — the full reference
  for every supported key.

## Where policies come from

The `config_manager` section chooses how the agent obtains its policies:

```yaml
orb:
  config_manager:
    active: local
```

| Source | `active` | Description |
|:--|:--|:--|
| [Local](local.md) | `local` | Policies are read from `orb.policies` in the config file itself. Nothing external is contacted, and no credentials are needed. |
| [Git](git.md) | `git` | Policies are fetched from a Git repository and re-synced on a schedule, so they can be changed without touching the agent host. |

The `config_manager` and `backends` sections are always read from the file at
startup, including under `git`; only policies are fetched remotely.

Any value in this file can also be set or overridden with `ORB_*` environment
variables, which is useful for injecting settings at deploy time without
templating the YAML. See
[Environment-Driven Configuration](../advanced_config/env_config.md).
