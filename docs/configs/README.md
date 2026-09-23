# Config Manager

The config manager decides where the agent gets its policies from. It is
selected by `orb.config_manager.active` in the agent configuration file:

```yaml
orb:
  config_manager:
    active: local
```

| Source | `active` | Description |
|:--|:--|:--|
| [Local](local.md) | `local` | Policies are read from `orb.policies` in the config file itself. Nothing external is contacted, and no credentials are needed. |
| [Git](git.md) | `git` | Policies are fetched from a Git repository and re-synced on a schedule, so they can be changed without touching the agent host. |

Only policies come from the selected source. The `config_manager` and `backends`
sections are always read from the file at startup, including under `git`, so
those must be correct before the agent starts.

## The configuration file

Whichever source is active, the agent starts from an `agent.yaml` passed with
`-c`. It declares the agent's identity, which backends run, how policies are
loaded, and optional secrets management. See
[Agent Configuration File (`agent.yaml`)](agent_yaml.md) for every supported key.

Any value in it can also be set or overridden with `ORB_*` environment
variables, which suits injecting settings at deploy time without templating the
YAML. See [Environment-Driven Configuration](../advanced_config/env_config.md).
