# Secrets Manager

The secrets manager resolves secret references when a policy is applied, so
credentials live in your secret store rather than in `agent.yaml`. A policy
writes a reference where the value would go:

```yaml
scope:
  - driver: ios
    hostname: 192.0.2.10
    username: admin
    password: "${vault://secret/devices/password}"
```

One provider is active at a time, selected by `orb.secrets_manager.active`, and
configured under `sources`:

```yaml
orb:
  secrets_manager:
    active: vault
    sources:
      vault:
        address: "https://vault.example.com:8200"
```

| Provider | `active` | Reference form |
|:--|:--|:--|
| [HashiCorp Vault](vault.md) | `vault` | `${vault://<mount>/<path>/<key>}` |
| [Doppler](doppler.md) | `doppler` | `${doppler://<project>/<config>/<secret>}` |
| [CyberArk (CCP)](cyberark.md) | `cyberark` | `${cyberark://<Safe>/<Object>/<Field>}` |
| [Delinea Secret Server](delinea.md) | `delinea` | `${delinea://path/<folder>/<name>/<field>}` |
| [Delinea DevOps Secrets Vault (DSV)](dsv.md) | `dsv` | `${dsv://<secret-path>/<field-key>}` |

Each provider's page documents its own reference forms in full, since most
accept more than one.

Leaving `active` unset or empty skips the secrets manager and the agent starts
normally. A value that is set but not recognised fails startup with an error
naming the supported types.

The provider and its settings can also be chosen entirely from the environment,
without editing the YAML, which suits injecting them at deploy time. See
[Environment-Driven Configuration](../advanced_config/env_config.md).

The agent logs a policy it applies by its ID and name only, at every log level,
so its own lines carry no resolved values. With debug logging on, the provider
logs the references it resolves, never the values. See
[Debug Logging](../config_samples.md#debug-logging).

A backend that refuses a policy can quote one of its values in the error, as a
type error does for a reference in a field that takes a number. Before the
agent logs that error or reports it as the policy's error, it masks each
resolved value as `********`:

- the whole value, and its first or last 7 bytes or more, as a backend that
  shortens a value quotes it, including first bytes that end inside a
  character;
- the same escaped, as Go or JSON quote a string.

A value shorter than 7 bytes is masked only where it is a word of its own, and
a run from the middle of a value is left alone, since it is more likely the
error's own words. The agent then names the fields whose values the error
quotes, because the backend's error points at a line of the policy as the
agent sent it, not at a field you wrote:

```text
400 yaml: unmarshal errors:
  line 4: cannot unmarshal !!str `********` into int (the error quotes the value of the secret reference at config.retries, masked as ********)
```

Only part of a refusal is kept: the agent logs at most 8 KiB of it and reports
at most 1 KiB as the policy's error. A refusal that is cut ends with
`... (truncated)`, followed by the note naming the fields.

## Rotation

Every provider takes an optional `schedule`, a cron expression for re-fetching
secrets that have already been resolved. When a referenced value changes, the
policies that used it are re-applied with the new value, so credentials can be
rotated without restarting the agent. Each provider's page covers what happens
when a re-fetch fails.
