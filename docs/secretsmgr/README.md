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
the secrets the agent's policies reference. When a referenced value changes,
the policies that use it are re-applied with the new value, so credentials can
be rotated without restarting the agent.

When a re-fetch fails, because the secret was deleted, the provider can't be
reached or the agent's own credentials to it expired, the agent stops the
policies that use the secret. It keeps them and reports each one failed with
a reason that starts with `failed to resolve policy secrets:` and names the
reference, as it does for a secret that doesn't resolve the first time a
policy is applied. The agent goes on reading the secret on the schedule:

- once the secret resolves again, the policies are re-applied, with no
  restart;
- a policy delivered again meanwhile, by an update to it for example, reads
  the secret again and is applied if it resolves.

A secret that doesn't resolve the first time a policy is applied is read on
the schedule the same way. Only the secrets named by the version of a policy
the agent applied last count: once an update that moves a policy to another
secret is applied, the one it used before can be deleted, and a removed
policy depends on none.

The agent stops the policies whatever made the read fail, so a provider that
can't be reached for a moment costs them collection until the next read that
succeeds: a schedule interval at least, more when a poll waits on a provider
that doesn't answer. A policy that runs once is run again when it is
re-applied, as it is when a value changes. The failure is logged once, at
ERROR, as `Failed to retrieve secret during polling`, and a poll that finds
the secret resolving again logs `Secret resolves again` at INFO.

Without a `schedule`, the agent reads a secret only when it applies a policy,
so a policy whose secret didn't resolve is applied again when it is delivered
again or the agent restarts.
