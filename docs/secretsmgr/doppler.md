# Doppler Secrets Manager

The Orb Agent can integrate with [Doppler](https://www.doppler.com/) to securely manage sensitive information such as passwords and API keys. This feature allows you to reference secrets stored in Doppler directly in your policy configurations without hardcoding sensitive values.

The provider is read-only and has been validated end-to-end against a real Doppler workplace using a Service Token, including secret rotation and cron-driven re-apply.

## Configuration

The Doppler secrets manager is configured in the `secrets_manager` section of your Orb Agent configuration file:

```yaml
orb:
  secrets_manager:
    active: doppler
    sources:
      doppler:
        token: "${DOPPLER_TOKEN}"        # Service Token, SA token, or personal token
        api_host: ""                     # Optional, defaults to https://api.doppler.com
        project: "orb"                   # Optional default for short-form placeholders
        config: "prd"                    # Optional default for short-form placeholders
        timeout: 60                      # Optional, HTTP timeout in seconds
        schedule: "*/5 * * * *"          # Optional, cron format for polling interval
```

### Configuration Options

| Option     | Type   | Required | Description |
|------------|--------|----------|-------------|
| `token`    | string | Yes | Doppler API token. Accepts a literal value or `${ENV_VAR}`. |
| `api_host` | string | No  | Override the Doppler API host (default `https://api.doppler.com`). |
| `project`  | string | No  | Default Doppler project for short-form placeholders. |
| `config`   | string | No  | Default Doppler config for short-form placeholders. |
| `timeout`  | int    | No  | HTTP request timeout in seconds (default `60`). |
| `schedule` | string | No  | Cron expression for periodic polling of cached secrets. When omitted, secrets are fetched once on first reference and never re-checked. |

Each string field accepts an environment-variable placeholder of the form `${VAR_NAME}`. The placeholder is resolved at agent startup; an unset referenced variable causes the agent to fail startup with a clear error.

## Authentication

The Doppler provider supports any token Doppler issues: **Service Tokens** (scoped to a single config), **Service Account tokens** (broader scope), and **Personal tokens**. The token is sent as `Authorization: Bearer <token>` on every secret lookup.

A Service Token is the recommended default: it can only read secrets from the single config it was issued for, so it pairs naturally with the `project` and `config` agent-level defaults and short-form placeholders.

The provider does not eagerly authenticate at startup — the first secret fetch is what surfaces a 401, with the error visible in the policy-apply log.

## Usage

To use a secret from Doppler in your policy configuration, use one of the two reference forms:

### Short form (uses agent defaults)

```
${doppler://<secret_name>}
```

Example — fetch `API_KEY` from the `project`/`config` configured at agent level:

```
${doppler://API_KEY}
```

Short form requires both `project` and `config` to be set under `sources.doppler`. If either default is missing, the agent fails the placeholder lookup with a clear error.

### Fully qualified

```
${doppler://<project>/<config>/<secret_name>}
```

Example — fetch `API_KEY` from the `orb` project's `prd` config explicitly:

```
${doppler://orb/prd/API_KEY}
```

Use the fully qualified form with Service Account or Personal tokens that have access to multiple configs.

## Change detection

When `schedule` is set, the provider re-fetches each cached secret on the cron cadence. If a value changed, the policy manager re-applies every policy that referenced it. If a secret becomes unreachable (deleted, revoked, network failure), the provider evicts the cache entry and asks the policy manager to mark the affected policies as failed; the policy can recover only after a successful re-fetch.

## Manual validation checklist (against a real Doppler workplace)

1. Create a Service Token scoped to a single config; run the agent with that token and a short-form placeholder.
2. Rotate the secret in Doppler; verify the agent's log emits `Detected changed secret` (with `scheme=doppler`) on the next poll and that the affected policy is re-applied.
3. Delete the secret in Doppler; verify the agent emits the failure log and that the policy is marked failed.
4. Configure the agent with no `project`/`config` defaults and use the fully qualified `${doppler://proj/cfg/NAME}` form with a Service Account token; verify the lookup succeeds.
5. Use an invalid token; verify the agent's log emits a 401 error on first lookup.
