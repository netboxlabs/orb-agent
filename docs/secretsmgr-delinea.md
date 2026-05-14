# Delinea Secret Server `secretsmgr` provider

orb-agent can resolve secrets from [Delinea Secret Server](https://delinea.com/products/secret-server/) (both Secret Server Cloud and on-prem / Platform) using the official [tss-sdk-go](https://github.com/DelineaXPM/tss-sdk-go).

## Configuration

```yaml
secrets_manager:
  active: delinea
  sources:
    delinea:
      server_url: ""                                 # on-prem / Platform URL; XOR with tenant
      tenant: "<your-tenant>"                        # Secret Server Cloud subdomain
      username: "svc_orb"
      password: "${DELINEA_PASSWORD}"
      skip_tls: false
      schedule: "*/5 * * * *"                        # optional cron for change-detection polling
```

Exactly one of `server_url` or `tenant` must be set. The provider does not eagerly authenticate at startup — the first secret fetch performs the OAuth handshake.

The `server_url`, `tenant`, `username`, and `password` fields each accept a `${ENV_VAR}` placeholder that is resolved from the agent's environment at startup; an unset referenced variable causes startup to fail with a clear error.

## Placeholder grammar

Inside any YAML value:

| Form | Syntax | Example |
|---|---|---|
| By numeric ID | `${delinea://id/<id>/<field>}` | `${delinea://id/42/password}` |
| By path | `${delinea://path/<folder>/.../<name>/<field>}` | `${delinea://path/Servers/prod-db/password}` |

Field names are Delinea **slugs** (e.g. `password`, `username`).

## Rotation

If `schedule` is set, the provider re-fetches every cached secret on the cron. When a value changes, all policies that referenced that secret are re-applied to their backends. A failed fetch also triggers re-apply, marking the policy as failed.

## Manual end-to-end validation

This procedure validates the full integration against a real Delinea instance. The Secret Server software itself requires Windows + MSSQL and is not practical to run locally, so use a free Secret Server Cloud trial tenant.

### Prereqs

- Free trial tenant from <https://secretservercloud.com>.
- Local `build/orb-agent` built from this branch (`make agent_bin`).

### Steps

1. **Provision in Delinea Cloud:**
   - Create a service user `svc_orb` with a strong password.
   - Create folder `/orb-test`.
   - Create a secret `orb-test-credential` (template "Password") with `password=hunter2-OBS1378`.
   - Grant `svc_orb` "View Secret" on `/orb-test`.

2. **Write `orb-agent.yaml`:**

   ```yaml
   version: 1.0
   orb:
     secrets_manager:
       active: delinea
       sources:
         delinea:
           tenant: "<your-tenant>"
           username: "svc_orb"
           password: "${DELINEA_PASSWORD}"
           schedule: "*/1 * * * *"
     backends: {}
     policies: {}
     config_manager:
       active: local
       sources:
         local:
           config: ./orb-agent.yaml
   ```

3. **Run with debug:**

   ```bash
   export DELINEA_PASSWORD='<svc_orb password>'
   ./build/orb-agent -c orb-agent.yaml -d
   ```

4. **Verify auth + lookup:** in the logs, look for a successful `SolvePolicySecrets` on a policy referencing `${delinea://path/orb-test/orb-test-credential/password}` — the resolved value must reach the backend, not the placeholder string. (Add a temporary local policy with that field if your config has no policies.)

5. **Verify rotation:** change the password in the Delinea UI to `rotated-hunter2`. Within one minute, the agent logs `Detected changed delinea secret` and re-applies the policy.

6. **Negative checks:**
   - Wrong password → first secret fetch fails with a clear auth error.
   - Bad placeholder grammar (e.g. `${delinea://id/abc/password}`) → policy apply fails with a parse error.

### Pass criteria

- Resolved secret value reaches the backend.
- A live rotation triggers a policy re-apply within one cron interval.
- Failure paths produce comprehensible errors.
