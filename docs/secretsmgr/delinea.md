# Delinea Secret Server Secrets Manager (beta)

The Orb Agent can integrate with [Delinea Secret Server](https://delinea.com/products/secret-server/) (both Secret Server Cloud and on-prem / Platform) to securely manage sensitive information such as passwords and API keys. This feature allows you to reference secrets stored in Delinea directly in your policy configurations without hardcoding sensitive values.

> **Beta:** The Delinea provider is read-only and supports username/password authentication only. The integration is exercised by unit tests against a fake Delinea HTTP server; end-to-end validation against a real Delinea tenant is captured as a manual checklist below.

## Configuration

The Delinea secrets manager is configured in the `secrets_manager` section of your Orb Agent configuration file:

```yaml
orb:
  secrets_manager:
    active: delinea
    sources:
      delinea:
        server_url: ""                  # On-prem / Platform URL (XOR with tenant)
        tenant: "<your-tenant>"         # Secret Server Cloud subdomain (XOR with server_url)
        username: "svc_orb"
        password: "${DELINEA_PASSWORD}"
        schedule: "*/5 * * * *"         # Optional, cron format for polling interval
```

Exactly one of `server_url` or `tenant` must be set. The provider does not eagerly authenticate at startup — the first secret fetch performs the OAuth handshake against Delinea.

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `server_url` | string | Cond. | URL of an on-prem Secret Server or Delinea Platform deployment. Mutually exclusive with `tenant`. |
| `tenant` | string | Cond. | Tenant subdomain for Secret Server Cloud (e.g. `acme` for `acme.secretservercloud.com`). Mutually exclusive with `server_url`. |
| `username` | string | Yes | Service-user username with `View Secret` permission on the referenced secrets. |
| `password` | string | Yes | Password for the service user. |
| `schedule` | string | No | Cron expression for periodic polling of cached secrets. When omitted, secrets are fetched once on first reference and never re-checked. |

Each of `server_url`, `tenant`, `username`, and `password` accepts an environment-variable placeholder of the form `${VAR_NAME}`. The placeholder is resolved at agent startup; an unset referenced variable causes the agent to fail startup with a clear error.

## Authentication

The Delinea SDK supports username/password authentication only. The Orb Agent uses the same set of credentials for both Secret Server Cloud and on-prem/Platform deployments — the SDK selects the correct endpoint based on whether `tenant` or `server_url` is set.

## Usage

To use a secret from Delinea in your policy configuration, use one of the two reference forms:

### By numeric secret ID

```
${delinea://id/<secret-id>/<field-slug>}
```

Example — fetch the `password` field of the secret with ID 42:

```
${delinea://id/42/password}
```

### By secret path

```
${delinea://path/<folder>/.../<name>/<field-slug>}
```

The path between `path/` and the final `/` becomes the Delinea secret path (with a leading slash prepended automatically); the final segment is the field slug.

Example — fetch the `password` field of the secret at `/Servers/prod-db`:

```
${delinea://path/Servers/prod-db/password}
```

Field names are Delinea **slugs** (the lowercased identifiers Delinea exposes for each template field, e.g. `password`, `username`, `notes`).

### Example

Here is an example of using Delinea secrets in a device discovery policy:

```yaml
orb:
  policies:
    device_discovery:
      discovery_1:
        schedule: "0 * * * *"  # Run hourly
        defaults:
          site: NY
        scope:
          - driver: ios
            hostname: 10.1.2.24
            username: admin
            password: "${delinea://path/Servers/v8000-cisco/password}"
```

The Orb Agent will resolve the Delinea reference and use the actual secret value when the policy is applied.

## Secret Polling

If you configure the `schedule` parameter, the Orb Agent will periodically re-fetch every secret that was resolved at least once. When a referenced secret value changes, the policies that referenced it are automatically re-applied with the new value.

If a poll fetch fails for a previously cached secret, every policy that referenced it is **removed** from its backend (this is the policy manager's contract for an invalid-secret signal). Subsequent recovery depends on the active config manager:

- **`config_manager.active: git` or `fleet`**: the policy will be re-applied on the next config-manager sync once the secret is reachable again.
- **`config_manager.active: local`**: there is no periodic sync. The removed policy will not come back on its own — the operator must restart the agent (or otherwise re-trigger the local config manager) to re-apply policies once Delinea is reachable.

If a policy references multiple Delinea secrets, a single failed fetch is sticky: that policy is removed even if another referenced secret merely changed value in the same poll cycle.

This is useful for credential rotation scenarios, where you want to rotate credentials in Delinea without restarting the Orb Agent or manually updating policies.

## Manual end-to-end validation

The Delinea Secret Server cannot be run locally (it requires Windows + MSSQL), so end-to-end validation uses a free Secret Server Cloud trial tenant.

### Prerequisites

- Free trial tenant from <https://secretservercloud.com>.
- Local `build/orb-agent` built from a branch containing this integration (`make agent_bin`).

### Steps

1. **Provision in Delinea Cloud:**
   - Create a service user `svc_orb` with a strong password.
   - Create folder `/orb-test`.
   - Create a secret `orb-test-credential` (template `Password`) with `password=hunter2-OBS1378`.
   - Grant `svc_orb` the `View Secret` permission on `/orb-test`.

2. **Write `orb-agent.yaml`:** the agent refuses to start with `backends: {}`, so the example includes a minimal `device_discovery` backend together with one local policy that references the Delinea secret. Adjust the backend block to whatever backend you actually run.

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
     backends:
       device_discovery:
         common: {}
     policies:
       device_discovery:
         orb-test-policy:
           data:
             credential: "${delinea://path/orb-test/orb-test-credential/password}"
     config_manager:
       active: local
       sources:
         local:
           config: ./orb-agent.yaml
   ```

3. **Run with debug logging:**

   ```bash
   export DELINEA_PASSWORD='<svc_orb password>'
   ./build/orb-agent -c orb-agent.yaml -d
   ```

4. **Verify auth + lookup:** in the logs, look for a successful `SolvePolicySecrets` call on the `orb-test-policy` policy. The `credential` field passed to the `device_discovery` backend must be the resolved value, not the placeholder string.

5. **Verify rotation:** change the password of `orb-test-credential` in the Delinea UI to `rotated-hunter2`. Within one minute, the agent logs `Detected changed delinea secret` and re-applies the policy with the new value.

6. **Negative checks:**
   - Wrong service-user password → the first secret fetch fails with a clear authentication error.
   - Bad placeholder grammar (for example `${delinea://id/abc/password}`) → policy apply fails with a parse error.

### Pass criteria

- The resolved secret value reaches the backend.
- A live rotation triggers a policy re-apply within one cron interval.
- Failure paths produce comprehensible errors in the agent log.
