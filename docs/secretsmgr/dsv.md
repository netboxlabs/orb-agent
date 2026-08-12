# Delinea DevOps Secrets Vault (DSV) Secrets Manager (beta)

The Orb Agent can integrate with [Delinea DevOps Secrets Vault (DSV)](https://delinea.com/products/devops-secrets-management-vault) to resolve sensitive values — passwords, tokens, API keys — referenced from your policy and config values, without hardcoding them.

> **DSV is a different product from Delinea Secret Server.** If you use Secret Server, see [the `delinea` provider](./delinea.md) instead. This page documents the `dsv` provider, which targets DevOps Secrets Vault via the official `dsv-sdk-go` SDK.

> **Beta:** The DSV provider is read-only and supports client-credential authentication only. It is exercised by unit tests against a fake DSV HTTP server; end-to-end validation against a real DSV tenant is captured as a manual checklist below.

## Configuration

The DSV secrets manager is configured in the `secrets_manager` section of your Orb Agent configuration file:

```yaml
orb:
  secrets_manager:
    active: dsv
    sources:
      dsv:
        tenant: "<your-tenant>"                 # DSV tenant subdomain
        client_id: "<client-id>"
        client_secret: "${DSV_CLIENT_SECRET}"
        tld: "com"                              # Optional, default "com"
        url_template: ""                        # Optional, advanced override
        schedule: "*/5 * * * *"                 # Optional, cron for polling interval
```

The provider does not eagerly authenticate at startup — the first secret fetch performs the client-credentials token handshake against DSV.

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `tenant` | string | Yes | DSV tenant subdomain, e.g. `acme` for `acme.secretsvaultcloud.com`. |
| `client_id` | string | Yes | Client-credential ID (from a DSV client credential). |
| `client_secret` | string | Yes | Client-credential secret. |
| `tld` | string | No | Region top-level domain for the DSV endpoint (`com`, `eu`, `com.au`, …). Defaults to `com`. |
| `url_template` | string | No | Advanced override of the SDK URL template (for a regional proxy or gateway). When empty, the SDK default `https://%s.secretsvaultcloud.%s/v1/%s%s` is used. |
| `schedule` | string | No | Cron expression for periodic polling of cached secrets. When omitted, secrets are fetched once on first reference and never re-checked. |

Each string option accepts an environment-variable placeholder of the form `${VAR_NAME}`. The placeholder is resolved at agent startup; an unset referenced variable causes the agent to fail startup with a clear error.

> **No request timeout option.** The DSV SDK performs its HTTP calls with a client that exposes no timeout hook, so — unlike the Vault, Doppler, and CyberArk providers — `dsv` has no `timeout` setting. This matches the `delinea` (Secret Server) provider.

## Authentication

The DSV provider uses **client-credential** authentication: the configured `client_id` / `client_secret` are exchanged for a short-lived access token on the first lookup, and the token is reused until it expires.

## Usage

Reference a DSV secret with:

```
${dsv://<secret-path>/<field-key>}
```

- `<secret-path>` is the DSV secret's path (slash-delimited, matching the DSV REST path). 
- `<field-key>` is a key inside the secret's data map.

The reference is split on its **last** `/`: everything before is the secret path, and the final segment is the field key. A field key is always required.

Example — fetch the `password` key of the secret at `servers/prod-db`:

```
${dsv://servers/prod-db/password}
```

### Example

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
            password: "${dsv://servers/v8000-cisco/password}"
```

The Orb Agent resolves the DSV reference and uses the actual secret value when the policy is applied.

## Secret Polling

If you configure the `schedule` parameter, the Orb Agent periodically re-fetches every secret that was resolved at least once. When a referenced secret value changes, the policies that referenced it are automatically re-applied with the new value.

If a poll fetch fails for a previously cached secret, every policy that referenced it is **removed** from its backend (the policy manager's contract for an invalid-secret signal). Subsequent recovery depends on the active config manager:

- **`config_manager.active: git` or `fleet`**: the policy is re-applied on the next config-manager sync once the secret is reachable again.
- **`config_manager.active: local`**: there is no periodic sync; the operator must restart the agent (or otherwise re-trigger the local config manager) to re-apply policies once DSV is reachable.

If a policy references multiple DSV secrets, a single failed fetch is sticky: that policy is removed even if another referenced secret merely changed value in the same poll cycle.

This is useful for credential-rotation scenarios: rotate a credential in DSV without restarting the Orb Agent or manually updating policies.

## Manual end-to-end validation

### Prerequisites

- A DSV tenant with a client credential (`client_id` / `client_secret`).
- A secret, e.g. at path `orb-test/credential`, with a `password` data field.
- Docker (the `netboxlabs/orb-agent:develop` image is used below; switch to `:latest` once a release containing this integration is published).

### Steps

1. **Provision in DSV:** create a client credential and grant it read access to `orb-test/credential`; set `password=hunter2-OBS1378` on that secret.

2. **Write `agent.yaml`** in the current directory (the agent refuses to start with `backends: {}`, so include a minimal `device_discovery` backend plus a local policy referencing the DSV secret):

   ```yaml
   version: 1.0
   orb:
     secrets_manager:
       active: dsv
       sources:
         dsv:
           tenant: "<your-tenant>"
           client_id: "<client-id>"
           client_secret: "${DSV_CLIENT_SECRET}"
           schedule: "*/1 * * * *"
     backends:
       device_discovery:
       common: {}
     policies:
       device_discovery:
         orb-test-policy:
           config:
             schedule: "*/5 * * * *"
             defaults:
               site: orb-test
           scope:
             - driver: ios
               hostname: 192.0.2.1
               username: demo
               password: "${dsv://orb-test/credential/password}"
     config_manager:
       active: local
       sources:
         local:
           config: /opt/orb/agent.yaml
   ```

3. **Run with debug logging:**

   ```bash
   docker pull netboxlabs/orb-agent:develop
   export DSV_CLIENT_SECRET='<client secret>'
   docker run --rm --net=host \
     -v "${PWD}":/opt/orb/ \
     -e DSV_CLIENT_SECRET \
     netboxlabs/orb-agent:develop run -c /opt/orb/agent.yaml -d
   ```

4. **Verify auth + lookup:** in the debug log, confirm the `device_discovery` backend accepts the policy without a `failed to solve secrets` error.

5. **Verify rotation:** change the `password` field of `orb-test/credential` in DSV. Within one minute, the agent detects the change and re-applies the policy with the new value.

6. **Negative checks:**
   - Wrong client secret → the first secret fetch fails with a clear authentication error.
   - Bad placeholder grammar (for example `${dsv://mysecret}` with no field key) → policy apply fails with a parse error.

### Pass criteria

- The resolved secret value reaches the backend.
- A live rotation triggers a policy re-apply within one cron interval.
- Failure paths produce comprehensible errors in the agent log.
