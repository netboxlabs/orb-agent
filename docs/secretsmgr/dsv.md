# Delinea DevOps Secrets Vault (DSV)

The Orb Agent can integrate with [Delinea DevOps Secrets Vault (DSV)](https://delinea.com/products/devops-secrets-management-vault) to resolve sensitive values — passwords, tokens, API keys — referenced from your policy and config values, without hardcoding them.

> **DSV is a different product from Delinea Secret Server.** If you use Secret Server, see [the `delinea` provider](./delinea.md) instead. This page documents the `dsv` provider, which reads from DevOps Secrets Vault through its REST API.

> **Note:** The DSV provider is read-only and supports client-credential authentication only.

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
        timeout: 60                             # Optional, seconds one read may take (default 60)
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
| `url_template` | string | No | Advanced override of the URL template (for a regional proxy or gateway), filled in with the tenant, the TLD, the resource (`token` or `secrets`) and the secret path, in that order. When empty, the default `https://%s.secretsvaultcloud.%s/v1/%s%s` is used. |
| `timeout` | int | No | Seconds one read may take, its token request and its secret request together, before it fails. Defaults to `60`. A value of `0` or less means the default. See [Timeouts and failures](#timeouts-and-failures). |
| `schedule` | string | No | Cron expression for periodic polling of cached secrets. When omitted, a secret is read when a policy that references it is applied, and not checked again while it resolves. |

Each string option accepts an environment-variable placeholder of the form `${VAR_NAME}`. The placeholder is resolved at agent startup; an unset referenced variable causes the agent to fail startup with a clear error.

## Authentication

The DSV provider uses **client-credential** authentication: for every read, the configured `client_id` / `client_secret` are exchanged for a short-lived access token at the token endpoint (`/v1/token` under the default URL template), and the secret is then read with that token. The token is used for that read only: the agent keeps it neither in memory nor in its environment, so the backends it starts cannot inherit it.

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

If you configure the `schedule` parameter, the Orb Agent periodically re-fetches every secret its policies reference. When a referenced secret value changes, the policies that referenced it are automatically re-applied with the new value.

If a poll fetch fails for a secret, every policy that references it is stopped on its backend and reported failed, whatever the config manager. The agent keeps polling the secret and re-applies those policies once it resolves again; see [Rotation](README.md#rotation).

If a policy references multiple DSV secrets, a single failed fetch is sticky: that policy is stopped even if another referenced secret merely changed value in the same poll cycle.

This is useful for credential-rotation scenarios: rotate a credential in DSV without restarting the Orb Agent or manually updating policies.

## Timeouts and failures

One read, its token request and its secret request together, fails once `timeout` seconds have passed. A read makes one attempt: a read that fails is read again by the next poll, or when the policy is next applied. So a DSV that accepts the connection and never answers costs a poll `timeout` seconds for each secret it reads, as a poll reads its secrets one after another; keep `timeout` times the number of secrets read under the `schedule` interval, or a poll still running when the next is due skips that one.

A failed read reports why, for example:

- `fetching token: 401 Unauthorized: {"code":401,"message":"..."}`: DSV refused the client credentials.
- `404 Not Found: {"code":404,"message":"..."}`: DSV has no secret at that path.
- `no answer within 1m0s: Get "https://...": context deadline exceeded`: DSV did not answer within `timeout`.
- `fetching token: Post "https://.../v1/token": dial tcp ...: connect: connection refused`: DSV could not be reached.

The error gives the HTTP status of a non-2xx answer and up to 200 characters of its body, or none of the body when it is an HTML page.

## Verifying the integration

### Prerequisites

- A DSV tenant with a client credential (`client_id` / `client_secret`).
- A secret, e.g. at path `orb-test/credential`, with a `password` data field.
- Docker.

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
   docker pull netboxlabs/orb-agent:latest
   export DSV_CLIENT_SECRET='<client secret>'
   docker run --rm --net=host \
     -v "${PWD}":/opt/orb/ \
     -e DSV_CLIENT_SECRET \
     netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml -d
   ```

4. **Verify auth + lookup:** in the debug log, confirm the `device_discovery` backend accepts the policy without a `failed to solve secrets` error.

5. **Verify rotation:** change the `password` field of `orb-test/credential` in DSV. Within one minute, the agent detects the change and re-applies the policy with the new value.

6. **Negative checks:**
   - Wrong client secret → the first secret fetch fails with a clear authentication error.
   - Bad placeholder grammar (for example `${dsv://mysecret}` with no field key) → policy apply fails with a parse error.

### Expected results

- The resolved secret value reaches the backend.
- A live rotation triggers a policy re-apply within one cron interval.
- Failure paths produce comprehensible errors in the agent log.
