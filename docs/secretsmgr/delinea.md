# Delinea Secret Server

The Orb Agent can integrate with [Delinea Secret Server](https://delinea.com/products/secret-server/) (both Secret Server Cloud and on-prem / Platform) to securely manage sensitive information such as passwords and API keys. This feature allows you to reference secrets stored in Delinea directly in your policy configurations without hardcoding sensitive values.

> **Note:** The Delinea provider is read-only and supports username/password authentication only.

## Configuration

The Delinea secrets manager is configured in the `secrets_manager` section of your Orb Agent configuration file:

```yaml
orb:
  secrets_manager:
    active: delinea
    sources:
      delinea:
        server_url: ""                  # Full URL, any deployment (XOR with tenant)
        tenant: "<your-tenant>"         # Subdomain, *.secretservercloud.com only (XOR with server_url)
        username: "svc_orb"
        password: "${DELINEA_PASSWORD}"
        schedule: "*/5 * * * *"         # Optional, cron format for polling interval
```

Exactly one of `server_url` or `tenant` must be set. `tenant` is a shorthand that expands to `https://<tenant>.secretservercloud.com`, so it fits only that domain; `server_url` takes the address as given and works for every deployment, which is the one to use if your tenant is on `delinea.app` or a regional domain. The provider does not eagerly authenticate at startup — the first secret fetch performs the OAuth handshake against Delinea.

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `server_url` | string | Cond. | Full URL of the Secret Server, including the scheme and with no trailing path. Use this for on-prem and Delinea Platform deployments, and for any cloud tenant whose hostname is not `<tenant>.secretservercloud.com`, such as a `delinea.app` tenant or a regional `secretservercloud.eu` one. Mutually exclusive with `tenant`. |
| `tenant` | string | Cond. | Subdomain of a Secret Server Cloud tenant on `secretservercloud.com`, for example `acme` for `acme.secretservercloud.com`. The rest of the hostname is fixed, so any other domain needs `server_url` instead. Mutually exclusive with `server_url`. |
| `username` | string | Yes | Service-user username with `View Secret` permission on the referenced secrets. |
| `password` | string | Yes | Password for the service user. |
| `schedule` | string | No | Cron expression for periodic polling of cached secrets. When omitted, secrets are fetched once on first reference and never re-checked. |

Each of `server_url`, `tenant`, `username`, and `password` accepts an environment-variable placeholder of the form `${VAR_NAME}`. The placeholder is resolved at agent startup; an unset referenced variable causes the agent to fail startup with a clear error.

## Authentication

The Delinea SDK supports username/password authentication only. The Orb Agent uses the same set of credentials for both Secret Server Cloud and on-prem/Platform deployments — the SDK selects the correct endpoint based on whether `tenant` or `server_url` is set.

## Usage

To use a secret from Delinea in your policy configuration, use one of the two reference forms. In either form, `${secret://…}` may be used instead of `${delinea://…}` — see [Provider-agnostic secret references](./secret_references.md).

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

## Verifying the integration

Delinea Secret Server cannot be run locally, since it requires Windows and MSSQL, so this walkthrough uses a free Secret Server Cloud trial tenant.

### Prerequisites

- Free trial tenant from <https://secretservercloud.com>.
- Docker.

### Steps

1. **Provision in Delinea Cloud:**
   - Create a service user `svc_orb` with a strong password.
   - Create folder `/orb-test`.
   - Create a secret `orb-test-credential` (template `Password`) with `password=hunter2-OBS1378`.
   - Grant `svc_orb` the `View Secret` permission on `/orb-test`.

2. **Write `agent.yaml`** in the current directory: the agent refuses to start with `backends: {}`, so the example includes a minimal `device_discovery` backend plus a local policy whose `scope` references the Delinea secret. Replace the `driver` / `hostname` block with whatever device you actually want to discover (or substitute a different backend you already run).

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
           config:
             schedule: "*/5 * * * *"
             defaults:
               site: orb-test
           scope:
             - driver: ios
               hostname: 192.0.2.1
               username: demo
               password: "${delinea://path/orb-test/orb-test-credential/password}"
     config_manager:
       active: local
       sources:
         local:
           config: /opt/orb/agent.yaml
   ```

3. **Pull the image and run with debug logging:**

   ```bash
   docker pull netboxlabs/orb-agent:latest
   export DELINEA_PASSWORD='<svc_orb password>'
   docker run --rm --net=host \
     -v "${PWD}":/opt/orb/ \
     -e DELINEA_PASSWORD \
     netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml -d
   ```

4. **Verify auth + lookup:** in the debug log, look for one line per resolved placeholder of the form `Resolved delinea secret ref=path/orb-test/orb-test-credential/password policy_id=…`, followed by the `device_discovery` backend accepting the policy without a `failed to solve secrets` error.

5. **Verify rotation:** change the password of `orb-test-credential` in the Delinea UI to `rotated-hunter2`. Within one minute, the agent logs `Detected changed delinea secret ref=path/orb-test/orb-test-credential/password` and re-applies the policy with the new value.

6. **Negative checks:**
   - Wrong service-user password → the first secret fetch fails with a clear authentication error.
   - Bad placeholder grammar (for example `${delinea://id/abc/password}`) → policy apply fails with a parse error.

### Expected results

- The resolved secret value reaches the backend.
- A live rotation triggers a policy re-apply within one cron interval.
- Failure paths produce comprehensible errors in the agent log.
