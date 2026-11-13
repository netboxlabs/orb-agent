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
        timeout: 60                     # Optional, seconds one read may take (default 60)
        allowed_vault_hosts: []         # Optional, Delinea Platform only
        schedule: "*/5 * * * *"         # Optional, cron format for polling interval
```

Exactly one of `server_url` or `tenant` must be set. `tenant` is a shorthand that expands to `https://<tenant>.secretservercloud.com`, so it fits only that domain; `server_url` takes the address as given and works for every deployment, which is the one to use if your tenant is on `delinea.app` or a regional domain. The provider does not eagerly authenticate at startup — the first secret fetch performs the OAuth handshake against Delinea.

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `server_url` | string | Cond. | Full URL of the Secret Server, including the scheme and with no trailing path. Use this for on-prem and Delinea Platform deployments, and for any cloud tenant whose hostname is not `<tenant>.secretservercloud.com`, such as a `delinea.app` tenant or a regional `secretservercloud.eu` one. It must not carry a user, a password, a query or a fragment. An `http://` URL works, but sends the service user's password and every secret read unencrypted, and the agent logs a warning at startup when it is set: see [Plain HTTP](#plain-http). Mutually exclusive with `tenant`. |
| `tenant` | string | Cond. | Subdomain of a Secret Server Cloud tenant on `secretservercloud.com`, for example `acme` for `acme.secretservercloud.com`. The rest of the hostname is fixed, so any other domain needs `server_url` instead. Mutually exclusive with `server_url`. |
| `username` | string | Yes | Service-user username with `View Secret` permission on the referenced secrets. |
| `password` | string | Yes | Password for the service user. |
| `timeout` | int | No | Seconds one read may take, from the first request to the last byte of the answer, before it fails. Defaults to `60`. A value of `0` or less means the default. See [Timeouts and failures](#timeouts-and-failures). |
| `allowed_vault_hosts` | list of strings | No | Delinea Platform only. Hosts, as `host` or `host:port`, that the agent may send its reads to when the Platform names a vault on a host of its own. Empty by default, which trusts a vault on the Platform's own host and port, and one on a Delinea Cloud domain (`secretservercloud.com` and its regional domains) on port 443. See [Delinea Platform vaults](#delinea-platform-vaults). |
| `schedule` | string | No | Cron expression for periodic polling of cached secrets. When omitted, a secret is read when a policy that references it is applied, and not checked again while it resolves. |

Each of `server_url`, `tenant`, `username`, and `password` accepts an environment-variable placeholder of the form `${VAR_NAME}`. The placeholder is resolved at agent startup; an unset referenced variable causes the agent to fail startup with a clear error.

### Plain HTTP

A `server_url` beginning with `http://` is used as given, but the service user's password and every secret read then cross the network unencrypted. When the agent starts with such a URL, it logs one warning:

```
delinea: Secret Server is reached over plain HTTP; the service user's password and the secrets read cross the network unencrypted
```

Use `https://` wherever the Secret Server offers it.

### Delinea Platform vaults

On the Delinea Platform, the agent asks the Platform's vault broker for its default vault and reads secrets from the vault's URL. That URL must use `https`. The agent trusts a vault on the Platform's own host and port, and one on a Delinea Cloud domain on port 443. A vault on any other host, such as an on-premises Secret Server the Platform fronts, is refused with `untrusted vault host "<host>"` until its host is listed in `allowed_vault_hosts`:

```yaml
        allowed_vault_hosts:
          - "vault.corp.example.com"        # port 443
          - "vault2.corp.example.com:8443"  # another port
```

An entry without a port matches the host on port 443 only. An entry must not carry a scheme or a path.

## Authentication

The Delinea SDK supports username/password authentication only. The Orb Agent uses the same set of credentials for both Secret Server Cloud and on-prem/Platform deployments. On its first read, the agent asks the server at `server_url` whether it is a Secret Server or the Delinea Platform, and signs in accordingly: on the Platform, `username` and `password` are the client ID and secret of a Platform service account.

The access token is kept in the agent's memory, and requested again when it expires or the server rejects it. It is not written to the agent's environment, so the backends the agent starts do not inherit it.

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

If you configure the `schedule` parameter, the Orb Agent will periodically re-fetch every secret its policies reference. When a referenced secret value changes, the policies that referenced it are automatically re-applied with the new value.

If a poll fetch fails for a secret, every policy that references it is stopped on its backend and reported failed, whatever the config manager. The agent keeps polling the secret and re-applies those policies once it resolves again; see [Rotation](README.md#rotation).

If a policy references multiple Delinea secrets, a single failed fetch is sticky: that policy is stopped even if another referenced secret merely changed value in the same poll cycle.

This is useful for credential rotation scenarios, where you want to rotate credentials in Delinea without restarting the Orb Agent or manually updating policies.

## Timeouts and failures

One read of a secret, from the first request to the last byte of the answer, fails once `timeout` seconds have passed. On the first read, that includes asking the server what it is and signing in. Each read makes one attempt: a read that fails is not retried at once, but is read again by the next poll, or when the policy is next applied. So a Secret Server that accepts the connection and never answers costs a poll `timeout` seconds for each secret it reads, as a poll reads its secrets one after another; keep `timeout` times the number of secrets read under the `schedule` interval, or a poll still running when the next is due skips that one.

A failed read reports why, for example:

- `transport error: ... connection refused` or `... connection reset by peer`: the server could not be reached, or dropped the connection.
- `timed out: ... context deadline exceeded`: the server did not answer within `timeout`.
- `access denied: token endpoint returned 400 Bad Request: ...`: the server refused the service user's credentials.
- `404 Not Found: (response body withheld because the request contained sensitive data)`: the server answered with an error status.

When Secret Server answers a read with an error status, the error gives the status but not the body of the answer, which the SDK withholds since it may echo part of the request. Failure reasons are therefore shorter than in agent releases before the SDK withheld them.

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

4. **Verify auth + lookup:** in the debug log, look for one line per distinct reference, the first time it is resolved, of the form `Resolved secret scheme=delinea ref=path/orb-test/orb-test-credential/password policy_id=…`, followed by the `device_discovery` backend accepting the policy without a `failed to solve secrets` error.

5. **Verify rotation:** change the password of `orb-test-credential` in the Delinea UI to `rotated-hunter2`. Within one minute, the agent logs `Detected changed secret scheme=delinea ref=path/orb-test/orb-test-credential/password` and re-applies the policy with the new value.

6. **Negative checks:**
   - Wrong service-user password → the first secret fetch fails with a clear authentication error.
   - Bad placeholder grammar (for example `${delinea://id/abc/password}`) → policy apply fails with a parse error.

### Expected results

- The resolved secret value reaches the backend.
- A live rotation triggers a policy re-apply within one cron interval.
- Failure paths produce comprehensible errors in the agent log.
