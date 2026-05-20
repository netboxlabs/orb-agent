# CyberArk Secrets Manager (beta)

The Orb Agent can integrate with [CyberArk Privileged Access Manager (PAM)](https://www.cyberark.com/products/privileged-access-manager/) via the Central Credential Provider (CCP) to retrieve secrets at runtime. This feature allows you to reference accounts stored in CyberArk directly in your policy configurations without hardcoding sensitive values.

> **Beta:** Validated via unit tests against a fake CCP HTTP server. End-to-end validation against a real CCP deployment is the next step.

## Prerequisites

Before configuring the agent, the CyberArk administrator must provision:

1. An **AppID** record in the Vault representing the orb-agent instance.
2. **Authentication evidence** on the AppID: a client certificate's Common Name / Subject, an IP allowlist of the agent hosts, an OS user, or a hostname.
3. **Safe access**: every Safe the agent will read from must grant the AppID the `Retrieve Accounts` permission.
4. **Account naming**: pick a consistent Object naming scheme so YAML placeholders are stable across rotations.

## Configuration

The CyberArk secrets manager is configured in the `secrets_manager` section of your Orb Agent configuration file:

```yaml
orb:
  secrets_manager:
    active: cyberark
    sources:
      cyberark:
        url: "https://ccp.corp.example.com"        # required — base URL of the CCP service
        app_id: "orb-agent"                        # required — provisioned in the Vault
        reason: "orb-agent policy resolution"      # optional — written to the CyberArk audit log on every fetch
        ca_bundle:   "/opt/orb/secrets/ccp-ca.pem" # optional — PEM CA chain for the CCP server cert
        client_cert: "/opt/orb/secrets/orb.crt"    # optional — client cert for mTLS to CCP
        client_key:  "/opt/orb/secrets/orb.key"    # optional — client key for mTLS to CCP
        timeout: 60                                # optional — HTTP timeout in seconds (default 60)
        schedule: "*/5 * * * *"                    # optional — cron format for polling interval
```

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `url` | string | Yes | Base URL of the CCP web service, e.g. `https://ccp.corp.example.com`. A trailing slash is trimmed automatically. |
| `app_id` | string | Yes | CyberArk AppID provisioned for this agent. Used in every short-form lookup and as the default for qualified ones. |
| `reason` | string | No | Free-text reason written to the CyberArk audit log on every fetch. Increases audit fidelity at the cost of one log line per fetch (including polling re-fetches). |
| `ca_bundle` | string | No | Path to a PEM file containing the CA chain that signed the CCP server cert. Only needed when the CCP cert is not signed by a publicly-trusted CA. |
| `client_cert` / `client_key` | string | No (must be set together) | Paths to a client cert/key pair for mTLS to CCP. Required when the CyberArk admin authenticates this AppID by client certificate. |
| `skip_tls_verify` | bool | No | Disables peer-cert verification. Logged at WARN at startup. Lab / development only. |
| `timeout` | int | No | HTTP timeout in seconds (default `60`). |
| `schedule` | string | No | Cron expression for periodic polling of cached secrets. When omitted, secrets are fetched once on first reference and never re-checked. |

The following fields accept an environment-variable placeholder of the form `${VAR_NAME}`: `url`, `app_id`, `reason`, `ca_bundle`, `client_cert`, `client_key`. Placeholders are resolved at agent startup; an unset variable causes the agent to fail startup with a clear error.

## Authentication

CCP authenticates the *requesting application* (the orb-agent process), not a user. CyberArk supports several mechanisms; pick whichever fits your environment:

- **Client certificate (recommended for production)**: set `client_cert` and `client_key`, and ensure the CyberArk admin configured the AppID to require the matching certificate Common Name.
- **IP allowlist**: nothing on the agent side; the CyberArk admin allowlists the agent host's IP on the AppID.
- **OS user / hostname**: nothing on the agent side; rarely used cross-OS.

The agent does not eagerly authenticate at startup — the first secret fetch is what surfaces a 401/403, with the error visible in the policy-apply log.

## Usage

The Orb Agent supports four reference shapes. Use whichever is most concise for your environment.

> **Reserved characters.** The `/` character is reserved by the placeholder grammar and may not appear inside any AppID, Safe, Object, or Field name referenced from a placeholder. CyberArk itself permits a wider character set for these names; if your existing accounts use `/` in their identifiers, you must either rename them or open a follow-up issue requesting percent-escape (`%2F`) support.

### Short form

```
${cyberark://<Safe>/<Object>}
```

Uses the AppID from `sources.cyberark.app_id` and returns the `Content` field (the password). Example:

```
${cyberark://Lab-DB/cisco-svc-account}
```

### Short form with field selector

```
${cyberark://<Safe>/<Object>/<Field>}
```

Returns the named field instead of `Content`. Useful for `UserName`, `Address`, `Database`, etc.

```
${cyberark://Lab-DB/cisco-svc-account/UserName}
```

### Fully qualified

```
${cyberark://<AppID>//<Safe>/<Object>}
```

Overrides the configured AppID for this one placeholder. Useful when the same orb-agent instance fetches from multiple CyberArk tenants. The `//` separator marks the end of the AppID.

```
${cyberark://OtherTenant//Lab-DB/cisco-svc-account}
```

### Fully qualified with field selector

```
${cyberark://<AppID>//<Safe>/<Object>/<Field>}
```

```
${cyberark://OtherTenant//Lab-DB/cisco-svc-account/UserName}
```

### Example

```yaml
orb:
  policies:
    device_discovery:
      discovery_1:
        schedule: "0 * * * *"
        defaults:
          site: NY
        scope:
          - driver: ios
            hostname: 10.1.2.24
            username: "${cyberark://Lab-DB/cisco-svc-account/UserName}"
            password: "${cyberark://Lab-DB/cisco-svc-account}"
```

The Orb Agent will resolve the CyberArk references and use the actual values when the policy is applied.

## Secret Polling

If you configure the `schedule` parameter, the Orb Agent will periodically re-fetch every cached secret. When a value changes, the related policies are automatically updated. The change is logged at INFO as `Detected changed secret scheme=cyberark ref=<body>` so operators can confirm a rotation has propagated. If a secret becomes unreachable (account deleted, AppID revoked, network failure), the provider evicts the cache entry and the policy manager marks the affected policies as failed; the policy can recover only after a successful re-fetch.

This is useful for credential rotation scenarios, where you want to update credentials in CyberArk without restarting the Orb Agent or manually updating policies.
