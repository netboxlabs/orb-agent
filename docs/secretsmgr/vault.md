# HashiCorp Vault

The Orb Agent can integrate with HashiCorp Vault to securely manage sensitive information such as passwords and API keys. This feature allows you to reference secrets stored in Vault directly in your policy configurations without hardcoding sensitive values.

## Configuration

The Vault secrets manager is configured in the `secrets_manager` section of your Orb Agent configuration file:

```yaml
orb:
  secrets_manager:
    active: vault
    sources:
      vault:
        address: "https://vault.example.com:8200"
        namespace: "my-namespace"  # Optional
        timeout: 60  # Optional, in seconds
        auth: "token"  # Required, see authentication methods below
        auth_args:     # Required, depends on the auth method
          token: "${VAULT_TOKEN}"
        schedule: "*/5 * * * *"  # Optional, cron format for polling interval
```

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `address` | string | Yes | The URL of your Vault server |
| `namespace` | string | No | Vault Enterprise namespace |
| `mount` | string | No | Default KV-v2 mount path. When set, placeholders may omit the mount and use the short form `${vault://path/to/secret/key}`. Supports multi-segment mounts (e.g. `foo/bar`). |
| `timeout` | int | No | Request timeout in seconds (default: 60) |
| `auth` | string | Yes | Authentication method (see below) |
| `auth_args` | map | Yes | Authentication method arguments |
| `schedule` | string | No | Cron expression for secret polling interval |

The `address` can carry a user and password for a proxy that asks for basic
auth in front of Vault, as in `https://user:password@vault.example.com:8200`.
The agent sends them as basic auth on every request. Wherever it logs or
reports the address, and in the errors of its requests to Vault, the password
is masked as `********` or left out, as is the user when there is no password.
A `/`, `?`, `#`, `%` or space in the user or password must be percent-encoded:
the agent refuses an address no URL parser reads, without quoting it.

## Authentication Methods

The Vault secrets manager supports several authentication methods.

Wherever the agent reports or logs its configuration, it masks every value of
`auth_args` as `********`, whatever the method, including a value written as
unquoted digits, nested or in a list. It keeps `mount_path`, `username`, `role`
and `service_account_file`, which name no credential, and a `true` or `false`
such as `wrapping_token`. An AppRole's `role_id` is masked too because, for a
role that binds no `secret_id`, Vault accepts a login with the `role_id` alone.
The agent itself still asks for a `secret_id`.

### Token Authentication

```yaml
auth: "token"
auth_args:
  token: "s.abcdefghijklmnopqrstuvwxyz"
```

### AppRole Authentication

```yaml
auth: "approle"
auth_args:
  role_id: "12345678-abcd-efgh-ijkl-123456789012"
  secret_id: "98765432-zyxw-vusr-qpon-987654321098"
  wrapping_token: false  # Optional
  mount_path: "approle"  # Optional
```

### UserPass Authentication

```yaml
auth: "userpass"
auth_args:
  username: "myuser"
  password: "mypassword"
  mount_path: "userpass"  # Optional
```

### Kubernetes Authentication

```yaml
auth: "kubernetes"
auth_args:
  role: "orb-agent"
  service_account_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"  # Optional
  mount_path: "kubernetes"  # Optional
```

### LDAP Authentication

```yaml
auth: "ldap"
auth_args:
  username: "myuser"
  password: "mypassword"
  mount_path: "ldap"  # Optional
```

## Usage

The Orb Agent supports three reference grammars; pick whichever fits your Vault layout. They are checked in priority order — fully qualified, short form, then legacy.

### Fully qualified (recommended for multi-segment mounts)

```
${vault://<mount>//<path-segments>/<key>}
```

The `//` separator marks the end of the mount, so multi-segment mounts work unambiguously. Examples:

```
${vault://kv//app/cred/password}              # mount=kv,        path=app/cred,  key=password
${vault://foo/bar//app/cred/password}         # mount=foo/bar,   path=app/cred,  key=password
${vault://team/svc/prd//api/key}              # mount=team/svc/prd, path=api,    key=key
```

### Short form (uses configured default `mount`)

When `sources.vault.mount` is set, you can omit the mount from each placeholder:

```yaml
sources:
  vault:
    mount: foo/bar
```

```
${vault://<path-segments>/<key>}
```

Example — with the YAML above, the placeholder resolves against `foo/bar`:

```
${vault://app/cred/password}                  # mount=foo/bar (from yaml), path=app/cred, key=password
```

> ⚠ **When `sources.vault.mount` is set, every unqualified placeholder is interpreted as path-only under that mount.** A placeholder that looks legacy-style — for example `${vault://kv/app/cred/password}` with `mount: foo/bar` configured — is **not** treated as legacy; it resolves to `mount=foo/bar`, path=`kv/app/cred`, key=`password`, and will almost certainly miss. If you need to target a different mount from the configured default, use the fully qualified form: `${vault://kv//app/cred/password}`.

### Legacy (single-segment mount, no separator)

For backward compatibility with placeholders that pre-date the `//` separator:

```
${vault://<mount>/<path-segments>/<key>}
```

The first segment is assumed to be a single-segment mount. **Only works for mounts mounted at one path segment**; multi-segment mounts will resolve to the wrong API endpoint and fail. Use the qualified form above for those.

```
${vault://kv/path/credentials/password}       # mount=kv, path=path/credentials, key=password
```

### Example

Here's an example of using Vault secrets in a device discovery policy:

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
            password: "${vault://secret/cisco/v8000/password}"
```

The Orb Agent will resolve the Vault reference and use the actual secret value from Vault when the policy is applied.

## Token lifetime

The agent logs in to Vault when it starts. It renews the token it gets while
Vault renews it, and logs in again with the same method once Vault renews it
no longer: at its max TTL, or when renewals keep failing. A read that Vault
refuses because the token is no longer valid also logs in again and reads
again: a token revoked, or one Vault does not renew (not renewable, or a batch
token), when it ends. Reads that find it so together log in once.

Vault refuses a read with a 403 both for a token that is no longer valid and
for a path the token may not read, so the agent asks Vault about its token
first, and does not log in again for a valid one. Give the token's policy the
`auth/token/lookup-self` capability, as Vault's `default` policy does: without
it, Vault refuses that question too, and the agent can't tell the two apart.

This holds for AppRole, userpass, LDAP and Kubernetes. AppRole logs in again
with the same `secret_id`, so it needs one that can be used again: a wrapped
`secret_id` (`wrapping_token: true`) is unwrapped once, and one with
`secret_id_num_uses` set runs out.

The agent tries to log in again for a read at most once a minute, and as
often after a login that fails: a directory counts failed binds against the
account. A login that fails, as with a `secret_id` that expired or a password
rotated, is logged once at ERROR, as `failed to log in to Vault again`, and
`logged in to Vault again` is logged at INFO once a login works.

Token auth and a wrapped `secret_id` cannot log in again. The agent does not
renew a token given with token auth. When the token ends, the reads fail until
the agent is restarted with valid credentials, and the agent says so once, at
ERROR.

## Secret Polling

If you configure the `schedule` parameter, the Orb Agent will periodically check for changes to referenced secrets. If a secret value changes, the related policies are automatically updated with the new values. If a secret can no longer be read (path deleted, Vault unreachable, a login that fails, a token given with token auth that expired), the agent stops the policies that use it, reports them failed, and re-applies them once a re-fetch succeeds; see [Rotation](README.md#rotation).

This is useful for credential rotation scenarios, where you want to update credentials in Vault without restarting the Orb Agent or manually updating policies.
