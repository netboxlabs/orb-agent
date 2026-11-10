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
reports the address, and in the errors of its requests to Vault, the user and
the password are masked together as `********`, as in
`https://********@vault.example.com:8200`, or left out.
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

A value of the wrong type in `auth_args`, such as a string for
`wrapping_token`, stops the agent at start. The error names the field and the
type it takes, as in `auth_args.wrapping_token: expected a bool`, and not the
value.

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
again, as for a token revoked, or for one Vault does not renew (not renewable,
or a batch token) once its TTL ends. Reads that find it so together log in
once. A token that may not look itself up is told ended by its lease instead;
see below.

Vault refuses a read with a 403 both for a token that is no longer valid and
for a path the token may not read, so the agent asks Vault about its token
first, and does not log in again for a valid one. Give the token's policy the
`auth/token/lookup-self` capability, as Vault's `default` policy does: without
it, Vault refuses that question too, and the agent can't tell the two apart.

The agent asks Vault about each token right after it logs in, and waits 5
seconds at most for the answer. When Vault refuses the question with a 403, as
for a role with `token_no_default_policy` set, the agent says so once at WARN.
It then takes that token to have ended only once its lease has: the lease its
login gave, moved by each renewal, or at once when the agent stopped renewing
it without logging in again, as after a login that failed. A read Vault
refuses before then fails, with no login, and one after logs in again. A
token revoked before its lease ends is replaced when the lease ends, and the
reads with it fail until then. A token with no lease, which Vault does not
end, is never taken to have ended: if it is revoked, the reads with it fail
until the agent restarts. The agent asks again after each login, so a
capability granted later counts from the next login. Any other answer, or
none, is taken as for a token that may look itself up.

After a login that replaces a token, the agent revokes the token it replaced
(`auth/token/revoke-self`, which Vault's `default` policy allows), so that it
does not stay valid in Vault until its own TTL. Vault refuses that for a
token that may not revoke itself, or one that already ended: the agent logs
it at DEBUG and goes on.

This holds for AppRole, userpass, LDAP and Kubernetes. AppRole logs in again
with the same `secret_id`, so it needs one that can be used again: a wrapped
`secret_id` (`wrapping_token: true`) is unwrapped once, and one with
`secret_id_num_uses` set runs out.

The agent tries to log in again for a read at most once in 50 seconds, so once
per poll of a one-minute schedule, and as often after a login that fails: a
directory counts failed binds against the account. After a login that fails,
the next read Vault refuses from 50 seconds on tries again. A login that
fails, as with a `secret_id` that expired or a password rotated, is logged at
ERROR as `failed to log in to Vault again` once until a login works again,
and every login that works is logged at INFO as `logged in to Vault again`.

Token auth and a wrapped `secret_id` cannot log in again. The agent does not
renew a token given with token auth. When the token ends, the reads fail until
the agent is restarted with valid credentials, and the agent says so once, at
ERROR.

## Secret Polling

If you configure the `schedule` parameter, the Orb Agent will periodically check for changes to referenced secrets. If a secret value changes, the related policies are automatically updated with the new values. If a secret can no longer be read (path deleted, Vault unreachable, a login that fails, a token given with token auth or from a wrapped `secret_id` that ended, a token that ends within 50 seconds of a try to log in again, a token that may not look itself up and was revoked before its lease ended), the agent stops the policies that use it, reports them failed, and re-applies them once a re-fetch succeeds; see [Rotation](README.md#rotation).

This is useful for credential rotation scenarios, where you want to update credentials in Vault without restarting the Orb Agent or manually updating policies.
