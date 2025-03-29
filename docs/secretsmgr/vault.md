# Vault Secrets Manager

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
| `timeout` | int | No | Request timeout in seconds (default: 60) |
| `auth` | string | Yes | Authentication method (see below) |
| `auth_args` | map | Yes | Authentication method arguments |
| `schedule` | string | No | Cron expression for secret polling interval |

## Authentication Methods

The Vault secrets manager supports several authentication methods:

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

To use a secret from Vault in your policy configuration, use the following format:

```
${vault://engine/path/to/secret/key}
```

For example, if you have a KV v2 secret engine mounted at `kv` with a secret at `path/credentials` that has a key `password` with value `secretvalue`, you would reference it as:

```
${vault://kv/path/credentials/password}
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

## Secret Polling

If you configure the `schedule` parameter, the Orb Agent will periodically check for changes to referenced secrets. If a secret value changes, the related policies are automatically updated with the new values.

This is useful for credential rotation scenarios, where you want to update credentials in Vault without restarting the Orb Agent or manually updating policies.
