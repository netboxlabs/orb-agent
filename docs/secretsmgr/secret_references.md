# Provider-agnostic secret references

Every secrets manager (Vault, Delinea, Doppler, CyberArk, and Fleet) accepts its own
placeholder scheme — `${vault://…}`, `${delinea://…}`, `${doppler://…}`,
`${cyberark://…}`, `${fleet://…}` — in policy and configuration fields. Alongside those,
the Orb Agent also accepts a provider-agnostic scheme:

```
${secret://<body>}
```

`${secret://<body>}` is resolved by whichever secrets manager is **active** on the
agent (the `secrets_manager.active` setting): Vault, Delinea, Doppler, CyberArk, or
Fleet. This lets a policy or config value reference a managed secret without naming
a specific provider, so the same placeholder can be reused across agents configured
with different secrets managers.

## Body grammar is unchanged

`secret://` only replaces the provider name in the placeholder — it does not change
how the body is interpreted. The active provider parses `<body>` exactly as it would
the body of its own scheme. For example, if Vault is active:

```
${secret://kv//app/cred/password}
```

resolves identically to:

```
${vault://kv//app/cred/password}
```

See each provider's own documentation for its body grammar:

- [HashiCorp Vault](./vault.md)
- [Doppler](./doppler.md)
- [CyberArk (CCP)](./cyberark.md)
- [Delinea Secret Server](./delinea.md)
- Fleet — path-style references (`${fleet://path}`) delivered by the fleet control plane

Provider-specific schemes keep working unchanged — `${secret://…}` is purely an
additional, optional alternative form; it does not deprecate or replace them.

## No secrets manager configured

If no secrets manager is active (`secrets_manager.active` is unset or invalid), a
policy or config value that uses a `${secret://…}` reference fails fast with a
clear error rather than being forwarded to the backend as a literal string:

```
a managed secret reference (${secret://<body>}) was found but no secrets manager is configured
```

Provider-specific schemes (`${vault://…}` etc.) keep their pre-existing behavior
and pass through unresolved in this case.

## Fleet secrets manager and config-level references

With the **fleet** secrets manager active, secret references inside the agent's own
configuration (backend settings, `config_manager` fields) cannot be resolved: config
resolution runs at startup, before the MQTT session that fleet secret requests
travel over is established, and the agent fails to start with a clear error. This
is a pre-existing property of the fleet provider and applies equally to
`${fleet://…}` and `${secret://…}` config references. References inside
**policies** are unaffected — policies arrive after the connection is up. The
other providers resolve config-level references at startup normally.
