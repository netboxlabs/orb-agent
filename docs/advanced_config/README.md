# Advanced Configuration

Settings that apply to the agent as a whole rather than to one backend or
policy.

- [Environment-Driven Configuration](env_config.md) — layer `ORB_*` environment
  variables over the YAML file to set or override any `orb.*` value without
  editing or templating it. Most often used to select and configure the secrets
  manager at deploy time, but it works for any config key.
- [Outbound Proxy Support](outbound_proxy.md) — reaching a remote Diode target
  through a corporate forward proxy. The agent honours the standard proxy
  environment variables, so no extra flags are needed.
- [Running as a Non-Root User](non_root_user.md) — running the agent as a
  UID other than root, what needs a passwd entry or a writable home directory,
  and the features that still need root.
