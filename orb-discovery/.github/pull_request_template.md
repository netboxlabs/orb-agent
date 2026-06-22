## Description

<!-- What does this PR change, and why? -->

## PR title checklist

This repo enforces a Conventional Commits PR title with a scope from the
allowlist (`type(scope): subject`). The title becomes the squashed commit message
and drives the per-backend release. See [`AGENTS.md`](/AGENTS.md) for the full
convention.

- [ ] Title is `type(scope): subject` with a scope from the allowlist:
      `device-discovery`, `gnmi-discovery`, `network-discovery`,
      `snmp-discovery`, `worker`, `ci`, `docs`, `deps`, `deps-dev`, `repo`.
- [ ] Type reflects intent — `feat`/`fix`/`perf` and `chore(deps)` cut a release
      for the scoped backend; other types do not.
- [ ] Changes are scoped to the backend named in the title (or use `repo`).
