# Secrets Manager

The secrets manager resolves secret references when a policy is applied, so
credentials live in your secret store rather than in `agent.yaml`. A policy
writes a reference where the value would go:

```yaml
scope:
  - driver: ios
    hostname: 192.0.2.10
    username: admin
    password: "${vault://secret/devices/password}"
```

One provider is active at a time, selected by `orb.secrets_manager.active`, and
configured under `sources`:

```yaml
orb:
  secrets_manager:
    active: vault
    sources:
      vault:
        address: "https://vault.example.com:8200"
```

| Provider | `active` | Reference form |
|:--|:--|:--|
| [HashiCorp Vault](vault.md) | `vault` | `${vault://<mount>/<path>/<key>}` |
| [Doppler](doppler.md) | `doppler` | `${doppler://<project>/<config>/<secret>}` |
| [CyberArk (CCP)](cyberark.md) | `cyberark` | `${cyberark://<Safe>/<Object>/<Field>}` |
| [Delinea Secret Server](delinea.md) | `delinea` | `${delinea://path/<folder>/<name>/<field>}` |
| [Delinea DevOps Secrets Vault (DSV)](dsv.md) | `dsv` | `${dsv://<secret-path>/<field-key>}` |

Each provider's page documents its own reference forms in full, since most
accept more than one.

Leaving `active` unset or empty skips the secrets manager and the agent starts
normally. A value that is set but not recognised fails startup with an error
naming the supported types.

The provider and its settings can also be chosen entirely from the environment,
without editing the YAML, which suits injecting them at deploy time. See
[Environment-Driven Configuration](../advanced_config/env_config.md).

The agent logs a policy it applies by its ID and name only, at every log level,
so its own lines carry no resolved values. With debug logging on, the provider
logs the references it resolves, never the values. See
[Debug Logging](../config_samples.md#debug-logging). The provider's own
credentials in the agent's configuration, such as a token, a password, a client
secret or any value of a Vault login's `auth_args` but its mount path, user
name, role and service account file, are masked as `********` wherever the
agent reports or logs its configuration, as are the user and the password of
a URL in it, such as a Vault address's, together. So are those of each URL of
a list, as `https://u:p@a.example,https://u:p@b.example`, of a URL in another
one's query or fragment, as after its `?`, `&` or `#`, and of a URL used as a
key. Two keys masked into the same one are both kept: in the order of
the keys as written, each one after the first gets ` (2)`, ` (3)` and so on
after it. A URL written without `//` whose part before its last `@` holds a
`:` and no space, as `user:password@host` or git's
`<token>:x-oauth-basic@host:path`, has all of that part masked from the start
of its word, a scheme written before it too, as `mailto:`: `********@host`.
Where the agent can't tell where a user and password end, as for an `@` in a
URL's path, a password holding a space, a `,` or a `//`, or URLs that a space
or a line break separates, it masks from the `//`, the first `:` or the start
of the text to the last `@`, hiding what lies between, hosts included. Before
a password with a space, the user is kept. Kept as written are an e-mail
address written alone, as `ops@example.com`, a secret reference, whatever
its path or field holds but a `}`, and a URL with a `/` before the `:` of its
user and password, which git reads as a local path. A `${vault://...}` whose
body holds a URL with a user info, one with a `:` or an `@` between its `://`
and its first `/`, or a `user:password@` word, as one that no `}` closes
before a URL takes in, is no reference, and is masked as the rest of the text
is. Another `://` is kept, as in CyberArk's
`${cyberark://AppID://Safe/Object}`, whatever its names hold. An image with a digest, as
`img:tag@sha256:...`, is masked before its `@` as a user would be, since
nothing tells it from git's `user@host:path`, unless a `/` comes before its
first `:`, as in `ghcr.io/org/img:tag@sha256:...`. The configuration the agent reports is the one as
written: a secret reference in it, such as one in `backends`, is reported as
the reference, never as the value it resolves to.

A backend that refuses a policy can quote one of its values in the error, as a
type error does for a reference in a field that takes a number. Before the
agent logs that error or reports it as the policy's error, it masks each
resolved value as `********`:

- the whole value, and its first or last 7 bytes or more, as a backend that
  shortens a value quotes it, including first bytes that end inside a
  character;
- the same escaped, as Go or JSON quote a string, or as Python's `repr` does;
- for a value of several lines, such as a private key, each of its lines of 7
  bytes or more wherever it occurs whole, trimmed of the spaces around it, as
  a backend that prints the value line by line quotes it.

Nothing is masked in the error wording the agent recognises, whatever the
length of the value:

- the status code in front of an HTTP refusal;
- the wording of a YAML decoding error: the `yaml: unmarshal errors:` heading,
  the `yaml: line N: ` in front of a syntax error, and each `cannot unmarshal`
  type error on a line of its own (`line 4: cannot unmarshal !!str ... into
  int`), apart from the value it quotes;
- device-discovery's refusal of a field of the wrong type, a field missing or
  one not allowed: each of pydantic's messages for those, such as
  `Input should be a valid integer, unable to parse string as an integer`,
  with the field and the error type that come with it. These quote nothing of
  the value, so such a refusal has nothing masked and no note. A message of
  one of device-discovery's own checks, such as one about a device's rack
  position, can quote a value, so its words are not left alone. The field is
  read as the path to it, of field names, list positions and keys, so for a
  policy whose name has a space in it, the agent can't tell where the field
  ends, and masks a short value in the message as anywhere else.

A value such as `int`, `line` or `marshal` is masked where such an error
quotes it and left where it is one of those words or a run of them, so the
error stays readable and doesn't show which words the value is. A value
shorter than 7 bytes is also masked only where it is a word of its own, and
not where it runs into that wording. Anywhere else the agent can't tell a
value from the error's own words, so a value that is one of them, or a run of
them 7 bytes or longer, is masked there too, which shows which words it is.
That includes the rest of a YAML syntax error, such as `key` in
`yaml: line 3: did not find expected key`. Any other run from the middle of a
value is left alone, since it is more likely the error's own words. The agent
then names the fields whose values
the error quotes, because the backend's error points at a line of the policy
as the agent sent it, not at a field you wrote:

```text
400 yaml: unmarshal errors:
  line 4: cannot unmarshal !!str `********` into int (the error quotes the value of the secret reference at config.retries, masked as ********)
```

When one secret reference fills several fields, the note names them all. When
references in different fields hold the value the error quotes, it names none
of them and says the error quotes the value of a secret reference: only the
value shows what the error quotes, and naming the fields would also show that
their secrets are equal.

Only part of a refusal is kept: the agent logs at most 8 KiB of it and reports
at most 1 KiB as the policy's error. A refusal that is cut ends with
`... (truncated)`, followed by the note naming the fields.

A backend can also quote a value after it accepted the policy: in the reason
it reports for a run, which can carry an exception's text, or in a line its
process prints, which the agent relays into its own log. The agent masks both
the same way, and keeps at most the same 1 KiB of a run's reason, followed by
the note naming the fields it quotes. A printed line names no policy, so the
agent masks in it the values of every policy that backend runs. A run's
targets and driver, which a backend can copy from the policy's scope, are
masked when one is a value whole, as it is or as a backend writes a host it
was given: without its line breaks, an address or a prefix in its canonical
form (`2001:db8::1` for `2001:DB8::1`), or with a port added
(`[2001:db8::1]:9339`). The agent compares the two without their line breaks
or the spaces around them, and whatever the case of their letters, as host
names are compared. It masks a reason or a printed line that quotes a value
in those forms, or in lower case, too. Any other target is kept as reported:
a short value such as a port does not mask a part of a host name, and the
addresses a backend expands a range or a prefix into are not masked either.

To mask them, the agent keeps the values of a policy's last two resolutions
that differ, for as long as it runs the policy: after an edit or a rotation,
the backend goes on reporting a run it ran with the earlier values. A
discovery backend keeps each target's runs across the policy's re-applies,
and a policy's runs after it is removed, under the policy's name. So the
agent stores and reports only the runs a backend started after the agent
began to apply the policy's previous resolution, or its only one on that
backend, and masks them with the values of the last three resolutions: a
backend removes the policy before it applies an update, and until then it can
still start a run with the resolution before. An earlier run can quote a
value the agent no longer keeps, or one of another policy the backend ran
under the name, and is not stored. A policy stored without being applied,
because its secrets did not resolve or its backend was not ready, keeps none
of the runs reported under its name. A run without a start time is kept
whatever its policy, since nothing tells when it began; every discovery
backend gives each run one. A backend that fails to remove the policy for two
updates in a row can go on running a value the agent no longer keeps. When
the policy is removed, or moved to another backend, its values keep masking
the output of the backend it ran on for a minute, for the lines it printed
before. A backend can also go on with a run of the policy it started before:
device-discovery stops a removed policy without waiting for its runs. For as
long as the backend reports a run still running under a name the agent
applied the policy with, its values keep masking the backend's output, and
for a minute after the last such report, up to an hour after the policy left
it. The agent then drops them. A backend reports the runs of every policy it
knew by a name under that name, so the agent can't tell the removed policy's
run from that of a policy that took its name since: a run of the new policy
keeps the removed policy's values masking the backend's output too, up to
the hour. A line a backend prints about the policy after that is relayed as
printed: one from a run that goes on for more than an hour, or one from a
backend that failed to remove the policy and starts another run of it on its
schedule more than a minute after the last one it reported running.

## Rotation

Every provider takes an optional `schedule`, a cron expression for re-fetching
the secrets the agent's policies reference. When a referenced value changes,
the policies that use it are re-applied with the new value, so credentials can
be rotated without restarting the agent.

When a re-fetch fails, because the secret was deleted, the provider can't be
reached or the agent's own credentials to it expired, the agent stops the
policies that use the secret. It keeps them and reports each one failed with
a reason that starts with `failed to resolve policy secrets:` and names the
reference, as it does for a secret that doesn't resolve the first time a
policy is applied. The agent goes on reading the secret on the schedule:

- once the secret resolves again, the policies are re-applied, with no
  restart;
- a policy delivered again meanwhile, by an update to it for example, reads
  the secret again and is applied if it resolves.

A secret that doesn't resolve the first time a policy is applied is read on
the schedule the same way. Only the secrets named by the version of a policy
the agent applied last count: once an update that moves a policy to another
secret is applied, the one it used before can be deleted, and a removed
policy depends on none.

The agent stops the policies whatever made the read fail, so a provider that
can't be reached for a moment costs them collection until the next read that
succeeds: a schedule interval at least, more when a poll waits on a provider
that doesn't answer. A policy that runs once is run again when it is
re-applied, as it is when a value changes. The failure is logged once, at
ERROR, as `Failed to retrieve secret during polling`, and a poll that finds
the secret resolving again logs `Secret resolves again` at INFO.

Without a `schedule`, the agent reads a secret only when it applies a policy,
so a policy whose secret didn't resolve is applied again when it is delivered
again or the agent restarts.

The agent keeps its own login to Vault going: it logs in again when its token
ends, so its policies keep running without a restart, unless it was given a
token with token auth or a wrapped `secret_id`, which it cannot log in again
with. See [Token lifetime](vault.md#token-lifetime).
