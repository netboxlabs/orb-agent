package config

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureWarnings(t *testing.T, yamlText string) string {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	WarnUnknownPolicyKeys([]byte(yamlText), logger)
	return buf.String()
}

// A mistyped config key is dropped by the permissive decode, and this backend
// parses config keys it does not act on, so without the warning the operator
// sees no difference between a typo and the option being absent.
func TestMistypedConfigKeyIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      metrics_interval: 60
      snmp_timout: 10
    scope:
      authentication:
        protocol_version: v2c
        community: public
      targets:
        - host: 192.0.2.1
`)
	require.Contains(t, out, "snmp_timout")
	assert.NotContains(t, out, "did_you_mean", "a key matching no known block must not get an invented suggestion")
}

// Credentials written one level up, directly under scope, are silently dropped
// and the run then fails as if the community string were wrong.
func TestMisplacedCredentialNamesTheCorrectPath(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      metrics_interval: 60
    scope:
      protocol_version: v2c
      community: public
      targets:
        - host: 192.0.2.1
`)
	require.Contains(t, out, "community")
	require.Contains(t, out, "authentication.community", "the warning must name the path the key belongs at")
}

func TestUnknownKeyInsideAuthenticationIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: v3
        auth_protocl: SHA
      targets:
        - host: 192.0.2.1
`)
	require.Contains(t, out, "auth_protocl")
}

func TestUnknownKeyOnATargetIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: v2c
        community: public
      targets:
        - host: 192.0.2.1
          prt: 1161
`)
	require.Contains(t, out, "prt")
}

// `metrics interval: 60` is a valid YAML mapping key, and yaml.v3 reports it
// with the space intact. Requiring a single non-whitespace token would skip the
// entry, hiding the very mistake this warning exists to surface.
func TestKeyContainingWhitespaceIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      metrics interval: 60
    scope:
      targets:
        - host: 192.0.2.1
`)
	require.Contains(t, out, "metrics interval")
}

// Policy names are operator-chosen, so nothing in the policy map itself has a
// closed set of keys to check against.
func TestPolicyNamesStaySilent(t *testing.T) {
	out := captureWarnings(t, `
policies:
  anything_at_all:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: v2c
        community: public
      targets:
        - host: 192.0.2.1
`)
	assert.Empty(t, out, "a valid policy must not warn")
}

func TestValidPolicyIsSilent(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      metrics_interval: 60
      profiles_dir: /etc/snmp
      snmp_timeout: 5
      retries: 2
    scope:
      authentication:
        protocol_version: SNMPv3
        security_level: authPriv
        username: u
        auth_protocol: SHA
        auth_passphrase: p
        priv_protocol: AES
        priv_passphrase: p
        context_name: ctx
      targets:
        - host: 192.0.2.1
          port: 161
          id: dev1
          authentication:
            protocol_version: v2c
            community: public
`)
	assert.Empty(t, out, "a valid policy must not warn")
}

// schedule is a policy field the discovery backends implement and this one does
// not: every target is scheduled on metrics_interval, and nothing reads a cron
// expression. Carrying the field made a policy asking to be polled at specific
// times poll continuously instead, with nothing said about it. It is reported as
// an unrecognised key rather than accepted, so an operator moving a policy from a
// discovery backend is told the field does nothing here.
func TestScheduleIsReportedAsUnsupported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      schedule: "* * * * *"
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: v2c
        community: public
      targets:
        - host: 192.0.2.1
`)
	assert.Contains(t, out, "schedule", "a policy asking for a cron schedule must be told this backend does not honour one")
}

func TestMalformedYamlIsLeftToThePermissiveDecode(t *testing.T) {
	out := captureWarnings(t, "policies: [this is not a map")
	assert.Empty(t, out, "syntax errors are reported by the real decode")
}

func TestNilLoggerIsSafe(t *testing.T) {
	assert.NotPanics(t, func() {
		WarnUnknownPolicyKeys([]byte("policies:\n  p1:\n    config:\n      bogus: 1\n"), nil)
	})
}
