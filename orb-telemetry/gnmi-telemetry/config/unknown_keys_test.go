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
      metrics_intervall: 10
    scope:
      username: admin
      tls:
        skip_verify: true
      targets:
        - host: 192.0.2.1
`)
	require.Contains(t, out, "metrics_intervall")
}

// A misspelled key inside the tls block is dropped like any other unknown key,
// so the block is one of the narrowed types the warning covers. Left unsaid, a
// policy meaning to skip verification would silently verify and every session
// would fail.
func TestUnknownKeyInsideTLSIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      metrics_interval: 60
    scope:
      tls:
        skip_verifi: true
      targets:
        - host: 192.0.2.1
`)
	require.Contains(t, out, "skip_verifi")
}

func TestUnknownKeyOnATargetIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      metrics_interval: 60
    scope:
      username: admin
      targets:
        - host: 192.0.2.1
          prt: 9339
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
      username: admin
      tls:
        skip_verify: true
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
      mode: sample
      profiles_dir: /etc/gnmi
      probe_timeout_ms: 3000
      rescan_interval_ms: 60000
      send_credentials_to_unverified_targets: true
    scope:
      username: admin
      password: s3cret
      port: 9339
      origin: openconfig
      tls:
        skip_verify: true
        insecure: false
        ca: /ca.pem
        cert: /cert.pem
        key: /key.pem
      targets:
        - host: 192.0.2.1
          port: 6030
          id: dev1
          mode: on_change
          profile: nokia_srlinux
          origin: ""
          username: u
          password: p
          tls:
            insecure: true
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
      username: admin
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
