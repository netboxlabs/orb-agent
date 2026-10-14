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

// This backend's tuning lives on scope, so a key that lands on config is
// usually meant for scope. Reporting the block it belongs to is the difference
// between a five second fix and a silently ineffective setting.
func TestScopeKeyWrittenOnConfigNamesScope(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      fast_mode: true
    scope:
      targets:
        - 192.0.2.0/24
`)
	require.Contains(t, out, "fast_mode")
	require.Contains(t, out, "scope.fast_mode", "the warning must name the block the key belongs to")
}

func TestDefaultsKeyWrittenOnConfigNamesDefaults(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      network_mask: 24
    scope:
      targets:
        - 192.0.2.0/24
`)
	require.Contains(t, out, "defaults.network_mask")
}

func TestUnknownKeyReportedWithoutSuggestion(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      totally_made_up_key: 42
    scope:
      targets:
        - 192.0.2.0/24
`)
	require.Contains(t, out, "totally_made_up_key")
	assert.NotContains(t, out, "did_you_mean", "a key matching nothing must not get an invented suggestion")
}

// `fast mode: true` is a valid YAML mapping key, and yaml.v3 reports it with
// the space intact. Requiring a single non-whitespace token skipped the entry,
// hiding the very mistake this warning exists to surface.
func TestKeyContainingWhitespaceIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      fast mode: true
    scope:
      targets:
        - 192.0.2.0/24
`)
	require.Contains(t, out, "fast mode")
}

// Only the config block is checked. Warning on blocks that carry
// operator-chosen keys would fire on correct files.
func TestBlocksWithOperatorChosenKeysStaySilent(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    stray_policy_key: 1
    config:
      defaults:
        stray_default: 1
    scope:
      targets:
        - 192.0.2.0/24
      stray_scope_key: 1
`)
	assert.Empty(t, out, "expected silence outside config")
}

func TestValidPolicyIsSilent(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      timeout: 30
      defaults:
        role: undefined
    scope:
      targets:
        - 192.0.2.0/24
      fast_mode: true
`)
	assert.Empty(t, out, "a valid policy must not warn")
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

func TestOptionKeyWrittenOnConfigNamesOptions(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      emit_scan_metadata: false
    scope:
      targets:
        - 192.0.2.0/24
`)
	require.Contains(t, out, "options.emit_scan_metadata")
}

func TestUnknownKeyInOptionsIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      options:
        emit_scan_metdata: false
    scope:
      targets:
        - 192.0.2.0/24
`)
	require.Contains(t, out, "emit_scan_metdata")
}

// An option key under defaults or scope would otherwise be dropped in silence,
// and the option would stay on.
func TestOptionKeyUnderAnotherBlockIsPointedAtOptions(t *testing.T) {
	for name, policy := range map[string]string{
		"defaults": `
policies:
  p1:
    config:
      defaults:
        emit_scan_metadata: false
    scope:
      targets: [192.0.2.0/24]
`,
		"scope": `
policies:
  p1:
    config:
      timeout: 5
    scope:
      emit_scan_metadata: false
      targets: [192.0.2.0/24]
`,
	} {
		t.Run(name, func(t *testing.T) {
			require.Contains(t, captureWarnings(t, policy), "did_you_mean=config.options.emit_scan_metadata")
		})
	}
}

func TestOptionsBesideConfigIsPointedAtConfig(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    options:
      emit_scan_metadata: false
    scope:
      targets: [192.0.2.0/24]
`)
	require.Contains(t, out, "did_you_mean=config.options")
}

// An options block nested under defaults or scope, or a bare option key on the
// policy, would otherwise be dropped in silence as well.
func TestOptionsNestedElsewhereArePointedAtConfig(t *testing.T) {
	for name, tc := range map[string]struct{ policy, want string }{
		"options under defaults": {`
policies:
  p1:
    config:
      defaults:
        options:
          emit_scan_metadata: false
    scope:
      targets: [192.0.2.0/24]
`, "did_you_mean=config.options"},
		"options under scope": {`
policies:
  p1:
    scope:
      options:
        emit_scan_metadata: false
      targets: [192.0.2.0/24]
`, "did_you_mean=config.options"},
		"option key on the policy": {`
policies:
  p1:
    emit_scan_metadata: false
    scope:
      targets: [192.0.2.0/24]
`, "did_you_mean=config.options.emit_scan_metadata"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Contains(t, captureWarnings(t, tc.policy), tc.want)
		})
	}
}
