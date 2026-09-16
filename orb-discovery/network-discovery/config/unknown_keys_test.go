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
