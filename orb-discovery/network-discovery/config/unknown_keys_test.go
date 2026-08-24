package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
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
	if !strings.Contains(out, "fast_mode") {
		t.Fatalf("key not reported: %s", out)
	}
	if !strings.Contains(out, "scope.fast_mode") {
		t.Fatalf("expected the correct block in the warning, got: %s", out)
	}
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
	if !strings.Contains(out, "defaults.network_mask") {
		t.Fatalf("expected the defaults block named, got: %s", out)
	}
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
	if !strings.Contains(out, "totally_made_up_key") {
		t.Fatalf("key not reported: %s", out)
	}
	if strings.Contains(out, "did_you_mean") {
		t.Fatalf("should not invent a suggestion: %s", out)
	}
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
	if out != "" {
		t.Fatalf("expected silence outside config, got: %s", out)
	}
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
	if out != "" {
		t.Fatalf("valid policy must not warn, got: %s", out)
	}
}

func TestMalformedYamlIsLeftToThePermissiveDecode(t *testing.T) {
	out := captureWarnings(t, "policies: [this is not a map")
	if out != "" {
		t.Fatalf("syntax errors are reported by the real decode, got: %s", out)
	}
}

func TestNilLoggerIsSafe(_ *testing.T) {
	WarnUnknownPolicyKeys([]byte("policies:\n  p1:\n    config:\n      bogus: 1\n"), nil)
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
	if !strings.Contains(out, "fast mode") {
		t.Fatalf("whitespace key not reported: %s", out)
	}
}
