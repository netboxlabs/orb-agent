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

// A key written at config level instead of config.options is reported with the
// path it belongs at. This is the shape that made a real report unreproducible:
// the key is dropped, module discovery stays off, and the emitted entity count
// is identical with and without it.
func TestMisplacedOptionNamesTheCorrectPath(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      capture_config: true
      defaults:
        site: s
    scope:
      targets:
        - host: 10.0.0.1
`)
	if !strings.Contains(out, "capture_config") {
		t.Fatalf("key not reported: %s", out)
	}
	if !strings.Contains(out, "options.capture_config") {
		t.Fatalf("expected the correct path in the warning, got: %s", out)
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
        - host: 10.0.0.1
`)
	if !strings.Contains(out, "totally_made_up_key") {
		t.Fatalf("key not reported: %s", out)
	}
	if strings.Contains(out, "did_you_mean") {
		t.Fatalf("should not invent a suggestion: %s", out)
	}
}

func TestUnknownKeyInsideOptionsIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      options:
        capture_config: true
        nope_option: 1
    scope:
      targets:
        - host: 10.0.0.1
`)
	if !strings.Contains(out, "nope_option") {
		t.Fatalf("key not reported: %s", out)
	}
}

// Only the config and options blocks are checked. Warning on blocks that carry
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
        - host: 10.0.0.1
          stray_target: 1
`)
	if out != "" {
		t.Fatalf("expected silence outside config/options, got: %s", out)
	}
}

func TestValidPolicyIsSilent(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      mode: subscribe
      options:
        capture_config: true
      defaults:
        site: s
    scope:
      targets:
        - host: 10.0.0.1
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

// `bogus key: 1` is a valid YAML mapping key, and yaml.v3 reports it with the
// space intact. Requiring a single non-whitespace token skipped the entry,
// hiding the very mistake this warning exists to surface.
func TestKeyContainingWhitespaceIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      bogus key: 1
    scope:
      targets:
        - host: 10.0.0.1
`)
	if !strings.Contains(out, "bogus key") {
		t.Fatalf("whitespace key not reported: %s", out)
	}
}
