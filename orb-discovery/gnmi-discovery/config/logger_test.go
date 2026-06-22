package config

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLogger_ReturnsNonNil(t *testing.T) {
	levels := []string{"DEBUG", "INFO", "WARN", "ERROR", "debug", "info", "warn", "error", "UNKNOWN"}
	formats := []string{"TEXT", "JSON", "text", "json", "OTHER"}
	for _, lvl := range levels {
		for _, fmt := range formats {
			l := NewLogger(lvl, fmt)
			require.NotNil(t, l, "NewLogger(%q, %q) returned nil", lvl, fmt)
		}
	}
}

// TestNewLogger_LevelFiltering asserts on the RETURNED logger's Enabled method
// rather than probing a separate handler. This ensures the level set by NewLogger
// is the one actually in effect.
func TestNewLogger_LevelFiltering(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		logLevel      string
		enabledLevel  slog.Level // must be Enabled
		disabledLevel slog.Level // must NOT be Enabled (or use -5 sentinel to skip)
	}{
		// DEBUG → everything enabled including DEBUG; nothing disabled below it
		{"DEBUG", slog.LevelDebug, slog.Level(-5)},
		// INFO → INFO enabled; DEBUG disabled
		{"INFO", slog.LevelInfo, slog.LevelDebug},
		// WARN → WARN enabled; INFO disabled
		{"WARN", slog.LevelWarn, slog.LevelInfo},
		// ERROR → ERROR enabled; WARN disabled
		{"ERROR", slog.LevelError, slog.LevelWarn},
		// unknown → falls back to DEBUG
		{"unknown", slog.LevelDebug, slog.Level(-5)},
		// mixed-case variants
		{"info", slog.LevelInfo, slog.LevelDebug},
		{"Info", slog.LevelInfo, slog.LevelDebug},
		{"warn", slog.LevelWarn, slog.LevelInfo},
		{"error", slog.LevelError, slog.LevelWarn},
	}

	for _, tc := range tests {
		t.Run(tc.logLevel, func(t *testing.T) {
			lg := NewLogger(tc.logLevel, "JSON")
			require.NotNil(t, lg)

			require.True(t, lg.Enabled(ctx, tc.enabledLevel),
				"NewLogger(%q): expected Enabled(%s)==true", tc.logLevel, tc.enabledLevel)

			// sentinel -5 means "nothing to assert for the disabled side"
			if tc.disabledLevel != slog.Level(-5) {
				require.False(t, lg.Enabled(ctx, tc.disabledLevel),
					"NewLogger(%q): expected Enabled(%s)==false", tc.logLevel, tc.disabledLevel)
			}
		})
	}
}

// TestNewLogger_FormatJSON asserts that NewLogger("INFO","JSON") returns a logger
// whose handler is a *slog.JSONHandler.
func TestNewLogger_FormatJSON(t *testing.T) {
	lg := NewLogger("INFO", "JSON")
	require.NotNil(t, lg)
	require.IsType(t, &slog.JSONHandler{}, lg.Handler(),
		"JSON format must return a *slog.JSONHandler")
}

// TestNewLogger_FormatText asserts that NewLogger("INFO","TEXT") returns a logger
// whose handler is a *slog.TextHandler.
func TestNewLogger_FormatText(t *testing.T) {
	lg := NewLogger("INFO", "TEXT")
	require.NotNil(t, lg)
	require.IsType(t, &slog.TextHandler{}, lg.Handler(),
		"TEXT format must return a *slog.TextHandler")
}

// TestNewLogger_DefaultFormatFallsBackToJSON asserts that an unknown format
// falls back to the default handler type (JSON, per NewLogger's default branch).
func TestNewLogger_DefaultFormatFallsBackToJSON(t *testing.T) {
	lg := NewLogger("INFO", "UNKNOWN_FORMAT")
	require.NotNil(t, lg)
	require.IsType(t, &slog.JSONHandler{}, lg.Handler(),
		"unknown format must fall back to *slog.JSONHandler")
}

// TestNewLogger_CaseInsensitive verifies handler type for all case variants.
func TestNewLogger_CaseInsensitive(t *testing.T) {
	tests := []struct {
		level       string
		format      string
		wantHandler any
	}{
		{"debug", "json", &slog.JSONHandler{}},
		{"Debug", "Json", &slog.JSONHandler{}},
		{"info", "text", &slog.TextHandler{}},
		{"Info", "Text", &slog.TextHandler{}},
		{"warn", "JSON", &slog.JSONHandler{}},
		{"Warn", "TEXT", &slog.TextHandler{}},
		{"error", "json", &slog.JSONHandler{}},
		{"Error", "text", &slog.TextHandler{}},
	}
	for _, tc := range tests {
		t.Run(tc.level+"/"+tc.format, func(t *testing.T) {
			lg := NewLogger(tc.level, tc.format)
			require.NotNil(t, lg, "NewLogger(%q, %q) must not return nil", tc.level, tc.format)
			require.IsType(t, tc.wantHandler, lg.Handler(),
				"NewLogger(%q,%q) handler type mismatch", tc.level, tc.format)
		})
	}
}
