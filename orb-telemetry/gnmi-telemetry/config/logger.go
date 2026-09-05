package config

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger creates a configured slog
func NewLogger(logLevel string, logFormat string) *slog.Logger {
	var l slog.Level
	switch strings.ToUpper(logLevel) {
	case "DEBUG":
		l = slog.LevelDebug
	case "INFO":
		l = slog.LevelInfo
	case "WARN":
		l = slog.LevelWarn
	case "ERROR":
		l = slog.LevelError
	default:
		l = slog.LevelDebug
	}

	var h slog.Handler
	switch strings.ToUpper(logFormat) {
	case "TEXT":
		h = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l, AddSource: false})
	case "JSON":
		h = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l, AddSource: false})
	default:
		h = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l, AddSource: false})
	}

	return slog.New(h)
}

// logValueReplacer collapses the line breaks a log value could carry into
// spaces. "\r\n" is listed first so a pair becomes one space rather than two.
var logValueReplacer = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")

// SanitizeLogValue returns v with its line breaks replaced by spaces. Values
// that reach the log from a policy body are remote input, and a line break in
// one lets the sender forge a log line of its own.
func SanitizeLogValue(v string) string {
	return logValueReplacer.Replace(v)
}
