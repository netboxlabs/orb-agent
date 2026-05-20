package worker

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseWorkerLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
		ok       bool
	}{
		{"trace", slog.LevelDebug, true},
		{"debug", slog.LevelDebug, true},
		{"DEBUG", slog.LevelDebug, true},
		{"info", slog.LevelInfo, true},
		{"INFO", slog.LevelInfo, true},
		{"warn", slog.LevelWarn, true},
		{"warning", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"err", slog.LevelError, true},
		{"exception", slog.LevelError, true},
		{"critical", slog.LevelError, true},
		{"fatal", slog.LevelError, true},
		{"unknown", 0, false},
		{"", 0, false},
		{"  info  ", slog.LevelInfo, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level, ok := parseWorkerLevel(tt.input)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.expected, level)
			}
		})
	}
}

func TestNormalizeWorkerLine_Valid(t *testing.T) {
	msg, attrs, level, ok := normalizeWorkerLine("INFO: mymodule: hello world", slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "hello world", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "module", attrs[0].Key)
	assert.Equal(t, "mymodule", attrs[0].Value.String())
}

func TestNormalizeWorkerLine_NoModule(t *testing.T) {
	msg, attrs, level, ok := normalizeWorkerLine("INFO: hello world", slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "hello world", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Nil(t, attrs)
}

func TestNormalizeWorkerLine_NoColon(t *testing.T) {
	_, _, _, ok := normalizeWorkerLine("plain text", slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeWorkerLine_UnknownLevel(t *testing.T) {
	_, _, _, ok := normalizeWorkerLine("VERBOSE: something", slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeWorkerLine_EmptyRemainder(t *testing.T) {
	msg, _, level, ok := normalizeWorkerLine("INFO:", slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, slog.LevelInfo, level)
	assert.NotEmpty(t, msg)
}
