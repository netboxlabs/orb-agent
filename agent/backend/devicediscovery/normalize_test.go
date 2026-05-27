package devicediscovery

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDeviceDiscoveryLevel(t *testing.T) {
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
			level, ok := parseDeviceDiscoveryLevel(tt.input)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.expected, level)
			}
		})
	}
}

func TestNormalizeDeviceDiscoveryLine_Valid(t *testing.T) {
	msg, attrs, level, ok := normalizeDeviceDiscoveryLine("INFO: mymodule: hello world", slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "hello world", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "module", attrs[0].Key)
	assert.Equal(t, "mymodule", attrs[0].Value.String())
}

func TestNormalizeDeviceDiscoveryLine_NoModule(t *testing.T) {
	msg, attrs, level, ok := normalizeDeviceDiscoveryLine("INFO: hello world", slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "hello world", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Nil(t, attrs)
}

func TestNormalizeDeviceDiscoveryLine_NoColon(t *testing.T) {
	_, _, _, ok := normalizeDeviceDiscoveryLine("plain text", slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeDeviceDiscoveryLine_UnknownLevel(t *testing.T) {
	_, _, _, ok := normalizeDeviceDiscoveryLine("VERBOSE: something", slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeDeviceDiscoveryLine_EmptyRemainder(t *testing.T) {
	msg, _, level, ok := normalizeDeviceDiscoveryLine("INFO:", slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, slog.LevelInfo, level)
	assert.NotEmpty(t, msg)
}

func TestNormalizeDeviceDiscoveryLine_ModuleNoRest(t *testing.T) {
	msg, attrs, level, ok := normalizeDeviceDiscoveryLine("DEBUG: mymodule:", slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, slog.LevelDebug, level)
	assert.NotEmpty(t, msg)
	assert.Len(t, attrs, 1)
}

func TestNormalizeDeviceDiscoveryLine_ModuleWithSpace_NotTreatedAsModule(t *testing.T) {
	// "module candidate" has a space so should NOT be treated as module attr
	msg, attrs, level, ok := normalizeDeviceDiscoveryLine("INFO: has space: rest", slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Nil(t, attrs)
	assert.NotEmpty(t, msg)
}
