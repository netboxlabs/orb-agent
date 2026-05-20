package networkdiscovery

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseNetworkDiscoveryLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
		ok       bool
	}{
		{"debug", slog.LevelDebug, true},
		{"DEBUG", slog.LevelDebug, true},
		{"info", slog.LevelInfo, true},
		{"INFO", slog.LevelInfo, true},
		{"warn", slog.LevelWarn, true},
		{"warning", slog.LevelWarn, true},
		{"WARNING", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"err", slog.LevelError, true},
		{"ERROR", slog.LevelError, true},
		{"unknown", 0, false},
		{"", 0, false},
		{"  info  ", slog.LevelInfo, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level, ok := parseNetworkDiscoveryLevel(tt.input)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.expected, level)
			}
		})
	}
}

func TestReadUnquotedValue(t *testing.T) {
	runes := []rune("hello world")
	val, idx, ok := readUnquotedValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, "hello", val)
	assert.Equal(t, 6, idx)
}

func TestReadQuotedValue_DoubleQuote(t *testing.T) {
	runes := []rune(`"hello world" rest`)
	val, idx, ok := readQuotedValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, "hello world", val)
	assert.Equal(t, 14, idx)
}

func TestReadQuotedValue_WithEscape(t *testing.T) {
	runes := []rune(`"hello \"world\""`)
	val, _, ok := readQuotedValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, `hello "world"`, val)
}

func TestReadQuotedValue_Unterminated(t *testing.T) {
	runes := []rune(`"hello`)
	_, _, ok := readQuotedValue(runes, 0)
	assert.False(t, ok)
}

func TestReadLogfmtValue_Quoted(t *testing.T) {
	runes := []rune(`"hello world"`)
	val, _, ok := readLogfmtValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, "hello world", val)
}

func TestReadLogfmtValue_Unquoted(t *testing.T) {
	runes := []rune("hello")
	val, _, ok := readLogfmtValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, "hello", val)
}

func TestReadLogfmtValue_Empty(t *testing.T) {
	val, idx, ok := readLogfmtValue([]rune{}, 0)
	assert.True(t, ok)
	assert.Equal(t, "", val)
	assert.Equal(t, 0, idx)
}

func TestParseNetworkDiscoveryLogfmt(t *testing.T) {
	line := `level=info msg="hello world" key=value`
	fields, ok := parseNetworkDiscoveryLogfmt(line)
	assert.True(t, ok)
	assert.Equal(t, "info", fields["level"])
	assert.Equal(t, "hello world", fields["msg"])
	assert.Equal(t, "value", fields["key"])
}

func TestParseNetworkDiscoveryLogfmt_Empty(t *testing.T) {
	_, ok := parseNetworkDiscoveryLogfmt("")
	assert.False(t, ok)
}

func TestParseNetworkDiscoveryLogfmt_InvalidFormat(t *testing.T) {
	_, ok := parseNetworkDiscoveryLogfmt("not logfmt at all")
	assert.False(t, ok)
}

func TestNormalizeNetworkDiscoveryLine_Valid(t *testing.T) {
	line := `level=info msg="starting up" component=main`
	msg, attrs, level, ok := normalizeNetworkDiscoveryLine(line, slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "starting up", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "component", attrs[0].Key)
}

func TestNormalizeNetworkDiscoveryLine_NoMsg(t *testing.T) {
	line := `level=info key=value`
	_, _, _, ok := normalizeNetworkDiscoveryLine(line, slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeNetworkDiscoveryLine_NotLogfmt(t *testing.T) {
	_, _, _, ok := normalizeNetworkDiscoveryLine("plain text line", slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeNetworkDiscoveryLine_NoAttrs(t *testing.T) {
	line := `level=info msg="hello"`
	msg, attrs, level, ok := normalizeNetworkDiscoveryLine(line, slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "hello", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Nil(t, attrs)
}

func TestNormalizeNetworkDiscoveryLine_UnknownLevel_UsesFallback(t *testing.T) {
	line := `level=verbose msg="hello"`
	_, _, level, ok := normalizeNetworkDiscoveryLine(line, slog.LevelWarn)
	assert.True(t, ok)
	assert.Equal(t, slog.LevelWarn, level)
}
