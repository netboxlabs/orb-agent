package snmpdiscovery

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSnmpDiscoveryLevel(t *testing.T) {
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
			level, ok := parseSnmpDiscoveryLevel(tt.input)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.expected, level)
			}
		})
	}
}

func TestReadSnmpUnquotedValue(t *testing.T) {
	runes := []rune("hello world")
	val, idx, ok := readSnmpUnquotedValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, "hello", val)
	assert.Equal(t, 6, idx)
}

func TestReadSnmpQuotedValue_DoubleQuote(t *testing.T) {
	runes := []rune(`"hello world" rest`)
	val, idx, ok := readSnmpQuotedValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, "hello world", val)
	assert.Equal(t, 14, idx)
}

func TestReadSnmpQuotedValue_WithEscape(t *testing.T) {
	runes := []rune(`"hello \"world\""`)
	val, _, ok := readSnmpQuotedValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, `hello "world"`, val)
}

func TestReadSnmpQuotedValue_Unterminated(t *testing.T) {
	runes := []rune(`"hello`)
	_, _, ok := readSnmpQuotedValue(runes, 0)
	assert.False(t, ok)
}

func TestReadSnmpLogfmtValue_Quoted(t *testing.T) {
	runes := []rune(`"hello world"`)
	val, _, ok := readSnmpLogfmtValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, "hello world", val)
}

func TestReadSnmpLogfmtValue_Unquoted(t *testing.T) {
	runes := []rune("hello")
	val, _, ok := readSnmpLogfmtValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, "hello", val)
}

func TestReadSnmpLogfmtValue_Empty(t *testing.T) {
	val, idx, ok := readSnmpLogfmtValue([]rune{}, 0)
	assert.True(t, ok)
	assert.Equal(t, "", val)
	assert.Equal(t, 0, idx)
}

func TestParseSnmpDiscoveryLogfmt(t *testing.T) {
	line := `level=info msg="hello world" key=value`
	fields, ok := parseSnmpDiscoveryLogfmt(line)
	assert.True(t, ok)
	assert.Equal(t, "info", fields["level"])
	assert.Equal(t, "hello world", fields["msg"])
	assert.Equal(t, "value", fields["key"])
}

func TestParseSnmpDiscoveryLogfmt_Empty(t *testing.T) {
	_, ok := parseSnmpDiscoveryLogfmt("")
	assert.False(t, ok)
}

func TestParseSnmpDiscoveryLogfmt_InvalidFormat(t *testing.T) {
	_, ok := parseSnmpDiscoveryLogfmt("not logfmt at all")
	assert.False(t, ok)
}

func TestNormalizeSnmpDiscoveryLine_Valid(t *testing.T) {
	line := `level=info msg="starting up" component=main`
	msg, attrs, level, ok := normalizeSnmpDiscoveryLine(line, slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "starting up", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "component", attrs[0].Key)
}

func TestNormalizeSnmpDiscoveryLine_NoMsg(t *testing.T) {
	line := `level=info key=value`
	_, _, _, ok := normalizeSnmpDiscoveryLine(line, slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeSnmpDiscoveryLine_NotLogfmt(t *testing.T) {
	_, _, _, ok := normalizeSnmpDiscoveryLine("plain text line", slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeSnmpDiscoveryLine_NoAttrs(t *testing.T) {
	line := `level=info msg="hello"`
	msg, attrs, level, ok := normalizeSnmpDiscoveryLine(line, slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "hello", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Nil(t, attrs)
}

func TestNormalizeSnmpDiscoveryLine_UnknownLevel_UsesFallback(t *testing.T) {
	line := `level=verbose msg="hello"`
	_, _, level, ok := normalizeSnmpDiscoveryLine(line, slog.LevelWarn)
	assert.True(t, ok)
	assert.Equal(t, slog.LevelWarn, level)
}
