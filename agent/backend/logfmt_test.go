package backend

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLogfmtLevel(t *testing.T) {
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
			level, ok := ParseLogfmtLevel(tt.input)
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

func TestParseLogfmt(t *testing.T) {
	line := `level=info msg="hello world" key=value`
	fields, ok := parseLogfmt(line)
	assert.True(t, ok)
	assert.Equal(t, "info", fields["level"])
	assert.Equal(t, "hello world", fields["msg"])
	assert.Equal(t, "value", fields["key"])
}

func TestParseLogfmt_Empty(t *testing.T) {
	_, ok := parseLogfmt("")
	assert.False(t, ok)
}

func TestParseLogfmt_InvalidFormat(t *testing.T) {
	_, ok := parseLogfmt("not logfmt at all")
	assert.False(t, ok)
}

func TestNormalizeLogfmtLine_Valid(t *testing.T) {
	line := `level=info msg="starting up" component=main`
	msg, attrs, level, ok := NormalizeLogfmtLine(line, slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "starting up", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "component", attrs[0].Key)
}

func TestNormalizeLogfmtLine_NoMsg(t *testing.T) {
	line := `level=info key=value`
	_, _, _, ok := NormalizeLogfmtLine(line, slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeLogfmtLine_NotLogfmt(t *testing.T) {
	_, _, _, ok := NormalizeLogfmtLine("plain text line", slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeLogfmtLine_NoAttrs(t *testing.T) {
	line := `level=info msg="hello"`
	msg, attrs, level, ok := NormalizeLogfmtLine(line, slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "hello", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Nil(t, attrs)
}

func TestNormalizeLogfmtLine_UnknownLevel_UsesFallback(t *testing.T) {
	line := `level=verbose msg="hello"`
	_, _, level, ok := NormalizeLogfmtLine(line, slog.LevelWarn)
	assert.True(t, ok)
	assert.Equal(t, slog.LevelWarn, level)
}

func TestReadLogfmtValue_SingleQuoted(t *testing.T) {
	runes := []rune("'hello world' rest")
	val, idx, ok := readLogfmtValue(runes, 0)
	assert.True(t, ok)
	assert.Equal(t, "hello world", val)
	assert.Equal(t, 14, idx)
}

func TestParseLogfmt_DuplicateKeys_LastWriterWins(t *testing.T) {
	line := `key=first key=second`
	fields, ok := parseLogfmt(line)
	assert.True(t, ok)
	assert.Equal(t, "second", fields["key"])
}
