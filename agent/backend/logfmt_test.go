package backend

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// attrPairs flattens attrs to key/value pairs: assert.Equal on slog.Attr
// compares only the length and first byte of a string value.
func attrPairs(attrs []slog.Attr) [][2]string {
	pairs := make([][2]string, 0, len(attrs))
	for _, attr := range attrs {
		pairs = append(pairs, [2]string{attr.Key, attr.Value.String()})
	}
	return pairs
}

// Values that are not valid Go double quoting keep the legacy decoding, which
// drops each backslash and keeps the character after it.
func TestNormalizeLogfmtLine_KeepsLegacyDecoding(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"unknown escape", `"bad \q escape"`, "bad q escape"},
		{"escape and unknown escape", `"line\nbad\q"`, "linenbadq"},
		{"surrogate half", `"\ud800"`, "ud800"},
		{"short hex escape", `"\x4"`, "x4"},
		{"escaped single quote", `"it\'s"`, "it's"},
		{"single quoted", `'two words'`, "two words"},
		{"single quoted escaped quote", `'it\'s'`, "it's"},
		{"single quoted backslash n", `'a\nb'`, "anb"},
		{"single quoted lone escape", `'\n'`, "n"},
		{"single quoted unicode escape", `'caf\u00e9'`, "cafu00e9"},
		{"single quoted double quotes", `'say "hi"'`, `say "hi"`},
		{"unquoted backslashes", `C:\dir\n`, `C:\dir\n`},
		{"unquoted empty", ``, ""},
		{"raw invalid byte quoted", "\"a\xffb\"", "a\ufffdb"},
		{"raw invalid byte unquoted", "a\xffb", "a\ufffdb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := `level=WARN msg=m key=` + tt.token + ` next=1`
			msg, attrs, level, ok := NormalizeLogfmtLine(line, slog.LevelError)
			require.True(t, ok)
			assert.Equal(t, "m", msg)
			assert.Equal(t, slog.LevelWarn, level)
			assert.Equal(t, [][2]string{{"key", tt.want}, {"next", "1"}}, attrPairs(attrs))
		})
	}

	t.Run("message", func(t *testing.T) {
		msg, _, _, ok := NormalizeLogfmtLine(`msg="bad \q escape"`, slog.LevelError)
		require.True(t, ok)
		assert.Equal(t, "bad q escape", msg)
	})
}

func TestNormalizeLogfmtLine_UnterminatedQuoteIsNotLogfmt(t *testing.T) {
	for _, token := range []string{`"open`, `"open\`, `"open\"`, `'open`} {
		t.Run(token, func(t *testing.T) {
			msg, attrs, level, ok := NormalizeLogfmtLine(`msg=m key=`+token, slog.LevelError)
			assert.False(t, ok)
			assert.Empty(t, msg)
			assert.Nil(t, attrs)
			assert.Equal(t, slog.LevelError, level)
		})
	}
}
