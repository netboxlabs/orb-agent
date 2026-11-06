package backend

import (
	"bytes"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// textHandlerLine returns the line slog.TextHandler, the handler the Go
// backends log with under their TEXT format, writes for one record.
func textHandlerLine(t *testing.T, msg string, args ...any) string {
	t.Helper()
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info(msg, args...)
	line := strings.TrimSuffix(buf.String(), "\n")
	require.NotContains(t, line, "\n", "the handler writes one line per record")
	return line
}

func TestNormalizeLogfmtLine_DecodesTextHandlerEscapes(t *testing.T) {
	value := "goroutine 1 [running]:\n\tmain.go:12 \"quoted\" C:\\dir caf\u00e9 nbsp\u00a0 \x1b[0m"
	line := textHandlerLine(t, "recovered from a panic", "stack", value)

	msg, attrs, level, ok := NormalizeLogfmtLine(line, slog.LevelError)
	require.True(t, ok)
	assert.Equal(t, "recovered from a panic", msg)
	assert.Equal(t, slog.LevelInfo, level)
	require.Len(t, attrs, 1)
	assert.Equal(t, "stack", attrs[0].Key)
	assert.Equal(t, value, attrs[0].Value.String())
}

func TestNormalizeLogfmtLine_TextHandlerRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		escape string // text the handler must write, so each escape class is covered
	}{
		{"no quoting", "sw1", "key=sw1 "},
		{"unquoted backslash", `C:\dir`, `key=C:\dir `},
		{"empty", "", `key="" `},
		{"space", "two words", `"two words"`},
		{"equals", "a=b", `"a=b"`},
		{"quote", `say "hi"`, `\"hi\"`},
		{"backslash", `C:\dir name`, `C:\\dir`},
		{"named escapes", "\a\b\f\n\r\t\v", `\a\b\f\n\r\t\v`},
		{"control bytes", "\x00 \x1b \x7f", `\x00 \x1b \x7f`},
		{"non-printable BMP rune", "\u00a0 \u200b \u2028", `\u00a0 \u200b \u2028`},
		{"non-printable rune above BMP", "\U000e0001", `\U000e0001`},
		{"printable non-ASCII", "caf\u00e9 \u65e5\u672c \U0001f642", "caf\u00e9 \u65e5\u672c \U0001f642"},
		{"replacement character", "\ufffd", "\"\ufffd\""},
		{"surrounding spaces", " padded ", `" padded "`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := textHandlerLine(t, "m", "key", tt.value, "next", "1")
			require.Contains(t, line, tt.escape)

			msg, attrs, _, ok := NormalizeLogfmtLine(line, slog.LevelError)
			require.True(t, ok)
			assert.Equal(t, "m", msg)
			assert.Equal(t, [][2]string{{"key", tt.value}, {"next", "1"}}, attrPairs(attrs))
		})
	}

	t.Run("message", func(t *testing.T) {
		line := textHandlerLine(t, "first line\n\tsecond line")
		msg, _, _, ok := NormalizeLogfmtLine(line, slog.LevelError)
		require.True(t, ok)
		assert.Equal(t, "first line\n\tsecond line", msg)
	})
}

// The rest of the strconv.Quote family writes valid Go quoting too.
func TestNormalizeLogfmtLine_DecodesGoQuotingFamily(t *testing.T) {
	value := "caf\u00e9\n\u00a0\U0001f642"
	for name, token := range map[string]string{
		"QuoteToASCII":   strconv.QuoteToASCII(value),
		"QuoteToGraphic": strconv.QuoteToGraphic(value),
	} {
		t.Run(name, func(t *testing.T) {
			_, attrs, _, ok := NormalizeLogfmtLine(`msg=m key=`+token, slog.LevelError)
			require.True(t, ok)
			assert.Equal(t, [][2]string{{"key", value}}, attrPairs(attrs))
		})
	}
}

// strconv.Quote writes a byte that is not UTF-8 as \xNN; the decoded value
// keeps that escape text so it stays valid UTF-8 for the OTLP export.
func TestNormalizeLogfmtLine_InvalidUTF8StaysEscaped(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"lone byte", "ok\xffbad", `ok\xffbad`},
		{"with a newline", "line1\nbad\xc3(", "line1\n" + `bad\xc3(`},
		{"truncated rune", "end\xe2\x82", `end\xe2\x82`},
		{"next to a replacement character", "\ufffd\xff", "\ufffd" + `\xff`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := textHandlerLine(t, "m", "key", tt.value)
			_, attrs, _, ok := NormalizeLogfmtLine(line, slog.LevelError)
			require.True(t, ok)
			require.Len(t, attrs, 1)
			assert.Equal(t, tt.want, attrs[0].Value.String())
			assert.True(t, utf8.ValidString(attrs[0].Value.String()))
		})
	}

	t.Run("octal escape", func(t *testing.T) {
		_, attrs, _, ok := NormalizeLogfmtLine(`msg=m key="a\377b"`, slog.LevelError)
		require.True(t, ok)
		assert.Equal(t, [][2]string{{"key", `a\xffb`}}, attrPairs(attrs))
	})

	t.Run("message", func(t *testing.T) {
		msg, _, _, ok := NormalizeLogfmtLine(textHandlerLine(t, "bad\xff byte"), slog.LevelError)
		require.True(t, ok)
		assert.Equal(t, `bad\xff byte`, msg)
	})
}

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
