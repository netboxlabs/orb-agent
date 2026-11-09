package backend

import (
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// NormalizeLogfmtLine parses a logfmt line into (msg, attrs, level, ok).
// ok=false when the line is not logfmt or has no non-empty msg key; callers then
// keep their fallback level and log the raw trimmed line as msg.
// Contract: msg/level/time keys are removed from attrs; blank keys are skipped;
// remaining attr keys are sorted alphabetically; level is parsed via ParseLogfmtLevel
// (unknown levels keep the fallback); duplicate keys last-writer-wins.
// A double-quoted value that is valid Go quoting, as slog.TextHandler writes with
// strconv.Quote, is decoded with strconv.Unquote, and a byte that would decode to
// invalid UTF-8 is written as a \xNN escape. Any other quoted value, ' or ", drops
// each backslash and keeps the character after it.
func NormalizeLogfmtLine(line string, fallback slog.Level) (string, []slog.Attr, slog.Level, bool) {
	fields, ok := parseLogfmt(line)
	if !ok {
		return "", nil, fallback, false
	}

	msg, ok := fields["msg"]
	if !ok || strings.TrimSpace(msg) == "" {
		return "", nil, fallback, false
	}

	level := fallback
	if lvlValue, exists := fields["level"]; exists {
		if parsedLevel, levelOK := ParseLogfmtLevel(lvlValue); levelOK {
			level = parsedLevel
		}
	}

	delete(fields, "msg")
	delete(fields, "level")
	delete(fields, "time")

	if len(fields) == 0 {
		return msg, nil, level, true
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		if strings.TrimSpace(key) == "" {
			continue
		}
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return msg, nil, level, true
	}

	sort.Strings(keys)

	attrs := make([]slog.Attr, 0, len(keys))
	for _, key := range keys {
		attrs = append(attrs, slog.String(key, fields[key]))
	}

	return msg, attrs, level, true
}

// ParseLogfmtLevel maps the shared level vocabulary; exported so colon/JSON
// backends can delegate and layer their own aliases. ok=false for unknown.
func ParseLogfmtLevel(value string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error", "err":
		return slog.LevelError, true
	default:
		return 0, false
	}
}

func parseLogfmt(line string) (map[string]string, bool) {
	result := make(map[string]string)
	runes := []rune(line)
	length := len(runes)
	index := 0

	for index < length {
		for index < length && runes[index] == ' ' {
			index++
		}
		if index >= length {
			break
		}

		keyStart := index
		for index < length && runes[index] != '=' && runes[index] != ' ' {
			index++
		}
		if index >= length || runes[index] != '=' {
			return nil, false
		}

		key := strings.TrimSpace(string(runes[keyStart:index]))
		index++ // skip '='

		value, nextIndex, ok := readLogfmtValue(runes, index)
		if !ok {
			return nil, false
		}

		result[key] = value
		index = nextIndex
	}

	if len(result) == 0 {
		return nil, false
	}

	return result, true
}

func readLogfmtValue(runes []rune, start int) (string, int, bool) {
	length := len(runes)
	if start >= length {
		return "", start, true
	}

	switch runes[start] {
	case '"', '\'':
		return readQuotedValue(runes, start)
	default:
		return readUnquotedValue(runes, start)
	}
}

func readQuotedValue(runes []rune, start int) (string, int, bool) {
	length := len(runes)
	quote := runes[start]
	index := start + 1
	var builder strings.Builder
	escaped := false

	for index < length {
		char := runes[index]
		if char == '\\' && index+1 < length {
			builder.WriteRune(runes[index+1])
			index += 2
			escaped = true
			continue
		}
		if char == quote {
			value := builder.String()
			// Go quoting, as slog.TextHandler writes it; anything else keeps the
			// legacy decoding. Without a backslash both read the same.
			if quote == '"' && escaped {
				if decoded, err := strconv.Unquote(string(runes[start : index+1])); err == nil {
					value = escapeInvalidUTF8(decoded)
				}
			}
			index++
			for index < length && runes[index] == ' ' {
				index++
			}
			return value, index, true
		}
		builder.WriteRune(char)
		index++
	}

	return "", length, false
}

// escapeInvalidUTF8 writes each byte that is not valid UTF-8 as a \xNN escape, as
// strconv.Quote does, because the OTLP log export rejects invalid UTF-8.
func escapeInvalidUTF8(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	var builder strings.Builder
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&builder, `\x%02x`, value[index])
		} else {
			builder.WriteString(value[index : index+size])
		}
		index += size
	}
	return builder.String()
}

func readUnquotedValue(runes []rune, start int) (string, int, bool) {
	length := len(runes)
	index := start
	for index < length && runes[index] != ' ' {
		index++
	}
	value := string(runes[start:index])
	for index < length && runes[index] == ' ' {
		index++
	}
	return value, index, true
}
