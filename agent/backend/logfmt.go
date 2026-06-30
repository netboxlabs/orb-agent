package backend

import (
	"log/slog"
	"sort"
	"strings"
)

// NormalizeLogfmtLine parses a logfmt line into (msg, attrs, level, ok).
// ok=false when the line is not logfmt or has no non-empty msg key; callers then
// keep their fallback level and log the raw trimmed line as msg.
// Contract: msg/level/time keys are removed from attrs; blank keys are skipped;
// remaining attr keys are sorted alphabetically; level map is
// debug→Debug, info→Info, warn|warning→Warn, error|err→Error, else not ok;
// quoted values accept ' and " with backslash escapes; duplicate keys
// last-writer-wins.
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

	for index < length {
		char := runes[index]
		if char == '\\' && index+1 < length {
			builder.WriteRune(runes[index+1])
			index += 2
			continue
		}
		if char == quote {
			index++
			for index < length && runes[index] == ' ' {
				index++
			}
			return builder.String(), index, true
		}
		builder.WriteRune(char)
		index++
	}

	return "", length, false
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
