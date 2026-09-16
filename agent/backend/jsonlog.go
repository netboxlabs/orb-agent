package backend

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// NormalizeJSONLine parses a JSON log record, the shape slog's JSON handler
// writes, into (msg, attrs, level, ok) under the same contract as
// NormalizeLogfmtLine: ok=false when the line is not a JSON object or has no
// non-empty msg; msg, level and time are removed from attrs; the remaining
// keys are sorted; the level is parsed with ParseLogfmtLevel and an unknown
// one keeps the fallback. Attribute values that are not strings are rendered
// with %v, so a nested object arrives as one attribute rather than being lost.
func NormalizeJSONLine(line string, fallback slog.Level) (string, []slog.Attr, slog.Level, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") {
		return "", nil, fallback, false
	}

	var fields map[string]any
	if err := json.Unmarshal([]byte(trimmed), &fields); err != nil {
		return "", nil, fallback, false
	}

	msg, ok := fields["msg"].(string)
	if !ok || strings.TrimSpace(msg) == "" {
		return "", nil, fallback, false
	}

	level := fallback
	if lvlValue, exists := fields["level"].(string); exists {
		if parsedLevel, levelOK := ParseLogfmtLevel(lvlValue); levelOK {
			level = parsedLevel
		}
	}

	delete(fields, "msg")
	delete(fields, "level")
	delete(fields, "time")

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
		switch value := fields[key].(type) {
		case string:
			attrs = append(attrs, slog.String(key, value))
		default:
			attrs = append(attrs, slog.String(key, fmt.Sprintf("%v", value)))
		}
	}

	return msg, attrs, level, true
}
