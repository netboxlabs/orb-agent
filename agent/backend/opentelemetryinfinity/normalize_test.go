package opentelemetryinfinity

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOpenTelemetryInfinityLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
		ok       bool
	}{
		{"debug", slog.LevelDebug, true},
		{"DEBUG", slog.LevelDebug, true},
		{"info", slog.LevelInfo, true},
		{"information", slog.LevelInfo, true},
		{"INFO", slog.LevelInfo, true},
		{"warn", slog.LevelWarn, true},
		{"warning", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"err", slog.LevelError, true},
		{"fatal", slog.LevelError, true},
		{"unknown", 0, false},
		{"", 0, false},
		{"  info  ", slog.LevelInfo, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level, ok := parseOpenTelemetryInfinityLevel(tt.input)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.expected, level)
			}
		})
	}
}

func TestParseOpenTelemetryInfinityJSON_Valid(t *testing.T) {
	line := `{"level":"info","msg":"hello","key":"value"}`
	fields, ok := parseOpenTelemetryInfinityJSON(line)
	assert.True(t, ok)
	assert.Equal(t, "info", fields["level"])
	assert.Equal(t, "hello", fields["msg"])
}

func TestParseOpenTelemetryInfinityJSON_Invalid(t *testing.T) {
	_, ok := parseOpenTelemetryInfinityJSON("not json")
	assert.False(t, ok)
}

func TestParseOpenTelemetryInfinityJSON_Empty(t *testing.T) {
	_, ok := parseOpenTelemetryInfinityJSON("{}")
	assert.False(t, ok)
}

func TestExtractMessage_MsgField(t *testing.T) {
	fields := map[string]any{"msg": "hello world"}
	msg, ok := extractMessage(fields)
	assert.True(t, ok)
	assert.Equal(t, "hello world", msg)
}

func TestExtractMessage_MessageField(t *testing.T) {
	fields := map[string]any{"message": "hello world"}
	msg, ok := extractMessage(fields)
	assert.True(t, ok)
	assert.Equal(t, "hello world", msg)
}

func TestExtractMessage_EmptyMsg(t *testing.T) {
	fields := map[string]any{"msg": "   "}
	_, ok := extractMessage(fields)
	assert.False(t, ok)
}

func TestExtractMessage_NoMsg(t *testing.T) {
	fields := map[string]any{"level": "info"}
	_, ok := extractMessage(fields)
	assert.False(t, ok)
}

func TestExtractMessage_NonStringMsg(t *testing.T) {
	fields := map[string]any{"msg": 42}
	_, ok := extractMessage(fields)
	assert.False(t, ok)
}

func TestBuildOpenTelemetryInfinityAttrs_Empty(t *testing.T) {
	attrs := buildOpenTelemetryInfinityAttrs(map[string]any{})
	assert.Nil(t, attrs)
}

func TestBuildOpenTelemetryInfinityAttrs_SkipsResource(t *testing.T) {
	fields := map[string]any{"resource": "something", "key": "value"}
	attrs := buildOpenTelemetryInfinityAttrs(fields)
	assert.Len(t, attrs, 1)
	assert.Equal(t, "key", attrs[0].Key)
}

func TestBuildOpenTelemetryInfinityAttrs_SkipsEmptyKey(t *testing.T) {
	fields := map[string]any{"  ": "something", "key": "value"}
	attrs := buildOpenTelemetryInfinityAttrs(fields)
	assert.Len(t, attrs, 1)
}

func TestConvertOpenTelemetryInfinityAttr_String(t *testing.T) {
	attr, ok := convertOpenTelemetryInfinityAttr("key", "value")
	assert.True(t, ok)
	assert.Equal(t, "key", attr.Key)
}

func TestConvertOpenTelemetryInfinityAttr_Float64_Integer(t *testing.T) {
	attr, ok := convertOpenTelemetryInfinityAttr("key", float64(42))
	assert.True(t, ok)
	assert.Equal(t, "key", attr.Key)
	assert.Equal(t, int64(42), attr.Value.Int64())
}

func TestConvertOpenTelemetryInfinityAttr_Float64_Decimal(t *testing.T) {
	attr, ok := convertOpenTelemetryInfinityAttr("key", float64(3.14))
	assert.True(t, ok)
	assert.Equal(t, "key", attr.Key)
}

func TestConvertOpenTelemetryInfinityAttr_Bool(t *testing.T) {
	attr, ok := convertOpenTelemetryInfinityAttr("key", true)
	assert.True(t, ok)
	assert.Equal(t, "key", attr.Key)
}

func TestConvertOpenTelemetryInfinityAttr_Nil(t *testing.T) {
	attr, ok := convertOpenTelemetryInfinityAttr("key", nil)
	assert.True(t, ok)
	assert.Equal(t, "key", attr.Key)
}

func TestConvertOpenTelemetryInfinityAttr_Slice(t *testing.T) {
	attr, ok := convertOpenTelemetryInfinityAttr("key", []any{"a", "b"})
	assert.True(t, ok)
	assert.Equal(t, "key", attr.Key)
}

func TestConvertOpenTelemetryInfinityAttr_NestedMap(t *testing.T) {
	attr, ok := convertOpenTelemetryInfinityAttr("key", map[string]any{"nested": "value"})
	assert.True(t, ok)
	assert.Equal(t, "key", attr.Key)
}

func TestConvertOpenTelemetryInfinityAttr_EmptyNestedMap(t *testing.T) {
	_, ok := convertOpenTelemetryInfinityAttr("key", map[string]any{})
	assert.False(t, ok)
}

func TestNormalizeOpenTelemetryInfinitySlice_Empty(t *testing.T) {
	result := normalizeOpenTelemetryInfinitySlice([]any{})
	assert.Empty(t, result)
}

func TestNormalizeOpenTelemetryInfinitySlice_Mixed(t *testing.T) {
	result := normalizeOpenTelemetryInfinitySlice([]any{float64(1), "hello", true, map[string]any{"k": "v"}})
	assert.Len(t, result, 4)
	assert.Equal(t, int64(1), result[0])
	assert.Equal(t, "hello", result[1])
}

func TestNormalizeOpenTelemetryInfinityValue_NestedSlice(t *testing.T) {
	result := normalizeOpenTelemetryInfinityValue([]any{float64(2)})
	slice, ok := result.([]any)
	assert.True(t, ok)
	assert.Equal(t, int64(2), slice[0])
}

func TestNormalizeOpenTelemetryInfinityValue_Map(t *testing.T) {
	result := normalizeOpenTelemetryInfinityValue(map[string]any{"k": float64(3), "  ": "skip"})
	m, ok := result.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, int64(3), m["k"])
	assert.NotContains(t, m, "  ")
}

func TestNormalizeOpenTelemetryInfinityLine_Valid(t *testing.T) {
	line := `{"level":"info","msg":"starting up","component":"main"}`
	msg, attrs, level, ok := normalizeOpenTelemetryInfinityLine(line, slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "starting up", msg)
	assert.Equal(t, slog.LevelInfo, level)
	assert.Len(t, attrs, 1)
}

func TestNormalizeOpenTelemetryInfinityLine_SeverityField(t *testing.T) {
	line := `{"severity":"warn","msg":"something"}`
	_, _, level, ok := normalizeOpenTelemetryInfinityLine(line, slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, slog.LevelWarn, level)
}

func TestNormalizeOpenTelemetryInfinityLine_MessageField(t *testing.T) {
	line := `{"level":"error","message":"oops"}`
	msg, _, level, ok := normalizeOpenTelemetryInfinityLine(line, slog.LevelDebug)
	assert.True(t, ok)
	assert.Equal(t, "oops", msg)
	assert.Equal(t, slog.LevelError, level)
}

func TestNormalizeOpenTelemetryInfinityLine_NotJSON(t *testing.T) {
	_, _, _, ok := normalizeOpenTelemetryInfinityLine("plain text", slog.LevelDebug)
	assert.False(t, ok)
}

func TestNormalizeOpenTelemetryInfinityLine_NoMessage(t *testing.T) {
	line := `{"level":"info","key":"value"}`
	_, _, _, ok := normalizeOpenTelemetryInfinityLine(line, slog.LevelDebug)
	assert.False(t, ok)
}

func TestOpenTelemetryInfinityGroupAttr_Empty(t *testing.T) {
	attr := openTelemetryInfinityGroupAttr("key", []slog.Attr{})
	assert.Equal(t, "key", attr.Key)
}

func TestOpenTelemetryInfinityGroupAttr_WithAttrs(t *testing.T) {
	attrs := []slog.Attr{slog.String("nested", "value")}
	attr := openTelemetryInfinityGroupAttr("key", attrs)
	assert.Equal(t, "key", attr.Key)
}
