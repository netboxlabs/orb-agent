package backend

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeJSONLine_Valid(t *testing.T) {
	msg, attrs, level, ok := NormalizeJSONLine(
		`{"time":"2026-09-04T12:00:00Z","level":"WARN","msg":"trap dropped","reason":"unknown_source","count":3}`,
		slog.LevelInfo)
	require.True(t, ok)
	assert.Equal(t, "trap dropped", msg)
	assert.Equal(t, slog.LevelWarn, level)
	assert.Equal(t, []slog.Attr{slog.String("count", "3"), slog.String("reason", "unknown_source")}, attrs)
}

func TestNormalizeJSONLine_ErrorLevel(t *testing.T) {
	_, _, level, ok := NormalizeJSONLine(`{"level":"ERROR","msg":"bind failed"}`, slog.LevelInfo)
	require.True(t, ok)
	assert.Equal(t, slog.LevelError, level)
}

func TestNormalizeJSONLine_UnknownLevel_UsesFallback(t *testing.T) {
	_, _, level, ok := NormalizeJSONLine(`{"level":"WARN+2","msg":"custom"}`, slog.LevelInfo)
	require.True(t, ok)
	assert.Equal(t, slog.LevelInfo, level)
}

func TestNormalizeJSONLine_NoMsg(t *testing.T) {
	for _, line := range []string{
		`{"level":"ERROR","detail":"x"}`,
		`{"level":"ERROR","msg":"   "}`,
		`{"level":"ERROR","msg":7}`,
	} {
		_, _, level, ok := NormalizeJSONLine(line, slog.LevelInfo)
		assert.False(t, ok, line)
		assert.Equal(t, slog.LevelInfo, level, line)
	}
}

func TestNormalizeJSONLine_NotJSON(t *testing.T) {
	_, _, _, ok := NormalizeJSONLine(`time=now level=INFO msg=hello`, slog.LevelInfo)
	assert.False(t, ok)
	_, _, _, ok = NormalizeJSONLine(`{not json`, slog.LevelInfo)
	assert.False(t, ok)
}

func TestNormalizeJSONLine_NoAttrs(t *testing.T) {
	msg, attrs, _, ok := NormalizeJSONLine(`{"time":"t","level":"INFO","msg":"ready"}`, slog.LevelError)
	require.True(t, ok)
	assert.Equal(t, "ready", msg)
	assert.Nil(t, attrs)
}

func TestNormalizeJSONLine_NestedValueRendered(t *testing.T) {
	_, attrs, _, ok := NormalizeJSONLine(`{"msg":"m","policy":{"name":"core","targets":2}}`, slog.LevelInfo)
	require.True(t, ok)
	assert.Equal(t, []slog.Attr{slog.String("policy", "map[name:core targets:2]")}, attrs)
}
