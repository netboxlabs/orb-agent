package mapping

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactConfig(t *testing.T) {
	in := []byte(`{
		"openconfig-system:system": {
			"aaa": {"authentication": {"users": {"user": [
				{"username": "admin", "config": {"password": "s3cret", "secret-key": "abc"}}
			]}}},
			"bgp": {"neighbors": {"community-set": ["65000:1"]}}
		}
	}`)
	out := RedactConfig(in)

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))

	sys := got["openconfig-system:system"].(map[string]any)
	users := sys["aaa"].(map[string]any)["authentication"].(map[string]any)["users"].(map[string]any)
	user0 := users["user"].([]any)[0].(map[string]any)
	cfg := user0["config"].(map[string]any)
	assert.Equal(t, "***", cfg["password"], "password must be redacted")
	assert.Equal(t, "***", cfg["secret-key"], "secret-key must be redacted")
	assert.Equal(t, "admin", user0["username"], "username must be preserved")

	// Benign keys that merely resemble secrets are NOT redacted (no false positives).
	bgp := sys["bgp"].(map[string]any)
	assert.Equal(t, []any{"65000:1"}, bgp["neighbors"].(map[string]any)["community-set"],
		"community-set must be preserved (not a secret)")
}

func TestRedactConfig_ModuleQualifiedKey(t *testing.T) {
	in := []byte(`{"openconfig-system:auth-password": "p", "keep": "v"}`)
	var got map[string]any
	require.NoError(t, json.Unmarshal(RedactConfig(in), &got))
	assert.Equal(t, "***", got["openconfig-system:auth-password"])
	assert.Equal(t, "v", got["keep"])
}

func TestRedactConfig_UnparseableReturnedUnchanged(t *testing.T) {
	raw := []byte("not json at all")
	assert.Equal(t, raw, RedactConfig(raw))
}

func TestNewDeviceConfig(t *testing.T) {
	assert.Nil(t, NewDeviceConfig(nil))
	assert.Nil(t, NewDeviceConfig([]byte{}))
	dc := NewDeviceConfig([]byte(`{"a":1}`))
	require.NotNil(t, dc)
	assert.Equal(t, []byte(`{"a":1}`), dc.Running)
	assert.Nil(t, dc.Startup)
	assert.Nil(t, dc.Candidate)
}
