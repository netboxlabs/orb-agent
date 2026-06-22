// Package mapping — config_redact.go: best-effort redaction of secrets in a
// captured CONFIG-datastore JSON document before it becomes DeviceConfig.Running.
package mapping

import (
	"encoding/json"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// sensitiveKeySubstrings are case-insensitive substrings of a JSON object's
// local key name whose value is replaced with redactedValue. Deliberately
// auth-focused and conservative: most devices already return hashed values, and
// over-broad terms (e.g. bare "key", "community") would wrongly redact benign
// config such as BGP community-sets, so they are excluded.
var sensitiveKeySubstrings = []string{
	"password",
	"passphrase",
	"secret",
	"private-key",
	"pre-shared-key",
	"auth-password",
	"authentication-key",
}

const redactedValue = "***"

// RedactConfig walks a decoded JSON_IETF config document and replaces values
// under sensitive keys with "***", returning re-serialized JSON. If the input
// does not parse as JSON it is returned unchanged (capturing an opaque blob is
// still better than dropping it). Best-effort by design — see
// sensitiveKeySubstrings.
func RedactConfig(raw []byte) []byte {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return raw
	}
	out, err := json.Marshal(redactNode(root))
	if err != nil {
		return raw
	}
	return out
}

// redactNode recursively redacts sensitive keys in maps and walks slices.
func redactNode(n any) any {
	switch v := n.(type) {
	case map[string]any:
		for k, child := range v {
			if isSensitiveKey(k) {
				v[k] = redactedValue
				continue
			}
			v[k] = redactNode(child)
		}
		return v
	case []any:
		for i, child := range v {
			v[i] = redactNode(child)
		}
		return v
	default:
		return n
	}
}

// isSensitiveKey matches on the local part of a possibly module-qualified key
// (e.g. "openconfig-system:auth-password" → "auth-password"), lower-cased.
func isSensitiveKey(key string) bool {
	local := key
	if i := strings.LastIndexByte(local, ':'); i >= 0 {
		local = local[i+1:]
	}
	local = strings.ToLower(local)
	for _, s := range sensitiveKeySubstrings {
		if strings.Contains(local, s) {
			return true
		}
	}
	return false
}

// NewDeviceConfig wraps already-redacted CONFIG-datastore bytes as a
// DeviceConfig with Running set; Startup/Candidate stay nil (no gNMI
// equivalent). Returns nil for empty input so the Device carries no config.
// Called by the runner post-Translate (the same decoration pattern as
// AssignPrimaryIP), keeping config capture out of the pure Translate path.
func NewDeviceConfig(running []byte) *diode.DeviceConfig {
	if len(running) == 0 {
		return nil
	}
	return &diode.DeviceConfig{Running: running}
}
