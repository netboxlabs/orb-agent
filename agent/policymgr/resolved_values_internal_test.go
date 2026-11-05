package policymgr

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestResolvedValues finds the values the secrets manager put in for a
// policy's secret references, and where they are in its data, and nothing
// else.
func TestResolvedValues(t *testing.T) {
	raw := map[string]any{
		"config": map[string]any{"retries": "${vault://secrets/a/retries}", "timeout": 5},
		"scope": map[string]any{
			"targets": []any{
				map[string]any{"host": "192.0.2.10", "community": "${vault://secrets/a/community}"},
				map[string]any{"host": "192.0.2.11", "community": "public"},
			},
		},
	}
	resolved := map[string]any{
		"config": map[string]any{"retries": "r3tr1es-v4l", "timeout": 5},
		"scope": map[string]any{
			"targets": []any{
				map[string]any{"host": "192.0.2.10", "community": "c0mmun1ty-v4l"},
				map[string]any{"host": "192.0.2.11", "community": "public"},
			},
		},
	}

	assert.ElementsMatch(t, []resolvedValue{
		{path: "config.retries", value: "r3tr1es-v4l"},
		{path: "scope.targets[0].community", value: "c0mmun1ty-v4l"},
	}, resolvedValues(raw, resolved))
	assert.Empty(t, resolvedValues(raw, raw), "data with nothing resolved")
}

// TestBackendRefusal masks a policy's resolved values in a backend's error,
// names the fields whose values it masked, and bounds the text it logs and
// the reason it stores.
func TestBackendRefusal(t *testing.T) {
	typeErr := "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `k3Y-9xQz` into int"

	t.Run("names the field whose value is masked", func(t *testing.T) {
		logged, reason := backendRefusal(typeErr, []resolvedValue{
			{path: "config.retries", value: "k3Y-9xQz"},
			{path: "scope.authentication.community", value: "n0t-qu0ted-here"},
		})
		want := "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `********` into int" +
			" (******** is the value of the secret reference at config.retries)"
		assert.Equal(t, want, reason)
		assert.Equal(t, want, logged)
	})

	t.Run("an error that quotes no value is left as it is", func(t *testing.T) {
		logged, reason := backendRefusal("400 policy name is taken", []resolvedValue{{path: "config.retries", value: "k3Y-9xQz"}})
		assert.Equal(t, "400 policy name is taken", reason)
		assert.Equal(t, "400 policy name is taken", logged)
	})

	t.Run("names at most three fields, in order", func(t *testing.T) {
		var values []resolvedValue
		for _, i := range []string{"10", "2", "0", "1"} {
			values = append(values, resolvedValue{path: "scope.targets[" + i + "].community", value: "c0mmun1ty-v4l"})
		}
		_, reason := backendRefusal("400 bad community c0mmun1ty-v4l", values)
		assert.Equal(t, "400 bad community ********"+
			" (******** is the value of the secret reference at scope.targets[0].community,"+
			" scope.targets[1].community, scope.targets[2].community and 1 more)", reason)
	})

	t.Run("bounds what it logs and stores", func(t *testing.T) {
		values := []resolvedValue{{path: "config.retries", value: "k3Y-9xQz"}}
		logged, reason := backendRefusal(typeErr+"; "+strings.Repeat("x", 20000), values)
		note := " (******** is the value of the secret reference at config.retries)"
		assert.NotContains(t, logged, "k3Y-9xQz")
		assert.NotContains(t, reason, "k3Y-9xQz")
		assert.True(t, strings.HasSuffix(reason, "... (truncated)"+note), "the reason says it is cut: %q", reason[len(reason)-120:])
		assert.LessOrEqual(t, len(reason), maxBackendErrLen+len(note))
		assert.True(t, strings.HasSuffix(logged, "... (truncated)"+note))
		assert.LessOrEqual(t, len(logged), maxMaskedErrLen+len(note))
	})

	t.Run("bounds a text that masking makes longer", func(t *testing.T) {
		// Each text is within its bound until " 0" becomes " ********".
		values := []resolvedValue{{path: "config.retries", value: "0"}}
		logged, _ := backendRefusal(strings.Repeat(" 0", 4000), values)
		assert.LessOrEqual(t, len(logged), maxMaskedErrLen+200)
		_, reason := backendRefusal(strings.Repeat(" 0", 500), values)
		assert.LessOrEqual(t, len(reason), maxBackendErrLen+200)
	})

	t.Run("cuts at the start of a character", func(t *testing.T) {
		got, cut := cutAt("abé", 3) // "é" is 2 bytes, from byte 2
		assert.Equal(t, "ab", got)
		assert.True(t, cut)
	})

	t.Run("a value the cut runs through is masked from its first byte", func(t *testing.T) {
		values := []resolvedValue{{path: "config.retries", value: "k3Y-9xQz"}}
		for _, limit := range []int{maxMaskedErrLen, maxBackendErrLen} {
			// Wherever near limit the cut falls, one of these puts it after
			// each of the value's bytes.
			for at := limit - len(truncationMarker) - len("k3Y-9xQz"); at <= limit; at++ {
				text := strings.Repeat("x", at) + "k3Y-9xQz" + strings.Repeat("y", 20000)
				logged, reason := backendRefusal(text, values)
				out := logged
				if limit == maxBackendErrLen {
					out = reason
				}
				assert.NotContains(t, out, "xk", "limit %d, the value from byte %d", limit, at)
			}
		}
	})

	t.Run("names only the fields masked in what it keeps", func(t *testing.T) {
		values := []resolvedValue{{path: "config.retries", value: "k3Y-9xQz"}}
		// The value is past the reason's cut and before the log's.
		logged, reason := backendRefusal(strings.Repeat("x ", 600)+"k3Y-9xQz into int", values)
		assert.NotContains(t, reason, "secret reference", "the reason shows no masked value to explain")
		assert.Contains(t, logged, "(******** is the value of the secret reference at config.retries)")
	})
}
