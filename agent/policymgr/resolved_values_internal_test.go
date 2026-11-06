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
// names the fields whose values the error quotes, and bounds the text it logs
// and the reason it stores.
func TestBackendRefusal(t *testing.T) {
	typeErr := "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `k3Y-9xQz` into int"
	retries := []resolvedValue{{path: "config.retries", value: "k3Y-9xQz"}}
	note := " (the error quotes the value of the secret reference at config.retries, masked as ********)"

	t.Run("names the field whose value the error quotes", func(t *testing.T) {
		logged, reason := backendRefusal(typeErr, append(retries, resolvedValue{path: "scope.authentication.community", value: "n0t-qu0ted-here"}))
		want := "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `********` into int" + note
		assert.Equal(t, want, reason)
		assert.Equal(t, want, logged)
	})

	t.Run("an error that quotes no value is left as it is", func(t *testing.T) {
		logged, reason := backendRefusal("400 policy name is taken", retries)
		assert.Equal(t, "400 policy name is taken", reason)
		assert.Equal(t, "400 policy name is taken", logged)
	})

	t.Run("names at most three fields, in order", func(t *testing.T) {
		var values []resolvedValue
		text := "400 bad communities"
		for _, i := range []string{"10", "2", "0", "1"} {
			values = append(values, resolvedValue{path: "scope.targets[" + i + "].community", value: "c0mmun1ty-v4l-" + i})
			text += " c0mmun1ty-v4l-" + i
		}
		_, reason := backendRefusal(text, values)
		assert.Equal(t, "400 bad communities ******** ******** ******** ********"+
			" (the error quotes the values of the secret references at scope.targets[0].community,"+
			" scope.targets[1].community, scope.targets[2].community and 1 more, masked as ********)", reason)
	})

	t.Run("names no field whose value another field shares", func(t *testing.T) {
		// Only the value tells which field the error quotes: naming every
		// field that holds it would claim the error quotes them all, and
		// show that their secrets are equal.
		shared := []resolvedValue{
			{path: "config.retries", value: "k3Y-9xQz"},
			{path: "scope.authentication.community", value: "k3Y-9xQz"},
		}
		_, reason := backendRefusal(typeErr, shared)
		assert.Equal(t, "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `********` into int"+
			" (the error quotes a value more than one secret reference holds, masked as ********)", reason)

		_, reason = backendRefusal("400 bad k3Y-9xQz and Sec0nd-v4l", append(shared, resolvedValue{path: "config.timeout", value: "Sec0nd-v4l"}))
		assert.Equal(t, "400 bad ******** and ********"+
			" (the error quotes the value of the secret reference at config.timeout,"+
			" and a value more than one secret reference holds, masked as ********)", reason)
	})

	t.Run("names no field for a short value that is only a word of the YAML error", func(t *testing.T) {
		text := "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int"
		logged, reason := backendRefusal(text, []resolvedValue{{path: "scope.authentication.community", value: "int"}})
		assert.Equal(t, text, reason)
		assert.Equal(t, text, logged)
	})

	t.Run("bounds what it logs and stores", func(t *testing.T) {
		logged, reason := backendRefusal(typeErr+"; "+strings.Repeat("x", 20000), retries)
		assert.NotContains(t, logged, "k3Y-9xQz")
		assert.NotContains(t, reason, "k3Y-9xQz")
		assert.True(t, strings.HasSuffix(reason, "... (truncated)"+note), "the reason says it is cut: %q", reason[len(reason)-120:])
		assert.Len(t, strings.TrimSuffix(reason, note), maxBackendErrLen)
		assert.True(t, strings.HasSuffix(logged, "... (truncated)"+note))
		assert.Len(t, strings.TrimSuffix(logged, note), maxMaskedErrLen)
	})

	t.Run("bounds a text that masking makes longer", func(t *testing.T) {
		zero := []resolvedValue{{path: "config.retries", value: "0"}}
		zeroNote := " (the error quotes the value of the secret reference at config.retries, masked as ********)"
		// The first texts are within their bound until " 0" becomes
		// " ********"; the last is cut before masking too.
		for _, text := range []string{strings.Repeat(" 0", 500), strings.Repeat(" 0", 4000), strings.Repeat(" 0", 6000)} {
			logged, reason := backendRefusal(text, zero)
			assert.LessOrEqual(t, len(strings.TrimSuffix(reason, zeroNote)), maxBackendErrLen, "%d bytes", len(text))
			assert.LessOrEqual(t, len(strings.TrimSuffix(logged, zeroNote)), maxMaskedErrLen, "%d bytes", len(text))
			assert.True(t, strings.HasSuffix(reason, "... (truncated)"+zeroNote), "%d bytes", len(text))
		}
	})

	t.Run("cuts at the start of a character", func(t *testing.T) {
		got, cut := cutAt("abé", 3) // "é" is 2 bytes, from byte 2
		assert.Equal(t, "ab", got)
		assert.True(t, cut)
	})

	t.Run("a value a kept bound runs through is masked", func(t *testing.T) {
		for _, limit := range []int{maxMaskedErrLen, maxBackendErrLen} {
			// Wherever near limit the bound falls, one of these puts it after
			// each of the value's bytes.
			for at := limit - len(truncationMarker) - len("k3Y-9xQz"); at <= limit; at++ {
				text := strings.Repeat("x", at) + "k3Y-9xQz" + strings.Repeat("y", 20000)
				logged, reason := backendRefusal(text, retries)
				out := logged
				if limit == maxBackendErrLen {
					out = reason
				}
				assert.NotContains(t, out, "xk", "limit %d, the value from byte %d", limit, at)
			}
		}
	})

	t.Run("a truncated value's tail a kept bound runs through is masked", func(t *testing.T) {
		// pydantic quotes a long value's first 25 and last 24 characters.
		value := "Pl41n-r3solved-credential-7f3a-and-more-to-be-truncated"
		values := []resolvedValue{{path: "config.token", value: value}}
		tail := value[len(value)-24:]
		repr := "input_value='" + value[:25] + "..." + tail + "'"
		for _, limit := range []int{maxMaskedErrLen, maxBackendErrLen} {
			for at := limit - len(truncationMarker) - len(repr); at <= limit; at++ {
				logged, reason := backendRefusal(strings.Repeat("x", at)+repr+strings.Repeat("y", 20000), values)
				out := logged
				if limit == maxBackendErrLen {
					out = reason
				}
				assert.NotContains(t, out, "..."+tail[:1], "limit %d, the repr from byte %d", limit, at)
			}
		}
	})

	t.Run("a value the end of what it masks runs through is masked when kept", func(t *testing.T) {
		// Masking each whole value shortens the text by 47 bytes, enough to
		// bring the end of what is masked within what is logged.
		value := "Pl41n-r3solved-credential-7f3a-and-more-to-be-truncated"
		values := []resolvedValue{{path: "config.token", value: value}}
		prefix := strings.Repeat(value+" ", 140)
		// One of these puts the end of what is masked, past maxMaskedErrLen,
		// after each of the last value's first bytes.
		for at := maxMaskedErrLen; at <= maxMaskedErrLen+2*len(value); at++ {
			logged, _ := backendRefusal(prefix+strings.Repeat("y", at-len(prefix))+value+strings.Repeat("z", 20000), values)
			assert.NotContains(t, logged, "yP", "the last value from byte %d", at)
		}
	})

	t.Run("names a field whose value is quoted past the reason's bound", func(t *testing.T) {
		logged, reason := backendRefusal(strings.Repeat("x ", 600)+"k3Y-9xQz into int", retries)
		assert.True(t, strings.HasSuffix(reason, note), "the reason still says what the error quotes: %q", reason)
		assert.Contains(t, logged, "******** into int"+note)
	})

	t.Run("names no field for the error's own bytes at the end of what it masks", func(t *testing.T) {
		// The error quotes the retries value; "parse" starts with the
		// community's first 2 bytes, and one of these puts the end of the
		// text masked between them and the rest.
		values := append(retries, resolvedValue{path: "scope.authentication.community", value: "pa55-w0rd-xyz"})
		for at := maxMaskedErrLen; at <= maxMaskedErrLen+50; at++ {
			logged, reason := backendRefusal(typeErr+strings.Repeat("y", at-len(typeErr))+"parse error"+strings.Repeat("z", 20000), values)
			assert.True(t, strings.HasSuffix(logged, note), "parse from byte %d", at)
			assert.True(t, strings.HasSuffix(reason, note), "parse from byte %d", at)
		}
	})
}

// TestComparePaths orders the numbers in paths as numbers.
func TestComparePaths(t *testing.T) {
	assert.Negative(t, comparePaths("a[2]", "a[10]"))
	assert.Positive(t, comparePaths("a[10]", "a[2]"))
	assert.Negative(t, comparePaths("a[002]", "a[10]"), "leading zeros do not count")
	assert.Negative(t, comparePaths("a", "a.b"), "a path before the paths under it")
	assert.Positive(t, comparePaths("a.b", "a"))
	assert.Negative(t, comparePaths("a.b", "a.c"))
}
