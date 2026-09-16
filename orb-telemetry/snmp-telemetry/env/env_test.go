package env

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Reference is what decides which name a caller checks against its allowlist,
// so it has to report exactly the name ResolveEnv would read, and report
// nothing for a value that is not a reference.
func TestReference(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantName string
		wantOk   bool
	}{
		{name: "a whole reference", value: "${SNMP_COMMUNITY}", wantName: "SNMP_COMMUNITY", wantOk: true},
		{name: "a literal", value: "public", wantOk: false},
		{name: "an empty name is not a reference", value: "${}", wantOk: false},
		{name: "an empty value", value: "", wantOk: false},
		{name: "an unclosed reference", value: "${SNMP_COMMUNITY", wantOk: false},
		{name: "a reference with text around it", value: "prefix-${SNMP_COMMUNITY}", wantOk: false},
		{name: "a reference with a trailing suffix", value: "${SNMP_COMMUNITY}-suffix", wantOk: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, ok := Reference(tt.value)
			assert.Equal(t, tt.wantOk, ok)
			assert.Equal(t, tt.wantName, name)
		})
	}
}

func TestResolveEnv_SubstitutesAReference(t *testing.T) {
	t.Setenv("SNMP_COMMUNITY", "read-only-community")

	got, err := ResolveEnv("${SNMP_COMMUNITY}")

	require.NoError(t, err)
	assert.Equal(t, "read-only-community", got)
}

func TestResolveEnv_PassesALiteralThrough(t *testing.T) {
	got, err := ResolveEnv("public")

	require.NoError(t, err)
	assert.Equal(t, "public", got)
}

// A value naming nothing is not a reference, so it stays a literal rather than
// becoming an error or an empty credential.
func TestResolveEnv_PassesAnEmptyNameThrough(t *testing.T) {
	got, err := ResolveEnv("${}")

	require.NoError(t, err)
	assert.Equal(t, "${}", got)
}

// An unset name is an error rather than an empty credential, so a policy is
// refused instead of running with nothing to authenticate with.
func TestResolveEnv_RejectsAnUnsetName(t *testing.T) {
	_, err := ResolveEnv("${SNMP_COMMUNITY_UNSET}")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "SNMP_COMMUNITY_UNSET")
}

// A name set to the empty string is treated as unset: it cannot authenticate
// either, and the policy is better refused than silently blank.
func TestResolveEnv_RejectsANameSetToEmpty(t *testing.T) {
	t.Setenv("SNMP_COMMUNITY", "")

	_, err := ResolveEnv("${SNMP_COMMUNITY}")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "SNMP_COMMUNITY")
}
