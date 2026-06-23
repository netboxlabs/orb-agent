package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetBuildVersion asserts the observable contract: the returned string has
// no leading or trailing whitespace (idempotent TrimSpace). The embedded content
// itself is set at build time and cannot be changed in unit tests.
func TestGetBuildVersion(t *testing.T) {
	v := GetBuildVersion()
	assert.Equal(t, strings.TrimSpace(v), v, "GetBuildVersion must return a whitespace-trimmed string")
}

// TestGetBuildCommit asserts the same idempotent-trim contract for the commit string.
func TestGetBuildCommit(t *testing.T) {
	c := GetBuildCommit()
	assert.Equal(t, strings.TrimSpace(c), c, "GetBuildCommit must return a whitespace-trimmed string")
}
