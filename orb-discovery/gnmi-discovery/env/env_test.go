package env

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveEnv(t *testing.T) {
	t.Run("resolves a set variable", func(t *testing.T) {
		t.Setenv("GNMI_TEST_VAR", "resolved-value")
		got, err := ResolveEnv("${GNMI_TEST_VAR}")
		require.NoError(t, err)
		assert.Equal(t, "resolved-value", got)
	})

	t.Run("errors on an unset variable", func(t *testing.T) {
		// Empty value is indistinguishable from unset to os.Getenv, and using
		// t.Setenv keeps the test isolated (auto-restored on cleanup).
		t.Setenv("GNMI_TEST_UNSET", "")
		_, err := ResolveEnv("${GNMI_TEST_UNSET}")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "GNMI_TEST_UNSET")
	})

	t.Run("empty variable name is returned verbatim", func(t *testing.T) {
		got, err := ResolveEnv("${}")
		require.NoError(t, err)
		assert.Equal(t, "${}", got)
	})

	t.Run("non-substitution value is returned unchanged", func(t *testing.T) {
		got, err := ResolveEnv("plain-value")
		require.NoError(t, err)
		assert.Equal(t, "plain-value", got)
	})

	t.Run("partial delimiters are not substituted", func(t *testing.T) {
		got, err := ResolveEnv("${unterminated")
		require.NoError(t, err)
		assert.Equal(t, "${unterminated", got)
	})
}

func TestResolveEnvOrExit_Success(t *testing.T) {
	t.Setenv("GNMI_TEST_OK", "ok-value")
	assert.Equal(t, "ok-value", ResolveEnvOrExit("${GNMI_TEST_OK}"))
	// Non-substitution path also returns the original value.
	assert.Equal(t, "literal", ResolveEnvOrExit("literal"))
}

// TestResolveEnvOrExit_ExitsOnUnset exercises the os.Exit(1) branch by
// re-executing this test in a subprocess and asserting it exits non-zero.
func TestResolveEnvOrExit_ExitsOnUnset(t *testing.T) {
	if os.Getenv("GNMI_ENV_CRASHER") == "1" {
		ResolveEnvOrExit("${GNMI_TEST_DEFINITELY_UNSET}")
		return // unreachable: ResolveEnvOrExit should os.Exit(1) first
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestResolveEnvOrExit_ExitsOnUnset")
	cmd.Env = append(os.Environ(), "GNMI_ENV_CRASHER=1")
	err := cmd.Run()
	var ee *exec.ExitError
	require.True(t, errors.As(err, &ee), "expected an ExitError, got %v", err)
	assert.False(t, ee.Success(), "expected a non-zero exit code")
}
