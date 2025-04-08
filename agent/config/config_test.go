package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func TestResolveEnv(t *testing.T) {
	err := os.Setenv("TEST_VAR", "test_value")
	assert.NoError(t, err, "failed to set environment variable")
	defer func() {
		err := os.Unsetenv("TEST_VAR")
		assert.NoError(t, err, "failed to unset environment variable")
	}()

	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{"${TEST_VAR}", "test_value", false},
		{"${UNSET_VAR}", "", true},
		{"no_env_var", "no_env_var", false},
	}

	for _, test := range tests {
		result, err := config.ResolveEnv(test.input)
		if test.hasError {
			assert.Error(t, err, "expected error for input %s", test.input)
		} else {
			assert.NoError(t, err, "unexpected error for input %s", test.input)
		}
		assert.Equal(t, test.expected, result, "unexpected result for input %s", test.input)
	}
}

func TestResolveEnvError(t *testing.T) {
	err := os.Unsetenv("UNSET_VAR") // Ensure the variable is not set
	assert.NoError(t, err, "failed to unset environment variable")

	_, err = config.ResolveEnv("${UNSET_VAR}")
	assert.Error(t, err, "expected error for unset environment variable")
}

func TestResolveEnvInMap(t *testing.T) {
	err := os.Setenv("TEST_VAR", "test_value")
	assert.NoError(t, err, "failed to set environment variable")
	defer func() {
		err := os.Unsetenv("TEST_VAR")
		assert.NoError(t, err, "failed to unset environment variable")
	}()

	data := map[string]any{
		"key1": "${TEST_VAR}",
		"key2": "static_value",
		"nested": map[string]any{
			"key3": "${TEST_VAR}",
		},
		"list": []any{
			"${TEST_VAR}",
		},
	}

	err = config.ResolveEnvInMap(data)
	assert.NoError(t, err, "unexpected error")

	assert.Equal(t, "test_value", data["key1"], "unexpected value for key1")
	assert.Equal(t, "static_value", data["key2"], "unexpected value for key2")

	nested, ok := data["nested"].(map[string]any)
	assert.True(t, ok, "expected nested to be a map")
	assert.Equal(t, "test_value", nested["key3"], "unexpected value for nested.key3")
}

func TestResolveEnvInMapError(t *testing.T) {
	err := os.Unsetenv("UNSET_VAR") // Ensure the variable is not set
	assert.NoError(t, err, "failed to unset environment variable")

	data := map[string]any{
		"key1": "${UNSET_VAR}",
	}

	err = config.ResolveEnvInMap(data)
	assert.Error(t, err, "expected error for unset environment variable in map")

	// Test with a nested map
	data = map[string]any{
		"key1": map[string]any{
			"nested_key": "${UNSET_VAR}",
		},
	}
	err = config.ResolveEnvInMap(data)
	assert.Error(t, err, "expected error for unset environment variable in nested map")

	// Test with a nested slice
	data = map[string]any{
		"key1": []any{"${UNSET_VAR}"},
	}
	err = config.ResolveEnvInMap(data)
	assert.Error(t, err, "expected error for unset environment variable in nested slice")
}

func TestResolveEnvInSlice(t *testing.T) {
	err := os.Setenv("TEST_VAR", "test_value")
	assert.NoError(t, err, "failed to set environment variable")
	defer func() {
		err := os.Unsetenv("TEST_VAR")
		assert.NoError(t, err, "failed to unset environment variable")
	}()

	data := []any{
		"${TEST_VAR}",
		"static_value",
		map[string]any{
			"key1": "${TEST_VAR}",
		},
		[]any{"${TEST_VAR}"},
	}

	err = config.ResolveEnvInSlice(data)
	assert.NoError(t, err, "unexpected error")

	assert.Equal(t, "test_value", data[0], "unexpected value at index 0")
	assert.Equal(t, "static_value", data[1], "unexpected value at index 1")

	nestedMap, ok := data[2].(map[string]any)
	assert.True(t, ok, "expected index 2 to be a map")
	assert.Equal(t, "test_value", nestedMap["key1"], "unexpected value for nestedMap.key1")

	nestedSlice, ok := data[3].([]any)
	assert.True(t, ok, "expected index 3 to be a slice")
	assert.Equal(t, "test_value", nestedSlice[0], "unexpected value for nestedSlice[0]")
}

func TestResolveEnvInSliceError(t *testing.T) {
	err := os.Unsetenv("UNSET_VAR") // Ensure the variable is not set
	assert.NoError(t, err, "failed to unset environment variable")

	data := []any{
		"${UNSET_VAR}",
	}

	err = config.ResolveEnvInSlice(data)
	assert.Error(t, err, "expected error for unset environment variable in slice")

	// Test with a nested map
	data = []any{
		map[string]any{
			"key1": "${UNSET_VAR}",
		},
	}
	err = config.ResolveEnvInSlice(data)
	assert.Error(t, err, "expected error for unset environment variable in nested map")
	// Test with a nested slice
	data = []any{
		[]any{"${UNSET_VAR}"},
	}
	err = config.ResolveEnvInSlice(data)
	assert.Error(t, err, "expected error for unset environment variable in nested slice")
}
