package config

import (
	"errors"
	"os"
	"strings"
)

// ResolveEnv replaces environment variable placeholders in the format ${VAR} with their actual values.
func ResolveEnv(value string) (string, error) {
	// Check if the value starts with "${" and ends with "}"
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		// Extract the environment variable name
		envVar := value[2 : len(value)-1]
		// Get the value of the environment variable
		envValue := os.Getenv(envVar)
		if envValue != "" {
			return envValue, nil
		}
		return "", errors.New("a provided environment variable is not set")
	}
	// Return the original value if no substitution occurs
	return value, nil
}

// ResolveEnvInMap recursively traverses and resolves env vars in map[string]any structures.
func ResolveEnvInMap(data map[string]any) error {
	for key, val := range data {
		switch v := val.(type) {
		case string:
			resolved, err := ResolveEnv(v)
			if err != nil {
				return err
			}
			data[key] = resolved
		case map[string]any:
			if err := ResolveEnvInMap(v); err != nil {
				return err
			}
		case []any:
			if err := ResolveEnvInSlice(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// ResolveEnvInSlice handles []any elements recursively.
func ResolveEnvInSlice(slice []any) error {
	for i, val := range slice {
		switch v := val.(type) {
		case string:
			resolved, err := ResolveEnv(v)
			if err != nil {
				return err
			}
			slice[i] = resolved
		case map[string]any:
			if err := ResolveEnvInMap(v); err != nil {
				return err
			}
		case []any:
			if err := ResolveEnvInSlice(v); err != nil {
				return err
			}
		}
	}
	return nil
}
