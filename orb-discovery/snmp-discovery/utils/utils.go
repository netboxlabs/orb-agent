package utils

import (
	"fmt"
	"os"
	"strings"
)

// ResolveEnv resolves environment variables in a string value.
// If the value starts with ${ and ends with }, it extracts the environment variable name
// and returns its value. If the environment variable is not set, it returns an error.
// Otherwise, it returns the original value.
func ResolveEnv(value string) (string, error) {
	// Check if the value starts with ${ and ends with }
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		// Extract the environment variable name
		envVar := value[2 : len(value)-1]
		// Skip empty environment variable names
		if envVar == "" {
			return value, nil
		}
		// Get the value of the environment variable
		envValue := os.Getenv(envVar)
		if envValue != "" {
			return envValue, nil
		}
		return "", fmt.Errorf("environment variable %s is not set", envVar)
	}
	// Return the original value if no substitution occurs
	return value, nil
}

// ResolveEnvOrExit resolves environment variables in a string value.
// If the value starts with ${ and ends with }, it extracts the environment variable name
// and returns its value. If the environment variable is not set, it prints an error
// and exits with code 1. Otherwise, it returns the original value.
func ResolveEnvOrExit(value string) string {
	resolved, err := ResolveEnv(value)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	return resolved
}
