package env

import (
	"fmt"
	"os"
	"strings"
)

// Reference reports the environment variable a value names, when the whole
// value is a ${NAME} reference. A value that is not a reference, or that names
// nothing, reports false. ResolveEnv reads exactly the name reported here, so a
// caller holding an untrusted value can decide whether that name may be read
// before the value is substituted.
func Reference(value string) (string, bool) {
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		return "", false
	}
	name := value[2 : len(value)-1]
	if name == "" {
		return "", false
	}
	return name, true
}

// ResolveEnv resolves environment variables in a string value.
// If the value is a ${NAME} reference, it returns the value of NAME, or an
// error when NAME is not set. Otherwise, it returns the original value.
func ResolveEnv(value string) (string, error) {
	name, ok := Reference(value)
	if !ok {
		// Not a reference, so there is nothing to substitute.
		return value, nil
	}
	envValue := os.Getenv(name)
	if envValue != "" {
		return envValue, nil
	}
	return "", fmt.Errorf("environment variable %s is not set", name)
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
