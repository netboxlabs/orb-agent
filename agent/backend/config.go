package backend

import "fmt"

// ConfigStringOrDefault returns config[name] when it is a non-nil string,
// otherwise it returns fallback.
func ConfigStringOrDefault(config map[string]any, name, fallback string) string {
	if v, ok := config[name].(string); ok {
		return v
	}
	return fallback
}

// ConfigValueOrDefault returns config[name] stringified via fmt.Sprintf("%v", …)
// when the key is present, otherwise it returns fallback. Unlike
// ConfigStringOrDefault it does not type-assert: it accepts any value type, which
// matches reads of numeric-or-string keys such as "port" that YAML may decode as
// an int or a string.
func ConfigValueOrDefault(config map[string]any, name, fallback string) string {
	if v, prs := config[name]; prs {
		return fmt.Sprintf("%v", v)
	}
	return fallback
}

// ConfigBoolOrDefault returns config[name] when it is a bool,
// otherwise it returns fallback.
func ConfigBoolOrDefault(config map[string]any, name string, fallback bool) bool {
	if v, ok := config[name].(bool); ok {
		return v
	}
	return fallback
}
