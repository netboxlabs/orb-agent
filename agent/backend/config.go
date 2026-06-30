package backend

// ConfigStringOrDefault returns config[name] when it is a non-nil string,
// otherwise it returns fallback.
func ConfigStringOrDefault(config map[string]any, name, fallback string) string {
	if v, ok := config[name].(string); ok {
		return v
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
