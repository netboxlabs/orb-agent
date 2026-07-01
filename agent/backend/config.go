package backend

import "fmt"

// ConfigValueOrDefault returns config[name] as type T when the key is present
// and holds a value of type T, otherwise it returns fallback.
//
// As a special case, when T is string and the present value is NOT already a
// string (for example a YAML-numeric "port"), it is formatted with
// fmt.Sprintf("%v", …) rather than dropped. bool and other typed reads stay
// strict: a present value of the wrong type yields fallback.
func ConfigValueOrDefault[T any](config map[string]any, name string, fallback T) T {
	value, present := config[name]
	if !present {
		return fallback
	}
	if typed, ok := value.(T); ok {
		return typed
	}
	// Present but not of type T. If a string was requested, coerce via %v so
	// numeric-or-string keys (e.g. "port") read consistently as a string.
	if _, wantString := any(fallback).(string); wantString {
		if coerced, ok := any(fmt.Sprintf("%v", value)).(T); ok {
			return coerced
		}
	}
	return fallback
}
