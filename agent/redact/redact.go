package redact

import (
	"reflect"
	"strings"
)

// MaskedSecret is the value used to replace sensitive information in logs
const MaskedSecret = "********"

// sensitiveFieldPatterns contains lowercase patterns that identify sensitive fields
var sensitiveFieldPatterns = []string{
	"client_secret",
	"clientsecret",
	"password",
	"private_key",
	"privatekey",
	"access_token",
	"accesstoken",
	"token",
	"secret",
	"api_key",
	"apikey",
	"auth_token",
	"authtoken",
	"bearer",
	"jwt",
}

// sensitiveFlagPatterns contains patterns for sensitive CLI flags
var sensitiveFlagPatterns = []string{
	"--diode-client-secret",
	"--client-secret",
	"--password",
	"--token",
	"--api-key",
	"--auth-token",
	"--private-key",
	"--bearer",
	"--jwt",
}

// sensitiveFlagSuffixes contains suffixes that indicate a sensitive flag
var sensitiveFlagSuffixes = []string{
	"-secret",
	"-password",
	"-token",
	"-key",
}

// SensitiveData creates a deep copy of the input data and masks sensitive fields.
// It handles maps, structs, slices, and primitive types recursively.
// Returns the redacted copy suitable for logging - original data is never modified.
func SensitiveData(data any) any {
	if data == nil {
		return nil
	}

	val := reflect.ValueOf(data)
	return redactValue(val, "")
}

// redactValue recursively redacts values based on their type
func redactValue(val reflect.Value, fieldName string) any {
	if !val.IsValid() {
		return nil
	}

	// Handle pointers
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return nil
		}
		elem := val.Elem()
		redacted := redactValue(elem, fieldName)
		// Return the redacted value directly, not wrapped in pointer
		return redacted
	}

	// Handle interfaces
	if val.Kind() == reflect.Interface {
		if val.IsNil() {
			return nil
		}
		return redactValue(val.Elem(), fieldName)
	}

	// Check if this field should be redacted
	if fieldName != "" && isSensitiveField(fieldName) {
		// Only redact string values
		if val.Kind() == reflect.String {
			return MaskedSecret
		}
		// For non-string sensitive fields, return as-is (e.g., port numbers)
	}

	switch val.Kind() {
	case reflect.Map:
		return redactMap(val)
	case reflect.Struct:
		return redactStruct(val)
	case reflect.Slice, reflect.Array:
		return redactSlice(val)
	case reflect.String:
		return val.String()
	case reflect.Bool:
		return val.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return val.Uint()
	case reflect.Float32, reflect.Float64:
		return val.Float()
	default:
		// For unknown types, try to return the interface value
		if val.CanInterface() {
			return val.Interface()
		}
		return nil
	}
}

// redactMap handles redaction of map types
func redactMap(val reflect.Value) any {
	if val.IsNil() {
		return nil
	}

	result := make(map[string]any, val.Len())
	iter := val.MapRange()
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Get the key as a string
		keyStr := ""
		if key.Kind() == reflect.String {
			keyStr = key.String()
		} else if key.CanInterface() {
			keyStr = key.Interface().(string)
		}

		// Redact the value, passing the field name for sensitive field detection
		result[keyStr] = redactValue(value, keyStr)
	}

	return result
}

// redactStruct handles redaction of struct types
func redactStruct(val reflect.Value) any {
	typ := val.Type()
	result := make(map[string]any, val.NumField())

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldValue := val.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get the field name from tags or use the struct field name
		fieldName := field.Name
		if jsonTag := field.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			// Parse json tag (handle "name,omitempty" format)
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				fieldName = parts[0]
			}
		} else if yamlTag := field.Tag.Get("yaml"); yamlTag != "" && yamlTag != "-" {
			// Parse yaml tag
			parts := strings.Split(yamlTag, ",")
			if parts[0] != "" {
				fieldName = parts[0]
			}
		}

		// Redact the field value
		result[fieldName] = redactValue(fieldValue, fieldName)
	}

	return result
}

// redactSlice handles redaction of slice and array types
func redactSlice(val reflect.Value) any {
	if val.Kind() == reflect.Slice && val.IsNil() {
		return nil
	}

	length := val.Len()
	result := make([]any, length)

	for i := 0; i < length; i++ {
		elem := val.Index(i)
		result[i] = redactValue(elem, "")
	}

	return result
}

// isSensitiveField checks if a field name matches sensitive patterns
func isSensitiveField(fieldName string) bool {
	lower := strings.ToLower(fieldName)
	for _, pattern := range sensitiveFieldPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// Args creates a copy of command-line arguments with sensitive values masked.
// It detects sensitive flags (like --client-secret) and masks their values.
// Returns a new slice - the original is never modified.
func Args(args []string) []string {
	if args == nil {
		return nil
	}

	// Create a copy of the slice
	result := make([]string, len(args))
	copy(result, args)

	// Scan for sensitive flags and mask the following value
	for i := 0; i < len(result); i++ {
		if isSensitiveArg(result[i]) {
			// Mask the next argument if it exists and isn't another flag
			if i+1 < len(result) && !strings.HasPrefix(result[i+1], "-") {
				result[i+1] = MaskedSecret
				i++ // Skip the next iteration since we just processed it
			}
		}
	}

	return result
}

// isSensitiveArg checks if a CLI argument is a sensitive flag
func isSensitiveArg(arg string) bool {
	lower := strings.ToLower(arg)

	// Check exact matches
	for _, pattern := range sensitiveFlagPatterns {
		if lower == pattern {
			return true
		}
	}

	// Check suffixes
	for _, suffix := range sensitiveFlagSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}

	return false
}
