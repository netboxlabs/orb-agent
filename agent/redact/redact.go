package redact

import (
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
)

// MaskedSecret is the value used to replace sensitive information in logs
const MaskedSecret = "********"

// sensitiveFieldPatterns contains lowercase exact field names that identify sensitive fields
var sensitiveFieldPatterns = []string{
	"client_secret",
	"clientsecret",
	"password",
	"private_key",
	"privatekey",
	"access_token",
	"accesstoken",
	"api_key",
	"apikey",
	"auth_token",
	"authtoken",
	"bearer",
	"jwt",
	"secret_id", // A Vault AppRole's credential
	"role_id",   // Its role: Vault accepts it alone for a role that binds no secret_id
	"secret",    // Exact match only
	"token",     // Exact match only
}

// sensitiveFieldSuffixes contains lowercase suffixes that indicate sensitive fields
var sensitiveFieldSuffixes = []string{
	"_secret",
	"_password",
	"_token",
	"_private_key",
	"_api_key",
	"_auth_key",
}

// sensitiveContainers names the fields whose every value is a credential but
// those of the fields listed, which name none. A Vault login's auth_args holds
// the login method's arguments: a method the lists above have no names for is
// still masked whole.
var sensitiveContainers = map[string][]string{
	"auth_args": {"mount_path", "username", "role", "service_account_file"},
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
	"-private-key",
	"-api-key",
	"-auth-key",
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
	if val.Kind() == reflect.Pointer {
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
		// Redact non-empty string values (preserve empty strings for debugging)
		if val.Kind() == reflect.String {
			if val.String() != "" {
				return MaskedSecret
			}
			return "" // Preserve empty strings
		}
		// Redact slices/arrays of strings (e.g., url.Values which is map[string][]string)
		if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
			return redactSliceSensitive(val)
		}
		// Redact numbers: YAML decodes a credential written as unquoted
		// digits into an untyped map, such as a Vault auth_args, as one.
		if isNumber(val.Kind()) {
			return MaskedSecret
		}
		// Keep a bool, such as wrapping_token: it holds no credential.
	}

	if keep, ok := sensitiveContainers[strings.ToLower(fieldName)]; ok && val.Kind() == reflect.Map {
		return redactContainer(val, keep)
	}

	switch val.Kind() {
	case reflect.Map:
		return redactMap(val)
	case reflect.Struct:
		return redactStruct(val)
	case reflect.Slice, reflect.Array:
		return redactSlice(val)
	case reflect.String:
		return URL(val.String())
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
		keyStr := mapKey(iter.Key())
		// Redact the value, passing the field name for sensitive field detection
		result[keyStr] = redactValue(iter.Value(), keyStr)
	}

	return result
}

// mapKey returns a map key as a string.
func mapKey(key reflect.Value) string {
	if key.Kind() == reflect.String {
		return key.String()
	}
	if key.CanInterface() {
		// Safely convert non-string keys using fmt.Sprintf
		if str, ok := key.Interface().(string); ok {
			return str
		}
		return fmt.Sprintf("%v", key.Interface())
	}
	// Fallback for unexported keys
	return fmt.Sprintf("%v", key)
}

// URL returns s with the user info of the URL it is masked as ********, when
// s is a URL that carries one, as a Vault address does for a proxy that asks
// for basic auth in front of Vault. The user and the password are masked
// together: the user is half of the login, the whole of it when the password
// is empty, and can be a token. Any other s is returned as it is.
func URL(s string) string {
	scheme := strings.Index(s, "://")
	if scheme < 0 {
		return opaqueURL(s)
	}
	if !strings.Contains(s[scheme:], "@") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		// No URL parser reads it, as when a password holds a / ? # % or a
		// space that is not escaped, or a parser reads its @ as part of a
		// path, query or fragment, as when a token given as the user holds a
		// / ? or #. Where its user info ends is a guess: everything between
		// :// and the last @ is masked, even when the @ is a path's.
		return s[:scheme+len("://")] + MaskedSecret + s[strings.LastIndex(s, "@"):]
	}
	// A * would be escaped in a URL's user info: xxxxx is written in place
	// of it, and replaced.
	masked := *u
	masked.User = url.User("xxxxx")
	return strings.Replace(masked.String(), "://xxxxx@", "://"+MaskedSecret+"@", 1)
}

// opaqueURL masks, in a URL written without //, which a parser reads as a
// scheme and an opaque part, as in https:user:password@host or
// user:password@host, everything between its scheme and its last @.
func opaqueURL(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || !strings.Contains(u.Opaque, "@") {
		return s
	}
	return s[:strings.Index(s, ":")+1] + MaskedSecret + s[strings.LastIndex(s, "@"):]
}

// isString reports whether val holds a string, through any pointer or
// interface.
func isString(val reflect.Value) bool {
	for val.IsValid() && (val.Kind() == reflect.Pointer || val.Kind() == reflect.Interface) {
		if val.IsNil() {
			return false
		}
		val = val.Elem()
	}
	return val.IsValid() && val.Kind() == reflect.String
}

// redactContainer masks every value of a sensitive container's map but those
// of the fields named in keep, which are redacted as anywhere else.
func redactContainer(val reflect.Value, keep []string) any {
	if val.IsNil() {
		return nil
	}

	result := make(map[string]any, val.Len())
	iter := val.MapRange()
	for iter.Next() {
		keyStr := mapKey(iter.Key())
		// A login reads a field under its exact name, and as a string.
		if slices.Contains(keep, keyStr) && isString(iter.Value()) {
			result[keyStr] = redactValue(iter.Value(), keyStr)
		} else {
			result[keyStr] = maskLeaves(iter.Value())
		}
	}

	return result
}

// maskLeaves masks every string and number in val, nested or listed, and
// keeps empty strings, bools and the shape of its maps and slices.
func maskLeaves(val reflect.Value) any {
	if !val.IsValid() {
		return nil
	}

	switch val.Kind() {
	case reflect.Pointer, reflect.Interface:
		if val.IsNil() {
			return nil
		}
		return maskLeaves(val.Elem())
	case reflect.String:
		if val.String() == "" {
			return ""
		}
		return MaskedSecret
	case reflect.Bool:
		return val.Bool()
	case reflect.Map:
		if val.IsNil() {
			return nil
		}
		result := make(map[string]any, val.Len())
		iter := val.MapRange()
		for iter.Next() {
			result[mapKey(iter.Key())] = maskLeaves(iter.Value())
		}
		return result
	case reflect.Slice, reflect.Array:
		if val.Kind() == reflect.Slice && val.IsNil() {
			return nil
		}
		result := make([]any, val.Len())
		for i := range val.Len() {
			result[i] = maskLeaves(val.Index(i))
		}
		return result
	default:
		// A number, or anything else a credential could be held in.
		return MaskedSecret
	}
}

// isNumber reports whether kind is an integer or a float.
func isNumber(kind reflect.Kind) bool {
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
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

// redactSliceSensitive handles redaction of slice/array values for sensitive fields
// It masks all string elements since the field itself is sensitive (e.g., url.Values)
func redactSliceSensitive(val reflect.Value) any {
	if val.Kind() == reflect.Slice && val.IsNil() {
		return nil
	}

	length := val.Len()
	result := make([]any, length)

	for i := 0; i < length; i++ {
		elem := val.Index(i)
		// Mask string elements in sensitive slices
		if elem.Kind() == reflect.String {
			result[i] = MaskedSecret
		} else {
			result[i] = redactValue(elem, "")
		}
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

	// Check exact matches first (to avoid false positives like "token_url")
	for _, pattern := range sensitiveFieldPatterns {
		if lower == pattern {
			return true
		}
	}

	// Check suffixes (e.g., "my_custom_secret" matches "_secret")
	for _, suffix := range sensitiveFieldSuffixes {
		if strings.HasSuffix(lower, suffix) {
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
			// Mask the next argument if it exists
			if i+1 < len(result) {
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
