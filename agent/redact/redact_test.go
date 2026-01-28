package redact

import (
	"reflect"
	"testing"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// TestSensitiveData_SimpleMap tests basic map redaction
func TestSensitiveData_SimpleMap(t *testing.T) {
	original := map[string]any{
		"client_secret": "my-secret-123",
		"password":      "my-password",
		"client_id":     "my-client-id",
		"url":           "https://example.com",
	}

	redacted := SensitiveData(original)

	redactedMap, ok := redacted.(map[string]any)
	if !ok {
		t.Fatalf("Expected map[string]any, got %T", redacted)
	}

	// Verify sensitive fields are masked
	if redactedMap["client_secret"] != MaskedSecret {
		t.Errorf("Expected client_secret to be %s, got %v", MaskedSecret, redactedMap["client_secret"])
	}
	if redactedMap["password"] != MaskedSecret {
		t.Errorf("Expected password to be %s, got %v", MaskedSecret, redactedMap["password"])
	}

	// Verify non-sensitive fields are preserved
	if redactedMap["client_id"] != "my-client-id" {
		t.Errorf("Expected client_id to be preserved, got %v", redactedMap["client_id"])
	}
	if redactedMap["url"] != "https://example.com" {
		t.Errorf("Expected url to be preserved, got %v", redactedMap["url"])
	}

	// Verify original is NOT mutated
	if original["client_secret"] != "my-secret-123" {
		t.Error("Original map was mutated!")
	}
}

// TestSensitiveData_NestedMap tests nested structure redaction
func TestSensitiveData_NestedMap(t *testing.T) {
	original := map[string]any{
		"backend": map[string]any{
			"client_secret": "nested-secret",
			"target":        "https://api.example.com",
		},
		"public_key": "public-value",
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)
	backend := redactedMap["backend"].(map[string]any)

	if backend["client_secret"] != MaskedSecret {
		t.Errorf("Expected nested client_secret to be masked, got %v", backend["client_secret"])
	}
	if backend["target"] != "https://api.example.com" {
		t.Errorf("Expected nested target to be preserved, got %v", backend["target"])
	}
}

// TestSensitiveData_FleetManager tests real config type
func TestSensitiveData_FleetManager(t *testing.T) {
	original := config.FleetManager{
		URL:          "https://fleet.example.com",
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
		TokenURL:     "https://auth.example.com",
	}

	redacted := SensitiveData(original)

	redactedMap, ok := redacted.(map[string]any)
	if !ok {
		t.Fatalf("Expected map[string]any, got %T", redacted)
	}

	// Verify sensitive field is masked (using yaml tag name)
	if redactedMap["client_secret"] != MaskedSecret {
		t.Errorf("Expected client_secret to be masked, got %v", redactedMap["client_secret"])
	}

	// Verify non-sensitive fields are preserved (using yaml tag names)
	if redactedMap["url"] != "https://fleet.example.com" {
		t.Errorf("Expected url to be preserved, got %v", redactedMap["url"])
	}
	if redactedMap["client_id"] != "my-client-id" {
		t.Errorf("Expected client_id to be preserved, got %v", redactedMap["client_id"])
	}

	// Verify original struct is NOT mutated
	if original.ClientSecret != "my-client-secret" {
		t.Error("Original struct was mutated!")
	}
}

// TestSensitiveData_GitManager tests GitManager with multiple secrets
func TestSensitiveData_GitManager(t *testing.T) {
	original := config.GitManager{
		URL:        "https://git.example.com",
		Username:   "gituser",
		Password:   "gitpass123",
		PrivateKey: "-----BEGIN RSA PRIVATE KEY-----",
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// Verify both sensitive fields are masked (using yaml tag names)
	if redactedMap["password"] != MaskedSecret {
		t.Errorf("Expected password to be masked, got %v", redactedMap["password"])
	}
	if redactedMap["private_key"] != MaskedSecret {
		t.Errorf("Expected private_key to be masked, got %v", redactedMap["private_key"])
	}

	// Verify non-sensitive fields are preserved (using yaml tag names)
	if redactedMap["username"] != "gituser" {
		t.Errorf("Expected username to be preserved, got %v", redactedMap["username"])
	}
}

// TestSensitiveData_BackendCommons tests BackendCommons with Diode config
func TestSensitiveData_BackendCommons(t *testing.T) {
	original := config.BackendCommons{}
	original.Diode.Target = "https://diode.example.com"
	original.Diode.ClientID = "diode-client"
	original.Diode.ClientSecret = "diode-secret-123"
	original.Diode.AgentName = "test-agent"

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)
	diode := redactedMap["Diode"].(map[string]any)

	// Verify sensitive field is masked (using yaml tag names)
	if diode["client_secret"] != MaskedSecret {
		t.Errorf("Expected Diode.client_secret to be masked, got %v", diode["client_secret"])
	}

	// Verify non-sensitive fields are preserved (using yaml tag names)
	if diode["target"] != "https://diode.example.com" {
		t.Errorf("Expected Diode.target to be preserved, got %v", diode["target"])
	}
	if diode["client_id"] != "diode-client" {
		t.Errorf("Expected Diode.client_id to be preserved, got %v", diode["client_id"])
	}
}

// TestSensitiveData_Slice tests slice redaction
func TestSensitiveData_Slice(t *testing.T) {
	original := []map[string]any{
		{"client_secret": "secret1", "name": "backend1"},
		{"client_secret": "secret2", "name": "backend2"},
	}

	redacted := SensitiveData(original)

	redactedSlice, ok := redacted.([]any)
	if !ok {
		t.Fatalf("Expected []any, got %T", redacted)
	}

	// Verify each item is redacted
	for i, item := range redactedSlice {
		itemMap := item.(map[string]any)
		if itemMap["client_secret"] != MaskedSecret {
			t.Errorf("Expected item %d client_secret to be masked, got %v", i, itemMap["client_secret"])
		}
		if itemMap["name"] == "" {
			t.Errorf("Expected item %d name to be preserved", i)
		}
	}

	// Verify original is NOT mutated
	if original[0]["client_secret"] != "secret1" {
		t.Error("Original slice was mutated!")
	}
}

// TestSensitiveData_NilValues tests handling of nil values
func TestSensitiveData_NilValues(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  any
	}{
		{"nil input", nil, nil},
		{"nil map", map[string]any(nil), nil},
		{"nil slice", []string(nil), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SensitiveData(tt.input)
			if result != tt.want {
				t.Errorf("Expected %v, got %v", tt.want, result)
			}
		})
	}
}

// TestSensitiveData_EmptyStrings tests that empty strings are preserved
func TestSensitiveData_EmptyStrings(t *testing.T) {
	original := map[string]any{
		"client_secret": "",
		"password":      "",
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// Empty sensitive fields should be masked
	if redactedMap["client_secret"] != MaskedSecret {
		t.Errorf("Expected empty client_secret to be masked, got %v", redactedMap["client_secret"])
	}
}

// TestSensitiveData_CaseVariations tests case-insensitive matching
func TestSensitiveData_CaseVariations(t *testing.T) {
	original := map[string]any{
		"CLIENT_SECRET": "secret1",
		"ClientSecret":  "secret2",
		"client_secret": "secret3",
		"Password":      "pass1",
		"PASSWORD":      "pass2",
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// All case variations should be masked
	for key, value := range redactedMap {
		if value != MaskedSecret {
			t.Errorf("Expected %s to be masked, got %v", key, value)
		}
	}
}

// TestSensitiveData_NonStringValues tests non-string sensitive fields
func TestSensitiveData_NonStringValues(t *testing.T) {
	original := map[string]any{
		"token_port":  8080,
		"secret_flag": true,
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// Non-string sensitive fields should be preserved (not masked)
	// Note: reflection returns int64 for int types, not uint64
	if redactedMap["token_port"] != int64(8080) {
		t.Errorf("Expected token_port to be preserved, got %v (type %T)", redactedMap["token_port"], redactedMap["token_port"])
	}
	if redactedMap["secret_flag"] != true {
		t.Errorf("Expected secret_flag to be preserved, got %v", redactedMap["secret_flag"])
	}
}

// TestSensitiveData_URLValues tests url.Values redaction (map[string][]string)
func TestSensitiveData_URLValues(t *testing.T) {
	// Simulate url.Values structure: map[string][]string
	original := map[string]any{
		"client_id":     []string{"my-client-id"},
		"client_secret": []string{"my-secret-123"},
		"grant_type":    []string{"client_credentials"},
		"scope":         []string{"read write"},
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// Verify sensitive field (slice) is masked
	clientSecretSlice, ok := redactedMap["client_secret"].([]any)
	if !ok {
		t.Fatalf("Expected client_secret to be []any, got %T", redactedMap["client_secret"])
	}
	if len(clientSecretSlice) != 1 {
		t.Fatalf("Expected client_secret slice to have 1 element, got %d", len(clientSecretSlice))
	}
	if clientSecretSlice[0] != MaskedSecret {
		t.Errorf("Expected client_secret[0] to be %s, got %v", MaskedSecret, clientSecretSlice[0])
	}

	// Verify non-sensitive fields are preserved
	clientIDSlice := redactedMap["client_id"].([]any)
	if clientIDSlice[0] != "my-client-id" {
		t.Errorf("Expected client_id to be preserved, got %v", clientIDSlice[0])
	}

	grantTypeSlice := redactedMap["grant_type"].([]any)
	if grantTypeSlice[0] != "client_credentials" {
		t.Errorf("Expected grant_type to be preserved, got %v", grantTypeSlice[0])
	}

	// Verify original is NOT mutated
	if original["client_secret"].([]string)[0] != "my-secret-123" {
		t.Error("Original map was mutated!")
	}
}

// TestIsSensitiveField tests the field name pattern matching
func TestIsSensitiveField(t *testing.T) {
	tests := []struct {
		fieldName string
		want      bool
	}{
		{"client_secret", true},
		{"clientSecret", true},
		{"CLIENT_SECRET", true},
		{"password", true},
		{"Password", true},
		{"private_key", true},
		{"privateKey", true},
		{"access_token", true},
		{"accessToken", true},
		{"token", true},
		{"Token", true},
		{"api_key", true},
		{"apiKey", true},
		{"secret", true},
		{"bearer", true},
		{"jwt", true},
		{"client_id", false},
		{"username", false},
		{"url", false},
		{"target", false},
		{"token_url", false},         // Should NOT match - not exact "token"
		{"secret_name", false},       // Should NOT match - not exact "secret"
		{"my_custom_secret", true},   // Should match - ends with "_secret"
		{"my_custom_token", true},    // Should match - ends with "_token"
		{"my_custom_password", true}, // Should match - ends with "_password"
		{"oauth_private_key", true},  // Should match - ends with "_private_key"
		{"oauth_api_key", true},      // Should match - ends with "_api_key"
		{"partition_key", false},     // Should NOT match - not a sensitive key type
		{"sort_key", false},          // Should NOT match - not a sensitive key type
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			result := isSensitiveField(tt.fieldName)
			if result != tt.want {
				t.Errorf("isSensitiveField(%q) = %v, want %v", tt.fieldName, result, tt.want)
			}
		})
	}
}

// TestArgs tests command-line argument redaction
func TestArgs(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "basic client secret",
			input: []string{"--diode-client-secret", "secret123", "--host", "localhost"},
			want:  []string{"--diode-client-secret", MaskedSecret, "--host", "localhost"},
		},
		{
			name:  "multiple sensitive flags",
			input: []string{"--client-id", "id123", "--client-secret", "secret123", "--password", "pass123"},
			want:  []string{"--client-id", "id123", "--client-secret", MaskedSecret, "--password", MaskedSecret},
		},
		{
			name:  "no sensitive flags",
			input: []string{"--host", "localhost", "--port", "8080"},
			want:  []string{"--host", "localhost", "--port", "8080"},
		},
		{
			name:  "sensitive flag at end without value",
			input: []string{"--host", "localhost", "--client-secret"},
			want:  []string{"--host", "localhost", "--client-secret"},
		},
		{
			name:  "sensitive flag followed by another flag",
			input: []string{"--client-secret", "--host", "localhost"},
			want:  []string{"--client-secret", "--host", "localhost"},
		},
		{
			name:  "empty args",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "nil args",
			input: nil,
			want:  nil,
		},
		{
			name:  "token flag",
			input: []string{"--token", "mytoken123", "--url", "https://example.com"},
			want:  []string{"--token", MaskedSecret, "--url", "https://example.com"},
		},
		{
			name:  "api-key flag",
			input: []string{"--api-key", "key123"},
			want:  []string{"--api-key", MaskedSecret},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Store original for mutation check
			var originalCopy []string
			if tt.input != nil {
				originalCopy = make([]string, len(tt.input))
				copy(originalCopy, tt.input)
			}

			result := Args(tt.input)

			if !reflect.DeepEqual(result, tt.want) {
				t.Errorf("Args() = %v, want %v", result, tt.want)
			}

			// Verify original is NOT mutated
			if tt.input != nil && !reflect.DeepEqual(tt.input, originalCopy) {
				t.Error("Original args slice was mutated!")
			}
		})
	}
}

// TestArgs_RealBackendExamples tests real backend argument patterns
func TestArgs_RealBackendExamples(t *testing.T) {
	// Simulate snmp-discovery backend args
	snmpArgs := []string{
		"--dry-run",
		"--dry-run-output-dir", "/tmp/output",
		"--diode-app-name-prefix", "test-agent",
		"--host", "localhost",
		"--port", "8070",
	}
	result := Args(snmpArgs)
	// No sensitive data, should be unchanged
	if !reflect.DeepEqual(result, snmpArgs) {
		t.Error("Non-sensitive snmp args were modified")
	}

	// Simulate with diode credentials
	diodeArgs := []string{
		"--diode-target", "https://diode.example.com",
		"--diode-client-id", "client123",
		"--diode-client-secret", "secret123",
		"--diode-app-name-prefix", "test-agent",
		"--host", "localhost",
		"--port", "8070",
	}
	result = Args(diodeArgs)
	expected := []string{
		"--diode-target", "https://diode.example.com",
		"--diode-client-id", "client123",
		"--diode-client-secret", MaskedSecret,
		"--diode-app-name-prefix", "test-agent",
		"--host", "localhost",
		"--port", "8070",
	}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Diode args redaction failed.\nGot:  %v\nWant: %v", result, expected)
	}
}

// TestIsSensitiveArg tests CLI flag pattern matching
func TestIsSensitiveArg(t *testing.T) {
	tests := []struct {
		arg  string
		want bool
	}{
		{"--diode-client-secret", true},
		{"--client-secret", true},
		{"--CLIENT-SECRET", true},
		{"--password", true},
		{"--Password", true},
		{"--token", true},
		{"--api-key", true},
		{"--auth-token", true},
		{"--private-key", true},
		{"--bearer", true},
		{"--jwt", true},
		{"--my-custom-secret", true},
		{"--my-custom-password", true},
		{"--my-custom-token", true},
		{"--my-custom-api-key", true},
		{"--my-custom-private-key", true},
		{"--sort-key", false},      // Should not match - not a sensitive key type
		{"--partition-key", false}, // Should not match - not a sensitive key type
		{"--host", false},
		{"--port", false},
		{"--client-id", false},
		{"--url", false},
		{"--target", false},
		{"--dry-run", false},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			result := isSensitiveArg(tt.arg)
			if result != tt.want {
				t.Errorf("isSensitiveArg(%q) = %v, want %v", tt.arg, result, tt.want)
			}
		})
	}
}
