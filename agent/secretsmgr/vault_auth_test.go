package secretsmgr

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestNewAuthentication(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		args      map[string]any
		expectErr bool
	}{
		{
			name:      "token auth with valid args",
			method:    "token",
			args:      map[string]any{"token": "test-token"},
			expectErr: false,
		},
		{
			name:      "token auth without token",
			method:    "token",
			args:      map[string]any{},
			expectErr: true,
		},
		{
			name:      "unsupported auth method",
			method:    "unsupported",
			args:      map[string]any{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := newAuthentication(tt.method, tt.args)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, auth)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, auth)
			}
		})
	}
}

func TestTokenAuth_Authenticate(t *testing.T) {
	// Create test vault server
	cluster, client := createTestVault(t)
	defer cluster.Cleanup()

	ctx := context.Background()

	// Test with invalid token
	auth := &AuthToken{Token: "invalid-token"}
	client.SetToken("invalid-token")

	// This should fail
	secret, err := auth.vaultAuthenticate(ctx, client)
	assert.Error(t, err)
	assert.Nil(t, secret)
}

func TestAuthAppRole_YAMLOmitEmpty(t *testing.T) {
	tests := []struct {
		name         string
		authAppRole  AuthAppRole
		expectedYAML string
		description  string
	}{
		{
			name: "with all fields",
			authAppRole: AuthAppRole{
				RoleID:        "test-role-id",
				SecretID:      "test-secret-id",
				WrappingToken: true,
				MountPath:     stringPtr("custom-path"),
			},
			expectedYAML: `role_id: test-role-id
secret_id: test-secret-id
wrapping_token: true
mount_path: custom-path
`,
			description: "All fields should be present in YAML",
		},
		{
			name: "omit empty fields",
			authAppRole: AuthAppRole{
				RoleID:        "test-role-id",
				SecretID:      "test-secret-id",
				WrappingToken: false, // zero value should be omitted
				MountPath:     nil,   // nil pointer should be omitted
			},
			expectedYAML: `role_id: test-role-id
secret_id: test-secret-id
`,
			description: "Zero values should be omitted from YAML due to omitempty tag",
		},
		{
			name: "omit empty mount_path only",
			authAppRole: AuthAppRole{
				RoleID:        "test-role-id",
				SecretID:      "test-secret-id",
				WrappingToken: true,
				MountPath:     nil, // nil pointer should be omitted
			},
			expectedYAML: `role_id: test-role-id
secret_id: test-secret-id
wrapping_token: true
`,
			description: "Only nil mount_path should be omitted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling (struct -> YAML)
			yamlBytes, err := yaml.Marshal(tt.authAppRole)
			assert.NoError(t, err, "Failed to marshal AuthAppRole to YAML")
			assert.Equal(t, tt.expectedYAML, string(yamlBytes), tt.description)

			// Test unmarshaling (YAML -> struct)
			var unmarshaled AuthAppRole
			err = yaml.Unmarshal([]byte(tt.expectedYAML), &unmarshaled)
			assert.NoError(t, err, "Failed to unmarshal YAML to AuthAppRole")

			// Compare the unmarshaled struct with expected values
			assert.Equal(t, tt.authAppRole.RoleID, unmarshaled.RoleID, "RoleID should match")
			assert.Equal(t, tt.authAppRole.SecretID, unmarshaled.SecretID, "SecretID should match")
			assert.Equal(t, tt.authAppRole.WrappingToken, unmarshaled.WrappingToken, "WrappingToken should match")

			if tt.authAppRole.MountPath == nil {
				assert.Nil(t, unmarshaled.MountPath, "MountPath should be nil")
			} else {
				assert.NotNil(t, unmarshaled.MountPath, "MountPath should not be nil")
				assert.Equal(t, *tt.authAppRole.MountPath, *unmarshaled.MountPath, "MountPath values should match")
			}
		})
	}
}

func TestAuthAppRole_YAMLValidation(t *testing.T) {
	tests := []struct {
		name      string
		yamlData  string
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid minimal config",
			yamlData: `role_id: test-role-id
secret_id: test-secret-id
`,
			expectErr: false,
		},
		{
			name: "missing role_id",
			yamlData: `secret_id: test-secret-id
`,
			expectErr: true,
			errMsg:    "missing required field 'role_id'",
		},
		{
			name: "missing secret_id",
			yamlData: `role_id: test-role-id
`,
			expectErr: true,
			errMsg:    "missing required field 'secret_id'",
		},
		{
			name: "valid with optional fields",
			yamlData: `role_id: test-role-id
secret_id: test-secret-id
wrapping_token: true
mount_path: custom-mount
`,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authAppRole AuthAppRole
			err := yaml.Unmarshal([]byte(tt.yamlData), &authAppRole)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, authAppRole.RoleID)
				assert.NotEmpty(t, authAppRole.SecretID)
			}
		})
	}
}

// Helper function to create a string pointer
func stringPtr(s string) *string {
	return &s
}
