package secretsmgr

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
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
	ln, client := createTestVault(t)
	defer func() {
		if err := ln.Close(); err != nil {
			assert.NoError(t, err, "Failed to close test vault listener")
		}
	}()

	ctx := context.Background()

	// Test with invalid token
	auth := &AuthToken{Token: "invalid-token"}
	client.SetToken("invalid-token")

	// This should fail
	secret, err := auth.vaultAuthenticate(ctx, client)
	assert.Error(t, err)
	assert.Nil(t, secret)
}
