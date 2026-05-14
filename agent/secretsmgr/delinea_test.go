package secretsmgr

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestDelineaStart_ConfigValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		cfg     config.DelineaManager
		wantErr string
	}{
		{
			name:    "both ServerURL and Tenant empty",
			cfg:     config.DelineaManager{Username: "u", Password: "p"},
			wantErr: "either server_url or tenant",
		},
		{
			name:    "both ServerURL and Tenant set",
			cfg:     config.DelineaManager{ServerURL: "https://example.com", Tenant: "example", Username: "u", Password: "p"},
			wantErr: "either server_url or tenant",
		},
		{
			name:    "missing username",
			cfg:     config.DelineaManager{ServerURL: "https://example.com", Password: "p"},
			wantErr: "username is required",
		},
		{
			name:    "missing password",
			cfg:     config.DelineaManager{ServerURL: "https://example.com", Username: "u"},
			wantErr: "password is required",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &delineaManager{logger: newTestLogger(), config: tc.cfg}
			err := m.Start(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
