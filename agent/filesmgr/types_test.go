package filesmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileSpec_Validate(t *testing.T) {
	tests := []struct {
		name    string
		spec    FileSpec
		wantErr string
	}{
		{
			name: "valid spec",
			spec: FileSpec{
				Name:   "custom_worker_backend",
				URL:    "https://example.com/bundle.tar.gz",
				SHA256: "abc",
			},
			wantErr: "",
		},
		{
			name:    "missing name",
			spec:    FileSpec{URL: "https://x", SHA256: "abc"},
			wantErr: "name is required",
		},
		{
			name:    "missing URL",
			spec:    FileSpec{Name: "x", SHA256: "abc"},
			wantErr: "url is required",
		},
		{
			name:    "missing sha256",
			spec:    FileSpec{Name: "x", URL: "https://x"},
			wantErr: "sha256 is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}
