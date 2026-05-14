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
			name: "valid spec with version",
			spec: FileSpec{
				Name:    "orb-worker",
				Version: "1.0.0",
				URL:     "https://example.com/orb-worker",
				SHA256:  "abc",
			},
			wantErr: "",
		},
		{
			name:    "missing name",
			spec:    FileSpec{URL: "https://x", SHA256: "abc"},
			wantErr: "name",
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
		// Path traversal: Name
		{
			name:    "name with path separator slash",
			spec:    FileSpec{Name: "a/b", URL: "https://x", SHA256: "abc"},
			wantErr: "name",
		},
		{
			name:    "name with path separator backslash",
			spec:    FileSpec{Name: `a\b`, URL: "https://x", SHA256: "abc"},
			wantErr: "name",
		},
		{
			name:    "name is dotdot",
			spec:    FileSpec{Name: "..", URL: "https://x", SHA256: "abc"},
			wantErr: "name",
		},
		{
			name:    "name is dot",
			spec:    FileSpec{Name: ".", URL: "https://x", SHA256: "abc"},
			wantErr: "name",
		},
		{
			name:    "name is absolute path",
			spec:    FileSpec{Name: "/etc/passwd", URL: "https://x", SHA256: "abc"},
			wantErr: "name",
		},
		{
			name:    "name contains traversal component",
			spec:    FileSpec{Name: "../../etc", URL: "https://x", SHA256: "abc"},
			wantErr: "name",
		},
		// Path traversal: Version
		{
			name:    "version with path separator",
			spec:    FileSpec{Name: "x", Version: "1.0/evil", URL: "https://x", SHA256: "abc"},
			wantErr: "version",
		},
		{
			name:    "version is dotdot",
			spec:    FileSpec{Name: "x", Version: "..", URL: "https://x", SHA256: "abc"},
			wantErr: "version",
		},
		{
			name:    "version is absolute",
			spec:    FileSpec{Name: "x", Version: "/1.0.0", URL: "https://x", SHA256: "abc"},
			wantErr: "version",
		},
		{
			name:    "version contains traversal",
			spec:    FileSpec{Name: "x", Version: "../1.0.0", URL: "https://x", SHA256: "abc"},
			wantErr: "version",
		},
		// TargetPath
		{
			name:    "TargetPath not supported in v1",
			spec:    FileSpec{Name: "x", URL: "https://x", SHA256: "abc", TargetPath: "/opt/custom"},
			wantErr: "TargetPath not supported in v1",
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
