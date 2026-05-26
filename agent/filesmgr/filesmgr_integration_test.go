//go:build integration

package filesmgr

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	s3BundleName    = "nbl_cisco_meraki"
	s3BundleVersion = "2.12.0"
	s3BundleBucket  = "nbl-orb-bundles-dev"
	s3BundleKey     = "nbl_cisco_meraki/2.12.0/bundle.tar.gz"
	s3BundleRegion  = "us-east-2"
	s3BundleSHA256  = "fd4c5fda92bf1ae36d589dcd331db7f2cdbb8807792af7fa85ca8b0105a9f5b1"
)

func presignS3URL(t *testing.T) string {
	t.Helper()
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(s3BundleRegion),
	)
	require.NoError(t, err, "failed to load AWS config — are credentials active?")

	client := s3.NewPresignClient(s3.NewFromConfig(cfg))
	req, err := client.PresignGetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(s3BundleBucket),
		Key:    aws.String(s3BundleKey),
	}, s3.WithPresignExpires(time.Hour))
	require.NoError(t, err, "failed to presign S3 URL")
	return req.URL
}

// TestManager_EnsureS3RealBundle tests Ensure() against the real
// nbl-orb-bundles-dev S3 bucket using a dynamically presigned URL.
//
// Prerequisites:
//   - AWS credentials for observability-dev-netboxlabs-AWSAdministratorAccess
//     must be active (use Granted + Firefox for SSO).
//   - Run with: go test -v -tags integration -run TestManager_EnsureS3RealBundle ./agent/filesmgr/
func TestManager_EnsureS3RealBundle(t *testing.T) {
	url := presignS3URL(t)

	root := t.TempDir()
	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// Subscribe before any Ensure call to capture all events
	var events []FileEvent
	var mu sync.Mutex
	m.Subscribe(func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	spec := FileSpec{
		Name:    s3BundleName,
		Version: s3BundleVersion,
		URL:     url,
		SHA256:  s3BundleSHA256,
		Extract: true,
	}

	// First Ensure — should download, extract, and emit EventInstalled
	path, err := m.Ensure(context.Background(), spec)
	require.NoError(t, err, "Ensure() against real S3 bundle should succeed")

	// Verify returned path is the stable symlink
	assert.Equal(t, filepath.Join(root, s3BundleName, "current"), path)

	// Verify symlink points to the correct version
	target, err := os.Readlink(filepath.Join(root, s3BundleName, "current"))
	require.NoError(t, err)
	assert.Equal(t, s3BundleVersion, target)

	// Verify version directory exists and has content
	versionDir := filepath.Join(root, s3BundleName, s3BundleVersion)
	assert.DirExists(t, versionDir)
	entries, err := os.ReadDir(versionDir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "extracted bundle directory should not be empty")

	// Verify exactly one EventInstalled was emitted
	mu.Lock()
	require.Len(t, events, 1, "first Ensure must emit exactly one event")
	assert.Equal(t, EventInstalled, events[0].Type)
	assert.Equal(t, s3BundleName, events[0].Entry.Name)
	assert.Equal(t, s3BundleVersion, events[0].Entry.Version)
	mu.Unlock()

	// Second Ensure — same spec, should be a no-op: same path, no new event
	path2, err := m.Ensure(context.Background(), spec)
	require.NoError(t, err, "second Ensure() should be idempotent")
	assert.Equal(t, path, path2)

	mu.Lock()
	assert.Len(t, events, 1, "idempotent Ensure must not emit a second event")
	mu.Unlock()

	// Verify state is tracked correctly
	entry, ok := m.Get(s3BundleName)
	require.True(t, ok, "bundle should be tracked after Ensure")
	assert.Equal(t, s3BundleVersion, entry.Version)
	assert.Equal(t, s3BundleSHA256, entry.SHA256)
}
