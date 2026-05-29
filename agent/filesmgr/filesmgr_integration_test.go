//go:build integration

package filesmgr

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_EnsureFromS3 is an integration test that downloads a real bundle
// from the nbl-orb-bundles-dev S3 bucket via a presigned URL and verifies the
// full Ensure flow: download, SHA256 verification, extraction, and symlink.
//
// Requirements:
//   - AWS credentials must be active (use: assume observability-dev-netboxlabs-AWSAdministratorAccess)
//   - Run with: go test -v -tags integration -timeout 120s ./agent/filesmgr/... -run TestManager_EnsureFromS3

const (
	s3Bucket       = "nbl-orb-bundles-dev"
	s3Region       = "us-east-2"
	s3Key          = "nbl_cisco_meraki/2.12.0/bundle.tar.gz"
	s3BundleSHA256 = "fd4c5fda92bf1ae36d589dcd331db7f2cdbb8807792af7fa85ca8b0105a9f5b1"
	s3BundleName   = "nbl_cisco_meraki"
	s3BundleVer    = "2.12.0"
)

func presignS3URL(t *testing.T) string {
	t.Helper()
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(s3Region))
	require.NoError(t, err, "load AWS config")

	client := s3.NewFromConfig(cfg)
	presignClient := s3.NewPresignClient(client)

	req, err := presignClient.PresignGetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &[]string{s3Bucket}[0],
		Key:    &[]string{s3Key}[0],
	}, s3.WithPresignExpires(15*time.Minute))
	require.NoError(t, err, "presign S3 URL")
	return req.URL
}

func TestManager_EnsureFromS3(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" && os.Getenv("AWS_SESSION_TOKEN") == "" {
		t.Skip("skipping S3 integration test: no AWS credentials found")
	}

	url := presignS3URL(t)

	root := t.TempDir()
	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	var eventCount int
	m.Subscribe(func(_ FileEvent) {
		eventCount++
	})

	// First Ensure — download, verify SHA256, extract, symlink
	path, err := m.Ensure(context.Background(), FileSpec{
		Name:    s3BundleName,
		Version: s3BundleVer,
		URL:     url,
		SHA256:  s3BundleSHA256,
		Extract: true,
	})
	require.NoError(t, err)

	expectedPath := filepath.Join(root, s3BundleName, "current")
	assert.Equal(t, expectedPath, path)

	target, err := os.Readlink(filepath.Join(root, s3BundleName, "current"))
	require.NoError(t, err)
	assert.Equal(t, s3BundleVer, target)

	assert.DirExists(t, filepath.Join(root, s3BundleName, s3BundleVer))
	assert.Equal(t, 1, eventCount, "expected exactly one install event")

	// Second Ensure — must be idempotent
	path2, err := m.Ensure(context.Background(), FileSpec{
		Name:    s3BundleName,
		Version: s3BundleVer,
		URL:     url,
		SHA256:  s3BundleSHA256,
		Extract: true,
	})
	require.NoError(t, err)
	assert.Equal(t, path, path2)
	assert.Equal(t, 1, eventCount, "idempotent Ensure must not emit a second event")
}
