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
// from a private S3 bucket via a presigned URL and verifies the
// full Ensure flow: download, SHA256 verification, extraction, and symlink.
//
// Requirements:
//   - AWS credentials must be active with read access to the configured S3 bucket
//   - The following environment variables must be set:
//     S3_TEST_BUCKET, S3_TEST_REGION, S3_TEST_KEY, S3_TEST_SHA256,
//     S3_TEST_BUNDLE_NAME, S3_TEST_BUNDLE_VERSION
//   - Run with: go test -v -tags integration -timeout 120s ./agent/filesmgr/... -run TestManager_EnsureFromS3

func s3TestConfig(t *testing.T) (bucket, region, key, sha256, name, version string) {
	t.Helper()
	get := func(env string) string {
		v := os.Getenv(env)
		if v == "" {
			t.Skipf("skipping S3 integration test: %s not set", env)
		}
		return v
	}
	return get("S3_TEST_BUCKET"), get("S3_TEST_REGION"), get("S3_TEST_KEY"),
		get("S3_TEST_SHA256"), get("S3_TEST_BUNDLE_NAME"), get("S3_TEST_BUNDLE_VERSION")
}

func presignS3URL(t *testing.T, bucket, region, key string) string {
	t.Helper()
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	require.NoError(t, err, "load AWS config")

	client := s3.NewFromConfig(cfg)
	presignClient := s3.NewPresignClient(client)

	req, err := presignClient.PresignGetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}, s3.WithPresignExpires(15*time.Minute))
	require.NoError(t, err, "presign S3 URL")
	return req.URL
}

func TestManager_EnsureFromS3(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" && os.Getenv("AWS_SESSION_TOKEN") == "" {
		t.Skip("skipping S3 integration test: no AWS credentials found")
	}

	bucket, region, key, sha256, bundleName, bundleVer := s3TestConfig(t)
	url := presignS3URL(t, bucket, region, key)

	root := t.TempDir()
	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	var eventCount int
	m.Subscribe(func(_ FileEvent) {
		eventCount++
	})

	// First Ensure — download, verify SHA256, extract, symlink
	path, err := m.Ensure(context.Background(), FileSpec{
		Name:    bundleName,
		Version: bundleVer,
		URL:     url,
		SHA256:  sha256,
		Extract: true,
	})
	require.NoError(t, err)

	expectedPath := filepath.Join(root, bundleName, "current")
	assert.Equal(t, expectedPath, path)

	target, err := os.Readlink(filepath.Join(root, bundleName, "current"))
	require.NoError(t, err)
	assert.Equal(t, bundleVer, target)

	assert.DirExists(t, filepath.Join(root, bundleName, bundleVer))
	assert.Equal(t, 1, eventCount, "expected exactly one install event")

	// Second Ensure — must be idempotent
	path2, err := m.Ensure(context.Background(), FileSpec{
		Name:    bundleName,
		Version: bundleVer,
		URL:     url,
		SHA256:  sha256,
		Extract: true,
	})
	require.NoError(t, err)
	assert.Equal(t, path, path2)
	assert.Equal(t, 1, eventCount, "idempotent Ensure must not emit a second event")
}
