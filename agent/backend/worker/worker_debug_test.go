package worker

import (
	"log/slog"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckWorkerSupportsDebug_Supported(t *testing.T) {
	execPath := createHelpScript(t, `Usage: orb-worker [OPTIONS]

Options:
  --host         Server host
  --port         Server port
  --debug        Enable debug logging
  --help         Show this message
`)

	backend := &workerBackend{
		exec:   execPath,
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	assert.True(t, backend.checkWorkerSupportsDebug())
}

func TestCheckWorkerSupportsDebug_NotSupported(t *testing.T) {
	execPath := createHelpScript(t, `Usage: orb-worker [OPTIONS]

Options:
  --host         Server host
  --port         Server port
  --help         Show this message
`)

	backend := &workerBackend{
		exec:   execPath,
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	assert.False(t, backend.checkWorkerSupportsDebug())
}

func createHelpScript(t *testing.T, helpOutput string) string {
	t.Helper()

	tempDir := t.TempDir()
	scriptPath := path.Join(tempDir, "orb-worker")

	script := "#!/bin/sh\necho '" + helpOutput + "'\n"
	err := os.WriteFile(scriptPath, []byte(script), 0o755)
	require.NoError(t, err)

	return scriptPath
}
