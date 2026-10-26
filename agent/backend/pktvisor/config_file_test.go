package pktvisor

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each start writes a new config file and removes the previous start's, so
// restarts leave one file behind, not one per restart.
func TestWriteConfigFileReplacesThePreviousStarts(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	p := &pktvisorBackend{logger: slog.New(slog.DiscardHandler), visorConfig: []byte("visor: {}\n")}

	require.NoError(t, p.writeConfigFile())
	first := p.configFile
	content, err := os.ReadFile(first)
	require.NoError(t, err)
	assert.Equal(t, "visor: {}\n", string(content))

	require.NoError(t, p.writeConfigFile())
	assert.NotEqual(t, first, p.configFile)
	_, err = os.Stat(first)
	assert.True(t, os.IsNotExist(err), "the previous start's file is removed")
	_, err = os.Stat(p.configFile)
	assert.NoError(t, err)
}
