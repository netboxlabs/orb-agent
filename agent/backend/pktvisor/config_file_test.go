package pktvisor

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
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

// A config file that cannot be written fails the start before anything is
// spawned, and leaves no file named for the next start to remove.
func TestStartFailsWhenTheConfigFileCannotBeWritten(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	require.NoError(t, os.WriteFile(filepath.Join(bin, defaultBinary), []byte("#!/bin/sh\n"), 0o755))
	spawned := false
	orig := backend.NewCmdOptions
	backend.NewCmdOptions = func(backend.CmdOptions, string, ...string) backend.Commander {
		spawned = true
		return nil
	}
	t.Cleanup(func() { backend.NewCmdOptions = orig })

	p := &pktvisorBackend{logger: slog.New(slog.DiscardHandler), binary: defaultBinary, visorConfig: []byte("visor: {}\n")}
	p.adminAPIPort.Configure("10853", "localhost", defaultAPIPort)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := p.Start(ctx, cancel)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config file")
	assert.False(t, spawned, "nothing is spawned without its config file")
	assert.Empty(t, p.configFile)
}
