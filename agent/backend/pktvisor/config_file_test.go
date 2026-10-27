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
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// The file carries the configured settings and taps with the port the start
// settled, whatever port the configuration named.
func TestRenderConfigFileCarriesTheStartsPort(t *testing.T) {
	p := &pktvisorBackend{
		visorSettings: map[string]any{"host": "localhost", "log_level": "debug"},
		visorTaps:     map[string]any{"default_pcap": map[string]any{"input_type": "pcap"}},
	}

	data, err := p.renderConfigFile("40001")
	require.NoError(t, err)
	assert.Contains(t, string(data), "port: 40001")
	assert.Contains(t, string(data), "log_level: debug")
	assert.Contains(t, string(data), "default_pcap")
	assert.NotContains(t, p.visorSettings, "port", "the port is not kept for the next start")

	data, err = p.renderConfigFile("")
	require.NoError(t, err)
	assert.NotContains(t, string(data), "port:")
}

// Each start writes a new config file and removes the previous start's, so
// restarts leave one file behind, not one per restart.
func TestWriteConfigFileReplacesThePreviousStarts(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	p := &pktvisorBackend{logger: slog.New(slog.DiscardHandler)}

	require.NoError(t, p.writeConfigFile("40001"))
	first := p.configFile
	content, err := os.ReadFile(first)
	require.NoError(t, err)
	assert.Contains(t, string(content), "port: 40001")

	require.NoError(t, p.writeConfigFile("40002"))
	assert.NotEqual(t, first, p.configFile)
	_, err = os.Stat(first)
	assert.True(t, os.IsNotExist(err), "the previous start's file is removed")
	content, err = os.ReadFile(p.configFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "port: 40002")
}

// A config file that cannot be written fails the start before anything is
// spawned. The previous start's file is still removed, and none is left
// named for the next start.
func TestStartFailsWhenTheConfigFileCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	previous := filepath.Join(dir, "pktvisor-previous.yaml")
	require.NoError(t, os.WriteFile(previous, []byte("visor: {}\n"), 0o600))
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.Mkdir(bin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bin, defaultBinary), []byte("#!/bin/sh\n"), 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TMPDIR", filepath.Join(dir, "missing"))
	orig := backend.NewCmdOptions
	backend.NewCmdOptions = func(backend.CmdOptions, string, ...string) backend.Commander {
		t.Fatal("nothing is spawned without its config file")
		return nil
	}
	t.Cleanup(func() { backend.NewCmdOptions = orig })

	p := &pktvisorBackend{
		logger:     slog.New(slog.DiscardHandler),
		binary:     defaultBinary,
		configFile: previous,
	}
	p.adminAPIPort.Configure("10853", "localhost", defaultAPIPort)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := p.Start(ctx, cancel)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config file")
	_, statErr := os.Stat(previous)
	assert.True(t, os.IsNotExist(statErr), "the previous start's file is removed")
	assert.Empty(t, p.configFile)
}

// Names starting with fleet_ belong to the taps the agent manages, so a local
// tap cannot take one.
func TestConfigureRefusesAReservedTapName(t *testing.T) {
	configure := func(taps map[string]any) error {
		p := &pktvisorBackend{}
		repo, err := policies.NewMemRepo()
		require.NoError(t, err)
		return p.Configure(slog.New(slog.DiscardHandler), repo, map[string]any{
			"taps": taps,
		}, config.BackendCommons{}, nil)
	}

	err := configure(map[string]any{"fleet_x": map[string]any{"input_type": "pcap"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
	assert.Contains(t, err.Error(), "fleet_x")

	require.NoError(t, configure(map[string]any{"edge": map[string]any{"input_type": "pcap"}}))
}
