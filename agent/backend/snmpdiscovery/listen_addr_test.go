package snmpdiscovery_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/snmpdiscovery"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// The backend refuses to start while another process holds the address it
// would listen on: its readiness check asks that address and would take the
// other process's answer as the child's. Nothing is spawned.
func TestSnmpDiscoveryStartRefusesWhileItsListenAddressIsHeld(t *testing.T) {
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = holder.Close() }()
	host, port, err := net.SplitHostPort(holder.Addr().String())
	require.NoError(t, err)
	createExecutable(t, "snmp-discovery")

	orig := backend.NewCmdOptions
	backend.NewCmdOptions = func(backend.CmdOptions, string, ...string) backend.Commander {
		t.Fatal("the backend was spawned while its listen address is held")
		return nil
	}
	t.Cleanup(func() { backend.NewCmdOptions = orig })

	require.True(t, snmpdiscovery.Register())
	be := backend.GetBackend("snmp_discovery")
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "collector:4317"
	commons.Diode.Target = "default-target"
	commons.Diode.DryRunOutputDir = t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	require.NoError(t, be.Configure(logger, repo, map[string]any{
		"host":               host,
		"port":               port,
		"target":             "default-target",
		"client_id":          "default-client",
		"client_secret":      "default-secret",
		"agent_name":         "default-agent",
		"dry_run":            false,
		"dry_run_output_dir": t.TempDir(),
	}, commons, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = be.Start(ctx, cancel)
	require.Error(t, err, "the start is refused")
	assert.Contains(t, err.Error(), holder.Addr().String(), "the error names the held address")
	assert.Contains(t, err.Error(), "in use", "the error says the address is held")
}
