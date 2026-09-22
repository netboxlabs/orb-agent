package pktvisor_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// The backend refuses to start while another process holds the address it
// would listen on: its readiness check asks that address and would take the
// other process's answer as the child's. Nothing is spawned.
func TestPktvisorStartRefusesWhileItsListenAddressIsHeld(t *testing.T) {
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = holder.Close() }()
	host, port, err := net.SplitHostPort(holder.Addr().String())
	require.NoError(t, err)
	createExecutable(t, "pktvisord")

	orig := backend.NewCmdOptions
	backend.NewCmdOptions = func(backend.CmdOptions, string, ...string) backend.Commander {
		t.Fatal("the backend was spawned while its listen address is held")
		return nil
	}
	t.Cleanup(func() { backend.NewCmdOptions = orig })

	require.True(t, pktvisor.Register())
	be := backend.GetBackend("pktvisor")
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	commons := config.BackendCommons{}
	commons.Otlp.HTTP = "http://collector:4318"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	require.NoError(t, be.Configure(logger, repo, map[string]any{
		"host": host,
		"port": port,
	}, commons, nil))

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), config.ContextKey("agent_id"), "test-agent"))
	defer cancel()
	err = be.Start(ctx, cancel)
	require.Error(t, err, "the start is refused")
	assert.ErrorIs(t, err, backend.ErrListenAddrInUse, "the refusal keeps its mark through the backend")
	assert.Contains(t, err.Error(), holder.Addr().String(), "the error names the held address")
	assert.Contains(t, err.Error(), "in use", "the error says the address is held")
}
