//go:build unix

package backend_test

import (
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

// A process killed by a signal, as pkill -9 kills pktvisord, reads as ended
// through the real command wrapper, not as one that runs without answering.
func TestGetRunningStatus_AProcessKilledBySignalHasEnded(t *testing.T) {
	proc := backend.NewCmdOptions(backend.CmdOptions{}, "sleep", "30")
	done := proc.Start()
	require.Eventually(t, func() bool { return proc.Status().PID > 0 }, 5*time.Second, 10*time.Millisecond)
	status, _, err := backend.GetRunningStatus(proc)
	require.Equal(t, backend.Running, status)
	require.False(t, backend.ProcessEnded(status, err))

	require.NoError(t, syscall.Kill(proc.Status().PID, syscall.SIGKILL))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the killed process did not end")
	}

	status, detail, err := backend.GetRunningStatus(proc)
	assert.Equal(t, backend.BackendError, status)
	assert.Equal(t, "process error: signal: killed", detail)
	assert.True(t, backend.ProcessEnded(status, err))
}
