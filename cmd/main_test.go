package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/config"
)

func configWithDebug(enable bool) config.Config {
	var c config.Config
	c.OrbAgent.Debug.Enable = enable
	return c
}

func TestNewRootLogger_FlagSetsDebugImmediately(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, true)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.True(t, logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestNewRootLogger_DefaultIsInfo(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, false)
	assert.Equal(t, slog.LevelInfo, level.Level())
	assert.False(t, logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestApplyConfigDebug_YAMLOnlyEnablesDebug(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, false)

	effective := applyConfigDebug(logger, level, false, configWithDebug(true))

	assert.True(t, effective)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.True(t, logger.Enabled(context.Background(), slog.LevelDebug))
	// The switch itself must be visible in the (now debug-enabled) output.
	assert.Contains(t, buf.String(), "debug logging enabled via config file")
}

func TestApplyConfigDebug_FlagOnlyStaysDebugNoDuplicateAnnounce(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, true)

	effective := applyConfigDebug(logger, level, true, configWithDebug(false))

	assert.True(t, effective)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.NotContains(t, buf.String(), "debug logging enabled via config file")
}

func TestApplyConfigDebug_BothOff(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, false)

	effective := applyConfigDebug(logger, level, false, configWithDebug(false))

	assert.False(t, effective)
	assert.Equal(t, slog.LevelInfo, level.Level())
	assert.False(t, logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestApplyConfigDebug_BothOnNoDuplicateAnnounce(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, true)

	effective := applyConfigDebug(logger, level, true, configWithDebug(true))

	assert.True(t, effective)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.NotContains(t, buf.String(), "debug logging enabled via config file",
		"flag already enabled debug; config adds nothing to announce")
}

// init registers every bundled backend; snmp_telemetry must be among them.
func TestInitRegistersSnmpTelemetry(t *testing.T) {
	assert.True(t, backend.HaveBackend("snmp_telemetry"))
}

// gnmi_telemetry ships in the image and is registered the same way.
func TestInitRegistersGnmiTelemetry(t *testing.T) {
	assert.True(t, backend.HaveBackend("gnmi_telemetry"))
}

// syncBuffer is a bytes.Buffer the backend's stream goroutine can write while
// the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// streamingProcess stands in for a backend process that keeps running after
// writing line to its stderr.
func streamingProcess(t *testing.T, line string) {
	t.Helper()
	status := backend.CmdStatus{PID: 4242}
	statusCh := make(chan backend.CmdStatus, 1)
	statusCh <- status
	close(statusCh) // a stop returns at once
	stdout, stderr := make(chan string), make(chan string, 1)
	stderr <- line
	t.Cleanup(func() {
		close(stdout)
		close(stderr)
	})

	proc := &mocks.MockCmd{}
	proc.On("Start").Return((<-chan backend.CmdStatus)(statusCh))
	proc.On("Status").Return(status)
	proc.On("GetStdout").Return((<-chan string)(stdout))
	proc.On("GetStderr").Return((<-chan string)(stderr))
	proc.On("Stop").Return(nil)

	orig := backend.NewCmdOptions
	backend.NewCmdOptions = func(backend.CmdOptions, string, ...string) backend.Commander { return proc }
	t.Cleanup(func() { backend.NewCmdOptions = orig })
}

// A backend's logfmt value can decode to a newline. The agent's root logger
// escapes it again, so a backend cannot write a line of its own into the
// agent's log.
func TestBackendLogLineCannotForgeAnAgentLogLine(t *testing.T) {
	forged := "\n" + `{"time":"2026-09-04T12:00:00Z","level":"ERROR","msg":"forged"}`
	msg, stack := "panic serving request"+forged, "goroutine 1 [running]:"+forged
	var child bytes.Buffer
	slog.New(slog.NewTextHandler(&child, nil)).Error(msg, "stack", stack)
	streamingProcess(t, strings.TrimSuffix(child.String(), "\n"))
	mocks.AllowHeldListenAddr(t)
	host, port := mocks.APIStandIn(t, "127.0.0.1")

	var out syncBuffer
	logger, _ := newRootLogger(&out, false)
	be := backend.GetBackend("snmp_discovery")
	require.NoError(t, be.Configure(logger, nil, map[string]any{"host": host, "port": port}, config.BackendCommons{}, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, be.Start(ctx, cancel))
	t.Cleanup(func() { _ = be.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		return strings.Contains(out.String(), "panic serving request")
	}, 5*time.Second, 10*time.Millisecond)

	var forwarded map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record), "each line is one agent record: %q", line)
		assert.NotEqual(t, "forged", record["msg"])
		if _, ok := record["stack"]; ok {
			forwarded = record
		}
	}
	require.NotNil(t, forwarded, "the backend's line reaches the agent's log")
	assert.Equal(t, msg, forwarded["msg"])
	assert.Equal(t, stack, forwarded["stack"])
	assert.Equal(t, "ERROR", forwarded["level"])
	assert.Equal(t, "snmp_discovery", forwarded["backend"])
}
